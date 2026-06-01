/*
 * backup.c — In-memory ZIP backup of database + data directories.
 *
 * Produces a STORE (no compression) ZIP archive that can be extracted
 * on any platform.  Restore by placing localdocsmd.db and the data/
 * directory next to the executable and running ./localdocsmd.
 */

#include "backup.h"
#include "localdocsmd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sqlite3.h>

/* ── ZIP limits ───────────────────────────────────────────────── */
#define ZIP_MAX_NAMELEN 256   /* max path length for a single entry */

/* ── Dynamic byte buffer ──────────────────────────────────────── */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} dyn_buf_t;

static bool dyn_init(dyn_buf_t *b, size_t initial) {
    b->data = malloc(initial);
    b->len  = 0;
    b->cap  = b->data ? initial : 0;
    return b->data != NULL;
}

static bool dyn_append(dyn_buf_t *b, const void *src, size_t n) {
    if (b->len + n > b->cap) {
        size_t newcap = b->cap * 2;
        if (newcap < b->len + n) newcap = b->len + n + 65536;
        uint8_t *p = realloc(b->data, newcap);
        if (!p) return false;
        b->data = p;
        b->cap  = newcap;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return true;
}

__attribute__((unused))
static void dyn_free(dyn_buf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len  = b->cap = 0;
}

/* ── Little-endian write helpers ──────────────────────────────── */
static void put_le16(dyn_buf_t *b, uint16_t v) {
    uint8_t buf[2] = { (uint8_t)(v), (uint8_t)(v >> 8) };
    dyn_append(b, buf, 2);
}

static void put_le32(dyn_buf_t *b, uint32_t v) {
    uint8_t buf[4] = {
        (uint8_t)(v),       (uint8_t)(v >> 8),
        (uint8_t)(v >> 16), (uint8_t)(v >> 24)
    };
    dyn_append(b, buf, 4);
}

/* ── CRC-32 (IEEE 802.3 / PKZIP standard) ─────────────────────── */
static uint32_t s_crc_table[256];
static bool     s_crc_init = false;

static void crc32_build_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        s_crc_table[i] = c;
    }
    s_crc_init = true;
}

static uint32_t crc32_compute(const uint8_t *data, size_t len) {
    if (!s_crc_init) crc32_build_table();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = s_crc_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* ── DOS time/date ────────────────────────────────────────────── */
static void dos_datetime(uint16_t *t_out, uint16_t *d_out) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    if (!tm) { *t_out = 0; *d_out = 0; return; }
    *t_out = (uint16_t)(
        ((uint16_t)(tm->tm_hour         & 0x1F) << 11) |
        ((uint16_t)(tm->tm_min          & 0x3F) << 5)  |
        ((uint16_t)((tm->tm_sec / 2)    & 0x1F))
    );
    *d_out = (uint16_t)(
        ((uint16_t)((tm->tm_year - 80)  & 0x7F) << 9) |
        ((uint16_t)((tm->tm_mon + 1)    & 0x0F) << 5) |
        ((uint16_t)(tm->tm_mday         & 0x1F))
    );
}

/* ── Per-file central directory entry ────────────────────────── */
typedef struct {
    uint32_t offset;
    uint32_t crc;
    uint32_t size;
    uint16_t mtime, mdate;
    uint16_t namelen;
    char    *name;     /* heap-alloc'd; freed after zip_finalize */
} zip_cd_t;

/* ── Append one STORE entry ───────────────────────────────────── */
static void zip_add_entry(dyn_buf_t *zip, const char *name,
                          const uint8_t *data, uint32_t size,
                          zip_cd_t *cd_out) {
    uint16_t mtime, mdate;
    dos_datetime(&mtime, &mdate);

    uint32_t crc     = crc32_compute(data, size);
    uint16_t namelen = (uint16_t)strlen(name);
    if (namelen >= ZIP_MAX_NAMELEN) namelen = ZIP_MAX_NAMELEN - 1;

    cd_out->offset  = (uint32_t)zip->len;
    cd_out->crc     = crc;
    cd_out->size    = size;
    cd_out->mtime   = mtime;
    cd_out->mdate   = mdate;
    cd_out->namelen = namelen;
    cd_out->name    = strndup(name, namelen); /* freed by caller */

    /* Local file header (30 + namelen bytes) */
    static const uint8_t LFH[4] = { 'P','K', 0x03, 0x04 };
    dyn_append(zip, LFH, 4);
    put_le16(zip, 20);       /* version needed (2.0) */
    put_le16(zip, 0);        /* general purpose flags */
    put_le16(zip, 0);        /* compression method: STORE */
    put_le16(zip, mtime);
    put_le16(zip, mdate);
    put_le32(zip, crc);
    put_le32(zip, size);     /* compressed size */
    put_le32(zip, size);     /* uncompressed size */
    put_le16(zip, namelen);
    put_le16(zip, 0);        /* extra field length */
    dyn_append(zip, name, namelen);
    if (size > 0) dyn_append(zip, data, size);
}

/* ── Write central directory + end-of-central-directory ─────── */
static void zip_finalize(dyn_buf_t *zip, const zip_cd_t *cd, int count) {
    static const uint8_t CD_SIG[4]   = { 'P','K', 0x01, 0x02 };
    static const uint8_t EOCD_SIG[4] = { 'P','K', 0x05, 0x06 };

    uint32_t cd_offset = (uint32_t)zip->len;

    for (int i = 0; i < count; i++) {
        dyn_append(zip, CD_SIG, 4);
        put_le16(zip, 20);              /* version made by */
        put_le16(zip, 20);              /* version needed */
        put_le16(zip, 0);               /* flags */
        put_le16(zip, 0);               /* method: STORE */
        put_le16(zip, cd[i].mtime);
        put_le16(zip, cd[i].mdate);
        put_le32(zip, cd[i].crc);
        put_le32(zip, cd[i].size);      /* compressed */
        put_le32(zip, cd[i].size);      /* uncompressed */
        put_le16(zip, cd[i].namelen);
        put_le16(zip, 0);               /* extra field */
        put_le16(zip, 0);               /* file comment */
        put_le16(zip, 0);               /* disk number start */
        put_le16(zip, 0);               /* internal file attributes */
        put_le32(zip, 0);               /* external file attributes */
        put_le32(zip, cd[i].offset);
        dyn_append(zip, cd[i].name, cd[i].namelen);
    }

    uint32_t cd_size = (uint32_t)zip->len - cd_offset;

    /* End of central directory record (22 bytes) */
    dyn_append(zip, EOCD_SIG, 4);
    put_le16(zip, 0);                     /* disk number */
    put_le16(zip, 0);                     /* disk with start of CD */
    put_le16(zip, (uint16_t)count);       /* entries on this disk */
    put_le16(zip, (uint16_t)count);       /* total entries */
    put_le32(zip, cd_size);
    put_le32(zip, cd_offset);
    put_le16(zip, 0);                     /* ZIP comment length */
}

/* ── Grow the central-directory array when needed ────────────── */
static bool cd_ensure(zip_cd_t **cd, int *cap, int need) {
    if (need < *cap) return true;
    int new_cap = *cap * 2;
    if (new_cap <= need) new_cap = need + 1024;
    zip_cd_t *p = realloc(*cd, (size_t)new_cap * sizeof(zip_cd_t));
    if (!p) return false;
    *cd  = p;
    *cap = new_cap;
    return true;
}

/* ── Recursively add a directory tree to the ZIP ─────────────── */
static void walk_dir(dyn_buf_t *zip, const char *zip_prefix,
                     const char *dir_path,
                     zip_cd_t **cd, int *count, int *cap) {
    DIR *d = opendir(dir_path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        /* skip hidden files, ., .. */
        if (ent->d_name[0] == '.') continue;

        char full_path[LDMD_MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, ent->d_name);

        char zip_name[ZIP_MAX_NAMELEN];
        snprintf(zip_name, sizeof(zip_name), "%s/%s", zip_prefix, ent->d_name);

        struct stat st;
        if (stat(full_path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            walk_dir(zip, zip_name, full_path, cd, count, cap);
        } else if (S_ISREG(st.st_mode) && st.st_size > 0) {
            if (!cd_ensure(cd, cap, *count)) continue;
            FILE *fp = fopen(full_path, "rb");
            if (!fp) continue;
            uint8_t *buf = malloc((size_t)st.st_size);
            if (!buf) { fclose(fp); continue; }
            size_t n = fread(buf, 1, (size_t)st.st_size, fp);
            fclose(fp);
            if (n == (size_t)st.st_size) {
                zip_add_entry(zip, zip_name, buf, (uint32_t)n, &(*cd)[*count]);
                (*count)++;
            }
            free(buf);
        }
    }
    closedir(d);
}

/* ── Public API ───────────────────────────────────────────────── */
uint8_t *backup_create_zip(sqlite3    *src_db,
                           const char *db_path,
                           const char *documents_path,
                           const char *media_path,
                           size_t     *out_len) {
    *out_len = 0;

    int       cd_cap = 1024;
    zip_cd_t *cd     = calloc((size_t)cd_cap, sizeof(zip_cd_t));
    if (!cd) return NULL;

    dyn_buf_t zip = {0};
    if (!dyn_init(&zip, 4 * 1024 * 1024)) {
        free(cd);
        return NULL;
    }

    int count = 0;

    /* ── 1. SQLite online backup → temp file → read into ZIP ── */
    char tmp_path[LDMD_MAX_PATH];
    snprintf(tmp_path, sizeof(tmp_path), "%s.baktmp", db_path);

    sqlite3 *dst_db = NULL;
    if (sqlite3_open(tmp_path, &dst_db) == SQLITE_OK) {
        sqlite3_backup *bk = sqlite3_backup_init(dst_db, "main", src_db, "main");
        if (bk) {
            sqlite3_backup_step(bk, -1);
            sqlite3_backup_finish(bk);
        }
        sqlite3_close(dst_db);
        dst_db = NULL;

        struct stat st;
        if (stat(tmp_path, &st) == 0 && st.st_size > 0) {
            FILE *fp = fopen(tmp_path, "rb");
            if (fp) {
                uint8_t *buf = malloc((size_t)st.st_size);
                if (buf) {
                    size_t n = fread(buf, 1, (size_t)st.st_size, fp);
                    if (n == (size_t)st.st_size && cd_ensure(&cd, &cd_cap, count)) {
                        zip_add_entry(&zip, db_path,
                                      buf, (uint32_t)n, &cd[count++]);
                    }
                    free(buf);
                }
                fclose(fp);
            }
        }
        remove(tmp_path);
    }

    /* ── 2. Document files ── */
    walk_dir(&zip, documents_path, documents_path, &cd, &count, &cd_cap);

    /* ── 3. Media files ── */
    walk_dir(&zip, media_path, media_path, &cd, &count, &cd_cap);

    /* ── 4. Central directory + EOCD ── */
    zip_finalize(&zip, cd, count);
    for (int i = 0; i < count; i++) free(cd[i].name);
    free(cd);

    *out_len = zip.len;
    return zip.data; /* caller must free() */
}
