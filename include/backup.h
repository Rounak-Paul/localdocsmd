#ifndef BACKUP_H
#define BACKUP_H

#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

/**
 * Create a ZIP backup (STORE, no compression) of the live database
 * and all data directories.
 *
 * The archive contains:
 *   localdocsmd.db   - consistent hot-copy of the running database
 *   <documents_path>/...  - all document files, preserving sub-directories
 *   <media_path>/...      - all media files, preserving sub-directories
 *
 * To restore: place localdocsmd.db and the data/ directory next to the
 * executable and run ./localdocsmd.
 *
 * @param src_db          Live sqlite3 connection (read-only hot backup)
 * @param db_path         Filesystem path of the DB file (used for temp file)
 * @param documents_path  Path to the documents directory
 * @param media_path      Path to the media directory
 * @param out_len         Set to the size of the returned buffer
 * @return malloc'd ZIP bytes (caller must free()), or NULL on failure
 */
uint8_t *backup_create_zip(sqlite3    *src_db,
                           const char *db_path,
                           const char *documents_path,
                           const char *media_path,
                           size_t     *out_len);

#endif /* BACKUP_H */
