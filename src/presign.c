#include "presign.h"
#include "auth.h"
#include "utils.h"
#include <pthread.h>
#include <string.h>
#include <time.h>

/* ── In-memory token store ─────────────────────────────────────── */

typedef struct {
    char    token[LDMD_TOKEN_LENGTH];
    char    doc_uuid[LDMD_UUID_LENGTH];
    int64_t user_id;
    time_t  expires_at;
    bool    active;
} presign_entry_t;

static presign_entry_t   g_store[PRESIGN_MAX_ENTRIES];
static pthread_mutex_t   g_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── Public API ────────────────────────────────────────────────── */

void presign_init(void) {
    pthread_mutex_lock(&g_mutex);
    memset(g_store, 0, sizeof(g_store));
    pthread_mutex_unlock(&g_mutex);
}

ldmd_error_t presign_create(const char *doc_uuid, int64_t user_id,
                            char *token_out) {
    if (!doc_uuid || !token_out) return LDMD_ERROR_INVALID;

    char token[LDMD_TOKEN_LENGTH];
    auth_generate_token(token);

    time_t now     = time(NULL);
    time_t expires = now + PRESIGN_EXPIRE_SECS;

    pthread_mutex_lock(&g_mutex);

    /* Find a free slot: prefer already-expired entries first, then empty. */
    int slot = -1;
    for (int i = 0; i < PRESIGN_MAX_ENTRIES; i++) {
        if (!g_store[i].active || g_store[i].expires_at < now) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&g_mutex);
        LOG_WARN("presign store full – cannot create token for doc %s", doc_uuid);
        return LDMD_ERROR;
    }

    memset(&g_store[slot], 0, sizeof(g_store[slot]));
    ldmd_strlcpy(g_store[slot].token,    token,    sizeof(g_store[slot].token));
    ldmd_strlcpy(g_store[slot].doc_uuid, doc_uuid, sizeof(g_store[slot].doc_uuid));
    g_store[slot].user_id    = user_id;
    g_store[slot].expires_at = expires;
    g_store[slot].active     = true;

    pthread_mutex_unlock(&g_mutex);

    ldmd_strlcpy(token_out, token, LDMD_TOKEN_LENGTH);
    return LDMD_OK;
}

ldmd_error_t presign_validate(const char *token, char *doc_uuid_out) {
    if (!token || token[0] == '\0') return LDMD_ERROR_UNAUTHORIZED;

    time_t now = time(NULL);

    pthread_mutex_lock(&g_mutex);

    for (int i = 0; i < PRESIGN_MAX_ENTRIES; i++) {
        if (!g_store[i].active) continue;
        if (strcmp(g_store[i].token, token) != 0) continue;

        if (g_store[i].expires_at < now) {
            /* Lazy expiry: mark inactive on first validation attempt. */
            g_store[i].active = false;
            pthread_mutex_unlock(&g_mutex);
            return LDMD_ERROR_UNAUTHORIZED;
        }

        if (doc_uuid_out) {
            ldmd_strlcpy(doc_uuid_out, g_store[i].doc_uuid, LDMD_UUID_LENGTH);
        }

        pthread_mutex_unlock(&g_mutex);
        return LDMD_OK;
    }

    pthread_mutex_unlock(&g_mutex);
    return LDMD_ERROR_UNAUTHORIZED;
}
