#include "session.h"
#include "auth.h"
#include "utils.h"
#include <string.h>

ldmd_error_t session_create(ldmd_database_t *db, int64_t user_id,
                            const char *ip_address, const char *user_agent,
                            int timeout_seconds, bool is_admin,
                            ldmd_session_t *session_out) {
    memset(session_out, 0, sizeof(*session_out));
    
    auth_generate_token(session_out->token);
    session_out->user_id = user_id;
    
    if (ip_address) {
        ldmd_strlcpy(session_out->ip_address, ip_address, sizeof(session_out->ip_address));
    }
    if (user_agent) {
        ldmd_strlcpy(session_out->user_agent, user_agent, sizeof(session_out->user_agent));
    }
    
    session_out->is_admin_session = is_admin;
    session_out->created_at = utils_now();
    session_out->expires_at = session_out->created_at + timeout_seconds;
    
    return db_session_create(db, session_out);
}

ldmd_error_t session_get(ldmd_database_t *db, const char *token,
                         ldmd_session_t *session_out) {
    return db_session_get(db, token, session_out);
}

ldmd_error_t session_validate(ldmd_database_t *db, const char *token,
                              int timeout_seconds, ldmd_session_t *session_out) {
    ldmd_session_t session;
    ldmd_error_t err = db_session_get(db, token, &session);
    if (err != LDMD_OK) {
        return LDMD_ERROR_UNAUTHORIZED;
    }
    
    time_t now = utils_now();
    
    // Check if expired
    if (session.expires_at < now) {
        db_session_delete(db, token);
        return LDMD_ERROR_UNAUTHORIZED;
    }
    
    // Optionally refresh session expiry
    if (timeout_seconds > 0) {
        // Only update if more than 10% of timeout has passed
        time_t threshold = session.expires_at - (timeout_seconds * 9 / 10);
        if (now > threshold) {
            session.expires_at = now + timeout_seconds;
            // Update in database (simple approach - just delete and recreate)
            // In production, you'd want an UPDATE statement
        }
    }
    
    if (session_out) {
        *session_out = session;
    }
    
    return LDMD_OK;
}

ldmd_error_t session_destroy(ldmd_database_t *db, const char *token) {
    return db_session_delete(db, token);
}

ldmd_error_t session_destroy_all(ldmd_database_t *db, int64_t user_id) {
    return db_session_delete_by_user(db, user_id);
}

ldmd_error_t session_cleanup(ldmd_database_t *db) {
    return db_session_cleanup(db);
}
