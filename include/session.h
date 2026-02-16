#ifndef SESSION_H
#define SESSION_H

#include "localdocsmd.h"
#include "database.h"

/**
 * Create new session
 * @param db Database handle
 * @param user_id User ID
 * @param ip_address Client IP
 * @param user_agent Client user agent
 * @param timeout_seconds Session timeout
 * @param is_admin Is this an admin session
 * @param session_out Output session
 * @return LDMD_OK or error code
 */
ldmd_error_t session_create(ldmd_database_t *db, int64_t user_id,
                            const char *ip_address, const char *user_agent,
                            int timeout_seconds, bool is_admin,
                            ldmd_session_t *session_out);

/**
 * Get session by token
 * @param db Database handle
 * @param token Session token
 * @param session_out Output session
 * @return LDMD_OK or LDMD_ERROR_NOT_FOUND
 */
ldmd_error_t session_get(ldmd_database_t *db, const char *token,
                         ldmd_session_t *session_out);

/**
 * Validate and refresh session
 * @param db Database handle
 * @param token Session token
 * @param timeout_seconds New timeout
 * @param session_out Output session (optional)
 * @return LDMD_OK if valid
 */
ldmd_error_t session_validate(ldmd_database_t *db, const char *token,
                              int timeout_seconds, ldmd_session_t *session_out);

/**
 * Destroy session
 * @param db Database handle
 * @param token Session token
 * @return LDMD_OK or error code
 */
ldmd_error_t session_destroy(ldmd_database_t *db, const char *token);

/**
 * Destroy all sessions for user
 * @param db Database handle
 * @param user_id User ID
 * @return LDMD_OK or error code
 */
ldmd_error_t session_destroy_all(ldmd_database_t *db, int64_t user_id);

/**
 * Cleanup expired sessions
 * @param db Database handle
 * @return LDMD_OK or error code
 */
ldmd_error_t session_cleanup(ldmd_database_t *db);

#endif // SESSION_H
