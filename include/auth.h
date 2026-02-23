#ifndef AUTH_H
#define AUTH_H

#include "localdocsmd.h"
#include "database.h"
#include "config.h"

/**
 * Hash a password with salt
 * @param password Plain text password
 * @param salt Salt (if NULL, generates new salt)
 * @param hash_out Output buffer for hash (at least LDMD_HASH_LENGTH)
 * @param salt_out Output buffer for salt (at least LDMD_SALT_LENGTH)
 * @return LDMD_OK or error code
 */
ldmd_error_t auth_hash_password(const char *password, const char *salt,
                                char *hash_out, char *salt_out);

/**
 * Verify password against hash
 * @param password Plain text password
 * @param hash Stored hash
 * @param salt Stored salt
 * @return true if password matches
 */
bool auth_verify_password(const char *password, const char *hash, const char *salt);

/**
 * Generate a random token
 * @param token_out Output buffer (at least LDMD_TOKEN_LENGTH)
 */
void auth_generate_token(char *token_out);

/**
 * Generate UUID
 * @param uuid_out Output buffer (at least LDMD_UUID_LENGTH)
 */
void auth_generate_uuid(char *uuid_out);

/**
 * Attempt user login
 * @param db Database handle
 * @param config Configuration
 * @param username Username
 * @param password Password
 * @param ip_address Client IP address
 * @param user_agent Client user agent
 * @param session_out Output session (if successful)
 * @return LDMD_OK or error code
 */
ldmd_error_t auth_login(ldmd_database_t *db, ldmd_config_t *config,
                        const char *username, const char *password,
                        const char *ip_address, const char *user_agent,
                        ldmd_session_t *session_out);

/**
 * Logout user (destroy session)
 * @param db Database handle
 * @param token Session token
 */
ldmd_error_t auth_logout(ldmd_database_t *db, const char *token);

/**
 * Validate session
 * @param db Database handle
 * @param token Session token
 * @param session_out Output session (optional)
 * @return LDMD_OK if valid, LDMD_ERROR_UNAUTHORIZED otherwise
 */
ldmd_error_t auth_validate_session(ldmd_database_t *db, const char *token,
                                   ldmd_session_t *session_out);

/**
 * Create new user
 * @param db Database handle
 * @param config Configuration
 * @param username Username
 * @param email Email
 * @param password Initial password (NULL for random temp password)
 * @param role Global role
 * @param user_out Output user
 * @return LDMD_OK or error code
 */
ldmd_error_t auth_create_user(ldmd_database_t *db, ldmd_config_t *config,
                              const char *username, const char *email,
                              const char *password, ldmd_role_t role,
                              ldmd_user_t *user_out);

/**
 * Change password (first time - no approval needed)
 * @param db Database handle
 * @param config Configuration
 * @param user_id User ID
 * @param current_password Current password
 * @param new_password New password
 * @return LDMD_OK or error code
 */
ldmd_error_t auth_change_password_first(ldmd_database_t *db, ldmd_config_t *config,
                                        int64_t user_id, const char *current_password,
                                        const char *new_password);

/**
 * Request password change (requires admin approval)
 * @param db Database handle
 * @param config Configuration
 * @param user_id User ID
 * @param current_password Current password
 * @param new_password New password
 * @return LDMD_OK or error code
 */
ldmd_error_t auth_request_password_change(ldmd_database_t *db, ldmd_config_t *config,
                                          int64_t user_id, const char *current_password,
                                          const char *new_password);

/**
 * Approve password change (admin only)
 * @param db Database handle
 * @param request_id Password request ID
 * @param admin_id Admin user ID who approved
 * @return LDMD_OK or error code
 */
ldmd_error_t auth_approve_password_change(ldmd_database_t *db, int64_t request_id,
                                          int64_t admin_id);

/**
 * Reject password change (admin only)
 * @param db Database handle
 * @param request_id Password request ID
 * @param admin_id Admin user ID who rejected
 * @return LDMD_OK or error code
 */
ldmd_error_t auth_reject_password_change(ldmd_database_t *db, int64_t request_id,
                                         int64_t admin_id);

/**
 * Check if IP is localhost
 * @param ip IP address string
 * @return true if localhost
 */
bool auth_is_localhost(const char *ip);

/**
 * Submit a forgot-password request (no authentication needed)
 * @param db Database handle
 * @param username Username of the user who forgot their password
 * @return LDMD_OK always (do not leak whether username exists)
 */
ldmd_error_t auth_forgot_password(ldmd_database_t *db, const char *username);

/**
 * Admin directly resets a user's password (sets temp password + forces change on next login)
 * @param db Database handle
 * @param config Configuration
 * @param user_uuid Target user UUID
 * @param new_password New temporary password
 * @param admin_id Admin user ID performing the reset
 * @return LDMD_OK or error code
 */
ldmd_error_t auth_admin_reset_password(ldmd_database_t *db, ldmd_config_t *config,
                                       const char *user_uuid, const char *new_password,
                                       int64_t admin_id);

/**
 * Admin handles a forgot-password request by supplying a new temp password
 * @param db Database handle
 * @param config Configuration
 * @param request_id The forgot-password request ID
 * @param new_password New temporary password to set for the user
 * @param admin_id Admin performing the action
 * @return LDMD_OK or error code
 */
ldmd_error_t auth_handle_forgot_password(ldmd_database_t *db, ldmd_config_t *config,
                                         int64_t request_id, const char *new_password,
                                         int64_t admin_id);

#endif // AUTH_H
