#include "auth.h"
#include "session.h"
#include "utils.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Generate random bytes as hex string
static void generate_random_hex(char *out, size_t bytes) {
    unsigned char *buf = malloc(bytes);
    if (!buf) {
        out[0] = '\0';
        return;
    }
    
    if (RAND_bytes(buf, (int)bytes) != 1) {
        // Fallback to less secure random
        for (size_t i = 0; i < bytes; i++) {
            buf[i] = (unsigned char)(rand() % 256);
        }
    }
    
    for (size_t i = 0; i < bytes; i++) {
        sprintf(out + i * 2, "%02x", buf[i]);
    }
    out[bytes * 2] = '\0';
    
    free(buf);
}

ldmd_error_t auth_hash_password(const char *password, const char *salt,
                                char *hash_out, char *salt_out) {
    // Generate salt if not provided
    char salt_buf[LDMD_SALT_LENGTH];
    if (!salt) {
        generate_random_hex(salt_buf, 16);
        salt = salt_buf;
    }
    
    // Combine password and salt
    size_t combined_len = strlen(password) + strlen(salt) + 1;
    char *combined = malloc(combined_len);
    if (!combined) {
        return LDMD_ERROR_MEMORY;
    }
    snprintf(combined, combined_len, "%s%s", password, salt);
    
    // Hash with SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)combined, strlen(combined), hash);
    free(combined);
    
    // Convert to hex
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_out + i * 2, "%02x", hash[i]);
    }
    hash_out[LDMD_HASH_LENGTH - 1] = '\0';
    
    ldmd_strlcpy(salt_out, salt, LDMD_SALT_LENGTH);
    
    return LDMD_OK;
}

bool auth_verify_password(const char *password, const char *hash, const char *salt) {
    char computed_hash[LDMD_HASH_LENGTH];
    char computed_salt[LDMD_SALT_LENGTH];
    
    if (auth_hash_password(password, salt, computed_hash, computed_salt) != LDMD_OK) {
        return false;
    }
    
    return strcmp(computed_hash, hash) == 0;
}

void auth_generate_token(char *token_out) {
    generate_random_hex(token_out, 32);
}

void auth_generate_uuid(char *uuid_out) {
    unsigned char buf[16];
    if (RAND_bytes(buf, 16) != 1) {
        for (int i = 0; i < 16; i++) {
            buf[i] = (unsigned char)(rand() % 256);
        }
    }
    
    // Set version (4) and variant bits
    buf[6] = (buf[6] & 0x0F) | 0x40;
    buf[8] = (buf[8] & 0x3F) | 0x80;
    
    snprintf(uuid_out, LDMD_UUID_LENGTH,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             buf[0], buf[1], buf[2], buf[3],
             buf[4], buf[5],
             buf[6], buf[7],
             buf[8], buf[9],
             buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
}

bool auth_is_localhost(const char *ip) {
    if (!ip) return false;
    
    return strcmp(ip, "127.0.0.1") == 0 ||
           strcmp(ip, "::1") == 0 ||
           strcmp(ip, "localhost") == 0 ||
           strncmp(ip, "127.", 4) == 0;
}

ldmd_error_t auth_login(ldmd_database_t *db, ldmd_config_t *config,
                        const char *username, const char *password,
                        const char *ip_address, const char *user_agent,
                        ldmd_session_t *session_out) {
    ldmd_user_t user;
    memset(&user, 0, sizeof(user));
    
    // Find user
    ldmd_error_t err = db_user_get_by_username(db, username, &user);
    if (err == LDMD_ERROR_NOT_FOUND) {
        LOG_WARN("Login attempt for non-existent user: %s", username);
        return LDMD_ERROR_UNAUTHORIZED;
    }
    if (err != LDMD_OK) {
        return err;
    }
    
    // Check if locked
    time_t now = utils_now();
    if (user.status == USER_STATUS_LOCKED && user.locked_until > now) {
        LOG_WARN("Login attempt for locked user: %s", username);
        return LDMD_ERROR_FORBIDDEN;
    }
    
    // Check if disabled
    if (user.status == USER_STATUS_DISABLED) {
        LOG_WARN("Login attempt for disabled user: %s", username);
        return LDMD_ERROR_FORBIDDEN;
    }
    
    // Verify password
    if (!auth_verify_password(password, user.password_hash, user.salt)) {
        user.login_attempts++;
        
        // Lock if too many attempts
        if (user.login_attempts >= config->max_login_attempts) {
            user.status = USER_STATUS_LOCKED;
            user.locked_until = now + config->lockout_duration;
            LOG_WARN("User locked due to too many login attempts: %s", username);
        }
        
        db_user_update(db, &user);
        return LDMD_ERROR_UNAUTHORIZED;
    }
    
    // Successful login - reset attempts
    user.login_attempts = 0;
    if (user.status == USER_STATUS_LOCKED) {
        user.status = USER_STATUS_ACTIVE;
        user.locked_until = 0;
    }
    user.last_login = now;
    db_user_update(db, &user);
    
    // Create session
    memset(session_out, 0, sizeof(*session_out));
    return session_create(db, user.id, ip_address, user_agent,
                         config->session_timeout, false, session_out);
}

ldmd_error_t auth_logout(ldmd_database_t *db, const char *token) {
    return session_destroy(db, token);
}

ldmd_error_t auth_validate_session(ldmd_database_t *db, const char *token,
                                   ldmd_session_t *session_out) {
    ldmd_session_t session;
    ldmd_error_t err = db_session_get(db, token, &session);
    if (err != LDMD_OK) {
        return LDMD_ERROR_UNAUTHORIZED;
    }
    
    // Check expiry
    if (session.expires_at < utils_now()) {
        db_session_delete(db, token);
        return LDMD_ERROR_UNAUTHORIZED;
    }
    
    if (session_out) {
        *session_out = session;
    }
    
    return LDMD_OK;
}

ldmd_error_t auth_create_user(ldmd_database_t *db, ldmd_config_t *config,
                              const char *username, const char *email,
                              const char *password, ldmd_role_t role,
                              ldmd_user_t *user_out) {
    (void)config;  // Reserved for future use
    
    // Check if username exists
    ldmd_user_t existing;
    if (db_user_get_by_username(db, username, &existing) == LDMD_OK) {
        LOG_WARN("User creation failed - username exists: %s", username);
        return LDMD_ERROR_EXISTS;
    }
    
    ldmd_user_t user;
    memset(&user, 0, sizeof(user));
    
    auth_generate_uuid(user.uuid);
    ldmd_strlcpy(user.username, username, LDMD_MAX_USERNAME);
    ldmd_strlcpy(user.email, email, LDMD_MAX_EMAIL);
    
    // Generate temporary password if not provided
    char temp_password[32];
    if (!password || strlen(password) == 0) {
        generate_random_hex(temp_password, 8);
        password = temp_password;
        ldmd_strlcpy(user.generated_password, temp_password, sizeof(user.generated_password));
        user.status = USER_STATUS_PENDING;
        LOG_INFO("Created user %s with auto-generated temporary password", username);
    } else {
        user.generated_password[0] = '\0';
        user.status = USER_STATUS_ACTIVE;
    }
    
    // Hash password
    ldmd_error_t err = auth_hash_password(password, NULL, user.password_hash, user.salt);
    if (err != LDMD_OK) {
        return err;
    }
    
    user.global_role = role;
    // New users always need to change password on first login
    user.password_change_pending = true;
    
    err = db_user_create(db, &user);
    if (err != LDMD_OK) {
        return err;
    }
    
    if (user_out) {
        *user_out = user;
    }
    
    LOG_INFO("User created: %s (role: %d)", username, role);
    return LDMD_OK;
}

ldmd_error_t auth_change_password_first(ldmd_database_t *db, ldmd_config_t *config,
                                        int64_t user_id, const char *current_password,
                                        const char *new_password) {
    ldmd_user_t user;
    ldmd_error_t err = db_user_get_by_id(db, user_id, &user);
    if (err != LDMD_OK) {
        return err;
    }
    
    // Verify current password
    if (!auth_verify_password(current_password, user.password_hash, user.salt)) {
        return LDMD_ERROR_UNAUTHORIZED;
    }
    
    // Check new password length
    if (strlen(new_password) < (size_t)config->password_min_length) {
        return LDMD_ERROR_INVALID;
    }
    
    // Hash new password
    err = auth_hash_password(new_password, NULL, user.password_hash, user.salt);
    if (err != LDMD_OK) {
        return err;
    }
    
    user.status = USER_STATUS_ACTIVE;
    user.password_change_pending = false;
    
    return db_user_update(db, &user);
}

ldmd_error_t auth_request_password_change(ldmd_database_t *db, ldmd_config_t *config,
                                          int64_t user_id, const char *current_password,
                                          const char *new_password) {
    ldmd_user_t user;
    ldmd_error_t err = db_user_get_by_id(db, user_id, &user);
    if (err != LDMD_OK) {
        return err;
    }
    
    // Verify current password
    if (!auth_verify_password(current_password, user.password_hash, user.salt)) {
        return LDMD_ERROR_UNAUTHORIZED;
    }
    
    // Check new password length
    if (strlen(new_password) < (size_t)config->password_min_length) {
        return LDMD_ERROR_INVALID;
    }
    
    // Create password change request
    ldmd_password_request_t request;
    memset(&request, 0, sizeof(request));
    request.user_id = user_id;
    
    err = auth_hash_password(new_password, NULL, request.new_password_hash, request.new_salt);
    if (err != LDMD_OK) {
        return err;
    }
    
    err = db_password_request_create(db, &request);
    if (err != LDMD_OK) {
        return err;
    }
    
    // Mark user as having pending password change
    user.password_change_pending = true;
    user.status = USER_STATUS_PASSWORD_RESET;
    db_user_update(db, &user);
    
    LOG_INFO("Password change requested for user: %s", user.username);
    return LDMD_OK;
}

ldmd_error_t auth_approve_password_change(ldmd_database_t *db, int64_t request_id,
                                          int64_t admin_id) {
    // Get request by iterating pending requests
    ldmd_password_request_t *requests = NULL;
    int count = 0;
    ldmd_error_t err = db_password_request_list_pending(db, &requests, &count);
    if (err != LDMD_OK) {
        return err;
    }
    
    ldmd_password_request_t *found = NULL;
    for (int i = 0; i < count; i++) {
        if (requests[i].id == request_id) {
            found = &requests[i];
            break;
        }
    }
    
    if (!found) {
        free(requests);
        return LDMD_ERROR_NOT_FOUND;
    }
    
    // Get user and update password
    ldmd_user_t user;
    err = db_user_get_by_id(db, found->user_id, &user);
    if (err != LDMD_OK) {
        free(requests);
        return err;
    }
    
    ldmd_strlcpy(user.password_hash, found->new_password_hash, LDMD_HASH_LENGTH);
    ldmd_strlcpy(user.salt, found->new_salt, LDMD_SALT_LENGTH);
    user.password_change_pending = false;
    user.status = USER_STATUS_ACTIVE;
    
    err = db_user_update(db, &user);
    if (err != LDMD_OK) {
        free(requests);
        return err;
    }
    
    // Update request
    found->status = USER_STATUS_ACTIVE;
    found->reviewed_at = utils_now();
    found->reviewed_by = admin_id;
    err = db_password_request_update(db, found);
    
    free(requests);
    
    LOG_INFO("Password change approved for user ID %lld by admin ID %lld", 
             (long long)found->user_id, (long long)admin_id);
    
    return err;
}

ldmd_error_t auth_reject_password_change(ldmd_database_t *db, int64_t request_id,
                                         int64_t admin_id) {
    ldmd_password_request_t *requests = NULL;
    int count = 0;
    ldmd_error_t err = db_password_request_list_pending(db, &requests, &count);
    if (err != LDMD_OK) {
        return err;
    }
    
    ldmd_password_request_t *found = NULL;
    for (int i = 0; i < count; i++) {
        if (requests[i].id == request_id) {
            found = &requests[i];
            break;
        }
    }
    
    if (!found) {
        free(requests);
        return LDMD_ERROR_NOT_FOUND;
    }
    
    // Get user and reset status
    ldmd_user_t user;
    err = db_user_get_by_id(db, found->user_id, &user);
    if (err == LDMD_OK) {
        user.password_change_pending = false;
        user.status = USER_STATUS_ACTIVE;
        db_user_update(db, &user);
    }
    
    // Update request as rejected (status = 2)
    found->status = 2;  // Rejected
    found->reviewed_at = utils_now();
    found->reviewed_by = admin_id;
    err = db_password_request_update(db, found);
    
    free(requests);
    
    LOG_INFO("Password change rejected for user ID %lld by admin ID %lld", 
             (long long)found->user_id, (long long)admin_id);
    
    return err;
}

ldmd_error_t auth_forgot_password(ldmd_database_t *db, const char *username) {
    ldmd_user_t user;
    ldmd_error_t err = db_user_get_by_username(db, username, &user);
    if (err == LDMD_ERROR_NOT_FOUND) {
        // Return OK to avoid username enumeration
        return LDMD_OK;
    }
    if (err != LDMD_OK) return err;

    ldmd_password_forgot_t req;
    memset(&req, 0, sizeof(req));
    req.user_id = user.id;
    ldmd_strlcpy(req.username, user.username, LDMD_MAX_USERNAME);

    err = db_password_forgot_create(db, &req);
    if (err != LDMD_OK) return err;

    LOG_INFO("Forgot-password request created for user: %s", username);
    return LDMD_OK;
}

ldmd_error_t auth_admin_reset_password(ldmd_database_t *db, ldmd_config_t *config,
                                       const char *user_uuid, const char *new_password,
                                       int64_t admin_id) {
    (void)admin_id;

    ldmd_user_t user;
    ldmd_error_t err = db_user_get_by_uuid(db, user_uuid, &user);
    if (err != LDMD_OK) return err;

    if (strlen(new_password) < (size_t)config->password_min_length) {
        return LDMD_ERROR_INVALID;
    }

    err = auth_hash_password(new_password, NULL, user.password_hash, user.salt);
    if (err != LDMD_OK) return err;

    user.password_change_pending = true;
    user.status = USER_STATUS_ACTIVE;

    err = db_user_update(db, &user);
    if (err != LDMD_OK) return err;

    // Invalidate all existing sessions for this user so they must log in fresh
    db_session_delete_by_user(db, user.id);

    LOG_INFO("Admin reset password for user: %s (admin ID %lld)",
             user.username, (long long)admin_id);
    return LDMD_OK;
}

ldmd_error_t auth_handle_forgot_password(ldmd_database_t *db, ldmd_config_t *config,
                                         int64_t request_id, const char *new_password,
                                         int64_t admin_id) {
    ldmd_password_forgot_t *requests = NULL;
    int count = 0;
    ldmd_error_t err = db_password_forgot_list_pending(db, &requests, &count);
    if (err != LDMD_OK) return err;

    ldmd_password_forgot_t *found = NULL;
    for (int i = 0; i < count; i++) {
        if (requests[i].id == request_id) {
            found = &requests[i];
            break;
        }
    }

    if (!found) {
        free(requests);
        return LDMD_ERROR_NOT_FOUND;
    }

    // Reuse admin reset logic (looks up by uuid) — get uuid first
    ldmd_user_t user;
    err = db_user_get_by_id(db, found->user_id, &user);
    if (err != LDMD_OK) { free(requests); return err; }

    if (strlen(new_password) < (size_t)config->password_min_length) {
        free(requests);
        return LDMD_ERROR_INVALID;
    }

    err = auth_hash_password(new_password, NULL, user.password_hash, user.salt);
    if (err != LDMD_OK) { free(requests); return err; }

    user.password_change_pending = true;
    user.status = USER_STATUS_ACTIVE;
    db_user_update(db, &user);
    db_session_delete_by_user(db, user.id);

    // Mark request handled
    found->status = 1;
    found->handled_at = utils_now();
    found->handled_by = admin_id;
    db_password_forgot_update(db, found);

    free(requests);
    LOG_INFO("Forgot-password request %lld handled by admin %lld for user: %s",
             (long long)request_id, (long long)admin_id, user.username);
    return LDMD_OK;
}
