#ifndef LOCALDOCSMD_H
#define LOCALDOCSMD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

// Version information
#define LDMD_VERSION_MAJOR 1
#define LDMD_VERSION_MINOR 0
#define LDMD_VERSION_PATCH 0
#define LDMD_VERSION_STRING "1.0.0"

// Common constants
#define LDMD_MAX_PATH 4096
#define LDMD_MAX_USERNAME 64
#define LDMD_MAX_EMAIL 256
#define LDMD_MAX_NAME 256
#define LDMD_MAX_DESCRIPTION 1024
#define LDMD_UUID_LENGTH 37
#define LDMD_HASH_LENGTH 65
#define LDMD_TOKEN_LENGTH 65
#define LDMD_SALT_LENGTH 33

// Error codes
typedef enum {
    LDMD_OK = 0,
    LDMD_ERROR = -1,
    LDMD_ERROR_MEMORY = -2,
    LDMD_ERROR_IO = -3,
    LDMD_ERROR_DATABASE = -4,
    LDMD_ERROR_NOT_FOUND = -5,
    LDMD_ERROR_UNAUTHORIZED = -6,
    LDMD_ERROR_FORBIDDEN = -7,
    LDMD_ERROR_INVALID = -8,
    LDMD_ERROR_EXISTS = -9,
    LDMD_ERROR_CONFIG = -10
} ldmd_error_t;

// User roles
typedef enum {
    ROLE_NONE = 0,
    ROLE_USER = 1,      // Regular user (global) / Viewer (workspace)
    ROLE_EDITOR = 2,    // Editor (workspace only)
    ROLE_ADMIN = 3      // Admin (global and workspace)
} ldmd_role_t;

// User status
typedef enum {
    USER_STATUS_PENDING = 0,      // Awaiting first login
    USER_STATUS_ACTIVE = 1,       // Active user
    USER_STATUS_LOCKED = 2,       // Locked out
    USER_STATUS_DISABLED = 3,     // Disabled by admin
    USER_STATUS_PASSWORD_RESET = 4 // Requires password approval
} ldmd_user_status_t;

// Forward declarations
typedef struct ldmd_config ldmd_config_t;
typedef struct ldmd_database ldmd_database_t;
typedef struct ldmd_session ldmd_session_t;
typedef struct ldmd_user ldmd_user_t;
typedef struct ldmd_workspace ldmd_workspace_t;
typedef struct ldmd_project ldmd_project_t;
typedef struct ldmd_document ldmd_document_t;
typedef struct ldmd_server ldmd_server_t;

// User structure
struct ldmd_user {
    int64_t id;
    char uuid[LDMD_UUID_LENGTH];
    char username[LDMD_MAX_USERNAME];
    char email[LDMD_MAX_EMAIL];
    char password_hash[LDMD_HASH_LENGTH];
    char salt[LDMD_SALT_LENGTH];
    ldmd_role_t global_role;
    ldmd_user_status_t status;
    int login_attempts;
    time_t locked_until;
    time_t created_at;
    time_t updated_at;
    time_t last_login;
    bool password_change_pending;
    // Only populated transiently when a random temp password was auto-generated;
    // never stored in the database.
    char generated_password[32];
};

// Workspace structure
struct ldmd_workspace {
    int64_t id;
    char uuid[LDMD_UUID_LENGTH];
    char name[LDMD_MAX_NAME];
    char description[LDMD_MAX_DESCRIPTION];
    int64_t owner_id;
    time_t created_at;
    time_t updated_at;
};

// Project structure
struct ldmd_project {
    int64_t id;
    char uuid[LDMD_UUID_LENGTH];
    char name[LDMD_MAX_NAME];
    char description[LDMD_MAX_DESCRIPTION];
    int64_t workspace_id;
    int64_t created_by;
    time_t created_at;
    time_t updated_at;
};

// Document structure
struct ldmd_document {
    int64_t id;
    char uuid[LDMD_UUID_LENGTH];
    char name[LDMD_MAX_NAME];
    char path[LDMD_MAX_PATH];
    int64_t project_id;
    int64_t created_by;
    int64_t updated_by;
    time_t created_at;
    time_t updated_at;
};

// Session structure
struct ldmd_session {
    int64_t id;
    char token[LDMD_TOKEN_LENGTH];
    int64_t user_id;
    char ip_address[64];
    char user_agent[512];
    time_t created_at;
    time_t expires_at;
    bool is_admin_session;
};

// Workspace membership
typedef struct {
    int64_t id;
    int64_t workspace_id;
    int64_t user_id;
    ldmd_role_t role;
    time_t created_at;
} ldmd_workspace_member_t;

// Project membership (view permissions)
typedef struct {
    int64_t id;
    int64_t project_id;
    int64_t user_id;
    bool can_view;
    int64_t granted_by;
    time_t created_at;
} ldmd_project_member_t;

// Password change request (by a logged-in user, pending admin approval)
typedef struct {
    int64_t id;
    int64_t user_id;
    char new_password_hash[LDMD_HASH_LENGTH];
    char new_salt[LDMD_SALT_LENGTH];
    ldmd_user_status_t status;
    time_t created_at;
    time_t reviewed_at;
    int64_t reviewed_by;
} ldmd_password_request_t;

// Forgot-password request (by an unauthenticated user who cannot log in)
typedef struct {
    int64_t id;
    int64_t user_id;
    char username[LDMD_MAX_USERNAME];  // denormalised for display
    int status;                        // 0 = pending, 1 = handled
    time_t created_at;
    time_t handled_at;
    int64_t handled_by;
} ldmd_password_forgot_t;

// Global application context
typedef struct {
    ldmd_config_t *config;
    ldmd_database_t *db;
    ldmd_server_t *server;
    bool running;
} ldmd_app_t;

// Utility macros
#define LDMD_MIN(a, b) ((a) < (b) ? (a) : (b))
#define LDMD_MAX(a, b) ((a) > (b) ? (a) : (b))
#define LDMD_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// Safe string copy
static inline void ldmd_strlcpy(char *dst, const char *src, size_t size) {
    if (size > 0) {
        strncpy(dst, src, size - 1);
        dst[size - 1] = '\0';
    }
}

#endif // LOCALDOCSMD_H
