#include "database.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// SQL schema
static const char *SCHEMA_SQL = 
    // Users table
    "CREATE TABLE IF NOT EXISTS users ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  uuid TEXT UNIQUE NOT NULL,"
    "  username TEXT UNIQUE NOT NULL,"
    "  email TEXT UNIQUE NOT NULL,"
    "  password_hash TEXT NOT NULL,"
    "  salt TEXT NOT NULL,"
    "  global_role INTEGER NOT NULL DEFAULT 1,"
    "  status INTEGER NOT NULL DEFAULT 0,"
    "  login_attempts INTEGER NOT NULL DEFAULT 0,"
    "  locked_until INTEGER DEFAULT 0,"
    "  password_change_pending INTEGER NOT NULL DEFAULT 0,"
    "  created_at INTEGER NOT NULL,"
    "  updated_at INTEGER NOT NULL,"
    "  last_login INTEGER DEFAULT 0"
    ");"
    
    // Sessions table
    "CREATE TABLE IF NOT EXISTS sessions ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  token TEXT UNIQUE NOT NULL,"
    "  user_id INTEGER NOT NULL,"
    "  ip_address TEXT,"
    "  user_agent TEXT,"
    "  is_admin_session INTEGER NOT NULL DEFAULT 0,"
    "  created_at INTEGER NOT NULL,"
    "  expires_at INTEGER NOT NULL,"
    "  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"
    ");"
    
    // Workspaces table
    "CREATE TABLE IF NOT EXISTS workspaces ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  uuid TEXT UNIQUE NOT NULL,"
    "  name TEXT NOT NULL,"
    "  description TEXT,"
    "  owner_id INTEGER NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  updated_at INTEGER NOT NULL,"
    "  FOREIGN KEY (owner_id) REFERENCES users(id)"
    ");"
    
    // Workspace members table
    "CREATE TABLE IF NOT EXISTS workspace_members ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  workspace_id INTEGER NOT NULL,"
    "  user_id INTEGER NOT NULL,"
    "  role INTEGER NOT NULL DEFAULT 1,"
    "  created_at INTEGER NOT NULL,"
    "  UNIQUE(workspace_id, user_id),"
    "  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,"
    "  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"
    ");"
    
    // Projects table
    "CREATE TABLE IF NOT EXISTS projects ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  uuid TEXT UNIQUE NOT NULL,"
    "  workspace_id INTEGER NOT NULL,"
    "  name TEXT NOT NULL,"
    "  description TEXT,"
    "  created_by INTEGER NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  updated_at INTEGER NOT NULL,"
    "  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,"
    "  FOREIGN KEY (created_by) REFERENCES users(id)"
    ");"
    
    // Documents table
    "CREATE TABLE IF NOT EXISTS documents ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  uuid TEXT UNIQUE NOT NULL,"
    "  project_id INTEGER NOT NULL,"
    "  name TEXT NOT NULL,"
    "  path TEXT NOT NULL,"
    "  created_by INTEGER NOT NULL,"
    "  updated_by INTEGER,"
    "  created_at INTEGER NOT NULL,"
    "  updated_at INTEGER NOT NULL,"
    "  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,"
    "  FOREIGN KEY (created_by) REFERENCES users(id),"
    "  FOREIGN KEY (updated_by) REFERENCES users(id)"
    ");"
    
    // Project members table - for granting view access to individual projects
    "CREATE TABLE IF NOT EXISTS project_members ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  project_id INTEGER NOT NULL,"
    "  user_id INTEGER NOT NULL,"
    "  can_view INTEGER NOT NULL DEFAULT 1,"
    "  granted_by INTEGER NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  UNIQUE(project_id, user_id),"
    "  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,"
    "  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,"
    "  FOREIGN KEY (granted_by) REFERENCES users(id)"
    ");"
    
    // Password change requests table
    "CREATE TABLE IF NOT EXISTS password_requests ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  user_id INTEGER NOT NULL,"
    "  new_password_hash TEXT NOT NULL,"
    "  new_salt TEXT NOT NULL,"
    "  status INTEGER NOT NULL DEFAULT 0,"
    "  created_at INTEGER NOT NULL,"
    "  reviewed_at INTEGER DEFAULT 0,"
    "  reviewed_by INTEGER DEFAULT 0,"
    "  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"
    ");"
    
    // Indexes
    "CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);"
    "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);"
    "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);"
    "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);"
    "CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);"
    "CREATE INDEX IF NOT EXISTS idx_workspaces_uuid ON workspaces(uuid);"
    "CREATE INDEX IF NOT EXISTS idx_projects_uuid ON projects(uuid);"
    "CREATE INDEX IF NOT EXISTS idx_projects_workspace ON projects(workspace_id);"
    "CREATE INDEX IF NOT EXISTS idx_documents_uuid ON documents(uuid);"
    "CREATE INDEX IF NOT EXISTS idx_documents_project ON documents(project_id);"
    "CREATE INDEX IF NOT EXISTS idx_workspace_members_workspace ON workspace_members(workspace_id);"
    "CREATE INDEX IF NOT EXISTS idx_workspace_members_user ON workspace_members(user_id);"
    "CREATE INDEX IF NOT EXISTS idx_project_members_project ON project_members(project_id);"
    "CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members(user_id);";

ldmd_database_t *db_init(const char *path) {
    ldmd_database_t *db = calloc(1, sizeof(ldmd_database_t));
    if (!db) {
        LOG_ERROR("Failed to allocate database structure");
        return NULL;
    }
    
    ldmd_strlcpy(db->path, path, sizeof(db->path));
    
    // Create directory if needed
    char dir[LDMD_MAX_PATH];
    ldmd_strlcpy(dir, path, sizeof(dir));
    char *last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        if (utils_mkdir_p(dir) != LDMD_OK) {
            free(db);
            return NULL;
        }
    }
    
    // Open database
    int rc = sqlite3_open(path, &db->db);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to open database: %s", sqlite3_errmsg(db->db));
        sqlite3_close(db->db);
        free(db);
        return NULL;
    }
    
    // Enable foreign keys
    sqlite3_exec(db->db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
    
    // Create schema
    char *errmsg = NULL;
    rc = sqlite3_exec(db->db, SCHEMA_SQL, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to create schema: %s", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(db->db);
        free(db);
        return NULL;
    }
    
    db->initialized = true;
    LOG_INFO("Database initialized: %s", path);
    
    return db;
}

void db_close(ldmd_database_t *db) {
    if (db) {
        if (db->db) {
            sqlite3_close(db->db);
        }
        free(db);
    }
}

ldmd_error_t db_exec(ldmd_database_t *db, const char *sql) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(db->db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("SQL error: %s", errmsg);
        sqlite3_free(errmsg);
        return LDMD_ERROR_DATABASE;
    }
    return LDMD_OK;
}

ldmd_error_t db_begin(ldmd_database_t *db) {
    return db_exec(db, "BEGIN TRANSACTION;");
}

ldmd_error_t db_commit(ldmd_database_t *db) {
    return db_exec(db, "COMMIT;");
}

ldmd_error_t db_rollback(ldmd_database_t *db) {
    return db_exec(db, "ROLLBACK;");
}

// User operations
ldmd_error_t db_user_create(ldmd_database_t *db, ldmd_user_t *user) {
    const char *sql = 
        "INSERT INTO users (uuid, username, email, password_hash, salt, global_role, "
        "status, login_attempts, locked_until, password_change_pending, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to prepare statement: %s", sqlite3_errmsg(db->db));
        return LDMD_ERROR_DATABASE;
    }
    
    time_t now = utils_now();
    user->created_at = now;
    user->updated_at = now;
    
    sqlite3_bind_text(stmt, 1, user->uuid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, user->email, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, user->password_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, user->salt, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, user->global_role);
    sqlite3_bind_int(stmt, 7, user->status);
    sqlite3_bind_int(stmt, 8, user->login_attempts);
    sqlite3_bind_int64(stmt, 9, user->locked_until);
    sqlite3_bind_int(stmt, 10, user->password_change_pending ? 1 : 0);
    sqlite3_bind_int64(stmt, 11, user->created_at);
    sqlite3_bind_int64(stmt, 12, user->updated_at);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to create user: %s", sqlite3_errmsg(db->db));
        return LDMD_ERROR_DATABASE;
    }
    
    user->id = sqlite3_last_insert_rowid(db->db);
    return LDMD_OK;
}

static void fill_user_from_stmt(sqlite3_stmt *stmt, ldmd_user_t *user) {
    user->id = sqlite3_column_int64(stmt, 0);
    ldmd_strlcpy(user->uuid, (const char *)sqlite3_column_text(stmt, 1), LDMD_UUID_LENGTH);
    ldmd_strlcpy(user->username, (const char *)sqlite3_column_text(stmt, 2), LDMD_MAX_USERNAME);
    ldmd_strlcpy(user->email, (const char *)sqlite3_column_text(stmt, 3), LDMD_MAX_EMAIL);
    ldmd_strlcpy(user->password_hash, (const char *)sqlite3_column_text(stmt, 4), LDMD_HASH_LENGTH);
    ldmd_strlcpy(user->salt, (const char *)sqlite3_column_text(stmt, 5), LDMD_SALT_LENGTH);
    user->global_role = sqlite3_column_int(stmt, 6);
    user->status = sqlite3_column_int(stmt, 7);
    user->login_attempts = sqlite3_column_int(stmt, 8);
    user->locked_until = sqlite3_column_int64(stmt, 9);
    user->password_change_pending = sqlite3_column_int(stmt, 10) != 0;
    user->created_at = sqlite3_column_int64(stmt, 11);
    user->updated_at = sqlite3_column_int64(stmt, 12);
    user->last_login = sqlite3_column_int64(stmt, 13);
}

ldmd_error_t db_user_get_by_id(ldmd_database_t *db, int64_t id, ldmd_user_t *user) {
    const char *sql = "SELECT id, uuid, username, email, password_hash, salt, "
                      "global_role, status, login_attempts, locked_until, "
                      "password_change_pending, created_at, updated_at, last_login "
                      "FROM users WHERE id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, id);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        fill_user_from_stmt(stmt, user);
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_user_get_by_username(ldmd_database_t *db, const char *username, ldmd_user_t *user) {
    const char *sql = "SELECT id, uuid, username, email, password_hash, salt, "
                      "global_role, status, login_attempts, locked_until, "
                      "password_change_pending, created_at, updated_at, last_login "
                      "FROM users WHERE username = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        fill_user_from_stmt(stmt, user);
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_user_get_by_uuid(ldmd_database_t *db, const char *uuid, ldmd_user_t *user) {
    const char *sql = "SELECT id, uuid, username, email, password_hash, salt, "
                      "global_role, status, login_attempts, locked_until, "
                      "password_change_pending, created_at, updated_at, last_login "
                      "FROM users WHERE uuid = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        fill_user_from_stmt(stmt, user);
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_user_update(ldmd_database_t *db, ldmd_user_t *user) {
    const char *sql = 
        "UPDATE users SET username=?, email=?, password_hash=?, salt=?, "
        "global_role=?, status=?, login_attempts=?, locked_until=?, "
        "password_change_pending=?, updated_at=?, last_login=? WHERE id=?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    user->updated_at = utils_now();
    
    sqlite3_bind_text(stmt, 1, user->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user->email, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, user->password_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, user->salt, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, user->global_role);
    sqlite3_bind_int(stmt, 6, user->status);
    sqlite3_bind_int(stmt, 7, user->login_attempts);
    sqlite3_bind_int64(stmt, 8, user->locked_until);
    sqlite3_bind_int(stmt, 9, user->password_change_pending ? 1 : 0);
    sqlite3_bind_int64(stmt, 10, user->updated_at);
    sqlite3_bind_int64(stmt, 11, user->last_login);
    sqlite3_bind_int64(stmt, 12, user->id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_user_delete(ldmd_database_t *db, int64_t id) {
    const char *sql = "DELETE FROM users WHERE id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_user_list(ldmd_database_t *db, ldmd_user_t **users, int *count) {
    const char *count_sql = "SELECT COUNT(*) FROM users;";
    const char *sql = "SELECT id, uuid, username, email, password_hash, salt, "
                      "global_role, status, login_attempts, locked_until, "
                      "password_change_pending, created_at, updated_at, last_login "
                      "FROM users ORDER BY username;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    rc = sqlite3_step(stmt);
    *count = (rc == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : 0;
    sqlite3_finalize(stmt);
    
    if (*count == 0) {
        *users = NULL;
        return LDMD_OK;
    }
    
    *users = calloc(*count, sizeof(ldmd_user_t));
    if (!*users) {
        return LDMD_ERROR_MEMORY;
    }
    
    rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(*users);
        *users = NULL;
        return LDMD_ERROR_DATABASE;
    }
    
    int i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < *count) {
        fill_user_from_stmt(stmt, &(*users)[i++]);
    }
    
    sqlite3_finalize(stmt);
    *count = i;
    
    return LDMD_OK;
}

ldmd_error_t db_user_count(ldmd_database_t *db, int *count) {
    const char *sql = "SELECT COUNT(*) FROM users;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    rc = sqlite3_step(stmt);
    *count = (rc == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : 0;
    sqlite3_finalize(stmt);
    
    return LDMD_OK;
}

// Session operations
ldmd_error_t db_session_create(ldmd_database_t *db, ldmd_session_t *session) {
    const char *sql = 
        "INSERT INTO sessions (token, user_id, ip_address, user_agent, "
        "is_admin_session, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?);";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_text(stmt, 1, session->token, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, session->user_id);
    sqlite3_bind_text(stmt, 3, session->ip_address, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, session->user_agent, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, session->is_admin_session ? 1 : 0);
    sqlite3_bind_int64(stmt, 6, session->created_at);
    sqlite3_bind_int64(stmt, 7, session->expires_at);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        return LDMD_ERROR_DATABASE;
    }
    
    session->id = sqlite3_last_insert_rowid(db->db);
    return LDMD_OK;
}

ldmd_error_t db_session_get(ldmd_database_t *db, const char *token, ldmd_session_t *session) {
    const char *sql = "SELECT id, token, user_id, ip_address, user_agent, "
                      "is_admin_session, created_at, expires_at "
                      "FROM sessions WHERE token = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        session->id = sqlite3_column_int64(stmt, 0);
        ldmd_strlcpy(session->token, (const char *)sqlite3_column_text(stmt, 1), LDMD_TOKEN_LENGTH);
        session->user_id = sqlite3_column_int64(stmt, 2);
        const char *ip = (const char *)sqlite3_column_text(stmt, 3);
        if (ip) ldmd_strlcpy(session->ip_address, ip, sizeof(session->ip_address));
        const char *ua = (const char *)sqlite3_column_text(stmt, 4);
        if (ua) ldmd_strlcpy(session->user_agent, ua, sizeof(session->user_agent));
        session->is_admin_session = sqlite3_column_int(stmt, 5) != 0;
        session->created_at = sqlite3_column_int64(stmt, 6);
        session->expires_at = sqlite3_column_int64(stmt, 7);
        
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_session_delete(ldmd_database_t *db, const char *token) {
    const char *sql = "DELETE FROM sessions WHERE token = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_session_cleanup(ldmd_database_t *db) {
    const char *sql = "DELETE FROM sessions WHERE expires_at < ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, utils_now());
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_session_delete_by_user(ldmd_database_t *db, int64_t user_id) {
    const char *sql = "DELETE FROM sessions WHERE user_id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, user_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

// Workspace operations
ldmd_error_t db_workspace_create(ldmd_database_t *db, ldmd_workspace_t *workspace) {
    const char *sql = 
        "INSERT INTO workspaces (uuid, name, description, owner_id, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?);";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    time_t now = utils_now();
    workspace->created_at = now;
    workspace->updated_at = now;
    
    sqlite3_bind_text(stmt, 1, workspace->uuid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, workspace->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, workspace->description, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, workspace->owner_id);
    sqlite3_bind_int64(stmt, 5, workspace->created_at);
    sqlite3_bind_int64(stmt, 6, workspace->updated_at);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        return LDMD_ERROR_DATABASE;
    }
    
    workspace->id = sqlite3_last_insert_rowid(db->db);
    return LDMD_OK;
}

static void fill_workspace_from_stmt(sqlite3_stmt *stmt, ldmd_workspace_t *workspace) {
    workspace->id = sqlite3_column_int64(stmt, 0);
    ldmd_strlcpy(workspace->uuid, (const char *)sqlite3_column_text(stmt, 1), LDMD_UUID_LENGTH);
    ldmd_strlcpy(workspace->name, (const char *)sqlite3_column_text(stmt, 2), LDMD_MAX_NAME);
    const char *desc = (const char *)sqlite3_column_text(stmt, 3);
    if (desc) ldmd_strlcpy(workspace->description, desc, LDMD_MAX_DESCRIPTION);
    workspace->owner_id = sqlite3_column_int64(stmt, 4);
    workspace->created_at = sqlite3_column_int64(stmt, 5);
    workspace->updated_at = sqlite3_column_int64(stmt, 6);
}

ldmd_error_t db_workspace_get_by_id(ldmd_database_t *db, int64_t id, ldmd_workspace_t *workspace) {
    const char *sql = "SELECT id, uuid, name, description, owner_id, created_at, updated_at "
                      "FROM workspaces WHERE id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, id);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        fill_workspace_from_stmt(stmt, workspace);
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_workspace_get_by_uuid(ldmd_database_t *db, const char *uuid, ldmd_workspace_t *workspace) {
    const char *sql = "SELECT id, uuid, name, description, owner_id, created_at, updated_at "
                      "FROM workspaces WHERE uuid = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        fill_workspace_from_stmt(stmt, workspace);
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_workspace_update(ldmd_database_t *db, ldmd_workspace_t *workspace) {
    const char *sql = "UPDATE workspaces SET name=?, description=?, updated_at=? WHERE id=?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    workspace->updated_at = utils_now();
    
    sqlite3_bind_text(stmt, 1, workspace->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, workspace->description, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, workspace->updated_at);
    sqlite3_bind_int64(stmt, 4, workspace->id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_workspace_delete(ldmd_database_t *db, int64_t id) {
    const char *sql = "DELETE FROM workspaces WHERE id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_workspace_list(ldmd_database_t *db, ldmd_workspace_t **workspaces, int *count) {
    const char *count_sql = "SELECT COUNT(*) FROM workspaces;";
    const char *sql = "SELECT id, uuid, name, description, owner_id, created_at, updated_at "
                      "FROM workspaces ORDER BY name;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    rc = sqlite3_step(stmt);
    *count = (rc == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : 0;
    sqlite3_finalize(stmt);
    
    if (*count == 0) {
        *workspaces = NULL;
        return LDMD_OK;
    }
    
    *workspaces = calloc(*count, sizeof(ldmd_workspace_t));
    if (!*workspaces) {
        return LDMD_ERROR_MEMORY;
    }
    
    rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(*workspaces);
        *workspaces = NULL;
        return LDMD_ERROR_DATABASE;
    }
    
    int i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < *count) {
        fill_workspace_from_stmt(stmt, &(*workspaces)[i++]);
    }
    
    sqlite3_finalize(stmt);
    *count = i;
    
    return LDMD_OK;
}

ldmd_error_t db_workspace_list_for_user(ldmd_database_t *db, int64_t user_id, 
                                        ldmd_workspace_t **workspaces, int *count) {
    const char *sql = 
        "SELECT DISTINCT w.id, w.uuid, w.name, w.description, w.owner_id, w.created_at, w.updated_at "
        "FROM workspaces w "
        "LEFT JOIN workspace_members wm ON w.id = wm.workspace_id "
        "WHERE w.owner_id = ? OR wm.user_id = ? "
        "ORDER BY w.name;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, user_id);
    sqlite3_bind_int64(stmt, 2, user_id);
    
    // First pass to count
    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) n++;
    sqlite3_reset(stmt);
    
    *count = n;
    if (n == 0) {
        *workspaces = NULL;
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    *workspaces = calloc(n, sizeof(ldmd_workspace_t));
    if (!*workspaces) {
        sqlite3_finalize(stmt);
        return LDMD_ERROR_MEMORY;
    }
    
    int i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < n) {
        fill_workspace_from_stmt(stmt, &(*workspaces)[i++]);
    }
    
    sqlite3_finalize(stmt);
    *count = i;
    
    return LDMD_OK;
}

// Workspace member operations
ldmd_error_t db_workspace_member_add(ldmd_database_t *db, ldmd_workspace_member_t *member) {
    const char *sql = 
        "INSERT INTO workspace_members (workspace_id, user_id, role, created_at) "
        "VALUES (?, ?, ?, ?);";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    member->created_at = utils_now();
    
    sqlite3_bind_int64(stmt, 1, member->workspace_id);
    sqlite3_bind_int64(stmt, 2, member->user_id);
    sqlite3_bind_int(stmt, 3, member->role);
    sqlite3_bind_int64(stmt, 4, member->created_at);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        return LDMD_ERROR_DATABASE;
    }
    
    member->id = sqlite3_last_insert_rowid(db->db);
    return LDMD_OK;
}

ldmd_error_t db_workspace_member_remove(ldmd_database_t *db, int64_t workspace_id, int64_t user_id) {
    const char *sql = "DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, workspace_id);
    sqlite3_bind_int64(stmt, 2, user_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_workspace_member_get_role(ldmd_database_t *db, int64_t workspace_id, 
                                          int64_t user_id, ldmd_role_t *role) {
    const char *sql = "SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, workspace_id);
    sqlite3_bind_int64(stmt, 2, user_id);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *role = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    *role = ROLE_NONE;
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_workspace_member_update_role(ldmd_database_t *db, int64_t workspace_id, 
                                             int64_t user_id, ldmd_role_t role) {
    const char *sql = "UPDATE workspace_members SET role = ? WHERE workspace_id = ? AND user_id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int(stmt, 1, role);
    sqlite3_bind_int64(stmt, 2, workspace_id);
    sqlite3_bind_int64(stmt, 3, user_id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_workspace_member_list(ldmd_database_t *db, int64_t workspace_id, 
                                      ldmd_workspace_member_t **members, int *count) {
    const char *sql = "SELECT id, workspace_id, user_id, role, created_at "
                      "FROM workspace_members WHERE workspace_id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, workspace_id);
    
    // First pass to count
    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) n++;
    sqlite3_reset(stmt);
    
    *count = n;
    if (n == 0) {
        *members = NULL;
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    *members = calloc(n, sizeof(ldmd_workspace_member_t));
    if (!*members) {
        sqlite3_finalize(stmt);
        return LDMD_ERROR_MEMORY;
    }
    
    int i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < n) {
        (*members)[i].id = sqlite3_column_int64(stmt, 0);
        (*members)[i].workspace_id = sqlite3_column_int64(stmt, 1);
        (*members)[i].user_id = sqlite3_column_int64(stmt, 2);
        (*members)[i].role = sqlite3_column_int(stmt, 3);
        (*members)[i].created_at = sqlite3_column_int64(stmt, 4);
        i++;
    }
    
    sqlite3_finalize(stmt);
    *count = i;
    
    return LDMD_OK;
}

// Project operations
ldmd_error_t db_project_create(ldmd_database_t *db, ldmd_project_t *project) {
    const char *sql = 
        "INSERT INTO projects (uuid, workspace_id, name, description, created_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    time_t now = utils_now();
    project->created_at = now;
    project->updated_at = now;
    
    sqlite3_bind_text(stmt, 1, project->uuid, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, project->workspace_id);
    sqlite3_bind_text(stmt, 3, project->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, project->description, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, project->created_by);
    sqlite3_bind_int64(stmt, 6, project->created_at);
    sqlite3_bind_int64(stmt, 7, project->updated_at);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        return LDMD_ERROR_DATABASE;
    }
    
    project->id = sqlite3_last_insert_rowid(db->db);
    return LDMD_OK;
}

static void fill_project_from_stmt(sqlite3_stmt *stmt, ldmd_project_t *project) {
    project->id = sqlite3_column_int64(stmt, 0);
    ldmd_strlcpy(project->uuid, (const char *)sqlite3_column_text(stmt, 1), LDMD_UUID_LENGTH);
    project->workspace_id = sqlite3_column_int64(stmt, 2);
    ldmd_strlcpy(project->name, (const char *)sqlite3_column_text(stmt, 3), LDMD_MAX_NAME);
    const char *desc = (const char *)sqlite3_column_text(stmt, 4);
    if (desc) ldmd_strlcpy(project->description, desc, LDMD_MAX_DESCRIPTION);
    project->created_by = sqlite3_column_int64(stmt, 5);
    project->created_at = sqlite3_column_int64(stmt, 6);
    project->updated_at = sqlite3_column_int64(stmt, 7);
}

ldmd_error_t db_project_get_by_id(ldmd_database_t *db, int64_t id, ldmd_project_t *project) {
    const char *sql = "SELECT id, uuid, workspace_id, name, description, created_by, created_at, updated_at "
                      "FROM projects WHERE id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, id);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        fill_project_from_stmt(stmt, project);
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_project_get_by_uuid(ldmd_database_t *db, const char *uuid, ldmd_project_t *project) {
    const char *sql = "SELECT id, uuid, workspace_id, name, description, created_by, created_at, updated_at "
                      "FROM projects WHERE uuid = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        fill_project_from_stmt(stmt, project);
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_project_update(ldmd_database_t *db, ldmd_project_t *project) {
    const char *sql = "UPDATE projects SET name=?, description=?, updated_at=? WHERE id=?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    project->updated_at = utils_now();
    
    sqlite3_bind_text(stmt, 1, project->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, project->description, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, project->updated_at);
    sqlite3_bind_int64(stmt, 4, project->id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_project_delete(ldmd_database_t *db, int64_t id) {
    const char *sql = "DELETE FROM projects WHERE id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_project_list(ldmd_database_t *db, int64_t workspace_id, 
                             ldmd_project_t **projects, int *count) {
    const char *sql = "SELECT id, uuid, workspace_id, name, description, created_by, created_at, updated_at "
                      "FROM projects WHERE workspace_id = ? ORDER BY name;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, workspace_id);
    
    // First pass to count
    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) n++;
    sqlite3_reset(stmt);
    
    *count = n;
    if (n == 0) {
        *projects = NULL;
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    *projects = calloc(n, sizeof(ldmd_project_t));
    if (!*projects) {
        sqlite3_finalize(stmt);
        return LDMD_ERROR_MEMORY;
    }
    
    int i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < n) {
        fill_project_from_stmt(stmt, &(*projects)[i++]);
    }
    
    sqlite3_finalize(stmt);
    *count = i;
    
    return LDMD_OK;
}

// Project member operations (view permissions)
ldmd_error_t db_project_member_add(ldmd_database_t *db, ldmd_project_member_t *member) {
    const char *sql = 
        "INSERT INTO project_members (project_id, user_id, can_view, granted_by, created_at) "
        "VALUES (?, ?, ?, ?, ?);";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    member->created_at = utils_now();
    
    sqlite3_bind_int64(stmt, 1, member->project_id);
    sqlite3_bind_int64(stmt, 2, member->user_id);
    sqlite3_bind_int(stmt, 3, member->can_view ? 1 : 0);
    sqlite3_bind_int64(stmt, 4, member->granted_by);
    sqlite3_bind_int64(stmt, 5, member->created_at);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        return LDMD_ERROR_DATABASE;
    }
    
    member->id = sqlite3_last_insert_rowid(db->db);
    return LDMD_OK;
}

ldmd_error_t db_project_member_remove(ldmd_database_t *db, int64_t project_id, int64_t user_id) {
    const char *sql = "DELETE FROM project_members WHERE project_id = ? AND user_id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, project_id);
    sqlite3_bind_int64(stmt, 2, user_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_project_member_check(ldmd_database_t *db, int64_t project_id, 
                                     int64_t user_id, bool *can_view) {
    const char *sql = "SELECT can_view FROM project_members WHERE project_id = ? AND user_id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, project_id);
    sqlite3_bind_int64(stmt, 2, user_id);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *can_view = sqlite3_column_int(stmt, 0) != 0;
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    *can_view = false;
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_project_member_list(ldmd_database_t *db, int64_t project_id,
                                    ldmd_project_member_t **members, int *count) {
    const char *sql = "SELECT id, project_id, user_id, can_view, granted_by, created_at "
                      "FROM project_members WHERE project_id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, project_id);
    
    // First pass to count
    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) n++;
    sqlite3_reset(stmt);
    
    *count = n;
    if (n == 0) {
        *members = NULL;
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    *members = calloc(n, sizeof(ldmd_project_member_t));
    if (!*members) {
        sqlite3_finalize(stmt);
        return LDMD_ERROR_MEMORY;
    }
    
    int i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < n) {
        (*members)[i].id = sqlite3_column_int64(stmt, 0);
        (*members)[i].project_id = sqlite3_column_int64(stmt, 1);
        (*members)[i].user_id = sqlite3_column_int64(stmt, 2);
        (*members)[i].can_view = sqlite3_column_int(stmt, 3) != 0;
        (*members)[i].granted_by = sqlite3_column_int64(stmt, 4);
        (*members)[i].created_at = sqlite3_column_int64(stmt, 5);
        i++;
    }
    
    sqlite3_finalize(stmt);
    *count = i;
    
    return LDMD_OK;
}

// Document operations
ldmd_error_t db_document_create(ldmd_database_t *db, ldmd_document_t *document) {
    const char *sql = 
        "INSERT INTO documents (uuid, project_id, name, path, created_by, updated_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    time_t now = utils_now();
    document->created_at = now;
    document->updated_at = now;
    
    sqlite3_bind_text(stmt, 1, document->uuid, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, document->project_id);
    sqlite3_bind_text(stmt, 3, document->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, document->path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, document->created_by);
    sqlite3_bind_int64(stmt, 6, document->updated_by);
    sqlite3_bind_int64(stmt, 7, document->created_at);
    sqlite3_bind_int64(stmt, 8, document->updated_at);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        return LDMD_ERROR_DATABASE;
    }
    
    document->id = sqlite3_last_insert_rowid(db->db);
    return LDMD_OK;
}

static void fill_document_from_stmt(sqlite3_stmt *stmt, ldmd_document_t *document) {
    document->id = sqlite3_column_int64(stmt, 0);
    ldmd_strlcpy(document->uuid, (const char *)sqlite3_column_text(stmt, 1), LDMD_UUID_LENGTH);
    document->project_id = sqlite3_column_int64(stmt, 2);
    ldmd_strlcpy(document->name, (const char *)sqlite3_column_text(stmt, 3), LDMD_MAX_NAME);
    ldmd_strlcpy(document->path, (const char *)sqlite3_column_text(stmt, 4), LDMD_MAX_PATH);
    document->created_by = sqlite3_column_int64(stmt, 5);
    document->updated_by = sqlite3_column_int64(stmt, 6);
    document->created_at = sqlite3_column_int64(stmt, 7);
    document->updated_at = sqlite3_column_int64(stmt, 8);
}

ldmd_error_t db_document_get_by_id(ldmd_database_t *db, int64_t id, ldmd_document_t *document) {
    const char *sql = "SELECT id, uuid, project_id, name, path, created_by, updated_by, created_at, updated_at "
                      "FROM documents WHERE id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, id);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        fill_document_from_stmt(stmt, document);
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_document_get_by_uuid(ldmd_database_t *db, const char *uuid, ldmd_document_t *document) {
    const char *sql = "SELECT id, uuid, project_id, name, path, created_by, updated_by, created_at, updated_at "
                      "FROM documents WHERE uuid = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        fill_document_from_stmt(stmt, document);
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_document_update(ldmd_database_t *db, ldmd_document_t *document) {
    const char *sql = "UPDATE documents SET name=?, path=?, updated_by=?, updated_at=? WHERE id=?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    document->updated_at = utils_now();
    
    sqlite3_bind_text(stmt, 1, document->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, document->path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, document->updated_by);
    sqlite3_bind_int64(stmt, 4, document->updated_at);
    sqlite3_bind_int64(stmt, 5, document->id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_document_delete(ldmd_database_t *db, int64_t id) {
    const char *sql = "DELETE FROM documents WHERE id = ?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_document_list(ldmd_database_t *db, int64_t project_id, 
                              ldmd_document_t **documents, int *count) {
    const char *sql = "SELECT id, uuid, project_id, name, path, created_by, updated_by, created_at, updated_at "
                      "FROM documents WHERE project_id = ? ORDER BY name;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, project_id);
    
    // First pass to count
    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) n++;
    sqlite3_reset(stmt);
    
    *count = n;
    if (n == 0) {
        *documents = NULL;
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    *documents = calloc(n, sizeof(ldmd_document_t));
    if (!*documents) {
        sqlite3_finalize(stmt);
        return LDMD_ERROR_MEMORY;
    }
    
    int i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < n) {
        fill_document_from_stmt(stmt, &(*documents)[i++]);
    }
    
    sqlite3_finalize(stmt);
    *count = i;
    
    return LDMD_OK;
}

// Password request operations
ldmd_error_t db_password_request_create(ldmd_database_t *db, ldmd_password_request_t *request) {
    // Delete any existing pending request for this user
    const char *del_sql = "DELETE FROM password_requests WHERE user_id = ? AND status = 0;";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db->db, del_sql, -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, request->user_id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    const char *sql = 
        "INSERT INTO password_requests (user_id, new_password_hash, new_salt, status, created_at) "
        "VALUES (?, ?, ?, ?, ?);";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    request->created_at = utils_now();
    request->status = USER_STATUS_PENDING;
    
    sqlite3_bind_int64(stmt, 1, request->user_id);
    sqlite3_bind_text(stmt, 2, request->new_password_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, request->new_salt, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, request->status);
    sqlite3_bind_int64(stmt, 5, request->created_at);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        return LDMD_ERROR_DATABASE;
    }
    
    request->id = sqlite3_last_insert_rowid(db->db);
    return LDMD_OK;
}

ldmd_error_t db_password_request_get(ldmd_database_t *db, int64_t user_id, 
                                     ldmd_password_request_t *request) {
    const char *sql = "SELECT id, user_id, new_password_hash, new_salt, status, "
                      "created_at, reviewed_at, reviewed_by "
                      "FROM password_requests WHERE user_id = ? AND status = 0;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int64(stmt, 1, user_id);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        request->id = sqlite3_column_int64(stmt, 0);
        request->user_id = sqlite3_column_int64(stmt, 1);
        ldmd_strlcpy(request->new_password_hash, 
                     (const char *)sqlite3_column_text(stmt, 2), LDMD_HASH_LENGTH);
        ldmd_strlcpy(request->new_salt, 
                     (const char *)sqlite3_column_text(stmt, 3), LDMD_SALT_LENGTH);
        request->status = sqlite3_column_int(stmt, 4);
        request->created_at = sqlite3_column_int64(stmt, 5);
        request->reviewed_at = sqlite3_column_int64(stmt, 6);
        request->reviewed_by = sqlite3_column_int64(stmt, 7);
        
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    sqlite3_finalize(stmt);
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t db_password_request_update(ldmd_database_t *db, ldmd_password_request_t *request) {
    const char *sql = "UPDATE password_requests SET status=?, reviewed_at=?, reviewed_by=? WHERE id=?;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    sqlite3_bind_int(stmt, 1, request->status);
    sqlite3_bind_int64(stmt, 2, request->reviewed_at);
    sqlite3_bind_int64(stmt, 3, request->reviewed_by);
    sqlite3_bind_int64(stmt, 4, request->id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? LDMD_OK : LDMD_ERROR_DATABASE;
}

ldmd_error_t db_password_request_list_pending(ldmd_database_t *db, 
                                              ldmd_password_request_t **requests, int *count) {
    const char *sql = "SELECT id, user_id, new_password_hash, new_salt, status, "
                      "created_at, reviewed_at, reviewed_by "
                      "FROM password_requests WHERE status = 0 ORDER BY created_at;";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return LDMD_ERROR_DATABASE;
    }
    
    // First pass to count
    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) n++;
    sqlite3_reset(stmt);
    
    *count = n;
    if (n == 0) {
        *requests = NULL;
        sqlite3_finalize(stmt);
        return LDMD_OK;
    }
    
    *requests = calloc(n, sizeof(ldmd_password_request_t));
    if (!*requests) {
        sqlite3_finalize(stmt);
        return LDMD_ERROR_MEMORY;
    }
    
    int i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < n) {
        (*requests)[i].id = sqlite3_column_int64(stmt, 0);
        (*requests)[i].user_id = sqlite3_column_int64(stmt, 1);
        ldmd_strlcpy((*requests)[i].new_password_hash, 
                     (const char *)sqlite3_column_text(stmt, 2), LDMD_HASH_LENGTH);
        ldmd_strlcpy((*requests)[i].new_salt, 
                     (const char *)sqlite3_column_text(stmt, 3), LDMD_SALT_LENGTH);
        (*requests)[i].status = sqlite3_column_int(stmt, 4);
        (*requests)[i].created_at = sqlite3_column_int64(stmt, 5);
        (*requests)[i].reviewed_at = sqlite3_column_int64(stmt, 6);
        (*requests)[i].reviewed_by = sqlite3_column_int64(stmt, 7);
        i++;
    }
    
    sqlite3_finalize(stmt);
    *count = i;
    
    return LDMD_OK;
}
