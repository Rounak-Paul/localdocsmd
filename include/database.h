#ifndef DATABASE_H
#define DATABASE_H

#include "localdocsmd.h"
#include <sqlite3.h>

// Database structure
struct ldmd_database {
    sqlite3 *db;
    char path[LDMD_MAX_PATH];
    bool initialized;
};

/**
 * Initialize database
 * @param path Database file path
 * @return Database handle or NULL on error
 */
ldmd_database_t *db_init(const char *path);

/**
 * Close database
 * @param db Database handle
 */
void db_close(ldmd_database_t *db);

/**
 * Execute SQL statement
 * @param db Database handle
 * @param sql SQL statement
 * @return LDMD_OK or error code
 */
ldmd_error_t db_exec(ldmd_database_t *db, const char *sql);

/**
 * Begin transaction
 */
ldmd_error_t db_begin(ldmd_database_t *db);

/**
 * Commit transaction
 */
ldmd_error_t db_commit(ldmd_database_t *db);

/**
 * Rollback transaction
 */
ldmd_error_t db_rollback(ldmd_database_t *db);

// User operations
ldmd_error_t db_user_create(ldmd_database_t *db, ldmd_user_t *user);
ldmd_error_t db_user_get_by_id(ldmd_database_t *db, int64_t id, ldmd_user_t *user);
ldmd_error_t db_user_get_by_username(ldmd_database_t *db, const char *username, ldmd_user_t *user);
ldmd_error_t db_user_get_by_uuid(ldmd_database_t *db, const char *uuid, ldmd_user_t *user);
ldmd_error_t db_user_update(ldmd_database_t *db, ldmd_user_t *user);
ldmd_error_t db_user_delete(ldmd_database_t *db, int64_t id);
ldmd_error_t db_user_list(ldmd_database_t *db, ldmd_user_t **users, int *count);
ldmd_error_t db_user_count(ldmd_database_t *db, int *count);

// Session operations
ldmd_error_t db_session_create(ldmd_database_t *db, ldmd_session_t *session);
ldmd_error_t db_session_get(ldmd_database_t *db, const char *token, ldmd_session_t *session);
ldmd_error_t db_session_delete(ldmd_database_t *db, const char *token);
ldmd_error_t db_session_cleanup(ldmd_database_t *db);
ldmd_error_t db_session_delete_by_user(ldmd_database_t *db, int64_t user_id);

// Workspace operations
ldmd_error_t db_workspace_create(ldmd_database_t *db, ldmd_workspace_t *workspace);
ldmd_error_t db_workspace_get_by_id(ldmd_database_t *db, int64_t id, ldmd_workspace_t *workspace);
ldmd_error_t db_workspace_get_by_uuid(ldmd_database_t *db, const char *uuid, ldmd_workspace_t *workspace);
ldmd_error_t db_workspace_update(ldmd_database_t *db, ldmd_workspace_t *workspace);
ldmd_error_t db_workspace_delete(ldmd_database_t *db, int64_t id);
ldmd_error_t db_workspace_list(ldmd_database_t *db, ldmd_workspace_t **workspaces, int *count);
ldmd_error_t db_workspace_list_for_user(ldmd_database_t *db, int64_t user_id, 
                                        ldmd_workspace_t **workspaces, int *count);

// Workspace membership operations
ldmd_error_t db_workspace_member_add(ldmd_database_t *db, ldmd_workspace_member_t *member);
ldmd_error_t db_workspace_member_remove(ldmd_database_t *db, int64_t workspace_id, int64_t user_id);
ldmd_error_t db_workspace_member_get_role(ldmd_database_t *db, int64_t workspace_id, 
                                          int64_t user_id, ldmd_role_t *role);
ldmd_error_t db_workspace_member_update_role(ldmd_database_t *db, int64_t workspace_id, 
                                             int64_t user_id, ldmd_role_t role);
ldmd_error_t db_workspace_member_list(ldmd_database_t *db, int64_t workspace_id, 
                                      ldmd_workspace_member_t **members, int *count);

// Project operations
ldmd_error_t db_project_create(ldmd_database_t *db, ldmd_project_t *project);
ldmd_error_t db_project_get_by_id(ldmd_database_t *db, int64_t id, ldmd_project_t *project);
ldmd_error_t db_project_get_by_uuid(ldmd_database_t *db, const char *uuid, ldmd_project_t *project);
ldmd_error_t db_project_update(ldmd_database_t *db, ldmd_project_t *project);
ldmd_error_t db_project_delete(ldmd_database_t *db, int64_t id);
ldmd_error_t db_project_list(ldmd_database_t *db, int64_t workspace_id, 
                             ldmd_project_t **projects, int *count);

// Project membership operations (view permissions)
ldmd_error_t db_project_member_add(ldmd_database_t *db, ldmd_project_member_t *member);
ldmd_error_t db_project_member_remove(ldmd_database_t *db, int64_t project_id, int64_t user_id);
ldmd_error_t db_project_member_check(ldmd_database_t *db, int64_t project_id, 
                                     int64_t user_id, bool *can_view);
ldmd_error_t db_project_member_list(ldmd_database_t *db, int64_t project_id,
                                    ldmd_project_member_t **members, int *count);

// Document operations
ldmd_error_t db_document_create(ldmd_database_t *db, ldmd_document_t *document);
ldmd_error_t db_document_get_by_id(ldmd_database_t *db, int64_t id, ldmd_document_t *document);
ldmd_error_t db_document_get_by_uuid(ldmd_database_t *db, const char *uuid, ldmd_document_t *document);
ldmd_error_t db_document_update(ldmd_database_t *db, ldmd_document_t *document);
ldmd_error_t db_document_delete(ldmd_database_t *db, int64_t id);
ldmd_error_t db_document_list(ldmd_database_t *db, int64_t project_id, 
                              ldmd_document_t **documents, int *count);

// Password change request operations
ldmd_error_t db_password_request_create(ldmd_database_t *db, ldmd_password_request_t *request);
ldmd_error_t db_password_request_get(ldmd_database_t *db, int64_t user_id, 
                                     ldmd_password_request_t *request);
ldmd_error_t db_password_request_update(ldmd_database_t *db, ldmd_password_request_t *request);
ldmd_error_t db_password_request_list_pending(ldmd_database_t *db, 
                                              ldmd_password_request_t **requests, int *count);

#endif // DATABASE_H
