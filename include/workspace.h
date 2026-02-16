#ifndef WORKSPACE_H
#define WORKSPACE_H

#include "localdocsmd.h"
#include "database.h"
#include "config.h"

/**
 * Create a new workspace
 * @param db Database handle
 * @param config Configuration
 * @param name Workspace name
 * @param description Description
 * @param owner_id Owner user ID
 * @param workspace_out Output workspace
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_create(ldmd_database_t *db, ldmd_config_t *config,
                              const char *name, const char *description,
                              int64_t owner_id, ldmd_workspace_t *workspace_out);

/**
 * Update workspace
 * @param db Database handle
 * @param workspace Workspace to update
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_update(ldmd_database_t *db, ldmd_workspace_t *workspace);

/**
 * Delete workspace and all contents
 * @param db Database handle
 * @param config Configuration
 * @param workspace_id Workspace ID
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_delete(ldmd_database_t *db, ldmd_config_t *config, int64_t workspace_id);

/**
 * Get workspace by ID
 * @param db Database handle
 * @param id Workspace ID
 * @param workspace_out Output workspace
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_get(ldmd_database_t *db, int64_t id, ldmd_workspace_t *workspace_out);

/**
 * Get workspace by UUID
 * @param db Database handle
 * @param uuid Workspace UUID
 * @param workspace_out Output workspace
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_get_by_uuid(ldmd_database_t *db, const char *uuid,
                                   ldmd_workspace_t *workspace_out);

/**
 * List all workspaces
 * @param db Database handle
 * @param workspaces_out Output array (caller frees)
 * @param count_out Output count
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_list_all(ldmd_database_t *db, ldmd_workspace_t **workspaces_out,
                                int *count_out);

/**
 * List workspaces accessible by user
 * @param db Database handle
 * @param user_id User ID
 * @param workspaces_out Output array (caller frees)
 * @param count_out Output count
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_list_for_user(ldmd_database_t *db, int64_t user_id,
                                     ldmd_workspace_t **workspaces_out, int *count_out);

/**
 * Add member to workspace
 * @param db Database handle
 * @param workspace_id Workspace ID
 * @param user_id User ID
 * @param role Role to assign
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_add_member(ldmd_database_t *db, int64_t workspace_id,
                                  int64_t user_id, ldmd_role_t role);

/**
 * Remove member from workspace
 * @param db Database handle
 * @param workspace_id Workspace ID
 * @param user_id User ID
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_remove_member(ldmd_database_t *db, int64_t workspace_id,
                                     int64_t user_id);

/**
 * Update member role
 * @param db Database handle
 * @param workspace_id Workspace ID
 * @param user_id User ID
 * @param role New role
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_update_member_role(ldmd_database_t *db, int64_t workspace_id,
                                          int64_t user_id, ldmd_role_t role);

/**
 * List workspace members
 * @param db Database handle
 * @param workspace_id Workspace ID
 * @param members_out Output array (caller frees)
 * @param count_out Output count
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_list_members(ldmd_database_t *db, int64_t workspace_id,
                                    ldmd_workspace_member_t **members_out, int *count_out);

/**
 * Get workspace directory path
 * @param config Configuration
 * @param workspace Workspace
 * @param path_out Output path buffer
 * @param path_size Path buffer size
 * @return LDMD_OK or error code
 */
ldmd_error_t workspace_get_path(ldmd_config_t *config, const ldmd_workspace_t *workspace,
                                char *path_out, size_t path_size);

#endif // WORKSPACE_H
