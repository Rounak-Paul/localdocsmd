#include "workspace.h"
#include "auth.h"
#include "rbac.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

ldmd_error_t workspace_create(ldmd_database_t *db, ldmd_config_t *config,
                              const char *name, const char *description,
                              int64_t owner_id, ldmd_workspace_t *workspace_out) {
    ldmd_workspace_t workspace;
    memset(&workspace, 0, sizeof(workspace));
    
    auth_generate_uuid(workspace.uuid);
    ldmd_strlcpy(workspace.name, name, LDMD_MAX_NAME);
    if (description) {
        ldmd_strlcpy(workspace.description, description, LDMD_MAX_DESCRIPTION);
    }
    workspace.owner_id = owner_id;
    
    ldmd_error_t err = db_workspace_create(db, &workspace);
    if (err != LDMD_OK) {
        return err;
    }
    
    // Create workspace directory
    char path[LDMD_MAX_PATH];
    workspace_get_path(config, &workspace, path, sizeof(path));
    err = utils_mkdir_p(path);
    if (err != LDMD_OK) {
        db_workspace_delete(db, workspace.id);
        return err;
    }
    
    // Add owner as admin member
    ldmd_workspace_member_t member;
    memset(&member, 0, sizeof(member));
    member.workspace_id = workspace.id;
    member.user_id = owner_id;
    member.role = ROLE_ADMIN;
    db_workspace_member_add(db, &member);
    
    if (workspace_out) {
        *workspace_out = workspace;
    }
    
    LOG_INFO("Workspace created: %s (uuid: %s)", name, workspace.uuid);
    return LDMD_OK;
}

ldmd_error_t workspace_update(ldmd_database_t *db, ldmd_workspace_t *workspace) {
    return db_workspace_update(db, workspace);
}

ldmd_error_t workspace_delete(ldmd_database_t *db, ldmd_config_t *config, int64_t workspace_id) {
    ldmd_workspace_t workspace;
    ldmd_error_t err = db_workspace_get_by_id(db, workspace_id, &workspace);
    if (err != LDMD_OK) {
        return err;
    }
    
    // Delete workspace directory
    char path[LDMD_MAX_PATH];
    workspace_get_path(config, &workspace, path, sizeof(path));
    utils_rmdir_r(path);
    
    // Delete from database (cascades to members, projects, documents)
    return db_workspace_delete(db, workspace_id);
}

ldmd_error_t workspace_get(ldmd_database_t *db, int64_t id, ldmd_workspace_t *workspace_out) {
    return db_workspace_get_by_id(db, id, workspace_out);
}

ldmd_error_t workspace_get_by_uuid(ldmd_database_t *db, const char *uuid,
                                   ldmd_workspace_t *workspace_out) {
    return db_workspace_get_by_uuid(db, uuid, workspace_out);
}

ldmd_error_t workspace_list_all(ldmd_database_t *db, ldmd_workspace_t **workspaces_out,
                                int *count_out) {
    return db_workspace_list(db, workspaces_out, count_out);
}

ldmd_error_t workspace_list_for_user(ldmd_database_t *db, int64_t user_id,
                                     ldmd_workspace_t **workspaces_out, int *count_out) {
    // Check if user is global admin
    ldmd_user_t user;
    if (db_user_get_by_id(db, user_id, &user) == LDMD_OK && user.global_role == ROLE_ADMIN) {
        return db_workspace_list(db, workspaces_out, count_out);
    }
    
    return db_workspace_list_for_user(db, user_id, workspaces_out, count_out);
}

ldmd_error_t workspace_add_member(ldmd_database_t *db, int64_t workspace_id,
                                  int64_t user_id, ldmd_role_t role) {
    ldmd_workspace_member_t member;
    memset(&member, 0, sizeof(member));
    member.workspace_id = workspace_id;
    member.user_id = user_id;
    member.role = role;
    
    return db_workspace_member_add(db, &member);
}

ldmd_error_t workspace_remove_member(ldmd_database_t *db, int64_t workspace_id,
                                     int64_t user_id) {
    return db_workspace_member_remove(db, workspace_id, user_id);
}

ldmd_error_t workspace_update_member_role(ldmd_database_t *db, int64_t workspace_id,
                                          int64_t user_id, ldmd_role_t role) {
    return db_workspace_member_update_role(db, workspace_id, user_id, role);
}

ldmd_error_t workspace_list_members(ldmd_database_t *db, int64_t workspace_id,
                                    ldmd_workspace_member_t **members_out, int *count_out) {
    return db_workspace_member_list(db, workspace_id, members_out, count_out);
}

ldmd_error_t workspace_get_path(ldmd_config_t *config, const ldmd_workspace_t *workspace,
                                char *path_out, size_t path_size) {
    snprintf(path_out, path_size, "%s/%s", config->documents_path, workspace->uuid);
    return LDMD_OK;
}
