#include "rbac.h"
#include "utils.h"
#include <string.h>

// Global permissions for each role
static const uint32_t GLOBAL_ROLE_PERMISSIONS[] = {
    [ROLE_NONE] = PERM_NONE,
    
    [ROLE_VIEWER] = PERM_VIEW_WORKSPACE | PERM_VIEW_DOCUMENT,
    
    [ROLE_EDITOR] = PERM_VIEW_WORKSPACE | PERM_VIEW_DOCUMENT |
                    PERM_CREATE_PROJECT | PERM_EDIT_PROJECT |
                    PERM_CREATE_DOCUMENT | PERM_EDIT_DOCUMENT,
    
    [ROLE_ADMIN] = PERM_ADMIN | PERM_CREATE_USER | PERM_MANAGE_USER |
                   PERM_CREATE_WORKSPACE | PERM_VIEW_WORKSPACE | PERM_EDIT_WORKSPACE |
                   PERM_DELETE_WORKSPACE | PERM_MANAGE_MEMBERS |
                   PERM_CREATE_PROJECT | PERM_EDIT_PROJECT | PERM_DELETE_PROJECT |
                   PERM_VIEW_DOCUMENT | PERM_CREATE_DOCUMENT | PERM_EDIT_DOCUMENT |
                   PERM_DELETE_DOCUMENT | PERM_APPROVE_PASSWORD
};

// Workspace-level permissions for each role
static const uint32_t WORKSPACE_ROLE_PERMISSIONS[] = {
    [ROLE_NONE] = PERM_NONE,
    
    [ROLE_VIEWER] = PERM_VIEW_WORKSPACE | PERM_VIEW_DOCUMENT,
    
    [ROLE_EDITOR] = PERM_VIEW_WORKSPACE | PERM_VIEW_DOCUMENT |
                    PERM_CREATE_PROJECT | PERM_EDIT_PROJECT |
                    PERM_CREATE_DOCUMENT | PERM_EDIT_DOCUMENT,
    
    [ROLE_ADMIN] = PERM_VIEW_WORKSPACE | PERM_EDIT_WORKSPACE | PERM_DELETE_WORKSPACE |
                   PERM_MANAGE_MEMBERS |
                   PERM_CREATE_PROJECT | PERM_EDIT_PROJECT | PERM_DELETE_PROJECT |
                   PERM_VIEW_DOCUMENT | PERM_CREATE_DOCUMENT | PERM_EDIT_DOCUMENT |
                   PERM_DELETE_DOCUMENT
};

uint32_t rbac_get_global_permissions(ldmd_role_t role) {
    if (role < 0 || role > ROLE_ADMIN) {
        return PERM_NONE;
    }
    return GLOBAL_ROLE_PERMISSIONS[role];
}

uint32_t rbac_get_workspace_permissions(ldmd_role_t role) {
    if (role < 0 || role > ROLE_ADMIN) {
        return PERM_NONE;
    }
    return WORKSPACE_ROLE_PERMISSIONS[role];
}

bool rbac_has_global_permission(const ldmd_user_t *user, ldmd_permission_t permission) {
    if (!user) return false;
    
    uint32_t perms = rbac_get_global_permissions(user->global_role);
    
    // Admin has all permissions
    if (perms & PERM_ADMIN) {
        return true;
    }
    
    return (perms & permission) != 0;
}

bool rbac_has_workspace_permission(ldmd_database_t *db, int64_t user_id,
                                   int64_t workspace_id, ldmd_permission_t permission) {
    // Get user
    ldmd_user_t user;
    if (db_user_get_by_id(db, user_id, &user) != LDMD_OK) {
        return false;
    }
    
    // Global admin has all permissions
    if (user.global_role == ROLE_ADMIN) {
        return true;
    }
    
    // Check workspace ownership
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_id(db, workspace_id, &workspace) == LDMD_OK) {
        if (workspace.owner_id == user_id) {
            // Owner has all workspace permissions
            return true;
        }
    }
    
    // Get workspace membership role
    ldmd_role_t ws_role = ROLE_NONE;
    db_workspace_member_get_role(db, workspace_id, user_id, &ws_role);
    
    uint32_t perms = rbac_get_workspace_permissions(ws_role);
    return (perms & permission) != 0;
}

bool rbac_can_access_workspace(ldmd_database_t *db, int64_t user_id, int64_t workspace_id) {
    return rbac_has_workspace_permission(db, user_id, workspace_id, PERM_VIEW_WORKSPACE);
}

bool rbac_can_edit_workspace(ldmd_database_t *db, int64_t user_id, int64_t workspace_id) {
    return rbac_has_workspace_permission(db, user_id, workspace_id, PERM_EDIT_DOCUMENT);
}

bool rbac_is_workspace_admin(ldmd_database_t *db, int64_t user_id, int64_t workspace_id) {
    // Get user
    ldmd_user_t user;
    if (db_user_get_by_id(db, user_id, &user) != LDMD_OK) {
        return false;
    }
    
    // Global admin
    if (user.global_role == ROLE_ADMIN) {
        return true;
    }
    
    // Workspace owner
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_id(db, workspace_id, &workspace) == LDMD_OK) {
        if (workspace.owner_id == user_id) {
            return true;
        }
    }
    
    // Workspace admin role
    ldmd_role_t ws_role = ROLE_NONE;
    db_workspace_member_get_role(db, workspace_id, user_id, &ws_role);
    
    return ws_role == ROLE_ADMIN;
}

ldmd_role_t rbac_get_effective_role(ldmd_database_t *db, const ldmd_user_t *user,
                                    int64_t workspace_id) {
    if (!user) return ROLE_NONE;
    
    // Global admin is always admin
    if (user->global_role == ROLE_ADMIN) {
        return ROLE_ADMIN;
    }
    
    // Check workspace ownership
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_id(db, workspace_id, &workspace) == LDMD_OK) {
        if (workspace.owner_id == user->id) {
            return ROLE_ADMIN;
        }
    }
    
    // Get workspace role
    ldmd_role_t ws_role = ROLE_NONE;
    db_workspace_member_get_role(db, workspace_id, user->id, &ws_role);
    
    return ws_role;
}

const char *rbac_role_to_string(ldmd_role_t role) {
    switch (role) {
        case ROLE_NONE:   return "none";
        case ROLE_VIEWER: return "viewer";
        case ROLE_EDITOR: return "editor";
        case ROLE_ADMIN:  return "admin";
        default:          return "unknown";
    }
}

ldmd_role_t rbac_string_to_role(const char *str) {
    if (!str) return ROLE_NONE;
    
    if (strcasecmp(str, "viewer") == 0) return ROLE_VIEWER;
    if (strcasecmp(str, "editor") == 0) return ROLE_EDITOR;
    if (strcasecmp(str, "admin") == 0) return ROLE_ADMIN;
    
    return ROLE_NONE;
}
