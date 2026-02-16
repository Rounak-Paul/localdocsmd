#ifndef RBAC_H
#define RBAC_H

#include "localdocsmd.h"
#include "database.h"

// Permission types
typedef enum {
    PERM_NONE = 0,
    
    // Global permissions
    PERM_ADMIN = (1 << 0),           // Full admin access
    PERM_CREATE_USER = (1 << 1),     // Create new users
    PERM_MANAGE_USER = (1 << 2),     // Edit/delete users
    PERM_CREATE_WORKSPACE = (1 << 3), // Create workspaces
    
    // Workspace permissions
    PERM_VIEW_WORKSPACE = (1 << 4),   // View workspace
    PERM_EDIT_WORKSPACE = (1 << 5),   // Edit workspace settings
    PERM_DELETE_WORKSPACE = (1 << 6), // Delete workspace
    PERM_MANAGE_MEMBERS = (1 << 7),   // Add/remove workspace members
    
    // Project permissions
    PERM_CREATE_PROJECT = (1 << 8),   // Create projects
    PERM_EDIT_PROJECT = (1 << 9),     // Edit project settings
    PERM_DELETE_PROJECT = (1 << 10),  // Delete projects
    
    // Document permissions
    PERM_VIEW_DOCUMENT = (1 << 11),   // View/read documents
    PERM_CREATE_DOCUMENT = (1 << 12), // Create documents
    PERM_EDIT_DOCUMENT = (1 << 13),   // Edit documents
    PERM_DELETE_DOCUMENT = (1 << 14), // Delete documents
    
    // Password management
    PERM_APPROVE_PASSWORD = (1 << 15), // Approve password changes
} ldmd_permission_t;

/**
 * Get permissions for a global role
 * @param role Global role
 * @return Permission bitmask
 */
uint32_t rbac_get_global_permissions(ldmd_role_t role);

/**
 * Get permissions for a workspace role
 * @param role Workspace role
 * @return Permission bitmask
 */
uint32_t rbac_get_workspace_permissions(ldmd_role_t role);

/**
 * Check if user has global permission
 * @param user User to check
 * @param permission Permission to check
 * @return true if user has permission
 */
bool rbac_has_global_permission(const ldmd_user_t *user, ldmd_permission_t permission);

/**
 * Check if user has permission in workspace
 * @param db Database handle
 * @param user_id User ID
 * @param workspace_id Workspace ID
 * @param permission Permission to check
 * @return true if user has permission
 */
bool rbac_has_workspace_permission(ldmd_database_t *db, int64_t user_id,
                                   int64_t workspace_id, ldmd_permission_t permission);

/**
 * Check if user can access workspace
 * @param db Database handle
 * @param user_id User ID
 * @param workspace_id Workspace ID
 * @return true if user can access
 */
bool rbac_can_access_workspace(ldmd_database_t *db, int64_t user_id, int64_t workspace_id);

/**
 * Check if user can edit in workspace
 * @param db Database handle
 * @param user_id User ID
 * @param workspace_id Workspace ID
 * @return true if user can edit
 */
bool rbac_can_edit_workspace(ldmd_database_t *db, int64_t user_id, int64_t workspace_id);

/**
 * Check if user is workspace admin
 * @param db Database handle
 * @param user_id User ID
 * @param workspace_id Workspace ID
 * @return true if user is admin
 */
bool rbac_is_workspace_admin(ldmd_database_t *db, int64_t user_id, int64_t workspace_id);

/**
 * Get user's effective role in workspace
 * @param db Database handle
 * @param user User
 * @param workspace_id Workspace ID
 * @return Effective role (global role may override)
 */
ldmd_role_t rbac_get_effective_role(ldmd_database_t *db, const ldmd_user_t *user,
                                    int64_t workspace_id);

/**
 * Role to string
 * @param role Role
 * @return String representation
 */
const char *rbac_role_to_string(ldmd_role_t role);

/**
 * Role to workspace-specific string (viewer/editor/manager)
 * @param role Role
 * @return String representation for workspace context
 */
const char *rbac_workspace_role_to_string(ldmd_role_t role);

/**
 * String to role
 * @param str String
 * @return Role or ROLE_NONE
 */
ldmd_role_t rbac_string_to_role(const char *str);

#endif // RBAC_H
