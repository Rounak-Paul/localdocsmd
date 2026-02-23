#ifndef ROUTES_H
#define ROUTES_H

#include "server.h"

/**
 * Initialize routes
 */
void routes_init(void);

/**
 * Handle HTTP request
 * @param req Request context
 * @return true if handled, false otherwise
 */
bool routes_handle(http_request_t *req);

// Page routes
void route_page_index(http_request_t *req);
void route_page_login(http_request_t *req);
void route_page_dashboard(http_request_t *req);
void route_page_admin(http_request_t *req);
void route_page_workspace(http_request_t *req, const char *workspace_uuid);
void route_page_project(http_request_t *req, const char *project_uuid);
void route_page_document(http_request_t *req, const char *document_uuid);
void route_page_editor(http_request_t *req, const char *document_uuid);

// API routes - Auth
void route_api_login(http_request_t *req);
void route_api_logout(http_request_t *req);
void route_api_change_password(http_request_t *req);

// API routes - Users
void route_api_users_list(http_request_t *req);
void route_api_users_search(http_request_t *req);
void route_api_users_create(http_request_t *req);
void route_api_users_get(http_request_t *req, const char *user_uuid);
void route_api_users_update(http_request_t *req, const char *user_uuid);
void route_api_users_delete(http_request_t *req, const char *user_uuid);

// API routes - Workspaces
void route_api_workspaces_list(http_request_t *req);
void route_api_workspaces_create(http_request_t *req);
void route_api_workspaces_get(http_request_t *req, const char *ws_uuid);
void route_api_workspaces_update(http_request_t *req, const char *ws_uuid);
void route_api_workspaces_delete(http_request_t *req, const char *ws_uuid);
void route_api_workspaces_members(http_request_t *req, const char *ws_uuid);
void route_api_workspaces_add_member(http_request_t *req, const char *ws_uuid);
void route_api_workspaces_remove_member(http_request_t *req, const char *ws_uuid, 
                                        const char *user_uuid);

// API routes - Projects
void route_api_projects_list(http_request_t *req, const char *ws_uuid);
void route_api_projects_create(http_request_t *req, const char *ws_uuid);
void route_api_projects_get(http_request_t *req, const char *project_uuid);
void route_api_projects_update(http_request_t *req, const char *project_uuid);
void route_api_projects_delete(http_request_t *req, const char *project_uuid);
void route_api_projects_list_members(http_request_t *req, const char *project_uuid);
void route_api_projects_add_member(http_request_t *req, const char *project_uuid);
void route_api_projects_remove_member(http_request_t *req, const char *project_uuid,
                                      const char *user_uuid);

// API routes - Documents
void route_api_documents_list(http_request_t *req, const char *project_uuid);
void route_api_documents_create(http_request_t *req, const char *project_uuid);
void route_api_documents_get(http_request_t *req, const char *doc_uuid);
void route_api_documents_update(http_request_t *req, const char *doc_uuid);
void route_api_documents_delete(http_request_t *req, const char *doc_uuid);
void route_api_documents_content(http_request_t *req, const char *doc_uuid);
void route_api_documents_render(http_request_t *req, const char *doc_uuid);

// API routes - Admin
void route_api_admin_stats(http_request_t *req);
void route_api_admin_password_requests(http_request_t *req);
void route_api_admin_approve_password(http_request_t *req, const char *request_id);
void route_api_admin_reject_password(http_request_t *req, const char *request_id);

// Forgot-password (public, no auth)
void route_api_forgot_password(http_request_t *req);

// Admin: password-forgot-requests management
void route_api_admin_forgot_requests(http_request_t *req);
void route_api_admin_handle_forgot(http_request_t *req, const char *request_id);

// Admin: direct password reset for any user
void route_api_admin_reset_user_password(http_request_t *req, const char *user_uuid);

#endif // ROUTES_H
