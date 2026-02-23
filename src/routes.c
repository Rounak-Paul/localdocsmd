#include "routes.h"
#include "auth.h"
#include "rbac.h"
#include "workspace.h"
#include "project.h"
#include "markdown.h"
#include "template.h"
#include "utils.h"
#include "mongoose.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>

// Helper to check if method matches
static bool method_is(http_request_t *req, const char *method) {
    return mg_strcasecmp(req->hm->method, mg_str(method)) == 0;
}

// Helper to parse JSON body
static cJSON *parse_json_body(http_request_t *req) {
    if (req->hm->body.len == 0) return NULL;
    
    char *body = malloc(req->hm->body.len + 1);
    if (!body) return NULL;
    memcpy(body, req->hm->body.buf, req->hm->body.len);
    body[req->hm->body.len] = '\0';
    
    cJSON *json = cJSON_Parse(body);
    free(body);
    return json;
}

// Helper to get string from JSON
static const char *json_get_string(cJSON *json, const char *key) {
    cJSON *item = cJSON_GetObjectItem(json, key);
    if (item && cJSON_IsString(item)) {
        return item->valuestring;
    }
    return NULL;
}

// Route matching helper
static bool uri_match(http_request_t *req, const char *pattern, char *param1, char *param2) {
    struct mg_str caps[3] = {{0}};
    
    if (mg_match(req->hm->uri, mg_str(pattern), caps)) {
        if (param1 && caps[0].len > 0 && caps[0].len < LDMD_UUID_LENGTH) {
            memcpy(param1, caps[0].buf, caps[0].len);
            param1[caps[0].len] = '\0';
        }
        if (param2 && caps[1].len > 0 && caps[1].len < LDMD_UUID_LENGTH) {
            memcpy(param2, caps[1].buf, caps[1].len);
            param2[caps[1].len] = '\0';
        }
        return true;
    }
    return false;
}

// Require authentication
static bool require_auth(http_request_t *req) {
    if (!req->authenticated) {
        if (method_is(req, "GET")) {
            http_respond_redirect(req->conn, "/login");
        } else {
            http_respond_error(req->conn, 401, "Unauthorized");
        }
        return false;
    }
    return true;
}

// Require admin
static bool require_admin(http_request_t *req) {
    if (!require_auth(req)) return false;
    
    if (req->user.global_role != ROLE_ADMIN) {
        http_respond_error(req->conn, 403, "Admin access required");
        return false;
    }
    return true;
}

// Helper to build navbar HTML for authenticated users
static void set_navbar(template_ctx_t *ctx, http_request_t *req) {
    if (!req->authenticated) {
        template_set(ctx, "navbar", "");
        return;
    }
    
    char navbar[2048];
    const char *admin_link = (req->user.global_role == ROLE_ADMIN) 
        ? "<a href=\"/admin\">Admin</a>" 
        : "";
    
    snprintf(navbar, sizeof(navbar),
        "<nav class=\"navbar\">"
        "<div class=\"navbar-brand\"><a href=\"/dashboard\">Local<span>Docs</span>MD</a></div>"
        "<div class=\"navbar-menu\">"
        "<span class=\"navbar-user\">%s</span>"
        "%s"
        "<div class=\"theme-switcher\">"
        "<button class=\"btn\" title=\"Theme\">&#9728;</button>"
        "<div class=\"theme-dropdown\">"
        "<button class=\"theme-option\" onclick=\"setTheme('midnight')\"><span class=\"theme-preview\" style=\"background:#0d1117;border-color:#30363d\"></span>Midnight</button>"
        "<button class=\"theme-option\" onclick=\"setTheme('daylight')\"><span class=\"theme-preview\" style=\"background:#fff;border-color:#d0d7de\"></span>Daylight</button>"
        "<button class=\"theme-option\" onclick=\"setTheme('dracula')\"><span class=\"theme-preview\" style=\"background:#282a36;border-color:#6272a4\"></span>Dracula</button>"
        "<button class=\"theme-option\" onclick=\"setTheme('nord')\"><span class=\"theme-preview\" style=\"background:#2e3440;border-color:#4c566a\"></span>Nord</button>"
        "</div>"
        "</div>"
        "<a href=\"#\" onclick=\"logout();return false;\" class=\"btn\">Logout</a>"
        "</div>"
        "</nav>",
        req->user.username, admin_link);
    
    template_set(ctx, "navbar", navbar);
}

void routes_init(void) {
    // Nothing to initialize
}

bool routes_handle(http_request_t *req) {
    char param1[LDMD_UUID_LENGTH] = {0};
    char param2[LDMD_UUID_LENGTH] = {0};
    
    // ============== Page Routes ==============
    
    // Index
    if (uri_match(req, "/", NULL, NULL) && method_is(req, "GET")) {
        route_page_index(req);
        return true;
    }
    
    // Login page
    if (uri_match(req, "/login", NULL, NULL) && method_is(req, "GET")) {
        route_page_login(req);
        return true;
    }
    
    // Dashboard
    if (uri_match(req, "/dashboard", NULL, NULL) && method_is(req, "GET")) {
        route_page_dashboard(req);
        return true;
    }
    
    // Admin
    if (uri_match(req, "/admin", NULL, NULL) && method_is(req, "GET")) {
        route_page_admin(req);
        return true;
    }
    
    // Workspace page
    if (uri_match(req, "/workspace/*", param1, NULL) && method_is(req, "GET")) {
        route_page_workspace(req, param1);
        return true;
    }
    
    // Project page
    if (uri_match(req, "/project/*", param1, NULL) && method_is(req, "GET")) {
        route_page_project(req, param1);
        return true;
    }
    
    // Document view
    if (uri_match(req, "/document/*", param1, NULL) && method_is(req, "GET")) {
        route_page_document(req, param1);
        return true;
    }
    
    // Editor page
    if (uri_match(req, "/editor/*", param1, NULL) && method_is(req, "GET")) {
        route_page_editor(req, param1);
        return true;
    }
    
    // ============== API Routes ==============
    
    // Auth API
    if (uri_match(req, "/api/login", NULL, NULL) && method_is(req, "POST")) {
        route_api_login(req);
        return true;
    }
    
    if (uri_match(req, "/api/logout", NULL, NULL) && method_is(req, "POST")) {
        route_api_logout(req);
        return true;
    }
    
    if (uri_match(req, "/api/change-password", NULL, NULL) && method_is(req, "POST")) {
        route_api_change_password(req);
        return true;
    }
    
    // Users API
    if (uri_match(req, "/api/users/search", NULL, NULL) && method_is(req, "GET")) {
        route_api_users_search(req);
        return true;
    }
    
    if (uri_match(req, "/api/users", NULL, NULL)) {
        if (method_is(req, "GET")) {
            route_api_users_list(req);
            return true;
        }
        if (method_is(req, "POST")) {
            route_api_users_create(req);
            return true;
        }
    }
    
    if (uri_match(req, "/api/users/*", param1, NULL)) {
        if (method_is(req, "GET")) {
            route_api_users_get(req, param1);
            return true;
        }
        if (method_is(req, "PUT") || method_is(req, "PATCH")) {
            route_api_users_update(req, param1);
            return true;
        }
        if (method_is(req, "DELETE")) {
            route_api_users_delete(req, param1);
            return true;
        }
    }
    
    // Workspaces API
    if (uri_match(req, "/api/workspaces", NULL, NULL)) {
        if (method_is(req, "GET")) {
            route_api_workspaces_list(req);
            return true;
        }
        if (method_is(req, "POST")) {
            route_api_workspaces_create(req);
            return true;
        }
    }
    
    if (uri_match(req, "/api/workspaces/*/members/*", param1, param2)) {
        if (method_is(req, "DELETE")) {
            route_api_workspaces_remove_member(req, param1, param2);
            return true;
        }
    }
    
    if (uri_match(req, "/api/workspaces/*/members", param1, NULL)) {
        if (method_is(req, "GET")) {
            route_api_workspaces_members(req, param1);
            return true;
        }
        if (method_is(req, "POST")) {
            route_api_workspaces_add_member(req, param1);
            return true;
        }
    }
    
    if (uri_match(req, "/api/workspaces/*/projects", param1, NULL)) {
        if (method_is(req, "GET")) {
            route_api_projects_list(req, param1);
            return true;
        }
        if (method_is(req, "POST")) {
            route_api_projects_create(req, param1);
            return true;
        }
    }
    
    if (uri_match(req, "/api/workspaces/*", param1, NULL)) {
        if (method_is(req, "GET")) {
            route_api_workspaces_get(req, param1);
            return true;
        }
        if (method_is(req, "PUT") || method_is(req, "PATCH")) {
            route_api_workspaces_update(req, param1);
            return true;
        }
        if (method_is(req, "DELETE")) {
            route_api_workspaces_delete(req, param1);
            return true;
        }
    }
    
    // Projects API
    if (uri_match(req, "/api/projects/*/members/*", param1, param2)) {
        if (method_is(req, "DELETE")) {
            route_api_projects_remove_member(req, param1, param2);
            return true;
        }
    }
    
    if (uri_match(req, "/api/projects/*/members", param1, NULL)) {
        if (method_is(req, "GET")) {
            route_api_projects_list_members(req, param1);
            return true;
        }
        if (method_is(req, "POST")) {
            route_api_projects_add_member(req, param1);
            return true;
        }
    }
    
    if (uri_match(req, "/api/projects/*/documents", param1, NULL)) {
        if (method_is(req, "GET")) {
            route_api_documents_list(req, param1);
            return true;
        }
        if (method_is(req, "POST")) {
            route_api_documents_create(req, param1);
            return true;
        }
    }
    
    if (uri_match(req, "/api/projects/*", param1, NULL)) {
        if (method_is(req, "GET")) {
            route_api_projects_get(req, param1);
            return true;
        }
        if (method_is(req, "PUT") || method_is(req, "PATCH")) {
            route_api_projects_update(req, param1);
            return true;
        }
        if (method_is(req, "DELETE")) {
            route_api_projects_delete(req, param1);
            return true;
        }
    }
    
    // Documents API
    if (uri_match(req, "/api/documents/*/content", param1, NULL)) {
        route_api_documents_content(req, param1);
        return true;
    }
    
    if (uri_match(req, "/api/documents/*/render", param1, NULL) && method_is(req, "GET")) {
        route_api_documents_render(req, param1);
        return true;
    }

    if (uri_match(req, "/api/documents/*/ping", param1, NULL) && method_is(req, "POST")) {
        route_api_documents_ping(req, param1);
        return true;
    }

    if (uri_match(req, "/api/documents/*/viewers", param1, NULL) && method_is(req, "GET")) {
        route_api_documents_viewers(req, param1);
        return true;
    }
    
    if (uri_match(req, "/api/documents/*", param1, NULL)) {
        if (method_is(req, "GET")) {
            route_api_documents_get(req, param1);
            return true;
        }
        if (method_is(req, "PUT") || method_is(req, "PATCH")) {
            route_api_documents_update(req, param1);
            return true;
        }
        if (method_is(req, "DELETE")) {
            route_api_documents_delete(req, param1);
            return true;
        }
    }
    
    // Admin API
    if (uri_match(req, "/api/admin/stats", NULL, NULL) && method_is(req, "GET")) {
        route_api_admin_stats(req);
        return true;
    }
    
    if (uri_match(req, "/api/admin/password-requests", NULL, NULL) && method_is(req, "GET")) {
        route_api_admin_password_requests(req);
        return true;
    }
    
    if (uri_match(req, "/api/admin/password-requests/*/approve", param1, NULL) && method_is(req, "POST")) {
        route_api_admin_approve_password(req, param1);
        return true;
    }
    
    if (uri_match(req, "/api/admin/password-requests/*/reject", param1, NULL) && method_is(req, "POST")) {
        route_api_admin_reject_password(req, param1);
        return true;
    }

    // Forgot-password (public - no auth required)
    if (uri_match(req, "/api/forgot-password", NULL, NULL) && method_is(req, "POST")) {
        route_api_forgot_password(req);
        return true;
    }

    // Admin: forgot-password requests
    if (uri_match(req, "/api/admin/forgot-requests", NULL, NULL) && method_is(req, "GET")) {
        route_api_admin_forgot_requests(req);
        return true;
    }

    if (uri_match(req, "/api/admin/forgot-requests/*/handle", param1, NULL) && method_is(req, "POST")) {
        route_api_admin_handle_forgot(req, param1);
        return true;
    }

    // Admin: direct password reset for any user
    if (uri_match(req, "/api/admin/users/*/reset-password", param1, NULL) && method_is(req, "POST")) {
        route_api_admin_reset_user_password(req, param1);
        return true;
    }

    return false;
}

// ============== Page Route Implementations ==============

void route_page_index(http_request_t *req) {
    if (req->authenticated) {
        http_respond_redirect(req->conn, "/dashboard");
    } else {
        http_respond_redirect(req->conn, "/login");
    }
}

void route_page_login(http_request_t *req) {
    if (req->authenticated) {
        http_respond_redirect(req->conn, "/dashboard");
        return;
    }
    
    template_ctx_t *ctx = template_create_context();
    template_set(ctx, "title", "Login - LocalDocsMD");
    set_navbar(ctx, req);
    
    char *html = NULL;
    ldmd_error_t err = template_render_with_layout(req->server->config->web_root, "login.html", ctx, &html);
    template_free_context(ctx);
    
    if (err == LDMD_OK && html) {
        http_respond_html(req->conn, 200, html);
        free(html);
    } else {
        http_respond_error(req->conn, 500, "Template error");
    }
}

void route_page_dashboard(http_request_t *req) {
    if (!require_auth(req)) return;
    
    template_ctx_t *ctx = template_create_context();
    template_set(ctx, "title", "Dashboard - LocalDocsMD");
    template_set(ctx, "username", req->user.username);
    template_set(ctx, "is_admin", req->user.global_role == ROLE_ADMIN ? "true" : "");
    template_set_bool(ctx, "password_pending", req->user.password_change_pending);
    set_navbar(ctx, req);
    
    char *html = NULL;
    ldmd_error_t err = template_render_with_layout(req->server->config->web_root, "dashboard.html", ctx, &html);
    template_free_context(ctx);
    
    if (err == LDMD_OK && html) {
        http_respond_html(req->conn, 200, html);
        free(html);
    } else {
        http_respond_error(req->conn, 500, "Template error");
    }
}

void route_page_admin(http_request_t *req) {
    if (!require_admin(req)) return;
    
    template_ctx_t *ctx = template_create_context();
    template_set(ctx, "title", "Admin - LocalDocsMD");
    template_set(ctx, "username", req->user.username);
    template_set(ctx, "is_admin", "true");
    set_navbar(ctx, req);
    
    char *html = NULL;
    ldmd_error_t err = template_render_with_layout(req->server->config->web_root, "admin.html", ctx, &html);
    template_free_context(ctx);
    
    if (err == LDMD_OK && html) {
        http_respond_html(req->conn, 200, html);
        free(html);
    } else {
        http_respond_error(req->conn, 500, "Template error");
    }
}

void route_page_workspace(http_request_t *req, const char *workspace_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_uuid(req->server->db, workspace_uuid, &workspace) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Workspace not found");
        return;
    }
    
    if (!rbac_can_access_workspace(req->server->db, req->user.id, workspace.id)) {
        http_respond_error(req->conn, 403, "Access denied");
        return;
    }
    
    template_ctx_t *ctx = template_create_context();
    
    char title[512];
    snprintf(title, sizeof(title), "%s - LocalDocsMD", workspace.name);
    template_set(ctx, "title", title);
    template_set(ctx, "username", req->user.username);
    template_set(ctx, "workspace_name", workspace.name);
    template_set(ctx, "workspace_uuid", workspace.uuid);
    template_set(ctx, "workspace_description", workspace.description);
    template_set_bool(ctx, "is_admin", rbac_is_workspace_admin(req->server->db, req->user.id, workspace.id));
    template_set_bool(ctx, "can_edit", rbac_can_edit_workspace(req->server->db, req->user.id, workspace.id));
    set_navbar(ctx, req);
    
    char *html = NULL;
    ldmd_error_t err = template_render_with_layout(req->server->config->web_root, "workspace.html", ctx, &html);
    template_free_context(ctx);
    
    if (err == LDMD_OK && html) {
        http_respond_html(req->conn, 200, html);
        free(html);
    } else {
        http_respond_error(req->conn, 500, "Template error");
    }
}

void route_page_project(http_request_t *req, const char *project_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_project_t project;
    if (db_project_get_by_uuid(req->server->db, project_uuid, &project) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Project not found");
        return;
    }
    
    if (!rbac_can_access_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Access denied");
        return;
    }
    
    ldmd_workspace_t workspace;
    db_workspace_get_by_id(req->server->db, project.workspace_id, &workspace);
    
    template_ctx_t *ctx = template_create_context();
    
    char title[512];
    snprintf(title, sizeof(title), "%s - LocalDocsMD", project.name);
    template_set(ctx, "title", title);
    template_set(ctx, "username", req->user.username);
    template_set(ctx, "project_name", project.name);
    template_set(ctx, "project_uuid", project.uuid);
    template_set(ctx, "project_description", project.description);
    template_set(ctx, "workspace_name", workspace.name);
    template_set(ctx, "workspace_uuid", workspace.uuid);
    template_set_bool(ctx, "is_admin", req->user.global_role == ROLE_ADMIN);
    template_set_bool(ctx, "can_edit", rbac_can_edit_workspace(req->server->db, req->user.id, workspace.id));
    set_navbar(ctx, req);
    
    char *html = NULL;
    ldmd_error_t err = template_render_with_layout(req->server->config->web_root, "project.html", ctx, &html);
    template_free_context(ctx);
    
    if (err == LDMD_OK && html) {
        http_respond_html(req->conn, 200, html);
        free(html);
    } else {
        http_respond_error(req->conn, 500, "Template error");
    }
}

void route_page_document(http_request_t *req, const char *document_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_document_t doc;
    if (db_document_get_by_uuid(req->server->db, document_uuid, &doc) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Document not found");
        return;
    }
    
    ldmd_project_t project;
    db_project_get_by_id(req->server->db, doc.project_id, &project);
    
    if (!rbac_can_access_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Access denied");
        return;
    }
    
    // Load and render markdown
    char *content = NULL;
    document_load_content(req->server->config, &doc, &content);
    
    char *html_content = NULL;
    if (content) {
        markdown_render(content, &html_content);
        free(content);
    }
    
    template_ctx_t *ctx = template_create_context();
    
    char title[512];
    snprintf(title, sizeof(title), "%s - LocalDocsMD", doc.name);
    template_set(ctx, "title", title);
    template_set(ctx, "username", req->user.username);
    template_set(ctx, "document_name", doc.name);
    template_set(ctx, "document_uuid", doc.uuid);
    template_set(ctx, "content", html_content ? html_content : "");
    template_set(ctx, "project_name", project.name);
    template_set(ctx, "project_uuid", project.uuid);
    template_set_bool(ctx, "can_edit", rbac_can_edit_workspace(req->server->db, req->user.id, project.workspace_id));
    set_navbar(ctx, req);
    
    free(html_content);
    
    char *html = NULL;
    ldmd_error_t err = template_render_with_layout(req->server->config->web_root, "document.html", ctx, &html);
    template_free_context(ctx);
    
    if (err == LDMD_OK && html) {
        http_respond_html(req->conn, 200, html);
        free(html);
    } else {
        http_respond_error(req->conn, 500, "Template error");
    }
}

void route_page_editor(http_request_t *req, const char *document_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_document_t doc;
    if (db_document_get_by_uuid(req->server->db, document_uuid, &doc) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Document not found");
        return;
    }
    
    ldmd_project_t project;
    db_project_get_by_id(req->server->db, doc.project_id, &project);
    
    if (!rbac_can_edit_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Edit access denied");
        return;
    }
    
    // Load markdown content
    char *content = NULL;
    document_load_content(req->server->config, &doc, &content);
    
    // Escape content for JSON/JavaScript
    char *escaped_content = NULL;
    template_json_escape(content ? content : "", &escaped_content);
    free(content);
    
    template_ctx_t *ctx = template_create_context();
    
    char title[512];
    snprintf(title, sizeof(title), "Edit: %s - LocalDocsMD", doc.name);
    template_set(ctx, "title", title);
    template_set(ctx, "username", req->user.username);
    template_set(ctx, "document_name", doc.name);
    template_set(ctx, "document_uuid", doc.uuid);
    template_set(ctx, "content", escaped_content ? escaped_content : "");
    template_set(ctx, "project_name", project.name);
    template_set(ctx, "project_uuid", project.uuid);
    set_navbar(ctx, req);
    
    free(escaped_content);
    
    char *html = NULL;
    ldmd_error_t err = template_render_with_layout(req->server->config->web_root, "editor.html", ctx, &html);
    template_free_context(ctx);
    
    if (err == LDMD_OK && html) {
        http_respond_html(req->conn, 200, html);
        free(html);
    } else {
        http_respond_error(req->conn, 500, "Template error");
    }
}

// ============== API Route Implementations ==============

void route_api_login(http_request_t *req) {
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *username = json_get_string(json, "username");
    const char *password = json_get_string(json, "password");
    
    if (!username || !password) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "Username and password required");
        return;
    }
    
    // Get user agent
    struct mg_str *ua = mg_http_get_header(req->hm, "User-Agent");
    char user_agent[512] = {0};
    if (ua && ua->len < sizeof(user_agent)) {
        memcpy(user_agent, ua->buf, ua->len);
    }
    
    ldmd_session_t session;
    ldmd_error_t err = auth_login(req->server->db, req->server->config,
                                  username, password, req->client_ip, user_agent, &session);
    cJSON_Delete(json);
    
    if (err == LDMD_OK) {
        ldmd_user_t user;
        db_user_get_by_id(req->server->db, session.user_id, &user);
        
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "token", session.token);
        cJSON_AddStringToObject(resp, "username", user.username);
        cJSON_AddStringToObject(resp, "role", rbac_role_to_string(user.global_role));
        cJSON_AddBoolToObject(resp, "password_change_required", 
                             user.status == USER_STATUS_PENDING || user.password_change_pending);
        
        char *json_str = cJSON_PrintUnformatted(resp);
        http_respond_json_with_cookie(req->conn, 200, json_str, session.token, req->server->config->session_timeout);
        free(json_str);
        cJSON_Delete(resp);
    } else if (err == LDMD_ERROR_FORBIDDEN) {
        http_respond_error(req->conn, 403, "Account locked");
    } else {
        http_respond_error(req->conn, 401, "Invalid credentials");
    }
}

void route_api_logout(http_request_t *req) {
    if (req->authenticated) {
        auth_logout(req->server->db, req->session.token);
    }
    
    http_respond_json_with_cookie(req->conn, 200, "{\"success\":true}", NULL, 0);
}

void route_api_change_password(http_request_t *req) {
    if (!require_auth(req)) return;
    
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *current = json_get_string(json, "current_password");
    const char *new_pass = json_get_string(json, "new_password");
    
    if (!current || !new_pass) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "Current and new password required");
        return;
    }
    
    ldmd_error_t err;
    
    // First password change (pending user or forced password change) doesn't need approval
    if (req->user.status == USER_STATUS_PENDING || req->user.password_change_pending) {
        err = auth_change_password_first(req->server->db, req->server->config,
                                        req->user.id, current, new_pass);
        if (err == LDMD_OK) {
            http_respond_json(req->conn, 200, "{\"success\":true,\"message\":\"Password changed\"}");
        } else if (err == LDMD_ERROR_INVALID) {
            http_respond_error(req->conn, 400, "Password too short");
        } else {
            http_respond_error(req->conn, 401, "Invalid current password");
        }
    } else {
        // Subsequent changes need approval
        err = auth_request_password_change(req->server->db, req->server->config,
                                           req->user.id, current, new_pass);
        if (err == LDMD_OK) {
            http_respond_json(req->conn, 200, 
                "{\"success\":true,\"message\":\"Password change submitted for approval\"}");
        } else if (err == LDMD_ERROR_INVALID) {
            http_respond_error(req->conn, 400, "Password too short");
        } else {
            http_respond_error(req->conn, 401, "Invalid current password");
        }
    }
    
    cJSON_Delete(json);
}

void route_api_users_list(http_request_t *req) {
    if (!require_admin(req)) return;
    
    ldmd_user_t *users = NULL;
    int count = 0;
    
    ldmd_error_t err = db_user_list(req->server->db, &users, &count);
    if (err != LDMD_OK) {
        http_respond_error(req->conn, 500, "Database error");
        return;
    }
    
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON *user = cJSON_CreateObject();
        cJSON_AddStringToObject(user, "uuid", users[i].uuid);
        cJSON_AddStringToObject(user, "username", users[i].username);
        cJSON_AddStringToObject(user, "email", users[i].email);
        cJSON_AddStringToObject(user, "role", rbac_role_to_string(users[i].global_role));
        cJSON_AddNumberToObject(user, "status", users[i].status);
        cJSON_AddBoolToObject(user, "password_pending", users[i].password_change_pending);
        cJSON_AddItemToArray(arr, user);
    }
    free(users);
    
    char *json_str = cJSON_PrintUnformatted(arr);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(arr);
}

// User search for permission dialogs - returns minimal user info
void route_api_users_search(http_request_t *req) {
    if (!require_auth(req)) return;
    
    // Get search query from URL parameter
    char query[256] = "";
    http_get_query_param(req, "q", query, sizeof(query));
    
    ldmd_user_t *users = NULL;
    int count = 0;
    
    ldmd_error_t err = db_user_list(req->server->db, &users, &count);
    if (err != LDMD_OK) {
        http_respond_error(req->conn, 500, "Database error");
        return;
    }
    
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        // Filter by query if provided
        if (query[0] != '\0') {
            // Case-insensitive search in username and email
            bool match = (strcasestr(users[i].username, query) != NULL) ||
                        (strcasestr(users[i].email, query) != NULL);
            if (!match) continue;
        }
        
        // Return minimal info for privacy
        cJSON *user = cJSON_CreateObject();
        cJSON_AddStringToObject(user, "uuid", users[i].uuid);
        cJSON_AddStringToObject(user, "username", users[i].username);
        cJSON_AddStringToObject(user, "email", users[i].email);
        cJSON_AddItemToArray(arr, user);
    }
    free(users);
    
    char *json_str = cJSON_PrintUnformatted(arr);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(arr);
}

void route_api_users_create(http_request_t *req) {
    if (!require_admin(req)) return;
    
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *username = json_get_string(json, "username");
    const char *email = json_get_string(json, "email");
    const char *password = json_get_string(json, "password");
    const char *role_str = json_get_string(json, "role");
    
    if (!username || !email) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "Username and email required");
        return;
    }
    
    ldmd_role_t role = role_str ? rbac_string_to_role(role_str) : ROLE_USER;
    
    ldmd_user_t user;
    ldmd_error_t err = auth_create_user(req->server->db, req->server->config,
                                        username, email, password, role, &user);
    cJSON_Delete(json);
    
    if (err == LDMD_ERROR_EXISTS) {
        http_respond_error(req->conn, 409, "Username already exists");
        return;
    }
    if (err != LDMD_OK) {
        http_respond_error(req->conn, 500, "Failed to create user");
        return;
    }
    
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "uuid", user.uuid);
    cJSON_AddStringToObject(resp, "username", user.username);
    cJSON_AddStringToObject(resp, "email", user.email);
    cJSON_AddStringToObject(resp, "role", rbac_role_to_string(user.global_role));
    cJSON_AddBoolToObject(resp, "password_pending", user.password_change_pending);
    // Include the generated temp password if no password was supplied by the admin
    if (user.generated_password[0] != '\0') {
        cJSON_AddStringToObject(resp, "generated_password", user.generated_password);
    }
    
    char *json_str = cJSON_PrintUnformatted(resp);
    http_respond_json(req->conn, 201, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void route_api_users_get(http_request_t *req, const char *user_uuid) {
    if (!require_admin(req)) return;
    
    ldmd_user_t user;
    if (db_user_get_by_uuid(req->server->db, user_uuid, &user) != LDMD_OK) {
        http_respond_error(req->conn, 404, "User not found");
        return;
    }
    
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "uuid", user.uuid);
    cJSON_AddStringToObject(resp, "username", user.username);
    cJSON_AddStringToObject(resp, "email", user.email);
    cJSON_AddStringToObject(resp, "role", rbac_role_to_string(user.global_role));
    cJSON_AddNumberToObject(resp, "status", user.status);
    cJSON_AddBoolToObject(resp, "password_pending", user.password_change_pending);
    
    char *json_str = cJSON_PrintUnformatted(resp);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void route_api_users_update(http_request_t *req, const char *user_uuid) {
    if (!require_admin(req)) return;
    
    ldmd_user_t user;
    if (db_user_get_by_uuid(req->server->db, user_uuid, &user) != LDMD_OK) {
        http_respond_error(req->conn, 404, "User not found");
        return;
    }
    
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *email = json_get_string(json, "email");
    const char *role_str = json_get_string(json, "role");
    cJSON *status_item = cJSON_GetObjectItem(json, "status");
    
    if (email) ldmd_strlcpy(user.email, email, LDMD_MAX_EMAIL);
    if (role_str) user.global_role = rbac_string_to_role(role_str);
    if (status_item && cJSON_IsNumber(status_item)) {
        user.status = status_item->valueint;
    }
    
    db_user_update(req->server->db, &user);
    cJSON_Delete(json);
    
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

void route_api_users_delete(http_request_t *req, const char *user_uuid) {
    if (!require_admin(req)) return;
    
    ldmd_user_t user;
    if (db_user_get_by_uuid(req->server->db, user_uuid, &user) != LDMD_OK) {
        http_respond_error(req->conn, 404, "User not found");
        return;
    }
    
    // Can't delete yourself
    if (user.id == req->user.id) {
        http_respond_error(req->conn, 400, "Cannot delete yourself");
        return;
    }
    
    db_user_delete(req->server->db, user.id);
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

void route_api_workspaces_list(http_request_t *req) {
    if (!require_auth(req)) return;
    
    ldmd_workspace_t *workspaces = NULL;
    int count = 0;
    
    workspace_list_for_user(req->server->db, req->user.id, &workspaces, &count);
    
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON *ws = cJSON_CreateObject();
        cJSON_AddStringToObject(ws, "uuid", workspaces[i].uuid);
        cJSON_AddStringToObject(ws, "name", workspaces[i].name);
        cJSON_AddStringToObject(ws, "description", workspaces[i].description);
        cJSON_AddItemToArray(arr, ws);
    }
    free(workspaces);
    
    char *json_str = cJSON_PrintUnformatted(arr);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(arr);
}

void route_api_workspaces_create(http_request_t *req) {
    if (!require_admin(req)) return;
    
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *name = json_get_string(json, "name");
    const char *description = json_get_string(json, "description");
    
    if (!name) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "Name required");
        return;
    }
    
    ldmd_workspace_t workspace;
    ldmd_error_t err = workspace_create(req->server->db, req->server->config,
                                        name, description, req->user.id, &workspace);
    cJSON_Delete(json);
    
    if (err != LDMD_OK) {
        http_respond_error(req->conn, 500, "Failed to create workspace");
        return;
    }
    
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "uuid", workspace.uuid);
    cJSON_AddStringToObject(resp, "name", workspace.name);
    cJSON_AddStringToObject(resp, "description", workspace.description);
    
    char *json_str = cJSON_PrintUnformatted(resp);
    http_respond_json(req->conn, 201, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void route_api_workspaces_get(http_request_t *req, const char *ws_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_uuid(req->server->db, ws_uuid, &workspace) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Workspace not found");
        return;
    }
    
    if (!rbac_can_access_workspace(req->server->db, req->user.id, workspace.id)) {
        http_respond_error(req->conn, 403, "Access denied");
        return;
    }
    
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "uuid", workspace.uuid);
    cJSON_AddStringToObject(resp, "name", workspace.name);
    cJSON_AddStringToObject(resp, "description", workspace.description);
    
    char *json_str = cJSON_PrintUnformatted(resp);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void route_api_workspaces_update(http_request_t *req, const char *ws_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_uuid(req->server->db, ws_uuid, &workspace) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Workspace not found");
        return;
    }
    
    if (!rbac_is_workspace_admin(req->server->db, req->user.id, workspace.id)) {
        http_respond_error(req->conn, 403, "Admin access required");
        return;
    }
    
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *name = json_get_string(json, "name");
    const char *description = json_get_string(json, "description");
    
    if (name) ldmd_strlcpy(workspace.name, name, LDMD_MAX_NAME);
    if (description) ldmd_strlcpy(workspace.description, description, LDMD_MAX_DESCRIPTION);
    
    workspace_update(req->server->db, &workspace);
    cJSON_Delete(json);
    
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

void route_api_workspaces_delete(http_request_t *req, const char *ws_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_uuid(req->server->db, ws_uuid, &workspace) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Workspace not found");
        return;
    }
    
    if (!rbac_is_workspace_admin(req->server->db, req->user.id, workspace.id)) {
        http_respond_error(req->conn, 403, "Admin access required");
        return;
    }
    
    workspace_delete(req->server->db, req->server->config, workspace.id);
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

void route_api_workspaces_members(http_request_t *req, const char *ws_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_uuid(req->server->db, ws_uuid, &workspace) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Workspace not found");
        return;
    }
    
    if (!rbac_is_workspace_admin(req->server->db, req->user.id, workspace.id)) {
        http_respond_error(req->conn, 403, "Admin access required");
        return;
    }
    
    ldmd_workspace_member_t *members = NULL;
    int count = 0;
    workspace_list_members(req->server->db, workspace.id, &members, &count);
    
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        ldmd_user_t user;
        if (db_user_get_by_id(req->server->db, members[i].user_id, &user) == LDMD_OK) {
            cJSON *m = cJSON_CreateObject();
            cJSON_AddStringToObject(m, "user_uuid", user.uuid);
            cJSON_AddStringToObject(m, "username", user.username);
            cJSON_AddStringToObject(m, "role", rbac_workspace_role_to_string(members[i].role));
            cJSON_AddItemToArray(arr, m);
        }
    }
    free(members);
    
    char *json_str = cJSON_PrintUnformatted(arr);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(arr);
}

void route_api_workspaces_add_member(http_request_t *req, const char *ws_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_uuid(req->server->db, ws_uuid, &workspace) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Workspace not found");
        return;
    }
    
    if (!rbac_is_workspace_admin(req->server->db, req->user.id, workspace.id)) {
        http_respond_error(req->conn, 403, "Admin access required");
        return;
    }
    
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *user_uuid = json_get_string(json, "user_uuid");
    const char *role_str = json_get_string(json, "role");
    
    if (!user_uuid) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "User UUID required");
        return;
    }
    
    ldmd_user_t user;
    if (db_user_get_by_uuid(req->server->db, user_uuid, &user) != LDMD_OK) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 404, "User not found");
        return;
    }
    
    ldmd_role_t role = role_str ? rbac_string_to_role(role_str) : ROLE_USER;
    
    workspace_add_member(req->server->db, workspace.id, user.id, role);
    cJSON_Delete(json);
    
    http_respond_json(req->conn, 201, "{\"success\":true}");
}

void route_api_workspaces_remove_member(http_request_t *req, const char *ws_uuid, 
                                        const char *user_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_uuid(req->server->db, ws_uuid, &workspace) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Workspace not found");
        return;
    }
    
    if (!rbac_is_workspace_admin(req->server->db, req->user.id, workspace.id)) {
        http_respond_error(req->conn, 403, "Admin access required");
        return;
    }
    
    ldmd_user_t user;
    if (db_user_get_by_uuid(req->server->db, user_uuid, &user) != LDMD_OK) {
        http_respond_error(req->conn, 404, "User not found");
        return;
    }

    // Managers (non-global-admins) cannot remove application admins
    if (user.global_role == ROLE_ADMIN && req->user.global_role != ROLE_ADMIN) {
        http_respond_error(req->conn, 403, "Cannot remove an application admin");
        return;
    }

    workspace_remove_member(req->server->db, workspace.id, user.id);
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

void route_api_projects_list(http_request_t *req, const char *ws_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_uuid(req->server->db, ws_uuid, &workspace) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Workspace not found");
        return;
    }
    
    if (!rbac_can_access_workspace(req->server->db, req->user.id, workspace.id)) {
        http_respond_error(req->conn, 403, "Access denied");
        return;
    }
    
    ldmd_project_t *projects = NULL;
    int count = 0;
    project_list(req->server->db, workspace.id, &projects, &count);
    
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON *p = cJSON_CreateObject();
        cJSON_AddStringToObject(p, "uuid", projects[i].uuid);
        cJSON_AddStringToObject(p, "name", projects[i].name);
        cJSON_AddStringToObject(p, "description", projects[i].description);
        cJSON_AddItemToArray(arr, p);
    }
    free(projects);
    
    char *json_str = cJSON_PrintUnformatted(arr);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(arr);
}

void route_api_projects_create(http_request_t *req, const char *ws_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_workspace_t workspace;
    if (db_workspace_get_by_uuid(req->server->db, ws_uuid, &workspace) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Workspace not found");
        return;
    }
    
    if (!rbac_can_edit_workspace(req->server->db, req->user.id, workspace.id)) {
        http_respond_error(req->conn, 403, "Edit access required");
        return;
    }
    
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *name = json_get_string(json, "name");
    const char *description = json_get_string(json, "description");
    
    if (!name) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "Name required");
        return;
    }
    
    ldmd_project_t project;
    ldmd_error_t err = project_create(req->server->db, req->server->config,
                                      workspace.id, name, description, req->user.id, &project);
    cJSON_Delete(json);
    
    if (err != LDMD_OK) {
        http_respond_error(req->conn, 500, "Failed to create project");
        return;
    }
    
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "uuid", project.uuid);
    cJSON_AddStringToObject(resp, "name", project.name);
    cJSON_AddStringToObject(resp, "description", project.description);
    
    char *json_str = cJSON_PrintUnformatted(resp);
    http_respond_json(req->conn, 201, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void route_api_projects_get(http_request_t *req, const char *project_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_project_t project;
    if (db_project_get_by_uuid(req->server->db, project_uuid, &project) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Project not found");
        return;
    }
    
    if (!rbac_can_access_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Access denied");
        return;
    }
    
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "uuid", project.uuid);
    cJSON_AddStringToObject(resp, "name", project.name);
    cJSON_AddStringToObject(resp, "description", project.description);
    
    char *json_str = cJSON_PrintUnformatted(resp);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void route_api_projects_update(http_request_t *req, const char *project_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_project_t proj;
    if (db_project_get_by_uuid(req->server->db, project_uuid, &proj) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Project not found");
        return;
    }
    
    if (!rbac_can_edit_workspace(req->server->db, req->user.id, proj.workspace_id)) {
        http_respond_error(req->conn, 403, "Edit access required");
        return;
    }
    
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *name = json_get_string(json, "name");
    const char *description = json_get_string(json, "description");
    
    if (name) ldmd_strlcpy(proj.name, name, LDMD_MAX_NAME);
    if (description) ldmd_strlcpy(proj.description, description, LDMD_MAX_DESCRIPTION);
    
    project_update(req->server->db, &proj);
    cJSON_Delete(json);
    
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

void route_api_projects_delete(http_request_t *req, const char *project_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_project_t proj;
    if (db_project_get_by_uuid(req->server->db, project_uuid, &proj) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Project not found");
        return;
    }
    
    if (!rbac_is_workspace_admin(req->server->db, req->user.id, proj.workspace_id)) {
        http_respond_error(req->conn, 403, "Admin access required");
        return;
    }
    
    project_delete(req->server->db, req->server->config, proj.id);
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

// Project member handlers (view permissions)
void route_api_projects_list_members(http_request_t *req, const char *project_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_project_t project;
    if (db_project_get_by_uuid(req->server->db, project_uuid, &project) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Project not found");
        return;
    }
    
    // Need edit access to the workspace to see project members
    if (!rbac_can_edit_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Edit access required");
        return;
    }
    
    ldmd_project_member_t *members = NULL;
    int count = 0;
    project_list_members(req->server->db, project.id, &members, &count);
    
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        ldmd_user_t user;
        if (db_user_get_by_id(req->server->db, members[i].user_id, &user) == LDMD_OK) {
            cJSON *m = cJSON_CreateObject();
            cJSON_AddStringToObject(m, "uuid", user.uuid);
            cJSON_AddStringToObject(m, "username", user.username);
            cJSON_AddStringToObject(m, "email", user.email);
            cJSON_AddBoolToObject(m, "can_view", members[i].can_view);
            cJSON_AddItemToArray(arr, m);
        }
    }
    free(members);
    
    char *json_str = cJSON_PrintUnformatted(arr);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(arr);
}

void route_api_projects_add_member(http_request_t *req, const char *project_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_project_t project;
    if (db_project_get_by_uuid(req->server->db, project_uuid, &project) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Project not found");
        return;
    }
    
    // Need edit access to the workspace to grant project view permissions
    if (!rbac_can_edit_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Edit access required");
        return;
    }
    
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *user_uuid = json_get_string(json, "user_uuid");
    if (!user_uuid) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "user_uuid required");
        return;
    }
    
    ldmd_user_t user;
    if (db_user_get_by_uuid(req->server->db, user_uuid, &user) != LDMD_OK) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 404, "User not found");
        return;
    }
    
    project_grant_view(req->server->db, project.id, user.id, req->user.id);
    cJSON_Delete(json);
    
    http_respond_json(req->conn, 201, "{\"success\":true}");
}

void route_api_projects_remove_member(http_request_t *req, const char *project_uuid,
                                      const char *user_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_project_t project;
    if (db_project_get_by_uuid(req->server->db, project_uuid, &project) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Project not found");
        return;
    }
    
    // Need edit access to the workspace to revoke project view permissions
    if (!rbac_can_edit_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Edit access required");
        return;
    }
    
    ldmd_user_t user;
    if (db_user_get_by_uuid(req->server->db, user_uuid, &user) != LDMD_OK) {
        http_respond_error(req->conn, 404, "User not found");
        return;
    }
    
    project_revoke_view(req->server->db, project.id, user.id);
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

void route_api_documents_list(http_request_t *req, const char *project_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_project_t project;
    if (db_project_get_by_uuid(req->server->db, project_uuid, &project) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Project not found");
        return;
    }
    
    if (!rbac_can_access_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Access denied");
        return;
    }
    
    ldmd_document_t *docs = NULL;
    int count = 0;
    document_list(req->server->db, project.id, &docs, &count);
    
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON *d = cJSON_CreateObject();
        cJSON_AddStringToObject(d, "uuid", docs[i].uuid);
        cJSON_AddStringToObject(d, "name", docs[i].name);
        cJSON_AddItemToArray(arr, d);
    }
    free(docs);
    
    char *json_str = cJSON_PrintUnformatted(arr);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(arr);
}

void route_api_documents_create(http_request_t *req, const char *project_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_project_t project;
    if (db_project_get_by_uuid(req->server->db, project_uuid, &project) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Project not found");
        return;
    }
    
    if (!rbac_can_edit_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Edit access required");
        return;
    }
    
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *name = json_get_string(json, "name");
    const char *content = json_get_string(json, "content");
    
    if (!name) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "Name required");
        return;
    }
    
    ldmd_document_t doc;
    ldmd_error_t err = document_create(req->server->db, req->server->config,
                                       project.id, name, content, req->user.id, &doc);
    cJSON_Delete(json);
    
    if (err != LDMD_OK) {
        http_respond_error(req->conn, 500, "Failed to create document");
        return;
    }
    
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "uuid", doc.uuid);
    cJSON_AddStringToObject(resp, "name", doc.name);
    
    char *json_str = cJSON_PrintUnformatted(resp);
    http_respond_json(req->conn, 201, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void route_api_documents_get(http_request_t *req, const char *doc_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_document_t doc;
    if (db_document_get_by_uuid(req->server->db, doc_uuid, &doc) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Document not found");
        return;
    }
    
    ldmd_project_t project;
    db_project_get_by_id(req->server->db, doc.project_id, &project);
    
    if (!rbac_can_access_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Access denied");
        return;
    }
    
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "uuid", doc.uuid);
    cJSON_AddStringToObject(resp, "name", doc.name);
    cJSON_AddStringToObject(resp, "project_uuid", project.uuid);
    
    char *json_str = cJSON_PrintUnformatted(resp);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void route_api_documents_update(http_request_t *req, const char *doc_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_document_t doc;
    if (db_document_get_by_uuid(req->server->db, doc_uuid, &doc) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Document not found");
        return;
    }
    
    ldmd_project_t project;
    db_project_get_by_id(req->server->db, doc.project_id, &project);
    
    if (!rbac_can_edit_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Edit access required");
        return;
    }
    
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }
    
    const char *name = json_get_string(json, "name");
    if (name) ldmd_strlcpy(doc.name, name, LDMD_MAX_NAME);
    
    doc.updated_by = req->user.id;
    document_update(req->server->db, &doc);
    cJSON_Delete(json);
    
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

void route_api_documents_delete(http_request_t *req, const char *doc_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_document_t doc;
    if (db_document_get_by_uuid(req->server->db, doc_uuid, &doc) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Document not found");
        return;
    }
    
    ldmd_project_t project;
    db_project_get_by_id(req->server->db, doc.project_id, &project);
    
    if (!rbac_can_edit_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Edit access required");
        return;
    }
    
    document_delete(req->server->db, req->server->config, doc.id);
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

void route_api_documents_content(http_request_t *req, const char *doc_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_document_t doc;
    if (db_document_get_by_uuid(req->server->db, doc_uuid, &doc) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Document not found");
        return;
    }
    
    ldmd_project_t project;
    db_project_get_by_id(req->server->db, doc.project_id, &project);
    
    if (method_is(req, "GET")) {
        if (!rbac_can_access_workspace(req->server->db, req->user.id, project.workspace_id)) {
            http_respond_error(req->conn, 403, "Access denied");
            return;
        }
        
        char *content = NULL;
        document_load_content(req->server->config, &doc, &content);
        
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "content", content ? content : "");
        free(content);
        
        char *json_str = cJSON_PrintUnformatted(resp);
        http_respond_json(req->conn, 200, json_str);
        free(json_str);
        cJSON_Delete(resp);
    } else if (method_is(req, "PUT") || method_is(req, "POST")) {
        if (!rbac_can_edit_workspace(req->server->db, req->user.id, project.workspace_id)) {
            http_respond_error(req->conn, 403, "Edit access required");
            return;
        }
        
        cJSON *json = parse_json_body(req);
        if (!json) {
            http_respond_error(req->conn, 400, "Invalid JSON");
            return;
        }
        
        const char *content = json_get_string(json, "content");
        document_save_content(req->server->config, &doc, content);
        
        doc.updated_by = req->user.id;
        document_update(req->server->db, &doc);
        
        cJSON_Delete(json);
        http_respond_json(req->conn, 200, "{\"success\":true}");
    }
}

void route_api_documents_render(http_request_t *req, const char *doc_uuid) {
    if (!require_auth(req)) return;
    
    ldmd_document_t doc;
    if (db_document_get_by_uuid(req->server->db, doc_uuid, &doc) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Document not found");
        return;
    }
    
    ldmd_project_t project;
    db_project_get_by_id(req->server->db, doc.project_id, &project);
    
    if (!rbac_can_access_workspace(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Access denied");
        return;
    }
    
    char *content = NULL;
    document_load_content(req->server->config, &doc, &content);
    
    char *html = NULL;
    if (content) {
        markdown_render(content, &html);
        free(content);
    }
    
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "html", html ? html : "");
    free(html);
    
    char *json_str = cJSON_PrintUnformatted(resp);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void route_api_admin_stats(http_request_t *req) {
    if (!require_admin(req)) return;
    
    int user_count = 0;
    db_user_count(req->server->db, &user_count);
    
    ldmd_workspace_t *workspaces = NULL;
    int workspace_count = 0;
    db_workspace_list(req->server->db, &workspaces, &workspace_count);
    free(workspaces);
    
    ldmd_password_request_t *requests = NULL;
    int pending_count = 0;
    db_password_request_list_pending(req->server->db, &requests, &pending_count);
    free(requests);

    int forgot_count = 0;
    db_password_forgot_count_pending(req->server->db, &forgot_count);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp, "users", user_count);
    cJSON_AddNumberToObject(resp, "workspaces", workspace_count);
    cJSON_AddNumberToObject(resp, "pending_password_requests", pending_count);
    cJSON_AddNumberToObject(resp, "pending_forgot_requests", forgot_count);
    
    char *json_str = cJSON_PrintUnformatted(resp);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void route_api_admin_password_requests(http_request_t *req) {
    if (!require_admin(req)) return;
    
    ldmd_password_request_t *requests = NULL;
    int count = 0;
    db_password_request_list_pending(req->server->db, &requests, &count);
    
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        ldmd_user_t user;
        if (db_user_get_by_id(req->server->db, requests[i].user_id, &user) == LDMD_OK) {
            cJSON *r = cJSON_CreateObject();
            cJSON_AddNumberToObject(r, "id", (double)requests[i].id);
            cJSON_AddStringToObject(r, "username", user.username);
            cJSON_AddNumberToObject(r, "created_at", (double)requests[i].created_at);
            cJSON_AddItemToArray(arr, r);
        }
    }
    free(requests);
    
    char *json_str = cJSON_PrintUnformatted(arr);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(arr);
}

void route_api_admin_approve_password(http_request_t *req, const char *request_id) {
    if (!require_admin(req)) return;
    
    int64_t id = atoll(request_id);
    ldmd_error_t err = auth_approve_password_change(req->server->db, id, req->user.id);
    
    if (err == LDMD_ERROR_NOT_FOUND) {
        http_respond_error(req->conn, 404, "Request not found");
        return;
    }
    
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

void route_api_admin_reject_password(http_request_t *req, const char *request_id) {
    if (!require_admin(req)) return;
    
    int64_t id = atoll(request_id);
    ldmd_error_t err = auth_reject_password_change(req->server->db, id, req->user.id);
    
    if (err == LDMD_ERROR_NOT_FOUND) {
        http_respond_error(req->conn, 404, "Request not found");
        return;
    }
    
    http_respond_json(req->conn, 200, "{\"success\":true}");
}

// ---- Forgot-password routes ----

void route_api_forgot_password(http_request_t *req) {
    // Public endpoint - no authentication required
    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }

    const char *username = json_get_string(json, "username");
    if (!username || strlen(username) == 0) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "Username required");
        return;
    }

    // Always succeed to avoid username enumeration
    auth_forgot_password(req->server->db, username);
    cJSON_Delete(json);

    http_respond_json(req->conn, 200,
        "{\"success\":true,\"message\":\"If this account exists, an admin has been notified\"}");
}

void route_api_admin_forgot_requests(http_request_t *req) {
    if (!require_admin(req)) return;

    ldmd_password_forgot_t *requests = NULL;
    int count = 0;
    db_password_forgot_list_pending(req->server->db, &requests, &count);

    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddNumberToObject(r, "id", (double)requests[i].id);
        cJSON_AddStringToObject(r, "username", requests[i].username);
        cJSON_AddNumberToObject(r, "created_at", (double)requests[i].created_at);
        cJSON_AddItemToArray(arr, r);
    }
    free(requests);

    char *json_str = cJSON_PrintUnformatted(arr);
    http_respond_json(req->conn, 200, json_str);
    free(json_str);
    cJSON_Delete(arr);
}

void route_api_admin_handle_forgot(http_request_t *req, const char *request_id) {
    if (!require_admin(req)) return;

    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }

    const char *new_password = json_get_string(json, "new_password");
    if (!new_password || strlen(new_password) == 0) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "new_password required");
        return;
    }

    int64_t id = atoll(request_id);
    ldmd_error_t err = auth_handle_forgot_password(req->server->db, req->server->config,
                                                   id, new_password, req->user.id);
    cJSON_Delete(json);

    if (err == LDMD_ERROR_NOT_FOUND) {
        http_respond_error(req->conn, 404, "Request not found");
    } else if (err == LDMD_ERROR_INVALID) {
        http_respond_error(req->conn, 400, "Password too short");
    } else if (err != LDMD_OK) {
        http_respond_error(req->conn, 500, "Internal error");
    } else {
        http_respond_json(req->conn, 200, "{\"success\":true}");
    }
}

void route_api_admin_reset_user_password(http_request_t *req, const char *user_uuid) {
    if (!require_admin(req)) return;

    cJSON *json = parse_json_body(req);
    if (!json) {
        http_respond_error(req->conn, 400, "Invalid JSON");
        return;
    }

    const char *new_password = json_get_string(json, "new_password");
    if (!new_password || strlen(new_password) == 0) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "new_password required");
        return;
    }

    ldmd_error_t err = auth_admin_reset_password(req->server->db, req->server->config,
                                                 user_uuid, new_password, req->user.id);
    cJSON_Delete(json);

    if (err == LDMD_ERROR_NOT_FOUND) {
        http_respond_error(req->conn, 404, "User not found");
    } else if (err == LDMD_ERROR_INVALID) {
        http_respond_error(req->conn, 400, "Password too short");
    } else if (err != LDMD_OK) {
        http_respond_error(req->conn, 500, "Internal error");
    } else {
        http_respond_json(req->conn, 200, "{\"success\":true}");
    }
}

void route_api_documents_ping(http_request_t *req, const char *doc_uuid) {
    if (!require_auth(req)) return;

    ldmd_error_t err = db_document_viewer_ping(req->server->db,
                                               doc_uuid,
                                               req->user.uuid,
                                               req->user.username);
    if (err != LDMD_OK) {
        http_respond_json(req->conn, 200, "{\"ok\":false}");
    } else {
        http_respond_json(req->conn, 200, "{\"ok\":true}");
    }
}

void route_api_documents_viewers(http_request_t *req, const char *doc_uuid) {
    if (!require_auth(req)) return;

    ldmd_viewer_t viewers[64];
    int count = 0;
    db_document_viewers_list(req->server->db, doc_uuid, viewers, 64, &count);

    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON *v = cJSON_CreateObject();
        cJSON_AddStringToObject(v, "uuid",      viewers[i].user_uuid);
        cJSON_AddStringToObject(v, "username",  viewers[i].username);
        cJSON_AddNumberToObject(v, "last_seen", (double)viewers[i].last_seen);
        cJSON_AddItemToArray(arr, v);
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "viewers", arr);
    cJSON_AddNumberToObject(root, "count", count);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (body) {
        http_respond_json(req->conn, 200, body);
        free(body);
    } else {
        http_respond_error(req->conn, 500, "Internal error");
    }
}
