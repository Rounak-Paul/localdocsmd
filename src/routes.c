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
#include <ctype.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>

// Insert one row into activity_log for the current user
static void activity_log_insert(ldmd_database_t *db, int64_t user_id, const char *action) {
    sqlite3_stmt *stmt;
    const char *sql =
        "INSERT INTO activity_log (user_id, action, ts) VALUES (?, ?, ?)";
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, user_id);
        sqlite3_bind_text (stmt, 2, action, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, (int64_t)time(NULL));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

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

    char navbar[16384];
    const char *admin_link = (req->user.global_role == ROLE_ADMIN)
        ? "<a href=\"/admin\">Admin</a>"
        : "";
    const char *role_str = rbac_role_to_string(req->user.global_role);
    char avatar = (char)toupper((unsigned char)req->user.username[0]);
    const char *pending_badge = req->user.password_change_pending
        ? "<div class=\"user-dropdown-pending\">&#9679; Password change pending approval</div>"
        : "";

    snprintf(navbar, sizeof(navbar),
        "<nav class=\"navbar\">"
        "<div class=\"navbar-brand\"><a href=\"/dashboard\">Local<span>Docs</span>MD</a></div>"
        "<div class=\"navbar-menu\">"
        "%s"
        "<a href=\"/search\" class=\"navbar-search-link\" title=\"Search documents\">"
        "<svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"11\" cy=\"11\" r=\"8\"></circle><line x1=\"21\" y1=\"21\" x2=\"16.65\" y2=\"16.65\"></line></svg>"
        "Search"
        "</a>"
        "<div class=\"nav-popup-wrap\">"
        "<button class=\"nav-popup-btn\" onclick=\"toggleNavPopup('theme-dd')\" title=\"Theme\">"
        "<svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"12\" cy=\"12\" r=\"5\"></circle><line x1=\"12\" y1=\"1\" x2=\"12\" y2=\"3\"></line><line x1=\"12\" y1=\"21\" x2=\"12\" y2=\"23\"></line><line x1=\"4.22\" y1=\"4.22\" x2=\"5.64\" y2=\"5.64\"></line><line x1=\"18.36\" y1=\"18.36\" x2=\"19.78\" y2=\"19.78\"></line><line x1=\"1\" y1=\"12\" x2=\"3\" y2=\"12\"></line><line x1=\"21\" y1=\"12\" x2=\"23\" y2=\"12\"></line><line x1=\"4.22\" y1=\"19.78\" x2=\"5.64\" y2=\"18.36\"></line><line x1=\"18.36\" y1=\"5.64\" x2=\"19.78\" y2=\"4.22\"></line></svg>"
        "</button>"
        "<div class=\"nav-popup-menu\" id=\"theme-dd\">"
        "<div class=\"nav-popup-hdr\">Theme</div>"
        "<button class=\"nav-popup-item nav-theme-item\" data-theme=\"midnight\" onclick=\"setTheme('midnight')\"><span class=\"theme-swatch\" style=\"background:#0d1117;border-color:#30363d\"></span>Midnight</button>"
        "<button class=\"nav-popup-item nav-theme-item\" data-theme=\"daylight\" onclick=\"setTheme('daylight')\"><span class=\"theme-swatch\" style=\"background:#f8fafc;border-color:#e2e8f0\"></span>Daylight</button>"
        "<button class=\"nav-popup-item nav-theme-item\" data-theme=\"catppuccin\" onclick=\"setTheme('catppuccin')\"><span class=\"theme-swatch\" style=\"background:#1e1e2e;border-color:#cba6f7\"></span>Catppuccin</button>"
        "</div>"
        "</div>"
        "<div class=\"nav-popup-wrap\">"
        "<button class=\"nav-popup-btn\" onclick=\"toggleNavPopup('font-dd')\" title=\"Font\">Aa</button>"
        "<div class=\"nav-popup-menu\" id=\"font-dd\">"
        "<div class=\"nav-popup-hdr\">Font</div>"
        "<button class=\"nav-popup-item nav-font-item\" data-font=\"departure-mono\" onclick=\"setAppFont('departure-mono')\">Departure Mono NF</button>"
        "<button class=\"nav-popup-item nav-font-item\" data-font=\"cascadia-cove\" onclick=\"setAppFont('cascadia-cove')\">CaskaydiaCove NF</button>"
        "<button class=\"nav-popup-item nav-font-item\" data-font=\"jetbrains-mono\" onclick=\"setAppFont('jetbrains-mono')\">JetBrainsMono NF</button>"
        "</div>"
        "</div>"
        "<div class=\"user-menu\" id=\"user-menu\">"
        "<button class=\"navbar-user\" onclick=\"toggleUserMenu(event)\">"
        "<span class=\"user-avatar-sm\">%c</span>"
        "<span class=\"user-name-text\">%s</span>"
        "<svg width=\"12\" height=\"12\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><polyline points=\"6 9 12 15 18 9\"></polyline></svg>"
        "</button>"
        "<div class=\"user-dropdown\" id=\"user-dropdown\" style=\"display:none\">"
        "<div class=\"user-dropdown-header\">"
        "<div class=\"user-avatar-lg\">%c</div>"
        "<div class=\"user-dropdown-info\">"
        "<div class=\"user-dropdown-name\">%s</div>"
        "<div class=\"user-dropdown-email\">%s</div>"
        "<span class=\"badge badge-%s\">%s</span>"
        "</div>"
        "</div>"
        "%s"
        "<div class=\"user-dropdown-divider\"></div>"
        "<button class=\"user-dropdown-item\" onclick=\"openChangePassword()\"><svg width=\"15\" height=\"15\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><rect width=\"18\" height=\"11\" x=\"3\" y=\"11\" rx=\"2\" ry=\"2\"></rect><path d=\"M7 11V7a5 5 0 0 1 10 0v4\"></path></svg>Change Password</button>"
        "<div class=\"user-dropdown-divider\"></div>"
        "<button class=\"user-dropdown-item user-dropdown-item-danger\" onclick=\"logout()\"><svg width=\"15\" height=\"15\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4\"></path><polyline points=\"16 17 21 12 16 7\"></polyline><line x1=\"21\" y1=\"12\" x2=\"9\" y2=\"12\"></line></svg>Logout</button>"
        "</div>"
        "</div>"
        "</div>"
        "</nav>",
        admin_link,
        avatar, req->user.username,
        avatar, req->user.username, req->user.email,
        role_str, role_str,
        pending_badge);

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

    // Search page
    if (uri_match(req, "/search", NULL, NULL) && method_is(req, "GET")) {
        route_page_search(req);
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

    if (uri_match(req, "/api/documents/*/tags/*", param1, param2)) {
        if (method_is(req, "DELETE")) {
            route_api_document_tags_remove(req, param1, param2);
            return true;
        }
    }

    if (uri_match(req, "/api/documents/*/tags", param1, NULL)) {
        if (method_is(req, "GET")) {
            route_api_document_tags_list(req, param1);
            return true;
        }
        if (method_is(req, "POST")) {
            route_api_document_tags_add(req, param1);
            return true;
        }
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
    
    // Tags API
    if (uri_match(req, "/api/tags/*", param1, NULL)) {
        if (method_is(req, "DELETE")) {
            route_api_tags_delete(req, param1);
            return true;
        }
    }

    if (uri_match(req, "/api/tags", NULL, NULL)) {
        if (method_is(req, "GET")) {
            route_api_tags_list(req);
            return true;
        }
        if (method_is(req, "POST")) {
            route_api_tags_create(req);
            return true;
        }
    }

    // Search API
    if (uri_match(req, "/api/search", NULL, NULL) && method_is(req, "GET")) {
        route_api_search(req);
        return true;
    }

    // Admin API
    if (uri_match(req, "/api/admin/stats", NULL, NULL) && method_is(req, "GET")) {
        route_api_admin_stats(req);
        return true;
    }
    
    // Activity API (per-user heatmap data)
    if (uri_match(req, "/api/activity", NULL, NULL) && method_is(req, "GET")) {
        route_api_activity(req);
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
    template_set_bool(ctx, "can_manage", rbac_is_workspace_admin(req->server->db, req->user.id, workspace.id));
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
    template_set_bool(ctx, "can_manage", rbac_is_workspace_admin(req->server->db, req->user.id, project.workspace_id));
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
        cJSON_AddNumberToObject(ws, "created_at", (double)workspaces[i].created_at);
        cJSON_AddNumberToObject(ws, "updated_at", (double)workspaces[i].updated_at);

        /* user's effective role in this workspace */
        ldmd_role_t ws_role = ROLE_NONE;
        if (req->user.global_role >= ROLE_ADMIN) {
            ws_role = ROLE_ADMIN;
        } else {
            db_workspace_member_get_role(req->server->db, workspaces[i].id,
                                        req->user.id, &ws_role);
        }
        cJSON_AddStringToObject(ws, "user_role", rbac_workspace_role_to_string(ws_role));

        /* project count */
        int proj_count = 0;
        {
            sqlite3_stmt *cs;
            if (sqlite3_prepare_v2(req->server->db->db,
                    "SELECT COUNT(*) FROM projects WHERE workspace_id = ?",
                    -1, &cs, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(cs, 1, workspaces[i].id);
                if (sqlite3_step(cs) == SQLITE_ROW)
                    proj_count = sqlite3_column_int(cs, 0);
                sqlite3_finalize(cs);
            }
        }
        cJSON_AddNumberToObject(ws, "project_count", proj_count);

        /* member count */
        int mem_count = 0;
        {
            sqlite3_stmt *cs;
            if (sqlite3_prepare_v2(req->server->db->db,
                    "SELECT COUNT(*) FROM workspace_members WHERE workspace_id = ?",
                    -1, &cs, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(cs, 1, workspaces[i].id);
                if (sqlite3_step(cs) == SQLITE_ROW)
                    mem_count = sqlite3_column_int(cs, 0);
                sqlite3_finalize(cs);
            }
        }
        cJSON_AddNumberToObject(ws, "member_count", mem_count);

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
        cJSON_AddNumberToObject(p, "created_at", (double)projects[i].created_at);
        cJSON_AddNumberToObject(p, "updated_at", (double)projects[i].updated_at);

        /* document count */
        int doc_count = 0;
        {
            sqlite3_stmt *cs;
            if (sqlite3_prepare_v2(req->server->db->db,
                    "SELECT COUNT(*) FROM documents WHERE project_id = ?",
                    -1, &cs, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(cs, 1, projects[i].id);
                if (sqlite3_step(cs) == SQLITE_ROW)
                    doc_count = sqlite3_column_int(cs, 0);
                sqlite3_finalize(cs);
            }
        }
        cJSON_AddNumberToObject(p, "document_count", doc_count);

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

    activity_log_insert(req->server->db, req->user.id, "project_create");

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
    sqlite3 *raw = req->server->db->db;
    for (int i = 0; i < count; i++) {
        cJSON *d = cJSON_CreateObject();
        cJSON_AddStringToObject(d, "uuid", docs[i].uuid);
        cJSON_AddStringToObject(d, "name", docs[i].name);
        cJSON_AddNumberToObject(d, "created_at", (double)docs[i].created_at);
        cJSON_AddNumberToObject(d, "updated_at", (double)docs[i].updated_at);

        /* file size from filesystem */
        struct stat st;
        if (docs[i].path[0] != '\0' && stat(docs[i].path, &st) == 0) {
            cJSON_AddNumberToObject(d, "size", (double)st.st_size);
        } else {
            cJSON_AddNumberToObject(d, "size", 0);
        }

        /* created_by username */
        {
            sqlite3_stmt *su = NULL;
            if (sqlite3_prepare_v2(raw,
                    "SELECT username FROM users WHERE id = ?", -1, &su, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(su, 1, (sqlite3_int64)docs[i].created_by);
                if (sqlite3_step(su) == SQLITE_ROW) {
                    const char *uname = (const char *)sqlite3_column_text(su, 0);
                    cJSON_AddStringToObject(d, "created_by_username", uname ? uname : "");
                } else {
                    cJSON_AddStringToObject(d, "created_by_username", "");
                }
                sqlite3_finalize(su);
            } else {
                cJSON_AddStringToObject(d, "created_by_username", "");
            }
        }

        /* tags for this document */
        {
            cJSON *tags_arr = cJSON_CreateArray();
            sqlite3_stmt *st2 = NULL;
            if (sqlite3_prepare_v2(raw,
                    "SELECT t.id, t.name, t.color "
                    "FROM tags t "
                    "JOIN document_tags dt ON dt.tag_id = t.id "
                    "JOIN documents doc ON doc.id = dt.document_id "
                    "WHERE doc.uuid = ? "
                    "ORDER BY t.name", -1, &st2, NULL) == SQLITE_OK) {
                sqlite3_bind_text(st2, 1, docs[i].uuid, -1, SQLITE_STATIC);
                while (sqlite3_step(st2) == SQLITE_ROW) {
                    cJSON *tag = cJSON_CreateObject();
                    cJSON_AddNumberToObject(tag, "id", (double)sqlite3_column_int64(st2, 0));
                    const char *tn = (const char *)sqlite3_column_text(st2, 1);
                    const char *tc = (const char *)sqlite3_column_text(st2, 2);
                    cJSON_AddStringToObject(tag, "name", tn ? tn : "");
                    cJSON_AddStringToObject(tag, "color", tc ? tc : "blue");
                    cJSON_AddItemToArray(tags_arr, tag);
                }
                sqlite3_finalize(st2);
            }
            cJSON_AddItemToObject(d, "tags", tags_arr);
        }

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

    activity_log_insert(req->server->db, req->user.id, "doc_create");

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
    
    if (!rbac_is_workspace_admin(req->server->db, req->user.id, project.workspace_id)) {
        http_respond_error(req->conn, 403, "Manager access required");
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
        activity_log_insert(req->server->db, req->user.id, "doc_save");
        
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

void route_api_activity(http_request_t *req) {
    if (!require_auth(req)) return;

    /*
     * Primary source: activity_log (one row per event, deployed going forward).
     * Historical fallback: for events that predate activity_log, pull from
     * documents/projects/workspaces tables but ONLY for timestamps strictly
     * before the earliest activity_log entry for this user — this prevents
     * double-counting once activity_log starts filling in.
     *
     * Uses SQLite named parameter ?1 so a single bind covers all occurrences.
     */
    const char *sql =
        "WITH cutoff AS ("
        "  SELECT COALESCE(MIN(ts), 32503680000) AS t"
        "  FROM activity_log WHERE user_id = ?1"
        ")"
        "SELECT ts FROM activity_log WHERE user_id = ?1 "
        "UNION ALL "
        "SELECT updated_at FROM documents "
        "  WHERE updated_by = ?1 AND updated_at < (SELECT t FROM cutoff) "
        "UNION ALL "
        "SELECT created_at FROM documents "
        "  WHERE created_by = ?1 AND (updated_by IS NULL OR updated_by = ?1) "
        "  AND created_at < (SELECT t FROM cutoff) "
        "UNION ALL "
        "SELECT updated_at FROM projects "
        "  WHERE created_by = ?1 AND updated_at < (SELECT t FROM cutoff) "
        "UNION ALL "
        "SELECT created_at FROM workspaces "
        "  WHERE owner_id = ?1 AND created_at < (SELECT t FROM cutoff) "
        "ORDER BY ts DESC LIMIT 10000";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(req->server->db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        http_respond_error(req->conn, 500, "DB error");
        return;
    }

    int64_t uid = req->user.id;
    sqlite3_bind_int64(stmt, 1, uid);  /* ?1 covers all occurrences */

    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t ts = sqlite3_column_int64(stmt, 0);
        cJSON_AddItemToArray(arr, cJSON_CreateNumber((double)ts));
    }
    sqlite3_finalize(stmt);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "timestamps", arr);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (body) {
        http_respond_json(req->conn, 200, body);
        free(body);
    } else {
        http_respond_error(req->conn, 500, "Internal error");
    }
}

/* =========================================================
   TAGS  –  /api/tags   and   /api/documents/:uuid/tags
   ========================================================= */

void route_api_tags_list(http_request_t *req) {
    if (!require_auth(req)) return;
    sqlite3 *raw = req->server->db->db;
    sqlite3_stmt *stmt = NULL;
    cJSON *arr = cJSON_CreateArray();
    if (sqlite3_prepare_v2(raw,
            "SELECT id, name, color FROM tags ORDER BY name COLLATE NOCASE",
            -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            cJSON *t = cJSON_CreateObject();
            cJSON_AddNumberToObject(t, "id",    (double)sqlite3_column_int64(stmt, 0));
            const char *n = (const char *)sqlite3_column_text(stmt, 1);
            const char *c = (const char *)sqlite3_column_text(stmt, 2);
            cJSON_AddStringToObject(t, "name",  n ? n : "");
            cJSON_AddStringToObject(t, "color", c ? c : "blue");
            cJSON_AddItemToArray(arr, t);
        }
        sqlite3_finalize(stmt);
    }
    char *js = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    if (js) { http_respond_json(req->conn, 200, js); free(js); }
    else      http_respond_error(req->conn, 500, "Internal error");
}

void route_api_tags_create(http_request_t *req) {
    if (!require_auth(req)) return;
    cJSON *json = parse_json_body(req);
    if (!json) { http_respond_error(req->conn, 400, "Invalid JSON"); return; }

    const char *name  = json_get_string(json, "name");
    const char *color = json_get_string(json, "color");
    if (!name || name[0] == '\0') {
        cJSON_Delete(json);
        http_respond_error(req->conn, 400, "name required");
        return;
    }
    if (!color || color[0] == '\0') color = "blue";

    sqlite3 *raw = req->server->db->db;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(raw,
        "INSERT OR IGNORE INTO tags (name, color, created_at) VALUES (?, ?, ?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cJSON_Delete(json);
        http_respond_error(req->conn, 500, "DB prepare error");
        return;
    }
    sqlite3_bind_text (stmt, 1, name,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 2, color, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (int64_t)time(NULL));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    cJSON_Delete(json);

    /* Return the tag (existing or newly created) */
    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(raw,
            "SELECT id, name, color FROM tags WHERE name = ? COLLATE NOCASE",
            -1, &sel, NULL) != SQLITE_OK) {
        http_respond_error(req->conn, 500, "DB error");
        return;
    }
    sqlite3_bind_text(sel, 1, name, -1, SQLITE_TRANSIENT);
    cJSON *resp = cJSON_CreateObject();
    if (sqlite3_step(sel) == SQLITE_ROW) {
        cJSON_AddNumberToObject(resp, "id",    (double)sqlite3_column_int64(sel, 0));
        const char *n = (const char *)sqlite3_column_text(sel, 1);
        const char *c = (const char *)sqlite3_column_text(sel, 2);
        cJSON_AddStringToObject(resp, "name",  n ? n : "");
        cJSON_AddStringToObject(resp, "color", c ? c : "blue");
    }
    sqlite3_finalize(sel);
    char *js = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    if (js) { http_respond_json(req->conn, 201, js); free(js); }
    else      http_respond_error(req->conn, 500, "Internal error");
}

void route_api_tags_delete(http_request_t *req, const char *tag_id) {
    if (!require_auth(req)) return;
    sqlite3 *raw = req->server->db->db;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(raw,
            "DELETE FROM tags WHERE id = ?", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (int64_t)atoll(tag_id));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    http_respond_json(req->conn, 200, "{\"ok\":true}");
}

void route_api_document_tags_list(http_request_t *req, const char *doc_uuid) {
    if (!require_auth(req)) return;
    sqlite3 *raw = req->server->db->db;
    cJSON *arr = cJSON_CreateArray();
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(raw,
            "SELECT t.id, t.name, t.color "
            "FROM tags t "
            "JOIN document_tags dt ON dt.tag_id = t.id "
            "JOIN documents d      ON d.id = dt.document_id "
            "WHERE d.uuid = ? ORDER BY t.name COLLATE NOCASE",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, doc_uuid, -1, SQLITE_STATIC);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            cJSON *t = cJSON_CreateObject();
            cJSON_AddNumberToObject(t, "id",    (double)sqlite3_column_int64(stmt, 0));
            const char *n = (const char *)sqlite3_column_text(stmt, 1);
            const char *c = (const char *)sqlite3_column_text(stmt, 2);
            cJSON_AddStringToObject(t, "name",  n ? n : "");
            cJSON_AddStringToObject(t, "color", c ? c : "blue");
            cJSON_AddItemToArray(arr, t);
        }
        sqlite3_finalize(stmt);
    }
    char *js = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    if (js) { http_respond_json(req->conn, 200, js); free(js); }
    else      http_respond_error(req->conn, 500, "Internal error");
}

void route_api_document_tags_add(http_request_t *req, const char *doc_uuid) {
    if (!require_auth(req)) return;

    /* Check document access (write) */
    ldmd_document_t doc;
    if (db_document_get_by_uuid(req->server->db, doc_uuid, &doc) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Document not found");
        return;
    }
    ldmd_project_t proj;
    if (db_project_get_by_id(req->server->db, doc.project_id, &proj) != LDMD_OK ||
        !rbac_can_edit_workspace(req->server->db, req->user.id, proj.workspace_id)) {
        http_respond_error(req->conn, 403, "Edit access required");
        return;
    }

    cJSON *json = parse_json_body(req);
    if (!json) { http_respond_error(req->conn, 400, "Invalid JSON"); return; }

    /* Accept either {"tag_id": N} or {"name": "...", "color": "..."} */
    int64_t tag_id = 0;
    cJSON *tid = cJSON_GetObjectItem(json, "tag_id");
    if (tid && cJSON_IsNumber(tid)) {
        tag_id = (int64_t)tid->valuedouble;
    } else {
        const char *name  = json_get_string(json, "name");
        const char *color = json_get_string(json, "color");
        if (!name || name[0] == '\0') {
            cJSON_Delete(json);
            http_respond_error(req->conn, 400, "tag_id or name required");
            return;
        }
        if (!color || color[0] == '\0') color = "blue";
        sqlite3 *raw = req->server->db->db;
        /* Upsert tag */
        sqlite3_stmt *ins = NULL;
        if (sqlite3_prepare_v2(raw,
                "INSERT OR IGNORE INTO tags (name, color, created_at) VALUES (?, ?, ?)",
                -1, &ins, NULL) == SQLITE_OK) {
            sqlite3_bind_text (ins, 1, name,  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (ins, 2, color, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(ins, 3, (int64_t)time(NULL));
            sqlite3_step(ins);
            sqlite3_finalize(ins);
        }
        sqlite3_stmt *sel = NULL;
        if (sqlite3_prepare_v2(raw,
                "SELECT id FROM tags WHERE name = ? COLLATE NOCASE",
                -1, &sel, NULL) == SQLITE_OK) {
            sqlite3_bind_text(sel, 1, name, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(sel) == SQLITE_ROW)
                tag_id = sqlite3_column_int64(sel, 0);
            sqlite3_finalize(sel);
        }
    }
    cJSON_Delete(json);

    if (tag_id == 0) {
        http_respond_error(req->conn, 400, "Could not resolve tag");
        return;
    }

    sqlite3 *raw = req->server->db->db;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(raw,
            "INSERT OR IGNORE INTO document_tags (document_id, tag_id) "
            "SELECT d.id, ? FROM documents d WHERE d.uuid = ?",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, tag_id);
        sqlite3_bind_text (stmt, 2, doc_uuid, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    http_respond_json(req->conn, 200, "{\"ok\":true}");
}

void route_api_document_tags_remove(http_request_t *req,
                                     const char *doc_uuid, const char *tag_id) {
    if (!require_auth(req)) return;

    ldmd_document_t doc;
    if (db_document_get_by_uuid(req->server->db, doc_uuid, &doc) != LDMD_OK) {
        http_respond_error(req->conn, 404, "Document not found");
        return;
    }
    ldmd_project_t proj;
    if (db_project_get_by_id(req->server->db, doc.project_id, &proj) != LDMD_OK ||
        !rbac_can_edit_workspace(req->server->db, req->user.id, proj.workspace_id)) {
        http_respond_error(req->conn, 403, "Edit access required");
        return;
    }

    sqlite3 *raw = req->server->db->db;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(raw,
            "DELETE FROM document_tags "
            "WHERE document_id = (SELECT id FROM documents WHERE uuid = ?) "
            "AND tag_id = ?",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text (stmt, 1, doc_uuid, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, (int64_t)atoll(tag_id));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    http_respond_json(req->conn, 200, "{\"ok\":true}");
}

/* =========================================================
   SEARCH  –  GET /api/search?q=...
   Searches document names and file content across all
   workspaces the requesting user has access to.
   ========================================================= */

/* Case-insensitive substring helper */
static bool ci_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle || needle[0] == '\0') return false;
    return strcasestr(haystack, needle) != NULL;
}

/* Read up to max_bytes from a file into a malloc'd buffer (NUL-terminated).
   Returns NULL on error. Caller must free. */
static char *read_file_content(const char *path, size_t max_bytes) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = malloc(max_bytes + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, max_bytes, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

/* Extract a short snippet (~120 chars) around the first match of needle */
static void extract_snippet(const char *text, const char *needle,
                             char *out, size_t out_size) {
    if (!text || !needle || needle[0] == '\0' || out_size == 0) {
        if (out_size > 0) out[0] = '\0';
        return;
    }
    const char *pos = strcasestr(text, needle);
    if (!pos) {
        /* no match – return first chars */
        strncpy(out, text, out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }
    /* Center around match */
    int start = (int)(pos - text) - 40;
    if (start < 0) start = 0;
    /* skip to word boundary */
    while (start > 0 && text[start - 1] != ' ' && text[start - 1] != '\n') start--;
    const char *src = text + start;
    size_t copy = out_size - 1;
    strncpy(out, src, copy);
    out[copy] = '\0';
    /* trim at newline */
    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
}

void route_api_search(http_request_t *req) {
    if (!require_auth(req)) return;

    char q[256] = "";
    http_get_query_param(req, "q", q, sizeof(q));
    if (q[0] == '\0') {
        http_respond_json(req->conn, 200, "{\"results\":[]}");
        return;
    }

    int is_admin = (req->user.global_role == ROLE_ADMIN);
    sqlite3 *raw  = req->server->db->db;

    /* One query: all documents the user can access, most recently updated first.
       Access = admin, OR owner of workspace, OR explicit workspace_member. */
    const char *sql =
        "SELECT d.uuid, d.name, d.path, d.updated_at, "
        "       p.uuid AS project_uuid, p.name AS project_name, "
        "       w.uuid AS workspace_uuid, w.name AS workspace_name, "
        "       u.username AS created_by "
        "FROM documents d "
        "JOIN projects p ON p.id = d.project_id "
        "JOIN workspaces w ON w.id = p.workspace_id "
        "JOIN users u ON u.id = d.created_by "
        "WHERE (?1 = 1 "
        "  OR w.owner_id = ?2 "
        "  OR EXISTS(SELECT 1 FROM workspace_members wm "
        "             WHERE wm.workspace_id = w.id AND wm.user_id = ?2)) "
        "ORDER BY d.updated_at DESC "
        "LIMIT 300";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(raw, sql, -1, &stmt, NULL) != SQLITE_OK) {
        http_respond_error(req->conn, 500, "DB error");
        return;
    }
    sqlite3_bind_int  (stmt, 1, is_admin ? 1 : 0);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)req->user.id);

    cJSON *results = cJSON_CreateArray();
    int found = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW && found < 50) {
        const char *d_uuid  = (const char *)sqlite3_column_text(stmt, 0);
        const char *d_name  = (const char *)sqlite3_column_text(stmt, 1);
        const char *d_path  = (const char *)sqlite3_column_text(stmt, 2);
        int64_t d_updated   = sqlite3_column_int64(stmt, 3);
        const char *p_uuid  = (const char *)sqlite3_column_text(stmt, 4);
        const char *p_name  = (const char *)sqlite3_column_text(stmt, 5);
        const char *w_uuid  = (const char *)sqlite3_column_text(stmt, 6);
        const char *w_name  = (const char *)sqlite3_column_text(stmt, 7);
        const char *created_by = (const char *)sqlite3_column_text(stmt, 8);

        bool name_match = ci_contains(d_name, q);
        bool content_match = false;
        char snippet[200] = "";

        if (!name_match && d_path && d_path[0] != '\0') {
            char *fc = read_file_content(d_path, 65536); /* read up to 64 KB */
            if (fc) {
                content_match = ci_contains(fc, q);
                if (content_match) {
                    extract_snippet(fc, q, snippet, sizeof(snippet));
                }
                free(fc);
            }
        } else if (name_match) {
            /* For name matches show beginning of file as preview */
            if (d_path && d_path[0] != '\0') {
                char *fc = read_file_content(d_path, 300);
                if (fc) {
                    char *nl = strchr(fc, '\n');
                    if (nl) *nl = '\0';
                    strncpy(snippet, fc, sizeof(snippet) - 1);
                    snippet[sizeof(snippet) - 1] = '\0';
                    free(fc);
                }
            }
        }

        if (!name_match && !content_match) continue;

        cJSON *r = cJSON_CreateObject();
        cJSON_AddStringToObject(r, "uuid",           d_uuid     ? d_uuid     : "");
        cJSON_AddStringToObject(r, "name",           d_name     ? d_name     : "");
        cJSON_AddNumberToObject(r, "updated_at",     (double)d_updated);
        cJSON_AddStringToObject(r, "snippet",        snippet);
        cJSON_AddStringToObject(r, "match_type",     name_match ? "name" : "content");
        cJSON_AddStringToObject(r, "project_uuid",   p_uuid     ? p_uuid     : "");
        cJSON_AddStringToObject(r, "project_name",   p_name     ? p_name     : "");
        cJSON_AddStringToObject(r, "workspace_uuid", w_uuid     ? w_uuid     : "");
        cJSON_AddStringToObject(r, "workspace_name", w_name     ? w_name     : "");
        cJSON_AddStringToObject(r, "created_by",     created_by ? created_by : "");
        cJSON_AddItemToArray(results, r);
        found++;
    }
    sqlite3_finalize(stmt);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "results", results);
    cJSON_AddStringToObject(root, "query", q);
    cJSON_AddNumberToObject(root, "count", found);

    char *js = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (js) { http_respond_json(req->conn, 200, js); free(js); }
    else      http_respond_error(req->conn, 500, "Internal error");
}

/* =========================================================
   SEARCH PAGE  –  GET /search
   ========================================================= */

void route_page_search(http_request_t *req) {
    if (!require_auth(req)) return;

    template_ctx_t *ctx = template_create_context();
    template_set(ctx, "title", "Search - LocalDocsMD");
    template_set(ctx, "username", req->user.username);
    template_set(ctx, "is_admin", req->user.global_role == ROLE_ADMIN ? "true" : "");
    set_navbar(ctx, req);

    char *html = NULL;
    ldmd_error_t err = template_render_with_layout(req->server->config->web_root, "search.html", ctx, &html);
    template_free_context(ctx);

    if (err == LDMD_OK && html) {
        http_respond_html(req->conn, 200, html);
        free(html);
    } else {
        http_respond_error(req->conn, 500, "Template error");
    }
}void route_api_documents_ping(http_request_t *req, const char *doc_uuid) {
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
