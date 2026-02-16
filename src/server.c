#include "server.h"
#include "routes.h"
#include "auth.h"
#include "utils.h"
#include "mongoose.h"
#include <signal.h>
#include <string.h>

static volatile sig_atomic_t s_signo = 0;

static void signal_handler(int signo) {
    s_signo = signo;
}

// Extract client IP from connection
static void get_client_ip(struct mg_connection *c, char *ip_out, size_t size) {
    char buf[64] = {0};
    mg_snprintf(buf, sizeof(buf), "%M", mg_print_ip, &c->rem);
    ldmd_strlcpy(ip_out, buf, size);
}

// HTTP event handler
static void http_handler(struct mg_connection *c, int ev, void *ev_data) {
    ldmd_server_t *server = (ldmd_server_t *)c->fn_data;
    
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        
        http_request_t req;
        http_parse_request(server, c, hm, &req);
        
        // Log the request
        LOG_DEBUG("Request: %.*s %.*s", (int)hm->method.len, hm->method.buf,
                  (int)hm->uri.len, hm->uri.buf);
        
        // Try to handle with routes
        bool handled = routes_handle(&req);
        LOG_DEBUG("Route handled: %s", handled ? "yes" : "no");
        
        if (!handled) {
            // Serve static files
            struct mg_http_serve_opts opts = {
                .root_dir = server->config->web_root,
                .extra_headers = "Cache-Control: max-age=3600\r\n"
            };
            mg_http_serve_dir(c, hm, &opts);
        }
    }
}

void http_parse_request(ldmd_server_t *server, struct mg_connection *c,
                        struct mg_http_message *hm, http_request_t *req_out) {
    memset(req_out, 0, sizeof(*req_out));
    
    req_out->conn = c;
    req_out->hm = hm;
    req_out->server = server;
    
    // Get client IP
    get_client_ip(c, req_out->client_ip, sizeof(req_out->client_ip));
    req_out->is_localhost = auth_is_localhost(req_out->client_ip);
    
    // Try to get session
    char token[LDMD_TOKEN_LENGTH] = {0};
    if (http_get_session_token(hm, token, sizeof(token))) {
        if (auth_validate_session(server->db, token, &req_out->session) == LDMD_OK) {
            req_out->authenticated = true;
            db_user_get_by_id(server->db, req_out->session.user_id, &req_out->user);
        }
    }
    
    // Handle localhost admin auto-login
    if (!req_out->authenticated && req_out->is_localhost && server->config->localhost_admin) {
        // Check if requesting admin pages or API
        if (mg_match(hm->uri, mg_str("/admin*"), NULL) ||
            mg_match(hm->uri, mg_str("/api/admin*"), NULL)) {
            // Create admin session
            struct mg_str ua = mg_http_get_header(hm, "User-Agent") ? 
                              *mg_http_get_header(hm, "User-Agent") : mg_str("");
            char user_agent[512] = {0};
            if (ua.len > 0) {
                size_t copy_len = ua.len < sizeof(user_agent) - 1 ? ua.len : sizeof(user_agent) - 1;
                memcpy(user_agent, ua.buf, copy_len);
            }
            
            if (auth_localhost_admin_session(server->db, server->config,
                                            req_out->client_ip, user_agent,
                                            &req_out->session) == LDMD_OK) {
                req_out->authenticated = true;
                db_user_get_by_id(server->db, req_out->session.user_id, &req_out->user);
                
                // Set cookie for future requests
                http_set_session_cookie(c, req_out->session.token, 
                                       server->config->session_timeout);
            }
        }
    }
}

bool http_get_session_token(struct mg_http_message *hm, char *token_out, size_t token_size) {
    // Check Authorization header first
    struct mg_str *auth = mg_http_get_header(hm, "Authorization");
    if (auth && auth->len > 7 && strncmp(auth->buf, "Bearer ", 7) == 0) {
        size_t len = auth->len - 7;
        if (len < token_size) {
            memcpy(token_out, auth->buf + 7, len);
            token_out[len] = '\0';
            return true;
        }
    }
    
    // Check cookie
    struct mg_str *cookie_header = mg_http_get_header(hm, "Cookie");
    if (cookie_header) {
        // Parse session= from cookie header
        const char *session_start = strstr(cookie_header->buf, "session=");
        if (session_start) {
            session_start += 8; // Skip "session="
            const char *session_end = session_start;
            while (*session_end && *session_end != ';' && *session_end != ' ' && 
                   (size_t)(session_end - cookie_header->buf) < cookie_header->len) {
                session_end++;
            }
            size_t len = session_end - session_start;
            if (len > 0 && len < token_size) {
                memcpy(token_out, session_start, len);
                token_out[len] = '\0';
                return true;
            }
        }
    }
    
    return false;
}

// Build Set-Cookie header into provided buffer, returns the buffer
char *http_build_cookie_header(char *buf, size_t size, const char *token, int max_age) {
    if (token) {
        snprintf(buf, size, "Set-Cookie: session=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict\r\n",
                 token, max_age);
    } else {
        snprintf(buf, size, "Set-Cookie: session=; Path=/; Max-Age=0; HttpOnly\r\n");
    }
    return buf;
}

void http_set_session_cookie(struct mg_connection *c, const char *token, int max_age) {
    // Note: This should be called AFTER mg_http_reply sends status line
    // Kept for backward compatibility but prefer http_respond_json_with_cookie
    (void)c; (void)token; (void)max_age;
}

void http_respond_json(struct mg_connection *c, int status, const char *json) {
    mg_http_reply(c, status, "Content-Type: application/json\r\n", "%s", json);
}

void http_respond_json_with_cookie(struct mg_connection *c, int status, const char *json, const char *token, int max_age) {
    char cookie[256];
    char headers[512];
    http_build_cookie_header(cookie, sizeof(cookie), token, max_age);
    snprintf(headers, sizeof(headers), "Content-Type: application/json\r\n%s", cookie);
    mg_http_reply(c, status, headers, "%s", json);
}

void http_respond_html(struct mg_connection *c, int status, const char *html) {
    mg_http_reply(c, status, "Content-Type: text/html; charset=utf-8\r\n", "%s", html);
}

void http_respond_error(struct mg_connection *c, int status, const char *message) {
    char json[256];
    snprintf(json, sizeof(json), "{\"error\":\"%s\"}", message ? message : "Unknown error");
    http_respond_json(c, status, json);
}

void http_respond_redirect(struct mg_connection *c, const char *location) {
    char headers[256];
    snprintf(headers, sizeof(headers), "Location: %s\r\n", location);
    mg_http_reply(c, 302, headers, "");
}

ldmd_server_t *server_create(ldmd_config_t *config, ldmd_database_t *db) {
    ldmd_server_t *server = calloc(1, sizeof(ldmd_server_t));
    if (!server) {
        LOG_ERROR("Failed to allocate server");
        return NULL;
    }
    
    server->config = config;
    server->db = db;
    
    server->mgr = calloc(1, sizeof(struct mg_mgr));
    if (!server->mgr) {
        LOG_ERROR("Failed to allocate mongoose manager");
        free(server);
        return NULL;
    }
    
    mg_mgr_init(server->mgr);
    
    return server;
}

ldmd_error_t server_start(ldmd_server_t *server) {
    char listen_url[128];
    snprintf(listen_url, sizeof(listen_url), "http://%s:%d",
             server->config->server_host, server->config->server_port);
    
    struct mg_connection *c = mg_http_listen(server->mgr, listen_url, http_handler, server);
    if (!c) {
        LOG_ERROR("Failed to bind to %s", listen_url);
        return LDMD_ERROR;
    }
    
    server->running = true;
    
    LOG_INFO("Server started on %s", listen_url);
    LOG_INFO("Localhost admin access: %s", server->config->localhost_admin ? "enabled" : "disabled");
    
    return LDMD_OK;
}

void server_stop(ldmd_server_t *server) {
    if (server) {
        server->running = false;
    }
}

void server_free(ldmd_server_t *server) {
    if (server) {
        if (server->mgr) {
            mg_mgr_free(server->mgr);
            free(server->mgr);
        }
        free(server);
    }
}

void server_run(ldmd_server_t *server) {
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    LOG_INFO("Server running. Press Ctrl+C to stop.");
    
    // Periodic cleanup
    time_t last_cleanup = time(NULL);
    
    while (server->running && s_signo == 0) {
        mg_mgr_poll(server->mgr, 100);
        
        // Cleanup expired sessions every 5 minutes
        time_t now = time(NULL);
        if (now - last_cleanup > 300) {
            db_session_cleanup(server->db);
            last_cleanup = now;
        }
    }
    
    LOG_INFO("Server shutting down...");
}
