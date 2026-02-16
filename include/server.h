#ifndef SERVER_H
#define SERVER_H

#include "localdocsmd.h"
#include "config.h"
#include "database.h"

// Forward declare mongoose types
struct mg_connection;
struct mg_http_message;

// Server structure
struct ldmd_server {
    struct mg_mgr *mgr;
    ldmd_config_t *config;
    ldmd_database_t *db;
    bool running;
};

/**
 * Create and initialize server
 * @param config Configuration
 * @param db Database handle
 * @return Server handle or NULL on error
 */
ldmd_server_t *server_create(ldmd_config_t *config, ldmd_database_t *db);

/**
 * Start server
 * @param server Server handle
 * @return LDMD_OK or error code
 */
ldmd_error_t server_start(ldmd_server_t *server);

/**
 * Stop server
 * @param server Server handle
 */
void server_stop(ldmd_server_t *server);

/**
 * Free server
 * @param server Server handle
 */
void server_free(ldmd_server_t *server);

/**
 * Run server main loop (blocking)
 * @param server Server handle
 */
void server_run(ldmd_server_t *server);

// HTTP helpers exposed for routes
void http_respond_json(struct mg_connection *c, int status, const char *json);
void http_respond_json_with_cookie(struct mg_connection *c, int status, const char *json, const char *token, int max_age);
void http_respond_html(struct mg_connection *c, int status, const char *html);
void http_respond_error(struct mg_connection *c, int status, const char *message);
void http_respond_redirect(struct mg_connection *c, const char *location);

// Request context
typedef struct {
    struct mg_connection *conn;
    struct mg_http_message *hm;
    ldmd_server_t *server;
    ldmd_session_t session;
    ldmd_user_t user;
    bool authenticated;
    bool is_localhost;
    char client_ip[64];
} http_request_t;

/**
 * Parse request and extract context
 * @param server Server handle
 * @param c Connection
 * @param hm HTTP message
 * @param req_out Output request context
 */
void http_parse_request(ldmd_server_t *server, struct mg_connection *c,
                        struct mg_http_message *hm, http_request_t *req_out);

/**
 * Get session token from request (cookie or header)
 * @param hm HTTP message
 * @param token_out Output buffer
 * @param token_size Buffer size
 * @return true if found
 */
bool http_get_session_token(struct mg_http_message *hm, char *token_out, size_t token_size);

/**
 * Set session cookie
 * @param c Connection
 * @param token Session token (NULL to clear)
 * @param max_age Max age in seconds
 */
void http_set_session_cookie(struct mg_connection *c, const char *token, int max_age);

#endif // SERVER_H
