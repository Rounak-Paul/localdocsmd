#ifndef SERVER_H
#define SERVER_H

#include "localdocsmd.h"
#include "config.h"
#include "database.h"
#include "mongoose.h"
#include <pthread.h>

/* mongoose.h provides the complete struct mg_http_message, mg_mgr,
   and mg_connection definitions needed by ldmd_work_item_t. */

/* ── Thread pool constants ──────────────────────────────────────── */
#define LDMD_MAX_WORKER_THREADS 64
#define LDMD_WORK_QUEUE_MAX     4096   /* max queued requests before back-pressure */

/* ── Per-request work item ─────────────────────────────────────── *
 * All fields that routes need are deep-copied here so the worker
 * thread never touches Mongoose's internal receive buffers.        */
typedef struct ldmd_work_item {
    /* routing key – used to deliver the response */
    unsigned long  conn_id;       /* mg_connection->id of the requester */
    struct mg_mgr *mgr;           /* main event-loop manager             */

    /* deep-copied HTTP data */
    char   method_buf[16];
    char   uri_buf[LDMD_MAX_PATH];
    char   query_buf[2048];
    char  *body_buf;              /* malloc'd, NULL if no body           */
    size_t body_buf_len;

    /* synthesised mg_http_message whose mg_str fields point to above */
    struct mg_http_message fake_hm;

    /* auth – resolved on the main thread before dispatch             */
    ldmd_session_t session;
    ldmd_user_t    user;
    bool           authenticated;
    bool           is_localhost;
    char           client_ip[64];

    /* response – filled by the worker thread                         */
    int   resp_status;
    char  resp_headers[1024];   /* complete header string, e.g.
                                   "Content-Type: …\r\nSet-Cookie: …\r\n" */
    char *resp_body;            /* malloc'd, NULL for empty body       */
    size_t resp_body_len;

    struct ldmd_work_item *next;
} ldmd_work_item_t;

/* ── Thread-local response capture ────────────────────────────── *
 * When http_respond_* is called from a worker thread the TLS key
 * points to one of these; the function populates it instead of
 * calling mg_http_reply.                                           */
typedef struct {
    bool   active;
    int    status;
    char   headers[1024];
    char  *body;       /* malloc'd */
    size_t body_len;
} ldmd_resp_capture_t;

/* Thread-local key – defined in server.c, extern here             */
extern pthread_key_t g_resp_capture_key;

/* ── Thread pool ───────────────────────────────────────────────── */
typedef struct ldmd_thread_pool {
    /* pending work */
    pthread_mutex_t  work_mutex;
    pthread_cond_t   work_cond;
    ldmd_work_item_t *work_head, *work_tail;
    int              work_count;

    /* completed responses waiting to be sent by main thread */
    pthread_mutex_t  resp_mutex;
    ldmd_work_item_t *resp_head;

    /* worker threads */
    pthread_t        threads[LDMD_MAX_WORKER_THREADS];
    int              num_threads;
    volatile bool    shutdown;

    /* per-worker DB connections (index == worker slot) */
    ldmd_database_t *dbs[LDMD_MAX_WORKER_THREADS];

    /* back-reference */
    struct ldmd_server *server;
} ldmd_thread_pool_t;

/* ── Server structure ──────────────────────────────────────────── */
struct ldmd_server {
    struct mg_mgr      *mgr;
    ldmd_config_t      *config;
    ldmd_database_t    *db;       /* main-thread DB connection   */
    bool                running;
    ldmd_thread_pool_t *pool;     /* NULL when num_threads == 0  */
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
    struct mg_connection   *conn;   /* may be NULL for worker-thread requests */
    struct mg_http_message *hm;
    ldmd_server_t          *server;
    ldmd_session_t          session;
    ldmd_user_t             user;
    bool                    authenticated;
    bool                    is_localhost;
    char                    client_ip[64];
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
 * Get query parameter from request
 * @param req Request context
 * @param name Parameter name
 * @param value_out Output buffer
 * @param value_size Buffer size
 * @return true if found
 */
bool http_get_query_param(http_request_t *req, const char *name, char *value_out, size_t value_size);

/**
 * Set session cookie
 * @param c Connection
 * @param token Session token (NULL to clear)
 * @param max_age Max age in seconds
 */
void http_set_session_cookie(struct mg_connection *c, const char *token, int max_age);

/**
 * Build Set-Cookie header string into buf, returns buf.
 */
char *http_build_cookie_header(char *buf, size_t size, const char *token, int max_age);

#endif // SERVER_H
