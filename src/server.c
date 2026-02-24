#include "server.h"
#include "routes.h"
#include "auth.h"
#include "utils.h"
#include "mongoose.h"
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>   /* sysconf */

/* ── Signals ──────────────────────────────────────────────────── */
static volatile sig_atomic_t s_signo = 0;

static void signal_handler(int signo) {
    s_signo = signo;
}

/* ── Thread-local response capture key ───────────────────────── */
pthread_key_t g_resp_capture_key;

static void resp_capture_destructor(void *p) {
    if (p) {
        ldmd_resp_capture_t *cap = (ldmd_resp_capture_t *)p;
        free(cap->body);
        free(cap);
    }
}

/* ── Static-file heuristic ────────────────────────────────────── *
 * Returns true for URIs under /css/, /js/, or any URI whose last
 * path segment contains a dot (has a file extension).            */
static bool is_static_path(struct mg_str uri) {
    if (mg_match(uri, mg_str("/css/**"), NULL)) return true;
    if (mg_match(uri, mg_str("/js/**"),  NULL)) return true;
    const char *last_slash = uri.buf;
    for (size_t i = 0; i < uri.len; i++) {
        if (uri.buf[i] == '/') last_slash = uri.buf + i;
    }
    for (const char *p = last_slash; p < uri.buf + uri.len; p++) {
        if (*p == '.') return true;
    }
    return false;
}

/* ── Work-item helpers ────────────────────────────────────────── */
static void work_item_free(ldmd_work_item_t *w) {
    if (!w) return;
    free(w->body_buf);
    free(w->resp_body);
    free(w);
}

/* ── Thread pool: push pending work ──────────────────────────── */
static void pool_push_work(ldmd_thread_pool_t *pool, ldmd_work_item_t *item) {
    pthread_mutex_lock(&pool->work_mutex);
    item->next = NULL;
    if (pool->work_tail) pool->work_tail->next = item;
    else                 pool->work_head       = item;
    pool->work_tail = item;
    pool->work_count++;
    pthread_cond_signal(&pool->work_cond);
    pthread_mutex_unlock(&pool->work_mutex);
}

static ldmd_work_item_t *pool_pop_work(ldmd_thread_pool_t *pool) {
    pthread_mutex_lock(&pool->work_mutex);
    while (pool->work_head == NULL && !pool->shutdown)
        pthread_cond_wait(&pool->work_cond, &pool->work_mutex);
    ldmd_work_item_t *item = pool->work_head;
    if (item) {
        pool->work_head = item->next;
        if (!pool->work_head) pool->work_tail = NULL;
        pool->work_count--;
    }
    pthread_mutex_unlock(&pool->work_mutex);
    return item;
}

static void pool_push_response(ldmd_thread_pool_t *pool, ldmd_work_item_t *item) {
    pthread_mutex_lock(&pool->resp_mutex);
    item->next      = pool->resp_head;
    pool->resp_head = item;
    pthread_mutex_unlock(&pool->resp_mutex);
}

static ldmd_work_item_t *pool_pop_response(ldmd_thread_pool_t *pool,
                                            unsigned long conn_id) {
    pthread_mutex_lock(&pool->resp_mutex);
    ldmd_work_item_t *prev = NULL, *cur = pool->resp_head;
    while (cur) {
        if (cur->conn_id == conn_id) {
            if (prev) prev->next = cur->next;
            else      pool->resp_head = cur->next;
            cur->next = NULL;
            pthread_mutex_unlock(&pool->resp_mutex);
            return cur;
        }
        prev = cur; cur = cur->next;
    }
    pthread_mutex_unlock(&pool->resp_mutex);
    return NULL;
}

/* ── Worker thread arg ────────────────────────────────────────── */
typedef struct {
    int                 slot;
    ldmd_thread_pool_t *pool;
} worker_arg_t;

/* ── Worker thread function ───────────────────────────────────── */
static void *worker_thread_fn(void *arg) {
    worker_arg_t       *wa   = (worker_arg_t *)arg;
    int                 slot = wa->slot;
    ldmd_thread_pool_t *pool = wa->pool;
    free(wa);

    ldmd_server_t *server = pool->server;

    /* Allocate thread-local response capture */
    ldmd_resp_capture_t *cap = calloc(1, sizeof(ldmd_resp_capture_t));
    if (!cap) { LOG_ERROR("[Worker %d] OOM", slot); return NULL; }
    pthread_setspecific(g_resp_capture_key, cap);

    /* Open this thread's private DB connection */
    pool->dbs[slot] = db_init(server->config->db_path);
    if (!pool->dbs[slot]) {
        LOG_ERROR("[Worker %d] Failed to open database", slot);
        return NULL;
    }

    /* Build a per-thread server context pointing to our own DB */
    ldmd_server_t thread_server;
    memset(&thread_server, 0, sizeof(thread_server));
    thread_server.config  = server->config;
    thread_server.db      = pool->dbs[slot];
    thread_server.running = true;
    thread_server.pool    = pool;
    /* mgr stays NULL in thread_server; routes only use config/db  */

    LOG_INFO("[Worker %d] Ready", slot);

    for (;;) {
        ldmd_work_item_t *item = pool_pop_work(pool);
        if (!item) break; /* shutdown */

        /* Set up thread_server.mgr so routes can reference it if needed */
        thread_server.mgr = item->mgr;

        /* Build http_request_t from deep-copied work item */
        http_request_t req;
        memset(&req, 0, sizeof(req));
        req.conn          = NULL;    /* responses captured via TLS */
        req.hm            = &item->fake_hm;
        req.server        = &thread_server;
        req.session       = item->session;
        req.user          = item->user;
        req.authenticated = item->authenticated;
        req.is_localhost  = item->is_localhost;
        ldmd_strlcpy(req.client_ip, item->client_ip, sizeof(req.client_ip));

        /* Arm TLS capture */
        cap->active    = false;
        cap->status    = 0;
        cap->headers[0] = '\0';
        free(cap->body);
        cap->body      = NULL;
        cap->body_len  = 0;

        bool handled = routes_handle(&req);

        if (!handled && !cap->active) {
            cap->active    = true;
            cap->status    = 404;
            snprintf(cap->headers, sizeof(cap->headers),
                     "Content-Type: text/plain\r\n");
            cap->body      = strdup("Not found");
            cap->body_len  = 9;
        }

        if (cap->active) {
            item->resp_status   = cap->status;
            ldmd_strlcpy(item->resp_headers, cap->headers,
                         sizeof(item->resp_headers));
            item->resp_body     = cap->body;  /* transfer ownership */
            item->resp_body_len = cap->body_len;
            cap->body     = NULL;
            cap->body_len = 0;

            pool_push_response(pool, item);
            if (!mg_wakeup(item->mgr, item->conn_id, NULL, 0)) {
                /* Connection already gone – discard */
                ldmd_work_item_t *stale =
                    pool_pop_response(pool, item->conn_id);
                if (stale) work_item_free(stale);
            }
        } else {
            work_item_free(item);
        }
    }

    LOG_INFO("[Worker %d] Exiting", slot);
    return NULL;
}

/* ── IP extraction ────────────────────────────────────────────── */
static void get_client_ip(struct mg_connection *c, char *ip_out, size_t size) {
    char buf[64] = {0};
    mg_snprintf(buf, sizeof(buf), "%M", mg_print_ip, &c->rem);
    ldmd_strlcpy(ip_out, buf, size);
}

/* ── Main HTTP event handler ──────────────────────────────────── */
static void http_handler(struct mg_connection *c, int ev, void *ev_data) {
    ldmd_server_t *server = (ldmd_server_t *)c->fn_data;

    /* ── Worker has finished: send the buffered response ── */
    if (ev == MG_EV_WAKEUP) {
        if (!server->pool) return;
        ldmd_work_item_t *resp = pool_pop_response(server->pool, c->id);
        if (resp) {
            mg_http_reply(c, resp->resp_status, resp->resp_headers,
                          "%.*s",
                          (int)resp->resp_body_len,
                          resp->resp_body ? resp->resp_body : "");
            work_item_free(resp);
        }
        return;
    }

    if (ev != MG_EV_HTTP_MSG) return;
    struct mg_http_message *hm = (struct mg_http_message *)ev_data;

    LOG_DEBUG("Request: %.*s %.*s",
              (int)hm->method.len, hm->method.buf,
              (int)hm->uri.len,    hm->uri.buf);

    /* ── Static files: serve synchronously on main thread ── */
    if (is_static_path(hm->uri)) {
        struct mg_http_serve_opts opts = {
            .root_dir      = server->config->web_root,
            .extra_headers = "Cache-Control: max-age=3600\r\n"
        };
        mg_http_serve_dir(c, hm, &opts);
        return;
    }

    /* ── Dispatch to thread pool ── */
    if (server->pool) {
        if (server->pool->work_count >= LDMD_WORK_QUEUE_MAX) {
            mg_http_reply(c, 503,
                          "Content-Type: application/json\r\n",
                          "{\"error\":\"Server busy\"}");
            return;
        }

        ldmd_work_item_t *item = calloc(1, sizeof(ldmd_work_item_t));
        if (!item) {
            mg_http_reply(c, 500,
                          "Content-Type: application/json\r\n",
                          "{\"error\":\"Out of memory\"}");
            return;
        }

        item->conn_id = c->id;
        item->mgr     = server->mgr;

        /* Deep-copy method */
        size_t n = hm->method.len < sizeof(item->method_buf) - 1
                   ? hm->method.len : sizeof(item->method_buf) - 1;
        memcpy(item->method_buf, hm->method.buf, n);
        item->method_buf[n] = '\0';

        /* Deep-copy URI */
        n = hm->uri.len < sizeof(item->uri_buf) - 1
            ? hm->uri.len : sizeof(item->uri_buf) - 1;
        memcpy(item->uri_buf, hm->uri.buf, n);
        item->uri_buf[n] = '\0';

        /* Deep-copy query */
        n = hm->query.len < sizeof(item->query_buf) - 1
            ? hm->query.len : sizeof(item->query_buf) - 1;
        memcpy(item->query_buf, hm->query.buf, n);
        item->query_buf[n] = '\0';

        /* Deep-copy body */
        if (hm->body.len > 0) {
            item->body_buf = malloc(hm->body.len + 1);
            if (item->body_buf) {
                memcpy(item->body_buf, hm->body.buf, hm->body.len);
                item->body_buf[hm->body.len] = '\0';
                item->body_buf_len = hm->body.len;
            }
        }

        /* Wire fake mg_http_message to point at our copies */
        memset(&item->fake_hm, 0, sizeof(item->fake_hm));
        item->fake_hm.method.buf = item->method_buf;
        item->fake_hm.method.len = strlen(item->method_buf);
        item->fake_hm.uri.buf    = item->uri_buf;
        item->fake_hm.uri.len    = strlen(item->uri_buf);
        item->fake_hm.query.buf  = item->query_buf;
        item->fake_hm.query.len  = strlen(item->query_buf);
        if (item->body_buf) {
            item->fake_hm.body.buf = item->body_buf;
            item->fake_hm.body.len = item->body_buf_len;
        }

        /* Resolve auth on main thread (fast indexed lookup) */
        char token[LDMD_TOKEN_LENGTH] = {0};
        if (http_get_session_token(hm, token, sizeof(token))) {
            if (auth_validate_session(server->db, token,
                                      &item->session) == LDMD_OK) {
                item->authenticated = true;
                db_user_get_by_id(server->db, item->session.user_id,
                                  &item->user);
            }
        }
        get_client_ip(c, item->client_ip, sizeof(item->client_ip));
        item->is_localhost = auth_is_localhost(item->client_ip);

        pool_push_work(server->pool, item);
        return;
    }

    /* ── Single-threaded fallback (pool == NULL) ── */
    http_request_t req;
    http_parse_request(server, c, hm, &req);
    bool handled = routes_handle(&req);
    if (!handled) {
        struct mg_http_serve_opts opts = {
            .root_dir      = server->config->web_root,
            .extra_headers = "Cache-Control: max-age=3600\r\n"
        };
        mg_http_serve_dir(c, hm, &opts);
    }
}

/* ── http_parse_request ───────────────────────────────────────── */
void http_parse_request(ldmd_server_t *server, struct mg_connection *c,
                        struct mg_http_message *hm, http_request_t *req_out) {
    memset(req_out, 0, sizeof(*req_out));
    req_out->conn   = c;
    req_out->hm     = hm;
    req_out->server = server;
    get_client_ip(c, req_out->client_ip, sizeof(req_out->client_ip));
    req_out->is_localhost = auth_is_localhost(req_out->client_ip);
    char token[LDMD_TOKEN_LENGTH] = {0};
    if (http_get_session_token(hm, token, sizeof(token))) {
        if (auth_validate_session(server->db, token,
                                  &req_out->session) == LDMD_OK) {
            req_out->authenticated = true;
            db_user_get_by_id(server->db, req_out->session.user_id,
                              &req_out->user);
        }
    }
}

/* ── http_respond_* – TLS-aware wrappers ─────────────────────── */

void http_respond_json(struct mg_connection *c, int status, const char *json) {
    ldmd_resp_capture_t *cap =
        (ldmd_resp_capture_t *)pthread_getspecific(g_resp_capture_key);
    if (cap) {
        cap->active = true; cap->status = status;
        snprintf(cap->headers, sizeof(cap->headers),
                 "Content-Type: application/json\r\n");
        free(cap->body);
        cap->body     = strdup(json ? json : "");
        cap->body_len = cap->body ? strlen(cap->body) : 0;
    } else {
        mg_http_reply(c, status,
                      "Content-Type: application/json\r\n",
                      "%s", json ? json : "");
    }
}

void http_respond_json_with_cookie(struct mg_connection *c, int status,
                                    const char *json, const char *token,
                                    int max_age) {
    char cookie[256];
    http_build_cookie_header(cookie, sizeof(cookie), token, max_age);

    ldmd_resp_capture_t *cap =
        (ldmd_resp_capture_t *)pthread_getspecific(g_resp_capture_key);
    if (cap) {
        cap->active = true; cap->status = status;
        snprintf(cap->headers, sizeof(cap->headers),
                 "Content-Type: application/json\r\n%s", cookie);
        free(cap->body);
        cap->body     = strdup(json ? json : "");
        cap->body_len = cap->body ? strlen(cap->body) : 0;
    } else {
        char hdrs[512];
        snprintf(hdrs, sizeof(hdrs),
                 "Content-Type: application/json\r\n%s", cookie);
        mg_http_reply(c, status, hdrs, "%s", json ? json : "");
    }
}

void http_respond_html(struct mg_connection *c, int status, const char *html) {
    ldmd_resp_capture_t *cap =
        (ldmd_resp_capture_t *)pthread_getspecific(g_resp_capture_key);
    if (cap) {
        cap->active = true; cap->status = status;
        snprintf(cap->headers, sizeof(cap->headers),
                 "Content-Type: text/html; charset=utf-8\r\n"
                 "Cache-Control: no-store\r\n");
        free(cap->body);
        cap->body     = strdup(html ? html : "");
        cap->body_len = cap->body ? strlen(cap->body) : 0;
    } else {
        mg_http_reply(c, status,
                      "Content-Type: text/html; charset=utf-8\r\n"
                      "Cache-Control: no-store\r\n",
                      "%s", html ? html : "");
    }
}

void http_respond_error(struct mg_connection *c, int status,
                         const char *message) {
    char json[256];
    snprintf(json, sizeof(json), "{\"error\":\"%s\"}",
             message ? message : "Unknown error");
    http_respond_json(c, status, json);
}

void http_respond_redirect(struct mg_connection *c, const char *location) {
    ldmd_resp_capture_t *cap =
        (ldmd_resp_capture_t *)pthread_getspecific(g_resp_capture_key);
    if (cap) {
        cap->active = true; cap->status = 302;
        snprintf(cap->headers, sizeof(cap->headers),
                 "Location: %s\r\n", location ? location : "/");
        free(cap->body);
        cap->body     = strdup("");
        cap->body_len = 0;
    } else {
        char hdrs[256];
        snprintf(hdrs, sizeof(hdrs), "Location: %s\r\n", location);
        mg_http_reply(c, 302, hdrs, "");
    }
}

/* ── Cookie helper ────────────────────────────────────────────── */
char *http_build_cookie_header(char *buf, size_t size,
                                const char *token, int max_age) {
    if (token) {
        snprintf(buf, size,
                 "Set-Cookie: session=%s; Path=/; Max-Age=%d; "
                 "HttpOnly; SameSite=Strict\r\n", token, max_age);
    } else {
        snprintf(buf, size,
                 "Set-Cookie: session=; Path=/; Max-Age=0; HttpOnly\r\n");
    }
    return buf;
}

/* ── Session-token extraction ─────────────────────────────────── */
bool http_get_session_token(struct mg_http_message *hm,
                             char *token_out, size_t token_size) {
    struct mg_str *auth = mg_http_get_header(hm, "Authorization");
    if (auth && auth->len > 7 && strncmp(auth->buf, "Bearer ", 7) == 0) {
        size_t len = auth->len - 7;
        if (len < token_size) {
            memcpy(token_out, auth->buf + 7, len);
            token_out[len] = '\0';
            return true;
        }
    }
    struct mg_str *cookie_hdr = mg_http_get_header(hm, "Cookie");
    if (cookie_hdr) {
        const char *s = strstr(cookie_hdr->buf, "session=");
        if (s) {
            s += 8;
            const char *e = s;
            while (*e && *e != ';' && *e != ' ' &&
                   (size_t)(e - cookie_hdr->buf) < cookie_hdr->len) e++;
            size_t len = (size_t)(e - s);
            if (len > 0 && len < token_size) {
                memcpy(token_out, s, len);
                token_out[len] = '\0';
                return true;
            }
        }
    }
    return false;
}

bool http_get_query_param(http_request_t *req, const char *name,
                           char *value_out, size_t value_size) {
    if (!req || !req->hm || !name || !value_out || value_size == 0) return false;
    return mg_http_get_var(&req->hm->query, name,
                           value_out, (int)value_size) > 0;
}

void http_set_session_cookie(struct mg_connection *c, const char *token,
                              int max_age) {
    (void)c; (void)token; (void)max_age; /* kept for ABI compat */
}

/* ── Thread pool lifecycle ────────────────────────────────────── */
static ldmd_thread_pool_t *pool_create(ldmd_server_t *server, int num_threads) {
    ldmd_thread_pool_t *pool = calloc(1, sizeof(ldmd_thread_pool_t));
    if (!pool) return NULL;

    pthread_mutex_init(&pool->work_mutex, NULL);
    pthread_cond_init (&pool->work_cond,  NULL);
    pthread_mutex_init(&pool->resp_mutex, NULL);
    pool->server      = server;
    pool->num_threads = 0;

    for (int i = 0; i < num_threads && i < LDMD_MAX_WORKER_THREADS; i++) {
        worker_arg_t *wa = malloc(sizeof(worker_arg_t));
        if (!wa) break;
        wa->slot = i;
        wa->pool = pool;
        if (pthread_create(&pool->threads[i], NULL, worker_thread_fn, wa) != 0) {
            free(wa);
            break;
        }
        pool->num_threads++;
    }

    LOG_INFO("Thread pool started with %d worker(s)", pool->num_threads);
    return pool;
}

static void pool_destroy(ldmd_thread_pool_t *pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->work_mutex);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->work_cond);
    pthread_mutex_unlock(&pool->work_mutex);
    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
        if (pool->dbs[i]) { db_close(pool->dbs[i]); pool->dbs[i] = NULL; }
    }
    ldmd_work_item_t *cur;
    cur = pool->work_head;
    while (cur) { ldmd_work_item_t *n = cur->next; work_item_free(cur); cur = n; }
    cur = pool->resp_head;
    while (cur) { ldmd_work_item_t *n = cur->next; work_item_free(cur); cur = n; }
    pthread_mutex_destroy(&pool->work_mutex);
    pthread_cond_destroy (&pool->work_cond);
    pthread_mutex_destroy(&pool->resp_mutex);
    free(pool);
}

/* ── Server create / start / run / free ──────────────────────── */
ldmd_server_t *server_create(ldmd_config_t *config, ldmd_database_t *db) {
    static int tls_init_done = 0;
    if (!tls_init_done) {
        pthread_key_create(&g_resp_capture_key, resp_capture_destructor);
        tls_init_done = 1;
    }

    ldmd_server_t *server = calloc(1, sizeof(ldmd_server_t));
    if (!server) { LOG_ERROR("Failed to allocate server"); return NULL; }
    server->config = config;
    server->db     = db;

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

    struct mg_connection *c =
        mg_http_listen(server->mgr, listen_url, http_handler, server);
    if (!c) { LOG_ERROR("Failed to bind to %s", listen_url); return LDMD_ERROR; }

    /* Must call before any mg_wakeup */
    mg_wakeup_init(server->mgr);

    /* Determine thread count */
    int num_threads = server->config->num_threads;
    if (num_threads < 0) num_threads = 0;
    if (num_threads == 0) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        num_threads = (int)(ncpu > 0 ? ncpu : 1);
        if (num_threads > LDMD_MAX_WORKER_THREADS)
            num_threads = LDMD_MAX_WORKER_THREADS;
    }

    if (num_threads > 1) {
        server->pool           = pool_create(server, num_threads);
        server->mgr->userdata  = server->pool;
    } else {
        LOG_INFO("Running single-threaded (num_threads=1)");
    }

    server->running = true;
    LOG_INFO("Server started on %s (%d thread%s)",
             listen_url, num_threads, num_threads == 1 ? "" : "s");
    return LDMD_OK;
}

void server_stop(ldmd_server_t *server) {
    if (server) server->running = false;
}

void server_free(ldmd_server_t *server) {
    if (!server) return;
    if (server->pool) { pool_destroy(server->pool); server->pool = NULL; }
    if (server->mgr)  { mg_mgr_free(server->mgr); free(server->mgr); }
    free(server);
}

void server_run(ldmd_server_t *server) {
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    LOG_INFO("Server running. Press Ctrl+C to stop.");

    time_t last_cleanup = time(NULL);
    while (server->running && s_signo == 0) {
        mg_mgr_poll(server->mgr, 100);
        time_t now = time(NULL);
        if (now - last_cleanup > 300) {
            db_session_cleanup(server->db);
            last_cleanup = now;
        }
    }

    LOG_INFO("Server shutting down...");
    if (server->pool) { pool_destroy(server->pool); server->pool = NULL; }
}

