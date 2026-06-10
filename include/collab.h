#ifndef COLLAB_H
#define COLLAB_H

#include "localdocsmd.h"
#include "database.h"
#include "config.h"
#include "mongoose.h"
#include <pthread.h>
#include <time.h>

#define COLLAB_MAX_DOCS      64
#define COLLAB_MAX_CLIENTS   32
#define COLLAB_OP_HISTORY    500
#define COLLAB_FLUSH_SECS    30

/**
 * Per-WebSocket-connection metadata stored in mg_connection->data as a pointer.
 * Allocated on connect, freed on close.
 */
typedef struct {
    char    doc_uuid[LDMD_UUID_LENGTH];
    char    collab_id[37];
    int64_t user_id;
    char    username[LDMD_MAX_USERNAME];
} ws_conn_data_t;

/**
 * Single OT operation. For inserts: pos+text+len. For deletes: pos+len, text=NULL.
 * version is the server version this op was applied at (used for transform history).
 */
typedef struct {
    char  type;     /* 'i' = insert, 'd' = delete */
    int   pos;
    int   len;      /* delete length or strlen(text) for insert */
    char *text;     /* heap-allocated for inserts, NULL for deletes */
    int   version;
} collab_op_t;

/** Connected WS client slot within a document session. */
typedef struct {
    struct mg_connection *conn;
    char    collab_id[37];
    int64_t user_id;
    char    username[LDMD_MAX_USERNAME];
    bool    active;
} collab_client_t;

/** In-memory collaborative session for one document. */
typedef struct {
    char             doc_uuid[LDMD_UUID_LENGTH];
    int64_t          doc_id;
    char             doc_path[LDMD_MAX_PATH];
    char            *content;
    int              version;
    bool             active;
    bool             dirty;
    time_t           last_activity;
    collab_client_t  clients[COLLAB_MAX_CLIENTS];
    int              client_count;
    collab_op_t      ops[COLLAB_OP_HISTORY];
    int              ops_start;
    int              ops_count;
    pthread_mutex_t  mutex;
} collab_doc_t;

/** Pending content-replace notification from a worker thread. */
typedef struct collab_notify {
    char                 doc_uuid[LDMD_UUID_LENGTH];
    char                *content;
    int64_t              by_user_id;
    char                 by_username[LDMD_MAX_USERNAME];
    struct collab_notify *next;
} collab_notify_t;

/** Top-level manager — one per server instance. */
typedef struct {
    collab_doc_t     docs[COLLAB_MAX_DOCS];
    pthread_mutex_t  docs_mutex;
    pthread_mutex_t  notify_mutex;
    collab_notify_t *notify_head;
    collab_notify_t *notify_tail;
} collab_manager_t;

/**
 * Allocate and initialise a collab manager.
 * @return Manager or NULL on OOM.
 */
collab_manager_t *collab_create(void);

/**
 * Flush all dirty sessions to disk, close all WS connections, and free the manager.
 * Must be called from the main (event-loop) thread.
 * @param cm   Manager
 * @param db   Main-thread DB connection
 * @param cfg  Server config
 */
void collab_destroy(collab_manager_t *cm, ldmd_database_t *db, ldmd_config_t *cfg);

/**
 * Register a new WS client for a document session.
 * Loads document content from disk on first connect.
 * Must be called from the main thread immediately after mg_ws_upgrade().
 * @param cm       Manager
 * @param db       Main-thread DB
 * @param cfg      Config
 * @param c        Upgraded WS connection
 * @param doc_uuid Document UUID
 * @param user_id  Authenticated user ID
 * @param username Authenticated username
 */
void collab_ws_connect(collab_manager_t *cm, ldmd_database_t *db, ldmd_config_t *cfg,
                        struct mg_connection *c, const char *doc_uuid,
                        int64_t user_id, const char *username);

/**
 * Deregister a WS client. Flushes to disk if the session becomes empty.
 * Must be called from the main thread on MG_EV_CLOSE.
 * @param cm  Manager
 * @param db  Main-thread DB
 * @param cfg Config
 * @param c   Closing connection
 */
void collab_ws_disconnect(collab_manager_t *cm, ldmd_database_t *db, ldmd_config_t *cfg,
                           struct mg_connection *c);

/**
 * Process an incoming WS text frame from a client.
 * Must be called from the main thread on MG_EV_WS_MSG.
 * @param cm   Manager
 * @param c    Connection that sent the message
 * @param data Frame data (not null-terminated)
 * @param len  Frame length
 */
void collab_ws_message(collab_manager_t *cm, struct mg_connection *c,
                        const char *data, size_t len);

/**
 * Enqueue a full content-replace notification from a worker thread.
 * Thread-safe. The manager takes ownership of a copy of @content.
 * @param cm          Manager
 * @param doc_uuid    Document UUID
 * @param content     New full content
 * @param by_user_id  User who triggered the save
 * @param by_username Username
 */
void collab_notify_replace(collab_manager_t *cm, const char *doc_uuid,
                            const char *content, int64_t by_user_id,
                            const char *by_username);

/**
 * Drain the notify queue and run periodic flush checks.
 * Must be called from the main thread every poll iteration.
 * @param cm  Manager
 * @param db  Main-thread DB
 * @param cfg Config
 */
void collab_tick(collab_manager_t *cm, ldmd_database_t *db, ldmd_config_t *cfg);

#endif /* COLLAB_H */
