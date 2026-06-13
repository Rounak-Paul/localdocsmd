#include "collab.h"
#include "project.h"
#include "database.h"
#include "utils.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

/* ── Helpers ──────────────────────────────────────────────────────── */

static void op_free_text(collab_op_t *op) {
    if (op->type == 'i') { free(op->text); op->text = NULL; }
}

/** Apply a single op to text, returning a new heap string (caller frees). */
static char *apply_op(const char *text, const collab_op_t *op) {
    size_t tlen = strlen(text);
    if (op->type == 'i') {
        int ipos = op->pos < 0 ? 0 : (op->pos > (int)tlen ? (int)tlen : op->pos);
        size_t ilen = op->text ? strlen(op->text) : 0;
        char *r = malloc(tlen + ilen + 1);
        if (!r) return NULL;
        memcpy(r, text, (size_t)ipos);
        if (ilen) memcpy(r + ipos, op->text, ilen);
        memcpy(r + ipos + ilen, text + ipos, tlen - (size_t)ipos);
        r[tlen + ilen] = '\0';
        return r;
    } else {
        int pos = op->pos < 0 ? 0 : (op->pos > (int)tlen ? (int)tlen : op->pos);
        int end = pos + op->len;
        if (end > (int)tlen) end = (int)tlen;
        int actual = end - pos;
        if (actual <= 0) return strdup(text);
        size_t nlen = tlen - (size_t)actual;
        char *r = malloc(nlen + 1);
        if (!r) return NULL;
        memcpy(r, text, (size_t)pos);
        memcpy(r + pos, text + end, tlen - (size_t)end);
        r[nlen] = '\0';
        return r;
    }
}

/**
 * Transform op_a as if op_b was already applied to the same base state.
 * Returns a new op_a adjusted to apply correctly after op_b.
 * b_wins controls insert-insert tie-breaking at the same position:
 *   true  — b wins; a is shifted right (use when b was applied first / is authoritative)
 *   false — a wins; a stays in place  (use when a was applied first)
 * The caller must free result.text for inserts.
 */
static collab_op_t transform_op(collab_op_t a, const collab_op_t *b, bool b_wins) {
    if (b->type == 'i') {
        if (a.type == 'i') {
            if (b_wins ? b->pos <= a.pos : b->pos < a.pos) a.pos += b->len;
        } else {
            if (b->pos <= a.pos)
                a.pos += b->len;
            else if (b->pos < a.pos + a.len)
                a.len += b->len;
        }
    } else { /* b is delete */
        int b_end = b->pos + b->len;
        if (a.type == 'i') {
            if (b_end <= a.pos)
                a.pos -= b->len;
            else if (b->pos < a.pos)
                a.pos = b->pos;
        } else {
            int a_end = a.pos + a.len;
            if (b_end <= a.pos) {
                a.pos -= b->len;
            } else if (b->pos < a_end) {
                int del_before = (b->pos < a.pos)
                    ? (b_end < a.pos ? b->len : a.pos - b->pos)
                    : 0;
                int ov_start = a.pos > b->pos ? a.pos : b->pos;
                int ov_end   = a_end < b_end  ? a_end : b_end;
                int del_inside = ov_end > ov_start ? ov_end - ov_start : 0;
                a.pos -= del_before;
                a.len -= del_inside;
                if (a.len < 0) a.len = 0;
            }
        }
    }
    return a;
}

/* ── Op history ring buffer ───────────────────────────────────────── */

static void history_push(collab_doc_t *doc, const collab_op_t *op) {
    if (doc->ops_count < COLLAB_OP_HISTORY) {
        int idx = (doc->ops_start + doc->ops_count) % COLLAB_OP_HISTORY;
        op_free_text(&doc->ops[idx]);
        doc->ops[idx] = *op;
        if (op->type == 'i' && op->text)
            doc->ops[idx].text = strdup(op->text);
        doc->ops_count++;
    } else {
        /* Ring is full — overwrite the oldest slot, then advance start. */
        int idx = doc->ops_start;
        op_free_text(&doc->ops[idx]);
        doc->ops[idx] = *op;
        if (op->type == 'i' && op->text)
            doc->ops[idx].text = strdup(op->text);
        doc->ops_start = (doc->ops_start + 1) % COLLAB_OP_HISTORY;
    }
}

/* ── Document slot management ─────────────────────────────────────── */

static collab_doc_t *find_doc(collab_manager_t *cm, const char *doc_uuid) {
    for (int i = 0; i < COLLAB_MAX_DOCS; i++) {
        if (cm->docs[i].active &&
            strcmp(cm->docs[i].doc_uuid, doc_uuid) == 0)
            return &cm->docs[i];
    }
    return NULL;
}

static collab_doc_t *find_doc_by_conn(collab_manager_t *cm, struct mg_connection *c) {
    for (int i = 0; i < COLLAB_MAX_DOCS; i++) {
        if (!cm->docs[i].active) continue;
        for (int j = 0; j < COLLAB_MAX_CLIENTS; j++) {
            if (cm->docs[i].clients[j].active &&
                cm->docs[i].clients[j].conn == c)
                return &cm->docs[i];
        }
    }
    return NULL;
}

static collab_doc_t *alloc_doc(collab_manager_t *cm, const char *doc_uuid,
                                int64_t doc_id, const char *doc_path) {
    for (int i = 0; i < COLLAB_MAX_DOCS; i++) {
        if (!cm->docs[i].active) {
            collab_doc_t *d = &cm->docs[i];
            memset(d, 0, sizeof(*d));
            ldmd_strlcpy(d->doc_uuid, doc_uuid, sizeof(d->doc_uuid));
            d->doc_id = doc_id;
            ldmd_strlcpy(d->doc_path, doc_path, sizeof(d->doc_path));
            d->active = true;
            d->last_activity = time(NULL);
            pthread_mutex_init(&d->mutex, NULL);
            return d;
        }
    }
    return NULL;
}

static void free_doc_content(collab_doc_t *doc) {
    free(doc->content);
    doc->content = NULL;
    for (int i = 0; i < COLLAB_OP_HISTORY; i++)
        op_free_text(&doc->ops[i]);
    doc->ops_start = 0;
    doc->ops_count = 0;
}

/* ── Flush ────────────────────────────────────────────────────────── */

static void flush_doc(collab_doc_t *doc, ldmd_database_t *db, ldmd_config_t *cfg) {
    if (!doc->dirty || !doc->content) return;

    ldmd_document_t ldoc;
    if (db_document_get_by_id(db, doc->doc_id, &ldoc) != LDMD_OK) return;

    /* Find the last active user for attribution */
    int64_t last_user = ldoc.updated_by ? ldoc.updated_by : ldoc.created_by;
    for (int i = 0; i < COLLAB_MAX_CLIENTS; i++) {
        if (doc->clients[i].active)
            last_user = doc->clients[i].user_id;
    }

    document_audit_snapshot(db, &ldoc, last_user);
    if (document_save_content(cfg, &ldoc, doc->content) != LDMD_OK) {
        LOG_INFO("collab: flush FAILED for %s — will retry", doc->doc_uuid);
        return; /* keep dirty=true so the next tick retries */
    }
    db_document_save_flush(db, ldoc.id, last_user, (time_t)time(NULL));

    doc->dirty = false;
    LOG_INFO("collab: flushed %s to disk", doc->doc_uuid);
}

/* ── Broadcast helpers ────────────────────────────────────────────── */

static void broadcast_to_doc(collab_doc_t *doc, const char *json,
                               const char *exclude_collab_id) {
    for (int i = 0; i < COLLAB_MAX_CLIENTS; i++) {
        if (!doc->clients[i].active) continue;
        if (exclude_collab_id &&
            strcmp(doc->clients[i].collab_id, exclude_collab_id) == 0)
            continue;
        mg_ws_send(doc->clients[i].conn, json, strlen(json), WEBSOCKET_OP_TEXT);
    }
}

static void broadcast_presence(collab_doc_t *doc) {
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "type", "presence");
    cJSON *users = cJSON_CreateArray();
    for (int i = 0; i < COLLAB_MAX_CLIENTS; i++) {
        if (!doc->clients[i].active) continue;
        cJSON *u = cJSON_CreateObject();
        cJSON_AddStringToObject(u, "collab_id", doc->clients[i].collab_id);
        cJSON_AddStringToObject(u, "username",  doc->clients[i].username);
        cJSON_AddItemToArray(users, u);
    }
    cJSON_AddItemToObject(msg, "users", users);
    char *json = cJSON_PrintUnformatted(msg);
    if (json) {
        broadcast_to_doc(doc, json, NULL);
        free(json);
    }
    cJSON_Delete(msg);
}

/* ── UUID generation (simple hex random) ─────────────────────────── */

static void gen_collab_id(char *out) {
    /* Use urandom for randomness */
    unsigned char buf[16] = {0};
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { (void)fread(buf, 1, sizeof(buf), f); fclose(f); }
    else {
        /* Fallback: use pointer address + time */
        uint64_t v = (uint64_t)(uintptr_t)out ^ (uint64_t)time(NULL);
        memcpy(buf, &v, 8);
    }
    /* RFC 4122 variant 4 */
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    snprintf(out, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        buf[0],buf[1],buf[2],buf[3], buf[4],buf[5], buf[6],buf[7],
        buf[8],buf[9], buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]);
}

/* ── JSON op parsing / serialisation ─────────────────────────────── */

static bool parse_op(const cJSON *jop, collab_op_t *op_out, int content_len) {
    memset(op_out, 0, sizeof(*op_out));
    cJSON *jt = cJSON_GetObjectItem(jop, "t");
    cJSON *jp = cJSON_GetObjectItem(jop, "pos");
    if (!jt || !cJSON_IsString(jt) || !jp || !cJSON_IsNumber(jp)) return false;

    const char *t = jt->valuestring;
    op_out->pos = (int)jp->valuedouble;
    if (op_out->pos < 0) op_out->pos = 0;
    if (op_out->pos > content_len) op_out->pos = content_len;

    if (strcmp(t, "i") == 0) {
        cJSON *jtxt = cJSON_GetObjectItem(jop, "text");
        if (!jtxt || !cJSON_IsString(jtxt)) return false;
        op_out->type = 'i';
        op_out->text = strdup(jtxt->valuestring);
        op_out->len  = (int)strlen(op_out->text);
    } else if (strcmp(t, "d") == 0) {
        cJSON *jlen = cJSON_GetObjectItem(jop, "len");
        if (!jlen || !cJSON_IsNumber(jlen)) return false;
        op_out->type = 'd';
        op_out->len  = (int)jlen->valuedouble;
        if (op_out->len < 0) op_out->len = 0;
        int max_del = content_len - op_out->pos;
        if (op_out->len > max_del) op_out->len = max_del;
    } else {
        return false;
    }
    return true;
}

static cJSON *op_to_json(const collab_op_t *op) {
    cJSON *j = cJSON_CreateObject();
    char tstr[2] = {op->type, '\0'};
    cJSON_AddStringToObject(j, "t", tstr);
    cJSON_AddNumberToObject(j, "pos", op->pos);
    if (op->type == 'i')
        cJSON_AddStringToObject(j, "text", op->text ? op->text : "");
    else
        cJSON_AddNumberToObject(j, "len", op->len);
    return j;
}

/* ── Public API ───────────────────────────────────────────────────── */

collab_manager_t *collab_create(void) {
    collab_manager_t *cm = calloc(1, sizeof(collab_manager_t));
    if (!cm) return NULL;
    pthread_mutex_init(&cm->docs_mutex, NULL);
    pthread_mutex_init(&cm->notify_mutex, NULL);
    return cm;
}

void collab_destroy(collab_manager_t *cm, ldmd_database_t *db, ldmd_config_t *cfg) {
    if (!cm) return;

    pthread_mutex_lock(&cm->docs_mutex);
    for (int i = 0; i < COLLAB_MAX_DOCS; i++) {
        if (!cm->docs[i].active) continue;
        collab_doc_t *doc = &cm->docs[i];
        pthread_mutex_lock(&doc->mutex);
        if (doc->dirty) flush_doc(doc, db, cfg);
        free_doc_content(doc);
        pthread_mutex_unlock(&doc->mutex);
        pthread_mutex_destroy(&doc->mutex);
    }
    pthread_mutex_unlock(&cm->docs_mutex);

    /* Free notify queue */
    pthread_mutex_lock(&cm->notify_mutex);
    collab_notify_t *n = cm->notify_head;
    while (n) {
        collab_notify_t *next = n->next;
        free(n->content);
        free(n);
        n = next;
    }
    pthread_mutex_unlock(&cm->notify_mutex);

    pthread_mutex_destroy(&cm->docs_mutex);
    pthread_mutex_destroy(&cm->notify_mutex);
    free(cm);
}

void collab_ws_connect(collab_manager_t *cm, ldmd_database_t *db, ldmd_config_t *cfg,
                        struct mg_connection *c, const char *doc_uuid,
                        int64_t user_id, const char *username) {
    if (!cm || !c) return;

    pthread_mutex_lock(&cm->docs_mutex);

    collab_doc_t *doc = find_doc(cm, doc_uuid);
    if (!doc) {
        /* Load document metadata */
        ldmd_document_t ldoc;
        if (db_document_get_by_uuid(db, doc_uuid, &ldoc) != LDMD_OK) {
            pthread_mutex_unlock(&cm->docs_mutex);
            mg_ws_send(c, "{\"type\":\"error\",\"msg\":\"not found\"}", 33, WEBSOCKET_OP_TEXT);
            return;
        }
        doc = alloc_doc(cm, doc_uuid, ldoc.id, ldoc.path);
        if (!doc) {
            pthread_mutex_unlock(&cm->docs_mutex);
            mg_ws_send(c, "{\"type\":\"error\",\"msg\":\"server full\"}", 35, WEBSOCKET_OP_TEXT);
            return;
        }
        /* Load content from disk */
        char *disk_content = NULL;
        document_load_content(cfg, &ldoc, &disk_content);
        doc->content = disk_content ? disk_content : strdup("");
        doc->version = (int)ldoc.version;
    }

    /* Find a free client slot */
    int slot = -1;
    for (int i = 0; i < COLLAB_MAX_CLIENTS; i++) {
        if (!doc->clients[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&cm->docs_mutex);
        mg_ws_send(c, "{\"type\":\"error\",\"msg\":\"session full\"}", 36, WEBSOCKET_OP_TEXT);
        return;
    }

    pthread_mutex_lock(&doc->mutex);

    collab_client_t *cl = &doc->clients[slot];
    cl->active  = true;
    cl->conn    = c;
    cl->user_id = user_id;
    ldmd_strlcpy(cl->username, username, sizeof(cl->username));
    gen_collab_id(cl->collab_id);
    doc->client_count++;
    doc->last_activity = time(NULL);

    /* Store collab_id in the WS connection data */
    ws_conn_data_t *wd = *(ws_conn_data_t **)c->data;
    if (wd) ldmd_strlcpy(wd->collab_id, cl->collab_id, sizeof(wd->collab_id));

    /* Send init message */
    cJSON *init = cJSON_CreateObject();
    cJSON_AddStringToObject(init, "type",      "init");
    cJSON_AddNumberToObject (init, "version",   doc->version);
    cJSON_AddStringToObject (init, "collab_id", cl->collab_id);
    cJSON_AddStringToObject (init, "content",   doc->content ? doc->content : "");
    char *json = cJSON_PrintUnformatted(init);
    if (json) {
        mg_ws_send(c, json, strlen(json), WEBSOCKET_OP_TEXT);
        free(json);
    }
    cJSON_Delete(init);

    pthread_mutex_unlock(&doc->mutex);

    broadcast_presence(doc);

    pthread_mutex_unlock(&cm->docs_mutex);

    (void)cfg;
}

void collab_ws_disconnect(collab_manager_t *cm, ldmd_database_t *db, ldmd_config_t *cfg,
                           struct mg_connection *c) {
    if (!cm || !c) return;

    pthread_mutex_lock(&cm->docs_mutex);

    collab_doc_t *doc = find_doc_by_conn(cm, c);
    if (!doc) {
        pthread_mutex_unlock(&cm->docs_mutex);
        return;
    }

    pthread_mutex_lock(&doc->mutex);

    for (int i = 0; i < COLLAB_MAX_CLIENTS; i++) {
        if (doc->clients[i].active && doc->clients[i].conn == c) {
            doc->clients[i].active = false;
            doc->client_count--;
            break;
        }
    }

    bool empty = (doc->client_count == 0);

    if (empty) {
        if (doc->dirty) flush_doc(doc, db, cfg);
        doc->last_empty_at = time(NULL);
        /* Don't evict here — keep the session alive through the grace period so
         * a page refresh reconnects to the in-memory canonical content instead
         * of reading stale on-disk content.  collab_tick() handles eviction. */
    }

    pthread_mutex_unlock(&doc->mutex);

    if (!empty) {
        broadcast_presence(doc);
    }

    pthread_mutex_unlock(&cm->docs_mutex);
}

void collab_ws_message(collab_manager_t *cm, struct mg_connection *c,
                        const char *data, size_t len) {
    if (!cm || !c || !data || len == 0) return;

    ws_conn_data_t *wd = *(ws_conn_data_t **)c->data;
    if (!wd) return;

    char *buf = malloc(len + 1);
    if (!buf) return;
    memcpy(buf, data, len);
    buf[len] = '\0';

    cJSON *msg = cJSON_Parse(buf);
    free(buf);
    if (!msg) return;

    cJSON *jtype = cJSON_GetObjectItem(msg, "type");
    if (!jtype || !cJSON_IsString(jtype)) { cJSON_Delete(msg); return; }

    if (strcmp(jtype->valuestring, "ping") == 0) {
        mg_ws_send(c, "{\"type\":\"pong\"}", 14, WEBSOCKET_OP_TEXT);
        cJSON_Delete(msg);
        return;
    }

    if (strcmp(jtype->valuestring, "op") != 0) { cJSON_Delete(msg); return; }

    cJSON *jbase = cJSON_GetObjectItem(msg, "base_version");
    cJSON *jops  = cJSON_GetObjectItem(msg, "ops");
    cJSON *jcid  = cJSON_GetObjectItem(msg, "collab_id");
    if (!jbase || !cJSON_IsNumber(jbase) || !jops || !cJSON_IsArray(jops) ||
        !jcid  || !cJSON_IsString(jcid)) {
        cJSON_Delete(msg);
        return;
    }

    int base_version = (int)jbase->valuedouble;
    /* Use the server-assigned collab_id from connection data, not the client-supplied
     * one — prevents a client from spoofing another session's collab_id. */
    const char *sender_collab_id = wd->collab_id;
    int n_ops = cJSON_GetArraySize(jops);
    if (n_ops <= 0 || n_ops > 512) { cJSON_Delete(msg); return; }

    pthread_mutex_lock(&cm->docs_mutex);

    collab_doc_t *doc = find_doc(cm, wd->doc_uuid);
    if (!doc) {
        pthread_mutex_unlock(&cm->docs_mutex);
        cJSON_Delete(msg);
        return;
    }

    pthread_mutex_lock(&doc->mutex);

    /* Reject ops from a client that claims to be ahead of the server — this
     * indicates a corrupted client state (e.g. stale reconnect with wrong version).
     * Also reject a base_version so far behind that we've evicted its history. */
    if (base_version > doc->version) {
        pthread_mutex_unlock(&doc->mutex);
        pthread_mutex_unlock(&cm->docs_mutex);
        cJSON_Delete(msg);
        /* Send the client a replace so it resync's to canonical state. */
        cJSON *rep = cJSON_CreateObject();
        cJSON_AddStringToObject(rep, "type",    "replace");
        cJSON_AddNumberToObject (rep, "version", doc->version);
        cJSON_AddStringToObject (rep, "content", doc->content ? doc->content : "");
        cJSON_AddStringToObject (rep, "by",      "");
        char *repjson = cJSON_PrintUnformatted(rep);
        cJSON_Delete(rep);
        if (repjson) { mg_ws_send(c, repjson, strlen(repjson), WEBSOCKET_OP_TEXT); free(repjson); }
        return;
    }

    /* Parse client ops, tracking running content length so each op's pos/len
     * is clamped against the correct base (after all prior ops in this batch). */
    collab_op_t *client_ops = calloc((size_t)n_ops, sizeof(collab_op_t));
    if (!client_ops) {
        pthread_mutex_unlock(&doc->mutex);
        pthread_mutex_unlock(&cm->docs_mutex);
        cJSON_Delete(msg);
        return;
    }
    int valid_ops  = 0;
    int running_len = doc->content ? (int)strlen(doc->content) : 0;
    for (int i = 0; i < n_ops; i++) {
        cJSON *jop = cJSON_GetArrayItem(jops, i);
        if (!jop) continue;
        if (parse_op(jop, &client_ops[valid_ops], running_len)) {
            /* Advance running_len for the next op in the batch. */
            const collab_op_t *cop = &client_ops[valid_ops];
            if (cop->type == 'i') running_len += cop->len;
            else                  running_len -= cop->len;
            if (running_len < 0) running_len = 0;
            valid_ops++;
        }
    }

    /* Transform client ops against server ops since base_version */
    if (base_version < doc->version) {
        int history_total = doc->ops_count;

        /* Check if history covers all versions since base_version. The oldest op
         * in history tells us the earliest version we can transform from.  If
         * the client is further behind than our ring buffer covers, we cannot
         * correctly transform — force a full resync instead of producing garbage. */
        bool history_gap = false;
        if (history_total > 0) {
            int oldest_idx = doc->ops_start % COLLAB_OP_HISTORY;
            if (doc->ops[oldest_idx].version > base_version + 1) {
                history_gap = true;
            }
        } else if (doc->version > base_version) {
            /* No history at all but server is ahead — shouldn't happen normally,
             * but treat it as a gap to be safe. */
            history_gap = true;
        }

        if (history_gap) {
            /* Client is too far behind; free parsed ops and resync. */
            pthread_mutex_unlock(&doc->mutex);
            pthread_mutex_unlock(&cm->docs_mutex);
            for (int i = 0; i < valid_ops; i++)
                if (client_ops[i].type == 'i') free(client_ops[i].text);
            free(client_ops);
            cJSON_Delete(msg);
            cJSON *rep = cJSON_CreateObject();
            cJSON_AddStringToObject(rep, "type",    "replace");
            cJSON_AddNumberToObject (rep, "version", doc->version);
            cJSON_AddStringToObject (rep, "content", doc->content ? doc->content : "");
            cJSON_AddStringToObject (rep, "by",      "");
            char *repjson = cJSON_PrintUnformatted(rep);
            cJSON_Delete(rep);
            if (repjson) { mg_ws_send(c, repjson, strlen(repjson), WEBSOCKET_OP_TEXT); free(repjson); }
            return;
        }

        /* Walk history ops from base_version to current, transforming in order.
         *
         * For each history op we maintain a working copy (hcopy) that advances past
         * each client op as we process them.  This is necessary because client_ops
         * are sequential — client_ops[i+1] was computed after client_ops[i] was
         * applied, so the history op's effective position changes as we move through
         * the client batch.  Without advancing hcopy, positions in later client ops
         * are transformed against the wrong base. */
        for (int h = 0; h < history_total; h++) {
            int hidx = (doc->ops_start + h) % COLLAB_OP_HISTORY;
            if (doc->ops[hidx].version <= base_version) continue;

            collab_op_t hcopy = doc->ops[hidx];
            if (hcopy.type == 'i' && hcopy.text) hcopy.text = strdup(hcopy.text);

            for (int i = 0; i < valid_ops; i++) {
                collab_op_t old_ci   = client_ops[i];
                char       *saved    = (client_ops[i].type == 'i') ? client_ops[i].text : NULL;
                /* history op (hcopy) was applied first on server — it wins ties */
                client_ops[i]        = transform_op(client_ops[i], &hcopy, true);
                if (client_ops[i].type == 'i' && client_ops[i].text == NULL)
                    client_ops[i].text = saved;
                /* Advance hcopy past old_ci: old_ci is client (arrived second), so
                 * hcopy (history) still wins ties when we advance it past old_ci. */
                hcopy = transform_op(hcopy, &old_ci, false);
            }

            if (hcopy.type == 'i') free(hcopy.text);
        }
    }

    if (valid_ops == 0) {
        pthread_mutex_unlock(&doc->mutex);
        pthread_mutex_unlock(&cm->docs_mutex);
        free(client_ops);
        cJSON_Delete(msg);
        return;
    }

    /* Apply transformed ops to canonical content */
    char *new_content = doc->content ? strdup(doc->content) : strdup("");
    if (!new_content) {
        pthread_mutex_unlock(&doc->mutex);
        pthread_mutex_unlock(&cm->docs_mutex);
        for (int i = 0; i < valid_ops; i++)
            if (client_ops[i].type == 'i') free(client_ops[i].text);
        free(client_ops);
        cJSON_Delete(msg);
        return;
    }
    bool oom = false;
    for (int i = 0; i < valid_ops; i++) {
        char *tmp = apply_op(new_content, &client_ops[i]);
        if (!tmp) { oom = true; break; }
        free(new_content);
        new_content = tmp;
    }
    if (oom) {
        free(new_content);
        pthread_mutex_unlock(&doc->mutex);
        pthread_mutex_unlock(&cm->docs_mutex);
        for (int i = 0; i < valid_ops; i++)
            if (client_ops[i].type == 'i') free(client_ops[i].text);
        free(client_ops);
        cJSON_Delete(msg);
        return;
    }

    free(doc->content);
    doc->content = new_content;
    doc->version++;
    doc->dirty = true;
    doc->last_activity = time(NULL);

    /* Store ops in history */
    for (int i = 0; i < valid_ops; i++) {
        client_ops[i].version = doc->version;
        history_push(doc, &client_ops[i]);
    }

    /* Build broadcast message */
    cJSON *broadcast = cJSON_CreateObject();
    cJSON_AddStringToObject(broadcast, "type",      "ops");
    cJSON_AddNumberToObject (broadcast, "version",   doc->version);
    cJSON_AddStringToObject (broadcast, "collab_id", sender_collab_id);
    cJSON *ops_arr = cJSON_CreateArray();
    for (int i = 0; i < valid_ops; i++) {
        cJSON_AddItemToArray(ops_arr, op_to_json(&client_ops[i]));
    }
    cJSON_AddItemToObject(broadcast, "ops", ops_arr);
    char *bcast_json = cJSON_PrintUnformatted(broadcast);
    cJSON_Delete(broadcast);

    pthread_mutex_unlock(&doc->mutex);

    /* Broadcast to all clients (sender gets it as ack) */
    if (bcast_json) {
        broadcast_to_doc(doc, bcast_json, NULL);
        free(bcast_json);
    }

    pthread_mutex_unlock(&cm->docs_mutex);

    /* Free client ops (text is owned by history now, but parse_op duped it) */
    for (int i = 0; i < valid_ops; i++) {
        if (client_ops[i].type == 'i') free(client_ops[i].text);
    }
    free(client_ops);
    cJSON_Delete(msg);
}

void collab_notify_replace(collab_manager_t *cm, const char *doc_uuid,
                            const char *content, int64_t by_user_id,
                            const char *by_username) {
    if (!cm || !doc_uuid || !content) return;

    collab_notify_t *n = calloc(1, sizeof(collab_notify_t));
    if (!n) return;
    n->content = strdup(content);
    if (!n->content) { free(n); return; }
    ldmd_strlcpy(n->doc_uuid, doc_uuid, sizeof(n->doc_uuid));
    n->by_user_id  = by_user_id;
    ldmd_strlcpy(n->by_username, by_username ? by_username : "", sizeof(n->by_username));

    pthread_mutex_lock(&cm->notify_mutex);
    if (cm->notify_tail) cm->notify_tail->next = n;
    else                 cm->notify_head = n;
    cm->notify_tail = n;
    pthread_mutex_unlock(&cm->notify_mutex);
}

void collab_tick(collab_manager_t *cm, ldmd_database_t *db, ldmd_config_t *cfg) {
    if (!cm) return;

    /* ── Drain notify queue ── */
    collab_notify_t *queue = NULL;
    pthread_mutex_lock(&cm->notify_mutex);
    queue = cm->notify_head;
    cm->notify_head = cm->notify_tail = NULL;
    pthread_mutex_unlock(&cm->notify_mutex);

    while (queue) {
        collab_notify_t *next = queue->next;

        pthread_mutex_lock(&cm->docs_mutex);
        collab_doc_t *doc = find_doc(cm, queue->doc_uuid);
        if (doc) {
            pthread_mutex_lock(&doc->mutex);
            free(doc->content);
            doc->content = queue->content;  /* transfer ownership */
            queue->content = NULL;
            doc->version++;
            doc->dirty = true;
            doc->last_activity = time(NULL);
            /* Clear op history — all client pending ops are now stale */
            for (int i = 0; i < doc->ops_count; i++)
                op_free_text(&doc->ops[(doc->ops_start + i) % COLLAB_OP_HISTORY]);
            doc->ops_start = 0;
            doc->ops_count = 0;

            /* Build replace broadcast */
            cJSON *rep = cJSON_CreateObject();
            cJSON_AddStringToObject(rep, "type",    "replace");
            cJSON_AddNumberToObject (rep, "version", doc->version);
            cJSON_AddStringToObject (rep, "content", doc->content);
            cJSON_AddStringToObject (rep, "by",      queue->by_username);
            char *json = cJSON_PrintUnformatted(rep);
            cJSON_Delete(rep);
            pthread_mutex_unlock(&doc->mutex);

            if (json) {
                broadcast_to_doc(doc, json, NULL);
                free(json);
            }
        }
        pthread_mutex_unlock(&cm->docs_mutex);

        free(queue->content);
        free(queue);
        queue = next;
    }

    /* ── Periodic flush and grace-period eviction ── */
    time_t now = time(NULL);
    pthread_mutex_lock(&cm->docs_mutex);
    for (int i = 0; i < COLLAB_MAX_DOCS; i++) {
        collab_doc_t *doc = &cm->docs[i];
        if (!doc->active) continue;

        bool has_clients = (doc->client_count > 0);

        if (!has_clients) {
            /* Fallback flush in case disconnect somehow left dirty state. */
            if (doc->dirty) {
                pthread_mutex_lock(&doc->mutex);
                flush_doc(doc, db, cfg);
                pthread_mutex_unlock(&doc->mutex);
            }
            /* Evict only after the grace period expires. */
            if (now - doc->last_empty_at >= COLLAB_SESSION_GRACE_SECS) {
                free_doc_content(doc);
                pthread_mutex_destroy(&doc->mutex);
                doc->active = false;
            }
        } else if (doc->dirty) {
            /* Periodic flush while clients are active. */
            time_t idle = now - doc->last_activity;
            if (idle >= COLLAB_FLUSH_SECS) {
                pthread_mutex_lock(&doc->mutex);
                flush_doc(doc, db, cfg);
                pthread_mutex_unlock(&doc->mutex);
            }
        }
    }
    pthread_mutex_unlock(&cm->docs_mutex);
}
