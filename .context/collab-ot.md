# Collaborative Editing — Architecture Context

## Status: IMPLEMENTED

## Overview
Real-time OT-based collaborative editing for LocalDocsMD documents.
Supports multiple simultaneous web editor users and raw-path (external editor) users.
Auto-migration runs on startup; no manual DB steps needed.

## Edit Paths
1. **Web Editor** — WebSocket `/ws/documents/{uuid}` — sends/receives OT operations
2. **Raw Path** — `PUT /raw/:token` — full content replace, broadcasts to WS clients via notify queue
3. **HTTP PUT** — `PUT /api/documents/{uuid}/content` — full content replace, broadcasts to WS clients

## Key Files Changed
- `include/collab.h` — collab manager, ws_conn_data_t, OT types
- `src/collab.c` — OT engine (transform_op, apply_op), WS session manager, flush logic, notify queue
- `include/localdocsmd.h` — added `int64_t version` to ldmd_document_t
- `include/database.h` — added db_run_migrations, db_document_save_flush prototypes
- `src/database.c` — migration runner, version column in schema, fill_document_from_stmt, db_document_save_flush
- `include/project.h` — added AUDIT_MAX_REVISIONS, document_audit_snapshot declaration
- `src/project.c` — document_audit_snapshot implementation (moved from routes.c static)
- `include/server.h` — collab_manager_t *collab field, #include "collab.h"
- `src/server.c` — WS upgrade/event handling in http_handler; collab_tick in server_run; collab lifecycle
- `src/routes.c` — removed static audit_snapshot, updated HTTP PUT + raw PUT handlers
- `include/presign.h` — presign_validate signature adds int64_t *user_id_out
- `src/presign.c` — presign_validate populates user_id_out
- `src/utils.c` — utils_write_file uses atomic write-then-rename
- `web/templates/editor.html` — OT WS client (computeOps, applyOps, xfOp, otConnect)
- `CMakeLists.txt` — added src/collab.c

## Schema Migration
`PRAGMA user_version` tracks schema version.
- v0 → v1: `ALTER TABLE documents ADD COLUMN version INTEGER NOT NULL DEFAULT 0`
- Fresh DB: creates schema WITH version column, sets user_version=1, migration runner is no-op
- Existing DB: user_version=0, migration runner adds column (idempotent via column-exists check)

## OT Protocol (WebSocket)
Server→Client:
- `{type:"init", version:N, collab_id:"...", content:"..."}`
- `{type:"ops", version:N, collab_id:"...", ops:[{t:"i",pos:P,text:"..."},{t:"d",pos:P,len:L}]}`
- `{type:"replace", version:N, content:"...", by:"username"}` — broadcasts on raw PUT / HTTP PUT
- `{type:"presence", users:[{collab_id:"...", username:"..."}]}`

Client→Server:
- `{type:"op", base_version:N, collab_id:"...", ops:[...]}`

## Thread Model
- WS events handled on main thread (Mongoose event loop)
- Worker threads push to notify queue (mutex-protected) via collab_notify_replace
- Main thread drains notify queue in collab_tick (called every poll iteration ~100ms)
- All OT transform+apply on main thread — no cross-thread content access

## Flush Strategy
- collab_tick() called every mg_mgr_poll (100ms)
- Dirty docs flushed every COLLAB_FLUSH_SECS(30)s while clients active
- Immediate flush when last client disconnects
- On flush: document_audit_snapshot (5-min debounce), atomic file write (utils_write_file), db_document_save_flush (increments version)

## Raw Path Attribution
presign_validate() now returns user_id alongside doc_uuid.
raw PUT attributes saves to the user who generated the presign token (not the last editor).
