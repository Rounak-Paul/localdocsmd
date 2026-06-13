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

## Key Files
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
- `{type:"replace", version:N, content:"...", by:"username"}` — broadcasts on raw PUT / HTTP PUT, or resync
- `{type:"presence", users:[{collab_id:"...", username:"..."}]}`

Client→Server:
- `{type:"op", base_version:N, collab_id:"...", ops:[...]}`

## Thread Model
- WS events handled on main thread (Mongoose event loop)
- Worker threads push to notify queue (mutex-protected) via collab_notify_replace
- Main thread drains notify queue in collab_tick (called every poll iteration ~100ms)
- All OT transform+apply on main thread — no cross-thread content access

## Flush + Session Lifetime Strategy
- collab_tick() called every mg_mgr_poll (100ms)
- Dirty docs flushed every COLLAB_FLUSH_SECS(5)s while clients active
- Immediate flush when last client disconnects
- On flush: document_audit_snapshot (5-min debounce), atomic file write (utils_write_file), db_document_save_flush (increments version)
- After last client disconnects, session stays alive for COLLAB_SESSION_GRACE_SECS(10)s before eviction
  - Allows page-refresh to reconnect to in-memory canonical content via WS init (avoids stale disk read)
  - collab_tick() evicts after grace period by calling free_doc_content + pthread_mutex_destroy + active=false

## Null Byte Protection
- HTTP PUT /api/documents/:uuid/content: raw body scanned for \0 before JSON parse; 400 returned if found
- raw PUT /raw/:token: body scanned for \0 after copy; 400 returned if found

## Frontend Sync Guarantee
- Editor readOnly=true on page load until WS init fires
- WS init (first connect): always applies server canonical content unconditionally, then readOnly=false
- WS onclose (if init never received): readOnly=false to allow offline editing
- Ctrl+S / saveDocument() is a no-op when WS is connected (shows "● Live"); only runs HTTP PUT when offline

## OT Tie-Breaking Rule (critical for convergence)

For concurrent inserts at the **same position**, the op that the server applied first wins — it
stays at its position and the later-arriving op is shifted right. Both sides must agree on this:

| Side | Call | a | b | rule |
|------|------|---|---|------|
| Server | `transform_op(arriving, history)` | arriving (later) | history (first) | `b->pos <= a->pos` → shift a |
| Client | `xfOps(serverOps, otSent, false)` | server op (first) | sent op (later) | `b.pos < a.pos` (strict) → don't shift a |
| Client | `xfOps(xfSent, otPending, false)` | server op (first) | pending op (later) | same — brings server to editor base |
| Client | `xfOps(otSent, serverOps)` | sent (later) | server (first) | `b.pos <= a.pos` → shift a |
| Client | `xfOps(otPending, xfSent)` | pending (later) | xfSent (first) | `b.pos <= a.pos` → shift a |

The `bWins` parameter on `xfOp`/`xfOps` encodes this:
- `bWins=true` (default): `b.pos <= a.pos` — b wins on tie
- `bWins=false`: `b.pos < a.pos` — a wins on tie (used when transforming server op past local ops)

## Two-Level Diamond (concurrent-ops transform correctness)

When a concurrent `ops` message arrives and we have both `otSent` (in-flight) and `otPending`
(queued), `otPending` is NOT at the same base as `serverOps` — it sits on top of `otSent`.
Treating all of them as concurrent to `serverOps` (the old `allLocal = [...otSent, ...otPending]`)
was wrong and caused position divergence under rapid concurrent editing.

Correct two-level diamond:
```
  shadow ──serverOps──► S'
    │                    │
  otSent             xfSent = xfOps(serverOps, otSent, false)
    │                    │
  otPending          xfFull = xfOps(xfSent, otPending, false)
    │                    │
  editor ──xfFull──────► editor'
```
- `xfSent` brings serverOps to the base after otSent (concurrent with otPending)
- `xfFull` brings serverOps to the editor's current base (apply this to editor)
- `otSent` rebased through raw `serverOps`
- `otPending` rebased through `xfSent` (not raw serverOps — xfSent is concurrent with pending)

Without this, a send-while-receiving scenario produces wrong positions in `otPending` and the
next flush sends corrupted ops; repeated rapid edits cause visible divergence between editors.

## Raw Path Attribution
presign_validate() now returns user_id alongside doc_uuid.
raw PUT attributes saves to the user who generated the presign token (not the last editor).

## Bug Fixes (2026-06-13)

### BFCache Content Duplication (primary glitch)
**Root cause**: When user clicks View button (navigate away) then Back (BFCache restore), the
browser restores frozen JS state including `otEverConnected = true`, stale `otSent`/`otPending`,
and a dead WS. The reconnect path used stale `editorEl.value` vs server canonical content to
compute ops, potentially re-sending ops the server already had (duplication) or missing the
server's newer content (divergence).

**Fix**:
- `pagehide` event: close WS cleanly (null out handlers first to suppress stale onclose), clear timers, set `_otPageHidden = true`
- `pageshow(persisted || _otPageHidden)`: call `otResetState()` which zeroes all OT vars, sets `otEverConnected = false`, then reconnects fresh — server is authoritative on init

### Programmatic editor changes bypassing OT (insertMarkdown, insertMedia, Tab)
**Root cause**: These functions assign directly to `editorEl.value` (no `input` event fires), so
OT ops were never computed or sent. Edits sat unsent until the next keystroke. Media inserts
called `scheduleAutosave()` even when WS was live.

**Fix**: Extracted `otApplyLocalChange(newValue)` — computes OT ops if connected (scheduleOtFlush),
otherwise schedules autosave. All programmatic edits now call this.

### Server: stale client version rejection
**Fix**: If client sends `base_version > doc->version` (impossible in normal flow — indicates stale
reconnect), server sends a `replace` resync instead of applying ops incorrectly.

### Server: history ring-buffer gap detection
**Fix**: Before transforming, check if oldest history op version covers `base_version + 1`. If the
ring buffer was evicted past what the client needs, send `replace` resync instead of silently
producing wrong transforms.

### replace message toast
Empty `by` field (resync messages) no longer shows a misleading toast.

## Complete Audit Fixes (2026-06-13)

### history_push double-free (memory corruption)
When ring buffer is full: `idx = (start + count) % SIZE = start`. Old code freed
`doc->ops[idx]`, wrote new op, then freed `doc->ops[ops_start]` again (same slot) —
double-free on the just-written text. Fixed by splitting into two branches: not-full
(append at end, increment count) and full (overwrite oldest, advance start).

### apply_op: no bounds check on insert position
If transform produces out-of-range pos, `memcpy(r, text, op->pos)` over-reads.
Fixed: clamp `ipos = clamp(op->pos, 0, tlen)` before all memcpy calls for both insert and delete.
Also use `strlen(op->text)` for ilen to guard against len/text mismatch.

### parse_op: single content_len for all ops in a batch
All batch ops were parsed using server content_len (state before batch). op[1] was
designed for the state after op[0]. Fix: maintain `running_len` during parse loop,
advancing it by each successfully parsed op's effect (insert adds, delete subtracts).

### Stale position clamp in apply loop removed
The old `client_ops[i+1].pos > nc_len` clamp after each apply was unnecessary after
parse now handles clamping per-op, and apply_op now clamps internally. Removed.

### Spoofed collab_id in op messages
Server used `jcid->valuestring` (client-supplied) as `sender_collab_id`. A malicious
client could send another session's collab_id, causing the real owner to treat the
broadcast as its own ack. Fixed: use `wd->collab_id` (server-assigned at connect time).

### otWs.send() uncaught exception (client)
`otWs.send()` can throw `InvalidStateError` if WS enters CLOSING state between the
`otConnected` check and the actual send. On throw, `otSent` had ops, `otPending` was
empty, `otWaitingAck=true`, but nothing was sent — state machine stuck.
Fixed: wrap in try/catch; on catch, restore `otPending = otSent.concat(otPending)`,
clear `otSent`, reset `otWaitingAck`. Reconnect will recover correctly.

### Multi-editor OT divergence — Root cause 1: wrong base for otPending
**Root cause**: The concurrent-ops path in `editor.html` used `allLocal = [...otSent, ...otPending]`
and called `xfOps(serverOps, allLocal, false)`. This treats `otPending` as concurrent to
`serverOps` at the same base as `otSent`, which is wrong — `otPending` is based on the state
*after* `otSent`.

**Fix**: Two-level diamond transform (see above). `xfSent = xfOps(serverOps, otSent, false)` first,
then `xfFull = xfOps(xfSent, otPending, false)`. Rebase `otPending` through `xfSent`.

### Multi-editor OT divergence — Root cause 2: incorrect batch transform (xfOps / server loop)
**Root cause**: When transforming a sequential batch of ops (e.g. `[delete, insert]` from
`computeOps`) against another sequential op, the transform function treated each op in the batch
independently. But op[1] was computed after op[0] was applied — so the history/server op's
effective position shifts as op[0] is processed. Without advancing the history op past op[0]
before using it to transform op[1], positions in op[1] are wrong.

**Same bug on server**: `collab.c` transform loop transformed each client op against the raw
history op independently — same incorrect base assumption.

**Fix (client `xfOps`)**: For each op in `against`, maintain a working copy `b` that advances
past each `ops[i]` (using `xfOp(b, oldA, ...)`) before processing `ops[i+1]`. This ensures b
is always at the correct base for the next client op. Single-element batches are unaffected.

**Fix (server transform loop in `collab_ws_message`)**: Same pattern — `hcopy` starts as the
history op and advances past each `client_ops[i]` (using `transform_op(hcopy, old_ci, false)`)
after transforming `client_ops[i]`. `transform_op` now takes a `b_wins` bool parameter.

**Tie-breaking for advancement**: When advancing `b` past `oldA`, the winner is the *inverse* of
the original `bWins` — if the original call says "b wins," then when transposing to advance b,
`oldA` (the ops element) does NOT win, so `bWins=false` for the advance call.
