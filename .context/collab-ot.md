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

### Second full audit fixes (2026-06-13)

**C server (`collab.c`):**
- **Eviction with unflushed dirty data**: `collab_tick` could evict a doc after a failed
  flush (flush leaves `dirty=true`), permanently losing the in-memory content. Fixed by
  only evicting when `!doc->dirty`.
- **`parse_op` strdup OOM crash**: `strlen(op_out->text)` called when strdup returns NULL.
  Added NULL check returning false on strdup failure.
- **`base_version` integer overflow**: Client could send a huge float `base_version`
  (e.g. 9e18) which cast to `int` wraps/overflows, bypassing version checks. Added
  explicit range guard: reject if `< 0 || > INT_MAX` before casting.
- **`COLLAB_FLUSH_SECS` type**: Was `5.0` (float literal) compared to `time_t` (integer).
  Changed to `5` for clean integer arithmetic.

**JS client (`editor.html`):**
- **`xfOp`/`applyOps`/`adjustPos` null guards**: `b.text.length` throws if text is
  undefined; `b.len` arithmetic with undefined produces NaN silently corrupting transforms.
  `applyOps` with null `op.text` would produce literal `"null"` in content.
  Added `b.text ? b.text.length : 0`, `b.len || 0`, `op.text || ''`, `op.len || 0`
  guards throughout. Defensive against any malformed message from the server.

### Third full audit fixes (2026-06-13)

**JS view (`document.html`):**
- **`applyOps` missing null guards**: `document.html` had its own copy of `applyOps`
  without the null guards added to `editor.html` in the second audit. `op.text` (undefined
  on malformed insert) would concatenate as the string `"undefined"` into `rawMarkdown`
  (corrupting the live view), and `op.len` (undefined on malformed delete) would produce
  `NaN` offsets making `text.slice(NaN)` return an empty string (dropping the rest of the
  document). Fixed: `op.text || ''` and `op.len || 0` in `document.html:applyOps`.

**No new C server issues found (third audit).** Verified:
- `history_push` ring-buffer correctness — both branches correct, no double-free.
- `apply_op` bounds clamping — full coverage for insert and delete.
- `transform_op` delete-delete overlap formula — correct.
- `history_gap` detection (`oldest_idx = ops_start % SIZE`) — no-op since `ops_start` is
  always in `[0, COLLAB_OP_HISTORY)`, always points to actual oldest entry.
- `collab_notify_replace` drain: `queue->content` nulled before `docs_mutex` released;
  `free(NULL)` at end is safe for the doc-found path.
- Locking model: all WS/tick functions on main thread; `docs_mutex` guards client slot reads
  in broadcasts; `doc->mutex` guards content mutations. No races.
- `otSent = []` cleared on every `init` (not just first-connect); reconnect computes fresh
  diff from server canonical state to editor — correctly subsumes old pending ops.
- `xfOps` bWins inversion for advancement is symmetric and consistent with server `hcopy`
  advancement (`b_wins=false` in `transform_op(hcopy, old_ci, false)`).
- Multi-op batch version tagging (all ops in one batch share same `doc->version`) is correct
  — server's `> base_version` filter processes the whole batch atomically.

### Fourth full audit fixes (2026-06-13)

**C server (`collab.c`):**
- **`history_push` strdup OOM → dangling pointer**: `doc->ops[idx] = *op` copies the
  `client_ops[i].text` pointer into the history slot. If `strdup` then fails, `text` stays
  as the original (soon-to-be-freed) pointer. When the caller frees `client_ops[i].text`
  after broadcast, the history slot holds a dangling pointer — use-after-free on the next
  transform that reads that history op. Fixed: on strdup failure set `doc->ops[idx].len = 0`
  (text implicitly NULL from the failed strdup return). Both branches (not-full and full)
  patched identically.

**C server (`server.c`):**
- **WS upgrade proceeds on `calloc` OOM**: If `calloc(ws_conn_data_t)` fails, the old code
  still called `mg_ws_upgrade()` and skipped `collab_ws_connect`. The client got an open WS
  connection that never received an `init` message — the editor would hang at "Syncing…"
  until the WS was eventually closed. Fixed: return HTTP 503 immediately on OOM before
  upgrading, so the client sees a proper error and retries.

**No new JS issues found (fourth audit).** Verified:
- `computeOps` edge cases: both-empty, prefix-only, suffix-only, identical — all correct.
- `_otPrevContent` tracking consistent across all paths (input, programmatic, init, replace,
  concurrent ops).
- `saveDocument` no-op when connected; `persistDocument` correctly guards re-entrant saves.
- Shift+Tab no-change path: `otApplyLocalChange` called with unchanged value → empty ops →
  no mutation. Harmless.
- `pool_pop_response` wakeup race: response always pushed before `mg_wakeup`, so the
  MG_EV_WAKEUP handler always finds the item. Stale-conn path handled by `mg_wakeup` return.
- `http_respond_error` JSON buffer (256 bytes) adequate for all literal message strings.
- Error messages in `routes.c` all string literals — no user-controlled data in JSON errors.

### Fifth full audit fixes — stability / memory exhaustion (2026-06-13)

**C server (`collab.c` + `collab.h`):**

- **No WS frame size limit**: `collab_ws_message` accepted frames of arbitrary size, allocating
  `malloc(len+1)` unconditionally. A malicious or buggy client could send a multi-gigabyte WS
  frame causing heap exhaustion and OOM crash. Fixed: reject frames larger than
  `COLLAB_MAX_WS_MSG_BYTES` (10 MB) at the top of `collab_ws_message` before any allocation.

- **`parse_op` float-to-int overflow on `pos` and `len`**: `(int)jp->valuedouble` without a
  pre-cast range check. A `pos` value of `3e9` would overflow a 32-bit int to a large negative,
  pass the `< 0` clamp (clamped to 0), and produce a silently wrong op. A `len` value similarly
  overflows. Fixed: reject any `pos` or `len` double outside `[0, 2147483647]` before casting,
  matching the existing `base_version` guard. (Post-cast negative-check removed since it is now
  unreachable.)

- **`(int)strlen(doc->content)` integer overflow**: On a document larger than ~2 GB (pathological
  but possible on 64-bit systems), `strlen` returns `size_t > INT_MAX` and the cast wraps
  negative, making all `parse_op` clamping wrong. Fixed: compute `strlen` as `size_t`, check
  against `COLLAB_MAX_CONTENT_BYTES` before casting to `int`. Ops that arrive when the document
  is already over the limit get a `replace` resync, preventing further growth.

- **`collab_notify_replace` accepts arbitrarily large content**: A raw PUT with a 200 MB body
  would `strdup` it into the notify queue (200 MB) then assign it to `doc->content` (another
  allocation), plus cJSON would serialise it for broadcast (third copy). Fixed: reject content
  larger than `COLLAB_MAX_CONTENT_BYTES` in `collab_notify_replace` before `strdup`.

- **`strdup("")` OOM on first connect leaves active doc slot with NULL content**: If `strdup("")`
  fails when no disk content exists, `doc->active = true` but `doc->content = NULL`. A later
  `collab_ws_message` would call `strlen(NULL)` — undefined behaviour / crash. Fixed: on strdup
  failure, immediately deactivate the slot, destroy its mutex, unlock, and send an error frame.

- **Added constants to `collab.h`**: `COLLAB_MAX_WS_MSG_BYTES` (10 MB) and
  `COLLAB_MAX_CONTENT_BYTES` (50 MB) as named limits for all size enforcement points.

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
