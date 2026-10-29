# F2 HTTP API v1 (frozen wire contract)

This is a mountable generic Node handler, not a listening service, identity system,
provider integration or production deployment. All tests use synthetic authentication
and adapters on ephemeral loopback servers. F0 contracts and F1 storage are unchanged.
No static UI files, arbitrary paths, CORS headers or authentication endpoints are served.

## Host configuration and trusted seam

```js
import { createBuilderHost } from './src/host.mjs';
const handler = createBuilderHost({ origin, authenticate, projects });
// Mount handler(req, res) in the existing HTTP server at /api/builder/v1.
// It owns responses for requests passed to it; route unrelated requests elsewhere.
// At service shutdown: handler.close(), then close the containing server.
```

`origin` is one exact canonical HTTP(S) origin, without trailing slash. It is trusted
configuration, never inferred from Host, Forwarded or a request. Terminating proxies
must preserve Origin and the raw request target without normalizing encoded dot
segments before this handler. Configure the containing server's headers/request
and connection timeouts and concurrency limits; the handler does not own that server.

`authenticate(req) -> {id,sessionId} | null | Promise` is a trusted injected resolver
using the existing server session. Both identifiers must be nonempty strings of at
most 200 JS code units. Only these two fields are retained; neither is accepted on
the wire or returned to the client. Session IDs must be server-derived, stable for
a session, and change on login/logout/rotation. The synthetic test headers are NOT
an authentication implementation and are never understood by the host itself.

`projects` is a Map from canonical project ID to `{adapter, store?}`. The map is
copied on creation. Adapter functions are own enumerable function properties.
`adapter.describe(principal)` returns the principal-specific F0 Descriptor or null;
it must project current supported capabilities and current grants, not cached client
state. The descriptor ID must match its registry key. Registry code must not expose
private roots, principal data, provider configuration or credentials in descriptors,
results, source, HTML, monitor rows or events. Shape validation cannot detect a
secret embedded in otherwise valid text. These callbacks are trusted host code.

All other adapter functions receive `(request, runtime)`:
- `request` is the exact F0 request record with captured context, no principal.
- `runtime.principalId` is server-derived; `runtime.signal` aborts on disconnect.
- `runtime.candidate` is the immutable server-captured Candidate for validate/commit.
- `runtime.prepared` is the immutable server-captured PreparedDeploy for startDeploy.
- `runtime.emit(event)` delivers events for subscribe; await it before the next event.
  `subscribe(request,runtime)` returns an unsubscribe function, optionally asynchronously.
- The only additional adapter method is `monitor({context},runtime) -> Monitor`.
  It requires both monitor and subscribe grants; snapshot/subscribe must be implemented.

Method arguments/results otherwise match `docs/extraction.md`. Capabilities whose
entire method set is missing are removed from both supported and permission rows.
Deploy requires prepareDeploy/startDeploy/deploymentStatus/reconcileDeploy even
though read-only reconcile currently has no public HTTP route. No missing method
is simulated. Known but unavailable routes fail closed (403); unknown route/method
combinations under an authenticated project return 501 UNSUPPORTED. Unauthorized
projects/workspaces/adapter versions return 403 without disclosing registry presence.

When `store` is an F1 RevisionStore, host dispatches readSource/readDraft/validate/
commitDraft to `read/readRevision/validate/commit`; other methods remain adapter
responsibilities. The store's authorize callback must independently consult current
server grants. The host does not create a polling subscription from F1.events():
subscribe is unavailable unless a real adapter event bridge implements it. The
adapter must provide snapshot/cursor replay without a snapshot/subscribe race,
otherwise close and require a new bootstrap. Task/deployment state cannot be
inferred from F1's empty task and deployment snapshot fields.

The host re-authenticates and rechecks grants before actions and after callbacks,
and before every emitted event. Store mutations additionally perform F1 checks.
This is not an atomic transaction with an external ACL system. Coordinate revocation
with provider/store writers if stronger guarantees are required. Trusted adapters
must honor abort signals and enforce resource/time limits; JS callbacks cannot be
preempted. Calls with external effects must implement their own durable idempotency,
unknown-outcome journal and target locks. A per-principal generation/start lock here
lasts for the callback, not for the lifetime of an asynchronously queued task.

## Exact transport

Base: `/api/builder/v1`. Credentials use the containing application's same-origin
session mechanism. Use `credentials: 'same-origin'` in fetch. Every route requires
an authenticated session. No access-control headers are emitted. Any supplied Origin
must exactly match the configured origin; Sec-Fetch-Site cross-site is rejected.
All mutations additionally require Origin and `X-Builder-CSRF` (case-insensitive HTTP
header names). Obtain the session-bound token with GET `/session`; response data is
`{csrfToken}`. The token is a keyed HMAC bound to principal and session. Default key
is 32 cryptographic random bytes per host instance; inject a stable secret (>=32
bytes) only from trusted host configuration when sharing instances. Key changes
require fetching a new token. Tokens never go in URLs or preview documents.

GET context carrier: `X-Builder-Context: <JSON RequestContext>`.
POST context carrier: exact JSON body property `context`. No GET context is needed
for `/session` or `/projects`. Context has exactly:

```json
{"projectId":"alpha","workspaceId":"draft","adapterVersion":{"version":"1.0.0","artifactHash":"sha256:<64 lowercase hex>"},"baseRevision":"sha256:<64 lowercase hex>","requestId":"<RFC variant UUID v1-v8>"}
```

The sample project/workspace are synthetic placeholders. UUIDs and digests must be
real valid values, not the angle-bracket strings above. A project action captures
this entire context; switching tabs must never rewrite it. Generate a new requestId
for a new action. **Validation and its commit share the SAME context/requestId.**
**Preparation, its start and status reads likewise share their original context.**
A different candidate/preparation needs a new requestId. Never add principalId,
permissions, roots, validation status or provider fields to wire requests.

POST accepts only `application/json` (optionally charset=utf-8), no content encoding,
fatal UTF-8 decoding, maximum 420000 UTF-8 request bytes including envelope. This is
a transport bound, NOT a per-file source cap. Operations still have F0's 400000-byte
JSON batch bound, maximum five unique paths. Reads have a 400000-byte total content
bound and 1–5 paths. There is no fixed per-file source cap. Unknown/extra body or
query properties and duplicate query keys are rejected. JSON duplicate object keys
follow native JSON.parse last-key semantics; do not rely on duplicate keys.
The raw target is capped at 20000 code units; GET context is additionally limited
by the containing server's configured header limits.

JSON success envelope: `{ok:true,data:<result>}`. JSON errors:
`{ok:false,error:{code:<stable code>,message:<same code>}}`. No thrown exception text,
source excerpts, local paths, tokens or stack traces are returned. All JSON has
Cache-Control no-store, nosniff and no-referrer. Clients render any returned text as
text, not markup. The preview object is untrusted data, NOT an HTML navigation
response; use the separately reviewed preview sandbox API to display it.

## Routes and exact fields

In the following list `P` means `/projects/:projectId`; all paths include the base.
The URL project must equal context.projectId exactly. POST bodies contain exactly
`context` plus the listed fields. All GET query fields are optional except paths.
No route accepts host-only fields.

| Method/path | Additional fields | Result in data | Grant |
| --- | --- | --- | --- |
| GET /session | none | `{csrfToken}` | authenticated |
| GET /projects | none | `{projects:[Descriptor]}` | at least one effective capability |
| GET P/bootstrap | none | Snapshot | subscribe |
| GET P/events | `cursor=<JSON Cursor or null>`; default null | SSE, below | subscribe |
| GET P/source | `paths=<JSON array of 1–5 canonical paths>`; revision default baseRevision | `{revision,files}` | source |
| GET P/draft | revision default baseRevision | `{manifest,validation,headRevision}` | source |
| GET P/preview | revision default baseRevision | Preview | preview |
| GET P/monitor | none | `{rows,truncated}` Monitor | monitor + subscribe |
| POST P/ask | text | Answer with scoped provenance | ask |
| POST P/tasks | text | `{taskId}` | propose |
| POST P/draft/validate | operations | `{captureId,candidateDigest,validation,expiresAt}` or conflict | saveDraft |
| POST P/draft | captureId | `{revision}` or conflict | saveDraft |
| POST P/deployments/prepare | revision, validationDigest | PreparedDeploy | deploy |
| POST P/deployments | preparedId | `{operationId,status,frozenRevision}` | deploy |
| GET P/deployments/:operationId | none | DeploymentSummary | deploy |

Reusable result schemas are in F0. `expiresAt` is milliseconds since Unix epoch.
Exception: F1 genesis GET draft returns **validation:null** and parentRevision:null.
This means unvalidated seed, never passed evidence. Other readDraft responses use
the normal F0 validator. A preview's returned CSP/HTML has only F0 shape validation;
this HTTP module does not itself run or sanitize preview code.

For ask/tasks/capture/prepare, baseRevision must equal the current server descriptor
revision or 409 STALE_BASE. A descriptor's currentRevision must therefore represent
that advertised workspace's head; registries with multiple independent workspace
heads must provide an appropriate descriptor strategy before enabling these writes.
Historical source/draft/preview reads may explicitly choose a different revision.
Prepare may explicitly freeze a historical revision: trusted prepareDeploy MUST
resolve the revision and verify recorded validation/manifest evidence, including
rejecting unvalidated genesis. A client-supplied validationDigest is a comparison
value, not evidence. Start receives the exact captured preparation, never a fresh
mutable head. Returned start/status revisions are checked against that preparation.
Actual provider verification, receipt evidence, recovery and reconcile are adapter
responsibilities; the host does not turn queued/unknown into succeeded.

## Capture, replay and restart semantics

Candidate digests are calculated with F1 candidateDigest, never accepted from the
client. Captured operations are recursively frozen and stored server-side, bound
to principal, session and the COMPLETE original context. Commit resolves captureId
under this binding and passes the candidate separately to storage. The configured
storage/adapter must revalidate at commit (F1 does). Failed/unknown validation is not
permission to commit. F1 CAS conflict is HTTP409 with success envelope data
`{code:'REVISION_CONFLICT',baseRevision,currentRevision}`; preserve unsaved client text.
No head is silently overwritten. Commit of a captured old base reaches F1's CAS.

Writes use in-memory idempotency records keyed by principal/project/workspace/method/
requestId and fingerprinted over the exact parsed body (canonical JSON). Exact replay
returns the same result/error; different payload returns409 IDEMPOTENCY_MISMATCH,
pending returns409 REQUEST_PENDING/ACTION_BUSY. Method names scope IDs so validate
and commit, or prepare and start, can share one context. Cached replies still require
current authorization. Records have bounded count and TTL; this is NOT durable
cross-restart task/deployment idempotency. F1's underlying commit journal remains
durable and unchanged, but the HTTP host intentionally requires recapture after
restart rather than accepting an unbound client hash to look up a lost candidate.

Uncommitted captures and preparations are memory-only, expire after five minutes
by default, and ALL expire on restart/close. Missing/expired IDs return410
CAPTURE_EXPIRED/PREPARATION_EXPIRED, including formerly committed capture replay
after restart. This does not assert that an earlier ambiguous write failed: read
current draft/head and inspect durable adapter state. Operation bindings also live
only in memory (default one hour); expired/restarted status lookup returns404
OPERATION_NOT_FOUND, not an invented deployment result. Preparation is marked used
BEFORE start dispatch. Ambiguous start errors do not automatically retry a provider.

Defaults: 16 captures per principal across scopes; 1000 global entries each in
capture/preparation/operation/request maps; records expire after one hour; 30 writes
per minute per principal/project with at most1000 rate keys. Rate keys and expired
records are pruned lazily; no background cache timer. Capacity exhaustion returns429.
Options: `now`, `captureTtlMs`, `maxCaptures`, `maxRecords`, `recordTtlMs`,
`rateLimit:{limit,windowMs,maxKeys}`, `streamCheckMs` (1000), `streamLifetimeMs`
(300000), `maxStreams` (100), `maxStreamsPerPrincipal` (4). Counts/times must be
positive safe integers. Limits are per host process, not distributed admission.

## Authenticated streaming fetch

Use fetch for GET events so the context header and existing same-origin credentials
are present (native EventSource cannot set this context header). Content-Type is
`text/event-stream; charset=utf-8`, Cache-Control no-store. Starts with
`: connected\n\n`. Each record is `event: builder\ndata: <one-line JSON Event>\n\n`.
The JSON is the exact F0 v1 Event; cursor is `{epoch,sequence}`, each serialized
event is at most16384 UTF-8 bytes. No source or whole-room polling is performed.

Pass bootstrap's epoch/sequence as cursor. Adapter subscribe must replay exactly
its successor and emit serially using await runtime.emit. A null cursor means the
first valid scoped event establishes a cursor; subsequent events require exact
successors. On gap/duplicate/epoch change, invalid/oversize/cross-scope event,
revoked/session-changed authorization, overlapping callback deliveries, slow-consumer
backpressure, disconnect, host.close or five-minute stream lifetime, the stream
closes and unsubscribes. No unbounded event queue is retained. Revocation is checked
before every event and at the configured interval when idle. Reconnect by fresh
authorized bootstrap, not blind last-event replay. Streaming errors after headers
are EOF, not JSON error records. Timers/listeners and abort signals are cleaned up;
asynchronous subscribe completion after disconnect is immediately unsubscribed.
There is no heartbeat payload or Last-Event-ID protocol. Use cancellation via
AbortController when selection/session changes and discard old in-flight responses.

## Status/error handling

- 200 successful reads, captures, writes or accepted adapter dispatch (not proof of
  deployment completion). SSE200 stays open until cancelled/closed.
- 400 INVALID_REQUEST / CONTEXT_REQUIRED / INVALID_JSON / INVALID_PATH; malformed
  F0 values, encoded traversal, unsafe or repeated paths and unknown fields.
- 401 UNAUTHENTICATED / SESSION_CHANGED.
- 403 FORBIDDEN / ORIGIN_DENIED / CSRF_DENIED / CAPTURE_SCOPE_DENIED /
  PREPARATION_SCOPE_DENIED.
- 404 NOT_FOUND / FILE_NOT_FOUND / OPERATION_NOT_FOUND.
- 409 STALE_BASE / IDEMPOTENCY_MISMATCH / REQUEST_PENDING / ACTION_BUSY /
  PREPARATION_USED; F1 conflict envelope described above.
- 410 CAPTURE_EXPIRED / PREPARATION_EXPIRED.
- 413 BODY_TOO_LARGE / READ_BATCH_TOO_LARGE.
- 415 JSON_REQUIRED / ENCODING_UNSUPPORTED.
- 422 VALIDATION_FAILED (configured storage refuses commit).
- 429 RATE_LIMITED / HOST_CAPACITY / CAPTURE_LIMIT / STREAM_LIMIT.
- 501 UNSUPPORTED.
- 502 ADAPTER_ERROR / ADAPTER_INVALID, including unrecognized internal IO errors.
- 503 STORE_BUSY / HOST_CLOSED.

## Filesystem helpers and boundaries

`security.mjs` exports `validateSourcePath`, `validateMaterializationPaths(paths)`,
`readSafeFile(root,path,{maxBytes=400000})`, HTTP/error/CSRF/rate helpers.
Materialization path validation rejects duplicates and file/directory-prefix
conflicts (both `a` and `a/b`), even though those are legal virtual F1 store names.
It does not materialize files. No filesystem-writing/materializing adapter ships.
Any future materializer MUST call this check for the complete resulting tree, not
just changed paths, and choose platform-specific alias/case/normalization policy.

readSafeFile is a POSIX read helper, not a general sandbox. It requires an absolute
canonical existing service-UID-owned0700 root with no symlink ancestors. Descendant
directories may not be symlinks; leaf open uses O_NOFOLLOW/O_NONBLOCK, requires a
regular service-owned file with nlink1, and rechecks directory device/inode identities
after open. Symlink files/directories, hardlinks, traversal and unsafe roots fail
closed. maxBytes is a caller's aggregate-read budget, not a fixed per-file source
policy. Multi-file adapters must decrement one shared budget and must not claim
partial coverage. F1 never materializes virtual source paths itself.

As with F1, provision a trusted parent hierarchy, prohibit adversarial same-UID
writers and coordinate external edits. Portable Node does not provide openat2 or a
race-proof sandbox against an attacker mutating every parent concurrently. Filesystem
helpers are not an execution sandbox, Windows support, archive extractor or arbitrary
checkout publisher. Only explicit allowlisted assets may be added by a future UI
host; no request path-to-disk mapping or static file route exists here.

## Verification

`node --test test/host.test.mjs test/security.test.mjs` runs real ephemeral HTTP,
F1 commits/readback/restart and synthetic adapter dispatch, plus helper tests.
`npm test` now runs every `test/*.test.mjs` file, including the contracts, store,
reducer, host, preview and shell suites. Browser probes run only when their
explicit environment configuration is supplied. The measurements below are
historical F2 component results, not the current complete-suite count.
No native/private app, credentials, external network or provider integration was
used. Live deployment and strong multi-process task/deploy journaling remain
explicit integration work, not claimed functioning behavior.

Measured local run: new host/security suite 20 tests, 20 passed, 0 failed/skipped;
combined existing plus new suite 181 tests, 179 passed, 0 failed, 2 skipped (the opt-in
contracts and concurrent preview browser probes were not configured). Both new
source modules passed `node --check`. These counts are synthetic local evidence,
not live integration acceptance.
