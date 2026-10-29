# F0: generic multiplayer-builder runtime contracts

This portable Node/browser ESM candidate implements **contracts**, not the editor,
HTTP service, revision store, deployment driver, or a live wrapper. It abstracts
source/revision, isolated preview, and task/deployment-summary separation from the
reviewed extraction contract. No existing application source was copied or loaded;
no native integration, compatibility, or production behavior is claimed.
The candidate is private and UNLICENSED. Publication and licensing remain owner decisions.

## Entry points and trust boundary

Import `src/contracts.mjs`. Validators return the original value or throw
`ContractError` (`code: INVALID_CONTRACT`). They do not coerce, strip, default,
mutate, freeze, authorize users, or log rejected payloads. Error messages contain
schema paths/reasons, not supplied values. Plain own enumerable data properties
are required; unknown/missing properties, getters, symbols, sparse arrays and
non-data prototypes are rejected. Object.prototype and null-prototype records
are accepted. Strings must be valid Unicode. Text lengths count code points;
byte limits count UTF-8 bytes. Arrays whose order has meaning preserve it.

- `validateDescriptor`, `validateDescribeResult`: validate trusted host-to-client
  authorized projections. A client-supplied descriptor is **not** authority.
- `validateRequestContext`: shape only; not permission checking.
- `assertAuthorizedContext(context, trustedDescriptor, capability)`: requires the
  exact project/workspace and pinned adapter, and that workspace's explicit
  effective permission. There is no capability default or cross-workspace union.
- `validateAdapterRequest(method, value, trustedDescriptor)` checks the concrete
  data arguments and authorization. `validateAdapterResult(method, value,
  validatedRequest, trustedDescriptor)` also binds returned identities wherever
  the interface supplies a matching input identity. Revalidate against current
  trusted grants at use time; never trust a client's cached permission projection.
- `validateAdapter(adapter, descriptors)` checks own function method availability
  for supported capabilities. Extra known methods do not grant access. This
  establishes interface shape, **not** method behavior or working integration.
- `validateValue(name, value)` checks a reusable value schema only. It does not
  bind to an external scope; use the request/result APIs for scoped transport.
  `VALUE_TYPES`, `ADAPTER_METHODS`, `METHOD_CAPABILITIES`, `CAPABILITIES`, event/type
  constants and `BOUNDS` are exported for later phases.
- `validateEvent`, `validateEventProgress`, `validatePreviewMessage`, and
  `validatePreviewEvent` enforce the event and frame contracts described below.

The host must derive principalId, permissions, rootBinding and providerBinding
from trusted authentication/registry state. They are never fields of request
context or client/frame messages. The descriptor's `permissions` is a deliberately
sanitized host output, not a principal or host credential object. Exact schemas
also reject token/secret fields at every concrete object boundary. They cannot
recognize secrets hidden inside valid free-text/source strings: output sanitation
and secret scanning remain host responsibilities.

`describe(principal)` is host-only: principal shape belongs to the future host
authentication layer, not this wire module. Its returned list has a validator.
AbortSignal, emit callbacks and subscribe's unsubscribe function are local runtime
objects, not JSON payloads. `ask`/`propose` requests therefore contain only context
and text. `subscribe` results must be a function; no callback lifecycle is executed.
Host code must pass trusted signals/callbacks separately.

## Exact v1 decisions

These choices resolve underspecification in the plan; later phases should reuse
these exports, not silently redefine them.

- Project/workspace/target/check/monitor-row IDs: lowercase registry keys matching
  `^[a-z][a-z0-9-]{0,63}$`, never filesystem paths.
- Request, task, operation, prepared, epoch and frameInstance IDs: lowercase,
  hyphenated RFC-variant UUIDs with version nibble 1–8. Nil UUIDs are rejected.
  Hosts must generate IDs securely; validators do not generate randomness.
- Revision and digest strings: `sha256:` plus exactly 64 lowercase hex digits.
  Revisions are opaque immutable manifest IDs, not counters or `latest`.
- `adapterVersion`: `{version, artifactHash}`, where version is a canonical pinned
  `major.minor.patch` (nonnegative integers, no leading zeros, tags or ranges), and
  artifactHash is the digest format above. Both fields participate in binding.
- Request context: `{projectId, workspaceId, adapterVersion, baseRevision, requestId}`.
- Descriptor: `{id,label,adapterVersion,workspaces,capabilities,permissions,
  currentRevision,deploymentStatus}`. Workspaces are nonempty unique `{id,label}`
  records. Both grants arrays have exactly one `{workspaceId,capabilities}` row
  per workspace; empty capabilities means explicitly unsupported/unauthorized.
  Effective permissions must be a subset of advertised supported capabilities.
  Labels are nonblank, at most 200 code points. No private registry examples or
  project-specific policies are part of the module.
- Capability mapping: readSource/readDraft → source; renderPreview → preview;
  ask → ask; propose → propose; validate/commitDraft → saveDraft;
  snapshot/subscribe → subscribe; all four deployment methods → deploy.
  Monitoring is delivered via snapshot/subscription, not an invented adapter
  method: monitor advertising requires snapshot and subscribe functions, and
  monitor events additionally require explicit monitor permission. A monitor
  consumer therefore needs both subscribe and monitor; neither implies the other.
- `sourceFile`: `{path,sha256,bytes,content}` with recomputed content SHA-256 and
  exact UTF-8 byte count. `path` is a nonempty canonical relative slash path:
  no absolute/empty/dot/traversal segments, backslashes, controls, colon, percent,
  query/fragment syntax or segment-edge whitespace. This is syntax, **not** a
  filesystem sandbox: symlink and root containment checks belong to adapters.
- `manifest`: `{projectId,workspaceId,revision,parentRevision,adapterVersion,files}`;
  parentRevision is digest or null; files are unique `{path,sha256,bytes}` entries.
- `candidate`: `{projectId,workspaceId,baseRevision,adapterVersion,candidateDigest,
  operations}`. One to five unique paths; operations are `{type:'write',path,content}`
  or `{type:'delete',path}`. The entire operations JSON UTF-8 representation must
  fit 400000 bytes, including escaping/metadata. The host must capture immutable
  candidates and recompute/verify candidate/manifest/validation digests using a
  separately specified canonicalization algorithm. F0 only validates digest
  syntax except for source content hashes; no canonical store encoding is invented.
- Validation: `{candidateDigest,validationDigest,checks,adapterVersion,status}`;
  checks are unique `{name,status,message}`; status is passed/failed/unknown.
  `passed` requires a nonempty all-passed check list. Other statuses remain distinct.
- Task summary: `{taskId,requestId,baseRevision,status,message}`, with status
  queued/running/succeeded/failed/cancelled; message ≤300 code points.
- Deployment summary: `{operationId,frozenRevision,status,message,receipt}`;
  status is idle/prepared/queued/running/succeeded/failed/unknown. A succeeded
  summary requires `{evidenceDigest,target}` receipt; all others require null.
  Receipt presence is a schema assertion, not proof that external evidence exists.
- Snapshot: `{epoch,sequence,revision,taskSummaries,deploymentSummary}` with nullable
  deploymentSummary; cursor: `{epoch,sequence}`. Sequence is a nonnegative safe
  integer; epoch is a UUID, not a wall-clock value.
- Prepared deployment: `{preparedId,revision,manifestDigest,target,validationDigest}`.
- Answer: `{text,provenance}` with nonempty provenance records
  `{projectId,workspaceId,revision,path,sha256}` bound to the request's base revision.
- Monitor: `{rows,truncated}` with ≤200 `{id,status,summary}` rows, status
  ok/warning/error/unknown and summary ≤300 code points. Truncation is explicit.
- Preview: `{revision,html,csp,manifestDigest}` with HTML ≤10000000 UTF-8 bytes and
  nonempty CSP text ≤16384 code points. This validates shape, not CSP semantics,
  HTML safety, asset size accounting or trusted bridge hashes. Those are F2 work.
- Commit result: `{revision}` or `{code:'REVISION_CONFLICT',baseRevision,currentRevision}`.
  Conflicts retain distinct identities; no CAS or draft persistence runs in F0.

### Adapter argument/result records

Every data request has the required `context` above plus exactly these fields:

| Method | Additional request fields | Result |
| --- | --- | --- |
| readSource | revision, paths (1–5 unique paths) | `{revision,files}`; exact requested path coverage, total content ≤400000 bytes |
| readDraft | revision | `{manifest,validation,headRevision}` |
| renderPreview | revision | Preview |
| ask | text | Answer |
| propose | text | `{taskId}` |
| validate | immutableCandidate | Validation |
| commitDraft | baseRevision, candidateDigest, requestId | Commit result |
| snapshot | none | Snapshot |
| subscribe | cursor (record or null) | unsubscribe function |
| prepareDeploy | revision, validationDigest | Prepared deployment |
| startDeploy | preparedId, requestId | `{operationId,status,frozenRevision}`; status queued/running/unknown |
| deploymentStatus | operationId | Deployment summary |
| reconcileDeploy | operationId | Deployment summary; no retry implied |

Prompt text is nonblank, ≤6000 code points. Redundant request/base-revision IDs must
agree with context. A read's revision may differ from baseRevision for historical
inspection; results must match the explicitly requested revision. Snapshot/head
may be newer than the base. startDeploy's frozen revision cannot be bound from
preparedId alone: a future prepared-action store must resolve and verify it.
No missing read file is silently treated as complete; overflow/missing paths
must be reported as an explicit host error rather than a partial success value.

### Versioned events and frame messages

Events are exactly `{version:1,projectId,workspaceId,epoch,sequence,revision,type,payload}`.
`validateEvent` requires an authorized subscribe context and exact project/workspace.
Payloads:

- draft.committed: `{baseRevision,requestId}`.
- task.updated: Task summary.
- deploy.updated: Deployment summary.
- monitor.updated: Monitor (also requires monitor permission).
- permissions.changed: `{capabilities}`; unique supported capability names only.
  This is notification data, not permission to mutate trusted grants.

Serialized event size ≤16384 UTF-8 bytes, including envelope. Revisions can advance
within a subscription. `validateEventProgress(previousCursor,nextCursor)` requires
same epoch and exactly next sequence; gaps/replays/epoch changes throw and demand
a fresh authorized bootstrap. F0 does not persist or order an event stream.

Frame messages are exactly `{version:1,projectId,workspaceId,revision,nonce,
frameInstance,type,payload}` and match a host-created binding containing those
identity fields (without version/type/payload). Nonce is 64 lowercase hex digits
(per-load cryptographic randomness is host responsibility). Types/payloads:
preview.ready `{}`, preview.error `{message}` (nonblank ≤300 code points),
preview.resize `{height}` (nonnegative safe integer ≤100000 CSS pixels, a v1
rendering guard). No deploy/save/createTask/fetch/navigate commands are recognized.
Messages also fit 16384 bytes. `validatePreviewEvent(event,boundWindow,binding)`
checks exact event.source identity and origin string `null` before schema/binding
validation. The browser host must independently create an opaque-origin iframe
with only allow-scripts, enforce CSP and replace only the frame document; F0 does
not create frames or retain composer state.

## Source limit override

`BOUNDS.sourceFileBytes === null` deliberately represents **no fixed per-file
source-size cap**. Neither the retired 100000-byte planned cap nor the removed
200KB live ceiling is reinstated. Standalone source file validation accepts files
larger than the batch boundary; a source read or operation batch must still fit its
400000-byte boundary. A 250001-byte source file and write operation are exercised
successfully by tests. Future large-file transport/chunking is not implemented.
The preview asset bound is exported for future consumers but is not applied to
source files or to nonexistent asset transport in F0.

## Local verification and remaining gates

Run `npm ci --ignore-scripts`, then `npm test` / `npm run check`. The v3 lock pins
the sole dependency, `@noble/hashes` **1.8.0**, with MIT license (Paul Miller,
copyright 2022; retain its license notice when distributing). The candidate itself
remains private/UNLICENSED. Registry metadata, installed metadata and LICENSE
were checked; `npm audit --omit=dev` reported zero vulnerabilities. This is a
dependency advisory check, not a claim that this candidate has a security audit.
The locked registry tarball integrity is:
`sha512-jCs9ldd7NwzpgXDIf6P3+NrHh9/sD6CQdxHyjQI+h/6rDNo88ypBxxz45UDuZHz9r3tNz7N/VInSVoVdtXEI4A==`.

Contracts use native `TextEncoder` for UTF-8 size and the dependency's synchronous
SHA-256 plus lowercase hex encoding. No public exports, sync signatures, wire
representations, validation rules, source-hash checks or size limits changed.
Node tests retain `node:crypto` and `Buffer` as independent hash/size oracles,
including empty/ASCII, non-ASCII, combining characters, NUL and SHA block-boundary
cases, with wrong hash/byte-count rejection.

The opt-in real browser test lives in `test/contracts.test.mjs`. Set
`CONTRACT_BROWSER_MODULE` to a locally installed Playwright ESM module URL and
`CONTRACT_BROWSER_BINARY` to a Chromium executable, then run `npm test`.
Current `npm test` runs all test files and skips any unconfigured browser probes.
The following counts are historical F0-only results from before the package test
script was expanded. After a clean `npm ci --ignore-scripts`, that phase reported
132 tests / 131 passed / 0 failed / 1 skipped; with browser configuration it
reported 132 tests / 132 passed / 0 failed / 0 skipped. `npm run check` passed.
The test serves only contracts and the installed dependency's browser ESM files
on an ephemeral loopback port, using an import map for SHA-256, utils and the
dependency's browser crypto export (not its Node conditional export). It closes
the browser and server in `finally`; it adds no shim or browser dependency.

The browser test failed against the original Node-only contracts, then passed
after the repair in Chrome 137.0.7151.119: 32 checks, with Buffer/process/require
all `undefined`. It exercises descriptor/context authorization, independent
ASCII/non-ASCII source hashes and sizes, >400000-byte standalone source acceptance,
readSource results, versioned events, preview values/messages, frame binding and
negative scope/hash/byte/sequence/origin/nonce cases. This proves real browser
module execution with native browser crypto, not production bundler configuration
or an actual sandbox iframe lifecycle. No host-specific paths enter npm scripts.

Synthetic tests exercise positive/negative schemas, explicit grants, unknown and
missing fields, malformed IDs, ordering types, all adapter data methods/results,
capability-method honesty, host-field rejection, scoped provenance, frame binding,
UTF-8/batch limits and removal of the source cap. They do not exercise a provider,
source store, CAS, idempotency cache, actual deployment, cancellation or
native application adapter. Authentication, capability attestation of behavior,
content sanitation, safe filesystem access, canonical digest verification,
immutable snapshot capture, prepared-action lookup and lifecycle integration
remain separate phases and parent review gates. No overall-builder completion
is implied by passing these contract tests.
