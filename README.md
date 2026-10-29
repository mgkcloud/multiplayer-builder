# Multiplayer Builder

Prerelease source package for an adapter-driven, multi-client source editor. Includes runtime contracts, a mountable Node HTTP host, a filesystem revision store, an event reducer, a browser editor shell and an isolated static preview. It is not a standalone service, identity provider, deployment platform or universal production-ready editor.

**Prerelease source release:** `private: true` prevents npm publication; `UNLICENSED` grants no permissive redistribution or reuse license. Public repository visibility does not change those restrictions. No npm release or live deployment is part of this package.

## Runtime and entry points

The package declares Node **18 or newer**; verification has been performed on Node **22**, not on every earlier supported release. The filesystem components require POSIX ownership, permission, fsync and atomic-rename semantics; Windows and distributed-filesystem correctness are not promised. Install the exact locked dependency with `npm ci --ignore-scripts` in a source checkout. There is no build step. `@noble/hashes` remains pinned to **1.8.0**; its license is separate from this source's license.

Explicit package imports (for a local linked/workspace checkout, not a published npm package):

- `@mgkcloud/multiplayer-builder` or `/contracts`: synchronous portable validators and authorization contracts.
- `/event-reducer`: portable immutable event/binding reducer.
- `/preview`: browser DOM preview controller.
- `/shell`: browser `mountBuilder(root, options)` editor UI.
- `/styles`: shell stylesheet (`src/shell.css`); load it through your asset pipeline.
- `/host`: Node-only `createBuilderHost` HTTP handler.
- `/security`: Node-only request, CSRF, rate and safe-file helpers.
- `/revision-store`: Node-only `RevisionStore`, `canonicalJSON`, `candidateDigest`.

The default export surface is contracts only: importing it does not load Node host/storage modules. The portable modules preserve synchronous hashing and validators. Browser consumers must bundle the pinned dependency or supply an import map for its browser ESM graph (including its browser crypto export). Bare package imports do not resolve automatically in browsers. Do not bundle the Node host/store into the browser.

## Host and browser integration

```js
// Node host: these values are supplied by the embedding application.
import { createBuilderHost } from '@mgkcloud/multiplayer-builder/host';
const handler = createBuilderHost({ origin, authenticate, projects });
// Route only /api/builder/v1 requests to handler(req, res).
// At shutdown call handler.close() and close the containing HTTP server.
```

`origin` is a trusted exact canonical HTTP(S) origin, not a request-derived host. Inject `authenticate(req)` using the application's real server session; it returns `{id, sessionId}` or null (or a Promise). Never accept client-provided principal IDs as authentication. Synthetic fixture headers/cookies are not production authentication. `projects` is a Map of project IDs to `{adapter, store?}`; adapters must derive current capabilities/grants from trusted state. The host serves neither authentication endpoints nor static assets. Configure TLS/proxy behavior, server timeouts and operational limits separately. See [HTTP API](docs/http-api.md) and [contracts](docs/extraction.md).

```js
// Browser entry, after resolving package imports with the application's bundler.
import { mountBuilder } from '@mgkcloud/multiplayer-builder/shell';
const editor = mountBuilder(document.querySelector('#builder'), {
  base: '/api/builder/v1'
});
// When removing the editor: editor.destroy().
```

Serve the shell assets explicitly and load the stylesheet. The UI uses same-origin session credentials and the host's session-bound CSRF token. It supports source editing, captured validation/save, project/workspace selection, conflict preservation, capability-gated actions, reconnect/bootstrap and isolated preview. This is revision/CAS and event-based multi-client coordination, **not** character-level collaborative editing or a CRDT.

Preview accepts **static HTML/CSS only**. It strips application scripts, navigation and unsupported resources, uses an opaque-origin sandbox and restrictive CSP, and validates frame/message bindings. It does not execute a live application or provide an arbitrary-code sandbox. Under a nonce-based parent CSP, pass the trusted request nonce as `previewScriptNonce` to `mountBuilder`, or `scriptNonce` to `createPreviewController`; nonce distribution and parent CSP are the embedding host's responsibility.

## Persistence and deployment boundaries

`RevisionStore` persists immutable hashed revisions, validation/idempotency records and ordered events with filesystem locking, fsync and atomic rename. Supply an existing absolute, service-owned 0700 root under a trusted nonsymlink hierarchy, plus trusted `authorize` and `validate` callbacks. All writers must coordinate through the store; hostile same-UID writers are outside its boundary. Cooperating processes on the same supported filesystem are covered, not a multi-host database. Stop all service writers before administrative stale-lock recovery; no automatic unsafe lock stealing is promised. Plan retention, backup and capacity separately.

The HTTP host's captures and task/deploy guards are process-local. Adapter subscriptions must implement a real snapshot/replay bridge; durable task/deployment journals, external-effect idempotency, cross-process target locks and reconciliation remain adapter responsibilities. Store events alone do not invent task state or provider completion.

Deployment is an **explicit adapter action**, separate from Save: prepare an immutable saved revision, confirm it, start once and inspect status. No deploy provider, filesystem materializer or publish transport ships. Unknown outcomes must be reconciled against the real external system, not blindly retried. Private customer/native-app adapters, production credentials, service configurations, user data and live deployments are **not included**.

## Tests

```sh
npm run check
npm test
```

`npm test` executes all existing `test/*.test.mjs` files, including real filesystem, competing-process and ephemeral loopback HTTP tests with synthetic adapters. Normal runs explicitly skip opt-in browser suites; a skip is not browser verification. The fixture uses `TMPDIR`, which must name an existing writable isolated scratch directory. No real provider credentials or production endpoints are needed.

Use an already installed Playwright-compatible ESM module and Chromium executable to enable browser tests (these are not package dependencies and are not downloaded by the scripts):

```sh
export TMPDIR="$(pwd)/node_modules/.test-tmp"
mkdir -p "$TMPDIR"
export CONTRACT_BROWSER_MODULE=file:///absolute/path/to/playwright-core/index.mjs
export CONTRACT_BROWSER_BINARY=/absolute/path/to/chromium
npm run test:browser
# Or run every test with the same browser configuration:
npm test
```

`test:browser` fails immediately unless **both** browser variables are set. It runs the contracts, preview and shell test files, including their non-browser tests. These fixtures launch Chromium with `--no-sandbox`; use an isolated test environment, never untrusted browsing or production data. Browser results depend on the local browser/tooling and host CSP configuration. Historical verification notes in included design docs are phase-local records, not the current full-suite result or a production security audit.

## Reviewed source export

`PUBLIC_SOURCE_MANIFEST.json` is the exact file-only export allowlist. Copy **only** those paths into a fresh repository, reject symlinks, and verify its count and content digests before publishing. Never copy the enclosing workspace or inherited git history. `.gitignore` is defense in depth, not an export policy. Generated output, installed dependencies, private adapters, credentials, service configs, receipts and user media are excluded.

Some local design notes are deliberately omitted pending separate sanitation/review; their presence beside this checkout does not authorize exporting them. Changes after review require a fresh privacy audit and regenerated manifest digests. The manifest omits its own content hash to avoid self-reference. Publication, repository creation and license decisions remain separate approval gates.
