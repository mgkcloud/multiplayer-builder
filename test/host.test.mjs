import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { mkdtemp, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { createBuilderHost } from '../src/host.mjs';
import { RevisionStore } from '../src/revision-store.mjs';
const hash = s => `sha256:${createHash('sha256').update(s).digest('hex')}`;
const adapterVersion = { version: '1.0.0', artifactHash: hash('synthetic adapter') };
const source = (path, content) => ({ path, content, bytes: Buffer.byteLength(content), sha256: hash(content) });
const caps = ['source', 'saveDraft', 'ask', 'propose', 'subscribe', 'preview', 'deploy', 'monitor'];
async function fixture(t, options = {}) {
  const root = await mkdtemp(join(process.env.TMPDIR, 'f2-host-')); await chmod(root, 0o700);
  let grants = [...caps], head, emit, stops = 0, asks = 0, deploys = 0, time = Date.now();
  const descriptor = () => ({ id: 'alpha', label: 'Synthetic', adapterVersion, workspaces: [{ id: 'draft', label: 'Draft' }], capabilities: [{ workspaceId: 'draft', capabilities: caps }], permissions: [{ workspaceId: 'draft', capabilities: grants }], currentRevision: head, deploymentStatus: 'idle' });
  const config = { root, authorize: ({ principalId }) => { if (principalId !== 'alice') throw new Error('denied'); return descriptor(); }, validate: () => ({ status: 'passed', checks: [{ name: 'synthetic-check', status: 'passed', message: '' }] }) };
  const store = new RevisionStore(config);
  const genesis = await store.initialize({ projectId: 'alpha', workspaceId: 'draft', adapterVersion, files: [source('src/main.txt', 'seed')] }); head = genesis.revision;
  const adapter = {
    describe: p => p.id === 'alice' || p.id === 'bob' ? descriptor() : null,
    snapshot: (r, rt) => store.snapshot({ ...r, principalId: rt.principalId }),
    subscribe: (r, rt) => { emit = rt.emit; return () => { stops++; emit = null; }; },
    ask: (r, rt) => { asks++; assert.equal(rt.principalId, 'alice'); return { text: r.text, provenance: [{ projectId: 'alpha', workspaceId: 'draft', revision: r.context.baseRevision, path: 'src/main.txt', sha256: hash('seed') }] }; },
    propose: () => ({ taskId: randomUUID() }),
    renderPreview: r => ({ revision: r.revision, html: '<p>Synthetic</p>', csp: "default-src 'none'", manifestDigest: r.revision }),
    monitor: () => ({ rows: [], truncated: false }),
    prepareDeploy: r => ({ preparedId: randomUUID(), revision: r.revision, manifestDigest: r.revision, target: 'synthetic', validationDigest: r.validationDigest }),
    startDeploy: (r, rt) => { deploys++; assert.ok(Object.isFrozen(rt.prepared)); return { operationId: randomUUID(), status: 'queued', frozenRevision: rt.prepared.revision }; },
    deploymentStatus: r => ({ operationId: r.operationId, frozenRevision: genesis.revision, status: 'unknown', message: 'Synthetic only', receipt: null }),
    reconcileDeploy: r => adapter.deploymentStatus(r),
  };
  const server = createServer((req, res) => handler(req, res));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const hostOptions = { origin, authenticate: req => req.headers['x-synthetic-user'] ? { id: req.headers['x-synthetic-user'], sessionId: req.headers['x-synthetic-session'] || 'fixture-session' } : null,
    projects: new Map([['alpha', { adapter, store }]]), streamCheckMs: 15, now: () => time, ...options };
  let handler = createBuilderHost(hostOptions);
  t.after(async () => { handler.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); });
  const context = (changes = {}) => ({ projectId: 'alpha', workspaceId: 'draft', adapterVersion, baseRevision: genesis.revision, requestId: randomUUID(), ...changes });
  async function call(path, { context: c, body, user = 'alice', headers = {}, method = body ? 'POST' : 'GET' } = {}) {
    let csrf;
    if (method === 'POST') csrf = (await (await fetch(origin + '/api/builder/v1/session', { headers: { 'x-synthetic-user': user } })).json()).data?.csrfToken;
    const response = await fetch(origin + '/api/builder/v1/' + path, { method, headers: { ...(user ? { 'x-synthetic-user': user } : {}), ...(c && method === 'GET' ? { 'x-builder-context': JSON.stringify(c) } : {}), ...(method === 'POST' ? { origin, 'x-builder-csrf': csrf, 'content-type': 'application/json' } : {}), ...headers }, ...(body ? { body: typeof body === 'string' ? body : JSON.stringify(body) } : {}) });
    return { status: response.status, json: await response.json(), headers: response.headers };
  }
  return { context, call, origin, adapter, store, config, genesis, server, setGrants: g => { grants = g; }, setHead: h => { head = h; }, advance: ms => { time += ms; }, counts: () => ({ stops, asks, deploys }), emit: e => emit?.(e), restart: () => { handler.close(); handler = createBuilderHost(hostOptions); } };
}
const sourceRoute = 'projects/alpha/source?paths=' + encodeURIComponent(JSON.stringify(['src/main.txt']));
test('real HTTP default deny, projected descriptors and cross-project/workspace/adapter denial', async t => {
  const f = await fixture(t), c = f.context();
  assert.equal((await f.call('projects', { user: null })).status, 401);
  const projects = await f.call('projects'); assert.equal(projects.status, 200); assert.equal(projects.json.data.projects.length, 1); assert.equal(projects.headers.get('access-control-allow-origin'), null);
  assert.equal((await f.call(sourceRoute, { context: c })).json.data.files[0].content, 'seed');
  assert.deepEqual((await f.call('projects/alpha/monitor', { context: c })).json.data, { rows: [], truncated: false });
  assert.equal((await f.call('projects/alpha/preview', { context: c })).json.data.revision, c.baseRevision);
  assert.equal((await f.call(sourceRoute, { context: { ...c, projectId: 'other' } })).status, 403);
  assert.equal((await f.call(sourceRoute, { context: { ...c, workspaceId: 'other' } })).status, 403);
  assert.equal((await f.call(sourceRoute, { context: { ...c, adapterVersion: { ...adapterVersion, version: '2.0.0' } } })).status, 403);
  f.setGrants([]); assert.deepEqual((await f.call('projects')).json.data.projects, []);
  assert.equal((await f.call(sourceRoute, { context: c })).status, 403);
});
test('real HTTP origin/CSRF rejects mutations, untrusted principal fields and malformed requests', async t => {
  const f = await fixture(t), c = f.context(), body = { context: c, text: 'hello' };
  for (const headers of [{ origin: 'http://evil.invalid' }, { 'x-builder-csrf': 'bad' }]) assert.equal((await f.call('projects/alpha/ask', { body, headers })).status, 403);
  assert.equal((await f.call('projects/alpha/ask', { body: { ...body, principalId: 'admin' } })).status, 400);
  assert.equal((await f.call('projects/alpha/ask', { body: '{' })).status, 400);
  assert.equal((await f.call('projects/alpha/ask', { body: 'x'.repeat(420001) })).status, 413);
  assert.equal((await f.call('projects/alpha/ask', { body, headers: { 'content-type': 'text/plain' } })).status, 415);
  assert.equal((await f.call('projects/alpha/ask', { body: { ...body, text: 'x'.repeat(6001) } })).status, 400);
  const token = (await f.call('session')).json.data.csrfToken;
  const rawOversize = await new Promise((resolve, reject) => {
    const req = httpRequest(f.origin + '/', { method: 'POST', path: '/api/builder/v1/projects/alpha/ask', headers: { 'x-synthetic-user': 'alice', origin: f.origin, 'x-builder-csrf': token, 'content-type': 'application/json' } }, res => { res.resume(); res.once('end', () => resolve(res.statusCode)); });
    req.on('error', reject); req.write('x'.repeat(220000)); req.end('x'.repeat(220000));
  });
  assert.equal(rawOversize, 413);
  assert.equal((await f.call('projects/alpha/ask', { body, method: 'PUT' })).status, 501);
});
test('captured candidate is server hashed and committed through real F1; genesis null is honest', async t => {
  const f = await fixture(t), c = f.context();
  const initial = await f.call('projects/alpha/draft', { context: c });
  assert.equal(initial.status, 200); assert.equal(initial.json.data.validation, null);
  const payload = { context: c, operations: [{ type: 'write', path: 'src/main.txt', content: 'x'.repeat(250001) }] };
  const validation = await f.call('projects/alpha/draft/validate', { body: payload }); assert.equal(validation.status, 200);
  const captured = validation.json.data;
  assert.equal(captured.validation.status, 'passed'); assert.equal(captured.validation.candidateDigest, captured.candidateDigest);
  assert.deepEqual((await f.call('projects/alpha/draft/validate', { body: payload })).json, validation.json);
  const body = { context: c, captureId: captured.captureId };
  const saved = await f.call('projects/alpha/draft', { body }); assert.equal(saved.status, 200);
  const revision = saved.json.data.revision; assert.notEqual(revision, c.baseRevision);
  assert.deepEqual((await f.call('projects/alpha/draft', { body })).json, saved.json);
  const read = await f.call(sourceRoute + '&revision=' + encodeURIComponent(revision), { context: c }); assert.equal(read.json.data.files[0].bytes, 250001);
  const restartedStore = new RevisionStore(f.config);
  assert.equal((await restartedStore.readRevision({ principalId: 'alice', context: c, revision })).manifest.revision, revision);
  const history = await f.store.events({ principalId: 'alice', context: c }); assert.equal(history.length, 1);
  assert.equal((await f.call('projects/alpha/draft', { body: { ...body, candidateDigest: hash('unbound') } })).status, 400);
});
test('capture binding includes principal, session, workspace, base and request; expiry and restart fail explicitly', async t => {
  const f = await fixture(t, { captureTtlMs: 50 }), c = f.context();
  const capture = (await f.call('projects/alpha/draft/validate', { body: { context: c, operations: [{ type: 'write', path: 'src/main.txt', content: 'captured' }] } })).json.data;
  const body = { context: c, captureId: capture.captureId };
  assert.equal((await f.call('projects/alpha/draft', { body, user: 'bob' })).status, 403);
  assert.equal((await f.call('projects/alpha/draft', { body: { ...body, context: f.context() } })).status, 403);
  f.advance(51);
  assert.equal((await f.call('projects/alpha/draft', { body })).status, 410);
  f.restart();
  assert.equal((await f.call('projects/alpha/draft', { body })).status, 410);
  assert.equal((await f.store.snapshot({ principalId: 'alice', context: c })).revision, c.baseRevision);
});
test('stale and mismatched request reuse, validation failure, batch bounds and grant revocation', async t => {
  const f = await fixture(t), c = f.context(), body = { context: c, text: 'hello' };
  assert.equal((await f.call('projects/alpha/ask', { body })).status, 200);
  assert.equal((await f.call('projects/alpha/ask', { body })).status, 200); assert.equal(f.counts().asks, 1);
  assert.equal((await f.call('projects/alpha/ask', { body: { ...body, text: 'different' } })).status, 409);
  assert.equal((await f.call('projects/alpha/ask', { body: { ...body, context: f.context({ baseRevision: hash('stale') }) } })).status, 409);
  assert.equal((await f.call('projects/alpha/draft/validate', { body: { context: f.context(), operations: [{ type: 'write', path: 'x', content: 'x'.repeat(400001) }] } })).status, 400);
  f.setGrants(['source']); assert.equal((await f.call('projects/alpha/ask', { body })).status, 403);
  f.setGrants(caps); f.adapter.ask = () => { throw new Error('/private/path token=secret source text'); };
  const error = await f.call('projects/alpha/ask', { body: { context: f.context(), text: 'safe' } });
  assert.equal(error.status, 502); assert.equal(JSON.stringify(error.json).includes('private'), false);
});
test('unsupported adapters are not advertised and malformed adapter results fail closed', async t => {
  const f = await fixture(t);
  delete f.adapter.renderPreview;
  const projects = (await f.call('projects')).json.data.projects;
  assert.equal(projects[0].capabilities[0].capabilities.includes('preview'), false);
  assert.equal((await f.call('projects/alpha/preview', { context: f.context() })).status, 403);
  f.adapter.ask = () => ({ text: 'invalid', provenance: [] });
  assert.equal((await f.call('projects/alpha/ask', { body: { context: f.context(), text: 'hello' } })).status, 502);
});
test('source traversal and extra query fields are rejected over real HTTP', async t => {
  const f = await fixture(t);
  for (const path of ['../secret', '%2e%2e/secret', 'a\\b', '/etc/file']) {
    assert.equal((await f.call('projects/alpha/source?paths=' + encodeURIComponent(JSON.stringify([path])), { context: f.context() })).status, 400);
  }
  assert.equal((await f.call(sourceRoute + '&principalId=admin', { context: f.context() })).status, 400);
  const raw = await new Promise((resolve, reject) => {
    const req = httpRequest(f.origin + '/', { path: '/api/builder/v1/projects/alpha/%2e%2e/source', headers: { 'x-synthetic-user': 'alice' } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }); req.on('error', reject); req.end();
  });
  assert.equal(raw, 400);
});
test('authenticated SSE emits scoped validated events, cleans up aborts and revoked grants', async t => {
  const f = await fixture(t), c = f.context();
  const snapshot = (await f.call('projects/alpha/bootstrap', { context: c })).json.data;
  const cursor = { epoch: snapshot.epoch, sequence: snapshot.sequence };
  const connect = async controller => fetch(f.origin + '/api/builder/v1/projects/alpha/events?cursor=' + encodeURIComponent(JSON.stringify(cursor)), { signal: controller.signal, headers: { 'x-synthetic-user': 'alice', 'x-builder-context': JSON.stringify(c) } });
  const controller = new AbortController(), res = await connect(controller), reader = res.body.getReader();
  assert.equal(res.headers.get('content-type'), 'text/event-stream; charset=utf-8'); await reader.read();
  const event = { version: 1, projectId: 'alpha', workspaceId: 'draft', epoch: snapshot.epoch, sequence: 1, revision: c.baseRevision, type: 'permissions.changed', payload: { capabilities: caps } };
  await f.emit(event);
  assert.match(new TextDecoder().decode((await reader.read()).value), /event: builder/);
  controller.abort(); await reader.cancel().catch(() => {});
  await new Promise(resolve => setTimeout(resolve, 30)); assert.equal(f.counts().stops, 1);
  const second = new AbortController(), next = await connect(second), nextReader = next.body.getReader(); await nextReader.read();
  f.setGrants(['source']);
  assert.equal((await nextReader.read()).done, true); assert.equal(f.counts().stops, 2); second.abort();
});
test('SSE gap and cross-scope events fail closed; stream limits are bounded', async t => {
  const f = await fixture(t, { maxStreamsPerPrincipal: 1 }), c = f.context();
  const snap = (await f.call('projects/alpha/bootstrap', { context: c })).json.data;
  const url = f.origin + '/api/builder/v1/projects/alpha/events?cursor=' + encodeURIComponent(JSON.stringify({ epoch: snap.epoch, sequence: 0 }));
  const headers = { 'x-synthetic-user': 'alice', 'x-builder-context': JSON.stringify(c) };
  const res = await fetch(url, { headers }), reader = res.body.getReader(); await reader.read();
  assert.equal((await fetch(url, { headers })).status, 429);
  await f.emit({ version: 1, projectId: 'alpha', workspaceId: 'draft', epoch: snap.epoch, sequence: 2, revision: c.baseRevision, type: 'permissions.changed', payload: { capabilities: [] } });
  assert.equal((await reader.read()).done, true); assert.equal(f.counts().stops, 1);
});
test('deployment dispatch requires a server captured preparation with exact frozen revision and request binding', async t => {
  const f = await fixture(t), c = f.context();
  const prep = await f.call('projects/alpha/deployments/prepare', { body: { context: c, revision: c.baseRevision, validationDigest: hash('synthetic validation') } });
  assert.equal(prep.status, 200);
  const body = { context: c, preparedId: prep.json.data.preparedId };
  assert.equal((await f.call('projects/alpha/deployments', { body: { ...body, context: f.context() } })).status, 403);
  const started = await f.call('projects/alpha/deployments', { body }); assert.equal(started.status, 200); assert.equal(started.json.data.frozenRevision, c.baseRevision);
  assert.deepEqual((await f.call('projects/alpha/deployments', { body })).json, started.json); assert.equal(f.counts().deploys, 1);
  const route = 'projects/alpha/deployments/' + started.json.data.operationId;
  assert.equal((await f.call(route, { context: c })).json.data.status, 'unknown');
  assert.equal((await f.call(route, { context: f.context() })).status, 404);
  f.restart(); assert.equal((await f.call('projects/alpha/deployments', { body })).status, 410);
});
test('real F1 failed validation never commits and concurrent captures retain CAS conflict identity', async t => {
  const f = await fixture(t), a = f.context(), b = f.context();
  const capture = async (context, content) => f.call('projects/alpha/draft/validate', { body: { context, operations: [{ type: 'write', path: 'src/main.txt', content }] } });
  const ca = (await capture(a, 'a')).json.data, cb = (await capture(b, 'b')).json.data;
  assert.equal((await f.call('projects/alpha/draft', { body: { context: a, captureId: ca.captureId } })).status, 200);
  const conflict = await f.call('projects/alpha/draft', { body: { context: b, captureId: cb.captureId } });
  assert.equal(conflict.status, 409); assert.equal(conflict.json.data.code, 'REVISION_CONFLICT'); assert.equal(conflict.json.data.baseRevision, b.baseRevision);
  const fail = await fixture(t);
  fail.config.validate = () => ({ status: 'failed', checks: [{ name: 'synthetic-check', status: 'failed', message: 'Not accepted' }] });
  // Construct a second store sharing the real root, with a genuinely failing validator.
  const failingStore = new RevisionStore(fail.config);
  fail.store.validate = failingStore.validate.bind(failingStore); fail.store.commit = failingStore.commit.bind(failingStore);
  const context = fail.context();
  const validation = await fail.call('projects/alpha/draft/validate', { body: { context, operations: [{ type: 'write', path: 'src/main.txt', content: 'rejected' }] } });
  assert.equal(validation.status, 200); assert.equal(validation.json.data.validation.status, 'failed');
  assert.equal((await fail.call('projects/alpha/draft', { body: { context, captureId: validation.json.data.captureId } })).status, 422);
  assert.equal((await fail.store.read({ principalId: 'alice', context, paths: ['src/main.txt'] })).files[0].content, 'seed');
});
test('authorization is rechecked after callback completion and generation admission is bounded', async t => {
  const f = await fixture(t); let release, started;
  const entered = new Promise(resolve => { started = resolve; });
  const pending = new Promise(resolve => { release = resolve; });
  const previous = f.adapter.ask;
  f.adapter.ask = async (r, rt) => { started(); await pending; return previous(r, rt); };
  const first = f.call('projects/alpha/ask', { body: { context: f.context(), text: 'first' } });
  await entered;
  assert.equal((await f.call('projects/alpha/tasks', { body: { context: f.context(), text: 'second' } })).status, 409);
  f.setGrants(['source']); release();
  assert.equal((await first).status, 403);
});
test('capture quotas, cross-scope and oversize SSE fail closed with cleanup', async t => {
  const f = await fixture(t, { maxCaptures: 1 });
  const capture = context => f.call('projects/alpha/draft/validate', { body: { context, operations: [{ type: 'write', path: 'src/main.txt', content: 'one' }] } });
  assert.equal((await capture(f.context())).status, 200); assert.equal((await capture(f.context())).status, 429);
  const c = f.context(), snap = (await f.call('projects/alpha/bootstrap', { context: c })).json.data;
  const headers = { 'x-synthetic-user': 'alice', 'x-builder-context': JSON.stringify(c) };
  for (const change of [{ workspaceId: 'other' }, { payload: { capabilities: ['source'], injected: 'x'.repeat(17000) } }]) {
    const res = await fetch(f.origin + '/api/builder/v1/projects/alpha/events', { headers }), reader = res.body.getReader(); await reader.read();
    await f.emit({ version: 1, projectId: 'alpha', workspaceId: 'draft', epoch: snap.epoch, sequence: 1, revision: c.baseRevision, type: 'permissions.changed', payload: { capabilities: [] }, ...change });
    assert.equal((await reader.read()).done, true);
  }
  assert.equal(f.counts().stops, 2);
});
test('write rate limits are enforced on actual HTTP requests', async t => {
  const f = await fixture(t, { rateLimit: { limit: 1 } });
  assert.equal((await f.call('projects/alpha/tasks', { body: { context: f.context(), text: 'first' } })).status, 200);
  assert.equal((await f.call('projects/alpha/tasks', { body: { context: f.context(), text: 'second' } })).status, 429);
});
