import { createServer } from 'node:http';
import { mkdtemp, chmod, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, randomUUID, randomBytes } from 'node:crypto';
import { createBuilderHost } from '../src/host.mjs';
import { RevisionStore } from '../src/revision-store.mjs';
const hash = s => 'sha256:' + createHash('sha256').update(s).digest('hex');
const file = content => ({ path: 'index.html', content, bytes: Buffer.byteLength(content), sha256: hash(content) });
const version = { version: '1.0.0', artifactHash: hash('synthetic-ui-adapter') };
const all = ['source', 'saveDraft', 'preview', 'subscribe', 'ask', 'propose', 'monitor', 'deploy'];

export async function createUIFixture({ strictParentCsp = false, shellOptions = {}, deploymentStatuses = ['unknown'], ambiguousStart = false } = {}) {
  const root = await mkdtemp(join(process.env.TMPDIR, 'builder-ui-')); await chmod(root, 0o700);
  const entries = new Map(), starts = [], requests = [], gates = new Map();
  let handler, authenticated = true, session = 'synthetic-ui-session';
  for (const id of ['alpha', 'beta', 'readonly']) {
    const caps = id === 'readonly' ? ['source', 'preview', 'subscribe'] : all;
    let head, epoch, sequence = 0, history = [];
    const subscribers = new Set();
    const descriptor = () => ({ id, label: id, adapterVersion: version, workspaces: [{ id: 'draft', label: 'Draft' }], capabilities: [{ workspaceId: 'draft', capabilities: caps }], permissions: [{ workspaceId: 'draft', capabilities: caps }], currentRevision: head, deploymentStatus: 'idle' });
    const store = new RevisionStore({ root, authorize: () => descriptor(), validate: () => ({ status: 'passed', checks: [{ name: 'synthetic', status: 'passed', message: 'Synthetic validator only' }] }) });
    const genesis = await store.initialize({ projectId: id, workspaceId: 'draft', adapterVersion: version, files: [file(`<h1>${id} seed</h1>`)] }); head = genesis.revision;
    const context = () => ({ projectId: id, workspaceId: 'draft', adapterVersion: version, baseRevision: head, requestId: randomUUID() });
    epoch = (await store.snapshot({ principalId: 'synthetic', context: context() })).epoch;
    const originalCommit = store.commit.bind(store);
    store.commit = async input => {
      const gate = gates.get(id + ':commit'); gate?.arrive(); await gate?.promise;
      const result = await originalCommit(input);
      if (!result.code && result.revision !== head) {
        const events = await store.events({ principalId: 'synthetic', context: input.context });
        history = events; head = result.revision; sequence = history.at(-1).sequence;
        for (const sub of subscribers) sub.queue = sub.queue.then(async () => { for (const event of history) if (event.sequence > sub.sequence) { sub.sequence = event.sequence; await sub.emit(event); } });
        await Promise.all([...subscribers].map(s => s.queue));
      }
      return result;
    };
    const operations = new Map();
    const adapter = {
      describe: () => descriptor(),
      snapshot: () => ({ epoch, sequence, revision: head, taskSummaries: [], deploymentSummary: null }),
      subscribe: (r, rt) => {
        const sub = { emit: rt.emit, sequence: r.cursor?.sequence ?? sequence, queue: Promise.resolve() };
        subscribers.add(sub);
        sub.queue = sub.queue.then(async () => { for (const event of history) if (event.sequence > sub.sequence) { sub.sequence = event.sequence; await sub.emit(event); } });
        return () => subscribers.delete(sub);
      },
      renderPreview: async (r, rt) => {
        const result = await store.read({ principalId: rt.principalId, context: r.context, revision: r.revision, paths: ['index.html'] });
        await gates.get(id + ':preview')?.promise;
        return { revision: r.revision, html: result.files[0].content, csp: "default-src 'none'", manifestDigest: r.revision };
      },
      ask: r => ({ text: 'Synthetic answer: ' + r.text, provenance: [{ projectId: id, workspaceId: 'draft', revision: r.context.baseRevision, path: 'index.html', sha256: hash('synthetic') }] }),
      propose: () => ({ taskId: randomUUID() }),
      monitor: () => ({ rows: [{ id: 'synthetic', status: 'ok', summary: 'Synthetic monitor only' }], truncated: false }),
      prepareDeploy: async (r, rt) => {
        const record = await store.readRevision({ principalId: rt.principalId, context: r.context, revision: r.revision });
        if (!record.validation || record.validation.status !== 'passed' || record.validation.validationDigest !== r.validationDigest) throw new Error('Not validated');
        return { preparedId: randomUUID(), revision: r.revision, manifestDigest: r.revision, target: 'synthetic-target', validationDigest: r.validationDigest };
      },
      startDeploy: async (r, rt) => {
        const result = { operationId: randomUUID(), status: 'queued', frozenRevision: rt.prepared.revision };
        starts.push({ context: structuredClone(r.context), prepared: structuredClone(rt.prepared), result }); operations.set(result.operationId, { result, checks: 0 });
        const gate = gates.get(id + ':start'); gate?.arrive(); await gate?.promise;
        if (ambiguousStart) throw new Error('Synthetic transport lost the start result');
        return result;
      },
      deploymentStatus: async r => {
        const operation = operations.get(r.operationId);
        const gate = gates.get(id + ':status'); gate?.arrive(); await gate?.promise;
        const status = deploymentStatuses[Math.min(operation.checks++, deploymentStatuses.length - 1)];
        return { ...operation.result, status, message: 'Synthetic status evidence only', receipt: status === 'succeeded' ? { target: 'synthetic-target', evidenceDigest: hash('synthetic completion evidence') } : null };
      },
      reconcileDeploy: r => adapter.deploymentStatus(r),
    };
    entries.set(id, { adapter, store, context, descriptor, subscribers, genesis });
  }
  const server = createServer(async (req, res) => {
    requests.push({ method: req.method, url: req.url, context: req.headers['x-builder-context'], cookie: req.headers.cookie });
    if (req.url.startsWith('/api/builder/v1')) { handler(req, res); return; }
    try {
      if (req.url === '/') {
        res.setHeader('Content-Type', 'text/html'); res.setHeader('Set-Cookie', 'synthetic=fixture; HttpOnly; SameSite=Strict; Path=/');
        const nonce = randomBytes(32).toString('base64');
        if (strictParentCsp) res.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${nonce}' 'strict-dynamic'; script-src-attr 'none'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-src 'self'; img-src data:; object-src 'none'; base-uri 'none'; form-action 'none'`);
        res.end(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Synthetic editor fixture</title><link rel="stylesheet" href="/shell.css"><script nonce="${nonce}" type="importmap">{"imports":{"@noble/hashes/sha256":"/noble/sha256.js","@noble/hashes/utils":"/noble/utils.js","@noble/hashes/crypto":"/noble/crypto.js"}}</script><main id="app"></main><script nonce="${nonce}" type="module">import { mountBuilder } from '/shell.mjs'; window.mountBuilder = mountBuilder; window.previewEvents = new WeakMap(); addEventListener('message', event => { const frame = document.querySelector('iframe'); if (frame && event.origin === 'null' && event.source === frame.contentWindow) { const messages = previewEvents.get(frame) || []; messages.push(event.data); previewEvents.set(frame, messages); } }); window.builder = mountBuilder(document.querySelector('#app'), { reconnectMs: 50, statusIntervalMs: 50, ...${JSON.stringify({ ...shellOptions, ...(strictParentCsp ? { previewScriptNonce: nonce } : {}) })} }); window.mounted = builder.ready;</script>`); return;
      }
      let target;
      if (['/shell.mjs', '/shell.css', '/preview.mjs', '/contracts.mjs'].includes(req.url)) target = new URL('../src' + req.url, import.meta.url);
      if (/^\/noble\/[a-zA-Z0-9_-]+\.js$/.test(req.url)) target = new URL('../node_modules/@noble/hashes/esm/' + req.url.slice(7), import.meta.url);
      if (!target) { res.writeHead(404).end(); return; }
      res.setHeader('Content-Type', req.url.endsWith('.css') ? 'text/css' : 'text/javascript'); res.end(await readFile(target));
    } catch { res.writeHead(404).end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  handler = createBuilderHost({ origin, authenticate: req => authenticated && req.headers.cookie?.includes('synthetic=fixture') ? { id: 'synthetic', sessionId: session } : null, projects: entries, streamCheckMs: 25 });
  return { origin, entries, starts, requests,
    hold(id, route = 'preview') {
      let release, arrive;
      const promise = new Promise(resolve => { release = resolve; });
      const entered = new Promise(resolve => { arrive = resolve; });
      gates.set(id + ':' + route, { promise, release, arrive });
      const finish = () => { gates.delete(id + ':' + route); release(); };
      finish.entered = entered; return finish;
    },
    setAuth(value) { authenticated = value; }, rotate() { session = randomUUID(); },
    async close() { for (const gate of gates.values()) gate.release?.(); handler.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); },
  };
}
