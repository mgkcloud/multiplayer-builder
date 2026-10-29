import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  CONTRACT_VERSION, BOUNDS, CAPABILITIES, EVENT_TYPES, ADAPTER_METHODS, VALUE_TYPES,
  METHOD_CAPABILITIES, ContractError, validateDescriptor, validateDescribeResult,
  validateRequestContext, assertAuthorizedContext, validateAdapter,
  validateAdapterRequest, validateAdapterResult, validateValue,
  validateEvent, validateEventProgress, validatePreviewMessage, validatePreviewEvent,
} from '../src/contracts.mjs';

test('real browser imports and executes contracts without Node shims', {
  skip: !process.env.CONTRACT_BROWSER_MODULE && !process.env.CONTRACT_BROWSER_BINARY,
  timeout: 30000,
}, async t => {
  assert.ok(process.env.CONTRACT_BROWSER_MODULE, 'set CONTRACT_BROWSER_MODULE to a Playwright ESM module URL');
  assert.ok(process.env.CONTRACT_BROWSER_BINARY, 'set CONTRACT_BROWSER_BINARY to a Chromium executable');
  const { chromium } = await import(process.env.CONTRACT_BROWSER_MODULE);
  const { createServer } = await import('node:http');
  const { readFile } = await import('node:fs/promises');
  const files = new Map([['/contracts.mjs', new URL('../src/contracts.mjs', import.meta.url)]]);
  const server = createServer(async (req, res) => {
    try {
      if (req.url === '/') {
        res.setHeader('Content-Type', 'text/html');
        res.end('<script type="importmap">{"imports":{"@noble/hashes/sha256":"/noble/sha256.js","@noble/hashes/utils":"/noble/utils.js","@noble/hashes/crypto":"/noble/crypto.js"}}</script>');
        return;
      }
      let target = files.get(req.url);
      if (/^\/noble\/[a-zA-Z0-9_-]+\.js$/.test(req.url)) target = new URL(`../node_modules/@noble/hashes/esm/${req.url.slice(7)}`, import.meta.url);
      if (!target) { res.writeHead(404).end(); return; }
      const content = await readFile(target);
      res.setHeader('Content-Type', 'text/javascript'); res.end(content);
    } catch { res.writeHead(404).end(); }
  });
  let browser;
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    browser = await chromium.launch({ executablePath: process.env.CONTRACT_BROWSER_BINARY, headless: true, args: ['--no-sandbox'] });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    const receipt = await page.evaluate(async fixtures => {
      const c = await import('/contracts.mjs');
      let checks = 0;
      const ok = value => { if (!value) throw new Error('browser assertion failed'); checks++; };
      const reject = fn => { let caught; try { fn(); } catch (e) { caught = e; } ok(caught instanceof c.ContractError); };
      ok(typeof Buffer === 'undefined' && typeof process === 'undefined' && typeof require === 'undefined');
      ok(c.validateDescriptor(fixtures.project) === fixtures.project);
      ok(c.validateRequestContext(fixtures.context) === fixtures.context);
      ok(c.assertAuthorizedContext(fixtures.context, fixtures.project, 'source') === fixtures.context);
      reject(() => c.assertAuthorizedContext({ ...fixtures.context, projectId: 'other-project' }, fixtures.project, 'source'));
      for (const source of fixtures.sources) {
        ok(c.validateValue('sourceFile', source) === source);
        reject(() => c.validateValue('sourceFile', { ...source, bytes: source.bytes + 1 }));
        reject(() => c.validateValue('sourceFile', { ...source, sha256: fixtures.wrongHash }));
      }
      ok(c.validateAdapterResult('readSource', fixtures.sourceResult, fixtures.sourceRequest, fixtures.project) === fixtures.sourceResult);
      ok(c.validateEvent(fixtures.event, fixtures.context, fixtures.project) === fixtures.event);
      reject(() => c.validateEvent({ ...fixtures.event, sequence: -1 }, fixtures.context, fixtures.project));
      ok(c.validateValue('preview', fixtures.preview) === fixtures.preview);
      ok(c.validatePreviewMessage(fixtures.message, fixtures.binding) === fixtures.message);
      ok(c.validatePreviewEvent({ source: window, origin: 'null', data: fixtures.message }, window, fixtures.binding) === fixtures.message);
      reject(() => c.validatePreviewEvent({ source: window, origin: location.origin, data: fixtures.message }, window, fixtures.binding));
      reject(() => c.validatePreviewMessage({ ...fixtures.message, nonce: 'b'.repeat(64) }, fixtures.binding));
      ok(c.BOUNDS.sourceFileBytes === null);
      return { checks, buffer: typeof Buffer, process: typeof process, require: typeof require };
    }, { project: project(), context: context(), sources: ['', 'abc', '🌱é', '中文\u0000e\u0301', 'a'.repeat(65), 'x'.repeat(400001)].map(content => file(content)), wrongHash: otherRev,
      sourceRequest: requests().readSource, sourceResult: results().readSource,
      event: event(), preview: preview(), message: message(), binding: binding() });
    assert.equal(receipt.checks, 32);
    t.diagnostic(JSON.stringify({ browser: browser.version(), ...receipt }));
  } finally {
    try { if (browser) await browser.close(); }
    finally { await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
  }
});

const hash = text => `sha256:${createHash('sha256').update(text).digest('hex')}`;
const rev = hash('synthetic revision');
const otherRev = hash('synthetic other revision');
const requestId = '00000000-0000-4000-8000-000000000001';
const otherId = '00000000-0000-4000-8000-000000000002';
const adapterVersion = { version: '1.0.0', artifactHash: hash('synthetic adapter') };
const context = () => ({ projectId: 'sample-project', workspaceId: 'canvas', adapterVersion: structuredClone(adapterVersion), baseRevision: rev, requestId });
const project = () => ({ id: 'sample-project', label: 'Synthetic project', adapterVersion: structuredClone(adapterVersion),
  workspaces: [{ id: 'canvas', label: 'Canvas' }, { id: 'notes', label: 'Notes' }],
  capabilities: [{ workspaceId: 'canvas', capabilities: [...CAPABILITIES] }, { workspaceId: 'notes', capabilities: ['source'] }],
  permissions: [{ workspaceId: 'canvas', capabilities: [...CAPABILITIES] }, { workspaceId: 'notes', capabilities: [] }],
  currentRevision: rev, deploymentStatus: 'unknown',
});
const invalid = fn => assert.throws(fn, ContractError);
const file = (content = 'synthetic content', path = 'src/example.txt') => ({ path, content, bytes: Buffer.byteLength(content), sha256: hash(content) });
const validation = () => ({ candidateDigest: hash('candidate'), validationDigest: hash('checks'), checks: [{ name: 'syntax', status: 'passed', message: '' }], adapterVersion: structuredClone(adapterVersion), status: 'passed' });
const candidate = () => ({ projectId: 'sample-project', workspaceId: 'canvas', baseRevision: rev, adapterVersion: structuredClone(adapterVersion), candidateDigest: hash('candidate'), operations: [{ type: 'write', path: 'src/example.txt', content: 'synthetic content' }] });
const task = () => ({ taskId: otherId, requestId, baseRevision: rev, status: 'running', message: '' });
const deployment = () => ({ operationId: otherId, frozenRevision: rev, status: 'unknown', message: '', receipt: null });
const manifest = () => ({ projectId: 'sample-project', workspaceId: 'canvas', revision: rev, parentRevision: null, adapterVersion: structuredClone(adapterVersion), files: [{ path: 'src/example.txt', bytes: 17, sha256: hash('synthetic content') }] });
const cursor = () => ({ epoch: requestId, sequence: 0 });
const prepared = () => ({ preparedId: otherId, revision: rev, manifestDigest: rev, target: 'test-target', validationDigest: hash('checks') });
const answer = () => ({ text: 'Synthetic answer.', provenance: [{ projectId: 'sample-project', workspaceId: 'canvas', revision: rev, path: 'src/example.txt', sha256: hash('synthetic content') }] });
const monitor = () => ({ rows: [{ id: 'example-job', status: 'unknown', summary: 'Synthetic summary' }], truncated: false });
const preview = () => ({ revision: rev, html: '<p>Synthetic preview</p>', csp: "default-src 'none'", manifestDigest: rev });
const snapshot = () => ({ ...cursor(), revision: rev, taskSummaries: [task()], deploymentSummary: deployment() });
const values = { adapterVersion: () => structuredClone(adapterVersion), sourceFile: file, manifest, candidate, validation, taskSummary: task, deploymentSummary: deployment, cursor, snapshot, preparedDeploy: prepared, answer, monitor, preview, commitResult: () => ({ revision: otherRev }) };
const requests = () => ({
  readSource: { context: context(), revision: rev, paths: ['src/example.txt'] },
  readDraft: { context: context(), revision: rev }, renderPreview: { context: context(), revision: rev },
  ask: { context: context(), text: 'Explain this synthetic source.' }, propose: { context: context(), text: 'Change the synthetic label.' },
  validate: { context: context(), immutableCandidate: candidate() },
  commitDraft: { context: context(), baseRevision: rev, candidateDigest: hash('candidate'), requestId },
  snapshot: { context: context() }, subscribe: { context: context(), cursor: null },
  prepareDeploy: { context: context(), revision: rev, validationDigest: hash('checks') },
  startDeploy: { context: context(), preparedId: otherId, requestId },
  deploymentStatus: { context: context(), operationId: otherId }, reconcileDeploy: { context: context(), operationId: otherId },
});
const results = () => ({
  readSource: { revision: rev, files: [file()] },
  readDraft: { manifest: manifest(), validation: validation(), headRevision: otherRev },
  renderPreview: preview(), ask: answer(), propose: { taskId: otherId }, validate: validation(),
  commitDraft: { revision: otherRev }, snapshot: snapshot(), subscribe: () => {},
  prepareDeploy: prepared(), startDeploy: { operationId: otherId, status: 'queued', frozenRevision: rev },
  deploymentStatus: deployment(), reconcileDeploy: deployment(),
});
const event = (type = 'task.updated') => ({ version: 1, projectId: 'sample-project', workspaceId: 'canvas', epoch: requestId, sequence: 1, revision: rev, type,
  payload: ({ 'task.updated': task, 'deploy.updated': deployment, 'monitor.updated': monitor, 'draft.committed': () => ({ baseRevision: rev, requestId }), 'permissions.changed': () => ({ capabilities: ['source'] }) })[type](),
});
const binding = () => ({ projectId: 'sample-project', workspaceId: 'canvas', revision: rev, nonce: 'a'.repeat(64), frameInstance: requestId });
const message = (type = 'preview.ready') => ({ version: 1, ...binding(), type, payload: type === 'preview.resize' ? { height: 400 } : type === 'preview.error' ? { message: 'Synthetic failure' } : {} });

for (const content of ['', 'abc', '🌱é', '中文\u0000e\u0301', 'a'.repeat(65)]) test(`independent SHA-256/UTF-8 oracle ${JSON.stringify(content)}`, () => {
  const source = file(content);
  assert.equal(validateValue('sourceFile', source), source);
  invalid(() => validateValue('sourceFile', { ...source, bytes: source.bytes + 1 }));
  invalid(() => validateValue('sourceFile', { ...source, sha256: hash(`${content}!`) }));
});

test('constants declare v1 and explicitly retire the per-file source cap', () => {
  assert.equal(CONTRACT_VERSION, 1); assert.equal(BOUNDS.sourceFileBytes, null);
  assert.equal(BOUNDS.sourceBatchBytes, 400000); assert.ok(Object.isFrozen(BOUNDS));
  assert.deepEqual(Object.keys(values).sort(), [...VALUE_TYPES].sort());
  assert.deepEqual(Object.keys(requests()).sort(), ADAPTER_METHODS.filter(x => x !== 'describe').sort());
});
test('descriptors and describe results carry explicit per-workspace grants', () => {
  const p = project(); assert.equal(validateDescriptor(p), p); assert.deepEqual(validateDescribeResult([p]), [p]);
  invalid(() => validateDescribeResult([p, p])); invalid(() => validateDescribeResult({ projects: [p] }));
});
for (const key of Object.keys(project())) test(`descriptor rejects missing ${key}`, () => {
  const p = project(); delete p[key]; invalid(() => validateDescriptor(p));
});
for (const mutate of [
  p => p.capabilities.push(p.capabilities[0]), p => p.permissions.pop(),
  p => p.permissions[1].capabilities.push('deploy'), p => p.capabilities[0].capabilities.push('shell'),
  p => p.workspaces.push(p.workspaces[0]), p => p.workspaces[0].root = '/synthetic',
  p => p.permissions[1].workspaceId = 'elsewhere', p => p.permissions[0].capabilities.push('source'),
  p => p.deploymentStatus = 'success', p => p.label = 42, p => p.rootBinding = 'private',
]) test(`descriptor rejects invalid grant/schema case ${String(mutate)}`, () => {
  const p = project(); mutate(p); invalid(() => validateDescriptor(p));
});
test('request context validates shape separately from trusted authorization', () => {
  const c = context(); assert.equal(validateRequestContext(c), c);
  assert.equal(assertAuthorizedContext(c, project(), 'source'), c);
  invalid(() => assertAuthorizedContext(c, project()));
});
for (const key of Object.keys(context())) test(`request context rejects missing ${key}`, () => {
  const c = context(); delete c[key]; invalid(() => validateRequestContext(c));
});
for (const key of ['principalId', 'permissions', 'rootBinding', 'providerBinding', 'token', 'secret', 'extra']) test(`untrusted payload rejects ${key} at every declared boundary`, () => {
  invalid(() => validateRequestContext({ ...context(), [key]: 'synthetic' }));
  invalid(() => validateDescriptor({ ...project(), [key]: 'synthetic' }));
  invalid(() => validateAdapterRequest('ask', { ...requests().ask, [key]: 'synthetic' }, project()));
  const e = event(); e.payload[key] = 'synthetic'; invalid(() => validateEvent(e, context(), project()));
  const m = message(); m.payload[key] = 'synthetic'; invalid(() => validatePreviewMessage(m, binding()));
  invalid(() => validatePreviewMessage({ ...message(), [key]: 'synthetic' }, binding()));
});
for (const [key, value] of [
  ['projectId', '../project'], ['projectId', 'Sample'], ['projectId', 'a'.repeat(65)], ['workspaceId', ''],
  ['baseRevision', 'latest'], ['baseRevision', 'sha256:' + 'A'.repeat(64)],
  ['requestId', 'not-a-uuid'], ['requestId', '00000000-0000-0000-0000-000000000000'],
  ['adapterVersion', { version: '1.0', artifactHash: rev }],
  ['adapterVersion', { version: '01.0.0', artifactHash: rev }],
  ['adapterVersion', { version: '1.0.0', artifactHash: 'unpinned' }],
]) test(`malformed context ${key}: ${JSON.stringify(value)}`, () => {
  invalid(() => validateRequestContext({ ...context(), [key]: value }));
});
for (const [key, value] of [['projectId', 'other-project'], ['workspaceId', 'other-workspace'], ['workspaceId', 'notes'], ['adapterVersion', { version: '2.0.0', artifactHash: rev }]]) test(`scope authorization rejects ${key} mismatch ${JSON.stringify(value)}`, () => {
  const c = { ...context(), [key]: value }; invalid(() => assertAuthorizedContext(c, project(), 'source'));
});
test('capabilities never leak across projects or workspaces', () => {
  const p = project(); p.permissions[0].capabilities = ['source'];
  invalid(() => assertAuthorizedContext(context(), p, 'deploy'));
  invalid(() => assertAuthorizedContext({ ...context(), projectId: 'other-project' }, p, 'source'));
  invalid(() => assertAuthorizedContext({ ...context(), workspaceId: 'notes' }, p, 'source'));
  p.permissions[1].capabilities = ['source'];
  assertAuthorizedContext({ ...context(), workspaceId: 'notes' }, p, 'source');
});
for (const [name, make] of Object.entries(values)) test(`value ${name}: positive, missing, unknown and wrong type schemas`, () => {
  const v = make(); assert.equal(validateValue(name, v), v);
  invalid(() => validateValue(name, { ...v, extra: true }));
  const missing = structuredClone(v); delete missing[Object.keys(missing)[0]]; invalid(() => validateValue(name, missing));
  invalid(() => validateValue(name, 'wrong-type'));
});
test('unknown dispatch names fail closed rather than calling inherited methods', () => {
  for (const name of ['toString', '__proto__', 'unknown']) {
    invalid(() => validateValue(name, {})); invalid(() => validateAdapterRequest(name, {}, project()));
  }
});
for (const method of ADAPTER_METHODS.filter(x => x !== 'describe')) test(`adapter ${method}: positive request/result and scoped denial`, () => {
  const req = requests()[method], result = results()[method];
  assert.equal(validateAdapterRequest(method, req, project()), req);
  assert.equal(validateAdapterResult(method, result, req, project()), result);
  invalid(() => validateAdapterRequest(method, { ...req, extra: true }, project()));
  const missing = { ...req }; delete missing.context; invalid(() => validateAdapterRequest(method, missing, project()));
  const p = project(); p.permissions[0].capabilities = p.permissions[0].capabilities.filter(x => x !== METHOD_CAPABILITIES[method]);
  invalid(() => validateAdapterRequest(method, req, p));
});
test('capability honesty requires all advertised adapter method functions', () => {
  const adapter = Object.fromEntries(ADAPTER_METHODS.map(m => [m, () => {}]));
  assert.equal(validateAdapter(adapter, [project()]), adapter);
  for (const method of ADAPTER_METHODS) { const incomplete = { ...adapter }; delete incomplete[method]; invalid(() => validateAdapter(incomplete, [project()])); }
  invalid(() => validateAdapter({ ...adapter, shell: () => {} }, [project()]));
  invalid(() => validateAdapter({ ...adapter, ask: true }, [project()]));
  const p = project(); for (const row of [...p.capabilities, ...p.permissions]) row.capabilities = [];
  validateAdapter({ describe() {} }, [p]);
  p.capabilities[0].capabilities = ['monitor']; invalid(() => validateAdapter({ describe() {} }, [p]));
});
test('source has no fixed per-file cap, while reads retain 400000-byte batch bound', () => {
  const large = file('x'.repeat(250001)); validateValue('sourceFile', large);
  const req = requests().readSource;
  validateAdapterResult('readSource', { revision: rev, files: [large] }, req, project());
  const huge = file('x'.repeat(400001)); validateValue('sourceFile', huge);
  invalid(() => validateAdapterResult('readSource', { revision: rev, files: [huge] }, req, project()));
  const exact = file('x'.repeat(400000)); validateAdapterResult('readSource', { revision: rev, files: [exact] }, req, project());
});
test('source uses UTF-8 bytes and cryptographic content hashes', () => {
  validateValue('sourceFile', file('🌱é'));
  invalid(() => validateValue('sourceFile', { ...file('🌱é'), bytes: 3 }));
  invalid(() => validateValue('sourceFile', { ...file(), sha256: otherRev }));
  invalid(() => validateValue('sourceFile', file('\ud800')));
});
for (const badPath of ['/absolute', '../traversal', 'a/../b', 'a//b', 'a/./b', 'a\\b', 'a%2fb', 'a?b', 'a#b', 'a\nfile', 'a/ b', 'C:/file', '']) test(`source path rejects ${JSON.stringify(badPath)}`, () => {
  invalid(() => validateValue('sourceFile', file('synthetic', badPath)));
});
test('source results must return exactly the requested unique paths at the pinned revision', () => {
  const req = requests().readSource;
  for (const result of [{ revision: otherRev, files: [file()] }, { revision: rev, files: [] }, { revision: rev, files: [file('x', 'unrequested.txt')] }, { revision: rev, files: [file(), file()] }]) invalid(() => validateAdapterResult('readSource', result, req, project()));
  invalid(() => validateAdapterRequest('readSource', { ...req, paths: Array(6).fill('file.txt') }, project()));
  invalid(() => validateAdapterRequest('readSource', { ...req, paths: ['file.txt', 'file.txt'] }, project()));
});
test('candidate scopes, operation counts and serialized batch bounds are strict', () => {
  const c = candidate(); c.operations[0].content = 'x'.repeat(250001); validateValue('candidate', c);
  c.operations[0].content = 'x'.repeat(400000); invalid(() => validateValue('candidate', c));
  c.operations = Array.from({ length: 6 }, (_, i) => ({ type: 'delete', path: `example-${i}.txt` })); invalid(() => validateValue('candidate', c));
  c.operations = [{ type: 'delete', path: 'example.txt' }]; validateValue('candidate', c);
  c.operations.push(c.operations[0]); invalid(() => validateValue('candidate', c));
  for (const change of [{ projectId: 'other-project' }, { workspaceId: 'notes' }, { baseRevision: otherRev }, { adapterVersion: { version: '2.0.0', artifactHash: rev } }]) invalid(() => validateAdapterRequest('validate', { context: context(), immutableCandidate: { ...candidate(), ...change } }, project()));
  invalid(() => validateValue('candidate', { ...candidate(), operations: [{ type: 'execute', path: 'src/example.txt', command: 'synthetic' }] }));
});
test('prompt lengths count Unicode code points and reject empty/missing data', () => {
  const req = requests().ask; validateAdapterRequest('ask', { ...req, text: '🌱'.repeat(6000) }, project());
  for (const text of ['x'.repeat(6001), '', '   ', 42, null]) invalid(() => validateAdapterRequest('ask', { ...req, text }, project()));
});
test('validation cannot report passed without positive evidence checks', () => {
  invalid(() => validateValue('validation', { ...validation(), checks: [] }));
  invalid(() => validateValue('validation', { ...validation(), checks: [{ name: 'syntax', status: 'unknown', message: '' }] }));
  invalid(() => validateValue('validation', { ...validation(), checks: [...validation().checks, ...validation().checks] }));
  validateValue('validation', { ...validation(), status: 'unknown', checks: [] });
});
test('duplicate argument IDs and revisions must agree with context', () => {
  invalid(() => validateAdapterRequest('commitDraft', { ...requests().commitDraft, requestId: otherId }, project()));
  invalid(() => validateAdapterRequest('commitDraft', { ...requests().commitDraft, baseRevision: otherRev }, project()));
  invalid(() => validateAdapterRequest('startDeploy', { ...requests().startDeploy, requestId: otherId }, project()));
});
test('results bind source provenance, manifests, validation, and deployment identities', () => {
  const result = results(), req = requests();
  result.ask.provenance[0].projectId = 'other-project'; invalid(() => validateAdapterResult('ask', result.ask, req.ask, project()));
  const a = answer(); a.provenance[0].revision = otherRev; invalid(() => validateAdapterResult('ask', a, req.ask, project()));
  result.readDraft.manifest.workspaceId = 'notes'; invalid(() => validateAdapterResult('readDraft', result.readDraft, req.readDraft, project()));
  result.validate.candidateDigest = otherRev; invalid(() => validateAdapterResult('validate', result.validate, req.validate, project()));
  result.prepareDeploy.validationDigest = otherRev; invalid(() => validateAdapterResult('prepareDeploy', result.prepareDeploy, req.prepareDeploy, project()));
  result.deploymentStatus.operationId = requestId; invalid(() => validateAdapterResult('deploymentStatus', result.deploymentStatus, req.deploymentStatus, project()));
  invalid(() => validateAdapterResult('subscribe', {}, req.subscribe, project()));
});
test('revision conflict is explicit; deployment unknown is never success', () => {
  validateAdapterResult('commitDraft', { code: 'REVISION_CONFLICT', baseRevision: rev, currentRevision: otherRev }, requests().commitDraft, project());
  invalid(() => validateAdapterResult('commitDraft', { code: 'REVISION_CONFLICT', baseRevision: otherRev, currentRevision: rev }, requests().commitDraft, project()));
  invalid(() => validateValue('deploymentSummary', { ...deployment(), status: 'succeeded' }));
  validateValue('deploymentSummary', { ...deployment(), status: 'succeeded', receipt: { target: 'test-target', evidenceDigest: hash('synthetic evidence') } });
  invalid(() => validateValue('deploymentSummary', { ...deployment(), receipt: { target: 'test-target', evidenceDigest: rev } }));
});
for (const type of EVENT_TYPES) test(`event ${type}: strict versioned payload and scope`, () => {
  const e = event(type); assert.equal(validateEvent(e, context(), project()), e);
  invalid(() => validateEvent({ ...e, version: 2 }, context(), project()));
  invalid(() => validateEvent({ ...e, projectId: 'other-project' }, context(), project()));
  invalid(() => validateEvent({ ...e, workspaceId: 'notes' }, context(), project()));
  const missing = { ...e }; delete missing.revision; invalid(() => validateEvent(missing, context(), project()));
  invalid(() => validateEvent({ ...e, payload: { ...e.payload, extra: true } }, context(), project()));
});
for (const value of [-1, 0.5, '1', NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, null]) test(`event ordering rejects sequence ${String(value)}`, () => {
  invalid(() => validateEvent({ ...event(), sequence: value }, context(), project()));
});
test('epoch and event type are pinned; monitor requires explicit permission', () => {
  invalid(() => validateEvent({ ...event(), epoch: 1 }, context(), project()));
  invalid(() => validateEvent({ ...event(), type: 'execute' }, context(), project()));
  const p = project(); p.permissions[0].capabilities = ['subscribe']; invalid(() => validateEvent(event('monitor.updated'), context(), p));
  p.capabilities[0].capabilities = ['subscribe']; invalid(() => validateEvent(event('permissions.changed'), context(), p));
});
test('cursor gaps, replays and epoch changes demand authorized bootstrap', () => {
  validateEventProgress(cursor(), { epoch: requestId, sequence: 1 });
  for (const next of [{ epoch: otherId, sequence: 1 }, { epoch: requestId, sequence: 0 }, { epoch: requestId, sequence: 2 }]) invalid(() => validateEventProgress(cursor(), next));
});
test('event UTF-8 byte cap and monitor row/truncation indicators are enforced', () => {
  const e = event('monitor.updated'); e.payload.rows = Array.from({ length: 80 }, (_, i) => ({ id: `job-${i}`, status: 'ok', summary: '🌱'.repeat(200) }));
  invalid(() => validateEvent(e, context(), project()));
  const m = monitor(); m.rows = Array(201).fill(m.rows[0]); invalid(() => validateValue('monitor', m));
  const missing = monitor(); delete missing.truncated; invalid(() => validateValue('monitor', missing));
  invalid(() => validateValue('taskSummary', { ...task(), message: 'x'.repeat(301) }));
});
for (const type of ['preview.ready', 'preview.error', 'preview.resize']) test(`preview ${type}: exact nonce/frame/scope binding`, () => {
  const m = message(type); assert.equal(validatePreviewMessage(m, binding()), m);
  for (const [key, value] of [['projectId', 'other-project'], ['workspaceId', 'notes'], ['revision', otherRev], ['nonce', 'b'.repeat(64)], ['frameInstance', otherId]]) invalid(() => validatePreviewMessage({ ...m, [key]: value }, binding()));
});
for (const type of ['deploy', 'save', 'createTask', 'fetch', 'navigate']) test(`preview cannot request ${type}`, () => {
  invalid(() => validatePreviewMessage({ ...message(), type }, binding()));
});
test('preview event requires exact bound window and opaque origin, not only message schema', () => {
  const window = {}; const e = { source: window, origin: 'null', data: message() };
  assert.equal(validatePreviewEvent(e, window, binding()), e.data);
  invalid(() => validatePreviewEvent({ ...e, source: {} }, window, binding()));
  invalid(() => validatePreviewEvent({ ...e, origin: 'https://synthetic.invalid' }, window, binding()));
  invalid(() => validatePreviewEvent(e, null, binding()));
  invalid(() => validatePreviewMessage({ ...message(), nonce: 'short' }, binding()));
  invalid(() => validatePreviewMessage(message(), { ...binding(), providerBinding: 'synthetic' }));
  invalid(() => validatePreviewMessage({ ...message('preview.resize'), payload: { height: 0.5 } }, binding()));
  invalid(() => validatePreviewMessage({ ...message('preview.resize'), payload: { height: 100001 } }, binding()));
});
test('strict data objects reject prototypes, symbols, getters, sparse arrays and hidden fields', () => {
  const inherited = Object.create(context()); invalid(() => validateRequestContext(inherited));
  const symbol = context(); symbol[Symbol('secret')] = 1; invalid(() => validateRequestContext(symbol));
  let invoked = false;
  const getter = context(); Object.defineProperty(getter, 'projectId', { enumerable: true, get() { invoked = true; return 'sample-project'; } });
  invalid(() => validateRequestContext(getter)); assert.equal(invoked, false);
  const hidden = context(); Object.defineProperty(hidden, 'secret', { value: 1 }); invalid(() => validateRequestContext(hidden));
  const p = project(); p.capabilities[0].capabilities = new Array(1); invalid(() => validateDescriptor(p));
  const cycle = candidate(); cycle.operations[0].content = cycle; invalid(() => validateValue('candidate', cycle));
  const nullPrototype = Object.assign(Object.create(null), context()); validateRequestContext(nullPrototype);
});
