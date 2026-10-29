import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createReducerState, reduceEventState, bindingToken, isCurrentBinding } from '../src/event-reducer.mjs';

const digest = n => `sha256:${String(n).repeat(64)}`;
const adapterVersion = { version: '1.0.0', artifactHash: digest(0) };
function selected(projectId = 'synthetic-project', workspaceId = 'draft', prior = createReducerState()) {
  const context = { projectId, workspaceId, adapterVersion, baseRevision: digest(1), requestId: randomUUID() };
  const descriptor = { id: projectId, label: 'Synthetic project', adapterVersion, workspaces: [{ id: workspaceId, label: 'Synthetic workspace' }], capabilities: [{ workspaceId, capabilities: ['subscribe', 'monitor', 'saveDraft'] }], permissions: [{ workspaceId, capabilities: ['subscribe', 'monitor'] }], currentRevision: digest(1), deploymentStatus: 'idle' };
  return reduceEventState(prior, { type: 'select', context, descriptor });
}
function bootstrap(state, sequence = 0, epoch = randomUUID()) {
  return reduceEventState(state, { type: 'bootstrap', binding: bindingToken(state), snapshot: { epoch, sequence, revision: digest(1), taskSummaries: [], deploymentSummary: null } });
}
function event(state, changes = {}) {
  return { version: 1, projectId: state.trusted.context.projectId, workspaceId: state.trusted.context.workspaceId, epoch: state.remote.cursor.epoch, sequence: state.remote.cursor.sequence + 1, revision: digest(2), type: 'draft.committed', payload: { baseRevision: state.remote.revision, requestId: randomUUID() }, ...changes };
}
const send = (state, e, binding = bindingToken(state)) => reduceEventState(state, { type: 'event', binding, event: e });

test('events advance remote state without resetting local draft or focus; duplicates are no-ops', () => {
  let state = bootstrap(selected());
  state = reduceEventState(state, { type: 'local', draft: 'unsaved synthetic draft', focus: 'composer' });
  const e = event(state), next = send(state, e);
  assert.equal(next.remote.revision, digest(2));
  assert.equal(next.remote.cursor.sequence, 1);
  assert.equal(next.local, state.local);
  assert.equal(next.local.draft, 'unsaved synthetic draft');
  assert.equal(send(next, e), next);
  assert.ok(Object.isFrozen(next.remote.cursor));
});

test('sequence gaps and changed epochs require fresh bootstrap and invalidate prior stream replies', () => {
  for (const changes of [{ sequence: 2 }, { epoch: randomUUID() }]) {
    const state = bootstrap(selected()), binding = bindingToken(state);
    const invalid = send(state, event(state, changes));
    assert.equal(invalid.needsBootstrap, true); assert.equal(invalid.remote, state.remote);
    assert.equal(isCurrentBinding(invalid, binding), false);
    assert.equal(send(invalid, event(state), binding), invalid);
    assert.equal(reduceEventState(invalid, { type: 'bootstrap', binding, snapshot: { epoch: randomUUID(), sequence: 0, revision: digest(1), taskSummaries: [], deploymentSummary: null } }), invalid);
    const recovered = bootstrap(invalid, 20);
    assert.equal(recovered.needsBootstrap, false); assert.equal(recovered.remote.cursor.sequence, 20);
    assert.equal(bootstrap(recovered, 0), recovered);
  }
});

test('selection and auth lifetimes reject old event and bootstrap replies, including ABA selection', () => {
  let a = bootstrap(selected()); const oldBinding = bindingToken(a), oldEvent = event(a);
  let b = selected('other-project', 'draft', a);
  assert.equal(send(b, oldEvent, oldBinding), b);
  b = bootstrap(b);
  const aAgain = selected('synthetic-project', 'draft', b);
  assert.equal(send(aAgain, oldEvent, oldBinding), aAgain);
  assert.equal(isCurrentBinding(aAgain, oldBinding), false);
  const authRefresh = selected('synthetic-project', 'draft', aAgain);
  assert.equal(isCurrentBinding(authRefresh, bindingToken(aAgain)), false);
  const cleared = reduceEventState(authRefresh, { type: 'clear' });
  assert.equal(bindingToken(cleared), null); assert.equal(cleared.trusted, null);
  assert.equal(send(cleared, oldEvent, oldBinding), cleared);
});

test('exact project/workspace, revision chain and event shape validation fail closed', () => {
  const state = bootstrap(selected());
  for (const changes of [{ projectId: 'other-project' }, { workspaceId: 'other-workspace' }, { sequence: -1 }, { payload: { baseRevision: digest(9), requestId: randomUUID() } }, { version: 2 }, { malicious: true }]) {
    const next = send(state, event(state, changes));
    assert.equal(next.needsBootstrap, true); assert.equal(next.remote, state.remote);
  }
  const badTask = event(state, { type: 'task.updated', revision: digest(9), payload: { taskId: randomUUID(), requestId: randomUUID(), baseRevision: digest(1), status: 'running', message: '' } });
  assert.equal(send(state, badTask).reason, 'revision-gap');
});

test('task, deployment and monitor updates are copied, ordered and deduplicated', () => {
  let state = bootstrap(selected());
  const task = { taskId: randomUUID(), requestId: randomUUID(), baseRevision: digest(1), status: 'running', message: '' };
  state = send(state, event(state, { type: 'task.updated', revision: digest(1), payload: task }));
  task.message = 'later caller mutation'; assert.equal(state.remote.tasks[0].message, '');
  state = send(state, event(state, { type: 'task.updated', revision: digest(1), payload: { ...task, status: 'succeeded' } }));
  assert.equal(state.remote.tasks.length, 1); assert.equal(state.remote.tasks[0].status, 'succeeded');
  const deployment = { operationId: randomUUID(), frozenRevision: digest(1), status: 'running', message: '', receipt: null };
  state = send(state, event(state, { type: 'deploy.updated', revision: digest(1), payload: deployment }));
  assert.equal(state.remote.deployment.status, 'running');
  const monitor = { rows: [{ id: 'synthetic-check', status: 'ok', summary: 'synthetic' }], truncated: false };
  state = send(state, event(state, { type: 'monitor.updated', revision: digest(1), payload: monitor }));
  assert.deepEqual(state.remote.monitor, monitor);
});

test('permission notifications never authorize themselves or replace current trusted grants', () => {
  let state = bootstrap(selected());
  state = reduceEventState(state, { type: 'local', draft: 'keep draft', focus: 'source' });
  const next = send(state, event(state, { type: 'permissions.changed', revision: digest(1), payload: { capabilities: ['subscribe', 'saveDraft'] } }));
  assert.equal(next.trusted, state.trusted);
  assert.deepEqual(next.trusted.descriptor.permissions[0].capabilities, ['subscribe', 'monitor']);
  assert.equal(next.local, state.local); assert.equal(next.needsBootstrap, true);
  assert.equal(next.reason, 'permissions-changed');
  assert.equal(bootstrap(next), next);
});

test('trusted inputs are captured; unsupported or ungranted selections cannot subscribe', () => {
  const state = selected(); const context = structuredClone(state.trusted.context), descriptor = structuredClone(state.trusted.descriptor);
  const next = reduceEventState(state, { type: 'select', context, descriptor });
  descriptor.permissions[0].capabilities = []; context.projectId = 'other';
  assert.equal(next.trusted.context.projectId, 'synthetic-project'); assert.ok(next.trusted.descriptor.permissions[0].capabilities.includes('subscribe'));
  assert.throws(() => reduceEventState(state, { type: 'select', context: state.trusted.context, descriptor }));
});

test('reducer and shared contracts load and execute in a browser-like VM with no Node globals', () => {
  const entry = new URL('../src/event-reducer.mjs', import.meta.url).href;
  const script = `import vm from 'node:vm';import fs from 'node:fs';
const ctx=vm.createContext({TextEncoder,structuredClone});const cache=new Map();
async function load(url){if(!url.startsWith('file:'))throw Error('non-browser dependency '+url);if(cache.has(url))return cache.get(url);const mod=new vm.SourceTextModule(fs.readFileSync(new URL(url),'utf8'),{context:ctx,identifier:url,initializeImportMeta:meta=>{meta.url=url}});cache.set(url,mod);await mod.link((specifier,parent)=>load(specifier.startsWith('.')?new URL(specifier,parent.identifier).href:specifier==='@noble/hashes/crypto'?new URL('./crypto.js',import.meta.resolve('@noble/hashes/sha256')).href:import.meta.resolve(specifier)));return mod;}
const mod=await load(${JSON.stringify(entry)});await mod.evaluate();const state=mod.namespace.createReducerState();if(state.lifetime!==0||!Object.isFrozen(state))throw Error('reducer failed');console.log('browser-like execution passed');`;
  const result = spawnSync(process.execPath, ['--experimental-vm-modules', '--input-type=module', '-e', script], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr); assert.match(result.stdout, /browser-like execution passed/);
});
