import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomUUID, createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { RevisionStore, candidateDigest, canonicalJSON } from '../src/revision-store.mjs';

const hash = text => `sha256:${createHash('sha256').update(text).digest('hex')}`;
const adapterVersion = { version: '1.0.0', artifactHash: hash('synthetic-adapter') };
const scope = { projectId: 'synthetic-project', workspaceId: 'draft' };
const descriptor = (projectId = scope.projectId, workspaceId = scope.workspaceId) => ({ id: projectId, label: 'Synthetic fixture', adapterVersion, workspaces: [{ id: workspaceId, label: 'Synthetic workspace' }], capabilities: [{ workspaceId, capabilities: ['saveDraft', 'source', 'subscribe'] }], permissions: [{ workspaceId, capabilities: ['saveDraft', 'source', 'subscribe'] }], currentRevision: hash('unused'), deploymentStatus: 'idle' });
const passed = () => ({ status: 'passed', checks: [{ name: 'synthetic-check', status: 'passed', message: '' }] });
const source = (p, content) => ({ path: p, content, bytes: Buffer.byteLength(content), sha256: hash(content) });
async function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'oug-synthetic-store-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const config = { root, authorize: () => descriptor(), validate: passed, ...options };
  const store = new RevisionStore(config);
  const initial = await store.initialize({ ...scope, adapterVersion, files: [source('src/main.txt', 'synthetic seed')] });
  return { root, config, store, initial };
}
function request(revision, text = 'synthetic updated', principalId = 'synthetic-user') {
  const context = { ...scope, adapterVersion, baseRevision: revision, requestId: randomUUID() };
  const candidate = { ...scope, adapterVersion, baseRevision: revision, candidateDigest: hash('placeholder'), operations: [{ type: 'write', path: 'src/main.txt', content: text }] };
  candidate.candidateDigest = candidateDigest(candidate);
  return { principalId, context, candidate };
}
const storeURL = new URL('../src/revision-store.mjs', import.meta.url).href;
function worker(root, input, stage = null) {
  const script = `import { RevisionStore } from ${JSON.stringify(storeURL)};
const input = ${JSON.stringify(input)};
const store = new RevisionStore({root:${JSON.stringify(root)}, authorize:()=>(${JSON.stringify(descriptor())}), validate:async()=>{await new Promise(r=>setTimeout(r,80));return ${JSON.stringify(passed())}}, fault:stage=>{if(stage===${JSON.stringify(stage)}) process.kill(process.pid,'SIGKILL')}});
process.send({ready:true});process.once('message',async()=>{try{const result=await store.commit(input);process.send({result});process.disconnect()}catch(e){process.send({error:e.code||e.message});process.disconnect()}});`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  let stderr = ''; child.stderr.on('data', d => stderr += d);
  const ready = new Promise((resolve, reject) => {
    let announced = false;
    child.once('message', value => { announced = true; resolve(value); });
    child.once('error', reject);
    child.once('exit', (code, signal) => { if (!announced) reject(new Error(`Worker exited before ready: ${code}/${signal}`)); });
  });
  let message;
  child.on('message', m => { if (!m.ready) message = m; });
  const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (code, signal) => resolve({ code, signal, message, stderr })); });
  return { child, ready, done };
}

test('canonical digest ignores object insertion order, binds scope/content and ignores no caller hash', async t => {
  const { store, initial } = await fixture(t);
  const input = request(initial.revision);
  assert.equal(candidateDigest({ operations: input.candidate.operations, candidateDigest: input.candidate.candidateDigest, adapterVersion, baseRevision: initial.revision, workspaceId: scope.workspaceId, projectId: scope.projectId }), input.candidate.candidateDigest);
  assert.equal(canonicalJSON({ z: 2, a: 1 }), '{"a":1,"z":2}');
  input.candidate.operations[0].content = 'tampered';
  await assert.rejects(store.commit(input), { code: 'CANDIDATE_DIGEST_MISMATCH' });
});

test('durable commit, immutable historical source, exact manifest digest and idempotent restart', async t => {
  const { store, config, root, initial } = await fixture(t);
  const input = request(initial.revision), result = await store.commit(input);
  const restarted = new RevisionStore(config);
  assert.deepEqual(await restarted.commit(input), result);
  assert.equal((await restarted.events(input)).length, 1);
  assert.equal((await restarted.snapshot(input)).revision, result.revision);
  assert.equal((await restarted.read({ ...input, revision: initial.revision, paths: ['src/main.txt'] })).files[0].content, 'synthetic seed');
  assert.equal((await restarted.read({ ...input, revision: result.revision, paths: ['src/main.txt'] })).files[0].content, 'synthetic updated');
  const manifest = JSON.parse(fs.readFileSync(path.join(root, scope.projectId, scope.workspaceId, 'revisions', result.revision.slice(7), 'manifest.json')));
  const { revision, ...body } = manifest; assert.equal(hash(canonicalJSON(body)), revision);
  const state = JSON.parse(fs.readFileSync(path.join(root, scope.projectId, scope.workspaceId, 'state.json'))).body;
  const record = Object.values(state.requests)[0];
  const { validationDigest, ...validationBody } = record.validation;
  assert.equal(hash(canonicalJSON(validationBody)), validationDigest);
  assert.equal(record.validation.candidateDigest, input.candidate.candidateDigest);
  const details = await restarted.readRevision({ ...input, revision: result.revision });
  assert.deepEqual(details.manifest, manifest); assert.deepEqual(details.validation, record.validation); assert.equal(details.headRevision, result.revision);
  assert.equal((await restarted.readRevision({ ...input, revision: initial.revision })).validation, null);
  const mismatch = structuredClone(input); mismatch.candidate.operations[0].content = 'mismatch'; mismatch.candidate.candidateDigest = candidateDigest(mismatch.candidate);
  await assert.rejects(restarted.commit(mismatch), { code: 'IDEMPOTENCY_MISMATCH' });
});

test('validate-only cannot move head; commit revalidates rather than trusts client passed fields', async t => {
  let good = true, calls = 0;
  const { store, initial } = await fixture(t, { validate: () => { calls++; return good ? passed() : { status: 'failed', checks: [{ name: 'synthetic-check', status: 'failed', message: '' }] }; } });
  const input = request(initial.revision);
  assert.equal((await store.validate(input)).status, 'passed');
  assert.equal((await store.snapshot(input)).revision, initial.revision);
  good = false;
  await assert.rejects(store.commit({ ...input, status: 'passed', validationDigest: hash('fake') }), { code: 'VALIDATION_FAILED' });
  assert.equal(calls, 2); assert.equal((await store.events(input)).length, 0);
  good = true;
  await assert.rejects(store.commit(input), { code: 'VALIDATION_FAILED' });
  assert.equal(calls, 2);
  const mismatch = request(initial.revision, 'conflicting failed request'); mismatch.context.requestId = input.context.requestId;
  await assert.rejects(store.commit(mismatch), { code: 'IDEMPOTENCY_MISMATCH' });
  input.context.requestId = randomUUID(); const result = await store.commit(input);
  const stale = request(initial.revision, 'stale');
  assert.deepEqual(await store.commit(stale), { code: 'REVISION_CONFLICT', baseRevision: initial.revision, currentRevision: result.revision });
  assert.equal(calls, 3);
});

test('candidate captured and recursively frozen before asynchronous authorization/validation', async t => {
  let release, entered;
  const gate = new Promise(r => release = r), signal = new Promise(r => entered = r);
  const { store, initial } = await fixture(t, { validate: async args => { assert.ok(Object.isFrozen(args.candidate.operations[0])); assert.ok(Object.isFrozen(args.files)); entered(); await gate; return passed(); } });
  const input = request(initial.revision, 'captured');
  const pending = store.commit(input); await signal;
  input.candidate.operations[0].content = 'later mutation'; input.context.projectId = 'other';
  release(); const result = await pending;
  const readInput = request(initial.revision);
  assert.equal((await store.read({ ...readInput, revision: result.revision, paths: ['src/main.txt'] })).files[0].content, 'captured');
});

test('one process and two actual competing processes cannot both win a base', async t => {
  const { root, store, initial } = await fixture(t);
  const a = worker(root, request(initial.revision, 'process-a')), b = worker(root, request(initial.revision, 'process-b'));
  await Promise.all([a.ready, b.ready]); a.child.send('go'); b.child.send('go');
  const outcomes = await Promise.all([a.done, b.done]);
  for (const o of outcomes) { assert.equal(o.code, 0, o.stderr); assert.ok(o.message.result, JSON.stringify(o)); }
  assert.equal(outcomes.filter(o => o.message.result.code === 'REVISION_CONFLICT').length, 1);
  assert.equal(outcomes.filter(o => !o.message.result.code).length, 1);
  const input = request(initial.revision); assert.equal((await store.events(input)).length, 1);
  const current = (await store.snapshot(input)).revision;
  const sameProcess = await Promise.all([store.commit(request(current, 'local-a')), store.commit(request(current, 'local-b'))]);
  assert.equal(sameProcess.filter(r => r.code === 'REVISION_CONFLICT').length, 1);
});

test('two processes retrying one request share one durable result/event', async t => {
  const { root, store, initial } = await fixture(t), input = request(initial.revision);
  const a = worker(root, input), b = worker(root, input);
  await Promise.all([a.ready, b.ready]); a.child.send('go'); b.child.send('go');
  const outcomes = await Promise.all([a.done, b.done]);
  for (const o of outcomes) { assert.equal(o.code, 0, o.stderr); assert.ok(o.message.result?.revision, JSON.stringify(o)); }
  assert.deepEqual(outcomes[0].message.result, outcomes[1].message.result);
  assert.equal((await store.events(input)).length, 1);
});

for (const mode of ['once', 'repeated', 'mkdir-denied', 'lstat-denied']) {
  test(`lock handoff ${mode}: isolated filesystem regression`, t => {
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'oug-synthetic-handoff-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const script = `import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import { RevisionStore, candidateDigest } from ${JSON.stringify(storeURL)};
const root = ${JSON.stringify(root)}, scope = ${JSON.stringify(scope)}, adapterVersion = ${JSON.stringify(adapterVersion)};
const lock = path.join(root, scope.projectId, scope.workspaceId, 'lock');
const mode = ${JSON.stringify(mode)}, originalMkdir = fs.mkdirSync, originalLstat = fs.lstatSync;
let remaining = 1, attempts = 0, heartbeats = 0;
const heartbeat = setInterval(() => heartbeats++, 1);
fs.mkdirSync = (target, options) => {
  if (target === lock && (mode !== 'once' || remaining-- > 0)) {
    attempts++;
    assert.equal(fs.existsSync(lock), false);
    throw Object.assign(new Error('synthetic handoff'), { code: mode === 'mkdir-denied' ? 'EACCES' : 'EEXIST' });
  }
  return originalMkdir(target, options);
};
fs.lstatSync = (target, ...args) => {
  if (target === lock && mode === 'lstat-denied') throw Object.assign(new Error('synthetic denied inspection'), { code: 'EACCES' });
  return originalLstat(target, ...args);
};
syncBuiltinESMExports();
try {
  const store = new RevisionStore({ root, authorize: () => (${JSON.stringify(descriptor())}), validate: () => (${JSON.stringify(passed())}), lockTimeoutMs: 40 });
  const seed = { ...scope, adapterVersion, files: [${JSON.stringify(source('src/main.txt', 'synthetic seed'))}] };
  if (mode === 'once') {
    const initial = await store.initialize(seed);
    assert.equal(attempts, 1);
    remaining = 1;
    const input = ${JSON.stringify(request(hash('placeholder')))};
    input.context.baseRevision = input.candidate.baseRevision = initial.revision;
    input.candidate.candidateDigest = candidateDigest(input.candidate);
    const result = await store.commit(input);
    assert.equal(attempts, 2);
    assert.deepEqual(await store.commit(input), result);
    assert.equal((await store.events(input)).length, 1);
    assert.equal((await store.snapshot(input)).revision, result.revision);
  } else {
    const start = Date.now();
    await assert.rejects(store.initialize(seed), { code: mode === 'repeated' ? 'STORE_BUSY' : 'EACCES' });
    if (mode === 'repeated') {
      assert.ok(Date.now() - start >= 40);
      assert.ok(attempts >= 2 && attempts <= 10, 'bounded polling, not tight spinning');
      assert.ok(heartbeats > 0, 'retry must yield to timers');
    } else assert.equal(attempts, 1);
    assert.equal(fs.existsSync(lock), false);
    assert.equal(fs.existsSync(path.join(path.dirname(lock), 'state.json')), false);
  }
} finally {
  clearInterval(heartbeat);
  fs.mkdirSync = originalMkdir; fs.lstatSync = originalLstat; syncBuiltinESMExports();
}`;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL' });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 0, result.stderr);
  });
}

test('repeated real two-process idempotency contention preserves one result/event per round', { timeout: 180000 }, async t => {
  const { root, store, initial } = await fixture(t);
  let revision = initial.revision;
  for (let round = 0; round < 6; round++) {
    const input = request(revision, `contention-round-${round}`);
    const workers = [worker(root, input), worker(root, input)];
    // Process startup under parallel browser load is not the store's lock deadline.
    let timer = setTimeout(() => workers.forEach(w => w.child.kill('SIGKILL')), 15000);
    try {
      await Promise.all(workers.map(w => w.ready));
      clearTimeout(timer);
      timer = setTimeout(() => workers.forEach(w => w.child.kill('SIGKILL')), 10000);
      workers.forEach(w => w.child.send('go'));
      const outcomes = await Promise.all(workers.map(w => w.done));
      for (const o of outcomes) { assert.equal(o.code, 0, JSON.stringify(o)); assert.ok(o.message?.result?.revision, JSON.stringify(o)); }
      assert.deepEqual(outcomes[0].message.result, outcomes[1].message.result);
      revision = outcomes[0].message.result.revision;
      const snapshot = await store.snapshot(input), events = await store.events(input);
      assert.equal(snapshot.sequence, round + 1);
      assert.equal(snapshot.revision, revision);
      assert.equal(events.length, round + 1);
      assert.equal(events.at(-1).payload.requestId, input.context.requestId);
      assert.deepEqual(await store.commit(input), { revision });
    } finally {
      clearTimeout(timer);
      workers.forEach(w => { if (w.child.exitCode === null) w.child.kill('SIGKILL'); });
    }
  }
});

test('unsafe lock entries still fail closed without removing them', async t => {
  const { store, root, initial } = await fixture(t);
  const lock = path.join(root, scope.projectId, scope.workspaceId, 'lock');
  for (const kind of ['file', 'symlink', 'permissions']) {
    if (kind === 'file') fs.writeFileSync(lock, 'synthetic sentinel');
    else if (kind === 'symlink') fs.symlinkSync(root, lock);
    else fs.mkdirSync(lock, { mode: 0o755 });
    await assert.rejects(store.commit(request(initial.revision)), { code: 'UNSAFE_DIRECTORY' });
    assert.ok(fs.lstatSync(lock));
    if (kind === 'permissions') fs.rmdirSync(lock); else fs.unlinkSync(lock);
  }
});

for (const stage of ['locked', 'afterAdmissionDurable', 'revisionDurable', 'beforeStateRename', 'afterStateDurable']) {
  test(`SIGKILL crash window ${stage}: explicit dead-owner recovery and exact retry`, async t => {
    const { root, store, config, initial } = await fixture(t);
    const input = request(initial.revision, `crash-${stage}`), child = worker(root, input, stage);
    await child.ready; child.child.send('go'); const ended = await child.done;
    assert.equal(ended.signal, 'SIGKILL', ended.stderr);
    const restart = new RevisionStore({ ...config, lockTimeoutMs: 20 });
    await assert.rejects(restart.commit(input), { code: 'STORE_BUSY' });
    const before = await restart.snapshot(input);
    assert.equal(before.revision === initial.revision, stage !== 'afterStateDurable');
    if (stage === 'revisionDurable' || stage === 'beforeStateRename') {
      const revisions = fs.readdirSync(path.join(root, scope.projectId, scope.workspaceId, 'revisions')).filter(name => /^[0-9a-f]{64}$/.test(name) && name !== initial.revision.slice(7));
      assert.equal(revisions.length, 1);
      const orphan = `sha256:${revisions[0]}`;
      await assert.rejects(restart.readRevision({ ...input, revision: orphan }), { code: 'REVISION_NOT_COMMITTED' });
      await assert.rejects(restart.read({ ...input, revision: orphan, paths: ['src/main.txt'] }), { code: 'REVISION_NOT_COMMITTED' });
    }
    restart.recoverLock(scope);
    const committed = await restart.commit(input);
    assert.deepEqual(await store.commit(input), committed);
    assert.equal((await restart.events(input)).length, 1);
    assert.equal((await restart.snapshot(input)).revision, committed.revision);
  });
}

test('permissions rechecked after validation and cannot come from client fields', async t => {
  let allowed = true;
  const { store, initial } = await fixture(t, { authorize: () => { const d = descriptor(); if (!allowed) d.permissions[0].capabilities = []; return d; }, validate: () => { allowed = false; return passed(); } });
  const input = request(initial.revision);
  await assert.rejects(store.commit({ ...input, permissions: ['saveDraft'] }), { code: 'INVALID_CONTRACT' });
  allowed = true; assert.equal((await store.snapshot(input)).revision, initial.revision);
});

test('scope, traversal, symlink isolation, unrecognized state and unsafe root fail closed', async t => {
  const { store, root, initial, config } = await fixture(t);
  await assert.rejects(store.commit({ ...request(initial.revision), context: { ...request(initial.revision).context, projectId: '../escape' } }));
  const input = request(initial.revision); input.candidate.operations[0].path = '../escape';
  await assert.rejects(store.commit(input));
  fs.symlinkSync(root, path.join(root, 'symlink-project'));
  await assert.rejects(store.initialize({ projectId: 'symlink-project', workspaceId: 'draft', adapterVersion }), { code: 'UNSAFE_DIRECTORY' });
  const danglingDir = path.join(root, 'synthetic-dangling', 'draft');
  fs.mkdirSync(path.dirname(danglingDir), { mode: 0o700 }); fs.mkdirSync(danglingDir, { mode: 0o700 });
  fs.symlinkSync('missing-synthetic-target', path.join(danglingDir, 'state.json'));
  await assert.rejects(store.initialize({ projectId: 'synthetic-dangling', workspaceId: 'draft', adapterVersion }), { code: 'ALREADY_INITIALIZED' });
  assert.ok(fs.lstatSync(path.join(danglingDir, 'state.json')).isSymbolicLink());
  const other = await store.initialize({ projectId: 'other-project', workspaceId: 'draft', adapterVersion });
  await assert.rejects(store.read({ ...request(initial.revision), revision: other.revision, paths: ['src/main.txt'] }));
  const dir = path.join(root, scope.projectId, scope.workspaceId);
  const statePath = path.join(dir, 'state.json');
  const unknown = JSON.parse(fs.readFileSync(statePath)); unknown.body.futureExtension = true; unknown.digest = hash(canonicalJSON(unknown.body));
  fs.writeFileSync(statePath, JSON.stringify(unknown));
  await assert.rejects(store.commit(request(initial.revision)), { code: 'CORRUPT_STATE' });
  assert.equal(JSON.parse(fs.readFileSync(statePath)).body.futureExtension, true);
  fs.writeFileSync(statePath, '{"unknown":true}');
  await assert.rejects(store.commit(request(initial.revision)), { code: 'CORRUPT_STATE' });
  assert.equal(fs.readFileSync(statePath, 'utf8'), '{"unknown":true}');
  fs.chmodSync(root, 0o755); assert.throws(() => new RevisionStore(config), { code: 'UNSAFE_DIRECTORY' }); fs.chmodSync(root, 0o700);
});

test('source has no 100KB cap but retains 400KB operation/read batches', async t => {
  const { store, initial } = await fixture(t);
  const input = request(initial.revision, 'x'.repeat(250001)), result = await store.commit(input);
  assert.equal((await store.read({ ...input, revision: result.revision, paths: ['src/main.txt'] })).files[0].bytes, 250001);
  await assert.rejects(async () => store.commit(request(result.revision, 'x'.repeat(400001))));
  await assert.rejects(store.read({ ...input, paths: ['src/main.txt', 'src/main.txt'] }), { code: 'INVALID_PATHS' });
});

test('delete operations, exact missing reads and aggregate read boundary', async t => {
  const { store, initial } = await fixture(t);
  let input = request(initial.revision, 'x'.repeat(250001));
  let result = await store.commit(input);
  input = request(result.revision, 'y'.repeat(250001)); input.candidate.operations[0].path = 'second.txt'; input.candidate.candidateDigest = candidateDigest(input.candidate);
  result = await store.commit(input);
  await assert.rejects(store.read({ ...input, revision: result.revision, paths: ['src/main.txt', 'second.txt'] }), { code: 'READ_BATCH_TOO_LARGE' });
  const deletion = request(result.revision); deletion.candidate.operations = [{ type: 'delete', path: 'second.txt' }]; deletion.candidate.candidateDigest = candidateDigest(deletion.candidate);
  const removed = await store.commit(deletion);
  await assert.rejects(store.read({ ...deletion, revision: removed.revision, paths: ['second.txt'] }), { code: 'FILE_NOT_FOUND' });
  assert.equal((await store.read({ ...deletion, revision: result.revision, paths: ['second.txt'] })).files[0].bytes, 250001);
});

test('idempotency scopes include principal/workspace/action, and stale validation is not cached as passed', async t => {
  const { root, initial } = await fixture(t);
  const store = new RevisionStore({ root, authorize: ({ context }) => descriptor(context.projectId, context.workspaceId), validate: passed });
  const input = request(initial.revision);
  await store.validate(input);
  const committed = await store.commit(input);
  const otherPrincipal = { ...input, principalId: 'synthetic-second-user' };
  assert.equal((await store.commit(otherPrincipal)).code, 'REVISION_CONFLICT');
  assert.equal((await store.validate({ ...input, context: { ...input.context, requestId: randomUUID() } })).code, 'REVISION_CONFLICT');
  const initialOther = await store.initialize({ ...scope, workspaceId: 'other', adapterVersion, files: [source('src/main.txt', 'synthetic seed')] });
  const otherWorkspace = request(initialOther.revision); otherWorkspace.context.workspaceId = 'other'; otherWorkspace.context.requestId = input.context.requestId; otherWorkspace.candidate.workspaceId = 'other'; otherWorkspace.candidate.candidateDigest = candidateDigest(otherWorkspace.candidate);
  const otherCommit = await store.commit(otherWorkspace);
  assert.notEqual(otherCommit.revision, committed.revision);
  assert.equal((await store.events(input)).length, 1);
  assert.equal((await store.events(otherWorkspace)).length, 1);
});

test('pending durable admission binds request ID even if validator throws before commit', async t => {
  let fail = true;
  const { store, config, initial } = await fixture(t, { validate: () => { if (fail) throw new Error('synthetic validation interruption'); return passed(); } });
  const input = request(initial.revision);
  await assert.rejects(store.commit(input), /synthetic validation interruption/);
  const changed = request(initial.revision, 'different'); changed.context.requestId = input.context.requestId;
  await assert.rejects(new RevisionStore(config).commit(changed), { code: 'IDEMPOTENCY_MISMATCH' });
  assert.equal((await store.snapshot(input)).revision, initial.revision);
  fail = false; const result = await new RevisionStore(config).commit(input);
  assert.equal((await store.snapshot(input)).revision, result.revision);
});

test('source blobs reject symlinks, hardlinks and content corruption without altering head', async t => {
  const { store, root, initial } = await fixture(t);
  const input = request(initial.revision), revDir = path.join(root, scope.projectId, scope.workspaceId, 'revisions', initial.revision.slice(7));
  const blob = path.join(revDir, hash('synthetic seed').slice(7)), sentinel = path.join(root, 'synthetic-sentinel.txt');
  fs.writeFileSync(sentinel, 'synthetic seed', { mode: 0o600 });
  fs.unlinkSync(blob); fs.symlinkSync(sentinel, blob);
  await assert.rejects(store.read({ ...input, paths: ['src/main.txt'] }), { code: 'ELOOP' });
  assert.equal(fs.readFileSync(sentinel, 'utf8'), 'synthetic seed');
  fs.unlinkSync(blob); fs.linkSync(sentinel, blob);
  await assert.rejects(store.read({ ...input, paths: ['src/main.txt'] }), { code: 'UNSAFE_FILE' });
  fs.unlinkSync(blob); fs.writeFileSync(blob, 'corrupt', { mode: 0o600 });
  await assert.rejects(store.commit(input), { code: 'INVALID_CONTRACT' });
  const state = JSON.parse(fs.readFileSync(path.join(root, scope.projectId, scope.workspaceId, 'state.json')));
  assert.equal(state.body.head, initial.revision);
});

test('administrative recovery refuses live or unknown lock owners', async t => {
  let store, observed = false;
  const fixtureResult = await fixture(t);
  store = new RevisionStore({ ...fixtureResult.config, fault: stage => { if (stage === 'locked') { assert.throws(() => store.recoverLock(scope), { code: 'LOCK_OWNER_ALIVE' }); observed = true; } } });
  await store.commit(request(fixtureResult.initial.revision)); assert.equal(observed, true);
  const lock = path.join(fixtureResult.root, scope.projectId, scope.workspaceId, 'lock'); fs.mkdirSync(lock, { mode: 0o700 });
  assert.throws(() => store.recoverLock(scope), { code: 'ENOENT' });
  assert.equal(fs.existsSync(lock), true);
  const ownerPath = path.join(lock, 'owner.json');
  for (const [content, expected] of [['{', SyntaxError], ['{"pid":0}', { code: 'UNKNOWN_LOCK' }]]) {
    fs.writeFileSync(ownerPath, content, { mode: 0o600 });
    assert.throws(() => store.recoverLock(scope), expected);
    assert.equal(fs.readFileSync(ownerPath, 'utf8'), content);
  }
});
