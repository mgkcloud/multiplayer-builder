import * as fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { assertAuthorizedContext, validateRequestContext, validateValue, BOUNDS } from './contracts.mjs';

const hash = text => `sha256:${createHash('sha256').update(text).digest('hex')}`;
export function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJSON(value[k])}`).join(',')}}`;
}
const digest = value => hash(canonicalJSON(value));
const copy = value => structuredClone(value);
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const error = code => Object.assign(new Error(code), { code });
const same = (a, b) => canonicalJSON(a) === canonicalJSON(b);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && same(Object.keys(value).sort(), [...keys].sort());
const id = value => { if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(value)) throw error('INVALID_SCOPE'); return value; };
export function candidateDigest(candidate) {
  validateValue('candidate', candidate);
  const { candidateDigest: ignored, ...body } = candidate;
  return digest(body);
}
function syncDir(dir) { const fd = fs.openSync(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function safeDir(dir) {
  const st = fs.lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid() || (st.mode & 0o077)) throw error('UNSAFE_DIRECTORY');
}
function mkdir(dir) { try { fs.mkdirSync(dir, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; } safeDir(dir); syncDir(path.dirname(dir)); }
function exists(file) { try { fs.lstatSync(file); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } }
function read(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { const st = fs.fstatSync(fd); if (!st.isFile() || st.nlink !== 1) throw error('UNSAFE_FILE'); return fs.readFileSync(fd, 'utf8'); } finally { fs.closeSync(fd); }
}
function write(file, content) {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, content); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function scopeCheck(scope) { id(scope.projectId); id(scope.workspaceId); }

export class RevisionStore {
  #root; #authorize; #validator; #fault; #lockTimeoutMs;
  constructor({ root, authorize, validate, fault = () => {}, lockTimeoutMs = 5000 }) {
    if (!path.isAbsolute(root) || root.split(path.sep).includes('..')) throw error('UNSAFE_ROOT');
    let current = path.parse(root).root;
    for (const part of root.slice(current.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, part);
      if (fs.lstatSync(current).isSymbolicLink()) throw error('UNSAFE_ROOT');
    }
    safeDir(root);
    if (typeof authorize !== 'function' || typeof validate !== 'function' || typeof fault !== 'function') throw error('TRUSTED_CALLBACK_REQUIRED');
    this.#root = root; this.#authorize = authorize; this.#validator = validate; this.#fault = fault; this.#lockTimeoutMs = lockTimeoutMs;
  }
  #directory(scope) {
    scopeCheck(scope);
    const project = path.join(this.#root, scope.projectId); mkdir(project);
    const dir = path.join(project, scope.workspaceId); mkdir(dir);
    return dir;
  }
  async #locked(scope, fn) {
    const dir = this.#directory(scope), lock = path.join(dir, 'lock');
    const start = Date.now();
    while (true) {
      try { fs.mkdirSync(lock, { mode: 0o700 }); break; }
      catch (e) {
        if (e.code !== 'EEXIST') throw e;
        // The holder may remove the lock between mkdir's EEXIST and inspection.
        try { safeDir(lock); } catch (inspectionError) { if (inspectionError.code !== 'ENOENT') throw inspectionError; }
        if (Date.now() - start >= this.#lockTimeoutMs) throw error('STORE_BUSY');
        await new Promise(r => setTimeout(r, 10));
      }
    }
    try {
      write(path.join(lock, 'owner.json'), canonicalJSON({ pid: process.pid, token: randomUUID() })); syncDir(lock); syncDir(dir);
      await this.#fault('locked');
      return await fn(dir);
    } finally {
      fs.unlinkSync(path.join(lock, 'owner.json')); fs.rmdirSync(lock); syncDir(dir);
    }
  }
  // Host administration only: all service writers must be stopped before recovery.
  recoverLock(scope) {
    const dir = this.#directory(scope), lock = path.join(dir, 'lock'); safeDir(lock);
    const owner = JSON.parse(read(path.join(lock, 'owner.json')));
    if (!Number.isSafeInteger(owner.pid) || owner.pid <= 0) throw error('UNKNOWN_LOCK');
    try { process.kill(owner.pid, 0); throw error('LOCK_OWNER_ALIVE'); } catch (e) { if (e.code !== 'ESRCH') throw e; }
    fs.unlinkSync(path.join(lock, 'owner.json')); fs.rmdirSync(lock); syncDir(dir);
  }
  #state(dir) {
    const state = JSON.parse(read(path.join(dir, 'state.json')));
    if (!exact(state, ['version', 'body', 'digest']) || state.version !== 1 || !exact(state.body, ['head', 'epoch', 'sequence', 'events', 'requests']) || digest(state.body) !== state.digest) throw error('CORRUPT_STATE');
    const body = state.body;
    if (!Array.isArray(body.events) || body.sequence !== body.events.length || !body.requests || typeof body.requests !== 'object' || Array.isArray(body.requests)) throw error('CORRUPT_STATE');
    for (const record of Object.values(body.requests)) {
      if (!exact(record, ['payload', 'candidate', 'status', 'result', 'validation', ...(record?.error ? ['error'] : [])]) || !['pending', 'complete'].includes(record.status) || (record.error && record.error !== 'VALIDATION_FAILED')) throw error('CORRUPT_STATE');
      validateValue('commitResult', { revision: record.payload });
      if (candidateDigest(record.candidate) !== record.candidate.candidateDigest || record.candidate.projectId !== path.basename(path.dirname(dir)) || record.candidate.workspaceId !== path.basename(dir)) throw error('CORRUPT_STATE');
      if (record.validation !== null) {
        validateValue('validation', record.validation);
        const { validationDigest, ...validationBody } = record.validation;
        if (digest(validationBody) !== validationDigest || record.validation.candidateDigest !== record.candidate.candidateDigest || !same(record.validation.adapterVersion, record.candidate.adapterVersion)) throw error('CORRUPT_STATE');
      }
      if (record.status === 'pending' && (record.result !== null || record.validation !== null || record.error)) throw error('CORRUPT_STATE');
      if (record.status === 'complete' && !record.error) validateValue(record.result?.validationDigest ? 'validation' : 'commitResult', record.result);
    }
    validateValue('snapshot', { epoch: body.epoch, sequence: body.sequence, revision: body.head, taskSummaries: [], deploymentSummary: null });
    const { manifest } = this.#revision(dir, body.head);
    for (const [index, event] of body.events.entries()) {
      if (!exact(event, ['version', 'projectId', 'workspaceId', 'epoch', 'sequence', 'revision', 'type', 'payload']) || !exact(event.payload, ['baseRevision', 'requestId']) || event.version !== 1 || event.type !== 'draft.committed' || event.projectId !== manifest.projectId || event.workspaceId !== manifest.workspaceId || event.epoch !== body.epoch || event.sequence !== index + 1 || (index && event.payload.baseRevision !== body.events[index - 1].revision)) throw error('CORRUPT_STATE');
      validateRequestContext({ projectId: event.projectId, workspaceId: event.workspaceId, adapterVersion: manifest.adapterVersion, baseRevision: event.payload.baseRevision, requestId: event.payload.requestId });
      validateValue('commitResult', { revision: event.revision });
    }
    if (body.events.length ? body.events.at(-1).revision !== body.head || body.events.at(-1).payload.baseRevision !== manifest.parentRevision : manifest.parentRevision !== null) throw error('CORRUPT_STATE');
    syncDir(dir);
    return body;
  }
  #revision(dir, revision) {
    validateValue('commitResult', { revision });
    const revDir = path.join(dir, 'revisions', revision.slice(7)); safeDir(path.join(dir, 'revisions')); safeDir(revDir);
    const manifest = JSON.parse(read(path.join(revDir, 'manifest.json'))); validateValue('manifest', manifest);
    const { revision: ignored, ...body } = manifest;
    if (revision !== manifest.revision || digest(body) !== revision || manifest.projectId !== path.basename(path.dirname(dir)) || manifest.workspaceId !== path.basename(dir)) throw error('CORRUPT_REVISION');
    const files = manifest.files.map(f => {
      const content = read(path.join(revDir, f.sha256.slice(7)));
      const value = { ...f, content }; validateValue('sourceFile', value); return value;
    });
    return { manifest, files };
  }
  async #publishState(dir, body, admission = false) {
    const tmp = path.join(dir, `state-${randomUUID()}.tmp`);
    write(tmp, canonicalJSON({ version: 1, body, digest: digest(body) }));
    await this.#fault(admission ? 'beforeAdmissionRename' : 'beforeStateRename');
    fs.renameSync(tmp, path.join(dir, 'state.json')); syncDir(dir);
    await this.#fault(admission ? 'afterAdmissionDurable' : 'afterStateDurable');
  }
  async #persistRevision(dir, scope, adapterVersion, parentRevision, files) {
    const body = { projectId: scope.projectId, workspaceId: scope.workspaceId, parentRevision, adapterVersion, files: files.map(({ content, ...f }) => f).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0) };
    const revision = digest(body), manifest = { ...body, revision }; validateValue('manifest', manifest);
    const revisions = path.join(dir, 'revisions'); mkdir(revisions);
    const target = path.join(revisions, revision.slice(7));
    if (exists(target)) { const existing = this.#revision(dir, revision); if (!same(existing.manifest, manifest)) throw error('CORRUPT_REVISION'); syncDir(revisions); return manifest; }
    const tmp = path.join(revisions, `pending-${randomUUID()}`); mkdir(tmp);
    for (const f of files) {
      const blob = path.join(tmp, f.sha256.slice(7));
      if (!exists(blob)) write(blob, f.content);
    }
    write(path.join(tmp, 'manifest.json'), canonicalJSON(manifest)); syncDir(tmp);
    fs.renameSync(tmp, target); syncDir(revisions); await this.#fault('revisionDurable'); return manifest;
  }
  async initialize({ projectId, workspaceId, adapterVersion, files = [] }) {
    // Host-only seed. Validate each entry using the common source schema.
    scopeCheck({ projectId, workspaceId }); validateValue('adapterVersion', adapterVersion);
    files.forEach(f => validateValue('sourceFile', f));
    const input = freeze(copy({ projectId, workspaceId, adapterVersion, files }));
    return this.#locked(input, async dir => {
      if (exists(path.join(dir, 'state.json'))) throw error('ALREADY_INITIALIZED');
      const manifest = await this.#persistRevision(dir, input, input.adapterVersion, null, input.files);
      const state = { head: manifest.revision, epoch: randomUUID(), sequence: 0, events: [], requests: {} };
      await this.#publishState(dir, state); return copy(manifest);
    });
  }
  async #authorized(principalId, context, action) {
    if (typeof principalId !== 'string' || !principalId || principalId.length > 512) throw error('INVALID_PRINCIPAL');
    const descriptor = await this.#authorize(freeze({ principalId, context, action }));
    assertAuthorizedContext(context, descriptor, action === 'read' ? 'source' : action === 'snapshot' ? 'subscribe' : 'saveDraft');
  }
  async read({ principalId, context, revision = context.baseRevision, paths }) {
    validateRequestContext(context); const c = freeze(copy(context));
    if (!Array.isArray(paths) || !paths.length || paths.length > BOUNDS.sourcePathsPerRead || new Set(paths).size !== paths.length) throw error('INVALID_PATHS');
    const requested = [...paths];
    await this.#authorized(principalId, c, 'read');
    const dir = this.#directory(c), s = this.#state(dir);
    if (revision !== s.head && !s.events.some(e => e.revision === revision || e.payload.baseRevision === revision)) throw error('REVISION_NOT_COMMITTED');
    const data = this.#revision(dir, revision);
    const files = requested.map(p => { const f = data.files.find(f => f.path === p); if (!f) throw error('FILE_NOT_FOUND'); return f; });
    if (files.reduce((n, f) => n + f.bytes, 0) > BOUNDS.sourceBatchBytes) throw error('READ_BATCH_TOO_LARGE');
    return { revision, files };
  }
  async readRevision({ principalId, context, revision = context.baseRevision }) {
    validateRequestContext(context); const c = freeze(copy(context));
    await this.#authorized(principalId, c, 'read');
    const dir = this.#directory(c), s = this.#state(dir);
    if (revision !== s.head && !s.events.some(e => e.revision === revision || e.payload.baseRevision === revision)) throw error('REVISION_NOT_COMMITTED');
    const { manifest } = this.#revision(dir, revision);
    const record = Object.values(s.requests).find(r => r.status === 'complete' && r.result?.revision === revision && r.validation);
    return copy({ manifest, validation: record?.validation ?? null, headRevision: s.head });
  }
  async snapshot({ principalId, context }) {
    validateRequestContext(context); const c = freeze(copy(context)); await this.#authorized(principalId, c, 'snapshot');
    const s = this.#state(this.#directory(c)); return { epoch: s.epoch, sequence: s.sequence, revision: s.head, taskSummaries: [], deploymentSummary: null };
  }
  async events({ principalId, context }) {
    validateRequestContext(context); const c = freeze(copy(context)); await this.#authorized(principalId, c, 'snapshot'); return copy(this.#state(this.#directory(c)).events);
  }
  async validate(input) { return this.#change('validate', input); }
  async commit(input) { return this.#change('commitDraft', input); }
  async #change(action, { principalId, context, candidate }) {
    validateRequestContext(context); validateValue('candidate', candidate);
    const c = freeze(copy(context)), captured = freeze(copy(candidate));
    if (captured.projectId !== c.projectId || captured.workspaceId !== c.workspaceId || captured.baseRevision !== c.baseRevision || !same(captured.adapterVersion, c.adapterVersion)) throw error('CANDIDATE_CONTEXT_MISMATCH');
    if (candidateDigest(captured) !== captured.candidateDigest) throw error('CANDIDATE_DIGEST_MISMATCH');
    await this.#authorized(principalId, c, action);
    return this.#locked(c, async dir => {
      await this.#authorized(principalId, c, action);
      const s = this.#state(dir);
      const key = digest({ principalId, projectId: c.projectId, workspaceId: c.workspaceId, action, requestId: c.requestId });
      const payload = digest({ context: c, candidate: captured });
      if (Object.hasOwn(s.requests, key)) {
        const previous = s.requests[key];
        if (previous.payload !== payload) throw error('IDEMPOTENCY_MISMATCH');
        if (previous.error) throw error(previous.error);
        if (previous.status === 'complete') return copy(previous.result);
        if (previous.status !== 'pending') throw error('CORRUPT_STATE');
      } else {
        s.requests[key] = { payload, candidate: captured, status: 'pending', result: null, validation: null };
        await this.#publishState(dir, s, true);
      }
      let result, recordedValidation = null;
      if (s.head !== c.baseRevision) result = { code: 'REVISION_CONFLICT', baseRevision: c.baseRevision, currentRevision: s.head };
      else {
        const base = this.#revision(dir, s.head);
        if (!same(base.manifest.adapterVersion, c.adapterVersion)) throw error('ADAPTER_MISMATCH');
        const map = new Map(base.files.map(f => [f.path, f]));
        for (const op of captured.operations) {
          if (op.type === 'delete') map.delete(op.path);
          else map.set(op.path, { path: op.path, content: op.content, bytes: Buffer.byteLength(op.content), sha256: hash(op.content) });
        }
        const files = freeze([...map.values()].map(copy));
        const report = await this.#validator(freeze({ principalId, context: c, candidate: captured, files }));
        const checks = copy(report.checks), status = report.status;
        const body = { candidateDigest: captured.candidateDigest, checks, adapterVersion: c.adapterVersion, status };
        const validation = { ...body, validationDigest: digest(body) }; validateValue('validation', validation);
        recordedValidation = validation;
        await this.#authorized(principalId, c, action);
        if (!same(this.#state(dir), s)) throw error('STATE_CHANGED_UNDER_LOCK');
        result = validation;
        if (action === 'commitDraft') {
          if (validation.status !== 'passed') {
            s.requests[key] = { payload, candidate: captured, status: 'complete', result: null, validation, error: 'VALIDATION_FAILED' };
            await this.#publishState(dir, s);
            throw error('VALIDATION_FAILED');
          }
          const manifest = await this.#persistRevision(dir, c, c.adapterVersion, c.baseRevision, files);
          if (!Number.isSafeInteger(s.sequence + 1)) throw error('SEQUENCE_EXHAUSTED');
          s.head = manifest.revision; s.sequence++;
          s.events.push({ version: 1, projectId: c.projectId, workspaceId: c.workspaceId, epoch: s.epoch, sequence: s.sequence, revision: s.head, type: 'draft.committed', payload: { baseRevision: c.baseRevision, requestId: c.requestId } });
          result = { revision: s.head };
        }
      }
      s.requests[key] = { payload, result, candidate: captured, validation: recordedValidation, status: 'complete' };
      await this.#publishState(dir, s); return copy(result);
    });
  }
}
