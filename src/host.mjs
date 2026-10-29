import { randomBytes, randomUUID } from 'node:crypto';
import { assertAuthorizedContext, validateDescriptor, validateDescribeResult, validateRequestContext,
  validateAdapterRequest, validateAdapterResult, validateValue, validateEvent, validateEventProgress } from './contracts.mjs';
import { candidateDigest, canonicalJSON } from './revision-store.mjs';
import { HttpError, deny, exactObject, decodeRoute, readJSON, checkOrigin, checkMutation, csrfToken, createRateLimiter, validateSourcePath } from './security.mjs';

const capabilityMethods = {
  source: ['readSource', 'readDraft'], preview: ['renderPreview'], ask: ['ask'], propose: ['propose'],
  saveDraft: ['validate', 'commitDraft'], subscribe: ['snapshot', 'subscribe'],
  deploy: ['prepareDeploy', 'startDeploy', 'deploymentStatus', 'reconcileDeploy'], monitor: ['snapshot', 'subscribe', 'monitor'],
};
const frozen = value => {
  if (value && typeof value === 'object') { for (const v of Object.values(value)) frozen(v); Object.freeze(value); }
  return value;
};
const clone = value => frozen(structuredClone(value));
const equal = (a, b) => canonicalJSON(a) === canonicalJSON(b);
const knownErrors = {
  REVISION_CONFLICT: 409, IDEMPOTENCY_MISMATCH: 409, CANDIDATE_DIGEST_MISMATCH: 400,
  VALIDATION_FAILED: 422, FILE_NOT_FOUND: 404, READ_BATCH_TOO_LARGE: 413, STORE_BUSY: 503,
};
function send(res, status, value) {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
  res.end(JSON.stringify(value));
}

export function createBuilderHost({ origin, authenticate, projects, csrfSecret = randomBytes(32),
  now = Date.now, captureTtlMs = 300000, maxCaptures = 16, maxRecords = 1000,
  recordTtlMs = 3600000, rateLimit = {}, streamCheckMs = 1000, streamLifetimeMs = 300000,
  maxStreams = 100, maxStreamsPerPrincipal = 4 } = {}) {
  if (new URL(origin).origin !== origin || !['http:', 'https:'].includes(new URL(origin).protocol) ||
      typeof authenticate !== 'function' || !(projects instanceof Map) || csrfSecret.length < 32 ||
      ![captureTtlMs, maxCaptures, maxRecords, recordTtlMs, streamCheckMs, streamLifetimeMs, maxStreams, maxStreamsPerPrincipal].every(n => Number.isSafeInteger(n) && n > 0)) throw new TypeError('Invalid host configuration');
  const registry = new Map(projects), captures = new Map(), prepared = new Map(), operations = new Map(), requests = new Map(), streams = new Map(), active = new Set();
  const rate = createRateLimiter({ ...rateLimit, now });
  let closed = false;
  const prune = map => { for (const [k, v] of map) if (v.until <= now() && !v.pending) map.delete(k); };
  const admit = map => { prune(map); if (map.size >= maxRecords) deny(429, 'HOST_CAPACITY'); };
  async function identity(req) {
    const p = await authenticate(req);
    if (!p || typeof p.id !== 'string' || !p.id || p.id.length > 200 || typeof p.sessionId !== 'string' || !p.sessionId || p.sessionId.length > 200) deny(401, 'UNAUTHENTICATED');
    return clone({ id: p.id, sessionId: p.sessionId });
  }
  function methods(entry) {
    const adapter = entry.adapter || {};
    const result = { ...adapter };
    if (entry.store) {
      result.readSource = (r, runtime) => entry.store.read({ principalId: runtime.principalId, ...r });
      result.readDraft = (r, runtime) => entry.store.readRevision({ principalId: runtime.principalId, ...r });
      result.validate = (r, runtime) => entry.store.validate({ principalId: runtime.principalId, context: r.context, candidate: runtime.candidate });
      result.commitDraft = (r, runtime) => entry.store.commit({ principalId: runtime.principalId, context: r.context, candidate: runtime.candidate });
    }
    return result;
  }
  async function describe(entry, principal, id) {
    if (typeof entry?.adapter?.describe !== 'function') return null;
    const raw = await entry.adapter.describe(principal);
    if (raw === null) return null;
    validateDescriptor(raw);
    if (raw.id !== id) deny(502, 'ADAPTER_INVALID');
    const d = structuredClone(raw), available = methods(entry);
    for (const field of ['capabilities', 'permissions']) for (const row of d[field]) row.capabilities = row.capabilities.filter(c => capabilityMethods[c].every(m => typeof available[m] === 'function'));
    return clone(d);
  }
  async function authorized(req, p, context, capability) {
    const current = await identity(req);
    if (!equal(current, p)) deny(401, 'SESSION_CHANGED');
    const entry = registry.get(context.projectId);
    const descriptor = await describe(entry, current, context.projectId);
    if (!descriptor) deny(403, 'FORBIDDEN');
    try { assertAuthorizedContext(context, descriptor, capability); } catch { deny(403, 'FORBIDDEN'); }
    return { entry, descriptor, available: methods(entry) };
  }
  async function call(method, request, state, runtime) {
    validateAdapterRequest(method, request, state.descriptor);
    if (typeof state.available[method] !== 'function') deny(501, 'UNSUPPORTED');
    const result = await state.available[method](request, runtime);
    if (result?.code === 'REVISION_CONFLICT' && method === 'validate') return validateValue('commitResult', result);
    try {
      if (method === 'readDraft' && result?.validation === null && state.entry.store) {
        exactObject(result, ['manifest', 'validation', 'headRevision']);
        validateValue('manifest', result.manifest);
        if (result.manifest.parentRevision !== null || result.manifest.revision !== request.revision || result.manifest.projectId !== request.context.projectId || result.manifest.workspaceId !== request.context.workspaceId || !equal(result.manifest.adapterVersion, request.context.adapterVersion) || !/^sha256:[0-9a-f]{64}$/.test(result.headRevision)) deny(502, 'ADAPTER_INVALID');
      } else validateAdapterResult(method, result, request, state.descriptor);
    } catch { deny(502, 'ADAPTER_INVALID'); }
    return clone(result);
  }
  async function once(key, input, fn) {
    prune(requests);
    const fingerprint = canonicalJSON(input), previous = requests.get(key);
    if (previous) {
      if (previous.fingerprint !== fingerprint) deny(409, 'IDEMPOTENCY_MISMATCH');
      if (previous.pending) deny(409, 'REQUEST_PENDING');
      if (previous.error) deny(previous.error.status, previous.error.code);
      return previous.result;
    }
    admit(requests);
    const record = { fingerprint, pending: true, until: now() + recordTtlMs }; requests.set(key, record);
    try { record.result = await fn(); return record.result; }
    catch (error) { record.error = error instanceof HttpError ? error : { status: knownErrors[error.code] || 502, code: knownErrors[error.code] ? error.code : 'ADAPTER_ERROR' }; throw error; }
    finally { record.pending = false; }
  }
  const binding = (p, context) => canonicalJSON({ principalId: p.id, sessionId: p.sessionId, context });
  async function eventStream(req, res, p, context, cursor, state, runtime) {
    validateAdapterRequest('subscribe', { context, cursor }, state.descriptor);
    if (streams.size >= maxStreams || [...streams.values()].filter(s => s.principalId === p.id).length >= maxStreamsPerPrincipal) deny(429, 'STREAM_LIMIT');
    let ended = false, busy = false, unsubscribe, timer, expiry;
    const cleanup = () => {
      if (ended) return;
      ended = true; clearInterval(timer); clearTimeout(expiry); runtime.controller.abort();
      req.off('aborted', cleanup); res.off('close', cleanup); streams.delete(cleanup);
      if (unsubscribe) { try { unsubscribe(); } catch {} }
      res.end();
    };
    streams.set(cleanup, { principalId: p.id });
    req.on('aborted', cleanup); res.on('close', cleanup);
    res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Accel-Buffering': 'no' });
    res.write(': connected\n\n');
    const emit = async event => {
      if (ended) return;
      if (busy) { cleanup(); return; }
      busy = true;
      try {
        const current = await authorized(req, p, context, 'subscribe');
        validateEvent(event, context, current.descriptor);
        const next = { epoch: event.epoch, sequence: event.sequence };
        if (cursor) validateEventProgress(cursor, next);
        cursor = next;
        if (!ended && !res.write(`event: builder\ndata: ${JSON.stringify(event)}\n\n`)) cleanup();
      } catch { cleanup(); } finally { busy = false; }
    };
    try {
      const stop = await state.available.subscribe({ context, cursor }, { ...runtime, emit });
      if (typeof stop !== 'function') throw new Error('Invalid subscription');
      unsubscribe = stop;
      if (ended) { unsubscribe(); return; }
      let checking = false;
      timer = setInterval(async () => {
        if (checking) { cleanup(); return; }
        checking = true;
        try { await authorized(req, p, context, 'subscribe'); } catch { cleanup(); }
        finally { checking = false; }
      }, streamCheckMs);
      timer.unref?.();
      expiry = setTimeout(cleanup, streamLifetimeMs); expiry.unref?.();
    } catch { cleanup(); }
  }
  async function handler(req, res) {
    const controller = new AbortController(); const abort = () => controller.abort();
    res.once('close', abort);
    try {
      if (closed) deny(503, 'HOST_CLOSED');
      const { parts, query } = decodeRoute(req.url);
      if (parts.slice(0, 3).join('/') !== 'api/builder/v1') deny(404, 'NOT_FOUND');
      checkOrigin(req, origin);
      const principal = await identity(req);
      const route = parts.slice(3);
      if (req.method === 'GET' && route.length === 1 && route[0] === 'session') {
        if (query.size) deny(400, 'INVALID_REQUEST');
        return send(res, 200, { ok: true, data: { csrfToken: csrfToken(csrfSecret, principal) } });
      }
      if (req.method === 'GET' && route.length === 1 && route[0] === 'projects') {
        if (query.size) deny(400, 'INVALID_REQUEST');
        const descriptors = [];
        for (const [id, entry] of registry) {
          const d = await describe(entry, principal, id);
          if (d && d.permissions.some(g => g.capabilities.length)) descriptors.push(d);
        }
        validateDescribeResult(descriptors);
        return send(res, 200, { ok: true, data: { projects: descriptors } });
      }
      if (route[0] !== 'projects' || route.length < 3) deny(404, 'NOT_FOUND');
      if (!['GET', 'POST'].includes(req.method)) deny(501, 'UNSUPPORTED');
      const write = req.method === 'POST';
      if (write) checkMutation(req, origin, csrfSecret, principal);
      let body, context;
      if (write) { if (query.size) deny(400, 'INVALID_REQUEST'); body = await readJSON(req); context = body?.context; }
      else {
        const raw = req.headers['x-builder-context'];
        try { context = JSON.parse(raw); } catch { deny(400, 'CONTEXT_REQUIRED'); }
      }
      validateRequestContext(context); context = clone(context);
      if (context.projectId !== route[1]) deny(403, 'FORBIDDEN');
      const action = route.slice(2).join('/');
      const specs = {
        'GET bootstrap': ['subscribe', 'snapshot'], 'GET events': ['subscribe', 'subscribe'],
        'GET source': ['source', 'readSource'], 'GET draft': ['source', 'readDraft'],
        'GET preview': ['preview', 'renderPreview'], 'GET monitor': ['monitor', 'monitor'],
        'POST ask': ['ask', 'ask'], 'POST tasks': ['propose', 'propose'],
        'POST draft/validate': ['saveDraft', 'validate'], 'POST draft': ['saveDraft', 'commitDraft'],
        'POST deployments/prepare': ['deploy', 'prepareDeploy'], 'POST deployments': ['deploy', 'startDeploy'],
      };
      const spec = specs[`${req.method} ${action}`] || (req.method === 'GET' && route.length === 4 && route[2] === 'deployments' ? ['deploy', 'deploymentStatus'] : null);
      if (!spec) deny(501, 'UNSUPPORTED');
      const [capability, method] = spec;
      let state = await authorized(req, principal, context, capability);
      if (method === 'monitor') await authorized(req, principal, context, 'subscribe');
      if (typeof state.available[method] !== 'function') deny(501, 'UNSUPPORTED');
      const runtime = { principalId: principal.id, signal: controller.signal, controller };
      let request = { context };
      const param = (name, fallback) => query.has(name) ? query.get(name) : fallback;
      const checkQuery = allowed => { if ([...query.keys()].some(k => !allowed.includes(k)) || [...new Set(query.keys())].some(k => query.getAll(k).length !== 1)) deny(400, 'INVALID_REQUEST'); };
      if (!write) {
        if (method === 'readSource') {
          checkQuery(['revision', 'paths']); let paths;
          try { paths = JSON.parse(query.get('paths')); } catch { deny(400, 'INVALID_REQUEST'); }
          if (Array.isArray(paths)) paths.forEach(validateSourcePath);
          request = { context, revision: param('revision', context.baseRevision), paths };
        } else if (['readDraft', 'renderPreview'].includes(method)) { checkQuery(['revision']); request.revision = param('revision', context.baseRevision); }
        else if (method === 'subscribe') {
          checkQuery(['cursor']); let cursor = null;
          try { if (query.has('cursor')) cursor = JSON.parse(query.get('cursor')); } catch { deny(400, 'INVALID_REQUEST'); }
          return await eventStream(req, res, principal, context, cursor, state, runtime);
        } else { checkQuery([]); if (method === 'deploymentStatus') request.operationId = route[3]; }
      } else {
        const fields = { ask: ['text'], propose: ['text'], validate: ['operations'], commitDraft: ['captureId'], prepareDeploy: ['revision', 'validationDigest'], startDeploy: ['preparedId'] }[method];
        exactObject(body, ['context', ...fields]);
        for (const field of fields) request[field] = body[field];
        rate(canonicalJSON([principal.id, context.projectId]));
      }
      const bound = binding(principal, context);
      const execute = async () => {
        state = await authorized(req, principal, context, capability);
        if (write && ['ask', 'propose', 'validate', 'prepareDeploy'].includes(method) && context.baseRevision !== state.descriptor.currentRevision) deny(409, 'STALE_BASE');
        let result;
        if (method === 'validate') {
          prune(captures); admit(captures);
          if ([...captures.values()].filter(c => c.principalId === principal.id).length >= maxCaptures) deny(429, 'CAPTURE_LIMIT');
          const candidate = { projectId: context.projectId, workspaceId: context.workspaceId, adapterVersion: context.adapterVersion, baseRevision: context.baseRevision, candidateDigest: `sha256:${'0'.repeat(64)}`, operations: request.operations };
          candidate.candidateDigest = candidateDigest(candidate);
          const captured = clone(candidate);
          request = { context, immutableCandidate: captured };
          result = await call('validate', request, state, { ...runtime, candidate: captured });
          if (result.code === 'REVISION_CONFLICT') return result;
          const captureId = randomUUID(), until = now() + captureTtlMs;
          captures.set(captureId, { principalId: principal.id, bound, candidate: captured, until });
          result = { captureId, candidateDigest: captured.candidateDigest, validation: result, expiresAt: until };
        } else if (method === 'commitDraft') {
          prune(captures);
          const captured = captures.get(request.captureId);
          if (!captured) deny(410, 'CAPTURE_EXPIRED');
          if (captured.bound !== bound) deny(403, 'CAPTURE_SCOPE_DENIED');
          request = { context, baseRevision: context.baseRevision, candidateDigest: captured.candidate.candidateDigest, requestId: context.requestId };
          result = await call(method, request, state, { ...runtime, candidate: captured.candidate });
        } else if (method === 'prepareDeploy') {
          admit(prepared);
          result = await call(method, request, state, runtime);
          if (prepared.has(result.preparedId)) deny(502, 'ADAPTER_INVALID');
          prepared.set(result.preparedId, { bound, value: result, until: now() + captureTtlMs });
        } else if (method === 'startDeploy') {
          prune(prepared); admit(operations);
          const capture = prepared.get(request.preparedId);
          if (!capture) deny(410, 'PREPARATION_EXPIRED');
          if (capture.bound !== bound) deny(403, 'PREPARATION_SCOPE_DENIED');
          if (capture.started) deny(409, 'PREPARATION_USED');
          capture.started = true;
          request = { context, preparedId: request.preparedId, requestId: context.requestId };
          result = await call(method, request, state, { ...runtime, prepared: capture.value });
          if (result.frozenRevision !== capture.value.revision || operations.has(result.operationId)) deny(502, 'ADAPTER_INVALID');
          operations.set(result.operationId, { principalId: principal.id, context, revision: capture.value.revision, until: now() + recordTtlMs });
        } else if (method === 'deploymentStatus') {
          prune(operations);
          const operation = operations.get(request.operationId);
          if (!operation || operation.principalId !== principal.id || !equal(operation.context, context)) deny(404, 'OPERATION_NOT_FOUND');
          result = await call(method, request, state, runtime);
          if (result.frozenRevision !== operation.revision) deny(502, 'ADAPTER_INVALID');
        } else if (method === 'monitor') {
          result = await state.available.monitor(request, runtime);
          try { validateValue('monitor', result); } catch { deny(502, 'ADAPTER_INVALID'); }
        } else result = await call(method, request, state, runtime);
        await authorized(req, principal, context, capability);
        return result;
      };
      let result;
      if (write) {
        const lock = canonicalJSON([principal.id, context.projectId, context.workspaceId, ['ask', 'propose'].includes(method) ? 'generation' : method === 'startDeploy' ? 'deployment' : method]);
        if (active.has(lock)) deny(409, 'ACTION_BUSY');
        active.add(lock);
        try { result = await once(canonicalJSON([principal.id, context.projectId, context.workspaceId, method, context.requestId]), body, execute); }
        finally { active.delete(lock); }
      } else result = await execute();
      send(res, result?.code === 'REVISION_CONFLICT' ? 409 : 200, { ok: true, data: result });
    } catch (error) {
      if (res.headersSent) { res.end(); return; }
      const status = error instanceof HttpError ? error.status : error.code === 'INVALID_CONTRACT' ? 400 : knownErrors[error.code] || 502;
      const code = error instanceof HttpError ? error.code : error.code === 'INVALID_CONTRACT' ? 'INVALID_REQUEST' : knownErrors[error.code] ? error.code : 'ADAPTER_ERROR';
      send(res, status, { ok: false, error: { code, message: code } });
    } finally { if (res.writableEnded) res.off('close', abort); }
  }
  handler.close = () => { closed = true; for (const stop of [...streams.keys()]) stop(); captures.clear(); prepared.clear(); operations.clear(); requests.clear(); };
  return handler;
}
