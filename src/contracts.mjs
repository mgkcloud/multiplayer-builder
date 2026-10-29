import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

export const CONTRACT_VERSION = 1;
export const BOUNDS = Object.freeze({
  sourceFileBytes: null, sourceBatchBytes: 400000, filesChangedPerSave: 5,
  promptCharacters: 6000, eventBytes: 16384, errorCharacters: 300,
  sourcePathsPerRead: 5, monitorRows: 200,
  previewTotalBytes: 10000000, previewAssetBytes: 2000000,
});
export const CAPABILITIES = Object.freeze(['preview', 'source', 'ask', 'propose', 'saveDraft', 'subscribe', 'deploy', 'monitor']);
export const EVENT_TYPES = Object.freeze(['draft.committed', 'task.updated', 'deploy.updated', 'monitor.updated', 'permissions.changed']);
export const ADAPTER_METHODS = Object.freeze(['describe', 'readSource', 'readDraft', 'renderPreview', 'ask', 'propose', 'validate', 'commitDraft', 'snapshot', 'subscribe', 'prepareDeploy', 'startDeploy', 'deploymentStatus', 'reconcileDeploy']);
export const DEPLOYMENT_STATUSES = Object.freeze(['idle', 'prepared', 'queued', 'running', 'succeeded', 'failed', 'unknown']);
export const TASK_STATUSES = Object.freeze(['queued', 'running', 'succeeded', 'failed', 'cancelled']);
export const PREVIEW_CHILD_TYPES = Object.freeze(['preview.ready', 'preview.error', 'preview.resize']);

export class ContractError extends TypeError {
  constructor(path, reason) { super(`${path}: ${reason}`); this.name = 'ContractError'; this.code = 'INVALID_CONTRACT'; }
}
const fail = (p, reason) => { throw new ContractError(p, reason); };
const encoder = new TextEncoder();
const bytes = s => encoder.encode(s).byteLength;
const digestOf = s => `sha256:${bytesToHex(sha256(encoder.encode(s)))}`;
const string = (v, p) => typeof v === 'string' && !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(v) || fail(p, 'expected Unicode string');
const text = (max, nonempty = false) => (v, p) => { string(v, p); if ((nonempty && !v.trim()) || [...v].length > max) fail(p, 'invalid text length'); };
const pattern = re => (v, p) => { string(v, p); if (!re.test(v)) fail(p, 'invalid identifier'); };
const id = pattern(/^[a-z][a-z0-9-]{0,63}$/);
const uuid = pattern(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
const digest = pattern(/^sha256:[0-9a-f]{64}$/);
const semver = pattern(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/);
const boolean = (v, p) => typeof v === 'boolean' || fail(p, 'expected boolean');
const integer = (v, p) => Number.isSafeInteger(v) && v >= 0 || fail(p, 'expected nonnegative safe integer');
const oneOf = values => (v, p) => values.includes(v) || fail(p, 'unknown value');
const nullable = schema => (v, p) => { if (v !== null) schema(v, p); };
const literal = value => oneOf([value]);
function object(fields) {
  return (v, p) => {
    if (v === null || typeof v !== 'object' || Array.isArray(v) || ![Object.prototype, null].includes(Object.getPrototypeOf(v))) fail(p, 'expected plain object');
    const keys = Reflect.ownKeys(v);
    if (keys.length !== Object.keys(fields).length || keys.some(k => typeof k !== 'string' || !Object.hasOwn(fields, k))) fail(p, 'missing or unknown property');
    for (const [key, schema] of Object.entries(fields)) {
      const property = Object.getOwnPropertyDescriptor(v, key);
      if (!property || !property.enumerable || !Object.hasOwn(property, 'value')) fail(`${p}.${key}`, 'expected own enumerable data property');
      schema(property.value, `${p}.${key}`);
    }
  };
}
function array(schema, max = Infinity, min = 0) {
  return (v, p) => {
    if (!Array.isArray(v) || Object.getPrototypeOf(v) !== Array.prototype || v.length > max || v.length < min || Reflect.ownKeys(v).length !== v.length + 1) fail(p, 'invalid array');
    for (let i = 0; i < v.length; i++) {
      const property = Object.getOwnPropertyDescriptor(v, String(i));
      if (!property || !property.enumerable || !Object.hasOwn(property, 'value')) fail(p, 'sparse/accessor array');
      schema(property.value, `${p}[${i}]`);
    }
  };
}
function unique(values, key, p) {
  if (new Set(values.map(key)).size !== values.length) fail(p, 'duplicates');
}
const caps = (v, p) => { array(oneOf(CAPABILITIES), CAPABILITIES.length)(v, p); unique(v, x => x, p); };
const adapterVersion = object({ version: semver, artifactHash: digest });
const scope = { projectId: id, workspaceId: id };
const context = object({ ...scope, adapterVersion, baseRevision: digest, requestId: uuid });
const path = (v, p) => {
  string(v, p);
  if (!v || v.startsWith('/') || v.includes('\\') || /[\x00-\x1f\x7f:%?#]/.test(v) || v.split('/').some(s => !s || s === '.' || s === '..' || s.trim() !== s)) fail(p, 'expected canonical relative path');
};
const fileEntry = object({ path, sha256: digest, bytes: integer });
const sourceFile = (v, p) => {
  object({ path, sha256: digest, bytes: integer, content: string })(v, p);
  if (v.bytes !== bytes(v.content) || v.sha256 !== digestOf(v.content)) fail(p, 'content hash/byte mismatch');
};
const grant = object({ workspaceId: id, capabilities: caps });
const descriptor = (v, p) => {
  object({ id, label: text(200, true), adapterVersion,
    workspaces: array(object({ id, label: text(200, true) }), Infinity, 1),
    capabilities: array(grant), permissions: array(grant), currentRevision: digest,
    deploymentStatus: oneOf(DEPLOYMENT_STATUSES),
  })(v, p);
  unique(v.workspaces, x => x.id, p);
  for (const field of ['capabilities', 'permissions']) {
    unique(v[field], x => x.workspaceId, `${p}.${field}`);
    if (v[field].length !== v.workspaces.length || v[field].some(g => !v.workspaces.some(w => w.id === g.workspaceId))) fail(p, 'explicit grant row required for each workspace');
  }
  for (const g of v.permissions) {
    if (g.capabilities.some(c => !v.capabilities.find(x => x.workspaceId === g.workspaceId).capabilities.includes(c))) fail(p, 'permission exceeds supported capability');
  }
};
const sameVersion = (a, b) => a.version === b.version && a.artifactHash === b.artifactHash;
export function validateDescriptor(value) { descriptor(value, 'descriptor'); return value; }
export function validateRequestContext(value) { context(value, 'context'); return value; }
export function assertAuthorizedContext(value, project, capability) {
  validateRequestContext(value); validateDescriptor(project);
  if (value.projectId !== project.id || !project.workspaces.some(w => w.id === value.workspaceId) || !sameVersion(value.adapterVersion, project.adapterVersion)) fail('context', 'project/workspace/adapter mismatch');
  if (!CAPABILITIES.includes(capability)) fail('capability', 'explicit known capability required');
  if (!project.permissions.find(g => g.workspaceId === value.workspaceId).capabilities.includes(capability)) fail('context', 'capability not granted');
  return value;
}
function boundScope(value, expected, p) {
  if (value.projectId !== expected.projectId || value.workspaceId !== expected.workspaceId) fail(p, 'scope mismatch');
}
const check = object({ name: id, status: oneOf(['passed', 'failed', 'unknown']), message: text(BOUNDS.errorCharacters) });
const validation = object({ candidateDigest: digest, validationDigest: digest, checks: array(check), adapterVersion, status: oneOf(['passed', 'failed', 'unknown']) });
function validateValidation(v, p) {
  validation(v, p); unique(v.checks, c => c.name, p);
  if (v.status === 'passed' && (!v.checks.length || v.checks.some(c => c.status !== 'passed'))) fail(p, 'passed requires positive checks');
}
const manifest = (v, p) => {
  object({ ...scope, revision: digest, parentRevision: nullable(digest), adapterVersion, files: array(fileEntry) })(v, p);
  unique(v.files, f => f.path, p);
};
const operation = (v, p) => {
  if (!v || typeof v !== 'object') fail(p, 'expected operation');
  const tag = Object.getOwnPropertyDescriptor(v, 'type');
  if (!tag || !Object.hasOwn(tag, 'value')) fail(p, 'operation type required');
  if (tag.value === 'write') object({ type: literal('write'), path, content: string })(v, p);
  else if (tag.value === 'delete') object({ type: literal('delete'), path })(v, p);
  else fail(p, 'unknown operation');
};
const candidate = (v, p) => {
  object({ ...scope, baseRevision: digest, adapterVersion, candidateDigest: digest, operations: array(operation, BOUNDS.filesChangedPerSave, 1) })(v, p);
  unique(v.operations, o => o.path, p);
  if (bytes(JSON.stringify(v.operations)) > BOUNDS.sourceBatchBytes) fail(p, 'operation batch exceeds byte boundary');
};
const task = object({ taskId: uuid, requestId: uuid, baseRevision: digest, status: oneOf(TASK_STATUSES), message: text(BOUNDS.errorCharacters) });
const deployment = (v, p) => {
  object({ operationId: uuid, frozenRevision: digest, status: oneOf(DEPLOYMENT_STATUSES), message: text(BOUNDS.errorCharacters), receipt: nullable(object({ evidenceDigest: digest, target: id })) })(v, p);
  if (v.status === 'succeeded' && v.receipt === null) fail(p, 'success requires evidence receipt');
  if (v.status !== 'succeeded' && v.receipt !== null) fail(p, 'receipt requires success');
};
const cursor = object({ epoch: uuid, sequence: integer });
const snapshot = object({ epoch: uuid, sequence: integer, revision: digest, taskSummaries: array(task), deploymentSummary: nullable(deployment) });
const prepared = object({ preparedId: uuid, revision: digest, manifestDigest: digest, target: id, validationDigest: digest });
const answer = object({ text: text(BOUNDS.previewTotalBytes), provenance: array(object({ ...scope, revision: digest, path, sha256: digest }), Infinity, 1) });
const monitor = object({ rows: array(object({ id, status: oneOf(['ok', 'warning', 'error', 'unknown']), summary: text(BOUNDS.errorCharacters) }), BOUNDS.monitorRows), truncated: boolean });
const preview = (v, p) => {
  object({ revision: digest, html: string, csp: text(16384, true), manifestDigest: digest })(v, p);
  if (bytes(v.html) > BOUNDS.previewTotalBytes) fail(p, 'preview exceeds byte boundary');
};
const conflict = object({ code: literal('REVISION_CONFLICT'), baseRevision: digest, currentRevision: digest });
const commit = (v, p) => {
  const code = v && typeof v === 'object' && Object.getOwnPropertyDescriptor(v, 'code');
  if (code) conflict(v, p);
  else object({ revision: digest })(v, p);
};
export const VALUE_TYPES = Object.freeze(['adapterVersion', 'sourceFile', 'manifest', 'candidate', 'validation', 'taskSummary', 'deploymentSummary', 'cursor', 'snapshot', 'preparedDeploy', 'answer', 'monitor', 'preview', 'commitResult']);
const values = { adapterVersion, sourceFile, manifest, candidate, validation: validateValidation, taskSummary: task, deploymentSummary: deployment, cursor, snapshot, preparedDeploy: prepared, answer, monitor, preview, commitResult: commit };
export function validateValue(type, value) {
  if (!Object.hasOwn(values, type)) fail('type', 'unknown value type');
  values[type](value, type); return value;
}
const methodCapability = Object.freeze({ readSource: 'source', readDraft: 'source', renderPreview: 'preview', ask: 'ask', propose: 'propose', validate: 'saveDraft', commitDraft: 'saveDraft', snapshot: 'subscribe', subscribe: 'subscribe', prepareDeploy: 'deploy', startDeploy: 'deploy', deploymentStatus: 'deploy', reconcileDeploy: 'deploy' });
export const METHOD_CAPABILITIES = methodCapability;
export function validateDescribeResult(projects) {
  array(descriptor)(projects, 'projects'); unique(projects, p => p.id, 'projects');
  return projects;
}
export function validateAdapter(adapter, projects) {
  validateDescribeResult(projects);
  if (!adapter || typeof adapter !== 'object') fail('adapter', 'expected implementation object');
  for (const name of Reflect.ownKeys(adapter)) {
    if (!ADAPTER_METHODS.includes(name)) fail('adapter', 'unknown method');
    const entry = Object.getOwnPropertyDescriptor(adapter, name);
    if (!Object.hasOwn(entry, 'value') || typeof entry.value !== 'function') fail('adapter', 'expected own function');
  }
  const supported = new Set(projects.flatMap(p => p.capabilities.flatMap(g => g.capabilities)));
  for (const method of ADAPTER_METHODS) {
    if ((method === 'describe' || supported.has(methodCapability[method]) || (supported.has('monitor') && ['snapshot', 'subscribe'].includes(method))) && !Object.hasOwn(adapter, method)) fail('adapter', `advertised capability requires ${method}`);
  }
  return adapter;
}
const requestFields = {
  readSource: { revision: digest, paths: array(path, BOUNDS.sourcePathsPerRead, 1) },
  readDraft: { revision: digest }, renderPreview: { revision: digest },
  ask: { text: text(BOUNDS.promptCharacters, true) }, propose: { text: text(BOUNDS.promptCharacters, true) },
  validate: { immutableCandidate: candidate },
  commitDraft: { baseRevision: digest, candidateDigest: digest, requestId: uuid },
  snapshot: {}, subscribe: { cursor: nullable(cursor) },
  prepareDeploy: { revision: digest, validationDigest: digest },
  startDeploy: { preparedId: uuid, requestId: uuid },
  deploymentStatus: { operationId: uuid }, reconcileDeploy: { operationId: uuid },
};
export function validateAdapterRequest(method, value, project) {
  if (!Object.hasOwn(requestFields, method)) fail('method', 'unknown request method');
  object({ context, ...requestFields[method] })(value, 'request');
  assertAuthorizedContext(value.context, project, methodCapability[method]);
  const c = value.context;
  if (Object.hasOwn(value, 'requestId') && value.requestId !== c.requestId) fail('request', 'requestId mismatch');
  if (Object.hasOwn(value, 'baseRevision') && value.baseRevision !== c.baseRevision) fail('request', 'baseRevision mismatch');
  if (method === 'readSource') unique(value.paths, x => x, 'paths');
  if (method === 'validate') {
    boundScope(value.immutableCandidate, c, 'candidate');
    if (value.immutableCandidate.baseRevision !== c.baseRevision || !sameVersion(value.immutableCandidate.adapterVersion, c.adapterVersion)) fail('candidate', 'context mismatch');
  }
  return value;
}
const sourceResult = (v, p) => {
  object({ revision: digest, files: array(sourceFile, BOUNDS.sourcePathsPerRead) })(v, p);
  unique(v.files, f => f.path, p);
  if (v.files.reduce((n, f) => n + f.bytes, 0) > BOUNDS.sourceBatchBytes) fail(p, 'source batch exceeds byte boundary');
};
const resultSchemas = {
  readSource: sourceResult,
  readDraft: object({ manifest, validation: validateValidation, headRevision: digest }),
  renderPreview: preview, ask: answer, propose: object({ taskId: uuid }),
  validate: validateValidation, commitDraft: commit, snapshot,
  prepareDeploy: prepared,
  startDeploy: object({ operationId: uuid, status: oneOf(['queued', 'running', 'unknown']), frozenRevision: digest }),
  deploymentStatus: deployment, reconcileDeploy: deployment,
};
export function validateAdapterResult(method, value, request, project) {
  validateAdapterRequest(method, request, project);
  if (method === 'subscribe') { if (typeof value !== 'function') fail('result', 'expected unsubscribe function'); return value; }
  if (!Object.hasOwn(resultSchemas, method)) fail('method', 'unknown result method');
  resultSchemas[method](value, 'result');
  const c = request.context;
  if (['readSource', 'renderPreview', 'prepareDeploy'].includes(method) && value.revision !== request.revision) fail('result', 'revision mismatch');
  if (method === 'readSource' && (value.files.length !== request.paths.length || value.files.some(f => !request.paths.includes(f.path)))) fail('result', 'incomplete or unrequested source paths');
  if (method === 'readDraft') {
    boundScope(value.manifest, c, 'manifest');
    if (value.manifest.revision !== request.revision || !sameVersion(value.manifest.adapterVersion, c.adapterVersion) || !sameVersion(value.validation.adapterVersion, c.adapterVersion)) fail('result', 'manifest context mismatch');
  }
  if (method === 'ask' && value.provenance.some(s => s.projectId !== c.projectId || s.workspaceId !== c.workspaceId || s.revision !== c.baseRevision)) fail('result', 'provenance context mismatch');
  if (method === 'validate' && (value.candidateDigest !== request.immutableCandidate.candidateDigest || !sameVersion(value.adapterVersion, c.adapterVersion))) fail('result', 'validation context mismatch');
  if (method === 'commitDraft' && Object.hasOwn(value, 'code') && value.baseRevision !== c.baseRevision) fail('result', 'conflict context mismatch');
  if (['deploymentStatus', 'reconcileDeploy'].includes(method) && value.operationId !== request.operationId) fail('result', 'operation mismatch');
  if (method === 'prepareDeploy' && value.validationDigest !== request.validationDigest) fail('result', 'validation digest mismatch');
  return value;
}
const payloads = {
  'draft.committed': object({ baseRevision: digest, requestId: uuid }),
  'task.updated': task, 'deploy.updated': deployment, 'monitor.updated': monitor,
  'permissions.changed': object({ capabilities: caps }),
};
export function validateEvent(value, expected, project) {
  assertAuthorizedContext(expected, project, 'subscribe');
  object({ version: literal(CONTRACT_VERSION), ...scope, epoch: uuid, sequence: integer, revision: digest, type: oneOf(EVENT_TYPES), payload: (v, p) => {
    // Inspect only after the enclosing object's own data property checks below.
    const type = Object.getOwnPropertyDescriptor(value, 'type');
    if (!type || !Object.hasOwn(type, 'value') || !Object.hasOwn(payloads, type.value)) fail(p, 'unknown event type');
    payloads[type.value](v, p);
  } })(value, 'event');
  boundScope(value, expected, 'event');
  if (value.type === 'monitor.updated') assertAuthorizedContext(expected, project, 'monitor');
  if (value.type === 'permissions.changed' && value.payload.capabilities.some(c => !project.capabilities.find(g => g.workspaceId === expected.workspaceId).capabilities.includes(c))) fail('event', 'unsupported permission');
  if (bytes(JSON.stringify(value)) > BOUNDS.eventBytes) fail('event', 'event exceeds byte boundary');
  return value;
}
export function validateEventProgress(previous, next) {
  cursor(previous, 'previous'); cursor(next, 'next');
  if (previous.epoch !== next.epoch || next.sequence !== previous.sequence + 1) fail('cursor', 'bootstrap required for gap, replay, or epoch change');
  return next;
}
const previewPayloads = {
  'preview.ready': object({}),
  'preview.error': object({ message: text(BOUNDS.errorCharacters, true) }),
  'preview.resize': object({ height: (v, p) => { integer(v, p); if (v > 100000) fail(p, 'height exceeds rendering bound'); } }),
};
export function validatePreviewMessage(value, binding) {
  object({ ...scope, revision: digest, nonce: pattern(/^[0-9a-f]{64}$/), frameInstance: uuid })(binding, 'binding');
  object({ version: literal(CONTRACT_VERSION), ...scope, revision: digest,
    nonce: pattern(/^[0-9a-f]{64}$/), frameInstance: uuid, type: oneOf(PREVIEW_CHILD_TYPES),
    payload: (v, p) => {
      const type = Object.getOwnPropertyDescriptor(value, 'type');
      if (!type || !Object.hasOwn(type, 'value') || !Object.hasOwn(previewPayloads, type.value)) fail(p, 'unknown preview type');
      previewPayloads[type.value](v, p);
    },
  })(value, 'previewMessage');
  for (const key of Object.keys(binding)) if (value[key] !== binding[key]) fail('previewMessage', 'binding mismatch');
  if (bytes(JSON.stringify(value)) > BOUNDS.eventBytes) fail('previewMessage', 'message exceeds byte boundary');
  return value;
}
export function validatePreviewEvent(event, boundWindow, binding) {
  if (!boundWindow || !event || event.source !== boundWindow || event.origin !== 'null') fail('previewEvent', 'window/origin mismatch');
  return validatePreviewMessage(event.data, binding);
}
