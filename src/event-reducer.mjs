import { assertAuthorizedContext, validateEvent, validateEventProgress, validateValue } from './contracts.mjs';

const clone = value => structuredClone(value);
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const finish = value => freeze(value);
const remoteEmpty = () => ({ revision: null, cursor: null, tasks: [], deployment: null, monitor: null, permissionNotice: null });
export function createReducerState() {
  return finish({ lifetime: 0, stream: 0, trusted: null, needsBootstrap: true, reason: 'unselected', remote: remoteEmpty(), local: { draft: '', focus: null } });
}
export function bindingToken(state) {
  if (!state.trusted) return null;
  return finish({ lifetime: state.lifetime, stream: state.stream, projectId: state.trusted.context.projectId, workspaceId: state.trusted.context.workspaceId });
}
export function isCurrentBinding(state, binding) {
  const token = bindingToken(state);
  return !!(token && binding && Object.keys(binding).length === 4 && Object.keys(token).every(k => token[k] === binding[k]));
}
function bootstrapRequired(state, reason) {
  return finish({ ...state, stream: state.stream + 1, needsBootstrap: true, reason });
}
export function reduceEventState(state, action) {
  if (action.type === 'select') {
    // This action is host-only, never populated from an event or client message.
    assertAuthorizedContext(action.context, action.descriptor, 'subscribe');
    const trusted = clone({ context: action.context, descriptor: action.descriptor });
    return finish({ ...state, lifetime: state.lifetime + 1, stream: state.stream + 1, trusted, needsBootstrap: true, reason: 'selection', remote: remoteEmpty(), local: { draft: '', focus: null } });
  }
  if (action.type === 'clear') return finish({ ...createReducerState(), lifetime: state.lifetime + 1, stream: state.stream + 1 });
  if (action.type === 'local') {
    if (typeof action.draft !== 'string' || !(action.focus === null || typeof action.focus === 'string')) throw new TypeError('invalid local state');
    return finish({ ...state, local: { draft: action.draft, focus: action.focus } });
  }
  if (!isCurrentBinding(state, action.binding)) return state;
  if (action.type === 'bootstrap') {
    if (!state.needsBootstrap || state.reason === 'permissions-changed') return state;
    validateValue('snapshot', action.snapshot);
    const snapshot = clone(action.snapshot);
    return finish({ ...state, needsBootstrap: false, reason: null, remote: { ...remoteEmpty(), revision: snapshot.revision, cursor: { epoch: snapshot.epoch, sequence: snapshot.sequence }, tasks: snapshot.taskSummaries, deployment: snapshot.deploymentSummary } });
  }
  if (action.type !== 'event' || state.needsBootstrap) return state;
  const event = action.event;
  try { validateEvent(event, state.trusted.context, state.trusted.descriptor); }
  catch { return bootstrapRequired(state, 'invalid-event'); }
  const cursor = state.remote.cursor;
  if (event.epoch !== cursor.epoch) return bootstrapRequired(state, 'epoch-change');
  if (event.sequence <= cursor.sequence) return state;
  try { validateEventProgress(cursor, { epoch: event.epoch, sequence: event.sequence }); }
  catch { return bootstrapRequired(state, 'event-gap'); }
  if (event.type === 'draft.committed' && event.payload.baseRevision !== state.remote.revision) return bootstrapRequired(state, 'revision-gap');
  if (event.type !== 'draft.committed' && event.revision !== state.remote.revision) return bootstrapRequired(state, 'revision-gap');
  const remote = { ...state.remote, cursor: { epoch: event.epoch, sequence: event.sequence }, revision: event.revision };
  if (event.type === 'task.updated') remote.tasks = [...remote.tasks.filter(t => t.taskId !== event.payload.taskId), clone(event.payload)];
  if (event.type === 'deploy.updated') remote.deployment = clone(event.payload);
  if (event.type === 'monitor.updated') remote.monitor = clone(event.payload);
  if (event.type === 'permissions.changed') {
    remote.permissionNotice = clone(event.payload);
    // Notification invalidates the stream but never installs remote grants.
    return bootstrapRequired({ ...state, remote }, 'permissions-changed');
  }
  return finish({ ...state, remote });
}
