import { validateDescribeResult, validateValue, validateAdapterResult, validateEvent, validateEventProgress } from './contracts.mjs';
import { createPreviewController } from './preview.mjs';

const copy = value => structuredClone(value);
const query = values => '?' + new URLSearchParams(Object.entries(values).map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)]));

/** previewScriptNonce is trusted parent-CSP configuration, never project content. */
export function mountBuilder(root, { base = '/api/builder/v1', reconnectMs = 500, statusChecks = 20, statusIntervalMs = 3000, previewScriptNonce } = {}) {
  if (!root?.isConnected || !root.ownerDocument?.defaultView) throw new TypeError('Connected browser root required');
  if (previewScriptNonce !== undefined && (typeof previewScriptNonce !== 'string' || previewScriptNonce.length < 22 || previewScriptNonce.length > 256 || !/^[A-Za-z0-9+/_-]+={0,2}(?![\s\S])/.test(previewScriptNonce))) throw new TypeError('Invalid previewScriptNonce');
  const doc = root.ownerDocument, win = doc.defaultView;
  const url = new URL(base, win.location.href);
  if (url.origin !== win.location.origin || url.search || url.hash || !Number.isSafeInteger(reconnectMs) || reconnectMs < 50 || !Number.isSafeInteger(statusChecks) || statusChecks < 0 || statusChecks > 20 || !Number.isSafeInteger(statusIntervalMs) || statusIntervalMs < 50) throw new TypeError('Invalid shell options');
  win.crypto.randomUUID();
  base = url.pathname.replace(/\/$/, '');
  const container = doc.createElement('section');
  container.className = 'builder-shell';
  container.innerHTML = `<header><h1>Project editor</h1><nav aria-label="Projects" data-ui="tabs"></nav><label>Workspace <select data-ui="workspace"></select></label><p data-ui="connection" role="status"></p></header>
    <p data-ui="error" role="alert"></p><button data-ui="reconnect" type="button">Reconnect</button>
    <div class="builder-columns"><section data-ui="source-panel"><h2>Source</h2><label>File <select data-ui="files"></select></label><textarea data-ui="source" aria-label="Source code" spellcheck="false"></textarea><p data-ui="draft-status" role="status"></p><div class="builder-actions"><button data-ui="save" type="button">Save draft</button><button data-ui="discard" type="button">Discard local changes and reload</button><button data-ui="prepare" type="button">Prepare deploy</button></div></section>
    <section><h2>Saved preview</h2><p data-ui="preview-label"></p><div data-ui="preview"></div></section></div>
    <section data-ui="compose-panel"><h2>Project request</h2><label>Message <textarea data-ui="composer" maxlength="6000"></textarea></label><div class="builder-actions"><button data-ui="ask" type="button">Ask</button><button data-ui="task" type="button">Create task</button></div><p data-ui="answer" role="status"></p></section>
    <section><h2>Tasks and deployment</h2><ul data-ui="tasks"></ul><p data-ui="deployment" role="status"></p><button data-ui="check-status" type="button" hidden>Check deployment status</button></section>
    <section data-ui="monitor-panel"><h2>Monitor</h2><table><thead><tr><th>Item</th><th>Status</th><th>Summary</th></tr></thead><tbody data-ui="monitor"></tbody></table><p data-ui="monitor-note"></p></section>
    <section data-ui="confirmation" role="region" aria-label="Deploy confirmation" hidden><h2>Confirm deploy</h2><p data-ui="frozen"></p><button data-ui="confirm" type="button">Deploy this revision</button><button data-ui="cancel" type="button">Cancel deploy</button></section>`;
  root.append(container);
  const el = name => container.querySelector(`[data-ui="${name}"]`);
  const text = (name, value) => { el(name).textContent = value; };
  for (const name of ['source-panel', 'compose-panel', 'monitor-panel']) el(name).hidden = true;
  function clearDisplayed() {
    el('source').value = ''; el('composer').value = '';
    for (const name of ['answer', 'tasks', 'monitor', 'monitor-note', 'deployment', 'preview-label', 'frozen', 'tabs', 'files', 'workspace', 'draft-status']) text(name, '');
    el('confirmation').hidden = true;
    el('check-status').hidden = true;
  }
  let destroyed = false, generation = 0, current = null, projects = [], csrf = null, initialController = new AbortController();
  let preview = createPreviewController({ container: el('preview'), scriptNonce: previewScriptNonce });
  const buffers = new Map(), composers = new Map(), deployments = new Map();
  function clearDeployments() {
    for (const operation of deployments.values()) operation.abort.abort();
    deployments.clear();
  }
  const active = s => !destroyed && current === s && !s.abort.signal.aborted;
  const can = (s, capability) => s.project.permissions.find(g => g.workspaceId === s.workspace)?.capabilities.includes(capability);
  const ctx = (s, revision = s.head) => copy({ projectId: s.project.id, workspaceId: s.workspace, adapterVersion: s.project.adapterVersion, baseRevision: revision, requestId: win.crypto.randomUUID() });
  const scopeKey = (p, w) => JSON.stringify([p.id, w, p.adapterVersion]);
  const fileKey = (s, path) => JSON.stringify([s.key, path]);
  const buffer = s => buffers.get(fileKey(s, s.path));
  const dirty = b => b && b.text !== b.saved;
  const path = (s, route) => '/projects/' + encodeURIComponent(s.project.id) + route;
  const fail = (s, error, fallback = 'Request failed. Reconnect or try again.') => {
    if (!active(s)) return;
    if (error.status === 401 || error.status === 403) {
      buffers.clear(); composers.clear(); clearDeployments(); csrf = null;
      s.abort.abort(); current = null; generation++;
      preview.destroy(); preview = createPreviewController({ container: el('preview'), scriptNonce: previewScriptNonce });
      container.querySelectorAll('button,select,textarea').forEach(n => { n.disabled = true; });
      el('reconnect').disabled = false;
      el('confirmation').hidden = true;
      clearDisplayed();
      text('connection', 'Access changed. Reconnect to sign in again.');
    }
    text('error', error.status === 409 ? 'Conflict: a newer saved revision exists. Your local text is retained; discard and reload to use it.' : fallback);
  };
  async function request(route, { context, body, signal = initialController.signal } = {}) {
    const response = await win.fetch(base + route, {
      method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', signal,
      headers: body ? { 'Content-Type': 'application/json', 'X-Builder-CSRF': csrf } : context ? { 'X-Builder-Context': JSON.stringify(context) } : {},
      ...(body ? { body: JSON.stringify({ context, ...body }) } : {}),
    });
    const value = await response.json();
    if (!response.ok || value.ok !== true) throw Object.assign(new Error('Request failed'), { status: response.status, code: value.data?.code || value.error?.code });
    return value.data;
  }
  const read = (s, route, context = ctx(s)) => request(path(s, route), { context, signal: s.abort.signal });
  const post = (s, route, context, body) => request(path(s, route), { context, body, signal: s.abort.signal });
  function options(name, list, selected) {
    el(name).replaceChildren(...list.map(item => { const option = doc.createElement('option'); option.value = item.id; option.textContent = item.label; return option; }));
    if (selected !== undefined) el(name).value = selected;
  }
  function controls(s) {
    if (!active(s)) return;
    const b = buffer(s);
    el('source-panel').hidden = !can(s, 'source');
    el('source').disabled = !b;
    el('save').hidden = !can(s, 'saveDraft') || !can(s, 'source');
    el('save').disabled = !dirty(b) || s.saving || !!b?.uncertain;
    el('discard').disabled = !b || s.saving;
    el('prepare').hidden = !can(s, 'deploy') || !can(s, 'source');
    el('prepare').disabled = s.preparing || deployments.has(s.key) || s.validation?.status !== 'passed';
    el('compose-panel').hidden = !can(s, 'ask') && !can(s, 'propose');
    el('ask').hidden = !can(s, 'ask'); el('task').hidden = !can(s, 'propose');
    el('ask').disabled = el('task').disabled = !!s.composing;
    el('monitor-panel').hidden = !can(s, 'monitor');
    text('draft-status', !b ? 'Choose a file.' : b.uncertain ? 'Save outcome unknown. Local text retained. Discard and reload only after reviewing the saved preview.' : dirty(b) ? b.base !== s.head ? 'Conflict: local changes are based on an older revision.' : 'Unsaved local changes. Preview shows saved content only.' : 'Saved source loaded.');
  }
  function summaries(s) {
    if (!active(s)) return;
    el('tasks').replaceChildren(...s.tasks.map(task => { const li = doc.createElement('li'); li.textContent = `${task.status}: ${task.message} (${task.taskId})`; return li; }));
    const operation = deployments.get(s.key), deployment = operation?.summary || s.deployment;
    text('deployment', deployment ? `${deployment.status}: ${deployment.message || ''} — ${deployment.frozenRevision}` : 'No deployment result reported.');
    el('check-status').hidden = !operation?.operationId || terminal(operation.summary) || !can(s, 'deploy');
    el('check-status').disabled = !!operation?.checking;
    if (s.monitor) {
      el('monitor').replaceChildren(...s.monitor.rows.map(row => { const tr = doc.createElement('tr'); for (const value of [row.id, row.status, row.summary]) { const td = doc.createElement('td'); td.textContent = value; tr.append(td); } return tr; }));
      text('monitor-note', s.monitor.truncated ? 'Only the first monitor rows are shown.' : s.monitor.rows.length ? '' : 'No monitor rows reported.');
    }
  }
  async function loadFile(s, selected = s.path, discard = false) {
    if (!selected || !active(s)) return;
    s.path = selected;
    const serial = ++s.fileSerial, revision = s.head;
    const key = fileKey(s, selected), existing = buffers.get(key);
    if (existing && !discard && (dirty(existing) || existing.uncertain || existing.base === revision)) {
      el('source').value = existing.text; controls(s); return;
    }
    el('source').value = existing?.text || '';
    el('source').disabled = true;
    try {
      const context = ctx(s, revision);
      const result = await read(s, '/source' + query({ paths: [selected], revision }), context);
      validateAdapterResult('readSource', result, { context, paths: [selected], revision }, s.project);
      if (!active(s) || serial !== s.fileSerial || s.head !== revision) return;
      const b = { text: result.files[0].content, saved: result.files[0].content, base: revision, uncertain: false };
      buffers.set(key, b); el('source').value = b.text; controls(s);
    } catch (error) { fail(s, error); }
  }
  async function refresh(s) {
    const serial = ++s.refreshSerial, revision = s.head;
    const work = [];
    if (can(s, 'preview')) {
      const context = ctx(s, revision);
      text('preview-label', `Saved revision ${revision}. Local edits are not previewed. Static HTML/CSS only.`);
      work.push(preview.update({ project: s.project, request: { context, revision } }, read(s, '/preview' + query({ revision }), context)));
    } else text('preview-label', 'Preview is not available for this selection.');
    if (can(s, 'source')) work.push((async () => {
      const result = await read(s, '/draft' + query({ revision }));
      validateValue('manifest', result.manifest);
      if (result.manifest.projectId !== s.project.id || result.manifest.workspaceId !== s.workspace || result.manifest.revision !== revision || result.manifest.adapterVersion.version !== s.project.adapterVersion.version || result.manifest.adapterVersion.artifactHash !== s.project.adapterVersion.artifactHash) throw new Error('Invalid manifest scope');
      validateValue('commitResult', { revision: result.headRevision });
      if (result.validation !== null) {
        validateValue('validation', result.validation);
        if (result.validation.adapterVersion.version !== s.project.adapterVersion.version || result.validation.adapterVersion.artifactHash !== s.project.adapterVersion.artifactHash) throw new Error('Validation adapter mismatch');
      }
      if (result.validation === null && result.manifest.parentRevision !== null) throw new Error('Missing validation');
      if (!active(s) || serial !== s.refreshSerial) return;
      s.validation = result.validation;
      const paths = result.manifest.files.map(f => ({ id: f.path, label: f.path }));
      s.path = paths.some(f => f.id === s.path) ? s.path : paths[0]?.id;
      options('files', paths, s.path); controls(s); await loadFile(s);
    })());
    await Promise.all(work);
  }
  async function save(s) {
    const b = buffer(s);
    if (!active(s) || !can(s, 'saveDraft') || !dirty(b) || b.uncertain || s.saving) return;
    const context = ctx(s, b.base), content = b.text, selected = s.path;
    s.saving = true; controls(s); text('error', '');
    let committing = false;
    try {
      const captured = await post(s, '/draft/validate', context, { operations: [{ type: 'write', path: selected, content }] });
      validateValue('validation', captured.validation);
      if (captured.validation.status !== 'passed') throw new Error('Validation failed');
      if (!active(s)) return;
      committing = true; b.uncertain = true;
      const result = await post(s, '/draft', context, { captureId: captured.captureId });
      validateValue('commitResult', result);
      if (result.code) throw Object.assign(new Error('Conflict'), { status: 409 });
      const authoritative = await read(s, '/source' + query({ revision: result.revision, paths: [selected] }), context);
      validateAdapterResult('readSource', authoritative, { context, revision: result.revision, paths: [selected] }, s.project);
      if (authoritative.files[0].content !== content) throw new Error('Readback differs');
      if (!active(s)) return;
      b.saved = content; b.base = result.revision; b.uncertain = false;
      // The stream may already have delivered an even newer head.
      if (s.head === context.baseRevision) { s.head = result.revision; s.validation = null; }
      await refresh(s).catch(error => fail(s, error, 'Saved source verified, but the saved preview could not be refreshed. Reconnect to refresh.'));
    } catch (error) {
      if (error.status === 409) b.uncertain = false;
      else if (committing) b.uncertain = true;
      fail(s, error, committing ? 'Save outcome unknown. Local text retained. Review saved content before any new write.' : 'Draft was not saved. Check your source and try again.');
    } finally { if (active(s)) { s.saving = false; controls(s); } }
  }
  async function prepare(s) {
    if (!active(s) || s.preparing || deployments.has(s.key) || s.validation?.status !== 'passed' || !can(s, 'deploy')) return;
    const context = ctx(s), revision = s.head, validationDigest = s.validation.validationDigest;
    s.preparing = true; controls(s);
    try {
      const prepared = await post(s, '/deployments/prepare', context, { revision, validationDigest });
      validateAdapterResult('prepareDeploy', prepared, { context, revision, validationDigest }, s.project);
      if (!active(s)) return;
      s.prepared = copy({ context, prepared });
      text('frozen', `Deploy saved revision ${prepared.revision} to ${prepared.target}. Later edits will not change this selection.`);
      el('confirmation').hidden = false; el('confirm').disabled = false;
    } catch (error) { fail(s, error, 'Deploy could not be prepared. No deployment was started.'); }
    finally { if (active(s)) { s.preparing = false; controls(s); } }
  }
  const delay = (s, ms) => new Promise(resolve => {
    const done = () => { win.clearTimeout(timer); s.abort.signal.removeEventListener('abort', done); resolve(); };
    const timer = win.setTimeout(done, ms); s.abort.signal.addEventListener('abort', done, { once: true });
  });
  const terminal = summary => ['succeeded', 'failed'].includes(summary?.status);
  const retained = operation => !destroyed && deployments.get(operation.key) === operation && !operation.abort.signal.aborted;
  function showOperation(operation) {
    if (retained(operation) && current?.key === operation.key) { summaries(current); controls(current); }
  }
  function unknownOperation(operation, message) {
    operation.summary = { status: 'unknown', frozenRevision: operation.prepared.revision, message };
    showOperation(operation);
  }
  function operationFailure(operation, error) {
    if (!retained(operation)) return;
    if (error.status === 401 || error.status === 403) {
      if (current) fail(current, error);
      else { clearDeployments(); buffers.clear(); composers.clear(); csrf = null; clearDisplayed(); }
      return;
    }
    unknownOperation(operation, operation.operationId
      ? 'Outcome unknown. Check deployment status; the start request will not be retried.'
      : 'Operator reconciliation required: no operation ID received. Do not repeat deployment; inspect the deployment system.');
  }
  async function checkOperation(operation, checks = 1, interval = 0) {
    if (!retained(operation) || !operation.operationId || operation.checking || terminal(operation.summary)) return;
    operation.checking = true; showOperation(operation);
    try {
      for (let i = 0; i < checks && retained(operation); i++) {
        if (interval) await delay(operation, interval);
        if (!retained(operation)) return;
        const { context, prepared, operationId } = operation;
        const result = await request(path(operation, '/deployments/' + encodeURIComponent(operationId)), { context, signal: operation.abort.signal });
        validateAdapterResult('deploymentStatus', result, { context, operationId }, operation.project);
        if (result.frozenRevision !== prepared.revision) throw new Error('Frozen revision mismatch');
        if (!retained(operation)) return;
        operation.summary = result; showOperation(operation);
        if (terminal(result)) return;
      }
      if (retained(operation) && interval) unknownOperation(operation, 'Status check budget exhausted; completion remains unknown. Check deployment status for fresh evidence.');
    } catch (error) { operationFailure(operation, error); }
    finally { operation.checking = false; showOperation(operation); }
  }
  async function deploy(s) {
    if (!active(s) || !s.prepared || deployments.has(s.key) || !can(s, 'deploy')) return;
    const operation = { ...copy(s.prepared), project: copy(s.project), key: s.key, abort: new AbortController(), operationId: null, checking: false };
    // Record uncertainty before sending: aborting a selection cannot undo an admitted start.
    deployments.set(s.key, operation); s.prepared = null;
    el('confirmation').hidden = true;
    unknownOperation(operation, 'Start outcome pending. Do not repeat deployment.');
    try {
      const { context, prepared } = operation;
      const started = await request(path(operation, '/deployments'), { context, body: { preparedId: prepared.preparedId }, signal: operation.abort.signal });
      validateAdapterResult('startDeploy', started, { context, preparedId: prepared.preparedId, requestId: context.requestId }, operation.project);
      if (started.frozenRevision !== prepared.revision) throw new Error('Frozen revision mismatch');
      if (!retained(operation)) return;
      operation.operationId = started.operationId;
      operation.summary = { ...started, message: 'Start accepted; completion not yet verified.' }; showOperation(operation);
      await checkOperation(operation, statusChecks, statusIntervalMs);
    } catch (error) { operationFailure(operation, error); }
  }
  async function compose(s, route) {
    const value = el('composer').value;
    if (!active(s) || s.composing || !value.trim() || !can(s, route === '/ask' ? 'ask' : 'propose')) return;
    const context = ctx(s); s.composing = true; controls(s);
    try {
      const result = await post(s, route, context, { text: value });
      validateAdapterResult(route === '/ask' ? 'ask' : 'propose', result, { context, text: value }, s.project);
      if (active(s)) text('answer', route === '/ask' ? result.text : `Task accepted: ${result.taskId}. Awaiting task updates.`);
    } catch (error) { fail(s, error, 'Request outcome unknown. Your message is retained; check tasks before submitting again.'); }
    finally { if (active(s)) { s.composing = false; controls(s); } }
  }
  async function stream(s, context, cursor) {
    const response = await win.fetch(base + path(s, '/events') + query({ cursor }), { credentials: 'same-origin', cache: 'no-store', headers: { 'X-Builder-Context': JSON.stringify(context) }, signal: s.abort.signal });
    if (!response.ok) throw Object.assign(new Error('Stream failed'), { status: response.status });
    if (!response.headers.get('content-type')?.startsWith('text/event-stream')) throw new Error('Invalid stream');
    if (!active(s)) { await response.body.cancel(); return; }
    text('connection', 'Connected to saved updates.');
    const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true });
    let pending = '';
    try {
      while (active(s)) {
        const chunk = await reader.read(); if (chunk.done) break;
        pending += decoder.decode(chunk.value, { stream: true });
        let end;
        while ((end = pending.indexOf('\n\n')) >= 0) {
          const record = pending.slice(0, end); pending = pending.slice(end + 2);
          if (new TextEncoder().encode(record).length > 16450) throw new Error('Oversize event');
          if (record.startsWith(':')) continue;
          if (!record.startsWith('event: builder\ndata: ')) throw new Error('Invalid event framing');
          const event = JSON.parse(record.slice(21));
          validateEvent(event, context, s.project); validateEventProgress(cursor, { epoch: event.epoch, sequence: event.sequence });
          if ((event.type === 'draft.committed' ? event.payload.baseRevision : event.revision) !== s.streamHead) throw new Error('Revision gap');
          cursor = { epoch: event.epoch, sequence: event.sequence }; s.streamHead = event.revision;
          if (!active(s)) return;
          if (event.type === 'permissions.changed') throw new Error('Permissions changed');
          if (event.type === 'draft.committed') { s.head = event.revision; s.validation = null; controls(s); refresh(s).catch(error => fail(s, error)); }
          if (event.type === 'task.updated') s.tasks = [...s.tasks.filter(t => t.taskId !== event.payload.taskId), event.payload];
          if (event.type === 'deploy.updated') s.deployment = event.payload;
          if (event.type === 'monitor.updated') s.monitor = event.payload;
          summaries(s);
        }
        if (pending.length > 16450) throw new Error('Oversize event');
      }
      throw new Error('Stream ended');
    } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
  }
  async function connect(s) {
    try {
      const context = ctx(s);
      if (can(s, 'subscribe')) {
        const snapshot = await read(s, '/bootstrap', context); validateValue('snapshot', snapshot);
        if (!active(s)) return;
        s.head = snapshot.revision; s.streamHead = snapshot.revision; s.tasks = snapshot.taskSummaries; s.deployment = snapshot.deploymentSummary;
        const streaming = stream(s, context, { epoch: snapshot.epoch, sequence: snapshot.sequence });
        streaming.catch(() => {});
        await Promise.all([refresh(s), can(s, 'monitor') ? read(s, '/monitor').then(value => { validateValue('monitor', value); if (active(s)) { s.monitor = value; summaries(s); } }) : null]);
        summaries(s); await streaming;
      } else {
        text('connection', 'Live updates unavailable. Reconnect to refresh saved content.');
        await refresh(s);
        if (can(s, 'monitor')) { const value = await read(s, '/monitor'); validateValue('monitor', value); if (active(s)) { s.monitor = value; summaries(s); } }
        return;
      }
    } catch (error) {
      if (!active(s)) return;
      if (error.status === 401 || error.status === 403) { fail(s, error); return; }
      text('connection', 'Disconnected. Refreshing authorized project state…');
      s.retry = Math.min((s.retry || reconnectMs) * 2, 10000);
      await delay(s, s.retry);
      if (active(s)) await discover(s.project.id, s.workspace, s.retry);
    }
  }
  function select(projectId, workspaceId, retry = 0) {
    if (destroyed) return;
    const project = projects.find(p => p.id === projectId);
    if (!project) throw new TypeError('Unknown project selection');
    current?.abort.abort(); initialController.abort(); initialController = new AbortController();
    generation++;
    const workspace = project.workspaces.find(w => w.id === workspaceId)?.id || project.workspaces[0].id;
    const s = { project: copy(project), workspace, head: project.currentRevision, key: scopeKey(project, workspace), abort: new AbortController(), tasks: [], deployment: null, path: null, refreshSerial: 0, fileSerial: 0, retry };
    current = s;
    preview.destroy(); preview = createPreviewController({ container: el('preview'), scriptNonce: previewScriptNonce });
    container.querySelectorAll('button,select,textarea').forEach(n => { n.disabled = false; });
    el('confirmation').hidden = true; el('source').value = ''; el('composer').value = composers.get(s.key) || '';
    for (const name of ['error', 'answer', 'deployment', 'monitor-note', 'preview-label']) text(name, '');
    el('tasks').replaceChildren(); el('monitor').replaceChildren(); options('files', []);
    options('workspace', project.workspaces, workspace);
    el('tabs').replaceChildren(...projects.map(p => { const button = doc.createElement('button'); button.type = 'button'; button.textContent = p.label; button.setAttribute('aria-pressed', String(p.id === project.id)); button.addEventListener('click', () => select(p.id)); return button; }));
    controls(s); summaries(s); text('connection', 'Loading authorized saved state…');
    return connect(s);
  }
  async function discover(projectId, workspaceId, retry = 0) {
    if (destroyed) return;
    current?.abort.abort(); current = null;
    el('confirmation').hidden = true;
    preview.destroy(); preview = createPreviewController({ container: el('preview'), scriptNonce: previewScriptNonce });
    container.querySelectorAll('button,select,textarea').forEach(n => { n.disabled = true; });
    el('reconnect').disabled = false;
    initialController.abort(); initialController = new AbortController(); const serial = ++generation;
    try {
      const session = await request('/session');
      if (destroyed || serial !== generation) return;
      if (typeof session.csrfToken !== 'string' || !session.csrfToken) throw new Error('Invalid session');
      if (csrf && csrf !== session.csrfToken) { buffers.clear(); composers.clear(); clearDeployments(); clearDisplayed(); }
      csrf = session.csrfToken;
      const result = await request('/projects'); validateDescribeResult(result.projects);
      if (destroyed || serial !== generation) return;
      projects = copy(result.projects);
      if (!projects.length) { clearDisplayed(); preview.destroy(); el('source-panel').hidden = el('compose-panel').hidden = el('monitor-panel').hidden = true; el('tabs').replaceChildren(); el('confirmation').hidden = true; text('connection', 'No accessible projects.'); return; }
      // Do not await the lifetime of an open event stream.
      select(projects.some(p => p.id === projectId) ? projectId : projects[0].id, workspaceId, retry);
    } catch (error) {
      if (!destroyed && serial === generation) { text('connection', 'Unable to connect. Sign in and reconnect.'); if (error.status === 401 || error.status === 403) { buffers.clear(); composers.clear(); clearDeployments(); csrf = null; clearDisplayed(); } }
    }
  }
  el('workspace').addEventListener('change', () => select(current.project.id, el('workspace').value));
  el('files').addEventListener('change', () => loadFile(current, el('files').value));
  el('source').addEventListener('input', () => { const b = current && buffer(current); if (b) { b.text = el('source').value; controls(current); } });
  el('composer').addEventListener('input', () => { if (current) composers.set(current.key, el('composer').value); });
  el('save').addEventListener('click', () => current && save(current));
  el('discard').addEventListener('click', () => current && loadFile(current, current.path, true));
  el('prepare').addEventListener('click', () => current && prepare(current));
  el('confirm').addEventListener('click', () => current && deploy(current));
  el('check-status').addEventListener('click', () => { if (current && active(current) && can(current, 'deploy')) { const operation = deployments.get(current.key); if (operation) checkOperation(operation); } });
  el('cancel').addEventListener('click', () => { if (current) { current.prepared = null; el('confirmation').hidden = true; } });
  el('ask').addEventListener('click', () => current && compose(current, '/ask'));
  el('task').addEventListener('click', () => current && compose(current, '/tasks'));
  el('reconnect').addEventListener('click', () => discover(current?.project.id, current?.workspace));
  const ready = discover();
  return Object.freeze({ ready, select: (projectId, workspaceId) => { select(projectId, workspaceId); }, reconnect: () => discover(current?.project.id, current?.workspace), destroy() {
    if (destroyed) return;
    destroyed = true; generation++; current?.abort.abort(); initialController.abort(); clearDeployments(); preview.destroy(); buffers.clear(); composers.clear(); container.remove(); current = null; csrf = null;
  } });
}
