import { CONTRACT_VERSION, validateAdapterRequest, validateAdapterResult, validatePreviewEvent } from './contracts.mjs';

const tags = new Set('a abbr article aside b blockquote br button caption code col colgroup dd details div dl dt em figcaption figure footer form h1 h2 h3 h4 h5 h6 header hr i img input label legend li main mark nav ol option p pre section select small span strong style sub summary sup table tbody td textarea th thead time tr u ul'.split(' '));
const attrs = new Set('alt aria-label aria-hidden checked class colspan disabled for height id lang max maxlength min multiple name placeholder readonly role rowspan selected step title type value width'.split(' '));

function prepareHTML(document, html) {
  // A template is inert, including resource loads; never attach the input tree.
  const template = document.createElement('template');
  template.innerHTML = html;
  const output = document.createElement('template');
  function copy(node, parent) {
    if (node.nodeType === 3) { parent.append(document.createTextNode(node.data)); return; }
    if (node.nodeType !== 1 || node.namespaceURI !== 'http://www.w3.org/1999/xhtml') return;
    const tag = node.localName;
    if (!tags.has(tag)) return;
    const clean = document.createElement(tag);
    if (tag === 'style') clean.textContent = node.textContent;
    else {
      for (const attribute of node.attributes) {
        const name = attribute.name;
        if (attrs.has(name) || name === 'style') clean.setAttribute(name, attribute.value);
        if (tag === 'img' && name === 'src' && /^data:image\/(png|gif|jpeg|webp);base64,[a-z0-9+/=\s]+$/i.test(attribute.value)) clean.setAttribute('src', attribute.value);
      }
      for (const child of node.childNodes) copy(child, clean);
    }
    // Preview input must never steal focus from the composer.
    parent.append(clean);
  }
  for (const child of template.content.childNodes) copy(child, output.content);
  return output.innerHTML;
}

function bridge(binding) {
  return `(() => {
    const binding = ${JSON.stringify(binding)};
    const send = (type, payload) => parent.postMessage({version:${CONTRACT_VERSION}, ...binding, type, payload}, '*');
    addEventListener('error', () => send('preview.error', {message:'Preview rendering error'}));
    addEventListener('unhandledrejection', () => send('preview.error', {message:'Preview rendering error'}));
    addEventListener('submit', event => event.preventDefault(), true);
    addEventListener('click', event => { if (event.target.closest('a,area')) event.preventDefault(); }, true);
    addEventListener('auxclick', event => event.preventDefault(), true);
    addEventListener('DOMContentLoaded', () => {
      let last = -1;
      const resize = () => {
        const height = Math.min(100000, Math.max(0, Math.ceil(document.body.getBoundingClientRect().height)));
        if (height !== last) { last = height; send('preview.resize', {height}); }
      };
      new ResizeObserver(resize).observe(document.body);
      send('preview.ready', {}); resize();
    }, {once:true});
  })();`;
}

/**
 * Create a local-only HTML/CSS preview; no adapter methods are invoked.
 * scriptNonce is optional trusted parent-CSP configuration (22–256 base64/base64url
 * characters, including optional trailing padding), never adapter or child input.
 */
export function createPreviewController({ container, onMessage = () => {}, minHeight = 80, maxHeight = 2000, scriptNonce } = {}) {
  const document = container?.ownerDocument;
  const window = document?.defaultView;
  if (!window || container.nodeType !== 1 || !container.isConnected) throw new TypeError('Connected browser container required');
  if (scriptNonce !== undefined && (typeof scriptNonce !== 'string' || scriptNonce.length < 22 || scriptNonce.length > 256 || !/^[A-Za-z0-9+/_-]+={0,2}(?![\s\S])/.test(scriptNonce))) throw new TypeError('Invalid scriptNonce');
  if (typeof onMessage !== 'function') throw new TypeError('onMessage must be a function');
  if (!Number.isSafeInteger(minHeight) || !Number.isSafeInteger(maxHeight) || minHeight < 0 || maxHeight < minHeight || maxHeight > 100000) throw new TypeError('Invalid height bounds');
  if (!window.crypto?.getRandomValues || !window.crypto?.randomUUID) throw new TypeError('Secure browser randomness required');
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.hidden = true;
  container.append(status);
  let generation = 0;
  let destroyed = false;
  let frame = null;
  let binding = null;
  const listener = event => {
    if (destroyed || !binding || !frame) return;
    let message;
    try { message = validatePreviewEvent(event, frame.contentWindow, binding); } catch { return; }
    if (message.type === 'preview.resize') frame.style.height = `${Math.min(maxHeight, Math.max(minHeight, message.payload.height))}px`;
    if (message.type === 'preview.error') { status.textContent = message.payload.message; status.hidden = false; }
    onMessage(message);
  };
  window.addEventListener('message', listener);
  function clearFrame() { binding = null; frame?.remove(); frame = null; }
  return Object.freeze({
    get iframe() { return frame; },
    get binding() { return binding && Object.freeze({ ...binding }); },
    async update({ project, request }, preview) {
      if (destroyed) throw new Error('Preview controller destroyed');
      const current = ++generation;
      binding = null;
      status.hidden = true;
      try {
        validateAdapterRequest('renderPreview', request, project);
        // Capture before the first await; caller mutation cannot redirect a pending load.
        const capturedProject = window.structuredClone(project);
        const capturedRequest = window.structuredClone(request);
        const result = await preview;
        if (destroyed || current !== generation) return false;
        validateAdapterResult('renderPreview', result, capturedRequest, capturedProject);
        const html = prepareHTML(document, result.html);
        const nonce = Array.from(window.crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('');
        const nextBinding = Object.freeze({ projectId: capturedRequest.context.projectId, workspaceId: capturedRequest.context.workspaceId, revision: result.revision, nonce, frameInstance: window.crypto.randomUUID() });
        // A srcdoc inherits the parent's CSP; only its trusted nonce authorizes the bridge.
        const bridgeNonce = scriptNonce ?? window.crypto.randomUUID();
        const csp = `default-src 'none'; script-src 'nonce-${bridgeNonce}'; script-src-attr 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'; media-src 'none'`;
        const next = document.createElement('iframe');
        next.setAttribute('sandbox', 'allow-scripts');
        next.setAttribute('referrerpolicy', 'no-referrer');
        next.setAttribute('allow', "camera 'none'; microphone 'none'; geolocation 'none'; clipboard-read 'none'; clipboard-write 'none'; payment 'none'; fullscreen 'none'");
        next.title = 'Isolated project preview';
        next.style.height = `${minHeight}px`;
        next.srcdoc = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${csp}"><script nonce="${bridgeNonce}">${bridge(nextBinding)}</script></head><body>${html}</body></html>`;
        clearFrame();
        frame = next; binding = nextBinding;
        container.append(next);
        return true;
      } catch (error) {
        if (destroyed || current !== generation) return false;
        clearFrame();
        status.textContent = 'Preview could not be rendered';
        status.hidden = false;
        throw error;
      }
    },
    destroy() {
      if (destroyed) return;
      destroyed = true; generation++;
      window.removeEventListener('message', listener);
      clearFrame(); status.remove();
    },
  });
}
