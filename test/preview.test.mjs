import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { createPreviewController } from '../src/preview.mjs';

const digest = character => `sha256:${character.repeat(64)}`;
function fixture(projectId = 'fixture', revision = digest('a'), html = '<h1>First preview</h1>') {
  const adapterVersion = { version: '1.0.0', artifactHash: digest('b') };
  const project = { id: projectId, label: 'Synthetic project', adapterVersion, workspaces: [{ id: 'main', label: 'Main' }], capabilities: [{ workspaceId: 'main', capabilities: ['preview'] }], permissions: [{ workspaceId: 'main', capabilities: ['preview'] }], currentRevision: revision, deploymentStatus: 'idle' };
  const request = { context: { projectId, workspaceId: 'main', adapterVersion, baseRevision: revision, requestId: '12345678-1234-4234-8234-123456789abc' }, revision };
  return { scope: { project, request }, preview: { revision, html, csp: "default-src * 'unsafe-inline' 'unsafe-eval'", manifestDigest: digest('c') } };
}

test('module imports without a DOM and rejects non-browser construction', () => {
  assert.equal(typeof createPreviewController, 'function');
  assert.throws(() => createPreviewController(), /Connected browser container/);
});

for (const strictParentCsp of [false, true]) test(`real Chromium sandbox, CSP, scoped messages and hot-reload lifecycle (strict parent: ${strictParentCsp})`, {
  skip: !process.env.CONTRACT_BROWSER_MODULE && !process.env.CONTRACT_BROWSER_BINARY,
  timeout: 60000,
}, async t => {
  assert.ok(process.env.CONTRACT_BROWSER_MODULE, 'CONTRACT_BROWSER_MODULE is required');
  assert.ok(process.env.CONTRACT_BROWSER_BINARY, 'CONTRACT_BROWSER_BINARY is required');
  const { chromium } = await import(process.env.CONTRACT_BROWSER_MODULE);
  const attempts = [];
  const parentNonce = randomBytes(32).toString('base64');
  const server = createServer(async (req, res) => {
    try {
      if (req.url === '/') {
        res.setHeader('Content-Type', 'text/html');
        res.setHeader('Set-Cookie', 'syntheticCredential=parent-only; SameSite=Strict');
        if (strictParentCsp) res.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${parentNonce}' 'strict-dynamic'; script-src-attr 'none'; style-src 'unsafe-inline'; connect-src 'self'; frame-src 'self'; img-src data:; object-src 'none'; base-uri 'none'; form-action 'none'`);
        res.end(`<script nonce="${parentNonce}" type="importmap">{"imports":{"@noble/hashes/sha256":"/noble/sha256.js","@noble/hashes/utils":"/noble/utils.js","@noble/hashes/crypto":"/noble/crypto.js"}}</script><input id="composer"><div id="preview"></div><script nonce="${parentNonce}" type="module">import { createPreviewController } from '/preview.mjs'; window.previewFactory = createPreviewController; window.trustedNonce = ${JSON.stringify(strictParentCsp ? parentNonce : null)};</script>`);
        return;
      }
      let file;
      if (['/preview.mjs', '/contracts.mjs'].includes(req.url)) file = new URL(`../src${req.url}`, import.meta.url);
      if (/^\/noble\/[a-zA-Z0-9_-]+\.js$/.test(req.url)) file = new URL(`../node_modules/@noble/hashes/esm/${req.url.slice(7)}`, import.meta.url);
      if (!file) { if (req.url.startsWith('/blocked')) attempts.push(req.url); res.writeHead(404).end(); return; }
      res.setHeader('Content-Type', 'text/javascript'); res.end(await readFile(file));
    } catch { res.writeHead(404).end(); }
  });
  let browser;
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;
    browser = await chromium.launch({ executablePath: process.env.CONTRACT_BROWSER_BINARY, headless: true, args: ['--no-sandbox'] });
    t.diagnostic(`Actual browser: ${await browser.version()}`);
    const page = await browser.newPage();
    await page.route('**/*', route => new URL(route.request().url()).hostname === '127.0.0.1' ? route.continue() : route.abort());
    await page.goto(origin);
    await page.waitForFunction(() => !!window.previewFactory);
    await page.evaluate(async () => {
      const createPreviewController = window.previewFactory;
      window.messages = [];
      window.previewListeners = new Set();
      window.previewListenerRemovals = 0;
      const add = window.addEventListener, remove = window.removeEventListener;
      window.addEventListener = function(type, callback, options) {
        if (type === 'message') previewListeners.add(callback);
        return add.call(this, type, callback, options);
      };
      window.removeEventListener = function(type, callback, options) {
        if (type === 'message' && previewListeners.delete(callback)) previewListenerRemovals++;
        return remove.call(this, type, callback, options);
      };
      window.controller = createPreviewController({ container: document.querySelector('#preview'), onMessage: message => messages.push(message), minHeight: 100, maxHeight: 600, ...(trustedNonce ? { scriptNonce: trustedNonce } : {}) });
      localStorage.setItem('syntheticCredential', 'parent-only');
    });
    const load = async data => {
      await page.evaluate(async data => { window.lastFixture = data; await controller.update(data.scope, data.preview); }, data);
      await page.waitForFunction(() => messages.some(m => m.type === 'preview.ready' && m.frameInstance === controller.binding?.frameInstance));
      return page.frames().find(frame => frame.parentFrame());
    };
    await t.test('trusted nonce validation fails before installing DOM or listeners', async () => {
      for (const scriptNonce of [null, 12, {}, '', 'a'.repeat(21), 'a'.repeat(257), 'a'.repeat(22) + '\n', 'a'.repeat(22) + '" onload="bad', 'a'.repeat(22) + "'; script-src *", '=abcd'.repeat(6)]) {
        await assert.rejects(page.evaluate(scriptNonce => previewFactory({ container: document.querySelector('#preview'), scriptNonce }), scriptNonce), /Invalid scriptNonce/);
      }
      assert.equal(await page.locator('#preview > *').count(), 1);
      assert.equal(await page.evaluate(() => previewListeners.size), 1);
    });
    if (strictParentCsp) await t.test('inherited policy blocks missing or nonmatching bridge nonce', async () => {
      for (const scriptNonce of [undefined, 'b'.repeat(32)]) {
        await page.evaluate(async ({ data, scriptNonce }) => {
          const container = document.createElement('div'); container.id = 'negative'; document.body.append(container);
          window.negativeMessages = [];
          window.negative = previewFactory({ container, scriptNonce, onMessage: message => negativeMessages.push(message) });
          await negative.update(data.scope, data.preview);
        }, { data: fixture(), scriptNonce });
        await page.frameLocator('#negative iframe').locator('h1').waitFor();
        const frame = await page.locator('#negative iframe').elementHandle().then(handle => handle.contentFrame());
        await frame.waitForFunction(() => document.readyState === 'complete');
        await page.waitForTimeout(100);
        assert.equal(await page.evaluate(() => negativeMessages.length), 0);
        await page.evaluate(() => { negative.destroy(); document.querySelector('#negative').remove(); });
      }
    });
    const first = fixture();
    let child = await load(first);
    assert.equal(await child.locator('h1').textContent(), 'First preview');
    assert.equal(await page.locator('iframe').getAttribute('sandbox'), 'allow-scripts');
    assert.match(await child.locator('meta[http-equiv]').getAttribute('content'), /connect-src 'none'/);
    assert.equal(await child.evaluate(() => {
      try { return parent.document.querySelector('#composer').value; } catch (e) { return e.name; }
    }), 'SecurityError');
    assert.deepEqual(await child.evaluate(() => {
      const results = [];
      for (const read of [() => document.cookie, () => localStorage.getItem('syntheticCredential'), () => parent.localStorage.getItem('syntheticCredential')]) {
        try { read(); results.push('ACCESSIBLE'); } catch (e) { results.push(e.name); }
      }
      return results;
    }), ['SecurityError', 'SecurityError', 'SecurityError']);

    await t.test('exact message source, origin, identities, F0 shape and height clamp', async () => {
      const result = await page.evaluate(() => {
        const binding = controller.binding;
        const base = { version: 1, ...binding, type: 'preview.resize', payload: { height: 450 } };
        const before = messages.length;
        const emit = (data, source = controller.iframe.contentWindow, origin = 'null') => dispatchEvent(new MessageEvent('message', { data, source, origin }));
        emit(base, window); emit(base, controller.iframe.contentWindow, location.origin);
        emit({ ...base, nonce: '0'.repeat(64) });
        emit({ ...base, revision: 'sha256:' + '0'.repeat(64) });
        emit({ ...base, projectId: 'wrong' }); emit({ ...base, workspaceId: 'wrong' });
        emit({ ...base, frameInstance: crypto.randomUUID() });
        emit({ ...base, payload: { height: '450' } }); emit({ ...base, payload: { height: 100001 } });
        emit({ ...base, payload: { height: -1 } }); emit({ ...base, payload: { height: 1.5 } });
        emit({ ...base, payload: { height: NaN } }); emit({ ...base, extra: 'no' });
        for (const type of ['save', 'deploy', 'createTask', 'preview.save', 'preview.deploy']) emit({ ...base, type, payload: {} });
        const denied = messages.length === before;
        emit(base);
        const accepted = messages.length === before + 1 && controller.iframe.style.height === '450px';
        emit({ ...base, payload: { height: 100000 } }); const upper = controller.iframe.style.height;
        emit({ ...base, payload: { height: 0 } }); const lower = controller.iframe.style.height;
        emit({ ...base, type: 'preview.error', payload: { message: '<img src=x onerror=alert(1)>' } });
        return { denied, accepted, upper, lower, text: document.querySelector('[role=status]').textContent, injected: !!document.querySelector('[role=status] img') };
      });
      assert.deepEqual(result, { denied: true, accepted: true, upper: '600px', lower: '100px', text: '<img src=x onerror=alert(1)>', injected: false });
      // Genuine browser-delivered child event, not only a synthetic MessageEvent.
      await child.evaluate(binding => parent.postMessage({ version: 1, ...binding, type: 'preview.resize', payload: { height: 333 } }, '*'), await page.evaluate(() => controller.binding));
      await page.waitForFunction(() => controller.iframe.style.height === '333px');
    });

    await t.test('hot reload preserves shell focus/text and invalidates old frames', async () => {
      await page.locator('#composer').fill('unfinished composer text');
      await page.locator('#composer').focus();
      await page.evaluate(() => { window.oldBinding = controller.binding; window.oldWindow = controller.iframe.contentWindow; window.oldFrame = controller.iframe; });
      child = await load(fixture('fixture', digest('d'), '<h2>Updated</h2><input autofocus value="do not steal focus">'));
      assert.equal(await child.locator('h2').textContent(), 'Updated');
      assert.equal(await page.locator('#composer').inputValue(), 'unfinished composer text');
      assert.equal(await page.locator('#composer').evaluate(input => document.activeElement === input), true);
      assert.equal(await page.evaluate(() => oldFrame.isConnected), false);
      assert.equal(await page.evaluate(() => {
        const before = messages.length;
        const cspAsBinding = { version: 1, ...controller.binding, nonce: trustedNonce || 'a'.repeat(32), type: 'preview.ready', payload: {} };
        dispatchEvent(new MessageEvent('message', { data: cspAsBinding, source: controller.iframe.contentWindow, origin: 'null' }));
        const data = { version: 1, ...oldBinding, type: 'preview.ready', payload: {} };
        dispatchEvent(new MessageEvent('message', { data, source: oldWindow, origin: 'null' }));
        dispatchEvent(new MessageEvent('message', { data, source: controller.iframe.contentWindow, origin: 'null' }));
        return messages.length === before && oldBinding.nonce !== controller.binding.nonce && oldBinding.frameInstance !== controller.binding.frameInstance;
      }), true);
    });

    await t.test('malicious markup, user scripts, network, forms and navigation stay blocked', async () => {
      const hostile = `<div nonce="${parentNonce}" id="user-nonce">Untrusted nonce</div><script nonce="${parentNonce}">parent.postMessage('NONCED_USER_SCRIPT_RAN','*')</script><meta http-equiv="refresh" content="0;url=${origin}/blocked-refresh"><base href="${origin}/blocked-base"><script>parent.postMessage('USER_SCRIPT_RAN','*')</script><script src="${origin}/blocked-script"></script><iframe src="${origin}/blocked-frame"></iframe><object data="${origin}/blocked-object"></object><img src="${origin}/blocked-image" onerror="parent.postMessage('HANDLER_RAN','*')"><style>@import '${origin}/blocked-style'; body { background-image: url('${origin}/blocked-css'); color: rgb(1, 2, 3); }</style><a href="${origin}/blocked-link" target="_top">Navigate</a><form action="${origin}/blocked-form"><input name="x" value="y"><button>Submit</button></form><h1>Safe remainder</h1>`;
      child = await load(fixture('fixture', digest('e'), hostile));
      assert.equal(await child.locator('h1').textContent(), 'Safe remainder');
      assert.equal(await child.locator('script').count(), 1);
      assert.equal(await child.locator('#user-nonce').getAttribute('nonce'), null);
      const bridgeNonce = await child.locator('script').evaluate(script => script.nonce);
      if (strictParentCsp) assert.equal(bridgeNonce, parentNonce);
      else assert.notEqual(bridgeNonce, parentNonce);
      assert.notEqual(bridgeNonce, await page.evaluate(() => controller.binding.nonce));
      assert.equal(await child.locator('base, iframe, object, meta[http-equiv=refresh], [onerror], a[href], form[action]').count(), 0);
      assert.equal(await child.locator('body').evaluate(body => getComputedStyle(body).color), 'rgb(1, 2, 3)');
      assert.equal(await child.evaluate(async url => {
        try { await fetch(url); return 'NETWORK_ALLOWED'; } catch { return 'blocked'; }
      }, `${origin}/blocked-fetch`), 'blocked');
      // DevTools injects test probes after preparation to test actual CSP independently.
      await child.evaluate(url => {
        const inline = document.createElement('script'); inline.textContent = "document.body.dataset.userScript = 'ran'"; document.body.append(inline);
        const wrongNonce = document.createElement('script'); wrongNonce.nonce = 'a'.repeat(32); wrongNonce.textContent = "document.body.dataset.userScript = 'wrong nonce ran'"; document.body.append(wrongNonce);
        const remote = document.createElement('script'); remote.src = url; document.body.append(remote);
        const form = document.querySelector('form'); form.action = url; form.submit();
      }, `${origin}/blocked-probe`);
      await child.locator('a').click();
      await child.locator('button').click();
      await page.waitForTimeout(200);
      assert.equal(await child.locator('body').getAttribute('data-user-script'), null);
      assert.equal(page.url(), `${origin}/`);
      assert.equal(await child.evaluate(() => location.href), 'about:srcdoc');
      assert.equal(await child.locator('h1').textContent(), 'Safe remainder');
      assert.deepEqual(attempts, []);
    });

    await t.test('slow render/project switch, immutable capture and destroy', async () => {
      const slow = fixture('old-project');
      const newest = fixture('new-project', digest('f'), '<h1>Newest project</h1>');
      await page.evaluate(data => {
        window.slowResult = data.preview;
        window.slowDone = controller.update(data.scope, new Promise(resolve => { window.releaseSlow = resolve; }));
        data.scope.request.context.projectId = 'mutated';
      }, slow);
      child = await load(newest);
      assert.equal(await page.evaluate(async () => { releaseSlow(slowResult); return await slowDone; }), false);
      assert.equal(await child.locator('h1').textContent(), 'Newest project');
      assert.equal(await page.evaluate(() => controller.binding.projectId), 'new-project');
      await page.evaluate(data => {
        window.staleRejection = controller.update(data.scope, new Promise((resolve, reject) => { window.rejectStale = reject; }));
      }, slow);
      child = await load(newest);
      assert.equal(await page.evaluate(async () => { rejectStale(new Error('stale render')); return await staleRejection; }), false);
      assert.equal(await child.locator('h1').textContent(), 'Newest project');
      const capture = fixture('captured', digest('d'), '<h1>Captured</h1>');
      await page.evaluate(data => {
        window.pendingCapture = controller.update(data.scope, new Promise(resolve => { window.releaseCapture = () => resolve(data.preview); }));
        data.scope.project.id = 'mutated'; data.scope.request.context.workspaceId = 'mutated';
        releaseCapture();
      }, capture);
      assert.equal(await page.evaluate(() => pendingCapture), true);
      await page.waitForFunction(() => messages.some(m => m.type === 'preview.ready' && m.frameInstance === controller.binding?.frameInstance));
      assert.equal(await page.evaluate(() => controller.binding.projectId), 'captured');
      assert.equal(await page.evaluate(async data => {
        const frame = controller.iframe.contentWindow, binding = controller.binding;
        window.pendingDestroy = controller.update(data.scope, new Promise(resolve => { window.releaseDestroy = () => resolve(data.preview); }));
        controller.destroy(); controller.destroy();
        const before = messages.length;
        dispatchEvent(new MessageEvent('message', { source: frame, origin: 'null', data: { version: 1, ...binding, type: 'preview.ready', payload: {} } }));
        releaseDestroy();
        return await pendingDestroy === false && messages.length === before && controller.iframe === null && document.querySelector('#preview').children.length === 0;
      }, newest), true);
      assert.deepEqual(await page.evaluate(() => ({ remaining: previewListeners.size, removed: previewListenerRemovals })), { remaining: 0, removed: strictParentCsp ? 3 : 1 });
      await assert.rejects(page.evaluate(data => controller.update(data.scope, data.preview), newest), /destroyed/);
    });

    await t.test('invalid grants/results fail closed without rendering error HTML', async () => {
      await page.evaluate(async () => { const { createPreviewController } = await import('/preview.mjs'); window.controller = createPreviewController({ container: document.querySelector('#preview') }); });
      const denied = fixture(); denied.scope.project.permissions[0].capabilities = [];
      await assert.rejects(page.evaluate(data => controller.update(data.scope, data.preview), denied), /capability not granted/);
      const mismatch = fixture(); mismatch.preview.revision = digest('d');
      await assert.rejects(page.evaluate(data => controller.update(data.scope, data.preview), mismatch), /revision mismatch/);
      const extra = fixture(); extra.preview.token = 'synthetic-forbidden';
      await assert.rejects(page.evaluate(data => controller.update(data.scope, data.preview), extra), /missing or unknown property/);
      assert.equal(await page.locator('#preview iframe').count(), 0);
      assert.equal(await page.locator('[role=status]').textContent(), 'Preview could not be rendered');
      await page.evaluate(() => controller.destroy());
    });
  } finally {
    await browser?.close();
    await new Promise(resolve => server.close(resolve));
  }
});
