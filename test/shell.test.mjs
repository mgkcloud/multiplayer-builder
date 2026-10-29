import test from 'node:test';
import assert from 'node:assert/strict';
import { mountBuilder } from '../src/shell.mjs';
import { createUIFixture } from './ui-fixture.mjs';

const ui = (page, name) => page.locator(`[data-ui="${name}"]`);
const waitSource = (page, expected) => page.waitForFunction(expected => document.querySelector('[data-ui="source"]').value === expected && !document.querySelector('[data-ui="source"]').disabled, expected);
const previewText = (page, value) => page.waitForFunction(value => {
  const frame = document.querySelector('iframe');
  const label = document.querySelector('[data-ui="preview-label"]').textContent;
  return frame?.title && previewEvents.get(frame)?.some(event => event.type === 'preview.ready' && label.includes(event.revision));
}, value).then(async () => {
  await page.frameLocator('iframe').locator('h1').filter({ hasText: value }).waitFor();
});

test('shell import is inert and non-browser mount rejected', () => {
  assert.equal(typeof mountBuilder, 'function'); assert.throws(() => mountBuilder(null), /Connected browser root/);
});

for (const strictParentCsp of [false, true]) test(`real two Chromium clients with real F2 HTTP and F1 revision store (strict parent: ${strictParentCsp})`, {
  skip: !process.env.CONTRACT_BROWSER_MODULE && !process.env.CONTRACT_BROWSER_BINARY,
  timeout: 90000,
}, async t => {
  assert.ok(process.env.CONTRACT_BROWSER_MODULE); assert.ok(process.env.CONTRACT_BROWSER_BINARY);
  const { chromium } = await import(process.env.CONTRACT_BROWSER_MODULE);
  const f = await createUIFixture({ strictParentCsp });
  const browsers = [], errors = [], blocked = [];
  try {
    for (let i = 0; i < 2; i++) browsers.push(await chromium.launch({ executablePath: process.env.CONTRACT_BROWSER_BINARY, headless: true, args: ['--no-sandbox'] }));
    t.diagnostic('Actual browsers: ' + (await Promise.all(browsers.map(b => b.version()))).join(', '));
    const pages = [];
    for (const [i, browser] of browsers.entries()) {
      const page = await browser.newPage({ viewport: { width: i ? 390 : 1280, height: 900 } });
      page.on('pageerror', error => errors.push(error.message));
      await page.route('**/*', route => { if (new URL(route.request().url()).origin === f.origin) return route.continue(); blocked.push(route.request().url()); return route.abort(); });
      await page.goto(f.origin); await page.evaluate(() => mounted); await waitSource(page, '<h1>alpha seed</h1>');
      pages.push(page);
      await previewText(page, 'alpha seed');
      if (strictParentCsp) {
        const policy = (await page.request.get(f.origin)).headers()['content-security-policy'];
        assert.match(policy, /script-src 'nonce-[^']+' 'strict-dynamic'; script-src-attr 'none'/);
        assert.doesNotMatch(policy.split('script-src ')[1].split(';')[0], /unsafe-inline|unsafe-eval/);
      }
    }
    const [a, b] = pages;
    await t.test('invalid trusted shell nonce rejected before DOM mutation or requests', async () => {
      const before = f.requests.length;
      for (const previewScriptNonce of [null, 1, {}, '', 'a'.repeat(21), 'a'.repeat(257), 'a'.repeat(22) + '\n', 'a'.repeat(22) + '" onload="bad', 'a'.repeat(22) + "'; script-src *"]) {
        await assert.rejects(a.evaluate(previewScriptNonce => mountBuilder(document.querySelector('#app'), { previewScriptNonce }), previewScriptNonce), /Invalid previewScriptNonce/);
      }
      assert.equal(await a.locator('.builder-shell').count(), 1);
      assert.equal(f.requests.length, before);
    });
    await t.test('usable source, saved preview, actual connection, responsive layout and honest genesis', async () => {
      for (const page of pages) {
        await previewText(page, 'alpha seed');
        assert.equal(await ui(page, 'tabs').locator('button').count(), 3);
        assert.equal(await ui(page, 'prepare').isDisabled(), true);
        assert.match(await ui(page, 'connection').textContent(), /Connected/);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        assert.equal(await page.locator('iframe').getAttribute('sandbox'), 'allow-scripts');
      }
      assert.match(await ui(a, 'monitor').textContent(), /Synthetic monitor only/);
    });
    await t.test('one save is read back by F1 and reaches both isolated previews without losing composer focus', async () => {
      await ui(b, 'composer').fill('keep this message'); await ui(b, 'composer').focus();
      await ui(a, 'source').fill('<h1>shared saved edit</h1>'); await ui(a, 'save').click();
      await waitSource(a, '<h1>shared saved edit</h1>'); await previewText(b, 'shared saved edit'); await waitSource(b, '<h1>shared saved edit</h1>');
      assert.equal(await ui(b, 'composer').inputValue(), 'keep this message');
      assert.equal(await ui(b, 'composer').evaluate(n => n === document.activeElement), true);
      const entry = f.entries.get('alpha'), result = await entry.store.read({ principalId: 'synthetic', context: entry.context(), paths: ['index.html'] });
      assert.equal(result.files[0].content, '<h1>shared saved edit</h1>'); assert.equal(f.starts.length, 0);
    });
    await t.test('remote saves preserve dirty text/base; a stale save conflicts instead of overwriting', async () => {
      await ui(b, 'source').fill('<h1>my local dirty text</h1>');
      await ui(a, 'source').fill('<h1>new remote revision</h1>'); await ui(a, 'save').click();
      await previewText(b, 'new remote revision');
      assert.equal(await ui(b, 'source').inputValue(), '<h1>my local dirty text</h1>');
      assert.match(await ui(b, 'draft-status').textContent(), /Conflict/);
      await ui(b, 'save').click(); await ui(b, 'error').filter({ hasText: 'Conflict:' }).waitFor();
      assert.equal(await ui(b, 'source').inputValue(), '<h1>my local dirty text</h1>');
      await b.evaluate(() => builder.select('beta')); await waitSource(b, '<h1>beta seed</h1>');
      await b.evaluate(() => builder.select('alpha')); await waitSource(b, '<h1>my local dirty text</h1>');
      assert.match(await ui(b, 'draft-status').textContent(), /Conflict/);
      await ui(b, 'discard').click(); await waitSource(b, '<h1>new remote revision</h1>');
    });
    await t.test('deploy confirmation is frozen even after a later save; no automatic provider start', async () => {
      await a.waitForFunction(() => !document.querySelector('[data-ui="prepare"]').disabled);
      await ui(a, 'prepare').click(); await ui(a, 'confirmation').waitFor({ state: 'visible' });
      const frozen = await ui(a, 'frozen').textContent(), oldRevision = f.entries.get('alpha').descriptor().currentRevision;
      assert.ok(frozen.includes(oldRevision)); assert.match(frozen, /synthetic-target/); assert.equal(f.starts.length, 0);
      await ui(a, 'source').fill('<h1>later revision</h1>'); await ui(a, 'save').click(); await previewText(b, 'later revision');
      assert.equal(await ui(a, 'frozen').textContent(), frozen);
      await ui(a, 'confirm').click(); await ui(a, 'deployment').filter({ hasText: 'unknown:' }).waitFor();
      assert.equal(f.starts.length, 1); assert.equal(f.starts[0].prepared.revision, oldRevision);
      assert.equal(f.starts[0].context.baseRevision, oldRevision);
      assert.notEqual(f.entries.get('alpha').descriptor().currentRevision, oldRevision);
    });
    await t.test('delayed previous-project preview cannot install after selection changes', async () => {
      const release = f.hold('beta');
      try {
        await a.evaluate(() => builder.select('beta')); await waitSource(a, '<h1>beta seed</h1>');
        await a.evaluate(() => builder.select('alpha')); await waitSource(a, '<h1>later revision</h1>'); await previewText(a, 'later revision');
        release();
        await a.waitForTimeout(100);
        assert.equal(await a.frameLocator('iframe').locator('h1').textContent(), 'later revision');
        assert.equal(await ui(a, 'tabs').locator('[aria-pressed="true"]').textContent(), 'alpha');
      } finally { release(); }
    });
    await t.test('unsupported controls absent; granted ask/task return genuine adapter results', async () => {
      await b.evaluate(() => builder.select('readonly')); await waitSource(b, '<h1>readonly seed</h1>');
      for (const name of ['save', 'prepare', 'compose-panel', 'monitor-panel']) assert.equal(await ui(b, name).isVisible(), false);
      await a.evaluate(() => builder.select('alpha')); await waitSource(a, '<h1>later revision</h1>');
      await ui(a, 'composer').fill('<img src=x onerror=alert(1)>'); await ui(a, 'ask').click(); await ui(a, 'answer').filter({ hasText: 'Synthetic answer:' }).waitFor();
      assert.equal(await ui(a, 'answer').locator('img').count(), 0);
      await ui(a, 'task').click(); await ui(a, 'answer').filter({ hasText: 'Task accepted:' }).waitFor();
    });
    await t.test('EOF/gap triggers fresh scoped bootstrap, retaining input without whole-room polling', async () => {
      await ui(a, 'source').fill('<h1>survive reconnect</h1>');
      const count = f.requests.filter(r => r.url.includes('/bootstrap')).length;
      const entry = f.entries.get('alpha'), snap = await entry.adapter.snapshot();
      for (const sub of entry.subscribers) await sub.emit({ version: 1, projectId: 'alpha', workspaceId: 'draft', epoch: snap.epoch, sequence: snap.sequence + 2, revision: snap.revision, type: 'permissions.changed', payload: { capabilities: allCaps() } });
      await a.waitForFunction(() => document.querySelector('[data-ui="connection"]').textContent.includes('Disconnected'));
      await waitSource(a, '<h1>survive reconnect</h1>');
      await a.waitForFunction(() => document.querySelector('[data-ui="connection"]').textContent.includes('Connected'));
      await previewText(a, 'later revision');
      assert.ok(f.requests.filter(r => r.url.includes('/bootstrap')).length > count);
      assert.equal(f.requests.filter(r => /\/projects\?/.test(r.url)).length, 0);
    });
    await t.test('cancelled commit remains uncertain across selection changes; never repeats a write', async () => {
      const release = f.hold('alpha', 'commit');
      try {
        await ui(a, 'source').fill('<h1>interrupted save</h1>');
        const dispatched = a.waitForRequest(r => r.method() === 'POST' && r.url().endsWith('/draft'));
        await ui(a, 'save').click(); await dispatched; await release.entered;
        await a.evaluate(() => builder.select('beta')); await waitSource(a, '<h1>beta seed</h1>');
        await a.evaluate(() => builder.select('alpha')); await waitSource(a, '<h1>interrupted save</h1>');
        assert.match(await ui(a, 'draft-status').textContent(), /unknown/);
        assert.equal(await ui(a, 'save').isDisabled(), true);
        release(); await previewText(a, 'interrupted save');
        assert.match(await ui(a, 'draft-status').textContent(), /unknown/);
        await ui(a, 'discard').click(); await waitSource(a, '<h1>interrupted save</h1>');
        await a.waitForFunction(() => document.querySelector('[data-ui="draft-status"]').textContent === 'Saved source loaded.');
      } finally { release(); }
    });
    await t.test('auth lifetime replacement clears private buffers, destroy cancels old work', async () => {
      f.rotate(); await a.evaluate(() => builder.reconnect()); await waitSource(a, '<h1>interrupted save</h1>');
      await previewText(a, 'interrupted save');
      assert.equal(await ui(a, 'composer').inputValue(), '');
      await Promise.all(pages.map(page => page.evaluate(() => { builder.destroy(); builder.destroy(); })));
      for (const page of pages) assert.equal(await page.locator('.builder-shell').count(), 0);
      await a.waitForTimeout(100);
      assert.equal(f.entries.get('alpha').subscribers.size, 0);
      assert.deepEqual(errors, []); assert.deepEqual(blocked, []);
      assert.ok(f.requests.filter(r => /\/source|\/bootstrap|\/events/.test(r.url)).every(r => r.context && r.cookie?.includes('synthetic=fixture')));
    });
  } finally { await Promise.all(browsers.map(b => b.close())); await f.close(); }
});
function allCaps() { return ['source', 'saveDraft', 'preview', 'subscribe', 'ask', 'propose', 'monitor', 'deploy']; }

const deploymentReads = f => f.requests.filter(r => r.method === 'GET' && /\/deployments\/[0-9a-f-]+$/.test(r.url));
async function prepareDeployment(page) {
  await ui(page, 'source').fill('<h1>validated deployment</h1>');
  await ui(page, 'save').click(); await waitSource(page, '<h1>validated deployment</h1>');
  await page.waitForFunction(() => !document.querySelector('[data-ui="prepare"]').disabled);
  await ui(page, 'prepare').click(); await ui(page, 'confirmation').waitFor({ state: 'visible' });
}
for (const scenario of ['progression', 'manual', 'zero-budget', 'failed', 'switch-start', 'switch-status', 'ambiguous', 'revoked', 'rotated']) test(`asynchronous deployment: ${scenario} (real Chromium, synthetic transport)`, {
  skip: !process.env.CONTRACT_BROWSER_MODULE && !process.env.CONTRACT_BROWSER_BINARY, timeout: 90000,
}, async () => {
  const { chromium } = await import(process.env.CONTRACT_BROWSER_MODULE);
  const f = await createUIFixture({ strictParentCsp: true, shellOptions: { statusChecks: scenario === 'zero-budget' ? 0 : scenario === 'manual' ? 2 : 3 },
    deploymentStatuses: scenario === 'failed' ? ['failed'] : scenario === 'zero-budget' ? ['succeeded'] : ['unknown', 'unknown', 'succeeded'], ambiguousStart: scenario === 'ambiguous' });
  const browser = await chromium.launch({ executablePath: process.env.CONTRACT_BROWSER_BINARY, headless: true, args: ['--no-sandbox'] });
  const errors = [], blocked = [];
  let release;
  try {
    const page = await browser.newPage(); page.on('pageerror', e => errors.push(e.message));
    await page.route('**/*', route => { if (new URL(route.request().url()).origin === f.origin) return route.continue(); blocked.push(route.request().url()); return route.abort(); });
    await page.goto(f.origin); await waitSource(page, '<h1>alpha seed</h1>'); await prepareDeployment(page);
    const frozen = f.entries.get('alpha').descriptor().currentRevision;
    if (['switch-start', 'ambiguous', 'rotated'].includes(scenario)) release = f.hold('alpha', 'start');
    if (['switch-status', 'revoked'].includes(scenario)) release = f.hold('alpha', 'status');
    await ui(page, 'confirm').click();
    if (release) await release.entered;
    if (scenario.startsWith('switch-') || scenario === 'ambiguous') {
      await page.evaluate(() => builder.select('beta')); await waitSource(page, '<h1>beta seed</h1>');
      if (scenario !== 'ambiguous') {
        release(); await page.waitForTimeout(300);
        assert.doesNotMatch(await ui(page, 'deployment').textContent(), /succeeded|validated deployment/);
        assert.equal(await ui(page, 'check-status').isVisible(), false);
      }
      await page.evaluate(() => builder.select('alpha')); await waitSource(page, '<h1>validated deployment</h1>');
      assert.equal(await ui(page, 'prepare').isDisabled(), true);
      assert.equal(await ui(page, 'confirmation').isVisible(), false);
      if (scenario === 'ambiguous') release();
    }
    if (scenario === 'manual') {
      await ui(page, 'deployment').filter({ hasText: 'budget exhausted' }).waitFor();
      assert.match(await ui(page, 'deployment').textContent(), /unknown:.*budget/i);
      assert.equal(deploymentReads(f).length, 2);
      await page.waitForTimeout(200); assert.equal(deploymentReads(f).length, 2);
      const original = structuredClone(f.starts[0].context);
      await ui(page, 'source').fill('<h1>new head after exhaustion</h1>'); await ui(page, 'save').click(); await waitSource(page, '<h1>new head after exhaustion</h1>');
      release = f.hold('alpha', 'status');
      await page.evaluate(() => { const button = document.querySelector('[data-ui="check-status"]'); button.click(); button.click(); });
      await release.entered;
      assert.equal(await ui(page, 'check-status').isDisabled(), true);
      assert.equal(deploymentReads(f).length, 3);
      release();
      await ui(page, 'deployment').filter({ hasText: 'succeeded:' }).waitFor();
      assert.equal(deploymentReads(f).length, 3);
      assert.ok(deploymentReads(f).every(r => JSON.stringify(JSON.parse(r.context)) === JSON.stringify(original)));
    } else if (scenario === 'zero-budget') {
      await ui(page, 'deployment').filter({ hasText: 'budget exhausted' }).waitFor();
      assert.equal(deploymentReads(f).length, 0);
      await ui(page, 'check-status').click();
      await ui(page, 'deployment').filter({ hasText: 'succeeded:' }).waitFor();
      assert.equal(deploymentReads(f).length, 1);
    } else if (scenario === 'failed') {
      await ui(page, 'deployment').filter({ hasText: 'failed:' }).waitFor();
      await page.waitForTimeout(200);
      assert.equal(deploymentReads(f).length, 1);
      assert.equal(await ui(page, 'check-status').isVisible(), false);
    } else if (scenario === 'ambiguous') {
      await ui(page, 'deployment').filter({ hasText: 'Operator reconciliation required' }).waitFor();
      assert.equal(await ui(page, 'check-status').isVisible(), false);
      await page.evaluate(() => builder.reconnect()); await waitSource(page, '<h1>validated deployment</h1>');
      assert.equal(await ui(page, 'prepare').isDisabled(), true);
      assert.equal(deploymentReads(f).length, 0);
    } else if (scenario === 'revoked') {
      f.setAuth(false); release();
      await ui(page, 'connection').filter({ hasText: 'Access changed' }).waitFor();
      assert.equal(await ui(page, 'deployment').textContent(), '');
      assert.equal(await ui(page, 'check-status').isVisible(), false);
      assert.equal(await ui(page, 'source').inputValue(), '');
    } else if (scenario === 'rotated') {
      f.rotate(); await page.evaluate(() => builder.reconnect()); await waitSource(page, '<h1>validated deployment</h1>');
      release(); await page.waitForTimeout(200);
      assert.doesNotMatch(await ui(page, 'deployment').textContent(), /succeeded|unknown:/);
      assert.equal(deploymentReads(f).length, 0);
    } else {
      await ui(page, 'deployment').filter({ hasText: 'succeeded:' }).waitFor();
      assert.equal(deploymentReads(f).length, 3);
    }
    assert.equal(f.starts.length, 1);
    assert.equal(f.requests.filter(r => r.method === 'POST' && r.url.endsWith('/deployments')).length, 1);
    if (!['revoked', 'rotated'].includes(scenario)) assert.match(await ui(page, 'deployment').textContent(), new RegExp(frozen));
    assert.deepEqual(errors, []); assert.deepEqual(blocked, []);
  } finally { release?.(); await browser.close(); await f.close(); }
});
