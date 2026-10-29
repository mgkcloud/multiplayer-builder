import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, chmod, symlink, link, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import { decodeRoute, readJSON, checkMutation, csrfToken, createRateLimiter, validateMaterializationPaths, readSafeFile } from '../src/security.mjs';

const rejects = (fn, code) => assert.throws(fn, { code });
test('route decoder preserves exact path boundaries and rejects encoded traversal', () => {
  assert.deepEqual(decodeRoute('/api/builder/v1/projects/alpha').parts, ['api', 'builder', 'v1', 'projects', 'alpha']);
  for (const path of ['/a/%2e%2e/b', '/a/%252e%252e', '/a/%2f', '/a/%5c', '/a//b', '/a/%00', '/a/%zz', '/a/../b', '//a', '/a?x?y']) rejects(() => decodeRoute(path), 'INVALID_PATH');
});
test('exact origin and constant-time session-bound CSRF', () => {
  const secret = randomBytes(32), p = { id: 'synthetic', sessionId: 'session' };
  const token = csrfToken(secret, p), headers = { origin: 'http://localhost', 'x-builder-csrf': token };
  checkMutation({ headers }, 'http://localhost', secret, p);
  for (const changed of [{ origin: 'http://evil' }, { origin: undefined }, { 'x-builder-csrf': 'x' }, { 'sec-fetch-site': 'cross-site' }]) rejects(() => checkMutation({ headers: { ...headers, ...changed } }, 'http://localhost', secret, p), changed['x-builder-csrf'] ? 'CSRF_DENIED' : 'ORIGIN_DENIED');
  rejects(() => checkMutation({ headers }, 'http://localhost', secret, { ...p, sessionId: 'other' }), 'CSRF_DENIED');
});
test('rate limiter has bounded keys and explicit expiry', () => {
  let time = 0; const limit = createRateLimiter({ limit: 2, windowMs: 10, maxKeys: 1, now: () => time });
  limit('a'); limit('a'); rejects(() => limit('a'), 'RATE_LIMITED'); rejects(() => limit('b'), 'RATE_LIMITED');
  time = 11; limit('b');
});
test('JSON streamed byte limits, malformed UTF-8 and encoding errors', async () => {
  const request = (chunks, headers = {}) => Object.assign(Readable.from(chunks.map(c => Buffer.isBuffer(c) ? c : Buffer.from(c))), { headers: { 'content-type': 'application/json', ...headers } });
  assert.deepEqual(await readJSON(request(['{"a":', '1}'])), { a: 1 });
  await assert.rejects(readJSON(request(['12345', '67890']), 8), { code: 'BODY_TOO_LARGE' });
  await assert.rejects(readJSON(request(['{}'], { 'content-length': '9' }), 8), { code: 'BODY_TOO_LARGE' });
  await assert.rejects(readJSON(request(['{'])), { code: 'INVALID_JSON' });
  await assert.rejects(readJSON(request([Buffer.from([0xff])])), { code: 'INVALID_JSON' });
  await assert.rejects(readJSON(request(['{}'], { 'content-encoding': 'gzip' })), { code: 'ENCODING_UNSUPPORTED' });
  await assert.rejects(readJSON(request(['{}'], { 'content-type': 'text/plain' })), { code: 'JSON_REQUIRED' });
});
test('materialization rejects virtual file/directory prefix conflicts and unsafe paths', () => {
  assert.deepEqual(validateMaterializationPaths(['a/b', 'a/c']), ['a/b', 'a/c']);
  for (const paths of [['a', 'a/b'], ['a/b', 'a'], ['a', 'a']]) rejects(() => validateMaterializationPaths(paths), 'PATH_CONFLICT');
  for (const path of ['../x', '/x', 'a/%2e', 'a\\b', 'a//b', 'a/./b']) assert.throws(() => validateMaterializationPaths([path]));
});
test('safe file reads reject symlink/hardlink escapes, nonprivate roots, oversized batches; no fixed file cap', async t => {
  const root = await mkdtemp(join(process.env.TMPDIR, 'f2-security-'));
  await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'src')); await writeFile(join(root, 'src', 'main'), 'x'.repeat(250001));
  assert.equal((await readSafeFile(root, 'src/main')).length, 250001);
  await assert.rejects(readSafeFile(root, 'src/main', { maxBytes: 10 }), { code: 'READ_BATCH_TOO_LARGE' });
  await symlink('src/main', join(root, 'alias')); await assert.rejects(readSafeFile(root, 'alias'));
  await symlink('src', join(root, 'dir')); await assert.rejects(readSafeFile(root, 'dir/main'), { code: 'UNSAFE_PATH' });
  await link(join(root, 'src/main'), join(root, 'hard')); await assert.rejects(readSafeFile(root, 'hard'), { code: 'UNSAFE_PATH' });
  await assert.rejects(readSafeFile(root, '../outside'));
  await chmod(root, 0o755); await assert.rejects(readSafeFile(root, 'src/main'), { code: 'UNSAFE_ROOT' });
});
