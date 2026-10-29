import { createHmac, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { isAbsolute, join, parse } from 'node:path';
import { validateValue } from './contracts.mjs';

export function validateSourcePath(path) {
  validateValue('sourceFile', { path, content: '', bytes: 0, sha256: 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' });
  return path;
}
export class HttpError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
export const deny = (status, code) => { throw new HttpError(status, code); };
export function exactObject(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k))) deny(400, 'INVALID_REQUEST');
  return value;
}
export function decodeRoute(raw) {
  if (typeof raw !== 'string' || raw.length > 20000 || !raw.startsWith('/') || raw.includes('#')) deny(400, 'INVALID_PATH');
  const [path, query = ''] = raw.split('?');
  if (raw.split('?').length > 2) deny(400, 'INVALID_PATH');
  let parts;
  try { parts = path.split('/').slice(1).map(decodeURIComponent); } catch { deny(400, 'INVALID_PATH'); }
  if (parts.some(p => !p || p === '.' || p === '..' || /[/%\\\x00-\x20\x7f]/.test(p))) deny(400, 'INVALID_PATH');
  return { parts, query: new URLSearchParams(query) };
}
export async function readJSON(req, limit = 420000) {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) deny(415, 'JSON_REQUIRED');
  if (req.headers['content-encoding']) deny(415, 'ENCODING_UNSUPPORTED');
  if (Number(req.headers['content-length']) > limit) deny(413, 'BODY_TOO_LARGE');
  const chunks = []; let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > limit) deny(413, 'BODY_TOO_LARGE');
    chunks.push(chunk);
  }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
  catch { deny(400, 'INVALID_JSON'); }
}
export function csrfToken(secret, principal) {
  return createHmac('sha256', secret).update(JSON.stringify([principal.id, principal.sessionId])).digest('hex');
}
export function checkOrigin(req, origin, required = false) {
  const supplied = req.headers.origin;
  if ((required && supplied !== origin) || (supplied !== undefined && supplied !== origin) || req.headers['sec-fetch-site'] === 'cross-site') deny(403, 'ORIGIN_DENIED');
}
export function checkMutation(req, origin, secret, principal) {
  checkOrigin(req, origin, true);
  const token = req.headers['x-builder-csrf'];
  const expected = csrfToken(secret, principal);
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token) || !timingSafeEqual(Buffer.from(token), Buffer.from(expected))) deny(403, 'CSRF_DENIED');
}
export function createRateLimiter({ limit = 30, windowMs = 60000, maxKeys = 1000, now = Date.now } = {}) {
  if (![limit, windowMs, maxKeys].every(n => Number.isSafeInteger(n) && n > 0)) throw new TypeError('Invalid rate limits');
  const entries = new Map();
  return key => {
    const time = now();
    for (const [k, v] of entries) if (v.until <= time) entries.delete(k);
    let value = entries.get(key);
    if (!value) {
      if (entries.size >= maxKeys) deny(429, 'RATE_LIMITED');
      entries.set(key, value = { until: time + windowMs, count: 0 });
    }
    if (++value.count > limit) deny(429, 'RATE_LIMITED');
  };
}
export function validateMaterializationPaths(paths) {
  const seen = new Set();
  for (const path of paths) {
    validateSourcePath(path);
    if (seen.has(path)) deny(400, 'PATH_CONFLICT');
    seen.add(path);
  }
  for (const path of seen) {
    const parts = path.split('/');
    for (let i = 1; i < parts.length; i++) if (seen.has(parts.slice(0, i).join('/'))) deny(400, 'PATH_CONFLICT');
  }
  return paths;
}
async function rootChain(root) {
  if (!isAbsolute(root) || root.split('/').some(p => p === '.' || p === '..') || root !== parse(root).root && root.endsWith('/')) deny(400, 'UNSAFE_ROOT');
  const components = root.split('/').filter(Boolean); const chain = [];
  let path = parse(root).root;
  for (const component of ['', ...components]) {
    if (component) path = join(path, component);
    const stat = await lstat(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) deny(403, 'UNSAFE_ROOT');
    chain.push({ path, stat });
  }
  const stat = chain.at(-1).stat;
  if (root === parse(root).root || stat.uid !== process.getuid() || (stat.mode & 0o077)) deny(403, 'UNSAFE_ROOT');
  return chain;
}
export async function readSafeFile(root, path, { maxBytes = 400000 } = {}) {
  validateSourcePath(path);
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new TypeError('Invalid read budget');
  const chain = await rootChain(root);
  let current = root;
  for (const component of path.split('/').slice(0, -1)) {
    current = join(current, component);
    const stat = await lstat(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) deny(403, 'UNSAFE_PATH');
    chain.push({ path: current, stat });
  }
  const handle = await open(join(root, path), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid()) deny(403, 'UNSAFE_PATH');
    if (stat.size > maxBytes) deny(413, 'READ_BATCH_TOO_LARGE');
    for (const entry of chain) {
      const next = await lstat(entry.path);
      if (!next.isDirectory() || next.dev !== entry.stat.dev || next.ino !== entry.stat.ino) deny(403, 'PATH_CHANGED');
    }
    const bytes = Buffer.alloc(Math.min(stat.size + 1, maxBytes + 1)); let total = 0;
    while (total < bytes.length) {
      const { bytesRead } = await handle.read(bytes, total, bytes.length - total, total);
      if (!bytesRead) break;
      total += bytesRead;
    }
    if (total > maxBytes) deny(413, 'READ_BATCH_TOO_LARGE');
    const after = await handle.stat();
    if (after.nlink !== 1 || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || total !== stat.size) deny(409, 'PATH_CHANGED');
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, total));
  } finally { await handle.close(); }
}
