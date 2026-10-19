// Drives assets/sync.js against a fake server: what stays in localStorage,
// what is pushed. Run: node tests/sync_flows.mjs (Node 22, no browser, no
// packages); tests/vault_vectors.rs runs it too.
import { readFileSync } from 'node:fs';

const store = new Map();
globalThis.localStorage = {
  get length() { return store.size; },
  key(i) { return [...store.keys()][i] ?? null; },
  getItem(k) { return store.has(k) ? store.get(k) : null; },
  setItem(k, v) { store.set(k, String(v)); },
  removeItem(k) { store.delete(k); },
};
globalThis.window = { dispatchEvent() {} };
globalThis.Event = class { constructor(t) { this.type = t; } };
let server; const pushes = [];
globalThis.fetch = async (url, opts = {}) => {
  const m = opts.method || 'GET';
  if (m === 'GET') return server.list();
  if (m === 'PUT') { pushes.push([url.split('/').pop(), opts.headers['If-Match'], opts.body]); return { ok: true, status: 200, json: async () => ({ version: 1 }) }; }
  return { ok: true, status: 204, json: async () => ({}) };
};
// A data: URL is always a module: no package.json, no syntax detection needed.
const code = readFileSync(new URL('../assets/sync.js', import.meta.url));
const { attach, cleanup } = await import(`data:text/javascript;base64,${code.toString('base64')}`);
const settle = () => new Promise((r) => setTimeout(r, 20));
const fakeStore = { set() { return true; }, del() {} };
const listing = (account, epoch, items) => ({ list: async () => ({ ok: true, status: 200, json: async () => ({ csrf: 't', account, epoch, items }) }) });
const off = { list: async () => ({ ok: false, status: 409, json: async () => ({ error: 'Sync is off.' }) }) };
const reset = (acked, epoch, values) => {
  store.clear(); pushes.length = 0;
  if (acked) store.set('l4f-sync:acked', JSON.stringify(acked));
  if (epoch !== null) store.set('l4f-sync:epoch', epoch);
  for (const [k, v] of Object.entries(values)) store.set(`l4f:${k}`, v);
};
const check = (name, ok) => { console.log(ok ? 'ok  ' : 'FAIL', name); if (!ok) process.exitCode = 1; };

// 1. Sync off: 409 keeps every value, drops ACKED only.
reset({ 'links:v1': { version: 3, json: '[1]' } }, 'A.E1', { 'links:v1': '[1]' });
server = off; attach(fakeStore); await settle();
check('409 keeps the value', store.get('l4f:links:v1') === '[1]');
check('409 drops ACKED', !store.has('l4f-sync:acked'));

// 2. Off then on (same account, new epoch, empty copy): nothing deleted, pushed as new.
reset({ 'links:v1': { version: 3, json: '[1]' } }, 'A.E1', { 'links:v1': '[1]' });
server = listing('A', 'E2', []); attach(fakeStore); await settle();
check('new epoch keeps the value', store.get('l4f:links:v1') === '[1]');
check('and pushes it as new', pushes.length === 1 && pushes[0][0] === 'links%3Av1' && pushes[0][1] === '0');
check('and keeps the new epoch', store.get('l4f-sync:epoch') === 'A.E2');

// 3. Same epoch, key gone on the server: deleted elsewhere, deleted here (as before).
reset({ 'links:v1': { version: 3, json: '[1]' } }, 'A.E1', { 'links:v1': '[1]' });
server = listing('A', 'E1', []); attach(fakeStore); await settle();
check('same epoch: a delete elsewhere still applies', !store.has('l4f:links:v1') && pushes.length === 0);

// 4. Another account signs in here: the first one's ACKED still clears its values (as before).
reset({ 'links:v1': { version: 3, json: '[1]' } }, 'A.E1', { 'links:v1': '[1]' });
server = listing('B', 'F1', []); attach(fakeStore); await settle();
check("another account: the first one's value is not pushed", pushes.length === 0 && !store.has('l4f:links:v1'));

// 5. No epoch kept (a browser from before epochs): treated as a new copy, nothing deleted.
reset({ 'links:v1': { version: 3, json: '[1]' } }, null, { 'links:v1': '[1]' });
server = listing('A', null, []); attach(fakeStore); await settle();
check('no epoch kept: nothing deleted', store.get('l4f:links:v1') === '[1]' && store.get('l4f-sync:epoch') === 'A.');

// 6. Sign-out cleanup removes ACKED and the epoch, keeps changed values.
reset({ 'a': { version: 1, json: '1' }, 'b': { version: 1, json: '2' } }, 'A.E1', { a: '1', b: '3' });
cleanup();
check('cleanup', !store.has('l4f:a') && store.get('l4f:b') === '3' && !store.has('l4f-sync:acked') && !store.has('l4f-sync:epoch'));
