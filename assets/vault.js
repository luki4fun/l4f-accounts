// The end-to-end encrypted vault (docs/vault-format.md, version 1). Every
// key is made and used here, with WebCrypto; the server stores ciphertext.
// The format functions are exported so a test can produce the vectors the
// Rust side decrypts. The page part runs only where #vault exists.
// No inline script, no HTML strings: text goes in with textContent only.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const PBKDF2_ITER = 600000;
export const KINDS = ['note', 'password', 'totp', 'ssh'];
const HKDF_INFO = 'l4f-vault-kek/v1';

export function b64u(bytes) {
  let s = '';
  new Uint8Array(bytes).forEach((b) => { s += String.fromCharCode(b); });
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64u(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

// RFC 4648 base32 without padding, in groups of four: the recovery key as shown.
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32(bytes) {
  let bits = 0, value = 0, out = '';
  bytes.forEach((b) => {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  });
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out.match(/.{1,4}/g).join(' ');
}
export function unbase32(s) {
  const clean = s.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const c of clean) {
    value = (value << 5) | B32.indexOf(c); bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

export async function kekFromPassphrase(pass, salt, iter) {
  if (iter < PBKDF2_ITER) throw new Error('This vault slot is weaker than allowed. Refusing it.');
  const base = await subtle.importKey('raw', enc.encode(pass.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
export async function kekFromSecret(secret, salt) {
  const base = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(HKDF_INFO) }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
export async function dekId(dek) {
  return new Uint8Array(await subtle.digest('SHA-256', dek)).slice(0, 8);
}
const slotAad = (account, id) => enc.encode(`l4f-vault-slot/v1|${account}|${id}`);
const itemAad = (account, kind, id) => enc.encode(`l4f-vault-item/v1|${account}|${kind}|${id}`);

/** A key slot wrapping `dek` (raw bytes) under `kek`. */
export async function makeSlot(account, id, kind, kdf, kek, dek, iv = random(12)) {
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: slotAad(account, id) }, kek, dek));
  return { v: 1, id, kind, kdf, dek_id: b64u(await dekId(dek)), iv: b64u(iv), ct: b64u(ct) };
}
/** The raw DEK a slot wraps, or a thrown error for a wrong secret. */
export async function openSlot(account, slot, kek) {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: unb64u(slot.iv), additionalData: slotAad(account, slot.id) }, kek, unb64u(slot.ct));
  return new Uint8Array(pt);
}
export async function dekKey(dek) {
  return subtle.importKey('raw', dek, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
/** `0x01 | dek_id | iv | AES-GCM(plaintext JSON)`. */
export async function sealItem(account, kind, id, key, keyId, value, iv = random(12)) {
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: itemAad(account, kind, id) }, key, enc.encode(JSON.stringify(value))));
  const out = new Uint8Array(1 + 8 + 12 + ct.length);
  out[0] = 1; out.set(keyId, 1); out.set(iv, 9); out.set(ct, 21);
  return out;
}
export async function openItem(account, kind, id, key, bytes) {
  if (bytes[0] !== 1) throw new Error('Unknown vault item version.');
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(9, 21), additionalData: itemAad(account, kind, id) }, key, bytes.slice(21));
  return JSON.parse(dec.decode(pt));
}

// ---------------------------------------------------------------- the page

const root = globalThis.document && document.getElementById('vault');
if (root) page(root);

function page(root) {
  const API = `${root.dataset.base}/api/vault`;
  let csrf = root.dataset.csrf, account = '', state = { slots: [], items: [] }, key = null, keyIdBytes = null;

  const h = (tag, attrs = {}, ...kids) => {
    const e = document.createElement(tag);
    Object.entries(attrs).forEach(([k, v]) => {
      if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
    });
    kids.flat().forEach((c) => e.append(typeof c === 'string' ? document.createTextNode(c) : c));
    return e;
  };
  const say = (msg, good) => { const n = root.querySelector('#vault-msg'); n.className = good ? 'notice good mt-2' : 'notice mt-2'; n.textContent = msg; n.hidden = !msg; };
  const call = (method, path, body, version, type = 'application/json') =>
    fetch(`${API}${path}`, { method, credentials: 'same-origin', headers: { 'Content-Type': type, 'X-CSRF': csrf, 'If-Match': String(version || 0) }, body })
      .then((r) => {
        if (r.status === 401) { location.assign(`${root.dataset.base}/login?next=${encodeURIComponent(location.pathname)}`); throw new Error('Signed out.'); }
        if (r.status === 204) return {};
        return r.json().then((j) => { if (!r.ok) throw new Error(j.error || (r.status === 409 ? 'It changed in another tab. Reload.' : 'Something went wrong.')); return j; });
      });
  const load = () => fetch(API, { credentials: 'same-origin' }).then((r) => r.json()).then((j) => {
    if (j.error) throw new Error(j.error);
    csrf = j.csrf; account = j.account;
    state = { slots: j.slots.map((s) => ({ ...s.v, version: s.version })), items: j.items.map((i) => ({ k: i.k, bytes: unb64u(i.v), version: i.version })) };
  });
  const view = (...kids) => { const body = root.querySelector('#vault-body'); body.replaceChildren(...kids); };
  const busy = (form, on) => form.querySelectorAll('button').forEach((b) => { b.disabled = on; });

  function create() {
    const form = h('form', { class: 'narrow mt-2', onsubmit: (e) => {
      e.preventDefault();
      const [p1, p2] = [form.elements.p1.value, form.elements.p2.value];
      if (p1.length < 12) return say('Use at least 12 characters for the vault passphrase.');
      if (p1 !== p2) return say('The two passphrases differ.');
      busy(form, true); say('Creating… this takes a moment.', true);
      (async () => {
        const dek = random(32), recovery = random(32);
        const passId = b64u(random(16)), recId = b64u(random(16));
        const salt = random(16), rsalt = random(32);
        const pass = await makeSlot(account, passId, 'pass', { alg: 'PBKDF2-SHA256', iter: PBKDF2_ITER, salt: b64u(salt) }, await kekFromPassphrase(p1, salt, PBKDF2_ITER), dek);
        const rec = await makeSlot(account, recId, 'recovery', { alg: 'HKDF-SHA256', salt: b64u(rsalt), info: HKDF_INFO }, await kekFromSecret(recovery, rsalt), dek);
        await call('PUT', `/slots/${passId}`, JSON.stringify(pass), 0);
        await call('PUT', `/slots/${recId}`, JSON.stringify(rec), 0);
        key = await dekKey(dek); keyIdBytes = await dekId(dek);
        await load();
        say('');
        view(h('div', { class: 'callout warn mt-2' },
          h('p', {}, 'Your recovery key, shown only now. Write it down and keep it apart from the passphrase: with neither, nothing in the vault can be read again, by you or anyone.'),
          h('p', { class: 'mono big anywhere' }, base32(recovery))),
        h('button', { class: 'btn mt-2', type: 'button', onclick: () => unlocked() }, 'I wrote it down'));
      })().catch((err) => { say(err.message); busy(form, false); });
    } },
    h('div', { class: 'field' }, h('label', { for: 'p1' }, 'Vault passphrase'), h('input', { type: 'password', id: 'p1', name: 'p1', autocomplete: 'new-password', required: true })),
    h('div', { class: 'field' }, h('label', { for: 'p2' }, 'The same again'), h('input', { type: 'password', id: 'p2', name: 'p2', autocomplete: 'new-password', required: true })),
    h('p', { class: 'hint' }, 'Not your account password. The server never sees it; nobody can reset it.'),
    h('button', { class: 'btn', type: 'submit' }, 'Create the vault'));
    view(h('p', {}, 'Your vault is empty. Create it with a passphrase.'), form);
  }

  async function unwrap(slot, secret) {
    const kek = slot.kind === 'pass'
      ? await kekFromPassphrase(secret, unb64u(slot.kdf.salt), slot.kdf.iter)
      : await kekFromSecret(unbase32(secret), unb64u(slot.kdf.salt));
    return openSlot(account, slot, kek);
  }

  function locked() {
    const form = h('form', { class: 'narrow mt-2', onsubmit: (e) => {
      e.preventDefault();
      const useRecovery = form.elements.how.value === 'recovery';
      const slot = state.slots.find((s) => s.kind === (useRecovery ? 'recovery' : 'pass'));
      if (!slot) return say('That way to unlock is not set up.');
      busy(form, true); say('Unlocking…', true);
      unwrap(slot, form.elements.secret.value)
        .then(async (dek) => { key = await dekKey(dek); keyIdBytes = await dekId(dek); say(''); unlocked(); })
        .catch(() => { say('That does not unlock the vault.'); busy(form, false); });
    } },
    h('div', { class: 'field' }, h('label', { for: 'how' }, 'Unlock with'),
      h('select', { id: 'how', name: 'how' }, h('option', { value: 'pass' }, 'the passphrase'), h('option', { value: 'recovery' }, 'the recovery key'))),
    h('div', { class: 'field' }, h('label', { for: 'secret' }, 'Passphrase or recovery key'), h('input', { type: 'password', id: 'secret', name: 'secret', autocomplete: 'current-password', required: true })),
    h('button', { class: 'btn', type: 'submit' }, 'Unlock'));
    view(form);
  }

  async function unlocked() {
    const rows = [];
    for (const it of state.items) {
      const [kind] = it.k.split('.');
      try {
        const v = await openItem(account, kind, it.k, key, it.bytes);
        rows.push(h('tr', {}, h('td', {}, kind), h('td', {}, v.name || ''), h('td', { class: 'mono small anywhere' }, v.secret || ''),
          h('td', {}, h('button', { class: 'btn btn-sm btn-quiet', type: 'button', onclick: () => {
            if (!confirm(`Delete ${v.name || 'this entry'}?`)) return;
            call('DELETE', `/items/${it.k}`, undefined, it.version).then(load).then(unlocked).catch((err) => say(err.message));
          } }, 'Delete'))));
      } catch { rows.push(h('tr', {}, h('td', { colspan: '4', class: 'muted' }, `${it.k}: cannot be opened with this key`))); }
    }
    const add = h('form', { class: 'narrow mt-3', onsubmit: (e) => {
      e.preventDefault();
      const kind = add.elements.kind.value, id = `${kind}.${b64u(random(16))}`;
      const value = { v: 1, name: add.elements.name.value.trim(), secret: add.elements.secret.value };
      busy(add, true);
      sealItem(account, kind, id, key, keyIdBytes, value)
        .then((bytes) => call('PUT', `/items/${id}`, bytes, 0, 'application/octet-stream'))
        .then(load).then(unlocked).catch((err) => { say(err.message); busy(add, false); });
    } },
    h('h2', {}, 'Add an entry'),
    h('div', { class: 'field' }, h('label', { for: 'kind' }, 'Kind'), h('select', { id: 'kind', name: 'kind' }, KINDS.map((k) => h('option', { value: k }, k)))),
    h('div', { class: 'field' }, h('label', { for: 'name' }, 'Name'), h('input', { type: 'text', id: 'name', name: 'name', maxlength: '100', required: true })),
    h('div', { class: 'field' }, h('label', { for: 'secret2' }, 'Secret'), h('textarea', { id: 'secret2', name: 'secret', rows: '3', class: 'mono', spellcheck: 'false', required: true })),
    h('button', { class: 'btn btn-sm', type: 'submit' }, 'Save'));
    const change = h('form', { class: 'narrow mt-3', onsubmit: (e) => {
      e.preventDefault();
      const slot = state.slots.find((s) => s.kind === 'pass');
      const np = change.elements.np.value;
      if (np.length < 12) return say('Use at least 12 characters for the vault passphrase.');
      busy(change, true); say('Changing…', true);
      (async () => {
        const dek = await unwrap(slot, change.elements.op.value);
        const salt = random(16);
        const fresh = await makeSlot(account, slot.id, 'pass', { alg: 'PBKDF2-SHA256', iter: PBKDF2_ITER, salt: b64u(salt) }, await kekFromPassphrase(np, salt, PBKDF2_ITER), dek);
        await call('PUT', `/slots/${slot.id}`, JSON.stringify(fresh), slot.version);
        await load(); say('Passphrase changed.', true); busy(change, false); change.reset();
      })().catch((err) => { say(err.message === 'The operation failed for an operation-specific reason' ? 'The current passphrase is wrong.' : err.message); busy(change, false); });
    } },
    h('h2', {}, 'Change the passphrase'),
    h('div', { class: 'field' }, h('label', { for: 'op' }, 'Current passphrase'), h('input', { type: 'password', id: 'op', name: 'op', autocomplete: 'current-password', required: true })),
    h('div', { class: 'field' }, h('label', { for: 'np' }, 'New passphrase'), h('input', { type: 'password', id: 'np', name: 'np', autocomplete: 'new-password', required: true })),
    h('button', { class: 'btn btn-sm btn-quiet', type: 'submit' }, 'Change'));
    view(
      h('div', { class: 'spread' }, h('p', { class: 'muted' }, `${state.items.length} entries`),
        h('button', { class: 'btn btn-sm btn-quiet', type: 'button', onclick: () => { key = null; keyIdBytes = null; locked(); } }, 'Lock')),
      h('div', { class: 'table-wrap mt-2' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Kind'), h('th', {}, 'Name'), h('th', {}, 'Secret'), h('th', {}))), h('tbody', {}, rows))),
      add, change);
  }

  load().then(() => (state.slots.length ? locked() : create())).catch((err) => say(err.message));
}
