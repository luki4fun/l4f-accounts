// The end-to-end encrypted vault (docs/vault-format.md, version 1). Every
// key is made and used here, with WebCrypto; the server stores ciphertext.
// The format functions are exported for tests/vault_vectors.mjs, which
// rebuilds the vectors the Rust side decrypts. The page part runs only where
// #vault exists.
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
/** A `pass` slot, as creating the vault and changing the passphrase write it. */
export async function passSlot(account, id, pass, dek, salt = random(16), iv = random(12)) {
  const kdf = { alg: 'PBKDF2-SHA256', iter: PBKDF2_ITER, salt: b64u(salt) };
  return makeSlot(account, id, 'pass', kdf, await kekFromPassphrase(pass, salt, PBKDF2_ITER), dek, iv);
}
/** A `recovery` slot for the 32 random bytes shown as the recovery key. */
export async function recoverySlot(account, id, secret, dek, salt = random(32), iv = random(12)) {
  const kdf = { alg: 'HKDF-SHA256', salt: b64u(salt), info: HKDF_INFO };
  return makeSlot(account, id, 'recovery', kdf, await kekFromSecret(secret, salt), dek, iv);
}
/** The raw DEK, opened with the passphrase or the recovery key as typed. A wrong one throws an OperationError. */
export async function unwrap(account, slot, secret) {
  const kek = slot.kind === 'pass'
    ? await kekFromPassphrase(secret, unb64u(slot.kdf.salt), slot.kdf.iter)
    : await kekFromSecret(unbase32(secret), unb64u(slot.kdf.salt));
  return openSlot(account, slot, kek);
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
  // Some errors carry no message (WebCrypto's, in Chromium): never say nothing.
  const fail = (err) => say(err.message || 'Something went wrong.');
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
  // The unlocked view again once a write is done, unless the vault was locked
  // (or opened with another key) while it was in flight.
  const redraw = (k) => () => (key === k ? unlocked() : undefined);

  // Each vault form names its own credential, so a password manager files the
  // vault passphrase apart from the account password.
  const who = () => h('input', { type: 'text', name: 'username', value: `vault:${account}`, autocomplete: 'username', hidden: true });

  // How to open the vault: the passphrase, or the recovery key in a plain text
  // field of its own that no password manager takes for a password. The two
  // inputs are named after the slot kinds; `p` prefixes their ids.
  function opener(p, label, passLabel) {
    const pass = h('input', { type: 'password', id: `${p}pass`, name: 'pass', autocomplete: 'current-password', required: true });
    const rec = h('input', { type: 'text', id: `${p}recovery`, name: 'recovery', autocomplete: 'off', autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false', required: true, disabled: true });
    const pf = h('div', { class: 'field' }, h('label', { for: pass.id }, passLabel), pass);
    const rf = h('div', { class: 'field', hidden: true }, h('label', { for: rec.id }, 'Recovery key'), rec);
    const how = h('select', { id: `${p}how`, name: 'how', onchange: () => {
      const r = how.value === 'recovery';
      pf.hidden = pass.disabled = r; rf.hidden = rec.disabled = !r;
    } }, h('option', { value: 'pass' }, 'the passphrase'), h('option', { value: 'recovery' }, 'the recovery key'));
    return [h('div', { class: 'field' }, h('label', { for: how.id }, label), how), pf, rf];
  }

  // The slots of one kind, those whose key opens the most items first: a
  // create that failed halfway may have left a slot whose key opens nothing.
  const slotsOf = (kind) => {
    const opens = (s) => state.items.filter((it) => b64u(it.bytes.slice(1, 9)) === s.dek_id).length;
    return state.slots.filter((s) => s.kind === kind).sort((a, b) => opens(b) - opens(a));
  };
  // The raw DEK and the slot that gave it, trying the slots of `kind` in turn.
  async function openAny(kind, secret) {
    let last = new Error('That way to unlock is not set up.');
    for (const slot of slotsOf(kind)) {
      try { return { slot, dek: await unwrap(account, slot, secret) }; } catch (err) { last = err; }
    }
    throw last;
  }

  function create() {
    const form = h('form', { class: 'narrow mt-2', onsubmit: (e) => {
      e.preventDefault();
      const [p1, p2] = [form.elements.p1.value, form.elements.p2.value];
      if (p1.length < 12) return say('Use at least 12 characters for the vault passphrase.');
      if (p1 !== p2) return say('The two passphrases differ.');
      busy(form, true); say('Creating… this takes a moment.', true);
      (async () => {
        // A second tab, or a try that failed halfway, may have made one already.
        await load();
        if (state.slots.length) { say('The vault exists already. Unlock it.'); return locked(); }
        const dek = random(32), recovery = random(32);
        const passId = b64u(random(16)), recId = b64u(random(16));
        const pass = await passSlot(account, passId, p1, dek), rec = await recoverySlot(account, recId, recovery, dek);
        try {
          await call('PUT', `/slots/${passId}`, JSON.stringify(pass), 0);
          await call('PUT', `/slots/${recId}`, JSON.stringify(rec), 0);
        } catch (err) {
          // Half a vault is worse than none, and a write whose answer was lost
          // may still have landed: take both back. If-Match 0 deletes any version.
          await Promise.all([passId, recId].map((id) => call('DELETE', `/slots/${id}`, undefined, 0).catch(() => {})));
          throw err;
        }
        key = await dekKey(dek); keyIdBytes = await dekId(dek);
        say('');
        // Shown as soon as it is stored; the refresh after it fails on its own.
        view(h('div', { class: 'callout warn mt-2' },
          h('p', {}, 'Your recovery key, shown only now. Write it down and keep it apart from the passphrase: with neither, nothing in the vault can be read again, by you or anyone.'),
          h('p', { class: 'mono big anywhere' }, base32(recovery))),
        h('button', { class: 'btn mt-2', type: 'button', onclick: () => load().then(unlocked).catch(fail) }, 'I wrote it down'));
      })().catch((err) => { fail(err); busy(form, false); });
    } },
    who(),
    h('div', { class: 'field' }, h('label', { for: 'p1' }, 'Vault passphrase'), h('input', { type: 'password', id: 'p1', name: 'p1', autocomplete: 'new-password', required: true })),
    h('div', { class: 'field' }, h('label', { for: 'p2' }, 'The same again'), h('input', { type: 'password', id: 'p2', name: 'p2', autocomplete: 'new-password', required: true })),
    h('p', { class: 'hint' }, 'Not your account password. The server never sees it; nobody can reset it.'),
    h('button', { class: 'btn', type: 'submit' }, 'Create the vault'));
    view(h('p', {}, 'Your vault is empty. Create it with a passphrase.'), form);
  }

  function locked() {
    const form = h('form', { class: 'narrow mt-2', onsubmit: (e) => {
      e.preventDefault();
      const kind = form.elements.how.value;
      if (!slotsOf(kind).length) return say('That way to unlock is not set up.');
      busy(form, true); say('Unlocking…', true);
      openAny(kind, form.elements[kind].value)
        .then(async ({ dek }) => { key = await dekKey(dek); keyIdBytes = await dekId(dek); say(''); unlocked(); })
        .catch(() => { say('That does not unlock the vault.'); busy(form, false); });
    } },
    who(), opener('', 'Unlock with', 'Vault passphrase'),
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
            call('DELETE', `/items/${it.k}`, undefined, it.version).then(load).then(redraw(key)).catch(fail);
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
        .then(load).then(redraw(key)).catch((err) => { fail(err); busy(add, false); });
    } },
    h('h2', {}, 'Add an entry'),
    h('div', { class: 'field' }, h('label', { for: 'kind' }, 'Kind'), h('select', { id: 'kind', name: 'kind' }, KINDS.map((k) => h('option', { value: k }, k)))),
    h('div', { class: 'field' }, h('label', { for: 'name' }, 'Name'), h('input', { type: 'text', id: 'name', name: 'name', maxlength: '100', required: true })),
    h('div', { class: 'field' }, h('label', { for: 'secret2' }, 'Secret'), h('textarea', { id: 'secret2', name: 'secret', rows: '3', class: 'mono', spellcheck: 'false', required: true })),
    h('button', { class: 'btn btn-sm', type: 'submit' }, 'Save'));
    const change = h('form', { class: 'narrow mt-3', onsubmit: (e) => {
      e.preventDefault();
      const f = change.elements, kind = f.how.value, np = f.np.value;
      if (!slotsOf(kind).length) return say('That way to unlock is not set up.');
      if (np.length < 12) return say('Use at least 12 characters for the vault passphrase.');
      if (np !== f.np2.value) return say('The two passphrases differ.');
      busy(change, true); say('Changing…', true);
      (async () => {
        const { slot, dek } = await openAny(kind, f[kind].value);
        // Replace the pass slot that opened, else the one wrapping this DEK;
        // with neither, start a new one.
        const kid = b64u(await dekId(dek));
        const old = kind === 'pass' ? slot : slotsOf('pass').find((s) => s.dek_id === kid);
        const fresh = await passSlot(account, old ? old.id : b64u(random(16)), np, dek);
        const { version } = await call('PUT', `/slots/${fresh.id}`, JSON.stringify(fresh), old ? old.version : 0);
        // Changed, whatever the refresh says: the new slot stands in until it answers.
        state.slots = [...state.slots.filter((s) => s.id !== fresh.id), { ...fresh, version }];
        await load().catch(() => {});
        say('Passphrase changed.', true); busy(change, false);
        change.reset(); f.how.dispatchEvent(new Event('change'));
      })().catch((err) => {
        const wrong = kind === 'pass' ? 'The current passphrase is wrong.' : 'That recovery key is wrong.';
        say(err.name === 'OperationError' ? wrong : (err.message || 'Something went wrong.'));
        busy(change, false);
      });
    } },
    h('h2', {}, 'Change the passphrase'),
    who(), opener('o', 'Confirm with', 'Current passphrase'),
    h('div', { class: 'field' }, h('label', { for: 'np' }, 'New passphrase'), h('input', { type: 'password', id: 'np', name: 'np', autocomplete: 'new-password', required: true })),
    h('div', { class: 'field' }, h('label', { for: 'np2' }, 'The same again'), h('input', { type: 'password', id: 'np2', name: 'np2', autocomplete: 'new-password', required: true })),
    h('button', { class: 'btn btn-sm btn-quiet', type: 'submit' }, 'Change'));
    view(
      h('div', { class: 'spread' }, h('p', { class: 'muted' }, `${state.items.length} entries`),
        h('button', { class: 'btn btn-sm btn-quiet', type: 'button', onclick: () => { key = null; keyIdBytes = null; locked(); } }, 'Lock')),
      h('div', { class: 'table-wrap mt-2' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Kind'), h('th', {}, 'Name'), h('th', {}, 'Secret'), h('th', {}))), h('tbody', {}, rows))),
      add, change);
  }

  load().then(() => (state.slots.length ? locked() : create())).catch(fail);
}
