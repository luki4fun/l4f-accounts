// Pins docs/vault-format.md, version 1, on the browser side: assets/vault.js
// itself must open tests/fixtures/vault/v1.json and rebuild it byte for byte
// (tests/vault_vectors.rs opens the same vectors with ring). A change that
// breaks this is a format change and needs `v: 2`, never an edit.
// Run: node tests/vault_vectors.mjs (Node 22, WebCrypto built in, no packages).

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { before, test } from 'node:test';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
// A data: URL is always a module: no package.json, no syntax detection needed.
const v = await import(`data:text/javascript;base64,${Buffer.from(read('../assets/vault.js')).toString('base64')}`);
const fx = JSON.parse(read('fixtures/vault/v1.json'));
const { account, pass_slot: ps, recovery_slot: rs } = fx;
const text = (slot) => JSON.stringify(slot); // what the page sends as the slot
const wrong = { name: 'OperationError' };

// The DEK, the way the page unlocks: from the passphrase and the pass slot.
let dek;
before(async () => { dek = await v.unwrap(account, ps, fx.pass); });

test('the pass slot opens to the DEK its dek_id names', async () => {
  assert.equal(ps.kdf.iter, v.PBKDF2_ITER);
  assert.equal(dek.length, 32);
  assert.equal(v.b64u(await v.dekId(dek)), ps.dek_id);
});

test('the pass slot rebuilds byte for byte', async () => {
  const again = await v.passSlot(account, ps.id, fx.pass, dek, v.unb64u(ps.kdf.salt), v.unb64u(ps.iv));
  assert.equal(text(again), text(ps));
});

test('the recovery key reads back as shown and opens the same DEK', async () => {
  const secret = v.unbase32(fx.recovery_key);
  assert.equal(secret.length, 32);
  assert.equal(v.base32(secret), fx.recovery_key);
  assert.deepEqual(await v.unwrap(account, rs, fx.recovery_key), dek);
  assert.deepEqual(await v.unwrap(account, rs, fx.recovery_key.toLowerCase().replace(/ /g, '')), dek, 'case and spaces do not matter');
});

test('the recovery slot rebuilds byte for byte', async () => {
  const again = await v.recoverySlot(account, rs.id, v.unbase32(fx.recovery_key), dek, v.unb64u(rs.kdf.salt), v.unb64u(rs.iv));
  assert.equal(text(again), text(rs));
});

test('the item rebuilds byte for byte and opens', async () => {
  const bytes = v.unb64u(fx.item), [kind] = fx.item_id.split('.'), key = await v.dekKey(dek);
  const again = await v.sealItem(account, kind, fx.item_id, key, await v.dekId(dek), fx.value, bytes.slice(9, 21));
  assert.deepEqual(again, bytes);
  assert.deepEqual(await v.openItem(account, kind, fx.item_id, key, bytes), fx.value);
});

test('the item is bound to its account, kind and id', async () => {
  const bytes = v.unb64u(fx.item), [kind, id] = fx.item_id.split('.'), key = await v.dekKey(dek);
  await assert.rejects(v.openItem('ff'.repeat(16), kind, fx.item_id, key, bytes), wrong);
  await assert.rejects(v.openItem(account, 'note', `note.${id}`, key, bytes), wrong);
  await assert.rejects(v.openItem(account, kind, `${kind}.${'A'.repeat(22)}`, key, bytes), wrong);
});

test('a wrong passphrase or recovery key fails with OperationError', async () => {
  await assert.rejects(v.unwrap(account, ps, 'correct horse battery stapler'), wrong);
  await assert.rejects(v.unwrap(account, rs, v.base32(new Uint8Array(32))), wrong);
  await assert.rejects(v.unwrap('ff'.repeat(16), ps, fx.pass), wrong, 'the slot is bound to its account');
});

test('a pass slot under 600 000 rounds is refused', async () => {
  await assert.rejects(v.unwrap(account, { ...ps, kdf: { ...ps.kdf, iter: 599999 } }, fx.pass), /weaker than allowed/);
});

test('the passphrase is NFC-normalised', async () => {
  const nfc = 'crème brûlée, café', nfd = nfc.normalize('NFD');
  assert.notEqual(nfd, nfc);
  const salt = v.unb64u(ps.kdf.salt), iv = v.unb64u(ps.iv);
  const slot = await v.passSlot(account, ps.id, nfd, dek, salt, iv);
  assert.equal(text(slot), text(await v.passSlot(account, ps.id, nfc, dek, salt, iv)));
  assert.deepEqual(await v.unwrap(account, slot, nfc), dek);
});

test('new slots draw salts and IVs of the documented sizes', async () => {
  const id = v.b64u(new Uint8Array(16).fill(3)), secret = new Uint8Array(32).fill(7);
  const p = await v.passSlot(account, id, fx.pass, dek), r = await v.recoverySlot(account, id, secret, dek);
  assert.deepEqual([p.kdf.salt, p.iv, p.ct].map((s) => v.unb64u(s).length), [16, 12, 48]);
  assert.deepEqual([r.kdf.salt, r.iv, r.ct].map((s) => v.unb64u(s).length), [32, 12, 48]);
  assert.deepEqual(await v.unwrap(account, r, v.base32(secret)), dek);
});
