# Vault format, version 1

The vault holds secrets (TOTP seeds, SSH keys, passwords, notes) that sync between a user's browsers while the server only ever sees ciphertext. Encryption and decryption happen in the client, in `assets/vault.js` using WebCrypto only. The server stores opaque blobs in `acct_blobs`:

| `ns` | `k` | holds |
|---|---|---|
| `vault_slot` | slot id | a key slot (JSON) |
| `vault` | item id | an encrypted item (binary) |

Every byte layout below is fixed. Any client — this site, a later voipc client, a recovery tool — must produce and accept exactly these bytes.

## Threat model, plainly

The vault does protect against:
- A database or backup leak.
- An operator browsing the tables.

It does **not** protect against a malicious or compromised server, because that server also serves `vault.js`. A changed script can read what you unlock.

A passphrase change keeps the DEK and only re-wraps it. So the old passphrase still opens any older copy of the `pass` slot, from a backup or a dump taken before the change. The DEK from that copy then opens every item in any later leak, also the items written after the change. The recovery key works the same way. The page cannot replace or revoke it, and a new recovery slot under the same DEK would not help. If the old passphrase or the recovery key leaked, only a DEK rotation locks out someone who holds an older copy of a slot, and the page does not offer rotation yet (see Operations).

## Keys

- **DEK** (data encryption key): 32 random bytes per account, used as an AES-256-GCM key. Every item is encrypted under it.
- **KEK** (key encryption key): one per slot, derived from that slot's unlock secret. It wraps the DEK.

| slot `kind` | unlock secret | KDF |
|---|---|---|
| `pass` | the vault passphrase (UTF-8, NFC-normalised; never the login password) | PBKDF2-HMAC-SHA256, `iter` ≥ 600 000, 16-byte random `salt` |
| `recovery` | 32 random bytes, shown once as Base32 (RFC 4648, no padding, groups of 4) | HKDF-SHA256, 32-byte random `salt`, info `"l4f-vault-kek/v1"` |
| `prf` | WebAuthn PRF output (32 bytes) for passkey `cred_id` with eval salt `prf_salt` | HKDF-SHA256, 32-byte random `salt`, info `"l4f-vault-kek/v1"` |

Clients **must refuse** a `pass` slot with `iter` < 600 000. Otherwise a malicious server could hand back a weakened slot to speed up an offline guess.

## Slot (JSON, stored as UTF-8 bytes)

```json
{
  "v": 1,
  "id": "<slot id: 16 random bytes, base64url>",
  "kind": "pass" | "recovery" | "prf",
  "kdf": { "alg": "PBKDF2-SHA256", "iter": 600000, "salt": "<b64u>" }
       | { "alg": "HKDF-SHA256", "salt": "<b64u>", "info": "l4f-vault-kek/v1" },
  "cred_id": "<b64u, prf only>",
  "prf_salt": "<b64u 32 bytes, prf only>",
  "dek_id": "<b64u 8 bytes: first 8 bytes of SHA-256(DEK)>",
  "iv": "<b64u 12 bytes>",
  "ct": "<b64u: AES-256-GCM(KEK, iv, DEK, aad) = 32-byte DEK + 16-byte tag>"
}
```

- The AAD (additional authenticated data) for the wrap is `"l4f-vault-slot/v1|" + hex(account_id) + "|" + id`.
- Binding the AAD to the account id and slot id stops a server from moving a slot to another account, or relabelling one.
- `dek_id` lets a client tell which DEK a slot wraps while a rotation is under way.

## Item (binary)

```
offset  size  field
0       1     version = 0x01
1       8     dek_id
9       12    iv (random per write, never reused)
21      n     AES-256-GCM ciphertext || 16-byte tag
```

- The AAD is `"l4f-vault-item/v1|" + hex(account_id) + "|" + kind + "|" + item_id`.
- `kind` is the item's type (`totp`, `ssh`, `password`, `note`).
- `item_id` is the blob key `k`, written `kind.id` with `id` 16 random bytes in base64url, so a client knows the kind before it decrypts.
- So the server cannot swap one item for another, or change an item's type, without the decryption failing.
- The plaintext is UTF-8 JSON chosen by the item kind. One example:
  ```json
  {"v":1,"name":"GitHub","secret":"JBSW...","issuer":"GitHub","digits":6,"period":30,"algo":"SHA1"}
  ```
- Random 96-bit IVs are safe for up to 2^32 encryptions under one DEK. A rotation (below) is due long before that.

## Operations

- **Create the vault:**
  1. Fetch the slots. If there are any, the vault exists: unlock it instead. This stops a retry or a second tab. It cannot stop two creates at the very same moment, because the server takes any number of slots.
  2. Generate the DEK.
  3. Write a `pass` slot.
  4. Write a `recovery` slot. If either write fails, delete both slots again, best effort, with `If-Match: 0` (any version): a write whose answer was lost may still have landed.
  5. Show the recovery key once, as soon as both slots are written.
- **Unlock:**
  1. Fetch the slots.
  2. Derive the KEK for a slot of the chosen kind. With more than one, try first the slot whose `dek_id` the most items carry in their header, then the others.
  3. Unwrap the DEK.
  4. Import it as a **non-extractable** CryptoKey.
- **Change passphrase:** unwrap the DEK with the current passphrase or with the recovery key, then write a new `pass` slot. With the passphrase, it replaces the `pass` slot that opened (same id, compare-and-set on its version). With the recovery key, it replaces the `pass` slot with the same `dek_id`, or gets a new id if there is none. The DEK stays the same and no item is touched; the threat model above says what that leaves open.
- **Add a passkey slot:** in the same `get()` that unlocks, pass `prf: { eval: { first: prf_salt } }`, then write a `prf` slot. (Defined for the format; the page does not offer it yet.)
- **Rotate the DEK** (defined for the format; the page does not offer it yet), after a suspected leak or before 2^32 writes:
  1. Decrypt every item.
  2. Re-encrypt it under a new DEK.
  3. Re-wrap all slots.
  4. Upload with compare-and-set versions. The client keeps the old DEK until every write has succeeded.
- **Lock:** drop the key from memory. The page keeps the DEK only as a non-extractable CryptoKey in memory: reloading or leaving locks the vault, and a 401 from `/account/api/*` sends the browser to sign in.

## Test vectors

`tests/fixtures/vault/v1.json` holds fixed vectors, made by `assets/vault.js` under Node's WebCrypto:
- a `pass` slot (iter 600 000)
- a `recovery` slot
- one `totp` item

Two tests pin this layout with them:
- `tests/vault_vectors.rs` decrypts them with ring (`cargo test`).
- `tests/vault_vectors.mjs` runs `assets/vault.js` itself: `node tests/vault_vectors.mjs` (Node 22, no packages). It opens the `pass` slot for the DEK and rebuilds both slots and the item byte for byte from the vectors' salts and IVs. It also checks that a wrong secret fails with an `OperationError`, that a slot under 600 000 rounds is refused, and that the passphrase is NFC-normalised. `cargo test` runs it too when `node` is on PATH, and skips it otherwise.

A client change that breaks them is a format change. It needs `v: 2` and a migration, never an edit to version 1.
