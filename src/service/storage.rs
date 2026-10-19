//! Opt-in storage: synced `store` settings (ns `kv`) and the end-to-end
//! encrypted vault (ns `vault`, `vault_slot`; see docs/vault-format.md). The
//! server keeps opaque values under compare-and-set versions and a quota per
//! account; for the vault it only ever sees ciphertext.

use super::{Accounts, Ctx, Error, Host, need};
use crate::model::{AccountId, User};
use crate::store::{Blob, PutBlob, PutLimited};
use crate::util;

pub(super) const KV: &str = "kv";
pub(super) const VAULT: &str = "vault";
pub(super) const SLOT: &str = "vault_slot";
/// The sync epoch's namespace and key (`sync_epoch`).
const EPOCH: &str = "kv_epoch";
pub const KV_MAX_KEYS: i64 = 200;
pub const KV_MAX_BYTES: usize = 32 * 1024;
pub const VAULT_ITEM_MAX: usize = 72 * 1024;
pub const VAULT_SLOT_MAX: usize = 4 * 1024;
pub const VAULT_MAX_ITEMS: i64 = 1000;
pub const VAULT_KINDS: [&str; 4] = ["totp", "ssh", "password", "note"];

/// How a write went. A conflict carries what is there now, for the client to
/// merge with.
pub enum Put {
    Done(i64),
    Conflict(Option<Blob>),
}

fn kv_key(k: &str) -> bool {
    (1..=64).contains(&k.len()) && k.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b':' | b'.' | b'_' | b'-'))
}

fn b64u_id(s: &str) -> bool {
    (16..=43).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `kind.id`: the kind is part of each item's AAD, so the client must know it
/// before it can decrypt.
fn item_key(k: &str) -> bool {
    k.split_once('.').is_some_and(|(kind, id)| VAULT_KINDS.contains(&kind) && b64u_id(id))
}

/// Shape only (the server cannot check what it cannot read): version byte,
/// dek_id, IV, and room for at least the tag.
fn item_shape(v: &[u8]) -> bool {
    v.len() >= 1 + 8 + 12 + 16 && v[0] == 1
}

/// A key slot: version 1, a known kind, and no PBKDF2 slot under 600 000
/// rounds, which no client should ever accept either.
fn slot_shape(k: &str, v: &[u8]) -> bool {
    let Ok(j) = serde_json::from_slice::<serde_json::Value>(v) else { return false };
    let iter_ok = match j["kind"].as_str() {
        Some("pass") => j["kdf"]["iter"].as_u64().is_some_and(|i| i >= 600_000),
        Some("recovery" | "prf") => true,
        _ => false,
    };
    j["v"] == 1 && j["id"].as_str() == Some(k) && iter_ok
}

impl<H: Host> Accounts<H> {
    /// `max_keys` and, for synced settings, the sync switch are checked under
    /// the account's lock: racing creates cannot all pass at the cap, nor a
    /// push land after sync was turned off and the copy deleted.
    pub(super) async fn put(&self, user: &User, ns: &str, k: &str, v: &[u8], expect: i64, max_keys: Option<i64>) -> Result<Put, Error> {
        let quota = self.host.config().storage_quota_bytes;
        match self.store.put_blob_limited(user.id, ns, k, v, expect, quota, max_keys, ns == KV).await? {
            PutLimited::Put(PutBlob::Done(ver)) => Ok(Put::Done(ver)),
            PutLimited::Put(PutBlob::Conflict) => Ok(Put::Conflict(self.store.blob(user.id, ns, k).await?)),
            PutLimited::Put(PutBlob::Quota) => Err(Error::Invalid("Your storage is full.")),
            PutLimited::Full if ns == KV => Err(Error::Invalid("Too many synced settings.")),
            PutLimited::Full => Err(Error::Invalid("Your vault is full.")),
            PutLimited::SyncOff => Err(Error::Invalid("Sync is off.")),
        }
    }

    // ---- synced settings

    fn sync_on(user: &User, scopes: &[String]) -> Result<(), Error> {
        need(scopes, "storage:sync")?;
        if user.sync_enabled { Ok(()) } else { Err(Error::Invalid("Sync is off.")) }
    }

    pub async fn kv_list(&self, user: &User, scopes: &[String]) -> Result<Vec<Blob>, Error> {
        Self::sync_on(user, scopes)?;
        Ok(self.store.blobs(user.id, KV).await?)
    }

    pub async fn kv_put(&self, user: &User, scopes: &[String], k: &str, v: &[u8], expect: i64) -> Result<Put, Error> {
        Self::sync_on(user, scopes)?;
        if !kv_key(k) {
            return Err(Error::Invalid("That is not a setting this site syncs."));
        }
        if v.len() > KV_MAX_BYTES || serde_json::from_slice::<serde_json::Value>(v).is_err() {
            return Err(Error::Invalid("That setting is too large or not JSON."));
        }
        self.put(user, KV, k, v, expect, Some(KV_MAX_KEYS)).await
    }

    pub async fn kv_delete(&self, user: &User, scopes: &[String], k: &str, expect: i64) -> Result<bool, Error> {
        Self::sync_on(user, scopes)?;
        Ok(self.store.delete_blob(user.id, KV, k, expect).await?)
    }

    /// Turning sync off deletes the server's copy; the browser keeps its own.
    /// Turning it on starts a new copy, under a new `sync_epoch`.
    pub async fn sync_set(&self, ctx: &Ctx, user: &User, scopes: &[String], on: bool) -> Result<(), Error> {
        if on {
            need(scopes, "storage:sync")?;
            // Before the switch, so a pull that sees sync on sees this epoch;
            // outside the quota, as the site's note rather than the account's
            // data. Of two turn-ons at once one writes it, new either way.
            self.store.delete_blobs(user.id, EPOCH).await?;
            self.store.put_blob(user.id, EPOCH, EPOCH, &util::random::<16>(), 0, i64::MAX).await?;
        }
        self.store.set_sync_enabled(user.id, on).await?;
        if !on {
            // The epoch before the copy: a pull that finds the copy gone then
            // finds no epoch either, and drops none of the values it holds.
            self.store.delete_blobs(user.id, EPOCH).await?;
            self.store.delete_blobs(user.id, KV).await?;
        }
        self.audit_after(ctx, Some(user.id), Some(user.id), if on { "sync_on" } else { "sync_off" }, "").await;
        Ok(())
    }

    /// The epoch of the server's copy: random, new each time sync is turned
    /// on, and none while it is off (nor for a copy older than epochs). A
    /// browser that last synced under another one knows that copy was deleted
    /// since, so what it saw then tells it nothing about what was deleted.
    pub async fn sync_epoch(&self, user: AccountId) -> sqlx::Result<Option<String>> {
        Ok(self.store.blob(user, EPOCH, EPOCH).await?.map(|b| util::b64u(&b.v)))
    }

    // ---- the vault

    /// Its slots and items, ciphertext all of it.
    pub async fn vault_list(&self, user: &User, scopes: &[String]) -> Result<(Vec<Blob>, Vec<Blob>), Error> {
        need(scopes, "vault:use")?;
        Ok((self.store.blobs(user.id, SLOT).await?, self.store.blobs(user.id, VAULT).await?))
    }

    pub async fn vault_put(&self, user: &User, scopes: &[String], slot: bool, k: &str, v: &[u8], expect: i64) -> Result<Put, Error> {
        need(scopes, "vault:use")?;
        let ok = if slot {
            b64u_id(k) && v.len() <= VAULT_SLOT_MAX && slot_shape(k, v)
        } else {
            item_key(k) && v.len() <= VAULT_ITEM_MAX && item_shape(v)
        };
        if !ok {
            return Err(Error::Invalid("That is not a vault entry this site takes."));
        }
        let (ns, max_keys) = if slot { (SLOT, None) } else { (VAULT, Some(VAULT_MAX_ITEMS)) };
        self.put(user, ns, k, v, expect, max_keys).await
    }

    pub async fn vault_delete(&self, user: &User, scopes: &[String], slot: bool, k: &str, expect: i64) -> Result<bool, Error> {
        need(scopes, "vault:use")?;
        Ok(self.store.delete_blob(user.id, if slot { SLOT } else { VAULT }, k, expect).await?)
    }

    /// Empties the vault: every item and slot. For a forgotten passphrase
    /// without the recovery key; nothing in it can be read without one.
    pub async fn vault_wipe(&self, ctx: &Ctx, user: &User, scopes: &[String]) -> Result<(), Error> {
        need(scopes, "vault:use")?;
        self.store.delete_blobs(user.id, VAULT).await?;
        self.store.delete_blobs(user.id, SLOT).await?;
        self.audit_after(ctx, Some(user.id), Some(user.id), "vault_wipe", "").await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_shapes() {
        assert!(kv_key("links:v1") && !kv_key("Links") && !kv_key("") && !kv_key(&"a".repeat(65)) && !kv_key("a/b"));
        assert!(item_key("totp.AAAAAAAAAAAAAAAAAAAAAA") && !item_key("evil.AAAAAAAAAAAAAAAAAAAAAA") && !item_key("totp.short"));
        let mut item = vec![1u8; 37];
        assert!(item_shape(&item));
        item[0] = 2;
        assert!(!item_shape(&item) && !item_shape(&[1; 36]));
        let id = "AAAAAAAAAAAAAAAAAAAAAA";
        let pass = |iter: u64| serde_json::json!({ "v": 1, "id": id, "kind": "pass", "kdf": { "iter": iter } }).to_string();
        assert!(slot_shape(id, pass(600_000).as_bytes()));
        assert!(!slot_shape(id, pass(1000).as_bytes()), "a weakened slot is refused");
        assert!(!slot_shape("BBBBBBBBBBBBBBBBBBBBBB", pass(600_000).as_bytes()), "the id must be the key");
        assert!(slot_shape(id, serde_json::json!({ "v": 1, "id": id, "kind": "recovery" }).to_string().as_bytes()));
        assert!(!slot_shape(id, b"not json"));
    }
}
