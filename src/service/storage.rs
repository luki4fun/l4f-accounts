//! Opt-in storage: synced `store` settings (ns `kv`) and the end-to-end
//! encrypted vault (ns `vault`, `vault_slot`; see docs/vault-format.md). The
//! server keeps opaque values under compare-and-set versions and a quota per
//! account; for the vault it only ever sees ciphertext.

use super::{Accounts, Ctx, Error, Host};
use crate::model::User;
use crate::scope;
use crate::store::{Blob, PutBlob};

pub(super) const KV: &str = "kv";
pub(super) const VAULT: &str = "vault";
pub(super) const SLOT: &str = "vault_slot";
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
    fn need(scopes: &[String], s: &str) -> Result<(), Error> {
        if scope::allowed(scopes, s) { Ok(()) } else { Err(Error::Forbidden) }
    }

    async fn put(&self, user: &User, ns: &str, k: &str, v: &[u8], expect: i64) -> Result<Put, Error> {
        let quota = self.host.config().storage_quota_bytes;
        match self.store.put_blob(user.id, ns, k, v, expect, quota).await? {
            PutBlob::Done(ver) => Ok(Put::Done(ver)),
            PutBlob::Conflict => Ok(Put::Conflict(self.store.blob(user.id, ns, k).await?)),
            PutBlob::Quota => Err(Error::Invalid("Your storage is full.")),
        }
    }

    // ---- synced settings

    fn sync_on(user: &User, scopes: &[String]) -> Result<(), Error> {
        Self::need(scopes, "storage:sync")?;
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
        if expect == 0 && self.store.blob_count(user.id, KV).await? >= KV_MAX_KEYS {
            return Err(Error::Invalid("Too many synced settings."));
        }
        self.put(user, KV, k, v, expect).await
    }

    pub async fn kv_delete(&self, user: &User, scopes: &[String], k: &str, expect: i64) -> Result<bool, Error> {
        Self::sync_on(user, scopes)?;
        Ok(self.store.delete_blob(user.id, KV, k, expect).await?)
    }

    /// Turning sync off deletes the server's copy; the browser keeps its own.
    pub async fn sync_set(&self, ctx: &Ctx, user: &User, scopes: &[String], on: bool) -> Result<(), Error> {
        if on {
            Self::need(scopes, "storage:sync")?;
        }
        self.store.set_sync_enabled(user.id, on).await?;
        if !on {
            self.store.delete_blobs(user.id, KV).await?;
        }
        self.audit(ctx, Some(user.id), Some(user.id), if on { "sync_on" } else { "sync_off" }, "").await?;
        Ok(())
    }

    // ---- the vault

    /// Its slots and items, ciphertext all of it.
    pub async fn vault_list(&self, user: &User, scopes: &[String]) -> Result<(Vec<Blob>, Vec<Blob>), Error> {
        Self::need(scopes, "vault:use")?;
        Ok((self.store.blobs(user.id, SLOT).await?, self.store.blobs(user.id, VAULT).await?))
    }

    pub async fn vault_put(&self, user: &User, scopes: &[String], slot: bool, k: &str, v: &[u8], expect: i64) -> Result<Put, Error> {
        Self::need(scopes, "vault:use")?;
        let ok = if slot {
            b64u_id(k) && v.len() <= VAULT_SLOT_MAX && slot_shape(k, v)
        } else {
            item_key(k) && v.len() <= VAULT_ITEM_MAX && item_shape(v)
        };
        if !ok {
            return Err(Error::Invalid("That is not a vault entry this site takes."));
        }
        if !slot && expect == 0 && self.store.blob_count(user.id, VAULT).await? >= VAULT_MAX_ITEMS {
            return Err(Error::Invalid("Your vault is full."));
        }
        self.put(user, if slot { SLOT } else { VAULT }, k, v, expect).await
    }

    pub async fn vault_delete(&self, user: &User, scopes: &[String], slot: bool, k: &str, expect: i64) -> Result<bool, Error> {
        Self::need(scopes, "vault:use")?;
        Ok(self.store.delete_blob(user.id, if slot { SLOT } else { VAULT }, k, expect).await?)
    }

    /// Empties the vault: every item and slot. For a forgotten passphrase
    /// without the recovery key; nothing in it can be read without one.
    pub async fn vault_wipe(&self, ctx: &Ctx, user: &User, scopes: &[String]) -> Result<(), Error> {
        Self::need(scopes, "vault:use")?;
        self.store.delete_blobs(user.id, VAULT).await?;
        self.store.delete_blobs(user.id, SLOT).await?;
        self.audit(ctx, Some(user.id), Some(user.id), "vault_wipe", "").await?;
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
