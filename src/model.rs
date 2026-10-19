//! The account types every layer passes around. Pure: the store fills them,
//! the service and the web layer read them, and a non-HTTP host can use them
//! without sqlx.

use serde::{Serialize, Serializer};

use crate::util;

/// 16 random bytes, stored as `BINARY(16)` (Postgres `BYTEA`, SQLite `BLOB`).
/// Random rather than AUTO_INCREMENT so an id says nothing about how many
/// accounts exist or which came first. Roles reuse it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct AccountId(pub [u8; 16]);

// A fresh random id is no "default"; `Default` would invite `..Default::default()`
// handing out ids by accident.
#[allow(clippy::new_without_default)]
impl AccountId {
    pub fn new() -> Self {
        Self(util::random())
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_slice(b: &[u8]) -> Option<Self> {
        b.try_into().ok().map(Self)
    }

    /// For ids in URLs and forms: exactly 32 hex digits.
    pub fn parse_hex(s: &str) -> Option<Self> {
        if s.len() != 32 {
            return None;
        }
        Self::from_slice(&hex::decode(s).ok()?)
    }
}

/// Hex in JSON: an array of 16 numbers is unreadable in an export.
impl Serialize for AccountId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active = 0,
    Disabled = 1,
}

impl UserStatus {
    /// Anything but 0 is disabled: a value this code does not know must not let
    /// anyone in.
    pub fn from_db(v: i8) -> Self {
        if v == 0 { Self::Active } else { Self::Disabled }
    }
}

/// An account as everything outside the store sees it. The password hash and
/// the sealed TOTP secret never leave the store in this type, only whether
/// they exist.
#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub id: AccountId,
    pub username: String,
    pub display_name: String,
    /// Verified only; a new address waits in `email_pending`.
    pub email: Option<String>,
    pub email_pending: Option<String>,
    pub has_password: bool,
    pub totp_enabled: bool,
    /// At least one passkey: it can stand in for the password or be the second factor.
    pub has_passkey: bool,
    pub status: UserStatus,
    pub sync_enabled: bool,
    pub created_at: i64,
}

/// A login method other than the password: a passkey now, SSH keys, device
/// keys and social identities later. `(kind, ext_id)` is globally unique.
#[derive(Clone, Debug, Serialize)]
pub struct Credential {
    pub kind: String,
    /// Credential id, key fingerprint, device id or provider subject.
    #[serde(skip)]
    pub ext_id: Vec<u8>,
    pub user_id: AccountId,
    #[serde(skip)]
    pub public_key: Option<Vec<u8>>,
    pub alg: i64,
    pub sign_count: i64,
    /// Bit 0: a passkey's backup-eligible flag, which never changes for it.
    pub flags: i64,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// Shown on the public profile (linked identities only).
    pub public: bool,
}

/// `Credential::flags` bit for a passkey that may be synced (backup eligible).
pub const FLAG_BACKUP_ELIGIBLE: i64 = 1;

/// What `Store::create_user` writes. The caller picks the id, so it knows it
/// without a read back (MySQL has no `RETURNING`). No `Debug`: it carries the
/// password hash.
pub struct NewUser {
    pub id: AccountId,
    /// Already through `scope::normalize_username`.
    pub username: String,
    pub display_name: String,
    /// Unverified until the link in the mail is followed, so it never goes into
    /// the unique `email` column directly.
    pub email_pending: Option<String>,
    pub password_hash: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Role {
    pub id: AccountId,
    pub name: String,
    pub description: String,
    pub badge: Option<String>,
    /// `admin` and `user`: seeded at boot, editable, never deletable.
    pub builtin: bool,
    /// Sorted.
    pub scopes: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct SessionInfo {
    /// SHA-256 of the cookie value. Skipped in JSON: it names the session in the
    /// owner's revoke URL and has no business anywhere else.
    #[serde(skip)]
    pub token_hash: [u8; 32],
    pub user_id: AccountId,
    pub created_at: i64,
    pub seen_at: i64,
    pub expires_at: i64,
    /// Last full authentication, for step-up. 0 = never in this session.
    pub auth_at: i64,
    pub mfa_ok: bool,
    pub method: String,
    pub ip: String,
    pub ua: String,
}

/// By hand, to leave `token_hash` out of logs.
impl std::fmt::Debug for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionInfo")
            .field("user_id", &self.user_id)
            .field("created_at", &self.created_at)
            .field("seen_at", &self.seen_at)
            .field("expires_at", &self.expires_at)
            .field("auth_at", &self.auth_at)
            .field("mfa_ok", &self.mfa_ok)
            .field("method", &self.method)
            .field("ip", &self.ip)
            .field("ua", &self.ua)
            .finish_non_exhaustive()
    }
}

/// A sign-up invite as the admin list shows it. The code itself is never
/// stored; `id` is its hash in hex, which names it for revoking.
#[derive(Clone, Debug, Serialize)]
pub struct Invite {
    pub id: String,
    pub created_by: Option<AccountId>,
    /// Bound to this name, or `None` for the holder's choice.
    pub username: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub used_by: Option<AccountId>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub user_id: Option<AccountId>,
    pub actor_id: Option<AccountId>,
    pub event: String,
    pub detail: String,
    pub ip: String,
    pub at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_id_hex_round_trips_and_rejects_bad_input() {
        let id = AccountId::new();
        assert_ne!(id, AccountId::new(), "ids are random");
        assert_eq!(AccountId::parse_hex(&id.hex()), Some(id));
        assert_eq!(AccountId::from_slice(&id.0), Some(id));
        for bad in ["", "00", &"0".repeat(31), &"0".repeat(33), &"g".repeat(32), &"é".repeat(16)] {
            assert_eq!(AccountId::parse_hex(bad), None, "{bad:?} must be refused");
        }
        assert_eq!(AccountId::from_slice(&[0; 15]), None);
        assert_eq!(AccountId::from_slice(&[0; 17]), None);
    }

    #[test]
    fn ids_serialize_as_hex_and_status_as_a_word() {
        let id = AccountId([0xab; 16]);
        assert_eq!(serde_json::to_value(id).unwrap(), serde_json::json!("ab".repeat(16)));
        assert_eq!(serde_json::to_value(UserStatus::Disabled).unwrap(), serde_json::json!("disabled"));
        assert_eq!(UserStatus::from_db(0), UserStatus::Active);
        assert_eq!(UserStatus::from_db(7), UserStatus::Disabled, "unknown values fail closed");
    }

    #[test]
    fn session_json_leaves_the_token_hash_out() {
        let s = SessionInfo {
            token_hash: [0x5a; 32],
            user_id: AccountId([1; 16]),
            created_at: 1,
            seen_at: 2,
            expires_at: 3,
            auth_at: 0,
            mfa_ok: true,
            method: "password".into(),
            ip: String::new(),
            ua: String::new(),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert!(v.get("token_hash").is_none());
        assert!(!v.to_string().contains("5a5a"));
    }
}
