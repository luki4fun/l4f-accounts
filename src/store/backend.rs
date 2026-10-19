//! `Store`: one type for the service whatever the database, picked at run
//! time. Each backend has the same methods (`MySqlStore`, `pg::Backend`,
//! `lite::Backend`); this file only forwards to the one in use.

use sqlx::Transaction;

use super::{Blob, CreateUserError, EmailConfirm, Profile, PutBlob, WriteError};
use crate::model::{AccountId, AuditEntry, Credential, NewUser, Role, SessionInfo, User, UserStatus};

/// The account store. Clone is cheap (a pool handle).
#[derive(Clone)]
pub enum Store {
    #[cfg(feature = "mysql")]
    My(super::MySqlStore),
    #[cfg(feature = "postgres")]
    Pg(super::pg::Backend),
    #[cfg(feature = "sqlite")]
    Lite(super::lite::Backend),
}

/// A connection of whichever backend the store runs on: what a host's
/// `delete_user` gets, inside the deletion transaction, and what the boot lock
/// hands out for a host's own migrations.
pub enum StoreConn<'a> {
    #[cfg(feature = "mysql")]
    My(&'a mut sqlx::MySqlConnection),
    #[cfg(feature = "postgres")]
    Pg(&'a mut sqlx::PgConnection),
    #[cfg(feature = "sqlite")]
    Lite(&'a mut sqlx::SqliteConnection),
}

/// `Store::begin`'s transaction. Dropping it rolls back.
pub enum StoreTx {
    #[cfg(feature = "mysql")]
    My(Transaction<'static, sqlx::MySql>),
    #[cfg(feature = "postgres")]
    Pg(Transaction<'static, sqlx::Postgres>),
    #[cfg(feature = "sqlite")]
    Lite(Transaction<'static, sqlx::Sqlite>),
}

impl StoreTx {
    pub fn conn(&mut self) -> StoreConn<'_> {
        match self {
            #[cfg(feature = "mysql")]
            StoreTx::My(t) => StoreConn::My(t),
            #[cfg(feature = "postgres")]
            StoreTx::Pg(t) => StoreConn::Pg(t),
            #[cfg(feature = "sqlite")]
            StoreTx::Lite(t) => StoreConn::Lite(t),
        }
    }

    pub async fn rollback(self) -> sqlx::Result<()> {
        match self {
            #[cfg(feature = "mysql")]
            StoreTx::My(t) => t.rollback().await,
            #[cfg(feature = "postgres")]
            StoreTx::Pg(t) => t.rollback().await,
            #[cfg(feature = "sqlite")]
            StoreTx::Lite(t) => t.rollback().await,
        }
    }

    pub async fn commit(self) -> sqlx::Result<()> {
        match self {
            #[cfg(feature = "mysql")]
            StoreTx::My(t) => t.commit().await,
            #[cfg(feature = "postgres")]
            StoreTx::Pg(t) => t.commit().await,
            #[cfg(feature = "sqlite")]
            StoreTx::Lite(t) => t.commit().await,
        }
    }
}

#[cfg(feature = "mysql")]
impl From<sqlx::MySqlPool> for Store {
    fn from(pool: sqlx::MySqlPool) -> Self {
        Store::My(super::MySqlStore(pool))
    }
}

#[cfg(feature = "postgres")]
impl From<sqlx::PgPool> for Store {
    fn from(pool: sqlx::PgPool) -> Self {
        Store::Pg(super::pg::Backend(pool))
    }
}

#[cfg(feature = "sqlite")]
impl From<sqlx::SqlitePool> for Store {
    fn from(pool: sqlx::SqlitePool) -> Self {
        Store::Lite(super::lite::Backend(pool))
    }
}

impl Store {
    /// Connects to `mysql://…`, `postgres://…` or `sqlite://…`, whichever of
    /// them this build has. A SQLite file is created when missing and runs in
    /// WAL mode, so readers never wait for the writer.
    pub async fn connect(url: &str) -> sqlx::Result<Store> {
        let scheme = url.split_once(':').map_or("", |(s, _)| s);
        match scheme {
            #[cfg(feature = "mysql")]
            "mysql" | "mariadb" => Ok(sqlx::MySqlPool::connect(url).await?.into()),
            #[cfg(feature = "postgres")]
            "postgres" | "postgresql" => Ok(sqlx::PgPool::connect(url).await?.into()),
            #[cfg(feature = "sqlite")]
            "sqlite" => {
                use std::str::FromStr;
                let opts = sqlx::sqlite::SqliteConnectOptions::from_str(url)?
                    .create_if_missing(true)
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
                Ok(sqlx::SqlitePool::connect_with(opts).await?.into())
            }
            _ => Err(sqlx::Error::Configuration(format!("no database backend for {scheme:?} in this build").into())),
        }
    }

    pub async fn close(&self) {
        match self {
            #[cfg(feature = "mysql")]
            Store::My(s) => s.0.close().await,
            #[cfg(feature = "postgres")]
            Store::Pg(s) => s.0.close().await,
            #[cfg(feature = "sqlite")]
            Store::Lite(s) => s.0.close().await,
        }
    }

    /// See `MySqlStore::begin`.
    pub async fn begin(&self) -> sqlx::Result<StoreTx> {
        Ok(match self {
            #[cfg(feature = "mysql")]
            Store::My(s) => StoreTx::My(s.begin().await?),
            #[cfg(feature = "postgres")]
            Store::Pg(s) => StoreTx::Pg(s.begin().await?),
            #[cfg(feature = "sqlite")]
            Store::Lite(s) => StoreTx::Lite(s.begin().await?),
        })
    }

    /// See `MySqlStore::delete_user`.
    pub async fn delete_user(conn: StoreConn<'_>, id: AccountId) -> Result<bool, WriteError> {
        match conn {
            #[cfg(feature = "mysql")]
            StoreConn::My(c) => super::MySqlStore::delete_user(c, id).await,
            #[cfg(feature = "postgres")]
            StoreConn::Pg(c) => super::pg::Backend::delete_user(c, id).await,
            #[cfg(feature = "sqlite")]
            StoreConn::Lite(c) => super::lite::Backend::delete_user(c, id).await,
        }
    }
}

/// Forwards each listed method to the backend in use. The documentation of
/// each is on `MySqlStore`.
macro_rules! forward {
    ($(fn $name:ident(&self $(, $arg:ident: $ty:ty)*) -> $ret:ty;)*) => {
        impl Store {
            $(
                pub async fn $name(&self $(, $arg: $ty)*) -> $ret {
                    match self {
                        #[cfg(feature = "mysql")]
                        Store::My(s) => s.$name($($arg),*).await,
                        #[cfg(feature = "postgres")]
                        Store::Pg(s) => s.$name($($arg),*).await,
                        #[cfg(feature = "sqlite")]
                        Store::Lite(s) => s.$name($($arg),*).await,
                    }
                }
            )*
        }
    };
}

forward! {
    fn create_user(&self, u: &NewUser, role: Option<&str>) -> Result<(), CreateUserError>;
    fn user_by_id(&self, id: AccountId) -> sqlx::Result<Option<User>>;
    fn user_by_username(&self, username: &str) -> sqlx::Result<Option<User>>;
    fn user_by_email(&self, email: &str) -> sqlx::Result<Option<User>>;
    fn set_email_pending(&self, id: AccountId, email: Option<&str>) -> sqlx::Result<bool>;
    fn confirm_email(&self, id: AccountId, email: &str, now: i64) -> sqlx::Result<EmailConfirm>;
    fn clear_email(&self, id: AccountId) -> sqlx::Result<()>;
    fn password_hash_of(&self, id: AccountId) -> sqlx::Result<Option<String>>;
    fn set_password_hash(&self, id: AccountId, hash: &str) -> sqlx::Result<bool>;
    fn rehash_password(&self, id: AccountId, old: &str, new: &str) -> sqlx::Result<bool>;
    fn set_status(&self, id: AccountId, status: UserStatus) -> Result<bool, WriteError>;
    fn set_display_name(&self, id: AccountId, name: &str) -> sqlx::Result<bool>;
    fn set_sync_enabled(&self, id: AccountId, on: bool) -> sqlx::Result<bool>;
    fn list_users(&self, search: Option<&str>, limit: u32, offset: u32) -> sqlx::Result<(Vec<User>, i64)>;
    fn insert_session(&self, s: &SessionInfo) -> sqlx::Result<()>;
    fn session_by_hash(&self, hash: &[u8; 32], now: i64) -> sqlx::Result<Option<SessionInfo>>;
    fn touch_session(&self, hash: &[u8; 32], now: i64) -> sqlx::Result<bool>;
    fn set_session_mfa(&self, hash: &[u8; 32], mfa_ok: bool, auth_at: i64) -> sqlx::Result<bool>;
    fn rotate_session(&self, old: &[u8; 32], new: &[u8; 32]) -> sqlx::Result<bool>;
    fn complete_session(&self, old: &[u8; 32], new: &[u8; 32], auth_at: i64, expires_at: i64) -> sqlx::Result<bool>;
    fn refresh_session(&self, old: &[u8; 32], new: &[u8; 32], auth_at: i64) -> sqlx::Result<bool>;
    fn delete_session(&self, hash: &[u8; 32], user: AccountId) -> sqlx::Result<bool>;
    fn delete_sessions_of(&self, user: AccountId, except: Option<&[u8; 32]>) -> sqlx::Result<u64>;
    fn sessions_of(&self, user: AccountId) -> sqlx::Result<Vec<SessionInfo>>;
    fn delete_expired_sessions(&self, now: i64, idle_secs: i64, batch: u64) -> sqlx::Result<u64>;
    fn totp_of(&self, user: AccountId) -> sqlx::Result<Option<(Vec<u8>, i64)>>;
    fn set_totp(&self, user: AccountId, sealed: Option<&[u8]>, last_step: i64) -> sqlx::Result<bool>;
    fn advance_totp(&self, user: AccountId, step: i64) -> sqlx::Result<bool>;
    fn reseal_totp(&self, user: AccountId, old: &[u8], new: &[u8]) -> sqlx::Result<bool>;
    fn replace_recovery(&self, user: AccountId, hashes: &[[u8; 32]]) -> sqlx::Result<()>;
    fn use_recovery(&self, user: AccountId, hash: &[u8; 32], now: i64) -> sqlx::Result<bool>;
    fn recovery_left(&self, user: AccountId) -> sqlx::Result<i64>;
    fn delete_recovery(&self, user: AccountId) -> sqlx::Result<()>;
    fn blobs(&self, user: AccountId, ns: &str) -> sqlx::Result<Vec<Blob>>;
    fn blob(&self, user: AccountId, ns: &str, k: &str) -> sqlx::Result<Option<Blob>>;
    fn blob_count(&self, user: AccountId, ns: &str) -> sqlx::Result<i64>;
    fn put_blob(&self, user: AccountId, ns: &str, k: &str, v: &[u8], expect: i64, quota: i64) -> sqlx::Result<PutBlob>;
    fn delete_blob(&self, user: AccountId, ns: &str, k: &str, expect: i64) -> sqlx::Result<bool>;
    fn delete_blobs(&self, user: AccountId, ns: &str) -> sqlx::Result<u64>;
    fn profile(&self, user: AccountId) -> sqlx::Result<Profile>;
    fn save_profile(&self, user: AccountId, p: &Profile, now: i64) -> sqlx::Result<()>;
    fn profile_owner(&self, public_id: &[u8; 16]) -> sqlx::Result<Option<AccountId>>;
    fn set_credential_public(&self, user: AccountId, kind: &str, ext_id: &[u8], public: bool) -> sqlx::Result<bool>;
    fn public_identities(&self, user: AccountId) -> sqlx::Result<Vec<(String, String)>>;
    fn insert_credential(&self, c: &Credential) -> sqlx::Result<bool>;
    fn credential(&self, kind: &str, ext_id: &[u8]) -> sqlx::Result<Option<Credential>>;
    fn credentials_of(&self, user: AccountId, kind: &str) -> sqlx::Result<Vec<Credential>>;
    fn delete_credential(&self, user: AccountId, kind: &str, ext_id: &[u8]) -> sqlx::Result<bool>;
    fn delete_credentials_of(&self, user: AccountId, kind: &str) -> sqlx::Result<u64>;
    fn delete_stale_credentials(&self, kind: &str, before: i64, batch: u64) -> sqlx::Result<u64>;
    fn login_credentials(&self, user: AccountId) -> sqlx::Result<i64>;
    fn used_credential(&self, kind: &str, ext_id: &[u8], sign_count: i64, now: i64) -> sqlx::Result<bool>;
    fn ensure_builtin_roles(&self, user_scopes: &[String]) -> sqlx::Result<()>;
    fn roles(&self) -> sqlx::Result<Vec<Role>>;
    fn role_by_name(&self, name: &str) -> sqlx::Result<Option<Role>>;
    fn create_role(&self, name: &str, description: &str, badge: Option<&str>) -> sqlx::Result<Option<AccountId>>;
    fn update_role(&self, role: AccountId, description: &str, badge: Option<&str>) -> sqlx::Result<bool>;
    fn set_role_scopes(&self, role: AccountId, scopes: &[String]) -> Result<(), WriteError>;
    fn delete_role(&self, role: AccountId) -> Result<bool, WriteError>;
    fn user_roles(&self, user: AccountId) -> sqlx::Result<Vec<Role>>;
    fn user_scopes(&self, user: AccountId) -> sqlx::Result<Vec<String>>;
    fn grant_role(&self, user: AccountId, role: AccountId, by: Option<AccountId>) -> sqlx::Result<bool>;
    fn revoke_role(&self, user: AccountId, role: AccountId) -> Result<bool, WriteError>;
    fn holders_of_scope_star(&self) -> sqlx::Result<i64>;
    fn audit(&self, user: Option<AccountId>, actor: Option<AccountId>, event: &str, detail: &str, ip: &str) -> sqlx::Result<()>;
    fn audit_of(&self, user: AccountId, limit: u32) -> sqlx::Result<Vec<AuditEntry>>;
    fn delete_audit_before(&self, ts: i64, batch: u64) -> sqlx::Result<u64>;
    fn export_user(&self, id: AccountId) -> sqlx::Result<Option<serde_json::Value>>;
}
