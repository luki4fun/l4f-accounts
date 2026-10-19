//! `Store`: one type for the service whatever the database, picked at run
//! time. Each backend has the same methods (`my::Backend`, also known as
//! `MySqlStore`, `pg::Backend` and `lite::Backend`, all from
//! `store/portable.rs`); this file forwards to the one in use, and documents
//! what each method promises.

use sqlx::Transaction;

use super::{Blob, CreateUserError, DeleteCredential, EmailConfirm, InviteSignup, Profile, PutBlob, PutLimited, WriteError};
use crate::model::{AccountId, AuditEntry, Credential, Invite, NewUser, Role, SessionInfo, User, UserStatus};

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

/// `Store::begin`'s transaction. Dropping it rolls back. It holds the
/// last-admin guard until it ends, so every write inside goes through
/// `conn()`: one through the pool can wait on it (see `Store::begin`).
pub enum StoreTx {
    #[cfg(feature = "mysql")]
    My(Transaction<'static, sqlx::MySql>),
    #[cfg(feature = "postgres")]
    Pg(Transaction<'static, sqlx::Postgres>),
    #[cfg(feature = "sqlite")]
    Lite(Transaction<'static, sqlx::Sqlite>),
}

/// A match with one arm per backend in the build, each running `$body` on the
/// variant's value; with `as`, the result goes back into the same variant of
/// another of these enums.
macro_rules! each {
    ($e:expr, $E:ident($v:ident) => $body:expr) => {
        match $e {
            #[cfg(feature = "mysql")]
            $E::My($v) => $body,
            #[cfg(feature = "postgres")]
            $E::Pg($v) => $body,
            #[cfg(feature = "sqlite")]
            $E::Lite($v) => $body,
        }
    };
    ($e:expr, $E:ident($v:ident) as $F:ident => $body:expr) => {
        match $e {
            #[cfg(feature = "mysql")]
            $E::My($v) => $F::My($body),
            #[cfg(feature = "postgres")]
            $E::Pg($v) => $F::Pg($body),
            #[cfg(feature = "sqlite")]
            $E::Lite($v) => $F::Lite($body),
        }
    };
}
#[cfg(test)]
pub(super) use each;

impl StoreTx {
    pub fn conn(&mut self) -> StoreConn<'_> {
        each!(self, StoreTx(t) as StoreConn => t)
    }

    pub async fn rollback(self) -> sqlx::Result<()> {
        each!(self, StoreTx(t) => t.rollback().await)
    }

    pub async fn commit(self) -> sqlx::Result<()> {
        each!(self, StoreTx(t) => t.commit().await)
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
    /// WAL mode, so readers never wait for the writer. It has to be a file:
    /// `migrate::run` refuses an in-memory or temporary database.
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
                use std::time::{Duration, Instant};
                let opts = sqlx::sqlite::SqliteConnectOptions::from_str(url)?
                    .create_if_missing(true)
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
                // The switch to WAL takes an exclusive lock and does not wait
                // for it: of processes opening a new file at once, all but one
                // get SQLITE_BUSY (primary code 5). Those try again, a while.
                let busy = |e: &sqlx::Error| {
                    matches!(e, sqlx::Error::Database(d) if d.code().is_some_and(|c| c.parse::<i32>().is_ok_and(|c| c & 0xff == 5)))
                };
                let until = Instant::now() + Duration::from_secs(5);
                loop {
                    match sqlx::SqlitePool::connect_with(opts.clone()).await {
                        Err(e) if busy(&e) && Instant::now() < until => tokio::time::sleep(Duration::from_millis(20)).await,
                        r => return Ok(r?.into()),
                    }
                }
            }
            _ => Err(sqlx::Error::Configuration(format!("no database backend for {scheme:?} in this build").into())),
        }
    }

    pub async fn close(&self) {
        each!(self, Store(s) => s.0.close().await)
    }

    /// A transaction for composing with `delete_user`, isolated the way the
    /// last-admin guard needs, and holding the guard's locks from the start.
    /// The caller's own writes come before `delete_user`'s count; had they
    /// locked an admin's row first, two admins deleting each other would each
    /// hold a row the other's count waits on.
    ///
    /// The guard is held until the transaction ends, so every write inside it
    /// goes through `tx.conn()`. One through the pool, `Store` or `Accounts`
    /// can wait on this transaction (on SQLite any write does), and fails when
    /// the wait runs out: Postgres's `lock_timeout` (30 s on guarded writes),
    /// SQLite's busy timeout, MySQL's `innodb_lock_wait_timeout`.
    pub async fn begin(&self) -> sqlx::Result<StoreTx> {
        Ok(each!(self, Store(s) as StoreTx => s.begin().await?))
    }

    /// One DELETE; the foreign keys take sessions, grants, credentials,
    /// recovery codes, blobs, the profile and the audit rows with it.
    ///
    /// Takes a connection, not `&self`: the service runs it inside the
    /// transaction (from `Store::begin`) that also removes the host's rows for
    /// the account. Inside one, this nests as a savepoint, so a refusal (last
    /// `*` holder) rolls back only this part and leaves the rest to the caller.
    /// On Postgres that transaction must be READ COMMITTED, as `Store::begin`'s
    /// is: at any other level the guard cannot see the write it waited for,
    /// so this refuses with `InvalidArgument`.
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

/// Forwards each listed method, with its docs, to the backend in use.
macro_rules! forward {
    ($($(#[$m:meta])* fn $name:ident(&self $(, $arg:ident: $ty:ty)*) -> $ret:ty;)*) => {
        impl Store {
            $(
                $(#[$m])*
                pub async fn $name(&self $(, $arg: $ty)*) -> $ret {
                    each!(self, Store(s) => s.$name($($arg),*).await)
                }
            )*
        }
    };
}

forward! {
    // ------------------------------------------------------------------ users

    /// Plain INSERT: the unique key settles a race for a name, not a SELECT
    /// first. `role`, when given, is granted in the same transaction, so an
    /// account never exists without the role it was made for. For bootstrap's
    /// admin that matters: a half-made one would hold the name and refuse the
    /// next boot.
    fn create_user(&self, u: &NewUser, role: Option<&str>) -> Result<(), CreateUserError>;
    fn user_by_id(&self, id: AccountId) -> sqlx::Result<Option<User>>;
    /// `username` as `scope::normalize_username` returns it. The column
    /// compares bytes, so case is not folded; on MySQL it is also PAD SPACE:
    /// `"name "` finds `name`. Never pass a raw string here.
    fn user_by_username(&self, username: &str) -> sqlx::Result<Option<User>>;
    /// A verified address only: a pending one belongs to nobody yet.
    fn user_by_email(&self, email: &str) -> sqlx::Result<Option<User>>;
    fn set_email_pending(&self, id: AccountId, email: Option<&str>) -> sqlx::Result<bool>;
    /// The pending address becomes the verified one, if it is still the one
    /// the link was for.
    fn confirm_email(&self, id: AccountId, email: &str, now: i64) -> sqlx::Result<EmailConfirm>;
    fn clear_email(&self, id: AccountId) -> sqlx::Result<()>;
    fn password_hash_of(&self, id: AccountId) -> sqlx::Result<Option<String>>;
    /// The first password of an account without one: false once it has one,
    /// so two first passwords set at once (a reset link used twice, or a reset
    /// racing the password page) cannot both be written. A password that
    /// replaces another goes through `rehash_password`.
    fn set_password_hash(&self, id: AccountId, hash: &str) -> sqlx::Result<bool>;
    /// The upgrade after a login whose hash `needs_rehash`: only while `old` is
    /// still the stored hash. A password change that lands while the login is
    /// verifying would otherwise be overwritten with the old password.
    fn rehash_password(&self, id: AccountId, old: &str, new: &str) -> sqlx::Result<bool>;
    /// Refuses to disable the last active holder of `*`. The caller still
    /// deletes the sessions of an account it disables.
    fn set_status(&self, id: AccountId, status: UserStatus) -> Result<bool, WriteError>;
    fn set_display_name(&self, id: AccountId, name: &str) -> sqlx::Result<bool>;
    fn set_sync_enabled(&self, id: AccountId, on: bool) -> sqlx::Result<bool>;
    /// Newest first, with the total for paging. `search` matches username,
    /// display name and verified email, case-insensitively (the columns
    /// compare bytes, so LIKE alone would not be).
    fn list_users(&self, search: Option<&str>, limit: u32, offset: u32) -> sqlx::Result<(Vec<User>, i64)>;

    // --------------------------------------------------------------- sessions

    /// Inserts only for an active account: a login still in flight when the
    /// account is disabled or deleted gets `RowNotFound`, not a session. Keeps
    /// the newest `MAX_SESSIONS` signed-in sessions per account (and
    /// `MAX_PENDING` waiting for a second factor), so a script that logs in in a
    /// loop cannot grow the table without bound. Pending sessions never push
    /// out signed-in ones: knowing the password alone must not sign the owner out.
    fn insert_session(&self, s: &SessionInfo) -> sqlx::Result<()>;
    /// Absolute expiry only; the idle limit is config, so the service checks
    /// `seen_at` itself.
    fn session_by_hash(&self, hash: &[u8; 32], now: i64) -> sqlx::Result<Option<SessionInfo>>;
    /// True when it wrote, i.e. `seen_at` was more than `TOUCH_SECS` old.
    fn touch_session(&self, hash: &[u8; 32], now: i64) -> sqlx::Result<bool>;
    /// New token, same session: a token seen before a privilege change (login,
    /// MFA, step-up, role change) stops working after it.
    fn rotate_session(&self, old: &[u8; 32], new: &[u8; 32]) -> sqlx::Result<bool>;
    /// The second factor is done: a new token, `mfa_ok`, the full lifetime.
    /// Only a pending session completes, and only once. It then counts
    /// against `MAX_SESSIONS`, as a login without a second factor does.
    fn complete_session(&self, old: &[u8; 32], new: &[u8; 32], auth_at: i64, expires_at: i64) -> sqlx::Result<bool>;
    /// Step-up: a new token and a fresh `auth_at`, on a complete session only.
    fn refresh_session(&self, old: &[u8; 32], new: &[u8; 32], auth_at: i64) -> sqlx::Result<bool>;
    /// Scoped to the owner: the revoke button posts a hash from a URL, and a
    /// hash belonging to someone else must delete nothing.
    fn delete_session(&self, hash: &[u8; 32], user: AccountId) -> sqlx::Result<bool>;
    /// "Sign out everywhere" keeps `except`, the session asking.
    fn delete_sessions_of(&self, user: AccountId, except: Option<&[u8; 32]>) -> sqlx::Result<u64>;
    /// Most recently used first. Includes rows the sweep has not reached yet;
    /// the caller knows the idle limit and filters.
    fn sessions_of(&self, user: AccountId) -> sqlx::Result<Vec<SessionInfo>>;
    /// One batch; the sweeper loops while a call returns a full one. Small
    /// batches keep each lock short.
    fn delete_expired_sessions(&self, now: i64, idle_secs: i64, batch: u64) -> sqlx::Result<u64>;

    // ------------------------------------------------------- second factors

    /// The sealed TOTP secret and the last step a code was accepted for.
    fn totp_of(&self, user: AccountId) -> sqlx::Result<Option<(Vec<u8>, i64)>>;
    /// Turns codes on (only while off, so two setups cannot race) or off.
    fn set_totp(&self, user: AccountId, sealed: Option<&[u8]>, last_step: i64) -> sqlx::Result<bool>;
    /// Accepts a code's step once: false when this step or a later one was
    /// already used, so a code read over a shoulder is worth nothing after.
    fn advance_totp(&self, user: AccountId, step: i64) -> sqlx::Result<bool>;
    /// The same secret under the current key, unless it changed meanwhile.
    fn reseal_totp(&self, user: AccountId, old: &[u8], new: &[u8]) -> sqlx::Result<bool>;
    /// Accounts with codes on and their sealed secrets, by id, from just past
    /// `after` (all zeros to start): the sweep pages through them to reseal.
    fn totp_rows(&self, after: AccountId, limit: u64) -> sqlx::Result<Vec<(AccountId, Vec<u8>)>>;
    /// A fresh set of recovery code hashes in place of the old one. Two at
    /// once leave one set, the later one's.
    fn replace_recovery(&self, user: AccountId, hashes: &[[u8; 32]]) -> sqlx::Result<()>;
    /// Spends one code: false when it is unknown or already spent.
    fn use_recovery(&self, user: AccountId, hash: &[u8; 32], now: i64) -> sqlx::Result<bool>;
    fn recovery_left(&self, user: AccountId) -> sqlx::Result<i64>;
    fn delete_recovery(&self, user: AccountId) -> sqlx::Result<()>;

    // ---------------------------------------------------------------- blobs

    fn blobs(&self, user: AccountId, ns: &str) -> sqlx::Result<Vec<Blob>>;
    fn blob(&self, user: AccountId, ns: &str, k: &str) -> sqlx::Result<Option<Blob>>;
    fn blob_count(&self, user: AccountId, ns: &str) -> sqlx::Result<i64>;
    /// Compare-and-set: `expect` 0 creates (and finds a conflict if the key
    /// exists), any other value replaces only that version. The account's row
    /// is locked first, so two writes cannot both fit under the quota, then
    /// the key's, so a `delete_blob` landing meanwhile makes this a conflict
    /// instead of being undone.
    fn put_blob(&self, user: AccountId, ns: &str, k: &str, v: &[u8], expect: i64, quota: i64) -> sqlx::Result<PutBlob>;
    /// `put_blob` with two more refusals, checked under the same account lock
    /// so that racing writes cannot pass them together: a create (`expect` 0)
    /// once `ns` holds `max_keys` keys, and with `need_sync`, an account whose
    /// sync is off (a push that waited while it was turned off stays out).
    #[allow(clippy::too_many_arguments)]
    fn put_blob_limited(
        &self,
        user: AccountId,
        ns: &str,
        k: &str,
        v: &[u8],
        expect: i64,
        quota: i64,
        max_keys: Option<i64>,
        need_sync: bool
    ) -> sqlx::Result<PutLimited>;
    /// `expect` 0 deletes whatever version is there.
    fn delete_blob(&self, user: AccountId, ns: &str, k: &str, expect: i64) -> sqlx::Result<bool>;
    fn delete_blobs(&self, user: AccountId, ns: &str) -> sqlx::Result<u64>;

    // -------------------------------------------------------------- profile

    fn profile(&self, user: AccountId) -> sqlx::Result<Profile>;
    fn save_profile(&self, user: AccountId, p: &Profile, now: i64) -> sqlx::Result<()>;
    /// The account behind a public profile link, if the profile is on.
    fn profile_owner(&self, public_id: &[u8; 16]) -> sqlx::Result<Option<AccountId>>;
    /// Whether a credential (a linked identity) shows on the public profile.
    fn set_credential_public(&self, user: AccountId, kind: &str, ext_id: &[u8], public: bool) -> sqlx::Result<bool>;
    /// Linked identities shown on the profile: (kind, name).
    fn public_identities(&self, user: AccountId) -> sqlx::Result<Vec<(String, String)>>;

    // ---------------------------------------------------------- credentials

    /// A plain INSERT: false when `(kind, ext_id)` already exists, so a key can
    /// never be moved to a second account by registering it again.
    fn insert_credential(&self, c: &Credential) -> sqlx::Result<bool>;
    fn credential(&self, kind: &str, ext_id: &[u8]) -> sqlx::Result<Option<Credential>>;
    /// Oldest first.
    fn credentials_of(&self, user: AccountId, kind: &str) -> sqlx::Result<Vec<Credential>>;
    /// Scoped to the owner, like `delete_session`.
    fn delete_credential(&self, user: AccountId, kind: &str, ext_id: &[u8]) -> sqlx::Result<bool>;
    /// Every credential of one kind an account has, e.g. its device keys when a
    /// second factor changes.
    fn delete_credentials_of(&self, user: AccountId, kind: &str) -> sqlx::Result<u64>;
    /// One batch of credentials of `kind` unused since `before`.
    fn delete_stale_credentials(&self, kind: &str, before: i64, batch: u64) -> sqlx::Result<u64>;
    /// Credentials that sign in on their own: passkeys, SSH keys, social
    /// identities. Device keys only stand in for one of these, so they do not
    /// count as a way in.
    fn login_credentials(&self, user: AccountId) -> sqlx::Result<i64>;
    /// Credentials that sign in and can also make a session recent: passkeys
    /// and social identities. An SSH sign-in never is, and there is no SSH
    /// step-up.
    fn step_up_credentials(&self, user: AccountId) -> sqlx::Result<i64>;
    /// `delete_credential`, unless the account would be left with neither its
    /// password nor a credential `step_up_credentials` counts: with SSH keys
    /// alone it could sign in but never confirm it's you. Counted after the
    /// delete, in its transaction, with the account's row locked first: two
    /// removals at once run one after the other, so they cannot both take
    /// what the other one counted on.
    fn delete_credential_if_not_last(&self, user: AccountId, kind: &str, ext_id: &[u8]) -> sqlx::Result<DeleteCredential>;
    /// Records a use. The counter only moves forward; 0 is taken only while
    /// the stored one is 0 too (authenticators that keep it there), so a clone
    /// reporting 0 cannot reset a counter in use. False means the credential
    /// is gone, another use raced this one or the authenticator went
    /// backwards, and the caller refuses.
    fn used_credential(&self, kind: &str, ext_id: &[u8], sign_count: i64, now: i64) -> sqlx::Result<bool>;

    // ------------------------------------------------------------------ roles

    /// Seeds `admin` (`*`) and `user` (`user_scopes`) on first boot. Scopes are
    /// written only when the role row is new: an admin who later trimmed the
    /// `user` role must not see it grow back on every restart.
    fn ensure_builtin_roles(&self, user_scopes: &[String]) -> sqlx::Result<()>;
    fn roles(&self) -> sqlx::Result<Vec<Role>>;
    fn role_by_name(&self, name: &str) -> sqlx::Result<Option<Role>>;
    /// `None` when the name is taken. Scopes come after, via `set_role_scopes`,
    /// so the role exists without them meanwhile: `create_role_with_scopes`
    /// for one that must not.
    fn create_role(&self, name: &str, description: &str, badge: Option<&str>) -> sqlx::Result<Option<AccountId>>;
    /// `create_role` and its scopes in one transaction. Until it commits nobody
    /// sees the role; an empty one would pass a grant's check that the granter
    /// covers what the role carries, and keep its grant once the scopes came.
    fn create_role_with_scopes(&self, name: &str, description: &str, badge: Option<&str>, scopes: &[String]) -> sqlx::Result<Option<AccountId>>;
    fn update_role(&self, role: AccountId, description: &str, badge: Option<&str>) -> sqlx::Result<bool>;
    /// Replaces the whole set in one transaction: a failure half-way leaves the
    /// old set, never an empty or partial one.
    fn set_role_scopes(&self, role: AccountId, scopes: &[String]) -> Result<(), WriteError>;
    /// False when there is no such role. Its scopes and grants go with it.
    fn delete_role(&self, role: AccountId) -> Result<bool, WriteError>;
    fn user_roles(&self, user: AccountId) -> sqlx::Result<Vec<Role>>;
    /// Every scope of every role the account holds, deduplicated and sorted.
    fn user_scopes(&self, user: AccountId) -> sqlx::Result<Vec<String>>;
    /// False when the account already held the role. Plain INSERT, not IGNORE:
    /// IGNORE would also swallow a missing user or role.
    fn grant_role(&self, user: AccountId, role: AccountId, by: Option<AccountId>) -> sqlx::Result<bool>;
    /// False when the account did not hold the role.
    fn revoke_role(&self, user: AccountId, role: AccountId) -> Result<bool, WriteError>;
    /// Active accounts holding `*`. Zero means nobody can administer the site:
    /// bootstrap runs then. A disabled admin does not count, since they cannot
    /// sign in.
    fn holders_of_scope_star(&self) -> sqlx::Result<i64>;

    // ------------------------------------------------------------------ audit

    /// `ip` is already shaped (`ip::shape_ip`); `detail` is cut to the column.
    fn audit(&self, user: Option<AccountId>, actor: Option<AccountId>, event: &str, detail: &str, ip: &str) -> sqlx::Result<()>;
    /// Newest first. `ip` is blanked on rows another account acted on (an
    /// admin's grant or disable): it is the admin's address, not the user's,
    /// and this is what the user's dashboard and export show.
    fn audit_of(&self, user: AccountId, limit: u32) -> sqlx::Result<Vec<AuditEntry>>;
    /// One batch of rows older than `ts`; loop like `delete_expired_sessions`.
    fn delete_audit_before(&self, ts: i64, batch: u64) -> sqlx::Result<u64>;

    // ---------------------------------------------------------------- invites

    fn insert_invite(&self, code_hash: &[u8; 32], by: Option<AccountId>, username: Option<&str>, expires_at: i64) -> sqlx::Result<()>;
    /// Unexpired ones, used or not, newest first.
    fn invites(&self, now: i64) -> sqlx::Result<Vec<Invite>>;
    /// False when there was no such invite.
    fn delete_invite(&self, code_hash: &[u8; 32]) -> sqlx::Result<bool>;
    /// One batch of invites past their expiry, used or not.
    fn delete_expired_invites(&self, now: i64, batch: u64) -> sqlx::Result<u64>;
    /// Whether `create_user_with_invite` would claim the code for `username`
    /// now: the claim's condition as a read, so a wrong code is refused before
    /// a password is hashed for it. The claim still decides.
    fn invite_open(&self, code_hash: &[u8; 32], username: &str, now: i64) -> sqlx::Result<bool>;
    /// Spends the invite and creates the account in one transaction: a name
    /// that turns out to be taken leaves the code unspent, and two people with
    /// one code cannot both get in.
    fn create_user_with_invite(&self, u: &NewUser, role: &str, code_hash: &[u8; 32], now: i64) -> sqlx::Result<InviteSignup>;
    /// Grants `admin` to `user` only while no active account holds `*`, under
    /// the last-admin guard's locks: two accounts racing for an empty site get
    /// one admin, not two. False when someone already holds it.
    fn grant_admin_if_none(&self, user: AccountId) -> Result<bool, WriteError>;

    // ----------------------------------------------------------------- export

    /// The GDPR download: the account row, roles, sessions, sign-in methods,
    /// when each recovery code was used, the profile settings (on or off, bio,
    /// badges), the stored data (synced settings, the vault as its ciphertext,
    /// the avatar) and the newest audit rows about the account (as `audit_of`
    /// shows them). No secrets and nothing that works as a credential: no
    /// password hash, TOTP secret, session hashes, recovery hashes or public
    /// keys. Not in it: audit rows where this account acted on another one,
    /// which sit in that account's log. `None` when the account does not exist.
    fn export_user(&self, id: AccountId) -> sqlx::Result<Option<serde_json::Value>>;
}
