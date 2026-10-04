//! The account operations, one call per thing a person does: sign up, sign in,
//! manage roles, delete an account. No HTTP types: the web layer turns a
//! request into one call here, and a host without HTTP makes the same calls.
//!
//! Every call that acts for someone takes a `Ctx` (from where) and returns a
//! domain value or an `Error`, which knows its sentence for the user and its
//! label for the log.

mod admin;
mod auth;
#[cfg(test)]
mod tests;

pub use admin::{Actor, RoleForm, UserDetail};
pub use auth::{LoginStep, NewSession, RegisterForm};

use std::{future::Future, net::IpAddr, sync::Arc};

use serde::Deserialize;
use tokio::sync::{Mutex, Semaphore};

use crate::ip::{self, IpMode};
use crate::keys::Keys;
use crate::limit::RateLimiter;
use crate::model::{AccountId, NewUser, User};
use crate::scope::{self, ScopeDef};
use crate::store::{CreateUserError, Store, WriteError};
use crate::{migrate, password, pow, util};

/// What the embedding app provides. Static dispatch with native async fns, so
/// no boxing and no async-trait crate.
pub trait Host: Send + Sync + 'static {
    /// Read on every call, so a config reload applies to the next request.
    fn config(&self) -> Arc<Config>;
    /// App-owned rows tied to an account (e.g. l4f's link ownership), merged into the GDPR export.
    fn export(&self, user: AccountId) -> impl Future<Output = Vec<(String, serde_json::Value)>> + Send;
    /// Runs inside the account-deletion transaction: an error here, or a refusal
    /// after it, rolls back the app's part too.
    fn delete_user(
        &self,
        tx: &mut sqlx::MySqlConnection,
        user: AccountId,
        delete_owned: bool,
    ) -> impl Future<Output = sqlx::Result<()>> + Send;
}

/// No `Debug`: it carries the IP salt.
#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Off refuses every sign-in and sign-up; sessions already issued keep working.
    pub enabled: bool,
    pub registration_open: bool,
    pub min_password_len: usize,
    pub session_idle_days: i64,
    pub session_max_days: i64,
    pub step_up_minutes: i64,
    /// Per address (IPv6: per /64), or per known device.
    pub login_per_15min: usize,
    /// Everyone without a known-device cookie together.
    pub login_per_15min_global: usize,
    pub login_per_user_15min: usize,
    pub signup: pow::Limits,
    /// On top of `scope::RESERVED`: the app's route words.
    pub reserved_usernames: Vec<String>,
    /// 0 keeps the audit log forever.
    pub audit_retention_days: i64,
    /// What the built-in `user` role is seeded with, and what is not privileged:
    /// anything else needs 2FA once `require_2fa_for_privileged` is on.
    pub default_user_scopes: Vec<String>,
    pub require_2fa_for_privileged: bool,
    #[serde(skip)]
    pub base_url: String,
    #[serde(skip)]
    pub cookie_secure: bool,
    #[serde(skip)]
    pub ip_mode: IpMode,
    #[serde(skip)]
    pub ip_salt: Vec<u8>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            // Open sign-up waits for 2FA (Phase 2).
            registration_open: false,
            min_password_len: password::MIN_LEN_DEFAULT,
            session_idle_days: 7,
            session_max_days: 30,
            step_up_minutes: 15,
            login_per_15min: 10,
            login_per_15min_global: 50,
            login_per_user_15min: 10,
            signup: pow::Limits::default(),
            reserved_usernames: Vec::new(),
            audit_retention_days: 180,
            default_user_scopes: Vec::new(),
            // Phase 2 flips this: until TOTP exists nobody could enrol, and the
            // bootstrap admin would hold `*` without being able to use it.
            require_2fa_for_privileged: false,
            base_url: String::new(),
            cookie_secure: true,
            ip_mode: IpMode::default(),
            ip_salt: Vec::new(),
        }
    }
}

/// Who is asking, as the host saw the request. `ip` must come from the host's
/// own proxy check, never from a header the client controls.
pub struct Ctx {
    pub ip: IpAddr,
    pub ua: String,
    /// The `Sec-Fetch-Site` header, or "" when there is none.
    pub sec_fetch_site: String,
}

impl Ctx {
    /// Another site, a sibling `*.l4f.cc` host included, posting through a
    /// visitor's browser. Scripts send no header at all.
    fn cross_site(&self) -> bool {
        matches!(self.sec_fetch_site.as_str(), "cross-site" | "same-site")
    }
}

#[derive(Debug)]
pub enum Error {
    /// `enabled` is off.
    Closed,
    /// Sign-up is off or has no PoW key.
    SignupClosed,
    /// The sign-up gate: PoW, honeypot, form age, caps.
    Gate(pow::Deny),
    /// A field was refused; the text says why.
    Invalid(&'static str),
    UsernameTaken,
    RoleTaken,
    /// Wrong name or password, or a disabled account: one answer for all.
    BadLogin,
    CrossSite,
    RateLimited,
    /// Both Argon2 slots are busy.
    Busy,
    Forbidden,
    NotFound,
    /// It would leave no active account holding `*`.
    LastAdmin,
    /// Built-in roles cannot be deleted.
    Builtin,
    Db(sqlx::Error),
}

impl Error {
    pub fn message(&self) -> &'static str {
        match self {
            Self::Closed => "Accounts are switched off right now.",
            Self::SignupClosed => "Sign-up is closed.",
            Self::Gate(d) => d.message,
            Self::Invalid(m) => m,
            Self::UsernameTaken => "That username is taken. Pick another one.",
            Self::RoleTaken => "A role with that name already exists.",
            Self::BadLogin => "Wrong username or password.",
            Self::CrossSite | Self::Db(_) => "Something went wrong. Please try again.",
            Self::RateLimited => "Too many attempts. Wait a few minutes.",
            Self::Busy => "The server is busy. Try again in a moment.",
            Self::Forbidden => "You are not allowed to do that.",
            Self::NotFound => "Not found.",
            Self::LastAdmin => "That would leave nobody with full access.",
            Self::Builtin => "Built-in roles cannot be deleted.",
        }
    }

    /// Stable label for logs, fail2ban and metrics.
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::SignupClosed => "signup_closed",
            Self::Gate(d) => d.outcome,
            Self::Invalid(_) => "invalid",
            Self::UsernameTaken => "username_taken",
            Self::RoleTaken => "role_taken",
            Self::BadLogin => "bad_login",
            Self::CrossSite => "cross_site",
            Self::RateLimited => "rate_limited",
            Self::Busy => "busy",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::LastAdmin => "last_admin",
            Self::Builtin => "builtin",
            Self::Db(_) => "db_error",
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl From<WriteError> for Error {
    fn from(e: WriteError) -> Self {
        match e {
            WriteError::LastAdmin => Self::LastAdmin,
            WriteError::Builtin => Self::Builtin,
            WriteError::Db(e) => Self::Db(e),
        }
    }
}

/// Why the boot-time admin was not created. The caller refuses to start.
#[derive(Debug)]
pub enum BootstrapError {
    BadName(&'static str),
    /// Not a hash a login could ever verify.
    BadHash,
    /// Someone else already has the name, and nobody holds `*`.
    NameTaken,
    Db(sqlx::Error),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadName(m) => write!(f, "L4F_ADMIN_USER: {m}"),
            #[cfg(feature = "legacy-bcrypt")]
            Self::BadHash => write!(f, "L4F_ADMIN_HASH is neither an Argon2 PHC string nor a usable bcrypt hash"),
            #[cfg(not(feature = "legacy-bcrypt"))]
            Self::BadHash => write!(f, "L4F_ADMIN_HASH is not an Argon2 PHC string (bcrypt needs the legacy-bcrypt feature)"),
            Self::NameTaken => write!(f, "L4F_ADMIN_USER names an existing account and nobody holds `*`: refusing to boot"),
            Self::Db(e) => write!(f, "bootstrap failed: {e}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

impl From<sqlx::Error> for BootstrapError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

/// Rows removed by one `sweep`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    pub sessions: u64,
    pub audit: u64,
}

const DAY: i64 = 86_400;
const SWEEP_BATCH: u64 = 5000;

pub struct Accounts<H: Host> {
    pub store: Store,
    pub keys: Keys,
    /// The app's limiter: one map, one key ceiling for the whole process.
    pub limiter: Arc<RateLimiter>,
    pub host: H,
    /// `CRATE_SCOPES` and the app's: what a role may carry.
    pub scopes: Vec<ScopeDef>,
    /// ALTCHA key; sign-up stays closed without one.
    pub pow_key: Option<Vec<u8>>,
    /// Held from the sign-up gate's peek to its commit.
    reg_lock: Mutex<()>,
    /// Argon2 runs at most two at once; owned permits move into the blocking
    /// task, so a client hanging up mid-hash cannot free its slot early.
    hash_permits: Arc<Semaphore>,
}

/// `scope::allowed`, for handlers that only hold the scope list.
pub fn require(scopes: &[String], required: &str) -> bool {
    scope::allowed(scopes, required)
}

/// TOTP for now; passkeys join in Phase 2.
pub fn has_second_factor(u: &User) -> bool {
    u.totp_enabled
}

impl<H: Host> Accounts<H> {
    /// Seeds the built-in roles, so call it after `migrate::run` and before
    /// `bootstrap_admin`. Refuses app scopes that are not valid names and
    /// default user scopes nobody registered.
    pub async fn build(
        store: Store,
        keys: Keys,
        limiter: Arc<RateLimiter>,
        host: H,
        app_scopes: &[ScopeDef],
        pow_key: Option<Vec<u8>>,
    ) -> sqlx::Result<Self> {
        if let Some(bad) = app_scopes.iter().find(|d| !scope::valid_scope(d.name)) {
            return Err(sqlx::Error::InvalidArgument(format!("not a valid scope name: {:?}", bad.name)));
        }
        let scopes = scope::CRATE_SCOPES.iter().chain(app_scopes).copied().collect();
        let a = Self {
            store,
            keys,
            limiter,
            host,
            scopes,
            pow_key,
            reg_lock: Mutex::new(()),
            hash_permits: Arc::new(Semaphore::new(2)),
        };
        let cfg = a.host.config();
        if let Some(bad) = cfg.default_user_scopes.iter().find(|s| !a.known_grant(s)) {
            return Err(sqlx::Error::InvalidArgument(format!("default_user_scopes: unknown scope {bad:?}")));
        }
        a.store.ensure_builtin_roles(&cfg.default_user_scopes).await?;
        Ok(a)
    }

    /// A grant a role may carry: a registered scope, `*`, or `prefix:*` where
    /// some registered scope starts with `prefix:`. A typo is refused, not
    /// stored as a grant that silently grants nothing.
    fn known_grant(&self, g: &str) -> bool {
        scope::valid_grant(g)
            && match g.strip_suffix('*') {
                Some(prefix) => self.scopes.iter().any(|d| d.name.starts_with(prefix)),
                None => self.scopes.iter().any(|d| d.name == g),
            }
    }

    /// Argon2 off the async workers, at most two at once, `Busy` past that.
    /// Callers hold no pool connection while this runs.
    async fn kdf<T: Send + 'static>(&self, work: impl FnOnce() -> T + Send + 'static) -> Result<T, Error> {
        let permit = self.hash_permits.clone().try_acquire_owned().map_err(|_| Error::Busy)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .map_err(|_| Error::Busy)
    }

    /// The address as config allows it to be stored or logged.
    fn shaped_ip(&self, ip: IpAddr) -> String {
        let cfg = self.host.config();
        ip::shape_ip(ip, cfg.ip_mode, &cfg.ip_salt)
    }

    async fn audit(&self, ctx: &Ctx, user: Option<AccountId>, actor: Option<AccountId>, event: &str, detail: &str) -> sqlx::Result<()> {
        self.store.audit(user, actor, event, detail, &self.shaped_ip(ctx.ip)).await
    }

    /// The account's scopes as they apply now: privileged ones (anything
    /// `default_user_scopes` does not cover) only once a second factor is
    /// enrolled, when the config asks for that.
    pub async fn effective_scopes(&self, user: &User) -> sqlx::Result<Vec<String>> {
        let mut held = self.store.user_scopes(user.id).await?;
        let cfg = self.host.config();
        if cfg.require_2fa_for_privileged && !has_second_factor(user) {
            held.retain(|s| scope::covers(&cfg.default_user_scopes, std::slice::from_ref(s)));
        }
        Ok(held)
    }

    /// The GDPR download: the store's export, plus the app's entries under `app`
    /// so no app key can shadow one of the crate's.
    pub async fn export(&self, user: AccountId) -> Result<serde_json::Value, Error> {
        let mut v = self.store.export_user(user).await?.ok_or(Error::NotFound)?;
        let app: serde_json::Map<_, _> = self.host.export(user).await.into_iter().collect();
        v["app"] = app.into();
        Ok(v)
    }

    /// Deletes `user` and, in the same transaction, the app's rows for it. Self
    /// deletion needs nothing more here; deleting someone else needs
    /// `users:admin` and every scope they hold. Step-up is the caller's.
    pub async fn delete_account(&self, ctx: &Ctx, actor: Actor<'_>, user: AccountId, delete_owned: bool) -> Result<(), Error> {
        let by_admin = actor.user.id != user;
        if by_admin {
            actor.need("users:admin")?;
            self.manageable(actor, user).await?;
        }
        let mut tx = self.store.begin().await?;
        self.host.delete_user(&mut tx, user, delete_owned).await?;
        // A refusal or a missing row drops `tx`, which rolls the app's part back.
        if !Store::delete_user(&mut tx, user).await? {
            return Err(Error::NotFound);
        }
        tx.commit().await?;
        // The account's own audit rows went with it; an admin's deletion is
        // still the admin's action to account for.
        if by_admin {
            self.audit(ctx, None, Some(actor.user.id), "account_delete", &user.hex()).await?;
        }
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "account_delete",
            user = %user.hex(), actor = %actor.user.id.hex(), delete_owned);
        Ok(())
    }

    /// Expired and idle sessions, then audit rows past retention, in batches so
    /// no lock is held long. The host runs it hourly.
    pub async fn sweep(&self, now: i64) -> sqlx::Result<Swept> {
        let cfg = self.host.config();
        let mut out = Swept::default();
        loop {
            let n = self.store.delete_expired_sessions(now, cfg.session_idle_days * DAY, SWEEP_BATCH).await?;
            out.sessions += n;
            if n < SWEEP_BATCH {
                break;
            }
        }
        if cfg.audit_retention_days > 0 {
            loop {
                let n = self.store.delete_audit_before(now - cfg.audit_retention_days * DAY, SWEEP_BATCH).await?;
                out.audit += n;
                if n < SWEEP_BATCH {
                    break;
                }
            }
        }
        if out != Swept::default() {
            tracing::info!(target: "accounts", sessions = out.sessions, audit = out.audit, "sweep");
        }
        Ok(out)
    }

    /// The first admin, from the old single-admin env (`L4F_ADMIN_USER` and
    /// `L4F_ADMIN_HASH`), only while nobody holds `*`. `None` when there was
    /// nothing to do. Call after `build` and before serving; it takes the
    /// migration lock itself, so two processes booting at once create one
    /// admin rather than one of them finding the name taken.
    ///
    /// The hash is stored as given (YOURLS's `!` mangling undone) and replaced
    /// by an Argon2id hash at the first login.
    pub async fn bootstrap_admin(&self, username: &str, legacy_hash: &str) -> Result<Option<AccountId>, BootstrapError> {
        let conn = migrate::lock(&self.store.0).await?;
        let r = self.bootstrap_locked(username, legacy_hash).await;
        migrate::unlock(conn).await;
        r
    }

    async fn bootstrap_locked(&self, username: &str, legacy_hash: &str) -> Result<Option<AccountId>, BootstrapError> {
        if self.store.holders_of_scope_star().await? > 0 {
            return Ok(None);
        }
        // Not `normalize_username`: the site's own name is on the reserved list
        // precisely so that only this path can create it.
        let name = scope::username_shape(username).map_err(BootstrapError::BadName)?;
        let hash = admin_hash(legacy_hash).ok_or(BootstrapError::BadHash)?;
        if self.store.user_by_username(&name).await?.is_some() {
            return Err(BootstrapError::NameTaken);
        }
        let id = AccountId::new();
        let u = NewUser {
            id,
            username: name.clone(),
            display_name: name.clone(),
            email_pending: None,
            password_hash: Some(hash),
            created_at: util::now(),
        };
        match self.store.create_user(&u, Some("admin")).await {
            Ok(()) => {}
            Err(CreateUserError::UsernameTaken) => return Err(BootstrapError::NameTaken),
            Err(CreateUserError::Db(e)) => return Err(e.into()),
        }
        self.store.audit(Some(id), None, "bootstrap", "", "").await?;
        tracing::info!(target: "accounts", outcome = "bootstrap", user = %id.hex(), username = ?name, "admin account created");
        Ok(Some(id))
    }

    /// The target exists and the actor holds every scope the target holds:
    /// nobody suspends or deletes someone with more power than they have.
    async fn manageable(&self, actor: Actor<'_>, target: AccountId) -> Result<User, Error> {
        let user = self.store.user_by_id(target).await?.ok_or(Error::NotFound)?;
        if !scope::covers(actor.scopes, &self.store.user_scopes(target).await?) {
            return Err(Error::Forbidden);
        }
        Ok(user)
    }
}

/// An `L4F_ADMIN_HASH` a login can verify, as it will be stored. Checked with
/// the same rules `password::verify` applies, so a bad value stops the boot
/// instead of locking the admin out at the first login.
fn admin_hash(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if password::argon2_accepted(raw) {
        return Some(raw.to_string());
    }
    #[cfg(feature = "legacy-bcrypt")]
    {
        let s = password::unmangle_yourls(raw);
        if password::bcrypt_accepted(&s) && bcrypt::verify("", &s).is_ok() {
            return Some(s);
        }
    }
    None
}
