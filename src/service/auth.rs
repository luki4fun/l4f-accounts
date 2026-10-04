//! Sign-up, password sign-in and the session lifecycle.

use std::time::Duration;

use sha2::{Digest, Sha256};

use super::{Accounts, Ctx, DAY, Error, Host, has_second_factor};
use crate::model::{AccountId, NewUser, SessionInfo, User, UserStatus};
use crate::store::{CreateUserError, TOUCH_SECS};
use crate::{password, pow, scope, util};

pub(super) const WINDOW: Duration = Duration::from_secs(900);
/// How long a session waits for its second factor.
const PENDING_MFA_SECS: i64 = 600;

pub struct RegisterForm<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub email: Option<&'a str>,
    pub display_name: Option<&'a str>,
    /// `sec_fetch_site` is taken from the `Ctx`, whatever this one says.
    pub proof: pow::Proof<'a>,
}

/// The cookie value and its row. No `Debug`: `token` is a live credential.
pub struct NewSession {
    pub token: String,
    pub info: SessionInfo,
}

pub enum LoginStep {
    Done(NewSession),
    /// The password was right and a second factor is enrolled: a session that
    /// grants nothing, lives `PENDING_MFA_SECS`, and only the MFA step accepts.
    NeedMfa(NewSession),
}

/// SHA-256 of the token's 32 bytes, or `None` for anything never issued.
pub(crate) fn token_hash(token: &str) -> Option<[u8; 32]> {
    // 32 bytes are exactly 43 characters; also refuses a padded second spelling.
    if token.len() != 43 {
        return None;
    }
    let raw: [u8; 32] = util::b64u_dec(token)?.try_into().ok()?;
    Some(Sha256::digest(raw).into())
}

pub(super) fn new_token() -> (String, [u8; 32]) {
    let raw: [u8; 32] = util::random();
    (util::b64u(&raw), Sha256::digest(raw).into())
}

/// Stored unverified, in `email_pending`, until a mailed link proves it.
pub(super) fn clean_email(raw: &str) -> Result<Option<String>, &'static str> {
    let e = raw.trim().to_lowercase();
    if e.is_empty() {
        return Ok(None);
    }
    let shape = match e.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty() && !domain.contains('@') && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        }
        None => false,
    };
    if !shape || e.len() > 254 || e.chars().any(|c| c.is_whitespace() || c.is_control() || scope::invisible(c)) {
        return Err("That does not look like an email address.");
    }
    Ok(Some(e))
}

impl<H: Host> Accounts<H> {
    /// Open sign-up: the PoW gate, the username and password rules, an Argon2
    /// hash, the `user` role, and a full session.
    pub async fn register(&self, ctx: &Ctx, form: RegisterForm<'_>) -> Result<NewSession, Error> {
        let r = self.register_inner(ctx, form).await;
        if let Err(e) = &r {
            tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = e.outcome(), "register refused");
        }
        r
    }

    async fn register_inner(&self, ctx: &Ctx, form: RegisterForm<'_>) -> Result<NewSession, Error> {
        let cfg = self.host.config();
        let Some(key) = self.pow_key.as_deref().filter(|_| cfg.enabled && cfg.registration_open) else {
            return Err(Error::SignupClosed);
        };
        let bucket = util::ip_key(ctx.ip);
        let gate = pow::Gate { limiter: &self.limiter, key, limits: &cfg.signup, ns: "acct-reg", bucket: &bucket };
        // Held from the gate's peek to its commit, or parallel posts all pass
        // the same peek before any of them counts.
        let reg = self.reg_lock.lock().await;
        let no_js = gate.precheck(pow::Proof { sec_fetch_site: &ctx.sec_fetch_site, ..form.proof }, true).map_err(Error::Gate)?;

        let extra: Vec<&str> = cfg.reserved_usernames.iter().map(String::as_str).collect();
        let username = scope::normalize_username(form.username, &extra).map_err(Error::Invalid)?;
        password::check_policy(form.password, cfg.min_password_len).map_err(Error::Invalid)?;
        let display_name = match form.display_name.filter(|d| !d.trim().is_empty()) {
            Some(d) => scope::clean_display_name(d).map_err(Error::Invalid)?,
            None => username.clone(),
        };
        let email_pending = clean_email(form.email.unwrap_or("")).map_err(Error::Invalid)?;
        // A taken name costs neither the caps nor a hash; the INSERT still
        // settles a race for it.
        if self.store.user_by_username(&username).await?.is_some() {
            return Err(Error::UsernameTaken);
        }
        let permit = gate.caps(no_js).map_err(Error::Gate)?;

        let pw = form.password.to_owned();
        let hash = self.kdf(move || password::hash(&pw)).await?;
        let now = util::now();
        let id = AccountId::new();
        let user = NewUser { id, username, display_name, email_pending, password_hash: Some(hash), created_at: now };
        match self.store.create_user(&user, Some("user")).await {
            Ok(()) => {}
            Err(CreateUserError::UsernameTaken) => return Err(Error::UsernameTaken),
            Err(CreateUserError::Db(e)) => return Err(e.into()),
        }
        permit.commit(&self.limiter);
        drop(reg);

        self.audit(ctx, Some(id), None, "register", "").await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "register", user = %id.hex(),
            username = ?user.username);
        Ok(self.create_session(id, "password", true, now, ctx).await?)
    }

    /// Username and password. `known_device_user` is the account named by a
    /// valid known-device cookie (checked by the caller): that browser gets a
    /// bucket of its own, so strangers spending the per-address, per-account
    /// and site-wide caps never lock the owner out.
    pub async fn login_password(
        &self,
        ctx: &Ctx,
        username: &str,
        password: &str,
        known_device_user: Option<AccountId>,
    ) -> Result<LoginStep, Error> {
        let r = self.login_inner(ctx, username, password, known_device_user).await;
        // No username: people type their password into that field often enough.
        if let Err(e) = &r {
            tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = e.outcome(), "login refused");
        }
        r
    }

    async fn login_inner(
        &self,
        ctx: &Ctx,
        username: &str,
        password: &str,
        known_device_user: Option<AccountId>,
    ) -> Result<LoginStep, Error> {
        let cfg = self.host.config();
        if !cfg.enabled {
            return Err(Error::Closed);
        }
        if ctx.cross_site() {
            return Err(Error::CrossSite);
        }
        let ip_caps = || {
            self.limiter.check(&format!("acct-login:{}", util::ip_key(ctx.ip)), WINDOW, cfg.login_per_15min)
                && self.limiter.check("acct-login:global", WINDOW, cfg.login_per_15min_global)
        };
        // Strangers are counted before the database is asked anything.
        if known_device_user.is_none() && !ip_caps() {
            return Err(Error::RateLimited);
        }
        let name = scope::username_shape(username).ok();
        let user = match &name {
            Some(n) => self.store.user_by_username(n).await?,
            None => None,
        };
        let known = known_device_user.is_some() && known_device_user == user.as_ref().map(|u| u.id);
        let allowed = if known {
            known_device_user.is_some_and(|d| {
                self.limiter.check(&format!("acct-dev-{}:global", d.hex()), WINDOW, cfg.login_per_15min)
            })
        } else {
            // A name nobody has is counted like one somebody has, so the cap
            // does not answer which names exist.
            let who = match (&user, &name) {
                (Some(u), _) => Some(u.id.hex()),
                (None, Some(n)) => Some(format!("n-{n}")),
                (None, None) => None,
            };
            (known_device_user.is_none() || ip_caps())
                && who.is_none_or(|w| {
                    self.limiter.check(&format!("acct-login-user-{w}:x"), WINDOW, cfg.login_per_user_15min)
                })
        };
        if !allowed {
            return Err(Error::RateLimited);
        }

        // Disabled accounts and accounts without a password verify against the
        // dummy, like unknown names: same cost, same answer. The lookup runs for
        // every name, so a real one costs no extra query either.
        let active = user.as_ref().filter(|u| u.status == UserStatus::Active).map(|u| u.id);
        let stored = self.store.password_hash_of(active.unwrap_or(AccountId([0; 16]))).await?.filter(|_| active.is_some());
        let (pw, check) = (password.to_owned(), stored.clone());
        let (ok, rehash) = self
            .kdf(move || match check.as_deref() {
                Some(h) => {
                    let v = password::verify(&pw, h);
                    (v.ok, (v.ok && v.needs_rehash).then(|| password::hash(&pw)))
                }
                None => {
                    password::verify_dummy(&pw);
                    (false, None)
                }
            })
            .await?;
        let user = match user {
            Some(u) if ok => u,
            Some(u) => {
                // Off the response path: waiting for the INSERT would make a
                // wrong password on a real account answer slower than a name
                // nobody has.
                let (store, ip) = (self.store.clone(), self.shaped_ip(ctx.ip));
                tokio::spawn(async move {
                    if let Err(e) = store.audit(Some(u.id), None, "login_fail", "password", &ip).await {
                        tracing::warn!(target: "accounts", error = %e, "audit write failed");
                    }
                });
                return Err(Error::BadLogin);
            }
            None => return Err(Error::BadLogin),
        };

        if let (Some(new), Some(old)) = (rehash, stored.as_deref()) {
            // Only while the old hash is still stored: a password change that
            // landed meanwhile wins.
            if self.store.rehash_password(user.id, old, &new).await? {
                tracing::info!(target: "accounts", outcome = "rehash", user = %user.id.hex(), "password hash upgraded");
            }
        }
        let ip = self.shaped_ip(ctx.ip);
        if has_second_factor(&user) {
            self.audit(ctx, Some(user.id), None, "login_need_mfa", "password").await?;
            tracing::info!(target: "accounts", %ip, outcome = "need_mfa", user = %user.id.hex());
            return Ok(LoginStep::NeedMfa(self.create_session(user.id, "password", false, 0, ctx).await?));
        }
        self.audit(ctx, Some(user.id), None, "login_ok", "password").await?;
        tracing::info!(target: "accounts", %ip, outcome = "login_ok", user = %user.id.hex());
        Ok(LoginStep::Done(self.create_session(user.id, "password", true, util::now(), ctx).await?))
    }

    /// A session that is waiting for its second factor (`mfa_ok` false) lives
    /// `PENDING_MFA_SECS`; a full one `session_max_days`.
    pub async fn create_session(&self, user: AccountId, method: &str, mfa_ok: bool, auth_at: i64, ctx: &Ctx) -> sqlx::Result<NewSession> {
        let cfg = self.host.config();
        let (token, token_hash) = new_token();
        let now = util::now();
        let info = SessionInfo {
            token_hash,
            user_id: user,
            created_at: now,
            seen_at: now,
            expires_at: now + if mfa_ok { cfg.session_max_days * DAY } else { PENDING_MFA_SECS },
            auth_at,
            mfa_ok,
            method: method.to_string(),
            ip: self.shaped_ip(ctx.ip),
            ua: ctx.ua.clone(),
        };
        self.store.insert_session(&info).await?;
        Ok(NewSession { token, info })
    }

    /// The account behind a session cookie, the session, and the scopes it
    /// grants right now. A session still waiting for its second factor grants
    /// none, so a handler that forgets to check `mfa_ok` cannot act on it.
    pub async fn session_from_token(&self, token: &str, now: i64) -> sqlx::Result<Option<(User, SessionInfo, Vec<String>)>> {
        let Some(hash) = token_hash(token) else { return Ok(None) };
        let Some(s) = self.store.session_by_hash(&hash, now).await? else { return Ok(None) };
        if s.seen_at + self.host.config().session_idle_days * DAY <= now {
            return Ok(None);
        }
        let Some(user) = self.store.user_by_id(s.user_id).await? else { return Ok(None) };
        // Disabling deletes the sessions; this covers a login that raced it.
        if user.status != UserStatus::Active {
            return Ok(None);
        }
        if now - s.seen_at > TOUCH_SECS {
            self.store.touch_session(&hash, now).await?;
        }
        let scopes = if s.mfa_ok { self.effective_scopes(&user).await? } else { Vec::new() };
        Ok(Some((user, s, scopes)))
    }

    /// Same session, new token, for privilege changes (MFA done, step-up).
    /// `None` when the token names no live session.
    pub async fn rotate(&self, token: &str) -> sqlx::Result<Option<NewSession>> {
        let Some(old) = token_hash(token) else { return Ok(None) };
        let (token, new) = new_token();
        if !self.store.rotate_session(&old, &new).await? {
            return Ok(None);
        }
        Ok(self.store.session_by_hash(&new, util::now()).await?.map(|info| NewSession { token, info }))
    }

    pub async fn logout(&self, token: &str) -> sqlx::Result<()> {
        let Some(hash) = token_hash(token) else { return Ok(()) };
        // Expired or not: the row goes either way.
        if let Some(s) = self.store.session_by_hash(&hash, i64::MIN).await? {
            self.store.delete_session(&hash, s.user_id).await?;
        }
        Ok(())
    }

    /// "Sign out everywhere": every session of `user` but `except`.
    pub async fn logout_all(&self, ctx: &Ctx, user: AccountId, except: Option<&[u8; 32]>) -> sqlx::Result<u64> {
        let n = self.store.delete_sessions_of(user, except).await?;
        self.audit(ctx, Some(user), Some(user), "logout_all", &n.to_string()).await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "logout_all", user = %user.hex(), sessions = n);
        Ok(n)
    }
}
