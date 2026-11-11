//! Sign-up, password sign-in and the session lifecycle.

use std::time::Duration;

use sha2::{Digest, Sha256};

use super::{Accounts, Config, Ctx, DAY, Error, Host, has_second_factor};
use crate::model::{AccountId, NewUser, SessionInfo, User, UserStatus};
use crate::store::TOUCH_SECS;
use crate::{password, pow, scope, util};

pub(super) const WINDOW: Duration = Duration::from_secs(900);
/// How long a session waits for its second factor.
const PENDING_MFA_SECS: i64 = 600;

/// What a new account signs in with: a password (hashed here), or a host key
/// (`hostkey`), stored as it is.
#[derive(Clone, Copy)]
pub(super) enum NewSecret<'a> {
    Password(&'a str),
    HostKey(&'a [u8; 32]),
}

impl NewSecret<'_> {
    /// The password, for its policy: a host key's never comes here.
    pub(super) fn password(&self) -> Option<&str> {
        match self {
            NewSecret::Password(pw) => Some(pw),
            NewSecret::HostKey(_) => None,
        }
    }

    /// The session's method.
    pub(super) fn method(&self) -> &'static str {
        match self {
            NewSecret::Password(_) => "password",
            NewSecret::HostKey(_) => super::hostkey::METHOD,
        }
    }
}

impl<H: Host> Accounts<H> {
    /// What goes in the password column: Argon2 of a password, or the host key's text.
    pub(super) async fn secret_hash(&self, secret: NewSecret<'_>) -> Result<String, Error> {
        match secret {
            NewSecret::Password(pw) => {
                let pw = pw.to_owned();
                Ok(self.kdf(move || password::hash(&pw)).await?)
            }
            NewSecret::HostKey(key) => Ok(super::hostkey::stored(key)),
        }
    }
}

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
    if !shape || e.len() > 254 || e.chars().any(|c| c.is_whitespace() || scope::breaks_text(c)) {
        return Err("That does not look like an email address.");
    }
    Ok(Some(e))
}

/// What `register` and `register_invite` both check, in this order: the
/// username, the password policy, the display name (the username when left
/// blank) and the address. Returns (username, display name, address).
pub(super) fn signup_fields(
    cfg: &Config,
    username: &str,
    password: Option<&str>,
    display_name: Option<&str>,
    email: Option<&str>,
) -> Result<(String, String, Option<String>), Error> {
    let username = cfg.username(username)?;
    // A host key's password stays on the device, which checks the policy there
    if let Some(password) = password {
        password::check_policy(password, cfg.min_password_len).map_err(Error::Invalid)?;
    }
    let display_name = match display_name.filter(|d| !d.trim().is_empty()) {
        Some(d) => scope::clean_display_name(d).map_err(Error::Invalid)?,
        None => username.clone(),
    };
    let email = clean_email(email.unwrap_or("")).map_err(Error::Invalid)?;
    Ok((username, display_name, email))
}

impl<H: Host> Accounts<H> {
    /// Open sign-up: the PoW gate, the username and password rules, an Argon2
    /// hash, the `user` role, and a full session.
    pub async fn register(&self, ctx: &Ctx, form: RegisterForm<'_>) -> Result<NewSession, Error> {
        let secret = NewSecret::Password(form.password);
        let r = self.register_inner(ctx, form, secret).await;
        if let Err(e) = &r {
            tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = e.outcome(), "register refused");
        }
        r
    }

    /// `register` with a host key for the password (`hostkey`): `form.password` is not
    /// read. The device that holds the password checked its policy.
    pub async fn register_hostkey(&self, ctx: &Ctx, form: RegisterForm<'_>, key: &[u8; 32]) -> Result<NewSession, Error> {
        let r = self.register_inner(ctx, form, NewSecret::HostKey(key)).await;
        if let Err(e) = &r {
            tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = e.outcome(), "register refused");
        }
        r
    }

    async fn register_inner(&self, ctx: &Ctx, form: RegisterForm<'_>, secret: NewSecret<'_>) -> Result<NewSession, Error> {
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

        let (username, display_name, email_pending) = signup_fields(&cfg, form.username, secret.password(), form.display_name, form.email)?;
        // A taken name costs neither the caps nor a hash; the INSERT still
        // settles a race for it.
        if self.store.user_by_username(&username).await?.is_some() {
            return Err(Error::UsernameTaken);
        }
        let permit = gate.caps(no_js).map_err(Error::Gate)?;

        let hash = self.secret_hash(secret).await?;
        let now = util::now();
        let id = AccountId::new();
        let user = NewUser { id, username, display_name, email_pending, password_hash: Some(hash), created_at: now };
        // Counted before the INSERT: a client that hangs up drops this future,
        // maybe after the INSERT committed, and a count after it would never
        // run. A lost race for the name counts one too many.
        permit.commit(&self.limiter);
        self.store.create_user(&user, Some("user")).await?;
        drop(reg);

        self.audit_after(ctx, Some(id), None, "register", "").await;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "register", user = %id.hex(),
            username = ?user.username);
        Ok(self.create_session(id, secret.method(), true, now, ctx).await?)
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
        let user = self.login_door(ctx, username, known_device_user).await?;

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
                self.audit_detached(ctx, u.id, None, "login_fail", "password");
                return Err(Error::BadLogin);
            }
            None => return Err(Error::BadLogin),
        };

        // The hash this sign-in proved: the stored one, or the upgrade it wrote.
        let mut proved = stored.clone();
        if let (Some(new), Some(old)) = (rehash, stored.as_deref()) {
            // Only while the old hash is still stored: a password change that
            // landed meanwhile wins.
            if self.store.rehash_password(user.id, old, &new).await? {
                tracing::info!(target: "accounts", outcome = "rehash", user = %user.id.hex(), "password hash upgraded");
                proved = Some(new);
            }
        }
        let step = if has_second_factor(&user) {
            self.audit(ctx, Some(user.id), None, "login_need_mfa", "password").await?;
            tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "need_mfa", user = %user.id.hex());
            LoginStep::NeedMfa(self.create_session(user.id, "password", false, 0, ctx).await?)
        } else {
            self.record(ctx, Some(user.id), None, "login_ok", "password").await?;
            LoginStep::Done(self.create_session(user.id, "password", true, util::now(), ctx).await?)
        };
        // A password change writes the new hash, then deletes the sessions. If
        // that DELETE ran before this session's INSERT, the hash shows it now.
        let (LoginStep::Done(s) | LoginStep::NeedMfa(s)) = &step;
        if self.store.password_hash_of(user.id).await? != proved {
            self.store.delete_session(&s.info.token_hash, user.id).await?;
            return Err(Error::BadLogin);
        }
        Ok(step)
    }

    /// What a sign-in by name passes before anything about the account is checked: the
    /// site is open, the caps of the address, the site and the name, counted the same for
    /// a name nobody has. Shared by the password and the host key, which are the same
    /// secret in two forms. `known_device_user`: see `login_password`.
    pub(super) async fn login_door(
        &self,
        ctx: &Ctx,
        username: &str,
        known_device_user: Option<AccountId>,
    ) -> Result<Option<User>, Error> {
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
        Ok(user)
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
    /// grants right now. A session still waiting for its second factor comes
    /// back too, with `mfa_ok` false and no scopes: nobody is signed in with
    /// it, so check `mfa_ok` before treating the account as signed in.
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
        // Remembered browsers too, and first: they could sign straight back in.
        self.revoke_devkeys(ctx, user, Some(user), "logout_all").await?;
        let n = self.store.delete_sessions_of(user, except).await?;
        self.audit_after(ctx, Some(user), Some(user), "logout_all", &n.to_string()).await;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "logout_all", user = %user.hex(), sessions = n);
        Ok(n)
    }
}
