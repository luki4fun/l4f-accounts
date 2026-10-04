//! Social sign-in, linking and step-up. The flow's secrets travel in a
//! sealed cookie set when the browser leaves for the provider: state, PKCE
//! verifier, nonce, the intent, the account (for linking) and where to go
//! after. The callback checks it came back to this browser, for this
//! provider, in time.
//!
//! Identities are keyed by (provider, subject) and never matched by email.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::auth::WINDOW;
use super::{ACCOUNT_PATH, Accounts, Ctx, Error, Host, LoginStep, NewSession, has_second_factor};
use crate::model::{Credential, NewUser, SessionInfo, User, UserStatus};
use crate::oauth::{self, Flow, Identity, Kind, Provider};
use crate::store::CreateUserError;
use crate::{pow, scope, util};

/// The configured providers and the client that may reach them.
pub struct OAuth {
    http: reqwest::Client,
    providers: Vec<Provider>,
}

impl OAuth {
    pub fn new(http: reqwest::Client, providers: Vec<Provider>) -> OAuth {
        OAuth { http, providers }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Intent {
    Login,
    Link,
    Reauth,
}

/// What a callback came to.
pub enum SocialOutcome {
    Signed(LoginStep),
    /// An identity nobody has, and sign-up is open: `cookie` carries it to the
    /// choose-a-username page.
    Signup { cookie: String },
    Linked,
    SteppedUp(NewSession),
}

const FLOW_SECS: i64 = 600;
const EXPIRED: Error = Error::Invalid("That sign-in took too long or started in another browser. Try again.");

#[derive(Serialize, Deserialize)]
struct FlowCookie {
    p: String,
    i: Intent,
    u: Option<String>,
    s: String,
    v: String,
    n: String,
    x: String,
    e: i64,
}

#[derive(Serialize, Deserialize)]
struct SignupCookie {
    p: String,
    sub: String,
    handle: String,
    e: i64,
}

impl<H: Host> Accounts<H> {
    pub fn with_oauth(mut self, o: OAuth) -> Self {
        self.oauth = Some(Arc::new(o));
        self
    }

    /// The providers configured, in display order.
    pub fn oauth_kinds(&self) -> Vec<Kind> {
        self.oauth.as_ref().map(|o| o.providers.iter().map(|p| p.kind).collect()).unwrap_or_default()
    }

    fn provider(&self, kind: Kind) -> Result<(&reqwest::Client, &Provider), Error> {
        let o = self.oauth.as_ref().ok_or(Error::NotFound)?;
        Ok((&o.http, o.providers.iter().find(|p| p.kind == kind).ok_or(Error::NotFound)?))
    }

    fn seal_json<T: Serialize>(&self, purpose: &str, v: &T) -> String {
        util::b64u(&self.keys.seal(purpose, b"", &serde_json::to_vec(v).expect("plain struct")))
    }

    fn open_json<T: for<'de> Deserialize<'de>>(&self, purpose: &str, s: &str) -> Option<T> {
        let (plain, _) = self.keys.open(purpose, b"", &util::b64u_dec(s)?)?;
        serde_json::from_slice(&plain).ok()
    }

    fn redirect_uri(&self, kind: Kind) -> String {
        format!("{}{ACCOUNT_PATH}/oauth/{}/cb", self.host.config().base_url, kind.slug())
    }

    /// Where to send the browser, and the sealed cookie value to set first.
    pub fn oauth_begin(&self, kind: Kind, intent: Intent, user: Option<&User>, next: &str) -> Result<(String, String), Error> {
        let (_, p) = self.provider(kind)?;
        if intent != Intent::Login && user.is_none() {
            return Err(Error::Forbidden);
        }
        let flow = Flow::new();
        let url = oauth::authorize_url(p, &self.redirect_uri(kind), &flow, intent == Intent::Reauth);
        let c = FlowCookie {
            p: kind.slug().into(),
            i: intent,
            u: user.map(|u| u.id.hex()),
            s: flow.state,
            v: flow.verifier,
            n: flow.nonce,
            x: util::safe_next(next, "").to_string(),
            e: util::now() + FLOW_SECS,
        };
        Ok((url, self.seal_json("oauth-flow", &c)))
    }

    /// The callback. Returns what happened and where the flow said to go next.
    pub async fn oauth_finish(
        &self,
        ctx: &Ctx,
        kind: Kind,
        cookie: &str,
        state: &str,
        code: &str,
        me: Option<(&User, &SessionInfo)>,
    ) -> Result<(SocialOutcome, String), Error> {
        let cfg = self.host.config();
        if !cfg.enabled {
            return Err(Error::Closed);
        }
        if !self.limiter.check(&format!("acct-oauth:{}", util::ip_key(ctx.ip)), WINDOW, cfg.login_per_15min * 3) {
            return Err(Error::RateLimited);
        }
        let fc: FlowCookie = self.open_json("oauth-flow", cookie).ok_or(EXPIRED)?;
        if fc.e <= util::now() || fc.p != kind.slug() || !util::ct_eq(&fc.s, state) {
            return Err(EXPIRED);
        }
        let (http, p) = self.provider(kind)?;
        let flow = Flow { state: fc.s, verifier: fc.v, nonce: fc.n };
        let id = oauth::exchange(http, p, code, &self.redirect_uri(kind), &flow).await.map_err(|e| {
            tracing::warn!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "oauth_failed", provider = kind.slug(), error = ?e);
            Error::Invalid("Signing in there did not work. Try again.")
        })?;
        let mine = |u: &User| fc.u.as_deref() == Some(u.id.hex().as_str());
        let outcome = match fc.i {
            Intent::Login => self.social_login(ctx, kind, &id).await?,
            Intent::Link => {
                let (u, s) = me.filter(|(u, _)| mine(u)).ok_or(Error::Forbidden)?;
                if !self.fresh(s, util::now()) {
                    return Err(Error::Invalid("Confirm it's you first, then link again."));
                }
                self.social_link(ctx, kind, u, &id).await?;
                SocialOutcome::Linked
            }
            Intent::Reauth => {
                let (u, s) = me.filter(|(u, _)| mine(u)).ok_or(Error::Forbidden)?;
                let cred = self.store.credential(&kind.credential_kind(), id.subject.as_bytes()).await?;
                if !cred.is_some_and(|c| c.user_id == u.id) {
                    return Err(Error::Invalid("That is not the account linked here."));
                }
                // Google says when the person last signed in; it must be just
                // now, after max_age=0. The others force their prompt by URL.
                if kind == Kind::Google && !id.auth_time.is_some_and(|t| (util::now() - t).abs() <= 300) {
                    return Err(Error::Invalid("Google did not ask you to sign in again. Try again."));
                }
                SocialOutcome::SteppedUp(self.refresh(ctx, u, s, kind.slug()).await?)
            }
        };
        Ok((outcome, fc.x))
    }

    async fn social_login(&self, ctx: &Ctx, kind: Kind, id: &Identity) -> Result<SocialOutcome, Error> {
        let cfg = self.host.config();
        let ckind = kind.credential_kind();
        let Some(cred) = self.store.credential(&ckind, id.subject.as_bytes()).await? else {
            if cfg.registration_open && self.pow_key.is_some() {
                let c = SignupCookie { p: kind.slug().into(), sub: id.subject.clone(), handle: id.handle.clone(), e: util::now() + FLOW_SECS };
                return Ok(SocialOutcome::Signup { cookie: self.seal_json("oauth-signup", &c) });
            }
            return Err(Error::Invalid("No account here uses that sign-in. Sign in another way, then link it on your security page."));
        };
        let user = self.store.user_by_id(cred.user_id).await?.filter(|u| u.status == UserStatus::Active).ok_or(Error::BadLogin)?;
        self.store.used_credential(&ckind, &cred.ext_id, 0, util::now()).await?;
        if has_second_factor(&user) {
            self.audit(ctx, Some(user.id), None, "login_need_mfa", &ckind).await?;
            return Ok(SocialOutcome::Signed(LoginStep::NeedMfa(self.create_session(user.id, "oauth", false, 0, ctx).await?)));
        }
        self.audit(ctx, Some(user.id), None, "login_ok", &ckind).await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "login_ok", user = %user.id.hex(), how = %ckind);
        Ok(SocialOutcome::Signed(LoginStep::Done(self.create_session(user.id, "oauth", true, 0, ctx).await?)))
    }

    fn identity_row(kind: Kind, user: &User, id: &Identity) -> Credential {
        Credential {
            kind: kind.credential_kind(),
            ext_id: id.subject.as_bytes().to_vec(),
            user_id: user.id,
            public_key: None,
            alg: 0,
            sign_count: 0,
            flags: 0,
            // What the provider calls the person, for the security page.
            name: scope::clean_display_name(&id.handle).unwrap_or_else(|_| kind.label().to_string()),
            created_at: util::now(),
            last_used_at: None,
            public: false,
        }
    }

    async fn social_link(&self, ctx: &Ctx, kind: Kind, user: &User, id: &Identity) -> Result<(), Error> {
        if !self.store.insert_credential(&Self::identity_row(kind, user, id)).await? {
            return Err(Error::Invalid("That account is linked to another account here already."));
        }
        self.audit(ctx, Some(user.id), Some(user.id), "oauth_link", kind.slug()).await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "oauth_link", user = %user.id.hex(), provider = kind.slug());
        Ok(())
    }

    /// The name the signup page suggests: the provider's handle in the
    /// username alphabet, if anything is left of it.
    pub fn oauth_signup_suggestion(&self, cookie: &str) -> Option<String> {
        let c: SignupCookie = self.open_json("oauth-signup", cookie)?;
        let s: String = c.handle.to_ascii_lowercase().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').take(32).collect();
        Some(s)
    }

    /// An account for an identity nobody has: the username rules and the same
    /// sign-up gate as the form (proof of work, caps), and no password.
    pub async fn oauth_signup(&self, ctx: &Ctx, cookie: &str, username: &str, proof: pow::Proof<'_>) -> Result<NewSession, Error> {
        let cfg = self.host.config();
        let Some(key) = self.pow_key.as_deref().filter(|_| cfg.enabled && cfg.registration_open) else {
            return Err(Error::SignupClosed);
        };
        let c: SignupCookie = self.open_json("oauth-signup", cookie).filter(|c: &SignupCookie| c.e > util::now()).ok_or(EXPIRED)?;
        let kind = Kind::from_slug(&c.p).ok_or(EXPIRED)?;
        let bucket = util::ip_key(ctx.ip);
        let gate = pow::Gate { limiter: &self.limiter, key, limits: &cfg.signup, ns: "acct-reg", bucket: &bucket };
        let reg = self.reg_lock.lock().await;
        let no_js = gate.precheck(pow::Proof { sec_fetch_site: &ctx.sec_fetch_site, ..proof }, true).map_err(Error::Gate)?;
        let extra: Vec<&str> = cfg.reserved_usernames.iter().map(String::as_str).collect();
        let username = scope::normalize_username(username, &extra).map_err(Error::Invalid)?;
        if self.store.user_by_username(&username).await?.is_some() {
            return Err(Error::UsernameTaken);
        }
        if self.store.credential(&kind.credential_kind(), c.sub.as_bytes()).await?.is_some() {
            return Err(Error::Invalid("That account is linked to another account here already."));
        }
        let permit = gate.caps(no_js).map_err(Error::Gate)?;
        let now = util::now();
        let display_name = scope::clean_display_name(&c.handle).unwrap_or_else(|_| username.clone());
        let new = NewUser { id: crate::model::AccountId::new(), username, display_name, email_pending: None, password_hash: None, created_at: now };
        match self.store.create_user(&new, Some("user")).await {
            Ok(()) => {}
            Err(CreateUserError::UsernameTaken) => return Err(Error::UsernameTaken),
            Err(CreateUserError::Db(e)) => return Err(e.into()),
        }
        let user = self.store.user_by_id(new.id).await?.ok_or(Error::NotFound)?;
        let id = Identity { subject: c.sub, handle: c.handle, email: None, auth_time: None };
        if !self.store.insert_credential(&Self::identity_row(kind, &user, &id)).await? {
            // Lost a race for the identity: no account without a way in.
            let mut conn = self.store.0.acquire().await?;
            crate::store::Store::delete_user(&mut conn, user.id).await?;
            return Err(Error::Invalid("That account is linked to another account here already."));
        }
        permit.commit(&self.limiter);
        drop(reg);
        self.audit(ctx, Some(user.id), None, "register", &kind.credential_kind()).await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "register", user = %user.id.hex(), how = kind.slug());
        Ok(self.create_session(user.id, "oauth", true, 0, ctx).await?)
    }

    /// The linked identities of one account, per provider.
    pub async fn oauth_linked(&self, user: crate::model::AccountId) -> sqlx::Result<Vec<(Kind, Credential)>> {
        let mut out = Vec::new();
        for k in self.oauth_kinds() {
            for c in self.store.credentials_of(user, &k.credential_kind()).await? {
                out.push((k, c));
            }
        }
        Ok(out)
    }
}
