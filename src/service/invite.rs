//! Sign-up by invite. An admin hands out a code; the code opens sign-up for one
//! account even while `registration_open` is off, and stands in for the
//! sign-up gate (it is the proof that a person was asked). A code bound to a
//! username is how an admin makes an account for someone: only that name can
//! use it.

use sha2::{Digest, Sha256};

use super::auth::{NewSession, WINDOW, signup_fields};
use super::{Accounts, Actor, Ctx, DAY, Error, Host};
use crate::model::{AccountId, Invite, NewUser};
use crate::store::InviteSignup;
use crate::{password, scope, util};

/// Sign-ups with a code per address per window. Codes are 128 random bits, so
/// this does not guard them; it keeps one address from minting accounts as
/// fast as it holds codes. A wrong code never reaches the password hash.
const INVITE_TRIES: usize = 20;
/// The longest an invite stays valid.
pub const MAX_INVITE_DAYS: i64 = 30;

pub struct InviteForm<'a> {
    pub code: &'a str,
    pub username: &'a str,
    pub password: &'a str,
    pub email: Option<&'a str>,
    pub display_name: Option<&'a str>,
}

/// SHA-256 of the code's 16 bytes, or `None` for anything never issued.
fn code_hash(code: &str) -> Option<[u8; 32]> {
    // 16 bytes are exactly 22 characters; also refuses a padded second spelling.
    if code.len() != 22 {
        return None;
    }
    let raw: [u8; 16] = util::b64u_dec(code)?.try_into().ok()?;
    Some(Sha256::digest(raw).into())
}

impl<H: Host> Accounts<H> {
    /// A new code, shown once: only its hash is kept. `username` binds it to
    /// that name (which must be free now); `days` is clamped to 1..=30. The
    /// account it makes gets the `user` role, so the actor must cover that
    /// role, as `grant_role` would ask.
    pub async fn invite_create(&self, ctx: &Ctx, actor: Actor<'_>, username: Option<&str>, days: i64) -> Result<String, Error> {
        actor.need("users:admin")?;
        if !scope::covers(actor.scopes, &self.role("user").await?.scopes) {
            return Err(Error::Forbidden);
        }
        self.issue_invite(ctx, Some(actor.user.id), username, days).await
    }

    /// `invite_create` for the host itself — its own shell, setting up a site
    /// nobody can sign in to yet — where no signed-in admin answers for it.
    /// The audit row has no actor.
    pub async fn invite_create_as_host(&self, ctx: &Ctx, username: Option<&str>, days: i64) -> Result<String, Error> {
        self.issue_invite(ctx, None, username, days).await
    }

    async fn issue_invite(&self, ctx: &Ctx, actor: Option<AccountId>, username: Option<&str>, days: i64) -> Result<String, Error> {
        let cfg = self.host.config();
        let username = match username.map(str::trim).filter(|u| !u.is_empty()) {
            Some(u) => {
                let name = cfg.username(u)?;
                if self.store.user_by_username(&name).await?.is_some() {
                    return Err(Error::UsernameTaken);
                }
                Some(name)
            }
            None => None,
        };
        let raw: [u8; 16] = util::random();
        let hash: [u8; 32] = Sha256::digest(raw).into();
        let expires_at = util::now() + days.clamp(1, MAX_INVITE_DAYS) * DAY;
        self.store.insert_invite(&hash, actor, username.as_deref(), expires_at).await?;
        self.audit_after(ctx, None, actor, "invite_create", &super::admin::marked(username.as_deref().unwrap_or(""), actor)).await;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "invite_create", actor = %super::admin::by(actor),
            bound = username.is_some());
        Ok(util::b64u(&raw))
    }

    /// Unexpired invites, used ones included, newest first.
    pub async fn invites(&self, actor: Actor<'_>) -> Result<Vec<Invite>, Error> {
        actor.need("users:admin")?;
        Ok(self.store.invites(util::now()).await?)
    }

    /// `id` as `Invite::id` gives it. False when there was no such invite.
    pub async fn invite_revoke(&self, ctx: &Ctx, actor: Actor<'_>, id: &str) -> Result<bool, Error> {
        actor.need("users:admin")?;
        let hash: [u8; 32] = hex::decode(id).ok().and_then(|b| b.try_into().ok()).ok_or(Error::NotFound)?;
        let gone = self.store.delete_invite(&hash).await?;
        if gone {
            self.audit_after(ctx, None, Some(actor.user.id), "invite_revoke", "").await;
        }
        Ok(gone)
    }

    /// Sign-up with a code: the username and password rules of `register`, the
    /// `user` role, and a full session. The code is spent with the account in
    /// one transaction, so a refusal leaves it for another try.
    pub async fn register_invite(&self, ctx: &Ctx, form: InviteForm<'_>) -> Result<NewSession, Error> {
        let r = self.register_invite_inner(ctx, form).await;
        if let Err(e) = &r {
            tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = e.outcome(), "invite sign-up refused");
        }
        r
    }

    async fn register_invite_inner(&self, ctx: &Ctx, form: InviteForm<'_>) -> Result<NewSession, Error> {
        let cfg = self.host.config();
        self.door(ctx, "acct-inv", WINDOW, INVITE_TRIES)?;
        const BAD: Error = Error::Invalid("That invite is not valid: wrong, used, expired, or meant for another name.");
        let hash = code_hash(form.code.trim()).ok_or(BAD)?;
        let (username, display_name, email_pending) = signup_fields(&cfg, form.username, form.password, form.display_name, form.email)?;
        // A wrong code or a taken name costs no hash: Argon2 has two slots for
        // the whole process. The claim below still settles a race for either.
        if !self.store.invite_open(&hash, &username, util::now()).await? {
            return Err(BAD);
        }
        if self.store.user_by_username(&username).await?.is_some() {
            return Err(Error::UsernameTaken);
        }
        let pw = form.password.to_owned();
        let password_hash = self.kdf(move || password::hash(&pw)).await?;
        let now = util::now();
        let id = AccountId::new();
        let user = NewUser { id, username, display_name, email_pending, password_hash: Some(password_hash), created_at: now };
        match self.store.create_user_with_invite(&user, "user", &hash, now).await? {
            InviteSignup::Done => {}
            InviteSignup::BadInvite => return Err(BAD),
            InviteSignup::UsernameTaken => return Err(Error::UsernameTaken),
        }
        self.audit_after(ctx, Some(id), None, "register", "invite").await;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "register", user = %id.hex(),
            username = ?user.username, how = "invite");
        Ok(self.create_session(id, "password", true, now, ctx).await?)
    }
}
