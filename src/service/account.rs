//! What a signed-in person does to their own account: confirm their password
//! for step-up, rename themselves, see and end their sessions.

use super::auth::WINDOW;
use super::{Accounts, Ctx, DAY, Error, Host, NewSession, has_second_factor};
use crate::model::{AccountId, SessionInfo, User};
use crate::{password, scope, util};

impl<H: Host> Accounts<H> {
    /// The signed-in account's password, again. A per-account bucket of its
    /// own, the size of the sign-in one: a stolen session cookie guesses no
    /// faster than a login form, and strangers spending the login form's
    /// bucket cannot lock the signed-in owner out of step-up. An account
    /// without a password runs the dummy and is refused.
    pub async fn confirm_password(&self, ctx: &Ctx, user: &User, password: &str) -> Result<(), Error> {
        if ctx.cross_site() {
            return Err(Error::CrossSite);
        }
        self.per_account("acct-reauth", user.id, WINDOW, self.host.config().login_per_user_15min)?;
        let stored = self.store.password_hash_of(user.id).await?;
        let pw = password.to_owned();
        let ok = self
            .kdf(move || match stored.as_deref() {
                Some(h) => password::verify(&pw, h).ok,
                None => {
                    password::verify_dummy(&pw);
                    false
                }
            })
            .await?;
        if !ok {
            self.audit_detached(ctx, user.id, Some(user.id), "reauth_fail", "password");
            tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "reauth_fail", user = %user.id.hex());
            return Err(Error::Invalid("Wrong password."));
        }
        Ok(())
    }

    /// Step-up with the password: `auth_at` becomes now, and the session gets a
    /// new token, since a token seen before a privilege change must stop
    /// working. The caller sets the returned cookie.
    ///
    /// An account with a second factor steps up with that factor instead
    /// (Phase 2): a password alone never counts as recent authentication there.
    pub async fn step_up(&self, ctx: &Ctx, user: &User, session: &SessionInfo, password: &str) -> Result<NewSession, Error> {
        if !session.mfa_ok || session.user_id != user.id {
            return Err(Error::Forbidden);
        }
        if has_second_factor(user) {
            return Err(Error::Invalid("Confirm with your second factor instead."));
        }
        self.confirm_password(ctx, user, password).await?;
        self.refresh(ctx, user, session, "password").await
    }

    /// The session authenticated recently enough for a sensitive action:
    /// `auth_at` within `step_up_minutes`. Device-key, SSH and recovery logins
    /// leave `auth_at` at 0, so they are never fresh.
    pub fn fresh(&self, s: &SessionInfo, now: i64) -> bool {
        s.mfa_ok && s.auth_at > 0 && now - s.auth_at < self.host.config().step_up_minutes * 60
    }

    /// Changes the password of a signed-in account. No old password is asked,
    /// so only from a session with a recent sign-in (`Forbidden` otherwise).
    /// This session stays, every other one goes.
    pub async fn password_change(&self, ctx: &Ctx, user: &User, session: &SessionInfo, new: &str) -> Result<(), Error> {
        if !session.mfa_ok || session.user_id != user.id || !self.fresh(session, util::now()) {
            return Err(Error::Forbidden);
        }
        let old = self.store.password_hash_of(user.id).await?;
        self.set_password(ctx, user, new, old.as_deref(), Some(&session.token_hash), "change").await
    }

    /// The one way a password changes: the policy, a per-account cap, Argon2,
    /// written only over `old` (the hash the caller saw, `None` for an account
    /// without one), then every remembered browser and every session but
    /// `keep` go, and the owner is told. `NotFound` when the hash changed
    /// meanwhile.
    pub(super) async fn set_password(
        &self,
        ctx: &Ctx,
        user: &User,
        new: &str,
        old: Option<&str>,
        keep: Option<&[u8; 32]>,
        how: &str,
    ) -> Result<(), Error> {
        let cfg = self.host.config();
        password::check_policy(new, cfg.min_password_len).map_err(Error::Invalid)?;
        // Each change is an Argon2 hash: one account must not keep both slots busy.
        self.per_account("acct-pw", user.id, WINDOW, cfg.login_per_user_15min)?;
        let pw = new.to_owned();
        let hash = self.kdf(move || password::hash(&pw)).await?;
        let written = match old {
            Some(o) => self.store.rehash_password(user.id, o, &hash).await?,
            None => self.store.set_password_hash(user.id, &hash).await?,
        };
        if !written {
            return Err(Error::NotFound);
        }
        self.revoke_devkeys(ctx, user.id, Some(user.id), "password").await?;
        self.store.delete_sessions_of(user.id, keep).await?;
        self.record_after(ctx, Some(user.id), Some(user.id), "password_change", how).await;
        #[cfg(feature = "email")]
        self.password_notice(user, if how == "reset" { " with a reset link" } else { "" });
        Ok(())
    }

    /// The cleaned name as stored.
    pub async fn set_display_name(&self, ctx: &Ctx, user: AccountId, raw: &str) -> Result<String, Error> {
        let name = scope::clean_display_name(raw).map_err(Error::Invalid)?;
        if !self.store.set_display_name(user, &name).await? {
            return Err(Error::NotFound);
        }
        self.audit_after(ctx, Some(user), Some(user), "display_name", &name).await;
        Ok(name)
    }

    /// The account's live sessions, most recently used first. Pending-MFA ones
    /// included: someone who knows the password is worth seeing.
    pub async fn sessions(&self, user: AccountId, now: i64) -> sqlx::Result<Vec<SessionInfo>> {
        let idle = self.host.config().session_idle_days * DAY;
        let mut v = self.store.sessions_of(user).await?;
        v.retain(|s| s.expires_at > now && s.seen_at + idle > now);
        Ok(v)
    }

    /// Ends one of the account's own sessions. False when `hash` names none of
    /// them (someone else's, or already gone).
    pub async fn revoke_session(&self, ctx: &Ctx, user: AccountId, hash: &[u8; 32]) -> sqlx::Result<bool> {
        if !self.store.delete_session(hash, user).await? {
            return Ok(false);
        }
        self.record_after(ctx, Some(user), Some(user), "session_revoke", "").await;
        Ok(true)
    }
}
