//! A password the host checks itself. The person's device derives an Ed25519 key from the
//! password and signs the host's own message over a challenge from here (bound to whatever
//! the host binds it to, such as its TLS session); the password and anything that could
//! stand in for it never leave the device. The public key is stored where the password
//! hash is (`hostkey$ed25519$<hex>`), so everything that holds for a password holds for
//! it: one per account, the same sign-in budgets, a second factor on top, a change ends the
//! other sessions and remembered browsers, the account has a password. A password sign-in
//! against it always fails, at the cost of any other.
//!
//! What the key signs is the host's to define: `verify` gets the stored key and answers.

use super::auth::WINDOW;
use super::{Accounts, Ctx, Error, Host, LoginStep, NewSession, has_second_factor};
use crate::challenge::{self, Purpose};
use crate::model::{AccountId, SessionInfo, User};
use crate::util;

/// The session method, and the audit detail, of a host-key sign-in.
pub(super) const METHOD: &str = "hostkey";
const PREFIX: &str = "hostkey$ed25519$";
/// Long enough for the device to stretch the password.
const TTL: i64 = 120;

const BAD_LOGIN: Error = Error::BadLogin;

/// What the password column holds for a host key.
pub(super) fn stored(key: &[u8; 32]) -> String {
    let mut s = String::with_capacity(PREFIX.len() + 64);
    s.push_str(PREFIX);
    for b in key {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The key in a password column, if it holds one.
fn key_of(stored: &str) -> Option<[u8; 32]> {
    let hex = stored.strip_prefix(PREFIX)?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

impl<H: Host> Accounts<H> {
    /// A challenge for the key: to sign in (`user` None), or for a signed-in account to
    /// confirm itself (`confirm_hostkey`, `step_up_hostkey`). `nonce` is the host's, kept
    /// with the connection it serves and never sent, as for the other key challenges.
    pub fn hostkey_challenge(&self, user: Option<&User>, nonce: &[u8]) -> String {
        let purpose = if user.is_some() { Purpose::StepUp } else { Purpose::Login };
        challenge::issue(&self.keys, purpose, user.map(|u| &u.id.0[..]), nonce, TTL)
    }

    /// The account's host key; None while it signs in with an Argon2 password, or none.
    pub async fn hostkey(&self, user: AccountId) -> sqlx::Result<Option<[u8; 32]>> {
        Ok(self.store.password_hash_of(user).await?.as_deref().and_then(key_of))
    }

    /// Sign-in by name with the host key: the password's caps and answers. `verify` checks
    /// the host's signature against the stored key (and is run against a key nobody has
    /// for a name without one, so both cost the same).
    pub async fn login_hostkey(
        &self,
        ctx: &Ctx,
        username: &str,
        token: &str,
        nonce: &[u8],
        known_device_user: Option<AccountId>,
        verify: impl FnOnce(&[u8; 32]) -> bool,
    ) -> Result<LoginStep, Error> {
        let r = self.login_hostkey_inner(ctx, username, token, nonce, known_device_user, verify).await;
        if let Err(e) = &r {
            tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = e.outcome(), "host key login refused");
        }
        r
    }

    async fn login_hostkey_inner(
        &self,
        ctx: &Ctx,
        username: &str,
        token: &str,
        nonce: &[u8],
        known_device_user: Option<AccountId>,
        verify: impl FnOnce(&[u8; 32]) -> bool,
    ) -> Result<LoginStep, Error> {
        let user = self.login_door(ctx, username, known_device_user).await?;
        let n = self.challenge_ok(Purpose::Login, None, token, nonce)?;
        let active = user.as_ref().filter(|u| u.status == crate::model::UserStatus::Active).map(|u| u.id);
        let proved = match active {
            Some(id) => self.store.password_hash_of(id).await?,
            None => None,
        };
        let key = proved.as_deref().and_then(key_of);
        let ok = verify(&key.unwrap_or([0; 32])) && key.is_some();
        let user = match (user, ok) {
            (Some(u), true) if active.is_some() => u,
            (Some(u), _) => {
                self.audit_detached(ctx, u.id, None, "login_fail", METHOD);
                return Err(BAD_LOGIN);
            }
            (None, _) => return Err(BAD_LOGIN),
        };
        self.burn(&n)?;
        let step = if has_second_factor(&user) {
            self.audit(ctx, Some(user.id), None, "login_need_mfa", METHOD).await?;
            LoginStep::NeedMfa(self.create_session(user.id, METHOD, false, 0, ctx).await?)
        } else {
            self.record(ctx, Some(user.id), None, "login_ok", METHOD).await?;
            LoginStep::Done(self.create_session(user.id, METHOD, true, util::now(), ctx).await?)
        };
        // A change writes the new value, then deletes the sessions. If that DELETE ran
        // before this session's INSERT, the value shows it now.
        let (LoginStep::Done(s) | LoginStep::NeedMfa(s)) = &step;
        if self.store.password_hash_of(user.id).await? != proved {
            self.store.delete_session(&s.info.token_hash, user.id).await?;
            return Err(BAD_LOGIN);
        }
        Ok(step)
    }

    /// The password again, for a signed-in account: `confirm_password` with the key, over
    /// a challenge from `hostkey_challenge(Some(user), …)`.
    pub async fn confirm_hostkey(
        &self,
        ctx: &Ctx,
        user: &User,
        token: &str,
        nonce: &[u8],
        verify: impl FnOnce(&[u8; 32]) -> bool,
    ) -> Result<(), Error> {
        if ctx.cross_site() {
            return Err(Error::CrossSite);
        }
        self.per_account("acct-reauth", user.id, WINDOW, self.host.config().login_per_user_15min)?;
        let n = self.challenge_ok(Purpose::StepUp, Some(user.id), token, nonce)?;
        let key = self.hostkey(user.id).await?;
        if !(verify(&key.unwrap_or([0; 32])) && key.is_some()) {
            self.audit_detached(ctx, user.id, Some(user.id), "reauth_fail", METHOD);
            tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "reauth_fail", user = %user.id.hex());
            return Err(Error::Invalid("Wrong password."));
        }
        self.burn(&n)
    }

    /// `step_up` with the key.
    pub async fn step_up_hostkey(
        &self,
        ctx: &Ctx,
        user: &User,
        session: &SessionInfo,
        token: &str,
        nonce: &[u8],
        verify: impl FnOnce(&[u8; 32]) -> bool,
    ) -> Result<NewSession, Error> {
        if !session.mfa_ok || session.user_id != user.id {
            return Err(Error::Forbidden);
        }
        if has_second_factor(user) {
            return Err(Error::Invalid("Confirm with your second factor instead."));
        }
        self.confirm_hostkey(ctx, user, token, nonce, verify).await?;
        self.refresh(ctx, user, session, METHOD).await
    }

    /// The same password, from now on as a host key: in place of the Argon2 hash, from a
    /// session that signed in recently (with that password, as the host knows). Nothing
    /// else changes: the other sessions and remembered browsers stay, nobody is told. The
    /// host checks that the key is the password's, which this cannot.
    pub async fn hostkey_upgrade(&self, ctx: &Ctx, user: &User, session: &SessionInfo, key: &[u8; 32]) -> Result<(), Error> {
        if !session.mfa_ok || session.user_id != user.id || !self.fresh(session, util::now()) {
            return Err(Error::Forbidden);
        }
        let old = self.store.password_hash_of(user.id).await?;
        match old.as_deref() {
            Some(o) if key_of(o).is_none() => {}
            Some(o) if key_of(o) == Some(*key) => return Ok(()),
            _ => return Err(Error::Invalid("This account has no password to move.")),
        }
        let old = old.unwrap_or_default();
        if !self.store.rehash_password(user.id, &old, &stored(key)).await? {
            return Err(Error::NotFound);
        }
        self.audit_after(ctx, Some(user.id), Some(user.id), "password_upgrade", METHOD).await;
        Ok(())
    }

    /// A new password as a host key: `password_change` with the key. This session stays,
    /// every other one goes, and every remembered browser.
    pub async fn hostkey_change(&self, ctx: &Ctx, user: &User, session: &SessionInfo, key: &[u8; 32]) -> Result<(), Error> {
        if !session.mfa_ok || session.user_id != user.id || !self.fresh(session, util::now()) {
            return Err(Error::Forbidden);
        }
        self.per_account("acct-pw", user.id, WINDOW, self.host.config().login_per_user_15min)?;
        let old = self.store.password_hash_of(user.id).await?;
        self.write_password(ctx, user, &stored(key), old.as_deref(), Some(&session.token_hash), "change")
            .await
    }

    /// `password_set_as_host` with a host key: a reset the host proved by other means.
    pub async fn hostkey_set_as_host(&self, ctx: &Ctx, target: AccountId, key: &[u8; 32]) -> Result<(), Error> {
        let user = self.store.user_by_id(target).await?.ok_or(Error::NotFound)?;
        let old = self.store.password_hash_of(user.id).await?;
        self.write_password(ctx, &user, &stored(key), old.as_deref(), None, "host").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_reads_back_and_nothing_else_reads_as_one() {
        let k = [0xab; 32];
        assert_eq!(key_of(&stored(&k)), Some(k));
        assert_eq!(key_of("$argon2id$v=19$m=19456,t=2,p=1$abc$def"), None);
        assert_eq!(key_of(&stored(&k)[..PREFIX.len() + 63]), None);
        assert_eq!(key_of(&format!("{PREFIX}{}", "zz".repeat(32))), None);
    }

    #[test]
    fn a_password_never_matches_a_key() {
        let v = crate::password::verify("anything", &stored(&[1; 32]));
        assert!(!v.ok);
    }
}
