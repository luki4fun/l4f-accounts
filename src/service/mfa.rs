//! Second factors: TOTP codes and recovery codes, the second sign-in step,
//! and step-up with a code. Passkeys are in `passkey`.

use super::auth::{WINDOW, new_token};
use super::{Accounts, Ctx, DAY, Error, Host, NewSession, has_second_factor};
use crate::model::{AccountId, SessionInfo, User};
use crate::{recovery, totp, util};

/// Codes per account per 15 minutes in each bucket below, right or wrong:
/// six digits must not be guessable.
const MFA_TRIES: usize = 5;
/// The second sign-in step, which whoever has the password reaches.
const SECOND_STEP: &str = "acct-mfa";
/// Step-up and setup, from a full session: a password holder who spends
/// `SECOND_STEP` cannot lock the owner out of these.
const STEP_UP: &str = "acct-mfa-up";

/// What the setup page shows. `sealed` goes back with the first code, so
/// nothing is stored until a code proves the app has the secret.
pub struct TotpSetup {
    /// Base32, for typing in.
    pub secret: String,
    /// `otpauth://`, for the QR code.
    pub uri: String,
    pub sealed: String,
}

impl<H: Host> Accounts<H> {
    fn mfa_try(&self, bucket: &str, user: AccountId) -> Result<(), Error> {
        self.per_account(bucket, user, WINDOW, MFA_TRIES)
    }

    pub fn totp_setup(&self, user: &User) -> TotpSetup {
        let secret = totp::new_secret();
        TotpSetup {
            secret: totp::base32_encode(&secret),
            uri: totp::otpauth_uri(self.host.config().issuer(), &user.username, &secret),
            sealed: util::b64u(&self.keys.seal("totp-setup", &user.id.0, &secret)),
        }
    }

    /// The same setup again, from what the form sent back: after a wrong code
    /// the QR code the app already scanned stays valid.
    pub fn totp_setup_again(&self, user: &User, sealed: &str) -> Option<TotpSetup> {
        let (secret, _) = self.keys.open("totp-setup", &user.id.0, &util::b64u_dec(sealed)?)?;
        Some(TotpSetup {
            secret: totp::base32_encode(&secret),
            uri: totp::otpauth_uri(self.host.config().issuer(), &user.username, &secret),
            sealed: sealed.to_string(),
        })
    }

    /// Turns codes on once a code from the new secret checks out. Returns new
    /// recovery codes when the account had none left (else none), and the
    /// caller's new session when these are the account's first second factor:
    /// every other session ends then, and this one gets a new token
    /// (`factor_added`).
    pub async fn totp_enable(
        &self,
        ctx: &Ctx,
        user: &User,
        session: &SessionInfo,
        sealed: &str,
        code: &str,
    ) -> Result<(Vec<String>, Option<NewSession>), Error> {
        if !session.mfa_ok || session.user_id != user.id {
            return Err(Error::Forbidden);
        }
        if user.totp_enabled {
            return Err(Error::Invalid("Two-factor codes are already on."));
        }
        let secret = util::b64u_dec(sealed)
            .and_then(|b| self.keys.open("totp-setup", &user.id.0, &b))
            .map(|(s, _)| s)
            .filter(|s| s.len() == 20)
            .ok_or(Error::Invalid("That setup is not valid any more. Start again."))?;
        self.mfa_try(STEP_UP, user.id)?;
        let step = totp::verify(&secret, code, util::now())
            .ok_or(Error::Invalid("That code is not right. Check that the phone's clock is set automatically."))?;
        if !self.store.set_totp(user.id, Some(&self.keys.seal("totp", &user.id.0, &secret)), step).await? {
            return Err(Error::Invalid("Two-factor codes are already on."));
        }
        let codes = if self.store.recovery_left(user.id).await? == 0 { self.new_recovery(user.id).await? } else { Vec::new() };
        let rotated = self.factor_added(ctx, user, session, "totp_on").await?;
        self.record_after(ctx, Some(user.id), Some(user.id), "totp_on", "").await;
        Ok((codes, rotated))
    }

    /// After a second factor was added to `user` (as it was before): every
    /// remembered browser forgets the account, and if it was the first one,
    /// every other session ends and `session` gets a new token, returned here.
    /// None of the others showed a second factor, yet `effective_scopes` would
    /// now give them the privileged scopes that wait for one; a copied cookie
    /// of `session` dies with its old token.
    pub(super) async fn factor_added(&self, ctx: &Ctx, user: &User, session: &SessionInfo, why: &str) -> Result<Option<NewSession>, Error> {
        self.revoke_devkeys(ctx, user.id, Some(user.id), why).await?;
        if has_second_factor(user) {
            return Ok(None);
        }
        self.store.delete_sessions_of(user.id, Some(&session.token_hash)).await?;
        let (token, new) = new_token();
        // Signed out meanwhile: the factor is on all the same, and the caller
        // still shows its recovery codes; there is just no session to keep.
        if !self.store.rotate_session(&session.token_hash, &new).await? {
            return Ok(None);
        }
        Ok(self.store.session_by_hash(&new, util::now()).await?.map(|info| NewSession { token, info }))
    }

    /// Codes off. Recovery codes go too when no passkey is left to recover.
    /// Refused without a password, passkey or linked account: an SSH sign-in
    /// is never recent, so nothing else could confirm it's you then.
    pub async fn totp_disable(&self, ctx: &Ctx, user: &User) -> Result<(), Error> {
        if !user.has_password && self.store.step_up_credentials(user.id).await? == 0 {
            return Err(Error::Invalid("Add a password, a passkey or a linked account first."));
        }
        if !self.store.set_totp(user.id, None, 0).await? {
            return Err(Error::Invalid("Two-factor codes are already off."));
        }
        if !user.has_passkey {
            self.store.delete_recovery(user.id).await?;
        }
        self.revoke_devkeys(ctx, user.id, Some(user.id), "totp_off").await?;
        self.record_after(ctx, Some(user.id), Some(user.id), "totp_off", "").await;
        Ok(())
    }

    /// One code, once: rate-limited per account in `bucket`, and a step is
    /// accepted only if it is later than the last one used.
    async fn check_totp(&self, ctx: &Ctx, user: &User, code: &str, bucket: &str) -> Result<(), Error> {
        self.mfa_try(bucket, user.id)?;
        let Some((sealed, _)) = self.store.totp_of(user.id).await? else {
            return Err(Error::Invalid("Two-factor codes are not on for this account."));
        };
        let Some((secret, old_key)) = self.keys.open("totp", &user.id.0, &sealed) else {
            // Only a lost or wrong L4F_ACCOUNTS_KEY gets here.
            tracing::error!(target: "accounts", user = %user.id.hex(), "TOTP secret does not open with L4F_ACCOUNTS_KEY");
            return Err(Error::Invalid("Codes cannot be checked right now. Use a recovery code."));
        };
        let Some(step) = totp::verify(&secret, code, util::now()) else {
            self.audit(ctx, Some(user.id), None, "mfa_fail", "totp").await?;
            return Err(Error::Invalid("That code is not right."));
        };
        if !self.store.advance_totp(user.id, step).await? {
            return Err(Error::Invalid("That code was already used. Wait for the next one."));
        }
        if old_key {
            self.store.reseal_totp(user.id, &sealed, &self.keys.seal("totp", &user.id.0, &secret)).await?;
        }
        Ok(())
    }

    /// A pending session of `user` that may still finish: the site is on, as
    /// every first factor checks, and the session has not expired. Checked
    /// before the second factor is spent, so a refusal costs no code.
    pub(super) fn pending_ok(&self, user: &User, pending: &SessionInfo) -> Result<(), Error> {
        if !self.host.config().enabled {
            return Err(Error::Closed);
        }
        if pending.mfa_ok || pending.user_id != user.id || pending.expires_at <= util::now() {
            return Err(Error::Forbidden);
        }
        Ok(())
    }

    /// Completes a session waiting for its second factor (`pending_ok` passed):
    /// a new token, the full lifetime, and `auth_at` (0 for recovery codes,
    /// which are never a recent sign-in). Logged as the first factor, as the
    /// session row has it, plus `factor`: `ssh+totp`, `oauth+passkey`.
    pub(super) async fn finish_mfa(&self, ctx: &Ctx, user: &User, pending: &SessionInfo, factor: &str, auth_at: i64) -> Result<NewSession, Error> {
        let now = util::now();
        let (token, new) = new_token();
        let expires = now + self.host.config().session_max_days * DAY;
        if !self.store.complete_session(&pending.token_hash, &new, auth_at, expires).await? {
            return Err(Error::NotFound);
        }
        let info = self.store.session_by_hash(&new, now).await?.ok_or(Error::NotFound)?;
        self.record_after(ctx, Some(user.id), None, "login_ok", &format!("{}+{factor}", pending.method)).await;
        Ok(NewSession { token, info })
    }

    /// The second sign-in step with a code from the app.
    pub async fn mfa_totp(&self, ctx: &Ctx, user: &User, pending: &SessionInfo, code: &str) -> Result<NewSession, Error> {
        self.pending_ok(user, pending)?;
        self.check_totp(ctx, user, code, SECOND_STEP).await?;
        self.finish_mfa(ctx, user, pending, "totp", util::now()).await
    }

    /// The second sign-in step with a recovery code. Returns how many are left.
    pub async fn mfa_recovery(&self, ctx: &Ctx, user: &User, pending: &SessionInfo, code: &str) -> Result<(NewSession, i64), Error> {
        self.pending_ok(user, pending)?;
        self.mfa_try(SECOND_STEP, user.id)?;
        self.spend_recovery(ctx, user, code).await?;
        let left = self.store.recovery_left(user.id).await?;
        let s = self.finish_mfa(ctx, user, pending, "recovery", 0).await?;
        Ok((s, left))
    }

    /// Spends one recovery code; a wrong or used one is audited and refused.
    async fn spend_recovery(&self, ctx: &Ctx, user: &User, code: &str) -> Result<(), Error> {
        let now = util::now();
        // Every key a code may have been issued under, the current one first.
        for key in self.keys.subkeys("recovery") {
            if self.store.use_recovery(user.id, &recovery::hash(&key, &user.id.0, code), now).await? {
                return Ok(());
            }
        }
        self.audit(ctx, Some(user.id), None, "mfa_fail", "recovery").await?;
        Err(Error::Invalid("That recovery code is not right, or was already used."))
    }

    /// Step-up with a code, for accounts that have codes: a password alone is
    /// never a recent sign-in for them.
    pub async fn step_up_totp(&self, ctx: &Ctx, user: &User, session: &SessionInfo, code: &str) -> Result<NewSession, Error> {
        if !session.mfa_ok || session.user_id != user.id {
            return Err(Error::Forbidden);
        }
        self.check_totp(ctx, user, code, STEP_UP).await?;
        self.refresh(ctx, user, session, "totp").await
    }

    /// Step-up with a recovery code, which it spends. A sign-in with one is
    /// never recent, so without this whoever lost the factor it stands in for
    /// could not replace it, nor make a new set.
    pub async fn step_up_recovery(&self, ctx: &Ctx, user: &User, session: &SessionInfo, code: &str) -> Result<NewSession, Error> {
        if !session.mfa_ok || session.user_id != user.id {
            return Err(Error::Forbidden);
        }
        self.mfa_try(STEP_UP, user.id)?;
        self.spend_recovery(ctx, user, code).await?;
        self.refresh(ctx, user, session, "recovery").await
    }

    /// `auth_at` = now and a new token, for a step-up that checked out.
    pub(super) async fn refresh(&self, ctx: &Ctx, user: &User, session: &SessionInfo, how: &str) -> Result<NewSession, Error> {
        let now = util::now();
        let (token, new) = new_token();
        if !self.store.refresh_session(&session.token_hash, &new, now).await? {
            return Err(Error::NotFound);
        }
        let info = self.store.session_by_hash(&new, now).await?.ok_or(Error::NotFound)?;
        self.record_after(ctx, Some(user.id), Some(user.id), "step_up", how).await;
        Ok(NewSession { token, info })
    }

    pub async fn recovery_left(&self, user: AccountId) -> sqlx::Result<i64> {
        self.store.recovery_left(user).await
    }

    /// A new set of ten; the old ones stop working. Only with a second factor,
    /// which is what they stand in for.
    pub async fn recovery_regenerate(&self, ctx: &Ctx, user: &User) -> Result<Vec<String>, Error> {
        if !has_second_factor(user) {
            return Err(Error::Invalid("Recovery codes come with two-factor sign-in. Turn that on first."));
        }
        let codes = self.new_recovery(user.id).await?;
        self.audit_after(ctx, Some(user.id), Some(user.id), "recovery_new", "").await;
        Ok(codes)
    }

    pub(super) async fn new_recovery(&self, user: AccountId) -> sqlx::Result<Vec<String>> {
        let codes = recovery::generate();
        let key = self.keys.subkey("recovery");
        let hashes: Vec<[u8; 32]> = codes.iter().map(|c| recovery::hash(&key, &user.0, c)).collect();
        self.store.replace_recovery(user, &hashes).await?;
        Ok(codes)
    }
}
