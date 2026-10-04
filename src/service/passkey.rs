//! Passkeys (WebAuthn): add one, sign in with one alone (user verification
//! required), use one as the second factor, or step up with one.
//!
//! Every ceremony runs on a stateless challenge bound to the account (except
//! sign-in, which does not know it yet), its purpose, and a nonce cookie of
//! the browser that asked, and is burned once it verified.

use serde_json::{Value, json};

use super::{Accounts, Ctx, Error, Host, NewSession};
use crate::challenge::{self, Purpose};
use crate::model::{AccountId, Credential, FLAG_BACKUP_ELIGIBLE, SessionInfo, User, UserStatus};
use crate::verify::webauthn::{self, ES256, RS256, Rp, WebauthnError};
use crate::{scope, util};

const KIND: &str = "passkey";
/// What the browser gets to finish a ceremony: long enough for a security key
/// in a drawer.
const TTL: i64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeyFor {
    Add,
    Login,
    Mfa,
    StepUp,
}

impl PasskeyFor {
    fn purpose(self) -> Purpose {
        match self {
            Self::Add => Purpose::Enroll,
            Self::Login => Purpose::Login,
            Self::Mfa => Purpose::Mfa,
            Self::StepUp => Purpose::StepUp,
        }
    }
}

const BAD: Error = Error::Invalid("That passkey did not work. Try again, or sign in another way.");
const EXPIRED: Error = Error::Invalid("That took too long. Try again.");

fn webauthn_error(e: WebauthnError) -> Error {
    tracing::info!(target: "accounts", outcome = "passkey_refused", reason = ?e);
    match e {
        WebauthnError::Unsupported => Error::Invalid("This authenticator is not supported. Try another one."),
        _ => BAD,
    }
}

impl<H: Host> Accounts<H> {
    /// The options `navigator.credentials.create()` / `.get()` take, as the
    /// JSON the browser's `parse…OptionsFromJSON` reads, and the challenge
    /// token that comes back with the answer. `user` is required for all but
    /// `Login`.
    pub async fn passkey_options(&self, what: PasskeyFor, user: Option<&User>, browser_nonce: &[u8]) -> Result<(Value, String), Error> {
        let cfg = self.host.config();
        let uid = user.map(|u| &u.id.0[..]);
        if what != PasskeyFor::Login && uid.is_none() {
            return Err(Error::Forbidden);
        }
        let token = challenge::issue(&self.keys, what.purpose(), uid, browser_nonce, TTL);
        let challenge = util::b64u(&challenge::challenge_bytes(&token));
        let mine = match user {
            Some(u) => self.store.credentials_of(u.id, KIND).await?,
            None => Vec::new(),
        };
        let ids: Vec<Value> = mine.iter().map(|c| json!({ "type": "public-key", "id": util::b64u(&c.ext_id) })).collect();
        let timeout = TTL * 1000;
        let options = match (what, user) {
            (PasskeyFor::Add, Some(u)) => json!({
                "rp": { "id": cfg.rp_id(), "name": cfg.issuer() },
                "user": { "id": util::b64u(&u.id.0), "name": u.username, "displayName": u.display_name },
                "challenge": challenge,
                "pubKeyCredParams": [{ "type": "public-key", "alg": ES256 }, { "type": "public-key", "alg": RS256 }],
                "timeout": timeout,
                "attestation": "none",
                "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true, "userVerification": "preferred" },
                "excludeCredentials": ids,
            }),
            // Alone, a passkey must verify the user (PIN, fingerprint); as the
            // second factor after a password, holding it is enough.
            _ => json!({
                "challenge": challenge,
                "rpId": cfg.rp_id(),
                "timeout": timeout,
                "userVerification": if what == PasskeyFor::Mfa { "preferred" } else { "required" },
                "allowCredentials": ids,
            }),
        };
        Ok((options, token))
    }

    /// The challenge checks out for this purpose, account and browser.
    /// Returns its nonce, to burn once the signature has verified.
    fn challenge_ok(&self, what: PasskeyFor, user: Option<AccountId>, token: &str, browser_nonce: &[u8]) -> Result<[u8; 16], Error> {
        let uid = user.as_ref().map(|u| &u.0[..]);
        challenge::check(&self.keys, token, what.purpose(), uid, browser_nonce, util::now()).map_err(|e| {
            tracing::info!(target: "accounts", outcome = "challenge_refused", reason = ?e);
            EXPIRED
        })
    }

    fn burn(&self, nonce: &[u8; 16]) -> Result<(), Error> {
        if challenge::burn(&self.limiter, nonce) { Ok(()) } else { Err(EXPIRED) }
    }

    pub async fn passkey_add(&self, ctx: &Ctx, user: &User, token: &str, browser_nonce: &[u8], json: &str, name: &str) -> Result<(), Error> {
        let cfg = self.host.config();
        let nonce = self.challenge_ok(PasskeyFor::Add, Some(user.id), token, browser_nonce)?;
        let origins = cfg.origins();
        let rp = Rp { id: cfg.rp_id(), origins: &origins };
        let c = webauthn::verify_registration(&rp, &challenge::challenge_bytes(token), json, false).map_err(webauthn_error)?;
        self.burn(&nonce)?;
        let name = match name.trim() {
            "" => "Passkey".to_string(),
            n => scope::clean_display_name(n).map_err(Error::Invalid)?,
        };
        let row = Credential {
            kind: KIND.into(),
            ext_id: c.id,
            user_id: user.id,
            public_key: Some(c.public_key),
            alg: c.alg,
            sign_count: c.sign_count.into(),
            flags: if c.backup_eligible { FLAG_BACKUP_ELIGIBLE } else { 0 },
            name,
            created_at: util::now(),
            last_used_at: None,
        };
        if !self.store.insert_credential(&row).await? {
            return Err(Error::Invalid("That passkey is already registered."));
        }
        self.audit(ctx, Some(user.id), Some(user.id), "passkey_add", &row.name).await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "passkey_add", user = %user.id.hex());
        Ok(())
    }

    /// Verifies an assertion against the stored key, which must be `owner`'s
    /// when the account is known already, and records its use.
    async fn assert_passkey(
        &self,
        what: PasskeyFor,
        owner: Option<AccountId>,
        token: &str,
        browser_nonce: &[u8],
        json: &str,
    ) -> Result<Credential, Error> {
        let cfg = self.host.config();
        let nonce = self.challenge_ok(what, owner, token, browser_nonce)?;
        let (id, handle) = webauthn::parse_assertion_ids(json).map_err(webauthn_error)?;
        let cred = self.store.credential(KIND, &id).await?.ok_or(BAD)?;
        if owner.is_some_and(|o| o != cred.user_id) {
            return Err(BAD);
        }
        // Discoverable sign-in: the authenticator names the account, and it
        // must be the key's owner (W3C L3 §7.2 step 6).
        if what == PasskeyFor::Login && handle.as_deref() != Some(&cred.user_id.0[..]) {
            return Err(BAD);
        }
        let origins = cfg.origins();
        let rp = Rp { id: cfg.rp_id(), origins: &origins };
        let spki = cred.public_key.as_deref().ok_or(BAD)?;
        let stored_count = u32::try_from(cred.sign_count).unwrap_or(u32::MAX);
        let a = webauthn::verify_assertion(
            &rp,
            &challenge::challenge_bytes(token),
            json,
            cred.alg,
            spki,
            stored_count,
            what != PasskeyFor::Mfa,
        )
        .map_err(webauthn_error)?;
        if a.backup_eligible != (cred.flags & FLAG_BACKUP_ELIGIBLE != 0) {
            tracing::warn!(target: "accounts", outcome = "passkey_flags_changed", user = %cred.user_id.hex());
            return Err(BAD);
        }
        self.burn(&nonce)?;
        if !self.store.used_credential(KIND, &cred.ext_id, a.sign_count.into(), util::now()).await? {
            tracing::warn!(target: "accounts", outcome = "passkey_counter", user = %cred.user_id.hex());
            return Err(BAD);
        }
        Ok(cred)
    }

    /// Sign-in with a passkey alone. Counts as a full sign-in with a second
    /// factor, and as recent: user verification is required.
    pub async fn passkey_login(&self, ctx: &Ctx, token: &str, browser_nonce: &[u8], json: &str) -> Result<NewSession, Error> {
        let cfg = self.host.config();
        if !cfg.enabled {
            return Err(Error::Closed);
        }
        if ctx.cross_site() {
            return Err(Error::CrossSite);
        }
        // Not the password caps: a passkey cannot be guessed. This only keeps
        // one address from making the server verify signatures all day.
        let w = super::auth::WINDOW;
        if !self.limiter.check(&format!("acct-pk:{}", util::ip_key(ctx.ip)), w, cfg.login_per_15min * 3) {
            return Err(Error::RateLimited);
        }
        let r = self.assert_passkey(PasskeyFor::Login, None, token, browser_nonce, json).await;
        let cred = match r {
            Ok(c) => c,
            Err(e) => {
                tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = e.outcome(), "passkey login refused");
                return Err(e);
            }
        };
        let user = self.store.user_by_id(cred.user_id).await?.filter(|u| u.status == UserStatus::Active).ok_or(BAD)?;
        let now = util::now();
        self.audit(ctx, Some(user.id), None, "login_ok", "passkey").await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "login_ok", user = %user.id.hex(), how = "passkey");
        Ok(self.create_session(user.id, "passkey", true, now, ctx).await?)
    }

    /// The second sign-in step with a passkey.
    pub async fn passkey_mfa(
        &self,
        ctx: &Ctx,
        user: &User,
        pending: &SessionInfo,
        token: &str,
        browser_nonce: &[u8],
        json: &str,
    ) -> Result<NewSession, Error> {
        self.assert_passkey(PasskeyFor::Mfa, Some(user.id), token, browser_nonce, json).await?;
        // Password plus a passkey: a recent sign-in.
        self.finish_mfa(ctx, user, pending, "password+passkey", util::now()).await
    }

    /// Step-up with a passkey that verifies the user.
    pub async fn passkey_step_up(
        &self,
        ctx: &Ctx,
        user: &User,
        session: &SessionInfo,
        token: &str,
        browser_nonce: &[u8],
        json: &str,
    ) -> Result<NewSession, Error> {
        if !session.mfa_ok || session.user_id != user.id {
            return Err(Error::Forbidden);
        }
        self.assert_passkey(PasskeyFor::StepUp, Some(user.id), token, browser_nonce, json).await?;
        self.refresh(ctx, user, session, "passkey").await
    }

    pub async fn passkeys(&self, user: AccountId) -> sqlx::Result<Vec<Credential>> {
        self.store.credentials_of(user, KIND).await
    }

    /// Never the last way in: an account without a password keeps one passkey.
    /// Recovery codes go when no second factor is left.
    pub async fn passkey_remove(&self, ctx: &Ctx, user: &User, ext_id: &[u8]) -> Result<(), Error> {
        let mine = self.store.credentials_of(user.id, KIND).await?;
        if !mine.iter().any(|c| c.ext_id == ext_id) {
            return Err(Error::NotFound);
        }
        if !user.has_password && mine.len() == 1 {
            return Err(Error::Invalid("That is your only way to sign in. Add another passkey first."));
        }
        if !self.store.delete_credential(user.id, KIND, ext_id).await? {
            return Err(Error::NotFound);
        }
        if mine.len() == 1 && !user.totp_enabled {
            self.store.delete_recovery(user.id).await?;
        }
        self.audit(ctx, Some(user.id), Some(user.id), "passkey_remove", "").await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "passkey_remove", user = %user.id.hex());
        Ok(())
    }
}
