//! Signing in with a key: an SSH key (`ssh-keygen -Y sign` over a challenge)
//! and a device key (a non-extractable WebCrypto Ed25519 key this browser
//! keeps). Plus removing any credential, which every kind shares.
//!
//! An SSH key is a first factor like the password: with a second factor
//! enrolled it opens a pending session. A device key stands in for a full
//! sign-in on the browser that holds it, but is never a recent sign-in, and
//! every change to the second factors revokes all of an account's device keys.

use super::auth::WINDOW;
use super::{Accounts, Ctx, DAY, Error, Host, LoginStep, NewSession, has_second_factor};
use crate::challenge::{self, Purpose};
use crate::model::{AccountId, Credential, User, UserStatus};
use crate::store::DeleteCredential;
use crate::verify::{devkey, sshsig};
use crate::{scope, util};

pub(super) const SSH: &str = "ssh";
pub(super) const DEVKEY: &str = "devkey";
/// Long enough to find the key and run the command.
const SSH_TTL: i64 = 600;
const DEVKEY_TTL: i64 = 120;
/// A device key nobody used for this long is deleted.
pub(super) const DEVKEY_DAYS: i64 = 90;

/// What a browser sends to be remembered: its id, its public key, and its
/// signature over the enrol challenge.
pub struct NewDeviceKey<'a> {
    pub device_id: &'a [u8],
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
}

const BAD_SSH: Error = Error::Invalid("That signature did not check out. Sign the text shown on this page with the namespace given.");
const BAD_DEVICE: Error = Error::Invalid("This browser is not remembered any more. Sign in another way.");
const EXPIRED: Error = Error::Invalid("That took too long. Try again.");

fn fp(blob: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(blob).to_vec()
}

impl<H: Host> Accounts<H> {
    fn key_challenge(&self, purpose: Purpose, user: Option<&User>, nonce: &[u8], ttl: i64) -> String {
        challenge::issue(&self.keys, purpose, user.map(|u| &u.id.0[..]), nonce, ttl)
    }

    /// The challenge checks out for this purpose, account and browser.
    /// Returns its nonce, to burn once the signature has verified.
    pub(super) fn challenge_ok(&self, purpose: Purpose, user: Option<AccountId>, token: &str, nonce: &[u8]) -> Result<[u8; 16], Error> {
        let uid = user.as_ref().map(|u| &u.0[..]);
        challenge::check(&self.keys, token, purpose, uid, nonce, util::now()).map_err(|e| {
            tracing::info!(target: "accounts", outcome = "challenge_refused", reason = ?e);
            EXPIRED
        })
    }

    /// Spends the nonce `challenge_ok` returned; a second use is refused like
    /// an expired one.
    pub(super) fn burn(&self, nonce: &[u8; 16]) -> Result<(), Error> {
        if challenge::burn(&self.limiter, nonce) { Ok(()) } else { Err(EXPIRED) }
    }

    /// A verified key sign-in (SSH, device key, passkey), per account. Charged
    /// once the signature checked out, so a stranger cannot spend it, and
    /// before the burn, so it bounds an account's live burns whatever number
    /// of addresses sign for it.
    pub(super) fn key_try(&self, user: AccountId) -> Result<(), Error> {
        self.per_account("acct-key", user, WINDOW, self.host.config().login_per_user_15min * 3)
    }

    // ---- SSH

    /// The text to sign: the challenge token itself, which only this browser
    /// (its nonce cookie) can turn back in.
    pub fn ssh_challenge(&self, user: Option<&User>, nonce: &[u8]) -> String {
        let purpose = if user.is_some() { Purpose::Enroll } else { Purpose::Login };
        self.key_challenge(purpose, user, nonce, SSH_TTL)
    }

    /// Adds a key once a signature by it over an enrol challenge checks out,
    /// so nobody can claim someone else's public key.
    pub async fn ssh_add(&self, ctx: &Ctx, user: &User, token: &str, nonce: &[u8], key_line: &str, signature: &str) -> Result<(), Error> {
        let cfg = self.host.config();
        let key = sshsig::parse_public_key(key_line)
            .map_err(|_| Error::Invalid("That is not a public key this site takes: ssh-ed25519, ssh-rsa (2048 to 8192 bits) or ecdsa-sha2-nistp256."))?;
        let n = self.challenge_ok(Purpose::Enroll, Some(user.id), token, nonce)?;
        sshsig::verify(signature, &cfg.ssh_namespace(), token.as_bytes(), &[&key.blob]).map_err(|e| {
            tracing::info!(target: "accounts", outcome = "ssh_refused", reason = ?e);
            BAD_SSH
        })?;
        self.burn(&n)?;
        let name = match key.comment.as_str() {
            "" => key.algo.clone(),
            c => scope::clean_display_name(c).unwrap_or_else(|_| key.algo.clone()),
        };
        let row = Credential::new(SSH, fp(&key.blob), user.id, Some(key.blob), name);
        if !self.store.insert_credential(&row).await? {
            return Err(Error::Invalid("That key is already registered."));
        }
        self.record_after(ctx, Some(user.id), Some(user.id), "ssh_add", &sshsig::fingerprint(row.public_key.as_deref().unwrap_or_default())).await;
        Ok(())
    }

    /// Sign-in with an SSH signature. The key names the account. Never a
    /// recent sign-in; with a second factor enrolled, a pending session.
    pub async fn ssh_login(&self, ctx: &Ctx, token: &str, nonce: &[u8], signature: &str) -> Result<LoginStep, Error> {
        let r = self.ssh_login_inner(ctx, token, nonce, signature).await;
        if let Err(e) = &r {
            tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = e.outcome(), "ssh login refused");
        }
        r
    }

    async fn ssh_login_inner(&self, ctx: &Ctx, token: &str, nonce: &[u8], signature: &str) -> Result<LoginStep, Error> {
        let cfg = self.host.config();
        self.door(ctx, "acct-ssh", WINDOW, cfg.login_per_15min * 3)?;
        let n = self.challenge_ok(Purpose::Login, None, token, nonce)?;
        let blob = sshsig::signer(signature).map_err(|_| BAD_SSH)?;
        let cred = self.store.credential(SSH, &fp(&blob)).await?.ok_or(BAD_SSH)?;
        let stored = cred.public_key.as_deref().ok_or(BAD_SSH)?;
        sshsig::verify(signature, &cfg.ssh_namespace(), token.as_bytes(), &[stored]).map_err(|_| BAD_SSH)?;
        self.key_try(cred.user_id)?;
        self.burn(&n)?;
        // False once the key was removed after the lookup above.
        if !self.store.used_credential(SSH, &cred.ext_id, 0, util::now()).await? {
            return Err(BAD_SSH);
        }
        let user = self.store.user_by_id(cred.user_id).await?.filter(|u| u.status == UserStatus::Active).ok_or(BAD_SSH)?;
        if has_second_factor(&user) {
            self.audit(ctx, Some(user.id), None, "login_need_mfa", "ssh").await?;
            return Ok(LoginStep::NeedMfa(self.create_session(user.id, "ssh", false, 0, ctx).await?));
        }
        self.record(ctx, Some(user.id), None, "login_ok", "ssh").await?;
        Ok(LoginStep::Done(self.create_session(user.id, "ssh", true, 0, ctx).await?))
    }

    pub async fn ssh_keys(&self, user: AccountId) -> sqlx::Result<Vec<Credential>> {
        self.store.credentials_of(user, SSH).await
    }

    // ---- device keys

    pub fn devkey_challenge(&self, user: Option<&User>, nonce: &[u8]) -> String {
        let purpose = if user.is_some() { Purpose::Enroll } else { Purpose::Login };
        self.key_challenge(purpose, user, nonce, DEVKEY_TTL)
    }

    /// The signature over `devkey::message` for one of the site's origins.
    fn devkey_ok(&self, public_key: &[u8], device_id: &[u8], token: &str, signature: &[u8]) -> bool {
        let ch = challenge::challenge_bytes(token);
        self.host.config().origins().iter().any(|o| devkey::verify(public_key, o, device_id, &ch, signature))
    }

    /// Remembers this browser for `user`. Needs a recent sign-in, checked by
    /// the caller like every credential change.
    pub async fn devkey_add(&self, ctx: &Ctx, user: &User, token: &str, nonce: &[u8], key: NewDeviceKey<'_>) -> Result<(), Error> {
        let NewDeviceKey { device_id, public_key, signature } = key;
        if !(16..=64).contains(&device_id.len()) {
            return Err(BAD_DEVICE);
        }
        let n = self.challenge_ok(Purpose::Enroll, Some(user.id), token, nonce)?;
        if !self.devkey_ok(public_key, device_id, token, signature) {
            return Err(Error::Invalid("This browser's key did not check out."));
        }
        self.burn(&n)?;
        let row = Credential::new(DEVKEY, device_id.to_vec(), user.id, Some(public_key.to_vec()), ctx.ua.chars().take(64).collect());
        if !self.store.insert_credential(&row).await? {
            return Err(Error::Invalid("This browser is already remembered."));
        }
        self.record_after(ctx, Some(user.id), Some(user.id), "devkey_add", "").await;
        Ok(())
    }

    /// Sign-in with this browser's key: a full session (the key stands in for
    /// both factors on the browser that holds it), never a recent sign-in.
    pub async fn devkey_login(&self, ctx: &Ctx, token: &str, nonce: &[u8], device_id: &[u8], signature: &[u8]) -> Result<NewSession, Error> {
        let r = self.devkey_login_inner(ctx, token, nonce, device_id, signature).await;
        if let Err(e) = &r {
            tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = e.outcome(), "devkey login refused");
        }
        r
    }

    async fn devkey_login_inner(&self, ctx: &Ctx, token: &str, nonce: &[u8], device_id: &[u8], signature: &[u8]) -> Result<NewSession, Error> {
        self.door(ctx, "acct-dk", WINDOW, self.host.config().login_per_15min * 3)?;
        let n = self.challenge_ok(Purpose::Login, None, token, nonce)?;
        let cred = self.store.credential(DEVKEY, device_id).await?.ok_or(BAD_DEVICE)?;
        let now = util::now();
        if cred.last_used_at.unwrap_or(cred.created_at) + DEVKEY_DAYS * DAY < now {
            self.store.delete_credential(cred.user_id, DEVKEY, device_id).await?;
            return Err(BAD_DEVICE);
        }
        if !self.devkey_ok(cred.public_key.as_deref().unwrap_or_default(), device_id, token, signature) {
            return Err(BAD_DEVICE);
        }
        self.key_try(cred.user_id)?;
        self.burn(&n)?;
        // False once this browser was forgotten after the lookup above.
        if !self.store.used_credential(DEVKEY, device_id, 0, now).await? {
            return Err(BAD_DEVICE);
        }
        let user = self.store.user_by_id(cred.user_id).await?.filter(|u| u.status == UserStatus::Active).ok_or(BAD_DEVICE)?;
        self.record(ctx, Some(user.id), None, "login_ok", "devkey").await?;
        let s = self.create_session(user.id, "devkey", true, 0, ctx).await?;
        // A revocation deletes the key, then the sessions. If that DELETE ran
        // before this session's INSERT, the key is gone now.
        if !self.store.credential(DEVKEY, device_id).await?.is_some_and(|c| c.user_id == user.id) {
            self.store.delete_session(&s.info.token_hash, user.id).await?;
            return Err(BAD_DEVICE);
        }
        Ok(s)
    }

    pub async fn devkeys(&self, user: AccountId) -> sqlx::Result<Vec<Credential>> {
        self.store.credentials_of(user, DEVKEY).await
    }

    /// Every remembered browser of the account forgets it: after a change to
    /// the second factors or sign-out everywhere. Run it before deleting the
    /// sessions: a device-key sign-in in flight then lands before that DELETE
    /// or finds its key gone (`devkey_login`). `actor` asked for it: the
    /// account, an admin (whose address the account's history then hides), or
    /// `None` for the host's shell. Returns how many keys went.
    pub(super) async fn revoke_devkeys(&self, ctx: &Ctx, user: AccountId, actor: Option<AccountId>, why: &str) -> sqlx::Result<u64> {
        let n = self.store.delete_credentials_of(user, DEVKEY).await?;
        if n > 0 {
            self.audit_after(ctx, Some(user), actor, "devkey_revoke", &super::admin::marked(why, actor)).await;
        }
        Ok(n)
    }

    // ---- removing any credential

    /// Never the last way in that can also confirm it's you: an account keeps
    /// its password, a passkey or a linked account, checked and deleted in one
    /// transaction (`Store::delete_credential_if_not_last`). SSH keys do not
    /// count, as their sign-in is never recent; a device key only stands in
    /// for another sign-in and goes unchecked. Recovery codes go with the last
    /// second factor; device keys go with any second factor.
    pub async fn remove_credential(&self, ctx: &Ctx, user: &User, kind: &str, ext_id: &[u8]) -> Result<(), Error> {
        let cred = self.store.credential(kind, ext_id).await?.filter(|c| c.user_id == user.id).ok_or(Error::NotFound)?;
        let gone = if kind == DEVKEY {
            self.store.delete_credential(user.id, kind, &cred.ext_id).await?
        } else {
            match self.store.delete_credential_if_not_last(user.id, kind, &cred.ext_id).await? {
                DeleteCredential::Done => true,
                DeleteCredential::NotFound => false,
                DeleteCredential::LastWayIn => {
                    return Err(Error::Invalid("That would leave no password, passkey or linked account to sign in with. Add one first."));
                }
            }
        };
        if !gone {
            return Err(Error::NotFound);
        }
        if kind == super::passkey::KIND {
            let left = self.store.credentials_of(user.id, kind).await?.len();
            if left == 0 && !user.totp_enabled {
                self.store.delete_recovery(user.id).await?;
            }
            self.revoke_devkeys(ctx, user.id, Some(user.id), "passkey_remove").await?;
        }
        self.audit_after(ctx, Some(user.id), Some(user.id), &format!("{kind}_remove"), &cred.name).await;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "credential_remove", kind, user = %user.id.hex());
        Ok(())
    }
}
