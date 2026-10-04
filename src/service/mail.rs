//! Mail-backed flows: an address confirmed by link, and a forgotten password
//! reset by link. Links carry signed, expiring tokens and no database row:
//! the reset token is bound to the current password hash, so it dies with
//! its first use, and the address token to the pending address.
//!
//! Mail goes out on a spawned task, so the answer neither waits for SMTP nor
//! tells by its timing whether an account exists.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::auth::{WINDOW, clean_email};
use super::{ACCOUNT_PATH, Accounts, Ctx, Error, Host};
use crate::email::Mailer;
use crate::model::{AccountId, User, UserStatus};
use crate::store::EmailConfirm;
use crate::{scope, util};

const HOUR: Duration = Duration::from_secs(3600);
const VERIFY_SECS: i64 = 24 * 3600;
const RESET_SECS: i64 = 3600;
const EXPIRED: Error = Error::Invalid("That link is not valid any more. Ask for a new one.");

/// `b64u(user | exp | extra)` + "." + its tag, over `bound` too.
fn token(keys: &crate::keys::Keys, purpose: &str, user: AccountId, exp: i64, extra: &[u8], bound: &[u8]) -> String {
    let mut p = user.0.to_vec();
    p.extend(exp.to_be_bytes());
    p.extend(extra);
    let tag = keys.sign(purpose, &[&p[..], bound].concat());
    format!("{}.{tag}", util::b64u(&p))
}

struct Parsed {
    user: AccountId,
    extra: Vec<u8>,
    payload: Vec<u8>,
    tag: String,
}

/// Shape and expiry only; `holds` checks the tag once the caller has what
/// the token is bound to.
fn parse(t: &str) -> Result<Parsed, Error> {
    let (p64, tag) = t.split_once('.').ok_or(EXPIRED)?;
    let p = util::b64u_dec(p64).filter(|p| p.len() >= 24 && p.len() <= 24 + 254).ok_or(EXPIRED)?;
    let user = AccountId::from_slice(&p[..16]).ok_or(EXPIRED)?;
    let exp = i64::from_be_bytes(p[16..24].try_into().map_err(|_| EXPIRED)?);
    if util::now() >= exp {
        return Err(EXPIRED);
    }
    Ok(Parsed { user, extra: p[24..].to_vec(), payload: p, tag: tag.to_string() })
}

fn holds(keys: &crate::keys::Keys, purpose: &str, p: &Parsed, bound: &[u8]) -> bool {
    keys.verify(purpose, &[&p.payload[..], bound].concat(), &p.tag)
}

fn host_of(base_url: &str) -> &str {
    base_url.split_once("://").map_or(base_url, |(_, r)| r).split('/').next().unwrap_or("")
}

impl<H: Host> Accounts<H> {
    pub fn with_mailer(mut self, m: Mailer) -> Self {
        self.mailer = Some(Arc::new(m));
        self
    }

    /// Whether the mail-backed pages are on.
    pub fn mail_ready(&self) -> bool {
        self.mailer.is_some()
    }

    /// Per account, per address and site-wide: a form must not become a way
    /// to mail-bomb someone, or the site's sender reputation.
    fn mail_allowed(&self, user: AccountId, addr: &str) -> bool {
        let a = hex::encode(&Sha256::digest(addr.as_bytes())[..12]);
        self.limiter.check(&format!("acct-mail-u-{}:x", user.hex()), HOUR, 5)
            && self.limiter.check(&format!("acct-mail-a-{a}:x"), HOUR, 3)
            && self.limiter.check("acct-mail:global", HOUR, 200)
    }

    fn send_later(&self, to: String, subject: &'static str, body: String) {
        let Some(m) = self.mailer.clone() else { return };
        tokio::spawn(async move {
            if let Err(e) = m.send(&to, subject, body).await {
                tracing::warn!(target: "accounts", error = %e, "mail not sent");
            }
        });
    }

    fn link(&self, path: &str, token: &str) -> String {
        format!("{}{ACCOUNT_PATH}{path}?t={token}", self.host.config().base_url)
    }

    /// A new address waits in `email_pending` until its link is opened.
    pub async fn email_set(&self, ctx: &Ctx, user: &User, raw: &str) -> Result<(), Error> {
        let email = clean_email(raw).map_err(Error::Invalid)?.ok_or(Error::Invalid("Enter an address."))?;
        if user.email.as_deref() == Some(&email) {
            return Err(Error::Invalid("That is your address already."));
        }
        if self.mailer.is_none() {
            return Err(Error::Invalid("This site cannot send mail right now."));
        }
        if !self.mail_allowed(user.id, &email) {
            return Err(Error::RateLimited);
        }
        self.store.set_email_pending(user.id, Some(&email)).await?;
        let t = token(&self.keys, "email-verify", user.id, util::now() + VERIFY_SECS, email.as_bytes(), b"");
        let site = host_of(&self.host.config().base_url).to_string();
        let body = format!(
            "Someone, hopefully you, asked to use this address for the account {} on {site}.\n\n\
             To confirm it, open this link within 24 hours:\n{}\n\n\
             If that was not you, ignore this message: nothing changes.\n",
            user.username,
            self.link("/verify-email", &t)
        );
        self.send_later(email, "Confirm your email address", body);
        self.audit(ctx, Some(user.id), Some(user.id), "email_pending", "").await?;
        Ok(())
    }

    pub async fn email_remove(&self, ctx: &Ctx, user: &User) -> Result<(), Error> {
        self.store.clear_email(user.id).await?;
        self.audit(ctx, Some(user.id), Some(user.id), "email_remove", "").await?;
        Ok(())
    }

    /// The link's POST: no sign-in needed, the token is the proof.
    pub async fn email_confirm(&self, ctx: &Ctx, t: &str) -> Result<(), Error> {
        let p = parse(t)?;
        if !holds(&self.keys, "email-verify", &p, b"") {
            return Err(EXPIRED);
        }
        let (user, email) = (p.user, String::from_utf8(p.extra).map_err(|_| EXPIRED)?);
        match self.store.confirm_email(user, &email, util::now()).await? {
            EmailConfirm::Done => {}
            EmailConfirm::Stale => return Err(EXPIRED),
            EmailConfirm::Taken => return Err(Error::Invalid("That address belongs to another account.")),
        }
        self.audit(ctx, Some(user), None, "email_verified", "").await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "email_verified", user = %user.hex());
        Ok(())
    }

    /// Always `Ok` unless refused outright: whether the name exists, and
    /// whether it has a confirmed address, is nobody's business. The lookup and
    /// the mail happen after the answer.
    pub async fn password_forgot(&self, ctx: &Ctx, who: &str) -> Result<(), Error> {
        if ctx.cross_site() {
            return Err(Error::CrossSite);
        }
        if !self.limiter.check(&format!("acct-forgot:{}", util::ip_key(ctx.ip)), WINDOW, 5) {
            return Err(Error::RateLimited);
        }
        let who = who.trim().to_lowercase();
        let user = if who.contains('@') {
            self.store.user_by_email(&who).await?
        } else {
            match scope::username_shape(&who) {
                Ok(n) => self.store.user_by_username(&n).await?,
                Err(_) => None,
            }
        };
        let Some(user) = user.filter(|u| u.status == UserStatus::Active) else { return Ok(()) };
        let Some(email) = user.email.clone() else { return Ok(()) };
        if !self.mail_allowed(user.id, &email) {
            return Ok(());
        }
        let hash = self.store.password_hash_of(user.id).await?.unwrap_or_default();
        let t = token(&self.keys, "reset", user.id, util::now() + RESET_SECS, b"", &Sha256::digest(hash.as_bytes()));
        let site = host_of(&self.host.config().base_url).to_string();
        let body = format!(
            "Someone asked to reset the password of the account {} on {site}.\n\n\
             To choose a new password, open this link within an hour:\n{}\n\n\
             If that was not you, ignore this message: your password stays as it is.\n",
            user.username,
            self.link("/reset", &t)
        );
        self.send_later(email, "Reset your password", body);
        self.audit(ctx, Some(user.id), None, "reset_mail", "").await?;
        Ok(())
    }

    /// Sets a new password from a reset link: nothing else. No sign-in, and a
    /// second factor stays. Every session and remembered browser goes.
    pub async fn password_reset(&self, ctx: &Ctx, t: &str, new: &str) -> Result<(), Error> {
        let p = parse(t)?;
        let old = self.store.password_hash_of(p.user).await?;
        if !holds(&self.keys, "reset", &p, &Sha256::digest(old.as_deref().unwrap_or_default().as_bytes())) {
            return Err(EXPIRED);
        }
        let user = p.user;
        let u = self.store.user_by_id(user).await?.filter(|u| u.status == UserStatus::Active).ok_or(EXPIRED)?;
        // Over the hash the link was bound to only: two uses of one link
        // cannot both set a password.
        self.set_password(ctx, &u, new, old.as_deref(), None, "reset").await.map_err(|e| match e {
            Error::NotFound => EXPIRED,
            e => e,
        })
    }

    /// The notice after a password change, if the account has an address.
    pub(super) fn password_notice(&self, user: &User, how: &str) {
        let Some(email) = user.email.clone() else { return };
        let site = host_of(&self.host.config().base_url).to_string();
        let body = format!(
            "The password of your account {} on {site} was just changed{how}. Every other session \
             was signed out.\n\nIf that was not you, reset it again and check your account's security page.\n",
            user.username
        );
        self.send_later(email, "Your password was changed", body);
    }
}
