//! Mail-backed flows: an address confirmed by link, and a forgotten password
//! reset by link. Links carry signed, expiring tokens and no database row:
//! the reset token is bound to the current password hash and address, so it
//! dies with its first use or a new address, and the address token to the
//! pending address.
//!
//! Mail goes out on a spawned task, a reset's reads and writes with it, so
//! the answer neither waits for SMTP nor tells by its timing whether an
//! account exists.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::auth::{WINDOW, clean_email};
use super::{ACCOUNT_PATH, Accounts, Ctx, Error, Host, account_key, audit_lost};
use crate::email::Mailer;
use crate::model::{AccountId, User, UserStatus};
use crate::store::EmailConfirm;
use crate::{scope, util};

const HOUR: Duration = Duration::from_secs(3600);
const VERIFY_SECS: i64 = 24 * 3600;
const RESET_SECS: i64 = 3600;
/// Longer than any token `token` makes: one for a 254-byte address is 415.
const MAX_TOKEN: usize = 512;
/// Mail per hour site-wide, once for confirmations and once for resets, so
/// resets nobody signed in for cannot use up the confirmations, or the
/// other way round.
const SITE_PER_HOUR: usize = 200;
const CONFIRM_SITE: &str = "acct-mail:global";
const RESET_SITE: &str = "acct-mail-reset:global";
const EXPIRED: Error = Error::Invalid("That link is not valid any more. Ask for a new one.");
const OTHER_ACCOUNT: Error = Error::Invalid("That link is for another account. Sign out, then open it again.");

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
    let (p, tag) = util::split_token(t, MAX_TOKEN).filter(|(p, _)| p.len() >= 24 && p.len() <= 24 + 254).ok_or(EXPIRED)?;
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

/// What a reset link is bound to: the password hash, so the link dies with
/// its first use, and the address it went to, so it dies with a new one.
/// A hash never holds a NUL.
fn reset_bound(hash: Option<&str>, email: Option<&str>) -> [u8; 32] {
    let (hash, email) = (hash.unwrap_or_default(), email.unwrap_or_default());
    Sha256::new().chain_update(hash).chain_update([0]).chain_update(email).finalize().into()
}

/// The mailbox an address delivers to, for the per-address cap: `+tags`,
/// and dots at Gmail, spell one inbox many ways.
fn mailbox(addr: &str) -> String {
    let addr = addr.to_lowercase();
    let Some((local, domain)) = addr.rsplit_once('@') else { return addr };
    let local = local.split('+').next().unwrap_or_default();
    match domain {
        "gmail.com" | "googlemail.com" => format!("{}@gmail.com", local.replace('.', "")),
        _ => format!("{local}@{domain}"),
    }
}

fn link(base_url: &str, path: &str, token: &str) -> String {
    format!("{base_url}{ACCOUNT_PATH}{path}?t={token}")
}

/// One message. Nobody waits for it, so a failure is only logged.
async fn deliver(m: &Mailer, to: &str, subject: &str, body: String) {
    if let Err(e) = m.send(to, subject, body).await {
        tracing::warn!(target: "accounts", error = %e, "mail not sent");
    }
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

    /// Per account, per mailbox and site-wide (`site`, a ceiling per kind of
    /// mail): a form must not become a way to mail-bomb someone, or the site's
    /// sender reputation. All are peeked first and counted only when all
    /// pass, so a refusal spends none of them.
    fn mail_allowed(&self, user: AccountId, addr: &str, site: &str) -> bool {
        let a = hex::encode(&Sha256::digest(mailbox(addr).as_bytes())[..12]);
        let buckets = [(account_key("acct-mail-u", user), 5), (format!("acct-mail-a-{a}:x"), 3), (site.to_string(), SITE_PER_HOUR)];
        if !buckets.iter().all(|(k, max)| self.limiter.peek(k, HOUR, *max)) {
            return false;
        }
        for (k, _) in &buckets {
            self.limiter.record(k, HOUR);
        }
        true
    }

    fn send_later(&self, to: String, subject: &'static str, body: String) {
        let Some(m) = self.mailer.clone() else { return };
        tokio::spawn(async move { deliver(&m, &to, subject, body).await });
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
        if !self.mail_allowed(user.id, &email, CONFIRM_SITE) {
            return Err(Error::RateLimited);
        }
        self.store.set_email_pending(user.id, Some(&email)).await?;
        let t = token(&self.keys, "email-verify", user.id, util::now() + VERIFY_SECS, email.as_bytes(), b"");
        let cfg = self.host.config();
        let body = format!(
            "Someone, hopefully you, asked to use this address for the account {} on {}.\n\n\
             To confirm it, open this link within 24 hours, signed in to that account:\n{}\n\n\
             If that was not you, ignore this message: nothing changes.\n",
            user.username,
            cfg.host(),
            link(&cfg.base_url, "/verify-email", &t)
        );
        self.send_later(email, "Confirm your email address", body);
        self.audit_after(ctx, Some(user.id), Some(user.id), "email_pending", "").await;
        Ok(())
    }

    /// The address goes, pending one included; a confirmed one is told.
    pub async fn email_remove(&self, ctx: &Ctx, user: &User) -> Result<(), Error> {
        self.store.clear_email(user.id).await?;
        if let Some(old) = user.email.clone() {
            self.address_notice(user, old, "removed");
        }
        self.audit_after(ctx, Some(user.id), Some(user.id), "email_remove", "").await;
        Ok(())
    }

    /// The link's POST, from a signed-in session of the account the link is
    /// for: whoever else reads the mail, the owner of a mistyped domain say,
    /// cannot make the address the account's. The address it replaces is told.
    pub async fn email_confirm(&self, ctx: &Ctx, user: &User, t: &str) -> Result<(), Error> {
        let p = parse(t)?;
        if !holds(&self.keys, "email-verify", &p, b"") {
            return Err(EXPIRED);
        }
        if p.user != user.id {
            return Err(OTHER_ACCOUNT);
        }
        let email = String::from_utf8(p.extra).map_err(|_| EXPIRED)?;
        match self.store.confirm_email(user.id, &email, util::now()).await? {
            EmailConfirm::Done => {}
            EmailConfirm::Stale => return Err(EXPIRED),
            EmailConfirm::Taken => return Err(Error::Invalid("That address belongs to another account.")),
        }
        if let Some(old) = user.email.clone().filter(|o| *o != email) {
            self.address_notice(user, old, "changed to another one");
        }
        self.record_after(ctx, Some(user.id), None, "email_verified", "").await;
        Ok(())
    }

    /// Always `Ok` unless refused outright: whether the name exists, and
    /// whether it has a confirmed address, is nobody's business. The answer
    /// comes right after the lookup, whatever it found; the hash, the link,
    /// the audit row and the mail are a task's of their own.
    pub async fn password_forgot(&self, ctx: &Ctx, who: &str) -> Result<(), Error> {
        if ctx.cross_site() {
            return Err(Error::CrossSite);
        }
        self.per_ip(ctx, "acct-forgot", WINDOW, 5)?;
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
        let (Some(email), Some(m)) = (user.email.clone(), self.mailer.clone()) else { return Ok(()) };
        if !self.mail_allowed(user.id, &email, RESET_SITE) {
            return Ok(());
        }
        let (store, keys, ip, cfg) = (self.store.clone(), self.keys.clone(), self.shaped_ip(ctx.ip), self.host.config());
        tokio::spawn(async move {
            let hash = match store.password_hash_of(user.id).await {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(target: "accounts", error = %e, "reset mail not sent");
                    return;
                }
            };
            let t = token(&keys, "reset", user.id, util::now() + RESET_SECS, b"", &reset_bound(hash.as_deref(), Some(&email)));
            let body = format!(
                "Someone asked to reset the password of the account {} on {}.\n\n\
                 To choose a new password, open this link within an hour:\n{}\n\n\
                 If that was not you, ignore this message: your password stays as it is.\n",
                user.username,
                cfg.host(),
                link(&cfg.base_url, "/reset", &t)
            );
            if let Err(e) = store.audit(Some(user.id), None, "reset_mail", "", &ip).await {
                audit_lost("reset_mail", &e);
            }
            deliver(&m, &email, "Reset your password", body).await;
        });
        Ok(())
    }

    /// Sets a new password from a reset link: nothing else. No sign-in, and a
    /// second factor stays. Every session and remembered browser goes.
    pub async fn password_reset(&self, ctx: &Ctx, t: &str, new: &str) -> Result<(), Error> {
        let p = parse(t)?;
        let u = self.store.user_by_id(p.user).await?.filter(|u| u.status == UserStatus::Active).ok_or(EXPIRED)?;
        let old = self.store.password_hash_of(u.id).await?;
        if !holds(&self.keys, "reset", &p, &reset_bound(old.as_deref(), u.email.as_deref())) {
            return Err(EXPIRED);
        }
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
        let site = self.host.config().host().to_string();
        let body = format!(
            "The password of your account {} on {site} was just changed{how}. Every other session \
             was signed out.\n\nIf that was not you, reset it again and check your account's security page.\n",
            user.username
        );
        self.send_later(email, "Your password was changed", body);
    }

    /// The notice to an address the account stops using, so a recovery
    /// address that moved does not go unseen. Not capped, like
    /// `password_notice`: each one follows a change of a confirmed address,
    /// and `email_set`'s caps bound those.
    fn address_notice(&self, user: &User, old: String, what: &str) {
        let site = self.host.config().host().to_string();
        let body = format!(
            "The email address of your account {} on {site} was just {what}. Mail for the account, \
             password resets included, no longer comes here.\n\nIf that was not you, sign in and check \
             your account's security page, or ask the site's admin for help.\n",
            user.username
        );
        self.send_later(old, "Your account's email address changed", body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_mailbox_however_it_is_spelled() {
        assert_eq!(mailbox("Dee+news@Example.org"), "dee@example.org");
        assert_eq!(mailbox("d.ee+a+b@googlemail.com"), "dee@gmail.com");
        assert_eq!(mailbox("D.E.E@gmail.com"), "dee@gmail.com");
        assert_eq!(mailbox("d.ee@example.org"), "d.ee@example.org", "dots count everywhere else");
    }
}
