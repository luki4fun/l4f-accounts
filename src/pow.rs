//! Self-hosted proof-of-work challenge, ALTCHA v1 wire format.
//!
//! Implemented directly rather than pulling `altcha-lib-rs`: that crate speaks
//! ALTCHA v2 (PBKDF2/scrypt/Argon2id) and drags in chrono, a second hmac major
//! version and base16ct for the same anti-bot outcome. Keeping the v1 wire
//! format means the official widget can be dropped in later without server changes.
//!
//! Server signs a challenge; the browser brute-forces a counter until
//! `SHA256(salt ++ n)` matches; the server re-checks one hash plus the signature.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::util::{self, now_secs};

/// Below this an ALTCHA key can be guessed or was mistyped, and a forged
/// proof-of-work passes: `Accounts` keeps sign-up closed with a shorter one.
pub const MIN_KEY_LEN: usize = 32;
/// Longest ttl `issue` grants. `verify` refuses an expiry further out: only a
/// forged challenge (a weak key) carries one, and its burn would last until it.
pub const MAX_POW_TTL: u64 = 86_400;
/// Slack for the wall clock stepping back while a challenge or its burn is live.
const SKEW: u64 = 60;

#[derive(Debug, Serialize, Clone)]
pub struct Challenge {
    pub algorithm: &'static str,
    pub challenge: String,
    pub maxnumber: u32,
    /// The JS and Go reference libraries disagree on the casing of this field.
    /// Emitting both costs one line and keeps the real widget swappable.
    #[serde(rename = "maxNumber")]
    pub max_number: u32,
    pub salt: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct Payload {
    pub algorithm: String,
    pub challenge: String,
    pub number: u64,
    pub salt: String,
    pub signature: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PowErr {
    Malformed,
    Expired,
    WrongSolution,
    Forged,
}

/// `ttl_secs` is clamped to [`MAX_POW_TTL`].
pub fn issue(key: &[u8], maxnumber: u32, ttl_secs: u64) -> Challenge {
    // The trailing `&` ends the number. Without it, digits can move from the
    // solution into the salt with the hashed string unchanged, and the expiry
    // grows at will (ALTCHA's CVE-2025-68113).
    let salt = format!("{}?expires={}&", hex::encode(util::random::<12>()), now_secs().saturating_add(ttl_secs.min(MAX_POW_TTL)));
    // The modulo bias is below 2^-32.
    let number = u64::from_le_bytes(util::random()) % u64::from(maxnumber.max(1));
    let challenge = hex::encode(Sha256::digest(format!("{salt}{number}").as_bytes()));
    Challenge {
        algorithm: "SHA-256",
        signature: hex::encode(util::mac_raw(key, challenge.as_bytes())),
        challenge,
        maxnumber,
        max_number: maxnumber,
        salt,
    }
}

/// Returns the challenge hex on success. The payload is the solution's JSON,
/// as is or in base64 as the official widget sends it.
///
/// The signature makes a challenge unforgeable but **not single-use** - the
/// caller must burn the returned value (`RateLimiter::spend`), or one solved
/// challenge registers unlimited accounts. [`Gate`] does.
pub fn verify(key: &[u8], payload: &str) -> Result<String, PowErr> {
    verify_until(key, payload).map(|(challenge, _)| challenge)
}

/// `verify`, plus the signed expiry (unix seconds) the burn must outlive.
fn verify_until(key: &[u8], payload: &str) -> Result<(String, u64), PowErr> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let payload = payload.trim();
    let decoded;
    let json = if payload.starts_with('{') {
        payload.as_bytes()
    } else {
        decoded = STANDARD.decode(payload).map_err(|_| PowErr::Malformed)?;
        &decoded[..]
    };
    let p: Payload = serde_json::from_slice(json).map_err(|_| PowErr::Malformed)?;
    if p.algorithm != "SHA-256" {
        return Err(PowErr::Malformed);
    }
    let exp: u64 = p
        .salt
        .split_once("?expires=")
        .and_then(|(_, rest)| rest.strip_suffix('&'))
        .ok_or(PowErr::Malformed)?
        .parse()
        .map_err(|_| PowErr::Malformed)?;
    let now = now_secs();
    if now > exp {
        return Err(PowErr::Expired);
    }
    // Further out than `issue` ever signs: only a forger picks that.
    if exp - now > MAX_POW_TTL + SKEW {
        return Err(PowErr::Malformed);
    }
    // One cheap hash before touching the HMAC.
    if hex::encode(Sha256::digest(format!("{}{}", p.salt, p.number).as_bytes())) != p.challenge {
        return Err(PowErr::WrongSolution);
    }
    let sig = hex::decode(&p.signature).map_err(|_| PowErr::Malformed)?;
    if !util::ct_eq_bytes(&util::mac_raw(key, p.challenge.as_bytes()), &sig) {
        return Err(PowErr::Forged);
    }
    Ok((p.challenge, exp))
}

/// A hidden, signed render timestamp. Catches instantly-submitted and stale
/// forms, and is the no-JS path's main defence alongside the honeypot. It is
/// not single-use: a replay within the accepted age passes, and the caller's
/// rate limits are what stop that.
pub fn stamp(key: &[u8], secs: u64) -> String {
    format!("{secs}.{}", util::mac(key, &secs.to_string()))
}

pub fn stamp_age(key: &[u8], raw: &str) -> Option<u64> {
    let (secs, _) = raw.split_once('.')?;
    let secs: u64 = secs.parse().ok()?;
    if !util::ct_eq(&stamp(key, secs), raw) {
        return None;
    }
    now_secs().checked_sub(secs)
}

// ------------------------------------------------------------- sign-up gate

/// The anti-abuse chain every sign-up form shares (Matrix registration, site
/// accounts, the "choose a username" step after a social login).
///
/// Two halves, because the caller validates its own fields in between and the
/// order matters: cheap junk is refused by [`Gate::precheck`] before it can
/// spend the site-wide attempt cap that [`Gate::caps`] charges. Account counts
/// are only peeked there; [`Permit::commit`] records them once the caller's
/// own checks passed, so a mistyped password never costs someone their sign-up.
///
/// Callers must hold one async lock from `precheck` to `commit`, or parallel
/// posts all pass the same peek before any of them counts.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_attempts_per_ip_hour: usize,
    pub max_attempts_per_hour: usize,
    pub max_accounts_per_hour: usize,
    /// Accounts per address (IPv6: per /64) per day.
    pub max_accounts_per_ip_day: usize,
    pub min_form_seconds: u64,
    pub pow_maxnumber: u32,
    pub pow_ttl_minutes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_attempts_per_ip_hour: 10,
            max_attempts_per_hour: 60,
            max_accounts_per_hour: 10,
            max_accounts_per_ip_day: 2,
            min_form_seconds: 3,
            pow_maxnumber: 60_000,
            pow_ttl_minutes: 60,
        }
    }
}

/// Why a sign-up was turned away: a stable label for the log (fail2ban, metrics)
/// and the sentence shown to the visitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deny {
    pub outcome: &'static str,
    pub message: &'static str,
}

const fn deny(outcome: &'static str, message: &'static str) -> Deny {
    Deny { outcome, message }
}

/// What the visitor sent besides their own fields.
#[derive(Debug, Default, Clone, Copy)]
pub struct Proof<'a> {
    /// The ALTCHA payload. Empty means the browser ran no JavaScript.
    pub altcha: &'a str,
    /// The signed render time from [`stamp`].
    pub ts: &'a str,
    /// The honeypot field. Anything in it is a bot.
    pub honeypot: &'a str,
    /// The request's `Sec-Fetch-Site`, or "".
    pub sec_fetch_site: &'a str,
}

pub struct Gate<'a> {
    pub limiter: &'a crate::limit::RateLimiter,
    pub key: &'a [u8],
    pub limits: &'a Limits,
    /// Limiter key prefix, e.g. `mx` or `acct-reg`. Never contains `:`.
    pub ns: &'a str,
    /// `util::ip_key` of the client.
    pub bucket: &'a str,
}

/// Returned by [`Gate::caps`]; records the account caps when committed. A
/// client that hangs up drops the request's future, so commit where that
/// cannot skip it for an account that gets created: right before the INSERT
/// (a lost race or a database error then counts one too many), or in a
/// spawned task that creates the account, which is why it owns its keys.
#[must_use = "commit() it with the account's creation, or the caps never count it"]
pub struct Permit {
    ns: String,
    bucket: String,
    no_js: bool,
}

const HOUR: std::time::Duration = std::time::Duration::from_secs(3600);
const DAY: std::time::Duration = std::time::Duration::from_secs(86400);

impl<'a> Gate<'a> {
    /// Origin, per-address attempt cap, honeypot, form age, then the proof of
    /// work (burned, so one solution is one sign-up) or, without JavaScript, a
    /// much stricter one-per-day cap that is only peeked here.
    ///
    /// `with_pow` false skips the PoW and the no-JS cap entirely: for a host
    /// form with a human check of its own. The crate's sign-up forms, social
    /// sign-up included, all pass true.
    pub fn precheck(&self, p: Proof<'_>, with_pow: bool) -> Result<bool, Deny> {
        let (ns, b, l) = (self.ns, self.bucket, self.limits);
        // Another site submitting the form through a visitor's browser would get
        // the account created and charged to that visitor. A sibling subdomain
        // counts as another site. Scripts send no Sec-Fetch-Site at all.
        if matches!(p.sec_fetch_site, "cross-site" | "same-site") {
            return Err(deny("cross_site", "Something went wrong. Please try again."));
        }
        if !self.limiter.check(&format!("{ns}:try:{b}"), HOUR, l.max_attempts_per_ip_hour) {
            return Err(deny("rate_limited", "Too many attempts from your connection. Try again later."));
        }
        if !p.honeypot.is_empty() {
            return Err(deny("honeypot", "Something went wrong. Please try again."));
        }
        // Not single-use, so it does not stop a replay within the hour; the caps do.
        match stamp_age(self.key, p.ts) {
            None => return Err(deny("too_fast", "The form expired. Please try again.")),
            Some(age) if age < l.min_form_seconds => {
                return Err(deny("too_fast", "That was quick. Give it a couple of seconds and try again."));
            }
            Some(age) if age > 3600 => return Err(deny("too_fast", "The form expired. Please try again.")),
            Some(_) => {}
        }
        if !with_pow {
            return Ok(false);
        }
        let no_js = p.altcha.is_empty();
        if no_js {
            // Peeked, not spent: a mistyped password must not cost someone their
            // one no-JS sign-up for the day.
            if !self.limiter.peek(&format!("{ns}:nojs:{b}"), DAY, 1) {
                return Err(deny("rate_limited", "Too many attempts from your connection. Try again tomorrow."));
            }
        } else {
            let (challenge, exp) = verify_until(self.key, p.altcha)
                .map_err(|_| deny("bad_pow", "The anti-spam check failed. Please try again."))?;
            // The signature proves the challenge is ours, not that it is unused.
            // Burned until its own signed expiry, not the configured ttl, which
            // a reload may have shortened since it was issued.
            let ttl = std::time::Duration::from_secs(exp.saturating_sub(now_secs()) + SKEW);
            if !self.limiter.spend(&format!("{ns}:pow:{challenge}"), ttl) {
                return Err(deny("bad_pow", "That anti-spam check was already used. Please try again."));
            }
        }
        Ok(no_js)
    }

    /// The site-wide attempt cap and the account caps. Call after the caller's
    /// own validation, including a lookup that the username is free, so junk
    /// and taken names refused there do not spend the global cap.
    ///
    /// The global caps fail closed: about `max_attempts_per_hour /
    /// max_attempts_per_ip_hour` sources can shut sign-up for everyone for an
    /// hour, again and again. The host needs a switch to close sign-up or move
    /// it behind invites while that happens.
    pub fn caps(&self, no_js: bool) -> Result<Permit, Deny> {
        let (ns, b, l) = (self.ns, self.bucket, self.limits);
        // Per source first: a source that already has its accounts must not
        // spend the site-wide budget.
        if !self.limiter.peek(&format!("{ns}:ok:{b}"), DAY, l.max_accounts_per_ip_day) {
            return Err(deny("rate_limited", "You have already created an account today."));
        }
        if !self.limiter.check(&format!("{ns}:try:global"), HOUR, l.max_attempts_per_hour) {
            return Err(deny("global_cap", "Too many attempts right now. Try again in an hour."));
        }
        if !self.limiter.peek(&format!("{ns}:ok:global"), HOUR, l.max_accounts_per_hour) {
            return Err(deny("global_cap", "Too many new accounts right now. Try again in an hour."));
        }
        Ok(Permit { ns: ns.to_string(), bucket: b.to_string(), no_js })
    }
}

impl Permit {
    pub fn commit(self, limiter: &crate::limit::RateLimiter) {
        limiter.record(&format!("{}:ok:{}", self.ns, self.bucket), DAY);
        limiter.record(&format!("{}:ok:global", self.ns), HOUR);
        if self.no_js {
            limiter.record(&format!("{}:nojs:{}", self.ns, self.bucket), DAY);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brute-force the challenge the way the browser does.
    fn solve(c: &Challenge) -> String {
        for n in 0..=c.maxnumber as u64 {
            if hex::encode(Sha256::digest(format!("{}{}", c.salt, n).as_bytes())) == c.challenge {
                return serde_json::json!({
                    "algorithm": c.algorithm, "challenge": c.challenge,
                    "number": n, "salt": c.salt, "signature": c.signature
                })
                .to_string();
            }
        }
        panic!("unsolvable challenge");
    }

    #[test]
    fn accepts_a_correct_solution() {
        let k = b"powkey";
        let c = issue(k, 500, 600);
        assert_eq!(verify(k, &solve(&c)), Ok(c.challenge.clone()));
    }

    #[test]
    fn rejects_wrong_number_forged_signature_and_expiry() {
        let k = b"powkey";
        let c = issue(k, 500, 600);
        let good: serde_json::Value = serde_json::from_str(&solve(&c)).unwrap();

        let mut bad = good.clone();
        bad["number"] = serde_json::json!(good["number"].as_u64().unwrap() + 1);
        assert_eq!(verify(k, &bad.to_string()), Err(PowErr::WrongSolution));

        assert_eq!(verify(b"other-key", &good.to_string()), Err(PowErr::Forged));

        let expired = issue(k, 500, 0);
        let mut p: serde_json::Value = serde_json::from_str(&solve(&expired)).unwrap();
        p["salt"] = serde_json::json!(format!("{}?expires=1&", hex::encode([0u8; 12])));
        assert!(matches!(
            verify(k, &p.to_string()),
            Err(PowErr::Expired) | Err(PowErr::WrongSolution)
        ));
    }

    /// Moving leading digits of the solution into the salt keeps the hashed
    /// string, and so the signature, intact while pushing the expiry out.
    #[test]
    fn rejects_digits_spliced_into_the_salt() {
        let k = b"powkey";
        let c = issue(k, 500, 600);
        let mut p: serde_json::Value = serde_json::from_str(&solve(&c)).unwrap();
        let n = p["number"].as_u64().unwrap().to_string();
        if n.len() < 2 {
            return; // a one-digit solution has nothing to move
        }
        p["salt"] = serde_json::json!(format!("{}{}", c.salt, &n[..1]));
        p["number"] = serde_json::json!(n[1..].parse::<u64>().unwrap());
        assert_eq!(verify(k, &p.to_string()), Err(PowErr::Malformed));
    }

    /// The official widget posts base64 of the JSON (GATES-7).
    #[test]
    fn accepts_the_widgets_base64_payload() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let k = b"powkey";
        let c = issue(k, 500, 600);
        assert_eq!(verify(k, &STANDARD.encode(solve(&c))), Ok(c.challenge.clone()));
        assert_eq!(verify(k, &format!(" {}\n", solve(&c))), Ok(c.challenge), "raw JSON too");
        assert_eq!(verify(k, "not base64!"), Err(PowErr::Malformed));
        assert_eq!(verify(k, &STANDARD.encode("[1]")), Err(PowErr::Malformed));
    }

    /// A challenge signed with the key itself, for an expiry `issue` never
    /// grants: what a weak key lets anyone forge (GATES-4).
    fn signed(k: &[u8], exp: u64) -> String {
        use hmac::{Hmac, Mac};
        let salt = format!("00?expires={exp}&");
        let challenge = hex::encode(Sha256::digest(format!("{salt}0").as_bytes()));
        let mut m = Hmac::<Sha256>::new_from_slice(k).unwrap();
        m.update(challenge.as_bytes());
        let signature = hex::encode(m.finalize().into_bytes());
        serde_json::json!({ "algorithm": "SHA-256", "challenge": challenge, "number": 0, "salt": salt, "signature": signature })
            .to_string()
    }

    #[test]
    fn the_expiry_is_bounded() {
        let k = b"powkey";
        let c = issue(k, 10, u64::MAX);
        let exp: u64 = c.salt.split_once("?expires=").unwrap().1.trim_end_matches('&').parse().unwrap();
        assert!(exp <= now_secs() + MAX_POW_TTL, "issue clamps the ttl");
        assert!(verify(k, &solve(&c)).is_ok());
        assert!(verify(k, &signed(k, now_secs() + MAX_POW_TTL)).is_ok());
        assert_eq!(verify(k, &signed(k, now_secs() + MAX_POW_TTL + SKEW + 5)), Err(PowErr::Malformed));
        assert_eq!(verify(k, &signed(k, u64::MAX)), Err(PowErr::Malformed), "would have panicked the limiter");
    }

    #[test]
    fn stamp_rejects_backdating() {
        let k = b"powkey";
        let s = stamp(k, now_secs() - 10);
        assert!(stamp_age(k, &s).unwrap() >= 10);
        assert_eq!(stamp_age(k, "9999.deadbeef"), None, "unsigned stamp must be refused");
    }

    /// A form rendered before an upgrade carries a stamp the old code made:
    /// HMAC-SHA256 over the decimal seconds, its first 16 bytes in hex.
    #[test]
    fn stamp_spelling_is_fixed() {
        assert_eq!(stamp(b"powkey", 1_700_000_000), "1700000000.b067c047a0c7ecd540d76793c255f999");
    }

    fn gate<'a>(l: &'a crate::limit::RateLimiter, lim: &'a Limits) -> Gate<'a> {
        Gate { limiter: l, key: b"powkey", limits: lim, ns: "t", bucket: "203.0.113.9" }
    }

    #[test]
    fn gate_accepts_a_solved_form_once() {
        let l = crate::limit::RateLimiter::default();
        let lim = Limits { min_form_seconds: 0, ..Limits::default() };
        let g = gate(&l, &lim);
        let ts = stamp(b"powkey", now_secs() - 5);
        let pay = solve(&issue(b"powkey", 500, 600));
        let p = Proof { altcha: &pay, ts: &ts, ..Proof::default() };
        let no_js = g.precheck(p, true).unwrap();
        assert!(!no_js);
        g.caps(no_js).unwrap().commit(&l);
        assert_eq!(g.precheck(p, true).unwrap_err().outcome, "bad_pow", "a solution is single-use");
    }

    #[test]
    fn gate_refuses_cross_site_honeypot_and_fresh_forms() {
        let l = crate::limit::RateLimiter::default();
        let lim = Limits::default();
        let g = gate(&l, &lim);
        let ts = stamp(b"powkey", now_secs());
        let base = Proof { ts: &ts, ..Proof::default() };
        assert_eq!(g.precheck(Proof { sec_fetch_site: "same-site", ..base }, true).unwrap_err().outcome, "cross_site");
        assert_eq!(g.precheck(Proof { honeypot: "x", ..base }, true).unwrap_err().outcome, "honeypot");
        assert_eq!(g.precheck(base, true).unwrap_err().outcome, "too_fast", "rendered 0s ago");
        assert_eq!(g.precheck(Proof { ts: "1.bad", ..base }, true).unwrap_err().outcome, "too_fast");
    }

    #[test]
    fn account_caps_count_only_committed_accounts() {
        let l = crate::limit::RateLimiter::default();
        let lim = Limits { min_form_seconds: 0, max_accounts_per_ip_day: 1, ..Limits::default() };
        let g = gate(&l, &lim);
        let ts = stamp(b"powkey", now_secs() - 5);
        let p = Proof { ts: &ts, ..Proof::default() };
        // No JS: the per-day no-JS slot is peeked, not spent, until commit.
        assert!(g.precheck(p, true).unwrap());
        let _abandoned = g.caps(true).unwrap();
        assert!(g.precheck(p, true).unwrap(), "an uncommitted attempt spent nothing");
        g.caps(true).unwrap().commit(&l);
        assert_eq!(g.precheck(p, true).unwrap_err().outcome, "rate_limited", "no-JS slot now spent");
        assert_eq!(g.caps(false).err().unwrap().outcome, "rate_limited", "per-address account cap reached");
    }

    #[test]
    fn social_signup_skips_only_the_pow() {
        let l = crate::limit::RateLimiter::default();
        let lim = Limits { min_form_seconds: 0, ..Limits::default() };
        let g = gate(&l, &lim);
        let ts = stamp(b"powkey", now_secs() - 5);
        assert!(!g.precheck(Proof { ts: &ts, ..Proof::default() }, false).unwrap());
        assert_eq!(g.precheck(Proof { ts: &ts, honeypot: "x", ..Proof::default() }, false).unwrap_err().outcome, "honeypot");
    }
}
