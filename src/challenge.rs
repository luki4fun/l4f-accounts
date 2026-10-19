//! Stateless single-use challenges for passkey, SSH and device-key logins.
//!
//! No table: the token carries its own nonce, expiry, purpose, user and browser
//! binding under an HMAC, and single use comes from burning the nonce in the
//! rate limiter. A restart forgets the burns, so a captured response (token,
//! signature and the browser cookie) could be replayed until the token's
//! expiry; keep ttls short. Burns are per process, too: every other instance
//! would accept that response once more (see `limit`).
//!
//! WebAuthn and the device key sign [`challenge_bytes`] of the token, one
//! fixed 32-byte value; SSH signs the token text itself (SSHSIG hashes it
//! under the namespace).

use sha2::{Digest, Sha256};

use crate::{
    keys::Keys,
    limit::RateLimiter,
    util::{b64u, ct_eq_bytes, now, random, split_token},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Login,
    Enroll,
    Mfa,
    StepUp,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Login => "login",
            Purpose::Enroll => "enroll",
            Purpose::Mfa => "mfa",
            Purpose::StepUp => "step-up",
        }
    }

    fn byte(self) -> u8 {
        match self {
            Purpose::Login => 1,
            Purpose::Enroll => 2,
            Purpose::Mfa => 3,
            Purpose::StepUp => 4,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChallengeError {
    Malformed,
    Forged,
    Expired,
    WrongPurpose,
    WrongUser,
    WrongBrowser,
}

/// Account ids are 16 bytes.
pub const MAX_USER: usize = 16;
/// The browser cookie must be at least this random; a shorter one cannot bind.
pub const MIN_BROWSER_NONCE: usize = 16;

/// Longest ttl `issue` grants. Every burn lasts this long plus `SKEW`, so a
/// burn always outlives its token whatever ttl the caller picked.
pub const MAX_TTL: i64 = 600;
/// Slack for the wall clock stepping back while a burn is live.
const SKEW: i64 = 60;

const MAC_PURPOSE: &str = "challenge";
const FIXED: usize = 16 + 8 + 1 + 1 + 16;
/// Length of the longest real token (unpadded payload, dot, 43-char tag);
/// longer is junk.
const MAX_TOKEN: usize = ((FIXED + MAX_USER) * 4).div_ceil(3) + 1 + 43;

/// Only a hash goes into the visible token, so a pasted or logged challenge
/// does not leak the HttpOnly cookie value.
fn browser_hash(browser_nonce: &[u8]) -> [u8; 16] {
    Sha256::digest(browser_nonce)[..16].try_into().expect("16 of 32 bytes")
}

/// `b64u(nonce(16) | exp(i64 BE) | purpose | user_len | user | SHA-256(browser_nonce)[..16])`
/// `+ "." + Keys::sign("challenge", payload)`.
///
/// `browser_nonce` is a random value (at least [`MIN_BROWSER_NONCE`] bytes) the
/// caller also sets in an HttpOnly cookie, so a challenge minted for one browser
/// cannot be completed in another. An empty `user` is the same as none.
///
/// `ttl_secs` is clamped to `1..=MAX_TTL`.
///
/// # Panics
/// If `user` is longer than [`MAX_USER`]: callers pass an account id, never input.
pub fn issue(keys: &Keys, purpose: Purpose, user: Option<&[u8]>, browser_nonce: &[u8], ttl_secs: i64) -> String {
    let user = user.unwrap_or_default();
    assert!(user.len() <= MAX_USER, "challenge user must be an account id (at most {MAX_USER} bytes)");
    let mut p = Vec::with_capacity(FIXED + user.len());
    p.extend_from_slice(&random::<16>());
    p.extend_from_slice(&(now() + ttl_secs.clamp(1, MAX_TTL)).to_be_bytes());
    p.push(purpose.byte());
    p.push(user.len() as u8);
    p.extend_from_slice(user);
    p.extend_from_slice(&browser_hash(browser_nonce));
    format!("{}.{}", b64u(&p), keys.sign(MAC_PURPOSE, &p))
}

/// The token's nonce, for [`burn`], once the MAC, expiry, purpose, user and
/// browser all match. Old-master tokens still verify during a rotation.
pub fn check(
    keys: &Keys,
    token: &str,
    purpose: Purpose,
    user: Option<&[u8]>,
    browser_nonce: &[u8],
    now: i64,
) -> Result<[u8; 16], ChallengeError> {
    use ChallengeError::*;
    // One spelling per token, or a caller keyed on the token text or
    // `challenge_bytes` would see the same nonce as new.
    let (p, tag) = split_token(token, MAX_TOKEN).ok_or(Malformed)?;
    if p.len() < FIXED || p[25] as usize > MAX_USER || p.len() != FIXED + p[25] as usize {
        return Err(Malformed);
    }
    if !keys.verify(MAC_PURPOSE, &p, tag) {
        return Err(Forged);
    }
    let nonce: [u8; 16] = p[..16].try_into().expect("length checked");
    let exp = i64::from_be_bytes(p[16..24].try_into().expect("length checked"));
    let user_len = p[25] as usize;
    let (token_user, bh) = p[26..].split_at(user_len);
    // A token from further ahead than `issue` ever mints would outlive its burn.
    if now >= exp || exp - now > MAX_TTL + SKEW {
        return Err(Expired);
    }
    if p[24] != purpose.byte() {
        return Err(WrongPurpose);
    }
    if !ct_eq_bytes(token_user, user.unwrap_or_default()) {
        return Err(WrongUser);
    }
    if browser_nonce.len() < MIN_BROWSER_NONCE || !ct_eq_bytes(bh, &browser_hash(browser_nonce)) {
        return Err(WrongBrowser);
    }
    Ok(nonce)
}

/// Spend a checked nonce. `false` means it was already used (or the
/// limiter's ceiling of live challenge burns is reached, which fails closed;
/// other single-use keys, such as sign-up proofs-of-work, count against
/// ceilings of their own). Call it only once the signature or assertion
/// verified: a burn before that lets anyone who can fetch a token fill the
/// set.
pub fn burn(limiter: &RateLimiter, nonce: &[u8; 16]) -> bool {
    let ttl = std::time::Duration::from_secs((MAX_TTL + SKEW) as u64);
    limiter.spend(&format!("acct-ch:{}", hex::encode(nonce)), ttl)
}

/// SHA-256 of the token text: the WebAuthn `challenge` and the device-key
/// challenge. An SSH signature is over the token text, not this.
pub fn challenge_bytes(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::b64u_dec;

    const UID: &[u8] = &[0x42; 16];
    const BROWSER: &[u8] = &[0x07; 32];

    fn k() -> Keys {
        Keys::new(&[1u8; 32], None).unwrap()
    }

    #[test]
    fn round_trip_returns_the_nonce() {
        let k = k();
        for user in [Some(UID), None, Some(&b"short"[..])] {
            let t = issue(&k, Purpose::Login, user, BROWSER, 300);
            let n = check(&k, &t, Purpose::Login, user, BROWSER, now()).unwrap();
            let payload = b64u_dec(t.split_once('.').unwrap().0).unwrap();
            assert_eq!(n[..], payload[..16], "the nonce is the payload's first 16 bytes");
            assert!(!t.contains(['+', '/', '=']), "URL- and form-safe: {t}");
            assert!(t.len() <= MAX_TOKEN);
        }
        assert_eq!(issue(&k, Purpose::Login, Some(UID), BROWSER, 300).len(), MAX_TOKEN, "the cap is the longest real token");
        let a = issue(&k, Purpose::Mfa, None, BROWSER, 300);
        let b = issue(&k, Purpose::Mfa, None, BROWSER, 300);
        assert_ne!(a, b, "every token has a fresh nonce");
    }

    #[test]
    fn every_purpose_round_trips_and_is_distinct() {
        let k = k();
        let all = [Purpose::Login, Purpose::Enroll, Purpose::Mfa, Purpose::StepUp];
        for p in all {
            let t = issue(&k, p, Some(UID), BROWSER, 60);
            for q in all {
                let r = check(&k, &t, q, Some(UID), BROWSER, now());
                if p == q {
                    assert!(r.is_ok(), "{p:?}");
                } else {
                    assert_eq!(r, Err(ChallengeError::WrongPurpose), "{p:?} token used as {q:?}");
                }
            }
        }
        let names: std::collections::HashSet<_> = all.iter().map(|p| p.as_str()).collect();
        assert_eq!(names.len(), all.len());
    }

    #[test]
    fn expired_is_refused() {
        let k = k();
        let t = issue(&k, Purpose::Login, None, BROWSER, 60);
        assert!(check(&k, &t, Purpose::Login, None, BROWSER, now() + 30).is_ok());
        assert_eq!(check(&k, &t, Purpose::Login, None, BROWSER, now() + 61), Err(ChallengeError::Expired));
        let dead = issue(&k, Purpose::Login, None, BROWSER, -1);
        assert_eq!(check(&k, &dead, Purpose::Login, None, BROWSER, now() + 1), Err(ChallengeError::Expired), "clamped to 1s");
        let huge = issue(&k, Purpose::Login, None, BROWSER, i64::MAX);
        assert!(check(&k, &huge, Purpose::Login, None, BROWSER, now()).is_ok());
        assert_eq!(check(&k, &huge, Purpose::Login, None, BROWSER, now() + MAX_TTL), Err(ChallengeError::Expired), "clamped to MAX_TTL");
    }

    /// A token valid longer than its burn could be replayed once the burn lapsed.
    #[test]
    fn a_token_that_outlives_its_burn_is_refused() {
        let k = k();
        let mut p = vec![0u8; 16];
        p.extend_from_slice(&(now() + MAX_TTL + SKEW + 10).to_be_bytes());
        p.extend_from_slice(&[Purpose::Login.byte(), 0]);
        p.extend_from_slice(&browser_hash(BROWSER));
        let t = format!("{}.{}", b64u(&p), k.sign(MAC_PURPOSE, &p));
        assert_eq!(check(&k, &t, Purpose::Login, None, BROWSER, now()), Err(ChallengeError::Expired));
    }

    #[test]
    fn wrong_user_is_refused() {
        let k = k();
        let t = issue(&k, Purpose::Enroll, Some(UID), BROWSER, 60);
        let other = [0x43u8; 16];
        assert_eq!(check(&k, &t, Purpose::Enroll, Some(&other), BROWSER, now()), Err(ChallengeError::WrongUser));
        assert_eq!(check(&k, &t, Purpose::Enroll, None, BROWSER, now()), Err(ChallengeError::WrongUser));
        assert_eq!(check(&k, &t, Purpose::Enroll, Some(&UID[..15]), BROWSER, now()), Err(ChallengeError::WrongUser));
        assert_eq!(check(&k, &t, Purpose::Enroll, Some(&[0x42; 40]), BROWSER, now()), Err(ChallengeError::WrongUser), "an oversized user does not panic");
        let anon = issue(&k, Purpose::Login, None, BROWSER, 60);
        assert_eq!(check(&k, &anon, Purpose::Login, Some(UID), BROWSER, now()), Err(ChallengeError::WrongUser));
        assert!(check(&k, &anon, Purpose::Login, Some(&[]), BROWSER, now()).is_ok(), "an empty user is none");
    }

    #[test]
    #[should_panic(expected = "account id")]
    fn issuing_for_an_oversized_user_panics() {
        issue(&k(), Purpose::Login, Some(&[0; 17]), BROWSER, 60);
    }

    #[test]
    fn wrong_browser_nonce_is_refused() {
        let k = k();
        let t = issue(&k, Purpose::Login, None, BROWSER, 60);
        assert_eq!(check(&k, &t, Purpose::Login, None, &[0x08; 32], now()), Err(ChallengeError::WrongBrowser));
        assert_eq!(check(&k, &t, Purpose::Login, None, b"", now()), Err(ChallengeError::WrongBrowser), "missing cookie");
        // A caller that forgot the cookie on both sides must not get a working binding.
        let weak = issue(&k, Purpose::Login, None, b"", 60);
        assert_eq!(check(&k, &weak, Purpose::Login, None, b"", now()), Err(ChallengeError::WrongBrowser));
        let short = issue(&k, Purpose::Login, None, &BROWSER[..15], 60);
        assert_eq!(check(&k, &short, Purpose::Login, None, &BROWSER[..15], now()), Err(ChallengeError::WrongBrowser));
    }

    #[test]
    fn tampered_tokens_are_refused() {
        let k = k();
        let t = issue(&k, Purpose::Mfa, Some(UID), BROWSER, 60);
        let (p64, tag) = t.split_once('.').unwrap();
        let payload = b64u_dec(p64).unwrap();
        for i in 0..payload.len() {
            let mut bad = payload.clone();
            bad[i] ^= 0x01;
            let r = check(&k, &format!("{}.{tag}", b64u(&bad)), Purpose::Mfa, Some(UID), BROWSER, now());
            // Byte 25 is the user length: changing it breaks the layout before the MAC.
            let want = if i == 25 { ChallengeError::Malformed } else { ChallengeError::Forged };
            assert_eq!(r, Err(want), "flipping payload byte {i}");
        }
        // Push the expiry out and keep the old tag.
        let mut later = payload.clone();
        later[16..24].copy_from_slice(&i64::MAX.to_be_bytes());
        assert_eq!(check(&k, &format!("{}.{tag}", b64u(&later)), Purpose::Mfa, Some(UID), BROWSER, now()), Err(ChallengeError::Forged));
        let mut tag_bad = tag.as_bytes().to_vec();
        tag_bad[0] = if tag_bad[0] == b'A' { b'B' } else { b'A' };
        let tag_bad = String::from_utf8(tag_bad).unwrap();
        assert_eq!(check(&k, &format!("{p64}.{tag_bad}"), Purpose::Mfa, Some(UID), BROWSER, now()), Err(ChallengeError::Forged));
        let foreign = issue(&Keys::new(&[2u8; 32], None).unwrap(), Purpose::Mfa, Some(UID), BROWSER, 60);
        assert_eq!(check(&k, &foreign, Purpose::Mfa, Some(UID), BROWSER, now()), Err(ChallengeError::Forged), "minted under another key");
        // A padded tag: over the cap on a full-length token, a wrong spelling on a shorter one.
        assert_eq!(check(&k, &format!("{p64}.{tag}="), Purpose::Mfa, Some(UID), BROWSER, now()), Err(ChallengeError::Malformed));
        let anon = issue(&k, Purpose::Mfa, None, BROWSER, 60);
        assert_eq!(check(&k, &format!("{anon}="), Purpose::Mfa, None, BROWSER, now()), Err(ChallengeError::Forged), "padded tag");
        assert_eq!(check(&k, &format!("{p64}.{}", &tag[..20]), Purpose::Mfa, Some(UID), BROWSER, now()), Err(ChallengeError::Forged));
    }

    #[test]
    fn malformed_tokens_are_refused() {
        let k = k();
        let t = issue(&k, Purpose::Login, None, BROWSER, 60);
        let (p64, tag) = t.split_once('.').unwrap();
        let payload = b64u_dec(p64).unwrap();
        let cases = [
            String::new(),
            ".".into(),
            p64.into(),
            format!("{p64}{tag}"),
            format!("!!{p64}.{tag}"),
            format!("{}.{tag}", b64u(&payload[..payload.len() - 1])),
            format!("{}.{tag}", b64u(&[payload.clone(), vec![0]].concat())),
            format!("{}.{tag}", b64u(&[0u8; 41])),
            format!("{p64}.{tag}{}", "A".repeat(MAX_TOKEN)),
        ];
        for c in cases {
            assert_eq!(check(&k, &c, Purpose::Login, None, BROWSER, now()), Err(ChallengeError::Malformed), "{c:?}");
        }
        // A user length above 16: correctly MAC'd it is over the cap; with a
        // short tag it fits, and the layout check refuses it before the MAC.
        let mut long = vec![0u8; 16];
        long.extend_from_slice(&i64::MAX.to_be_bytes());
        long.extend_from_slice(&[1, 17]);
        long.extend_from_slice(&[0u8; 17 + 16]);
        let tag = k.sign(MAC_PURPOSE, &long);
        let forged = format!("{}.{tag}", b64u(&long));
        assert_eq!(check(&k, &forged, Purpose::Login, None, BROWSER, now()), Err(ChallengeError::Malformed), "over the cap");
        let fits = format!("{}.{}", b64u(&long), &tag[..40]);
        assert!(fits.len() <= MAX_TOKEN);
        assert_eq!(check(&k, &fits, Purpose::Login, None, BROWSER, now()), Err(ChallengeError::Malformed), "user length 17");
    }

    /// The same payload must not pass under a second spelling: each one would
    /// have its own `challenge_bytes` for the same nonce. A 16-byte user's token
    /// is already at [`MAX_TOKEN`], so padding it trips the length cap; the
    /// shorter ones reach the spelling check.
    #[test]
    fn only_the_canonical_payload_spelling_is_accepted() {
        let k = k();
        for user in [Some(UID), None, Some(&b"short"[..])] {
            let t = issue(&k, Purpose::Login, user, BROWSER, 60);
            let (p64, tag) = t.split_once('.').unwrap();
            for pad in ["=", "==", "==="] {
                let padded = format!("{p64}{pad}.{tag}");
                assert_eq!(check(&k, &padded, Purpose::Login, user, BROWSER, now()), Err(ChallengeError::Malformed), "{padded}");
            }
        }
        // A 58-byte payload leaves 4 unused bits in its last character; a lax
        // decoder would read the same bytes with one set. `b64u_dec` refuses it
        // today, and the spelling check would if it ever stopped.
        let t = issue(&k, Purpose::Login, Some(UID), BROWSER, 60);
        let (p64, tag) = t.split_once('.').unwrap();
        let (head, last) = p64.split_at(p64.len() - 1);
        let alt = match last {
            "A" => "B",
            "Q" => "R",
            "g" => "h",
            "w" => "x",
            other => panic!("unexpected final character {other}"),
        };
        assert_eq!(check(&k, &format!("{head}{alt}.{tag}"), Purpose::Login, Some(UID), BROWSER, now()), Err(ChallengeError::Malformed));
    }

    #[test]
    fn burn_is_single_use() {
        let l = RateLimiter::default();
        let k = k();
        let t = issue(&k, Purpose::Login, None, BROWSER, 120);
        let n = check(&k, &t, Purpose::Login, None, BROWSER, now()).unwrap();
        assert!(burn(&l, &n));
        assert!(!burn(&l, &n), "a burned nonce must not be accepted twice");
        assert!(check(&k, &t, Purpose::Login, None, BROWSER, now()).is_ok(), "check alone is stateless; burn is what spends it");
        assert!(burn(&l, &[9u8; 16]), "other nonces are unaffected");
    }

    #[test]
    fn old_key_still_verifies_after_rotation() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let before = Keys::new(&a, None).unwrap();
        let t = issue(&before, Purpose::StepUp, Some(UID), BROWSER, 60);
        let rotated = Keys::new(&b, Some(&a)).unwrap();
        assert!(check(&rotated, &t, Purpose::StepUp, Some(UID), BROWSER, now()).is_ok());
        let retired = Keys::new(&b, None).unwrap();
        assert_eq!(check(&retired, &t, Purpose::StepUp, Some(UID), BROWSER, now()), Err(ChallengeError::Forged));
        let fresh = issue(&rotated, Purpose::StepUp, Some(UID), BROWSER, 60);
        assert!(check(&retired, &fresh, Purpose::StepUp, Some(UID), BROWSER, now()).is_ok(), "new tokens use the current key");
    }

    #[test]
    fn challenge_bytes_is_sha256_of_the_token() {
        let t = issue(&k(), Purpose::Login, None, BROWSER, 60);
        assert_eq!(challenge_bytes(&t), <[u8; 32]>::from(Sha256::digest(t.as_bytes())));
        assert_eq!(hex::encode(challenge_bytes("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_ne!(challenge_bytes(&t), challenge_bytes(&issue(&k(), Purpose::Login, None, BROWSER, 60)));
    }
}
