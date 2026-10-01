//! Self-hosted proof-of-work challenge, ALTCHA v1 wire format.
//!
//! Implemented directly rather than pulling `altcha-lib-rs`: that crate speaks
//! ALTCHA v2 (PBKDF2/scrypt/Argon2id) and drags in chrono, a second hmac major
//! version and base16ct for the same anti-bot outcome. Keeping the v1 wire
//! format means the official widget can be dropped in later without server changes.
//!
//! Server signs a challenge; the browser brute-forces a counter until
//! `SHA256(salt ++ n)` matches; the server re-checks one hash plus the signature.

use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::util::now_secs;

type H = Hmac<Sha256>;

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

pub fn issue(key: &[u8], maxnumber: u32, ttl_secs: u64) -> Challenge {
    let mut raw = [0u8; 12];
    rand::rng().fill_bytes(&mut raw);
    // The trailing `&` ends the number. Without it, digits can move from the
    // solution into the salt with the hashed string unchanged, and the expiry
    // grows at will (ALTCHA's CVE-2025-68113).
    let salt = format!("{}?expires={}&", hex::encode(raw), now_secs() + ttl_secs);
    let number = rand::rng().random_range(0..maxnumber.max(1)) as u64;
    let challenge = hex::encode(Sha256::digest(format!("{salt}{number}").as_bytes()));
    let mut m = <H>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(challenge.as_bytes());
    Challenge {
        algorithm: "SHA-256",
        signature: hex::encode(m.finalize().into_bytes()),
        challenge,
        maxnumber,
        max_number: maxnumber,
        salt,
    }
}

/// Returns the challenge hex on success.
///
/// The signature makes a challenge unforgeable but **not single-use** - the
/// caller must burn the returned value through the rate limiter, or one solved
/// challenge registers unlimited accounts.
pub fn verify(key: &[u8], payload_json: &str) -> Result<String, PowErr> {
    let p: Payload = serde_json::from_str(payload_json).map_err(|_| PowErr::Malformed)?;
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
    if now_secs() > exp {
        return Err(PowErr::Expired);
    }
    // One cheap hash before touching the HMAC.
    if hex::encode(Sha256::digest(format!("{}{}", p.salt, p.number).as_bytes())) != p.challenge {
        return Err(PowErr::WrongSolution);
    }
    let mut m = <H>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(p.challenge.as_bytes());
    m.verify_slice(&hex::decode(&p.signature).map_err(|_| PowErr::Malformed)?)
        .map_err(|_| PowErr::Forged)?; // constant-time, free with hmac
    Ok(p.challenge)
}

/// A hidden, signed render timestamp. Catches instantly-submitted and stale
/// forms, and is the no-JS path's main defence alongside the honeypot. It is
/// not single-use: a replay within the accepted age passes, and the caller's
/// rate limits are what stop that.
pub fn stamp(key: &[u8], secs: u64) -> String {
    let mut m = <H>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(secs.to_string().as_bytes());
    format!("{secs}.{}", hex::encode(&m.finalize().into_bytes()[..16]))
}

pub fn stamp_age(key: &[u8], raw: &str) -> Option<u64> {
    let (secs, _) = raw.split_once('.')?;
    let secs: u64 = secs.parse().ok()?;
    if !crate::util::ct_eq(&stamp(key, secs), raw) {
        return None;
    }
    now_secs().checked_sub(secs)
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

    #[test]
    fn stamp_rejects_backdating() {
        let k = b"powkey";
        let s = stamp(k, now_secs() - 10);
        assert!(stamp_age(k, &s).unwrap() >= 10);
        assert_eq!(stamp_age(k, "9999.deadbeef"), None, "unsigned stamp must be refused");
    }
}
