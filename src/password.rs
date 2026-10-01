//! Password policy, Argon2id hashing and verification.
//!
//! New hashes are always Argon2id with the `argon2` crate defaults (19 MiB,
//! t=2, p=1), the OWASP baseline. With `legacy-bcrypt`, the YOURLS-era admin
//! bcrypt hash still verifies once so the caller can rehash it on that login.
//!
//! Hashing is blocking CPU work (~20-50 ms): callers run it on a blocking thread.

use argon2::password_hash::{Error as PhcError, phc::Salt};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

pub const MIN_LEN_DEFAULT: usize = 10;
/// Long enough for any passphrase or manager output, short enough that one
/// request cannot make the KDF chew on megabytes.
pub const MAX_LEN: usize = 512;

/// Ceilings for a stored hash's cost parameters. Stored hashes are ours, but a
/// corrupted or hand-edited row must not make one login allocate gigabytes or
/// spin for minutes; nothing this module writes comes near them.
const MAX_M_COST: u32 = 256 * 1024; // KiB
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 16;
#[cfg(feature = "legacy-bcrypt")]
const MAX_BCRYPT_COST: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub ok: bool,
    /// Only ever true together with `ok`: rehashing needs the plaintext, which
    /// the caller holds only right after a successful verify.
    pub needs_rehash: bool,
}

const FAILED: Verified = Verified { ok: false, needs_rehash: false };

/// Lengths are in characters, not bytes: a limit in bytes would let a
/// non-Latin passphrase pass with far fewer symbols than the policy promises.
/// No trimming or normalisation: the password is used exactly as typed.
pub fn check_policy(pw: &str, min_len: usize) -> Result<(), &'static str> {
    // Bounded count, so a huge body costs no more than MAX_LEN steps.
    let len = pw.chars().take(MAX_LEN + 1).count();
    if len > MAX_LEN {
        return Err("password is too long");
    }
    // An empty password is never acceptable, whatever the configured minimum.
    if len < min_len.max(1) {
        return Err("password is too short");
    }
    // NUL truncates in C-string APIs (bcrypt among them), so two different
    // passwords could end up meaning the same thing somewhere downstream.
    if pw.contains('\0') {
        return Err("password must not contain NUL characters");
    }
    Ok(())
}

/// Argon2id m=19456 KiB t=2 p=1 as a PHC string (`$argon2id$v=19$...`).
///
/// Only for a password that passed `check_policy`: `verify` refuses anything
/// over MAX_LEN, so hashing a longer one would lock the account for good.
///
/// Panics if the OS RNG fails, the 19 MiB allocation fails, or the password
/// exceeds 4 GiB.
pub fn hash(pw: &str) -> String {
    debug_assert!(pw.chars().nth(MAX_LEN).is_none(), "hash() takes only passwords that passed check_policy");
    Argon2::default()
        .hash_password(pw.as_bytes())
        .expect("argon2 with default params fails only on RNG or allocation failure")
        .to_string()
}

/// Verifies an Argon2 PHC string, or with `legacy-bcrypt` a bcrypt hash that
/// `bcrypt_accepted` takes, also in its YOURLS-mangled form. Anything
/// unparsable is a plain failure, never a panic.
pub fn verify(pw: &str, stored: &str) -> Verified {
    // Refused before any hashing; `verify_dummy` goes through the same check,
    // so this shortcut times the same for known and unknown users.
    if pw.chars().nth(MAX_LEN).is_some() {
        return FAILED;
    }
    let checked = if stored.starts_with("$argon2") {
        verify_argon2(pw, stored)
    } else {
        #[cfg(feature = "legacy-bcrypt")]
        {
            verify_bcrypt(pw, stored)
        }
        #[cfg(not(feature = "legacy-bcrypt"))]
        {
            None
        }
    };
    // A row refused before any hashing (corrupt, over a cost ceiling, or the
    // YOURLS hash read by a build without legacy-bcrypt) must still cost a
    // full verify, or its answer time tells that the account exists. Straight
    // to the dummy rather than through `verify_dummy`, so there is no path
    // back into this function.
    checked.unwrap_or_else(|| {
        std::hint::black_box(verify_argon2(pw, DUMMY_HASH));
        FAILED
    })
}

/// `None` when the stored string is refused before the KDF runs.
fn verify_argon2(pw: &str, stored: &str) -> Option<Verified> {
    let parsed = PasswordHash::new(stored).ok()?;
    let alg = Algorithm::new(parsed.algorithm.as_str()).ok()?;
    let params = Params::try_from(&parsed).ok()?;
    // Without a salt or digest the verifier gives up before hashing, with the
    // same error as a wrong password, so those are told apart here.
    let salt = parsed.salt.as_ref()?;
    if parsed.hash.is_none() || too_costly(&params) {
        return None;
    }
    let current = Argon2::default();
    // The verifier takes algorithm, version and params from the hash itself,
    // not from this instance, so older hashes keep verifying.
    match current.verify_password(pw.as_bytes(), &parsed) {
        Ok(()) => {}
        // Only a digest mismatch comes after the KDF ran; every other error
        // (bad version, salt, output size, allocation) is raised before it.
        Err(PhcError::PasswordInvalid) => return Some(FAILED),
        Err(_) => return None,
    }
    let cur = current.params();
    // Anything that differs from what `hash()` writes, stronger or weaker,
    // so every stored hash converges on the one current parameter set.
    let stale = alg != Algorithm::default()
        // No `v=` means 0x10 under the PHC spec, so a missing one is stale too.
        || parsed.version != Some(u32::from(Version::default()))
        || params.m_cost() != cur.m_cost()
        || params.t_cost() != cur.t_cost()
        || params.p_cost() != cur.p_cost()
        || params.output_len() != Some(Params::DEFAULT_OUTPUT_LEN)
        || salt.len() != Salt::RECOMMENDED_LENGTH
        || !params.keyid().is_empty()
        || !params.data().is_empty();
    Some(Verified { ok: true, needs_rehash: stale })
}

fn too_costly(p: &Params) -> bool {
    p.m_cost() > MAX_M_COST || p.t_cost() > MAX_T_COST || p.p_cost() > MAX_P_COST
}

/// `None` when the stored string is refused before the KDF runs.
#[cfg(feature = "legacy-bcrypt")]
fn verify_bcrypt(pw: &str, stored: &str) -> Option<Verified> {
    let s = unmangle_yourls(stored);
    if !bcrypt_accepted(&s) {
        return None;
    }
    // Truncating verify, as PHP's password_verify did: a YOURLS password
    // longer than 72 bytes must still log in once to be rehashed.
    match bcrypt::verify(pw.as_bytes(), &s) {
        Ok(true) => Some(Verified { ok: true, needs_rehash: true }),
        Ok(false) => Some(FAILED),
        // The crate only errors on a malformed hash, before hashing.
        Err(_) => None,
    }
}

/// The legacy hashes `verify` takes, after `unmangle_yourls`: `$2a$`, `$2b$`
/// or `$2y$` with cost at most MAX_BCRYPT_COST. Narrower than what the bcrypt
/// crate parses, so the bootstrap must check L4F_ADMIN_HASH with this (plus
/// `bcrypt::verify("", h).is_ok()`) and refuse to boot otherwise, rather than
/// lock the admin out at the first login. `$2x$` marks hashes from the broken
/// pre-2011 crypt_blowfish; the YOURLS import never produces it.
#[cfg(feature = "legacy-bcrypt")]
pub(crate) fn bcrypt_accepted(s: &str) -> bool {
    ["$2a$", "$2b$", "$2y$"].iter().any(|p| s.starts_with(p))
        && s.get(4..6).and_then(|c| c.parse::<u32>().ok()).is_some_and(|cost| cost <= MAX_BCRYPT_COST)
}

/// Burns the same CPU as a real verify, for unknown users and users without a
/// password, so response time does not reveal which accounts exist.
pub fn verify_dummy(pw: &str) {
    std::hint::black_box(verify(pw, DUMMY_HASH));
}

/// `hash("l4f-accounts timing dummy")` under the current defaults, so
/// verifying against it costs what verifying any `hash()` output costs. A
/// constant rather than hashed at first use: built lazily, the first unknown
/// user after every restart paid two Argon2 runs and stood out. The test
/// `dummy_hash_is_a_current_defaults_hash` fails if the argon2 defaults move.
const DUMMY_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$d8Kg5nysgKU91nRJc1gdPw$HG4+kLYZ7Zy4O7CE/YcTRKhPJ2xwF+demHiW7dDlshU";

/// YOURLS stores bcrypt hashes with every `$` written as `!`, so that PHP does
/// not interpolate them in the config file. `!` never occurs in a real bcrypt
/// string, so this is safe to apply to an already-unmangled hash too.
pub fn unmangle_yourls(stored: &str) -> String {
    stored.trim_start_matches("phpass:").replace('!', "$")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Hash with explicit variant, version and costs; cheap when m is small.
    fn argon2_with(alg: Algorithm, version: Version, m: u32, t: u32, p: u32, pw: &str) -> String {
        let params = Params::new(m, t, p, None).unwrap();
        Argon2::new(alg, version, params).hash_password(pw.as_bytes()).unwrap().to_string()
    }

    fn timed(f: impl FnOnce()) -> Duration {
        let t = Instant::now();
        f();
        t.elapsed()
    }

    /// Asserts `f` costs at least a quarter of a wrong-password verify against
    /// `real_hash`. That verify runs right before and right after `f` and the
    /// faster run counts, so a change in load (other tests hashing in
    /// parallel) cannot fake a gap. A skipped KDF is ~10^5 times faster.
    fn assert_costs_a_full_verify(real_hash: &str, what: &str, f: impl FnOnce()) {
        let real = || timed(|| assert_eq!(verify("a wrong password", real_hash), FAILED));
        let before = real();
        let t = timed(f);
        let real = before.min(real());
        assert!(t * 4 >= real, "{what} took {t:?}, a real verify {real:?}");
    }

    #[test]
    fn policy_accepts_reasonable_passwords() {
        assert_eq!(check_policy("correct horse battery", MIN_LEN_DEFAULT), Ok(()));
        assert_eq!(check_policy(&"x".repeat(MAX_LEN), MIN_LEN_DEFAULT), Ok(()), "exactly MAX_LEN is allowed");
        assert_eq!(check_policy(&"x".repeat(MIN_LEN_DEFAULT), MIN_LEN_DEFAULT), Ok(()), "exactly min is allowed");
    }

    #[test]
    fn policy_rejects_short_long_and_nul() {
        assert_eq!(check_policy("short", MIN_LEN_DEFAULT), Err("password is too short"));
        assert_eq!(check_policy(&"x".repeat(MIN_LEN_DEFAULT - 1), MIN_LEN_DEFAULT), Err("password is too short"));
        assert_eq!(check_policy(&"x".repeat(MAX_LEN + 1), MIN_LEN_DEFAULT), Err("password is too long"));
        assert_eq!(check_policy(&"x".repeat(100_000), MIN_LEN_DEFAULT), Err("password is too long"));
        assert_eq!(
            check_policy("long enough\0but nul", MIN_LEN_DEFAULT),
            Err("password must not contain NUL characters")
        );
    }

    #[test]
    fn policy_never_accepts_empty_even_with_zero_min() {
        assert_eq!(check_policy("", 0), Err("password is too short"));
        assert_eq!(check_policy("a", 0), Ok(()));
    }

    #[test]
    fn policy_counts_characters_not_bytes() {
        // 10 two-byte chars = 20 bytes: passes min 10, as it should.
        assert_eq!(check_policy(&"é".repeat(10), 10), Ok(()));
        // 5 four-byte chars = 20 bytes but only 5 symbols: too short.
        assert_eq!(check_policy(&"🔑".repeat(5), 10), Err("password is too short"));
        // MAX_LEN multi-byte chars is fine even though bytes exceed MAX_LEN.
        assert_eq!(check_policy(&"é".repeat(MAX_LEN), 10), Ok(()));
        assert_eq!(check_policy(&"é".repeat(MAX_LEN + 1), 10), Err("password is too long"));
    }

    #[test]
    fn hash_is_argon2id_with_default_params_and_round_trips() {
        let h = hash("correct horse battery staple");
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "unexpected PHC prefix: {h}");
        assert_eq!(verify("correct horse battery staple", &h), Verified { ok: true, needs_rehash: false });
        assert_eq!(verify("correct horse battery stapl", &h), FAILED);
        assert_eq!(verify("", &h), FAILED);
    }

    #[test]
    fn hash_salts_every_call() {
        assert_ne!(hash("same password"), hash("same password"), "two hashes must not collide");
    }

    #[test]
    fn verify_handles_unicode_passwords() {
        let pw = "pässwörd-🔑-日本語";
        let h = hash(pw);
        assert!(verify(pw, &h).ok);
        assert!(!verify("passwörd-🔑-日本語", &h).ok);
    }

    #[test]
    fn verify_refuses_oversized_passwords_without_hashing() {
        let long = "x".repeat(MAX_LEN + 1);
        // Even a hash of exactly that string cannot be satisfied by verify.
        let h = argon2_with(Algorithm::Argon2id, Version::V0x13, 8, 1, 1, &long);
        assert_eq!(verify(&long, &h), FAILED);
        let max = "x".repeat(MAX_LEN);
        let h = argon2_with(Algorithm::Argon2id, Version::V0x13, 8, 1, 1, &max);
        assert!(verify(&max, &h).ok, "exactly MAX_LEN still verifies");
    }

    #[test]
    fn weaker_argon2_params_verify_but_need_rehash() {
        for (m, t, p) in [(8, 2, 1), (19456, 1, 1), (19456 / 2, 2, 1)] {
            let h = argon2_with(Algorithm::Argon2id, Version::V0x13, m, t, p, "pw");
            assert_eq!(
                verify("pw", &h),
                Verified { ok: true, needs_rehash: true },
                "m={m} t={t} p={p} must verify and be flagged"
            );
            assert_eq!(verify("wrong", &h), FAILED, "m={m} t={t} p={p} wrong password");
        }
    }

    #[test]
    fn stronger_argon2_params_also_need_rehash() {
        // "Differs from the current defaults", not just "weaker": keeps every
        // stored hash converging on one parameter set. Each case is stronger
        // in exactly one cost, so a weaker-only rule fails it.
        for (m, t, p) in [(20480, 2, 1), (19456, 3, 1), (19456, 2, 2)] {
            let h = argon2_with(Algorithm::Argon2id, Version::V0x13, m, t, p, "pw");
            assert_eq!(
                verify("pw", &h),
                Verified { ok: true, needs_rehash: true },
                "m={m} t={t} p={p} is stronger, yet not what hash() writes"
            );
        }
    }

    #[test]
    fn other_argon2_variants_and_versions_need_rehash() {
        // Default costs, so the variant or version alone must trigger it.
        for alg in [Algorithm::Argon2i, Algorithm::Argon2d] {
            let h = argon2_with(alg, Version::V0x13, 19456, 2, 1, "pw");
            assert!(h.starts_with(&format!("${}$v=19$m=19456,t=2,p=1$", alg.as_str())), "{h}");
            assert_eq!(verify("pw", &h), Verified { ok: true, needs_rehash: true }, "{alg} must be flagged");
            assert_eq!(verify("nope", &h), FAILED);
        }
        let v10 = argon2_with(Algorithm::Argon2id, Version::V0x10, 19456, 2, 1, "pw");
        assert!(v10.starts_with("$argon2id$v=16$m=19456,t=2,p=1$"), "{v10}");
        assert_eq!(verify("pw", &v10), Verified { ok: true, needs_rehash: true }, "v=16 must be flagged");
    }

    #[test]
    fn argon2_without_version_field_needs_rehash() {
        // From a current hash, so the missing `v=` alone must trigger it.
        let no_v = hash("pw").replacen("$v=19", "", 1);
        assert!(no_v.starts_with("$argon2id$m=19456,t=2,p=1$"), "{no_v}");
        // The crate verifies a missing version as 0x13, so it still matches;
        // it must be flagged so the stored string gains an explicit v=19.
        assert_eq!(verify("pw", &no_v), Verified { ok: true, needs_rehash: true });
    }

    #[test]
    fn argon2_hashes_shaped_unlike_ours_need_rehash() {
        // Default costs throughout: only the digest length, the salt length or
        // an extra parameter differs from what hash() writes.
        let with = |b: &mut argon2::ParamsBuilder| {
            let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, b.build().unwrap());
            a.hash_password(b"pw").unwrap().to_string()
        };
        let short_out = with(argon2::ParamsBuilder::new().output_len(10));
        let short_salt = Argon2::default().hash_password_with_salt(b"pw", b"8 bytes!").unwrap().to_string();
        let data = with(argon2::ParamsBuilder::new().data(argon2::AssociatedData::new(b"eno").unwrap()));
        let keyid = with(argon2::ParamsBuilder::new().keyid(argon2::KeyId::new(b"k1").unwrap()));
        for h in [short_out, short_salt, data, keyid] {
            assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1"), "{h}");
            assert_eq!(verify("pw", &h), Verified { ok: true, needs_rehash: true }, "{h} must be flagged");
        }
    }

    #[test]
    fn tampered_argon2_hashes_fail() {
        let h = argon2_with(Algorithm::Argon2id, Version::V0x13, 8, 2, 1, "pw");
        assert!(verify("pw", &h).ok);
        // Flip one bit of the digest. The first character, not the last: a
        // final base64 character carries padding bits a decoder may ignore.
        let at = h.rfind('$').unwrap() + 1;
        let mut bad = h.clone();
        bad.replace_range(at..at + 1, if &h[at..at + 1] == "A" { "B" } else { "A" });
        assert_ne!(bad, h);
        assert_eq!(verify("pw", &bad), FAILED, "changed digest");
        // Change a cost parameter: same salt and digest no longer match.
        assert_eq!(verify("pw", &h.replace("t=2", "t=3")), FAILED, "changed t");
        // Change the variant.
        assert_eq!(verify("pw", &h.replacen("$argon2id$", "$argon2i$", 1)), FAILED, "changed variant");
    }

    #[test]
    fn malformed_stored_strings_fail_without_panicking() {
        let good = argon2_with(Algorithm::Argon2id, Version::V0x13, 8, 2, 1, "pw");
        let no_digest = good.rsplit_once('$').unwrap().0.to_string();
        let mut cases = vec![
            String::new(),
            "$".into(),
            "$argon2".into(),
            "$argon2id".into(),
            "$argon2id$".into(),
            "$argon2id$v=19$m=8,t=2,p=1".into(),
            "$argon2x$v=19$m=8,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo".into(),
            "$argon2id$v=99$m=8,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo".into(),
            "$argon2id$v=19$m=8,t=2,p=1,z=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo".into(),
            "$argon2id$v=19$m=0,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo".into(),
            "$argon2id$v=19$m=8,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo".into(),
            "$argon2id$v=19$m=8,t=2,p=1$!!!$aGFzaGhhc2hoYXNo".into(),
            "$argon2id$v=19$m=8,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo$extra".into(),
            "argon2id$v=19$m=8,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo".into(),
            "plaintext-password".into(),
            "pw".into(),
            "$P$Bxyz".into(),
            "$6$rounds=5000$salt$hash".into(),
            no_digest,
            format!("{good}\n"),
            format!(" {good}"),
        ];
        cases.push(good.replace("m=8", "m=-8"));
        for c in &cases {
            assert_eq!(verify("pw", c), FAILED, "{c:?} must fail");
        }
    }

    #[test]
    fn cost_ceilings_sit_exactly_at_the_maximum() {
        let p = |m, t, p| Params::new(m, t, p, None).unwrap();
        assert!(!too_costly(&Params::default()), "current defaults must pass");
        assert!(!too_costly(&p(MAX_M_COST, MAX_T_COST, MAX_P_COST)), "the ceiling itself passes");
        assert!(too_costly(&p(MAX_M_COST + 1, 2, 1)), "m over the ceiling");
        assert!(too_costly(&p(19456, MAX_T_COST + 1, 1)), "t over the ceiling");
        assert!(too_costly(&p(19456, 2, MAX_P_COST + 1)), "p over the ceiling");
    }

    #[test]
    fn hostile_argon2_costs_are_refused_before_hashing() {
        // Cheap but correct hashes just over a ceiling: they would verify if
        // hashed, so FAILED here can only come from the ceiling. First, so a
        // missing ceiling fails here instead of hanging on the next loop.
        for (m, t, p) in [(8, MAX_T_COST + 1, 1), (8 * (MAX_P_COST + 1), 1, MAX_P_COST + 1)] {
            let h = argon2_with(Algorithm::Argon2id, Version::V0x13, m, t, p, "pw");
            assert_eq!(verify("pw", &h), FAILED, "{h} is correct, only the ceiling may refuse it");
        }
        // Each of these would allocate gigabytes or run for hours if attempted;
        // the test finishing at all shows verify refused them up front.
        let good = argon2_with(Algorithm::Argon2id, Version::V0x13, 8, 2, 1, "pw");
        for params in ["m=4194304,t=2,p=1", "m=19456,t=4294967295,p=1", "m=4194304,t=2,p=1024"] {
            let s = good.replacen("m=8,t=2,p=1", params, 1);
            assert!(
                Params::try_from(&PasswordHash::new(&s).unwrap()).is_ok(),
                "{s} must be well-formed, so only the ceiling can stop it"
            );
            assert_eq!(verify("pw", &s), FAILED, "{s} must be refused");
        }
    }

    /// Hashes made by other bcrypt implementations, tested as they are and in
    /// YOURLS form: the bcrypt crate's own vectors (from Python and an online
    /// tool), crypt_blowfish's (the code inside PHP, including its over-72-byte
    /// case) and the `$2y$` hash from PHP's password_verify manual page.
    const BCRYPT_VECTORS: [(&str, &str); 5] = [
        ("correctbatteryhorsestapler", "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie"),
        ("password", "$2a$04$UuTkLRZZ6QofpDOlMz32MuuxEHA43WOemOYHPz6.SjsVsyO1tDU96"),
        ("U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"),
        (
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored",
            "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
        ),
        ("rasmuslerdorf", "$2y$07$BCryptRequires22Chrcte/VlQH0piJtjXl.0t1XkA8pw9dMXTpOq"),
    ];

    #[test]
    fn bcrypt_hashes_verify_only_with_the_legacy_feature() {
        for (pw, h) in BCRYPT_VECTORS {
            let mangled = format!("phpass:{}", h.replace('$', "!"));
            for stored in [h, mangled.as_str()] {
                let r = verify(pw, stored);
                if cfg!(feature = "legacy-bcrypt") {
                    assert_eq!(r, Verified { ok: true, needs_rehash: true }, "{stored} must verify and be flagged");
                    assert_eq!(verify("wrong", stored), FAILED, "{stored} with a wrong password");
                } else {
                    assert_eq!(r, FAILED, "without legacy-bcrypt {stored} must not verify");
                }
            }
        }
    }

    #[test]
    fn dummy_hash_is_a_current_defaults_hash() {
        // needs_rehash false means variant, version, costs, salt and digest
        // length all match what hash() writes today; if the argon2 defaults
        // move, regenerate DUMMY_HASH from the password below.
        assert!(DUMMY_HASH.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{DUMMY_HASH}");
        assert_eq!(verify("l4f-accounts timing dummy", DUMMY_HASH), Verified { ok: true, needs_rehash: false });
    }

    #[test]
    fn verify_dummy_costs_what_a_real_verify_costs() {
        let h = hash("the real password");
        assert_costs_a_full_verify(&h, "verify_dummy", || verify_dummy("a wrong password"));
        // An oversized password is refused before hashing for a known user, so
        // the dummy must skip the KDF for it too.
        let long = "x".repeat(MAX_LEN + 1);
        let dummy_long = timed(|| verify_dummy(&long));
        let real = timed(|| assert_eq!(verify("a wrong password", &h), FAILED));
        assert!(dummy_long * 4 < real, "verify_dummy hashed an oversized password: {dummy_long:?} vs {real:?}");
    }

    #[test]
    fn unusable_stored_hashes_cost_a_full_verify() {
        // A row refused before hashing must not answer faster than a wrong
        // password, or the timing tells that the account exists.
        let good = hash("pw");
        let no_digest = good.rsplit_once('$').unwrap().0.to_string();
        let mut cases = vec![
            String::new(),
            "garbage".into(),
            no_digest,
            good.replacen("$v=19$", "$v=99$", 1),
            good.replacen("t=2", &format!("t={}", MAX_T_COST + 1), 1),
            // Refused by both builds: unknown prefix, and over the bcrypt ceiling.
            "$2x$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie".into(),
            "$2b$17$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie".into(),
            // Passes the prefix and cost check, then the bcrypt crate refuses it.
            "$2b$04$tooshort".into(),
        ];
        if !cfg!(feature = "legacy-bcrypt") {
            // The bootstrap admin's YOURLS hash, read by a build that cannot check it.
            cases.push("phpass:!2y!07!BCryptRequires22Chrcte/VlQH0piJtjXl.0t1XkA8pw9dMXTpOq".into());
        }
        for stored in &cases {
            assert_costs_a_full_verify(&good, &format!("{stored:?}"), || assert_eq!(verify("pw", stored), FAILED));
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "check_policy")]
    fn hash_refuses_in_debug_builds_what_verify_would_never_accept() {
        hash(&"x".repeat(MAX_LEN + 1));
    }

    #[test]
    fn yourls_hash_unmangling() {
        assert_eq!(unmangle_yourls("phpass:!2a!08!Lq/puXhLGnBH.txuKiWR6e"), "$2a$08$Lq/puXhLGnBH.txuKiWR6e");
        // already unmangled, and plain hashes without the prefix, pass through
        assert_eq!(unmangle_yourls("$2a$08$abc"), "$2a$08$abc");
    }

    /// The whole point of keeping his existing hash: a password that verified
    /// under YOURLS must still verify here, straight out of the mangled config
    /// value, with no password reset.
    #[cfg(feature = "legacy-bcrypt")]
    #[test]
    fn a_yourls_stored_hash_still_verifies() {
        let real = bcrypt::hash_with_result("correct horse battery staple", 6).unwrap().to_string();
        // Store it exactly as YOURLS writes it into user/config.php.
        let stored = format!("phpass:{}", real.replace('$', "!"));
        assert!(stored.contains('!') && !stored.contains('$'), "config form has no $ in it");

        let recovered = unmangle_yourls(&stored);
        assert_eq!(recovered, real);
        assert!(bcrypt::verify("correct horse battery staple", &recovered).unwrap());
        assert!(!bcrypt::verify("wrong", &recovered).unwrap());

        // And through this module's verify, which must also ask for a rehash.
        let ok = Verified { ok: true, needs_rehash: true };
        assert_eq!(verify("correct horse battery staple", &stored), ok, "mangled form");
        assert_eq!(verify("correct horse battery staple", &recovered), ok, "unmangled form");
        assert_eq!(verify("wrong", &stored), FAILED);
        assert_eq!(verify("", &stored), FAILED);
    }

    #[cfg(feature = "legacy-bcrypt")]
    #[test]
    fn bcrypt_prefixes_2a_2b_2y_verify_and_others_do_not() {
        let b = bcrypt::hash_with_result("pw-legacy", 4).unwrap();
        for v in [bcrypt::Version::TwoA, bcrypt::Version::TwoB, bcrypt::Version::TwoY] {
            let h = b.format_for_version(v);
            assert_eq!(verify("pw-legacy", &h), Verified { ok: true, needs_rehash: true }, "{h}");
            assert_eq!(verify("pw-legacy!", &h), FAILED, "{h} wrong password");
        }
        // $2x$ is accepted by the bcrypt crate but never by us.
        let x = b.format_for_version(bcrypt::Version::TwoX);
        assert!(bcrypt::verify("pw-legacy", &x).unwrap(), "precondition: the crate takes $2x$");
        assert_eq!(verify("pw-legacy", &x), FAILED, "$2x$ must be refused");
    }

    #[cfg(feature = "legacy-bcrypt")]
    #[test]
    fn bcrypt_accepted_set_and_cost_ceiling_are_exact() {
        let h = |prefix: &str, cost: &str| {
            format!("{prefix}{cost}$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie")
        };
        for prefix in ["$2a$", "$2b$", "$2y$"] {
            assert!(bcrypt_accepted(&h(prefix, "04")), "{prefix} cost 4");
            assert!(bcrypt_accepted(&h(prefix, &MAX_BCRYPT_COST.to_string())), "{prefix} the ceiling itself");
            assert!(!bcrypt_accepted(&h(prefix, &(MAX_BCRYPT_COST + 1).to_string())), "{prefix} one over");
        }
        for refused in [
            h("$2x$", "04"),
            h("$2$", "04"),
            h("$2b$", "31"),
            h("$2b$", "xx"),
            h("$2b$", "-4"),
            "$2b$".into(),
        ] {
            assert!(!bcrypt_accepted(&refused), "{refused:?}");
        }
    }

    #[cfg(feature = "legacy-bcrypt")]
    #[test]
    fn malformed_and_hostile_bcrypt_hashes_fail() {
        let good = bcrypt::hash_with_result("pw", 4).unwrap().format_for_version(bcrypt::Version::TwoB);
        let over = format!("$2b${}{}", MAX_BCRYPT_COST + 1, &good[6..]);
        assert_eq!(over.len(), 60);
        // Run at cost 17 this takes ~6 s even in release; refused, it costs one
        // dummy Argon2 run. Checked first, so a missing ceiling fails here
        // instead of hanging on the `$31$` case below.
        let t = timed(|| assert_eq!(verify("pw", &over), FAILED));
        assert!(t < Duration::from_secs(3), "{over} was hashed at cost 17 ({t:?})");
        for c in [
            good.replacen("$04$", "$31$", 1),
            good.replacen("$04$", "$xx$", 1),
            good.replacen("$04$", "$-4$", 1),
            good[..59].to_string(),
            format!("{good}x"),
            format!("$2b$04${}x", "é".repeat(26)),
            "$2b$".into(),
            "$2b$04".into(),
            "phpass:".into(),
            "!2b!".into(),
        ] {
            assert_eq!(verify("pw", &c), FAILED, "{c:?} must fail");
        }
        // Flip one bit of the digest's first character ('.' and '/' are 0 and 1
        // in bcrypt's alphabet); `$2b$04$` plus the 22-char salt come first.
        let mut bad = good.clone();
        bad.replace_range(29..30, if &good[29..30] == "." { "/" } else { "." });
        assert_ne!(bad, good);
        assert_eq!(verify("pw", &bad), FAILED, "tampered digest");
    }

    #[cfg(feature = "legacy-bcrypt")]
    #[test]
    fn bcrypt_truncates_at_72_bytes_like_php() {
        // Documented legacy behaviour, kept so a long YOURLS password still
        // logs in once; the rehash then covers the full password.
        let long = "a".repeat(80);
        let h = bcrypt::hash(&long, 4).unwrap();
        assert!(verify(&long, &h).ok);
        assert!(verify(&"a".repeat(72), &h).ok, "bcrypt only sees 72 bytes");
        assert!(!verify(&"a".repeat(71), &h).ok);
    }
}
