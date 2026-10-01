//! One-time recovery codes for a lost second factor.
//!
//! Only `hash(key, user, code)` is stored. A code carries 59.4 bits, too few
//! for a bare digest: one GPU search of the code space tests every row of a
//! dumped table at once (minutes for 10^5 rows). A server key that never sits
//! in the database makes the dump alone useless; binding the user id keeps a
//! row copied to another account from matching and, should the key leak too,
//! makes each account its own search. A MAC is deterministic, so the burn
//! stays one conditional UPDATE on an index.
//!
//! Issue with `keys.subkey("recovery")`; burn by trying each of
//! `keys.subkeys("recovery")`. Codes are single-use, so nothing is resealed:
//! once an old master is dropped, its codes stop working and the user makes a
//! new set.

use rand::Rng;

use crate::util::mac_raw;

pub const COUNT: usize = 10;

/// a-z and 2-9 without i, l and o: nothing a reader can confuse with 0, 1 or
/// each other when copying from paper. 31 symbols, so 12 of them carry
/// 12 * log2(31) = 59.4 bits.
const ALPHABET: &[u8; 31] = b"abcdefghjkmnpqrstuvwxyz23456789";
const GROUPS: usize = 3;
const GROUP_LEN: usize = 4;

/// Codes look like "abcd-efgh-jkmn": 12 symbols grouped by 4.
pub fn generate() -> Vec<String> {
    let mut rng = rand::rng();
    let mut codes: Vec<String> = Vec::with_capacity(COUNT);
    while codes.len() < COUNT {
        let mut c = String::with_capacity(GROUPS * (GROUP_LEN + 1));
        for g in 0..GROUPS {
            if g > 0 {
                c.push('-');
            }
            for _ in 0..GROUP_LEN {
                // `random_range` uses a widening multiply; its bias is
                // negligible, unlike `% 31`.
                c.push(ALPHABET[rng.random_range(0..ALPHABET.len())] as char);
            }
        }
        // A repeat is a 2^-59 event, but two equal rows would burn together.
        if !codes.contains(&c) {
            codes.push(c);
        }
    }
    codes
}

/// HMAC-SHA256 under `key` of `len(user) as u64 BE | user | code`; store only
/// this. `user` is the account id as the row holds it (e.g. its big-endian
/// bytes); the length prefix keeps it from running into the code.
///
/// The code is normalised first (ASCII lowercase, whitespace and dashes
/// dropped): codes are read off paper and retyped, so neither the grouping nor
/// the case may matter.
pub fn hash(key: &[u8; 32], user: &[u8], code: &str) -> [u8; 32] {
    let mut msg = Vec::with_capacity(8 + user.len() + code.len());
    msg.extend_from_slice(&(user.len() as u64).to_be_bytes());
    msg.extend_from_slice(user);
    msg.extend(
        code.bytes()
            .filter(|&b| !b.is_ascii_whitespace() && b != b'-')
            .map(|b| b.to_ascii_lowercase()),
    );
    mac_raw(key, &msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const USER: &[u8] = &42u64.to_be_bytes();

    #[test]
    fn alphabet_is_31_unambiguous_symbols() {
        let mut seen = std::collections::HashSet::new();
        for &b in ALPHABET {
            assert!(b.is_ascii_lowercase() || b.is_ascii_digit(), "{:?} not lowercase alnum", b as char);
            assert!(!b"0o1li".contains(&b), "{:?} is easily misread", b as char);
            assert!(seen.insert(b), "{:?} listed twice", b as char);
        }
        assert_eq!(seen.len(), 31);
    }

    #[test]
    fn generates_ten_distinct_well_formed_codes() {
        let codes = generate();
        assert_eq!(codes.len(), COUNT);
        for c in &codes {
            assert_eq!(c.len(), 14, "{c} is 12 symbols plus 2 dashes");
            let groups: Vec<&str> = c.split('-').collect();
            assert_eq!(groups.len(), 3, "{c} has three groups");
            for g in groups {
                assert_eq!(g.len(), 4, "{c}: group {g} has four symbols");
                assert!(g.bytes().all(|b| ALPHABET.contains(&b)), "{c}: {g} outside the alphabet");
            }
        }
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), COUNT, "codes within a set are distinct");
        assert_ne!(generate(), codes, "every call draws new codes");
    }

    #[test]
    fn generation_uses_the_whole_alphabet() {
        // 50 sets = 6000 symbols, about 194 per symbol; a missing one means an
        // off-by-one in the range, not bad luck.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            for c in generate() {
                seen.extend(c.bytes().filter(|&b| b != b'-'));
            }
        }
        let mut want: Vec<u8> = ALPHABET.to_vec();
        let mut got: Vec<u8> = seen.into_iter().collect();
        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn hash_is_hmac_of_user_and_normalised_code() {
        // Stored hashes must stay valid for as long as the key does, so pin the
        // exact format (checked with Python's hmac):
        // HMAC-SHA256(0..32, u64be(8) | u64be(42) | "abcdefghjkmn").
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let want = hex::decode("5a11f342526855dfbff5619e6bdb1d818407f0a32485185294a8aeb680b44e25").unwrap();
        assert_eq!(hash(&key, USER, "abcd-efgh-jkmn").as_slice(), want.as_slice());
        assert_eq!(hash(&key, USER, "abcdefghjkmn").as_slice(), want.as_slice());
    }

    #[test]
    fn hash_is_not_a_bare_digest() {
        // The old format: SHA-256 of the code alone, which a dumped table
        // exposes to one search over all 2^59.4 codes for every row at once.
        use sha2::{Digest, Sha256};
        let bare: [u8; 32] = Sha256::digest(b"abcdefghjkmn").into();
        assert_ne!(hash(&KEY, USER, "abcd-efgh-jkmn"), bare);
        assert_ne!(hash(&KEY, b"", "abcd-efgh-jkmn"), bare, "not even without a user");
    }

    #[test]
    fn hash_depends_on_key_and_user() {
        let code = "abcd-efgh-jkmn";
        let want = hash(&KEY, USER, code);
        assert_ne!(hash(&[8; 32], USER, code), want, "another server key");
        assert_ne!(hash(&KEY, &43u64.to_be_bytes(), code), want, "row copied to another account");
        assert_ne!(hash(&KEY, b"", code), want, "no user");
        // The length prefix keeps the user from running into the code.
        assert_ne!(hash(&KEY, b"1", "2abc-defg-hjkm"), hash(&KEY, b"12", "abcd-efgh-jkm"));
        assert_ne!(hash(&KEY, b"", "12abcdefghjk"), hash(&KEY, b"12", "abcdefghjk"));
    }

    #[test]
    fn hash_ignores_case_spacing_and_dashes() {
        let want = hash(&KEY, USER, "abcd-efgh-jkmn");
        for typed in [
            "ABCD-EFGH-JKMN",
            "abcd efgh jkmn",
            "  abcd-efgh-jkmn\n",
            "AbCd--EfGh - JkMn",
            "abcdefghjkmn",
            "a-b-c-d-e-f-g-h-j-k-m-n",
            "abcd\tefgh\r\njkmn",
        ] {
            assert_eq!(hash(&KEY, USER, typed), want, "{typed:?} is the same code");
        }
    }

    #[test]
    fn hash_distinguishes_other_input() {
        let want = hash(&KEY, USER, "abcd-efgh-jkmn");
        for other in [
            "abcd-efgh-jkmp",  // one symbol changed
            "abcd-efgh-jkm",   // one symbol short
            "abcd-efgh-jkmnn", // one symbol extra
            "efgh-abcd-jkmn",  // groups swapped
            "abcd_efgh_jkmn",  // only spaces and dashes are separators
            "abcd.efgh.jkmn",
            "abcd-efgh-jkmn\0",
            "ａｂｃｄ-ｅｆｇｈ-ｊｋｍｎ", // fullwidth letters are not folded
            "",
        ] {
            assert_ne!(hash(&KEY, USER, other), want, "{other:?} must not match");
        }
        assert_eq!(hash(&KEY, USER, "- -"), hash(&KEY, USER, ""), "separators alone normalise to nothing");
    }

    #[test]
    fn generated_codes_hash_as_typed_back() {
        for c in generate() {
            let typed = c.to_ascii_uppercase().replace('-', " ");
            assert_eq!(hash(&KEY, USER, &typed), hash(&KEY, USER, &c), "{c}");
        }
    }

    #[test]
    fn burn_tries_every_key_once_per_code() {
        // What the service does: rows hold hashes under the key current at
        // issue; a burn tries `subkeys` (current first) and deletes the match.
        fn burn(rows: &mut Vec<[u8; 32]>, keys: &[[u8; 32]], user: &[u8], code: &str) -> bool {
            for k in keys {
                let h = hash(k, user, code);
                if let Some(i) = rows.iter().position(|r| *r == h) {
                    rows.remove(i);
                    return true;
                }
            }
            false
        }
        let (old, new) = ([1u8; 32], [2u8; 32]);
        let codes = generate();
        let mut rows: Vec<[u8; 32]> = codes.iter().map(|c| hash(&old, USER, c)).collect();
        assert!(burn(&mut rows, &[new, old], USER, &codes[0]), "issued before the rotation");
        assert!(!burn(&mut rows, &[new, old], USER, &codes[0]), "single use");
        assert!(!burn(&mut rows, &[new, old], &43u64.to_be_bytes(), &codes[1]), "another account");
        assert!(!burn(&mut rows, &[new], USER, &codes[1]), "old key dropped: regenerate");
        assert_eq!(rows.len(), COUNT - 1);
    }
}
