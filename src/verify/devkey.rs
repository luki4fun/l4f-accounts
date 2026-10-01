//! Device keys: a non-extractable WebCrypto Ed25519 key the browser keeps in
//! IndexedDB, stored here as its raw 32-byte public key.
//!
//! The signed message names the origin and the device, so a signature made for
//! a phishing origin or for another enrolled device does not verify here.

use ring::signature::{ED25519, UnparsedPublicKey};

const PREFIX: &[u8] = b"l4f-devkey-v1\0";

/// `"l4f-devkey-v1\0" || origin || "\0" || device_id || "\0" || challenge`.
///
/// Only unambiguous with a NUL-free origin and a fixed-length challenge, which
/// is why [`verify`] insists on both: a binary `device_id` may contain NUL.
pub fn message(origin: &str, device_id: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(PREFIX.len() + origin.len() + device_id.len() + challenge.len() + 2);
    m.extend_from_slice(PREFIX);
    m.extend_from_slice(origin.as_bytes());
    m.push(0);
    m.extend_from_slice(device_id);
    m.push(0);
    m.extend_from_slice(challenge);
    m
}

const fn low(b0: u8) -> [u8; 32] {
    let mut b = [0; 32];
    b[0] = b0;
    b
}

const fn high(b0: u8) -> [u8; 32] {
    let mut b = [0xff; 32];
    b[0] = b0;
    b[31] = 0x7f;
    b
}

/// Encodings of the points of order 1, 2, 4 and 8, sign bit cleared, plus the
/// non-canonical `p` and `p + 1`: libsodium's `has_small_order` list.
const SMALL_ORDER: [[u8; 32]; 7] = [
    low(0), // y = 0, order 4
    low(1), // the identity
    // order 8, as is the next
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, //
        0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, //
        0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
    ],
    high(0xec), // p - 1, order 2
    high(0xed), // p, a non-canonical 0
    high(0xee), // p + 1, a non-canonical identity
];

/// A key of small order verifies `R || 0` for a small-order `R` whatever the
/// message (the identity verifies one fixed signature for every message), so
/// it binds nothing. The sign bit is ignored: it only picks `x` or `-x`.
fn small_order(public_key: &[u8; 32]) -> bool {
    SMALL_ORDER.iter().any(|b| b[..31] == public_key[..31] && b[31] == public_key[31] & 0x7f)
}

/// Ed25519 over [`message`]. `public_key` is the stored raw 32-byte key and
/// `challenge` the 32-byte `challenge::challenge_bytes`; other lengths, an origin
/// containing NUL, a signature that is not 64 bytes, or a small-order key (which
/// would accept one signature for every origin, device and challenge) are refused.
pub fn verify(public_key: &[u8], origin: &str, device_id: &[u8], challenge: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = <&[u8; 32]>::try_from(public_key) else {
        return false;
    };
    !small_order(pk)
        && challenge.len() == 32
        && signature.len() == 64
        && !origin.contains('\0')
        && UnparsedPublicKey::new(&ED25519, pk)
            .verify(&message(origin, device_id, challenge), signature)
            .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    const ORIGIN: &str = "https://l4f.cc";
    const DEV: &[u8] = b"dev-0001";

    fn challenge() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    fn key() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    #[test]
    fn message_layout_is_fixed() {
        let m = message(ORIGIN, DEV, &[0xaa, 0xbb]);
        assert_eq!(m, b"l4f-devkey-v1\0https://l4f.cc\0dev-0001\0\xaa\xbb");
    }

    #[test]
    fn a_fresh_signature_verifies() {
        let kp = key();
        let sig = kp.sign(&message(ORIGIN, DEV, &challenge()));
        assert!(verify(kp.public_key().as_ref(), ORIGIN, DEV, &challenge(), sig.as_ref()));
    }

    /// Made with `openssl pkeyutl -sign -rawin` (Ed25519 is deterministic), so the
    /// layout and the verifier agree with an implementation other than ring.
    #[test]
    fn external_signature_verifies() {
        let pk = hex::decode("34047670e2dcbb0a7f4d5b61a72a49a3e2a94e8fe5666ca38ef0fa84df455562").unwrap();
        let sig = hex::decode(
            "c0593daa0fabec2439c34c5a21d09ab1714703b1a51fdd481c0a4fe46e1b7378\
             6badd8a9fe298efc0d07b1e6921a251b24a817eb5ae852cccf2dd9825bf83e04",
        )
        .unwrap();
        assert!(verify(&pk, ORIGIN, DEV, &challenge(), &sig));
        assert!(!verify(&pk, "https://l4f.cc.evil", DEV, &challenge(), &sig));
    }

    #[test]
    fn signature_does_not_transfer_to_other_inputs() {
        let kp = key();
        let pk = kp.public_key().as_ref().to_vec();
        let c = challenge();
        let sig = kp.sign(&message(ORIGIN, DEV, &c)).as_ref().to_vec();
        assert!(!verify(&pk, "https://evil.example", DEV, &c, &sig), "wrong origin");
        assert!(!verify(&pk, "https://l4f.cc/", DEV, &c, &sig), "origin is compared byte for byte");
        assert!(!verify(&pk, ORIGIN, b"dev-0002", &c, &sig), "another device id");
        let mut other = c;
        other[31] ^= 1;
        assert!(!verify(&pk, ORIGIN, DEV, &other, &sig), "another challenge");
        assert!(!verify(&pk, ORIGIN, DEV, &c[..31], &sig), "truncated challenge");
        assert!(!verify(key().public_key().as_ref(), ORIGIN, DEV, &c, &sig), "another key");
    }

    /// `message` alone is not injective: a NUL can move across a separator. The
    /// fixed challenge length and the NUL-free origin are what pin the layout.
    #[test]
    fn separator_shifts_are_refused() {
        let kp = key();
        let pk = kp.public_key().as_ref().to_vec();
        let c = challenge(); // starts with a 0 byte
        let sig = kp.sign(&message(ORIGIN, DEV, &c)).as_ref().to_vec();
        assert_eq!(message(ORIGIN, b"dev-0001\0", &c[1..]), message(ORIGIN, DEV, &c));
        assert!(!verify(&pk, ORIGIN, b"dev-0001\0", &c[1..], &sig), "the challenge must be 32 bytes");
        let sig = kp.sign(&message(ORIGIN, b"a\0b", &c)).as_ref().to_vec();
        assert!(verify(&pk, ORIGIN, b"a\0b", &c, &sig), "a binary device id is fine");
        assert_eq!(message("https://l4f.cc\0a", b"b", &c), message(ORIGIN, b"a\0b", &c));
        assert!(!verify(&pk, "https://l4f.cc\0a", b"b", &c, &sig), "an origin cannot contain NUL");
    }

    #[test]
    fn tampered_or_malformed_signatures_are_refused() {
        let kp = key();
        let pk = kp.public_key().as_ref().to_vec();
        let c = challenge();
        let sig = kp.sign(&message(ORIGIN, DEV, &c)).as_ref().to_vec();
        for i in [0, 31, 32, 63] {
            let mut bad = sig.clone();
            bad[i] ^= 0x01;
            assert!(!verify(&pk, ORIGIN, DEV, &c, &bad), "flipped signature byte {i}");
        }
        assert!(!verify(&pk, ORIGIN, DEV, &c, &sig[..63]), "short signature");
        assert!(!verify(&pk, ORIGIN, DEV, &c, &[sig.clone(), vec![0]].concat()), "long signature");
        assert!(!verify(&pk, ORIGIN, DEV, &c, &[]), "empty signature");
        assert!(!verify(&pk, ORIGIN, DEV, &c, &[0u8; 64]), "all-zero signature");
    }

    #[test]
    fn malformed_public_keys_are_refused() {
        let kp = key();
        let pk = kp.public_key().as_ref().to_vec();
        let c = challenge();
        let sig = kp.sign(&message(ORIGIN, DEV, &c)).as_ref().to_vec();
        assert!(!verify(&pk[..31], ORIGIN, DEV, &c, &sig), "31-byte key");
        assert!(!verify(&[pk.clone(), vec![0]].concat(), ORIGIN, DEV, &c, &sig), "33-byte key");
        assert!(!verify(&[], ORIGIN, DEV, &c, &sig), "empty key");
        let mut flipped = pk.clone();
        flipped[0] ^= 1;
        assert!(!verify(&flipped, ORIGIN, DEV, &c, &sig), "flipped key byte");
    }

    /// Ring alone accepts this pair: with the identity as the key and `R`, and
    /// `S = 0`, the check `[S]B == R + [k]A` holds for every `k`.
    #[test]
    fn the_identity_key_does_not_verify_a_universal_signature() {
        let identity = low(1);
        let sig = [identity, [0; 32]].concat();
        for (origin, dev) in [(ORIGIN, DEV), ("https://evil", &[9u8; 32][..]), (ORIGIN, b"")] {
            for c in [challenge(), [0; 32], [0xff; 32]] {
                let m = message(origin, dev, &c);
                assert!(UnparsedPublicKey::new(&ED25519, &identity).verify(&m, &sig).is_ok(), "ring alone accepts it");
                assert!(!verify(&identity, origin, dev, &c, &sig), "{origin} {dev:?}");
            }
        }
    }

    /// Ring decodes every blocklisted entry with either sign bit (`-0`, `p` and
    /// `p + 1` included) and accepts a `R || 0` forgery for each. Requiring that
    /// forgery per entry is what pins the constants: a mistyped entry is not
    /// small-order and has none. Only seven distinct `y` are small-order, so
    /// seven distinct forgeable entries is also the whole list.
    #[test]
    fn small_order_keys_are_refused() {
        let candidates: Vec<[u8; 32]> = SMALL_ORDER
            .iter()
            .flat_map(|b| {
                let mut neg = *b;
                neg[31] |= 0x80;
                [*b, neg]
            })
            .collect();
        assert_eq!(candidates.iter().collect::<std::collections::HashSet<_>>().len(), 14, "seven distinct entries");
        for pk in &candidates {
            assert!(small_order(pk), "{}", hex::encode(pk));
            let (c, sig) = (0..=255u8)
                .find_map(|i| {
                    let mut c = challenge();
                    c[0] = i;
                    let m = message(ORIGIN, DEV, &c);
                    candidates
                        .iter()
                        .map(|r| [&r[..], &[0; 32]].concat())
                        .find(|sig| UnparsedPublicKey::new(&ED25519, pk).verify(&m, sig).is_ok())
                        .map(|sig| (c, sig))
                })
                .unwrap_or_else(|| panic!("ring accepts no forgery for {}: not a small-order key", hex::encode(pk)));
            assert!(!verify(pk, ORIGIN, DEV, &c, &sig), "forgery for {}", hex::encode(pk));
        }
        let kp = key();
        assert!(!small_order(kp.public_key().as_ref().try_into().unwrap()), "a real key is not small-order");
    }
}
