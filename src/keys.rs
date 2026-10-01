//! The one server secret and everything derived from it: per-purpose HMAC
//! subkeys, sealed blobs (TOTP secrets, the OAuth cookie) and MAC'd tokens.
//!
//! Every use gets its own subkey, so a value MAC'd for one purpose can never be
//! replayed as another. An optional old master keeps sealed rows and issued
//! tokens readable across a rotation; `open` says when a row should be re-sealed.

use hmac::{Hmac, Mac};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use sha2::{Digest, Sha256};

use crate::util::{b64u, ct_eq, ct_eq_bytes, random};

type H = Hmac<Sha256>;

/// Below this a master key is guessable or was mistyped.
pub const MIN_MASTER_LEN: usize = 32;

const LABEL: &str = "l4f-accounts/v1/";
const TAG_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    TooShort,
    OldTooShort,
}

/// The HMAC state keyed with a master, so the raw master bytes are not kept and
/// every subkey is exactly `HMAC-SHA256(master, label)`.
#[derive(Clone)]
struct Master {
    mac: H,
    /// First byte of SHA-256(master): tells `open` which master sealed a blob
    /// without trying both. Two masters share it 1 time in 256; `open` then
    /// tries both and the tag decides.
    id: u8,
}

impl Master {
    fn new(master: &[u8]) -> Self {
        Self {
            mac: <H>::new_from_slice(master).expect("hmac accepts any key length"),
            id: Sha256::digest(master)[0],
        }
    }

    fn subkey(&self, purpose: &str) -> [u8; 32] {
        let mut m = self.mac.clone();
        m.update(LABEL.as_bytes());
        m.update(purpose.as_bytes());
        m.finalize().into_bytes().into()
    }
}

#[derive(Clone)]
pub struct Keys {
    current: Master,
    old: Option<Master>,
}

/// Never prints key material, so a `{:?}` in a log line is harmless.
impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("current_id", &self.current.id)
            .field("old_id", &self.old.as_ref().map(|o| o.id))
            .finish()
    }
}

fn aead(subkey: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, subkey).expect("32-byte ChaCha20-Poly1305 key"))
}

impl Keys {
    /// `old` is the previous master during a rotation. An `old` equal to
    /// `current` is dropped: it would only double every verification.
    pub fn new(current: &[u8], old: Option<&[u8]>) -> Result<Keys, KeyError> {
        if current.len() < MIN_MASTER_LEN {
            return Err(KeyError::TooShort);
        }
        if old.is_some_and(|o| o.len() < MIN_MASTER_LEN) {
            return Err(KeyError::OldTooShort);
        }
        Ok(Keys {
            current: Master::new(current),
            old: old.filter(|o| !ct_eq_bytes(o, current)).map(Master::new),
        })
    }

    /// `HMAC-SHA256(master, "l4f-accounts/v1/" + purpose)`, current master only:
    /// for anything new.
    pub fn subkey(&self, purpose: &str) -> [u8; 32] {
        self.current.subkey(purpose)
    }

    /// Current first, then old: for checking MACs that must survive a rotation.
    pub fn subkeys(&self, purpose: &str) -> Vec<[u8; 32]> {
        self.masters().map(|(m, _)| m.subkey(purpose)).collect()
    }

    /// `(master, is_old)`, current first.
    fn masters(&self) -> impl Iterator<Item = (&Master, bool)> {
        std::iter::once((&self.current, false)).chain(self.old.iter().map(|o| (o, true)))
    }

    /// ChaCha20-Poly1305 under `subkey(purpose)`: `[key id | nonce(12) | ct | tag]`.
    ///
    /// `aad` binds the blob to its row (the owner's id), so a sealed value copied
    /// into another user's row does not open. Random nonces are safe here: each
    /// purpose has its own key and none of them comes near 2^32 seals.
    pub fn seal(&self, purpose: &str, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce = random::<NONCE_LEN>();
        let mut out = Vec::with_capacity(1 + NONCE_LEN + plaintext.len() + TAG_LEN);
        out.push(self.current.id);
        out.extend_from_slice(&nonce);
        let mut body = plaintext.to_vec();
        aead(&self.current.subkey(purpose))
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut body)
            .expect("plaintext far below the ChaCha20-Poly1305 length limit");
        out.extend_from_slice(&body);
        out
    }

    /// The plaintext, and `true` when it was sealed under the old master so the
    /// caller should store `seal(..)` of it again before the old key is retired.
    pub fn open(&self, purpose: &str, aad: &[u8], sealed: &[u8]) -> Option<(Vec<u8>, bool)> {
        if sealed.len() < 1 + NONCE_LEN + TAG_LEN {
            return None;
        }
        let (id, rest) = (sealed[0], &sealed[1..]);
        let (nonce, body) = rest.split_at(NONCE_LEN);
        for (m, is_old) in self.masters().filter(|(m, _)| m.id == id) {
            let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
            let mut buf = body.to_vec();
            if let Ok(pt) = aead(&m.subkey(purpose)).open_in_place(nonce, Aad::from(aad), &mut buf) {
                return Some((pt.to_vec(), is_old));
            }
        }
        None
    }

    /// `b64u(HMAC-SHA256(subkey(purpose), msg))`, the full 32 bytes.
    pub fn sign(&self, purpose: &str, msg: &[u8]) -> String {
        b64u(&crate::util::mac_raw(&self.subkey(purpose), msg))
    }

    /// Constant-time check of a `sign` tag under the current, then the old master.
    /// Compared as text, so a second spelling of the same bytes (padding, stray
    /// low bits) is not accepted.
    pub fn verify(&self, purpose: &str, msg: &[u8], tag: &str) -> bool {
        self.subkeys(purpose).iter().any(|k| ct_eq(&b64u(&crate::util::mac_raw(k, msg)), tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &[u8] = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &[u8] = b"cccccccccccccccccccccccccccccccccccccccc";

    fn keys(cur: &[u8]) -> Keys {
        Keys::new(cur, None).unwrap()
    }

    #[test]
    fn short_master_is_refused() {
        assert_eq!(Keys::new(&A[..31], None).unwrap_err(), KeyError::TooShort);
        assert_eq!(Keys::new(b"", None).unwrap_err(), KeyError::TooShort);
        assert_eq!(Keys::new(A, Some(&B[..31])).unwrap_err(), KeyError::OldTooShort);
        assert!(Keys::new(&A[..32], None).is_ok(), "exactly 32 bytes is enough");
        assert!(Keys::new(&[7u8; 200], Some(B)).is_ok(), "long masters are fine");
    }

    #[test]
    fn subkey_is_the_documented_hmac() {
        let k = keys(A);
        assert_eq!(k.subkey("totp"), crate::util::mac_raw(A, b"l4f-accounts/v1/totp"));
        let long = [9u8; 100]; // longer than the HMAC block, so HMAC hashes it first
        assert_eq!(keys(&long).subkey("x"), crate::util::mac_raw(&long, b"l4f-accounts/v1/x"));
    }

    #[test]
    fn purposes_are_separated() {
        let k = keys(A);
        assert_ne!(k.subkey("totp"), k.subkey("oauth"));
        assert_ne!(k.subkey("totp"), k.subkey(""), "the empty purpose is its own key too");
        let sealed = k.seal("totp", b"uid", b"secret");
        assert_eq!(k.open("oauth", b"uid", &sealed), None, "a blob sealed for one purpose must not open for another");
        let tag = k.sign("email", b"msg");
        assert!(!k.verify("reset", b"msg", &tag), "a MAC for one purpose must not verify for another");
    }

    #[test]
    fn seal_open_round_trip() {
        let k = keys(A);
        for pt in [&b""[..], b"x", &[0xffu8; 1000]] {
            let sealed = k.seal("totp", b"user-1", pt);
            assert_eq!(sealed.len(), 1 + 12 + pt.len() + 16);
            assert_eq!(sealed[0], Sha256::digest(A)[0], "the id byte is the first byte of SHA-256(master)");
            assert_eq!(k.open("totp", b"user-1", &sealed), Some((pt.to_vec(), false)));
        }
        assert_ne!(k.seal("totp", b"", b"same"), k.seal("totp", b"", b"same"), "nonces must be fresh");
    }

    #[test]
    fn tampering_anywhere_fails_to_open() {
        let k = keys(A);
        let sealed = k.seal("totp", b"user-1", b"JBSWY3DPEHPK3PXP");
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 0x01;
            assert_eq!(k.open("totp", b"user-1", &bad), None, "flipping byte {i} (id, nonce, ct or tag) must fail");
        }
        assert_eq!(k.open("totp", b"user-2", &sealed), None, "wrong aad: copied into another user's row");
        assert_eq!(k.open("totp", b"", &sealed), None);
        assert_eq!(k.open("totp", b"user-1", &sealed[..sealed.len() - 1]), None, "truncated tag");
        assert_eq!(k.open("totp", b"user-1", &[sealed.clone(), vec![0]].concat()), None, "appended byte");
        for short in [&[][..], &sealed[..1], &sealed[..28]] {
            assert_eq!(k.open("totp", b"user-1", short), None, "{} bytes is too short", short.len());
        }
    }

    #[test]
    fn old_key_opens_and_asks_for_a_reseal() {
        let before = keys(A);
        let sealed = before.seal("totp", b"u", b"secret");
        let rotated = Keys::new(B, Some(A)).unwrap();
        assert_eq!(rotated.open("totp", b"u", &sealed), Some((b"secret".to_vec(), true)));
        let resealed = rotated.seal("totp", b"u", b"secret");
        assert_eq!(rotated.open("totp", b"u", &resealed), Some((b"secret".to_vec(), false)));
        assert_eq!(keys(B).open("totp", b"u", &sealed), None, "once the old key is gone the blob is dead");
        assert_eq!(Keys::new(C, Some(B)).unwrap().open("totp", b"u", &sealed), None, "an unrelated pair cannot open it");
    }

    /// Two masters can share an id byte; `open` must then try both rather than
    /// give up after the first.
    #[test]
    fn colliding_key_ids_still_open() {
        let id = |m: &[u8]| Sha256::digest(m)[0];
        let mut other = [0u8; 32];
        for i in 0u32.. {
            other[..4].copy_from_slice(&i.to_be_bytes());
            if id(&other) == id(A) && other[..] != *A {
                break;
            }
        }
        let sealed = keys(A).seal("p", b"", b"hi");
        let k = Keys::new(&other, Some(A)).unwrap();
        assert_eq!(k.current.id, k.old.as_ref().unwrap().id);
        assert_eq!(k.open("p", b"", &sealed), Some((b"hi".to_vec(), true)));
    }

    #[test]
    fn old_equal_to_current_is_dropped() {
        let k = Keys::new(A, Some(A)).unwrap();
        assert_eq!(k.subkeys("p").len(), 1);
        let sealed = k.seal("p", b"", b"x");
        assert_eq!(k.open("p", b"", &sealed), Some((b"x".to_vec(), false)), "never flags a reseal under itself");
    }

    #[test]
    fn subkeys_list_current_then_old() {
        let k = Keys::new(B, Some(A)).unwrap();
        assert_eq!(k.subkeys("p"), vec![keys(B).subkey("p"), keys(A).subkey("p")]);
        assert_eq!(keys(B).subkeys("p"), vec![keys(B).subkey("p")]);
    }

    #[test]
    fn sign_and_verify() {
        let k = keys(A);
        let tag = k.sign("email", b"uid|a@b.c|123");
        assert_eq!(tag.len(), 43, "full 32-byte MAC, unpadded base64url");
        assert_eq!(crate::util::b64u_dec(&tag).unwrap(), crate::util::mac_raw(&k.subkey("email"), b"uid|a@b.c|123"));
        assert!(k.verify("email", b"uid|a@b.c|123", &tag));
        assert!(!k.verify("email", b"uid|a@b.c|124", &tag), "other message");
        assert!(!keys(B).verify("email", b"uid|a@b.c|123", &tag), "other key");
        assert!(!k.verify("email", b"uid|a@b.c|123", &format!("{tag}=")), "a padded spelling is not the tag");
        assert!(!k.verify("email", b"uid|a@b.c|123", &tag[..42]), "truncated");
        for junk in ["", "AAAA", "not base64 !!"] {
            assert!(!k.verify("email", b"uid|a@b.c|123", junk), "{junk:?}");
        }
    }

    #[test]
    fn verify_survives_rotation() {
        let tag = keys(A).sign("email", b"m");
        assert!(Keys::new(B, Some(A)).unwrap().verify("email", b"m", &tag), "old-key tags still verify");
        assert!(!keys(B).verify("email", b"m", &tag), "until the old key is retired");
        assert_eq!(Keys::new(B, Some(A)).unwrap().sign("email", b"m"), keys(B).sign("email", b"m"), "new tags use the current key");
    }

    #[test]
    fn debug_does_not_print_key_material() {
        let s = format!("{:?}", Keys::new(A, Some(B)).unwrap());
        assert!(s.starts_with("Keys {") && !s.contains("aaaa") && !s.contains("97, 97"), "{s}");
    }
}
