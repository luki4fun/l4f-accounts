//! SSH key login: authorized_keys lines and `ssh-keygen -Y sign` signatures
//! (OpenSSH PROTOCOL.sshsig), verified with ring.
//!
//! Hand-rolled because the `ssh-key` crate verifies RSA through the `rsa` crate
//! (open Marvin advisory), and the wire format is a handful of length-prefixed
//! strings. Only ssh-ed25519, ssh-rsa (2048..=8192 bits, rsa-sha2-* signatures)
//! and ecdsa-sha2-nistp256 are accepted; sk-* keys and certificates are not.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use sha2::{Digest, Sha256, Sha512};

use crate::scope::invisible;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKey {
    pub algo: String,
    /// Wire-format public key: what `fingerprint` hashes and `verify` returns.
    pub blob: Vec<u8>,
    /// Becomes the key's label: whitespace runs collapsed, cut to 64 chars, and
    /// empty if it held a bidi control, U+200B, U+2060 or U+FEFF (`invisible`).
    /// Other invisible format characters such as ZWJ stay, so two labels can
    /// still look alike; the fingerprint is what tells keys apart.
    pub comment: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SshError {
    /// Bad armor, base64 or length field, trailing bytes, non-canonical encoding,
    /// or RSA numbers that are no RSA key (even modulus, even or tiny exponent).
    Malformed,
    /// Key type not accepted here (sk-*, DSA, other curves, certificates, or an
    /// authorized_keys options prefix in front of the type), a small-order
    /// Ed25519 point, or an RSA exponent above ring's 2^33 - 1.
    UnsupportedKey,
    /// RSA modulus outside 2048..=8192 bits.
    KeySize,
    Version,
    Namespace,
    HashAlg,
    /// Signature algorithm does not fit the key, or is SHA-1 `ssh-rsa`.
    SigAlg,
    BadSignature,
    /// Signed by a key that is not one of the enrolled ones.
    WrongKey,
}

const MAGIC: &[u8] = b"SSHSIG";
const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const END: &str = "-----END SSH SIGNATURE-----";
/// A pasted key or signature is a few KiB at most (RSA-8192 is about 3 KiB of
/// base64); anything longer is not worth decoding.
const MAX_INPUT: usize = 16 * 1024;
const ACCEPTED: [&str; 3] = ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"];
const MAX_COMMENT: usize = 64;
/// ring rejects larger RSA exponents at every verify.
const MAX_RSA_E: u64 = (1 << 33) - 1;

/// Parse an authorized_keys-style line: `type base64 [comment]`.
///
/// Every key that parses is one ring will verify with, except that P-256 and
/// Ed25519 points are only checked to lie on the curve at `verify`; an
/// off-curve key fails its enrolment signature with `BadSignature`.
pub fn parse_public_key(line: &str) -> Result<SshKey, SshError> {
    let line = line.trim();
    // A multi-line paste would otherwise turn the next key into this one's comment.
    let line_break = |c: char| c.is_control() && c != '\t' || matches!(c, '\u{2028}' | '\u{2029}');
    if line.len() > MAX_INPUT || line.chars().any(line_break) {
        return Err(SshError::Malformed);
    }
    let (algo, rest) = line.split_once([' ', '\t']).ok_or(SshError::Malformed)?;
    if !ACCEPTED.contains(&algo) {
        return Err(SshError::UnsupportedKey);
    }
    let rest = rest.trim_start_matches([' ', '\t']);
    let (b64, comment) = rest.split_once([' ', '\t']).unwrap_or((rest, ""));
    let blob = STANDARD.decode(b64).map_err(|_| SshError::Malformed)?;
    if parse_blob(&blob)?.algo() != algo {
        return Err(SshError::Malformed);
    }
    Ok(SshKey { algo: algo.to_string(), blob, comment: clean_comment(comment) })
}

/// Like the display-name rules (see `scope::clean_display_name`), but for a
/// label nobody typed into our form, so it is fixed instead of refused: too
/// long is cut, an `invisible` char empties it, and the key is kept. Line breaks
/// and other control chars never get here; they refuse the whole line.
fn clean_comment(raw: &str) -> String {
    let words: Vec<&str> = raw.split_whitespace().collect();
    if words.iter().any(|w| w.chars().any(invisible)) {
        return String::new();
    }
    let joined = words.join(" ");
    joined.chars().take(MAX_COMMENT).collect::<String>().trim_end().to_string()
}

/// The `SHA256:...` form `ssh-keygen -l` prints.
pub fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// Verify an armored SSHSIG over `message` in `namespace`, made by one of the
/// `enrolled` key blobs (the stored keys at login, the pasted key at
/// enrollment). Returns which one. A signature by any other key is `WrongKey`,
/// refused before any RSA or ECDSA work.
pub fn verify(armored: &str, namespace: &str, message: &[u8], enrolled: &[&[u8]]) -> Result<usize, SshError> {
    let pk = verify_by(armored, namespace, message, Some(enrolled))?;
    Ok(enrolled.iter().position(|k| *k == pk).expect("checked in verify_by"))
}

/// The signature check itself. With `enrolled` `None` it accepts whatever key
/// the signer embedded and returns it; only tests want that.
fn verify_by(armored: &str, namespace: &str, message: &[u8], enrolled: Option<&[&[u8]]>) -> Result<Vec<u8>, SshError> {
    // The namespace is the only domain separation (a login signature must not
    // double as a git or file signature); PROTOCOL.sshsig forbids an empty one.
    if namespace.is_empty() {
        return Err(SshError::Namespace);
    }
    let raw = dearmor(armored)?;
    let mut r = Rd(&raw);
    if r.take(6)? != MAGIC {
        return Err(SshError::Malformed);
    }
    if r.u32()? != 1 {
        return Err(SshError::Version);
    }
    let pk = r.string()?;
    let ns = r.string()?;
    let reserved = r.string()?;
    let hash_alg = r.string()?;
    let sig_field = r.string()?;
    r.end()?;

    if ns != namespace.as_bytes() {
        return Err(SshError::Namespace);
    }
    if enrolled.is_some_and(|keys| !keys.contains(&pk)) {
        return Err(SshError::WrongKey);
    }
    if !reserved.is_empty() {
        return Err(SshError::Malformed);
    }
    let digest = match hash_alg {
        b"sha256" => Sha256::digest(message).to_vec(),
        b"sha512" => Sha512::digest(message).to_vec(),
        _ => return Err(SshError::HashAlg),
    };
    let key = parse_blob(pk)?;
    let mut s = Rd(sig_field);
    let sig_algo = s.string()?;
    let sig = s.string()?;
    s.end()?;

    let mut signed = Vec::with_capacity(MAGIC.len() + 16 + ns.len() + hash_alg.len() + digest.len());
    signed.extend_from_slice(MAGIC);
    for field in [ns, reserved, hash_alg, &digest[..]] {
        put_string(&mut signed, field);
    }

    let ok = match (key, sig_algo) {
        (Key::Ed25519(k), b"ssh-ed25519") => {
            if sig.len() != 64 {
                return Err(SshError::Malformed);
            }
            UnparsedPublicKey::new(&signature::ED25519, k).verify(&signed, sig).is_ok()
        }
        (Key::Rsa { n, e }, b"rsa-sha2-256" | b"rsa-sha2-512") => {
            let params = if sig_algo == b"rsa-sha2-256" {
                &signature::RSA_PKCS1_2048_8192_SHA256
            } else {
                &signature::RSA_PKCS1_2048_8192_SHA512
            };
            // OpenSSH pads to the modulus length but accepts shorter signatures
            // from other signers; ring wants the exact length.
            if sig.len() > n.len() {
                return Err(SshError::Malformed);
            }
            let mut padded = vec![0u8; n.len() - sig.len()];
            padded.extend_from_slice(sig);
            RsaPublicKeyComponents { n, e }.verify(params, &signed, &padded).is_ok()
        }
        (Key::P256(q), b"ecdsa-sha2-nistp256") => {
            let mut rs = Rd(sig);
            let mut fixed = [0u8; 64];
            scalar32(rs.string()?, &mut fixed[..32])?;
            scalar32(rs.string()?, &mut fixed[32..])?;
            rs.end()?;
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, q).verify(&signed, &fixed).is_ok()
        }
        _ => return Err(SshError::SigAlg),
    };
    if !ok {
        return Err(SshError::BadSignature);
    }
    Ok(pk.to_vec())
}

enum Key<'a> {
    Ed25519(&'a [u8]),
    /// Both without the mpint sign byte, as ring wants them.
    Rsa {
        n: &'a [u8],
        e: &'a [u8],
    },
    /// Uncompressed SEC1 point.
    P256(&'a [u8]),
}

impl Key<'_> {
    fn algo(&self) -> &'static str {
        match self {
            Key::Ed25519(_) => "ssh-ed25519",
            Key::Rsa { .. } => "ssh-rsa",
            Key::P256(_) => "ecdsa-sha2-nistp256",
        }
    }
}

fn parse_blob(blob: &[u8]) -> Result<Key<'_>, SshError> {
    let mut r = Rd(blob);
    let key = match r.string()? {
        b"ssh-ed25519" => {
            let k = r.string()?;
            let point = <&[u8; 32]>::try_from(k).map_err(|_| SshError::Malformed)?;
            if small_order(point) {
                return Err(SshError::UnsupportedKey);
            }
            Key::Ed25519(k)
        }
        b"ssh-rsa" => {
            let e = mpint(r.string()?)?;
            let n = mpint(r.string()?)?;
            if !(2048..=8192).contains(&bits(n)) {
                return Err(SshError::KeySize);
            }
            // ring refuses these at every verify; refusing them here tells the
            // user at enrolment instead of failing as a bad signature. The length
            // check also keeps the u64 fold below from shifting bytes out.
            if e.len() > 5 {
                return Err(SshError::UnsupportedKey);
            }
            let ev = e.iter().fold(0u64, |a, b| a << 8 | u64::from(*b));
            if ev > MAX_RSA_E {
                return Err(SshError::UnsupportedKey);
            }
            if ev < 3 || ev & 1 == 0 || n.last().is_some_and(|b| b & 1 == 0) {
                return Err(SshError::Malformed);
            }
            Key::Rsa { n, e }
        }
        b"ecdsa-sha2-nistp256" => {
            if r.string()? != b"nistp256" {
                return Err(SshError::Malformed);
            }
            let q = r.string()?;
            if q.len() != 65 || q[0] != 4 {
                return Err(SshError::Malformed);
            }
            Key::P256(q)
        }
        _ => return Err(SshError::UnsupportedKey),
    };
    r.end()?;
    Ok(key)
}

/// The Ed25519 points of order 1, 2, 4 and 8, plus p and p+1 (0 and 1
/// unreduced): libsodium's `ge25519_has_small_order` list. ring accepts them.
/// Against the identity key (1 or p+1), R = identity, S = 0 verifies for any
/// message; against the others some small-order R with S = 0 does for most
/// messages, so such a key would let anyone in. Proof of possession at
/// enrolment is just as forgeable.
const ED25519_SMALL_ORDER: [[u8; 32]; 7] = [
    le(0x00, 0x00, 0x00),
    le(0x01, 0x00, 0x00),
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf,
        0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20,
        0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
    ],
    le(0xec, 0xff, 0x7f),
    le(0xed, 0xff, 0x7f),
    le(0xee, 0xff, 0x7f),
];

/// 32 little-endian bytes: `low`, then 30 times `fill`, then `high`.
const fn le(low: u8, fill: u8, high: u8) -> [u8; 32] {
    let mut b = [fill; 32];
    b[0] = low;
    b[31] = high;
    b
}

/// The top bit is the sign of x, which does not change the order.
fn small_order(k: &[u8; 32]) -> bool {
    ED25519_SMALL_ORDER.iter().any(|bad| k[..31] == bad[..31] && k[31] & 0x7f == bad[31])
}

fn dearmor(armored: &str) -> Result<Vec<u8>, SshError> {
    if armored.len() > MAX_INPUT {
        return Err(SshError::Malformed);
    }
    let body = armored.trim().strip_prefix(BEGIN).and_then(|s| s.strip_suffix(END)).ok_or(SshError::Malformed)?;
    // Whitespace (LF or CRLF, wherever a paste wrapped it) is the only slack.
    let b64: String = body.split_ascii_whitespace().collect();
    STANDARD.decode(b64).map_err(|_| SshError::Malformed)
}

/// A positive mpint in its one canonical encoding, returned without the sign
/// byte. Canonical only, so one key has exactly one blob and one fingerprint.
fn mpint(b: &[u8]) -> Result<&[u8], SshError> {
    match b {
        [0, rest @ ..] if rest.first().is_some_and(|x| x & 0x80 != 0) => Ok(rest),
        [x, ..] if *x != 0 && *x & 0x80 == 0 => Ok(b),
        // zero, negative, or padded with a needless zero byte
        _ => Err(SshError::Malformed),
    }
}

/// An ECDSA r or s mpint, left-padded into a 32-byte slot.
fn scalar32(m: &[u8], out: &mut [u8]) -> Result<(), SshError> {
    let v = mpint(m)?;
    if v.len() > out.len() {
        return Err(SshError::Malformed);
    }
    let pad = out.len() - v.len();
    out[pad..].copy_from_slice(v);
    Ok(())
}

fn bits(n: &[u8]) -> usize {
    n.first().map_or(0, |b| n.len() * 8 - b.leading_zeros() as usize)
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Reader over SSH wire data: every length is checked against what is left.
struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SshError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(SshError::Malformed)?;
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, SshError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> Result<&'a [u8], SshError> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn end(&self) -> Result<(), SshError> {
        if self.0.is_empty() { Ok(()) } else { Err(SshError::Malformed) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = "login@l4f.cc";
    const MSG: &[u8] = include_bytes!("../../tests/fixtures/sshsig/msg");

    const ED_PUB: &str = include_str!("../../tests/fixtures/sshsig/ed25519.pub");
    const ED_SIG: &str = include_str!("../../tests/fixtures/sshsig/ed25519.sig");
    const ED2_PUB: &str = include_str!("../../tests/fixtures/sshsig/ed25519b.pub");
    const ED2_SHA256_SIG: &str = include_str!("../../tests/fixtures/sshsig/ed25519b-sha256.sig");
    const RSA_PUB: &str = include_str!("../../tests/fixtures/sshsig/rsa3072.pub");
    const RSA_SIG: &str = include_str!("../../tests/fixtures/sshsig/rsa3072.sig");
    const RSA_SHA256_SIG: &str = include_str!("../../tests/fixtures/sshsig/rsa3072-sha256.sig");
    const RSA_RSASHA256_SIG: &str = include_str!("../../tests/fixtures/sshsig/rsa3072-rsasha256.sig");
    const EC_PUB: &str = include_str!("../../tests/fixtures/sshsig/ecdsa256.pub");
    const EC_SIG: &str = include_str!("../../tests/fixtures/sshsig/ecdsa256.sig");
    const EC_PADDED_SIG: &str = include_str!("../../tests/fixtures/sshsig/ecdsa256-padded.sig");
    const EC_SHORT_SIG: &str = include_str!("../../tests/fixtures/sshsig/ecdsa256-short.sig");
    const RSA1024_PUB: &str = include_str!("../../tests/fixtures/sshsig/rsa1024.pub");
    const RSA1024_SIG: &str = include_str!("../../tests/fixtures/sshsig/rsa1024.sig");
    /// A real signature whose first byte was 0x00, with that byte stripped
    /// (`ssh-keygen -Y verify` accepts it): what a signer that does not pad sends.
    const RSA2048_PUB: &str = include_str!("../../tests/fixtures/sshsig/rsa2048.pub");
    const RSA2048_SHORT_SIG: &str = include_str!("../../tests/fixtures/sshsig/rsa2048-short.sig");

    /// Every field of an SSHSIG, so a test can change one and re-armor.
    struct Parts {
        magic: Vec<u8>,
        version: u32,
        pk: Vec<u8>,
        ns: Vec<u8>,
        reserved: Vec<u8>,
        hash: Vec<u8>,
        algo: Vec<u8>,
        sig: Vec<u8>,
        /// Bytes after the signature inside the signature string.
        sig_tail: Vec<u8>,
    }

    fn split(armored: &str) -> Parts {
        let raw = dearmor(armored).expect("fixture dearmors");
        let mut r = Rd(&raw);
        let magic = r.take(6).unwrap().to_vec();
        let version = r.u32().unwrap();
        let mut f = || r.string().unwrap().to_vec();
        let (pk, ns, reserved, hash, sig_field) = (f(), f(), f(), f(), f());
        let mut s = Rd(&sig_field);
        let algo = s.string().unwrap().to_vec();
        let sig = s.string().unwrap().to_vec();
        Parts { magic, version, pk, ns, reserved, hash, algo, sig, sig_tail: s.0.to_vec() }
    }

    fn join_raw(p: &Parts) -> Vec<u8> {
        let mut sig_field = Vec::new();
        put_string(&mut sig_field, &p.algo);
        put_string(&mut sig_field, &p.sig);
        sig_field.extend_from_slice(&p.sig_tail);
        let mut out = p.magic.clone();
        out.extend_from_slice(&p.version.to_be_bytes());
        for f in [&p.pk, &p.ns, &p.reserved, &p.hash, &sig_field] {
            put_string(&mut out, f);
        }
        out
    }

    fn armor(raw: &[u8]) -> String {
        let b = STANDARD.encode(raw);
        let lines: Vec<&str> = b.as_bytes().chunks(70).map(|c| std::str::from_utf8(c).unwrap()).collect();
        format!("{BEGIN}\n{}\n{END}\n", lines.join("\n"))
    }

    fn join(p: &Parts) -> String {
        armor(&join_raw(p))
    }

    fn blob(pub_line: &str) -> Vec<u8> {
        parse_public_key(pub_line).expect("fixture key parses").blob
    }

    /// (r, s) of an ECDSA signature as the raw mpint bytes.
    fn ec_rs(p: &Parts) -> (Vec<u8>, Vec<u8>) {
        let mut r = Rd(&p.sig);
        (r.string().unwrap().to_vec(), r.string().unwrap().to_vec())
    }

    fn ec_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, r);
        put_string(&mut out, s);
        out
    }

    #[test]
    fn real_ssh_keygen_signatures_verify_and_return_the_signer() {
        for (name, sig, key) in [
            ("ed25519", ED_SIG, ED_PUB),
            ("ed25519 hashalg=sha256", ED2_SHA256_SIG, ED2_PUB),
            ("rsa-3072", RSA_SIG, RSA_PUB),
            ("rsa-3072 hashalg=sha256", RSA_SHA256_SIG, RSA_PUB),
            ("rsa-3072 rsa-sha2-256", RSA_RSASHA256_SIG, RSA_PUB),
            ("rsa-2048 leading zero byte dropped", RSA2048_SHORT_SIG, RSA2048_PUB),
            ("ecdsa-p256", EC_SIG, EC_PUB),
            ("ecdsa-p256 33-byte r,s", EC_PADDED_SIG, EC_PUB),
            ("ecdsa-p256 short r", EC_SHORT_SIG, EC_PUB),
        ] {
            assert_eq!(any(sig, NS, MSG), Ok(blob(key)), "{name} must verify and return its key");
        }
    }

    #[test]
    fn fixtures_cover_the_variants_they_claim() {
        assert_eq!(split(ED_SIG).hash, b"sha512", "ssh-keygen default");
        assert_eq!(split(ED2_SHA256_SIG).hash, b"sha256");
        assert_eq!(split(RSA_SIG).algo, b"rsa-sha2-512", "ssh-keygen signs sshsig with rsa-sha2-512");
        assert_eq!(split(RSA_SHA256_SIG).hash, b"sha256");
        assert_eq!(split(RSA_RSASHA256_SIG).algo, b"rsa-sha2-256");
        assert_eq!(split(RSA2048_SHORT_SIG).sig.len(), 255, "one byte short of the 2048-bit modulus");
        let (r, s) = ec_rs(&split(EC_SIG));
        assert_eq!((r.len(), s.len()), (32, 32));
        let (r, s) = ec_rs(&split(EC_PADDED_SIG));
        assert_eq!((r.len(), s.len()), (33, 33), "high bit set: sign byte present");
        let (r, s) = ec_rs(&split(EC_SHORT_SIG));
        assert!(r.len() < 32 || s.len() < 32, "a scalar with a leading zero byte dropped");
    }

    #[test]
    fn fingerprints_match_ssh_keygen() {
        // `ssh-keygen -lf <file>.pub`
        for (key, fp) in [
            (ED_PUB, "SHA256:6g1QEjnXZPzknBj72T63yEQMX3JVFKFh6OI642FQ+r4"),
            (ED2_PUB, "SHA256:uzGBnbonDAzvPorksKX6PSliaXrP/+B566UtbnFI/hw"),
            (RSA_PUB, "SHA256:jmZ8ZAIDfafYKP8Z7SmYQDyOgiQo/XVE6z1GNuugD3o"),
            (RSA2048_PUB, "SHA256:BTHfeR4kON9zlymoerbeIg7xkTqHfrgkkL6ZG+kPNvo"),
            (EC_PUB, "SHA256:YGwmEItGCnZJpzZE4PfmgLey1ItRLmnenbWNBJasdQw"),
        ] {
            assert_eq!(fingerprint(&blob(key)), fp);
        }
    }

    #[test]
    fn parses_authorized_keys_lines() {
        let k = parse_public_key(ED_PUB).unwrap();
        assert_eq!((k.algo.as_str(), k.comment.as_str()), ("ssh-ed25519", "ed@test"));
        assert_eq!(k.blob.len(), 4 + 11 + 4 + 32);
        assert_eq!(parse_public_key(RSA_PUB).unwrap().algo, "ssh-rsa");
        assert_eq!(parse_public_key(EC_PUB).unwrap().algo, "ecdsa-sha2-nistp256");

        let b64 = ED_PUB.split_whitespace().nth(1).unwrap();
        let bare = parse_public_key(&format!("ssh-ed25519 {b64}")).unwrap();
        assert_eq!((bare.blob, bare.comment), (k.blob.clone(), String::new()), "comment is optional");
        let spaced = parse_public_key(&format!("  ssh-ed25519\t {b64}  my laptop key \r\n")).unwrap();
        assert_eq!(spaced.comment, "my laptop key", "comment keeps inner spaces, outer whitespace trimmed");
    }

    #[test]
    fn rsa_1024_is_refused_at_parse_and_verify() {
        assert_eq!(parse_public_key(RSA1024_PUB), Err(SshError::KeySize));
        assert_eq!(any(RSA1024_SIG, NS, MSG), Err(SshError::KeySize), "a real 1024-bit signature");
    }

    #[test]
    fn parse_refuses_other_types_and_options() {
        let b64 = ED_PUB.split_whitespace().nth(1).unwrap();
        for (line, want) in [
            (format!("command=\"echo hi\" ssh-ed25519 {b64} x"), SshError::UnsupportedKey),
            (format!("restrict ssh-ed25519 {b64}"), SshError::UnsupportedKey),
            (format!("sk-ssh-ed25519@openssh.com {b64}"), SshError::UnsupportedKey),
            (format!("sk-ecdsa-sha2-nistp256@openssh.com {b64}"), SshError::UnsupportedKey),
            (format!("ssh-ed25519-cert-v01@openssh.com {b64}"), SshError::UnsupportedKey),
            (format!("ssh-dss {b64}"), SshError::UnsupportedKey),
            (format!("ecdsa-sha2-nistp384 {b64}"), SshError::UnsupportedKey),
            (format!("SSH-ED25519 {b64}"), SshError::UnsupportedKey),
            (format!("ssh-rsa {b64}"), SshError::Malformed),
            // With a comment, so the newline cannot just break the base64.
            (format!("ssh-ed25519 {b64} laptop\nssh-ed25519 {b64}"), SshError::Malformed),
            (format!("ssh-ed25519 {b64} x\u{1b}[31m"), SshError::Malformed),
            (format!("ssh-ed25519 {}", &b64[1..]), SshError::Malformed),
            (format!("ssh-ed25519 {b64}="), SshError::Malformed),
            ("ssh-ed25519 !!!!".to_string(), SshError::Malformed),
            ("ssh-ed25519".to_string(), SshError::Malformed),
            (String::new(), SshError::Malformed),
            (format!("ssh-ed25519 {b64} {}", "x".repeat(MAX_INPUT)), SshError::Malformed),
        ] {
            assert_eq!(parse_public_key(&line), Err(want), "{line:?}");
        }
    }

    fn key_line(algo: &str, fields: &[&[u8]]) -> String {
        let mut blob = Vec::new();
        for f in fields {
            put_string(&mut blob, f);
        }
        format!("{algo} {}", STANDARD.encode(blob))
    }

    #[test]
    fn parse_refuses_bad_blobs() {
        let ed = blob(ED_PUB);
        let rsa = blob(RSA_PUB);
        let ec = blob(EC_PUB);
        let mut trailing = ed.clone();
        trailing.push(0);
        let point = &ec[ec.len() - 65..];
        let mut not_04 = point.to_vec();
        not_04[0] = 2;
        let mut r = Rd(&rsa);
        let (_, e, n) = (r.string().unwrap(), r.string().unwrap(), r.string().unwrap());
        let mut negative_n = n.to_vec();
        negative_n.remove(0);
        let mut padded_n = vec![0u8];
        padded_n.extend_from_slice(n);
        let mut padded_e = vec![0u8];
        padded_e.extend_from_slice(e);

        for (name, line, want) in [
            ("trailing byte", format!("ssh-ed25519 {}", STANDARD.encode(&trailing)), SshError::Malformed),
            ("short ed25519", key_line("ssh-ed25519", &[b"ssh-ed25519", &[7; 31]]), SshError::Malformed),
            ("long ed25519", key_line("ssh-ed25519", &[b"ssh-ed25519", &[7; 33]]), SshError::Malformed),
            (
                "sk inner type",
                key_line("ssh-ed25519", &[b"sk-ssh-ed25519@openssh.com", &[7; 32], b"ssh:"]),
                SshError::UnsupportedKey,
            ),
            (
                "wrong curve",
                key_line("ecdsa-sha2-nistp256", &[b"ecdsa-sha2-nistp256", b"nistp384", point]),
                SshError::Malformed,
            ),
            (
                "compressed point",
                key_line("ecdsa-sha2-nistp256", &[b"ecdsa-sha2-nistp256", b"nistp256", &point[..33]]),
                SshError::Malformed,
            ),
            (
                "65 bytes, not 0x04",
                key_line("ecdsa-sha2-nistp256", &[b"ecdsa-sha2-nistp256", b"nistp256", &not_04]),
                SshError::Malformed,
            ),
            ("rsa negative n", key_line("ssh-rsa", &[b"ssh-rsa", e, &negative_n]), SshError::Malformed),
            ("rsa padded n", key_line("ssh-rsa", &[b"ssh-rsa", e, &padded_n]), SshError::Malformed),
            ("rsa padded e", key_line("ssh-rsa", &[b"ssh-rsa", &padded_e, n]), SshError::Malformed),
            ("rsa zero e", key_line("ssh-rsa", &[b"ssh-rsa", b"", n]), SshError::Malformed),
            ("rsa huge n", key_line("ssh-rsa", &[b"ssh-rsa", e, &[0x7f; 1025]]), SshError::KeySize),
        ] {
            assert_eq!(parse_public_key(&line), Err(want), "{name}");
        }
        for cut in 0..ed.len() {
            let line = format!("ssh-ed25519 {}", STANDARD.encode(&ed[..cut]));
            assert_eq!(parse_public_key(&line), Err(SshError::Malformed), "blob cut at {cut}");
        }
    }

    #[test]
    fn wrong_namespace_or_message_fails() {
        assert_eq!(any(ED_SIG, "file", MSG), Err(SshError::Namespace));
        assert_eq!(any(ED_SIG, "login@l4f.cc.evil", MSG), Err(SshError::Namespace));
        let mut p = split(ED_SIG);
        p.ns = vec![];
        assert_eq!(any(&join(&p), "", MSG), Err(SshError::Namespace), "empty, even if the signature's is too");
        for sig in [ED_SIG, RSA_SIG, EC_SIG] {
            assert_eq!(any(sig, NS, b"l4f-challenge-tesT"), Err(SshError::BadSignature));
            assert_eq!(any(sig, NS, b"l4f-challenge-test\n"), Err(SshError::BadSignature));
        }
    }

    /// Test shorthand: any embedded key, returned.
    fn any(armored: &str, namespace: &str, message: &[u8]) -> Result<Vec<u8>, SshError> {
        verify_by(armored, namespace, message, None)
    }

    #[test]
    fn only_an_enrolled_key_is_accepted() {
        let (ed, rsa) = (blob(ED_PUB), blob(RSA_PUB));
        assert_eq!(verify(ED_SIG, NS, MSG, &[&rsa, &ed]), Ok(1), "says which key signed");
        assert_eq!(verify(ED_SIG, NS, MSG, &[&rsa]), Err(SshError::WrongKey), "a valid signature by another key");
        assert_eq!(verify(ED_SIG, NS, MSG, &[]), Err(SshError::WrongKey));
        assert_eq!(verify(ED_SIG, NS, b"other", &[&ed]), Err(SshError::BadSignature));
    }

    #[test]
    fn signer_key_is_returned_not_assumed() {
        let signer = any(ED_SIG, NS, MSG).unwrap();
        assert_ne!(signer, blob(ED2_PUB), "caller compares against the stored key");
        assert_ne!(fingerprint(&signer), fingerprint(&blob(ED2_PUB)));
        let mut p = split(ED_SIG);
        p.pk = blob(ED2_PUB);
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::BadSignature), "same type, someone else's key");
        for (sig, other) in [(RSA_SIG, ED_PUB), (EC_SIG, RSA_PUB), (ED_SIG, EC_PUB)] {
            let mut p = split(sig);
            p.pk = blob(other);
            assert_eq!(any(&join(&p), NS, MSG), Err(SshError::SigAlg), "other key type in the envelope");
        }
    }

    #[test]
    fn tampered_signatures_fail() {
        for (name, sig) in [("ed25519", ED_SIG), ("rsa", RSA_SIG), ("ecdsa s", EC_SIG)] {
            let mut p = split(sig);
            // Near the end: signature bytes for every type, never a length field.
            let at = p.sig.len() - 2;
            p.sig[at] ^= 0x40;
            assert_eq!(any(&join(&p), NS, MSG), Err(SshError::BadSignature), "{name}");
        }
        let mut p = split(EC_SIG);
        p.sig[10] ^= 0x01;
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::BadSignature), "ecdsa r");
        let mut p = split(RSA_SIG);
        p.sig.pop();
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::BadSignature), "a cut-off signature");
        p.sig = vec![1; 385];
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::Malformed), "longer than the modulus");
        let mut p = split(ED_SIG);
        p.sig.push(0);
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::Malformed), "ed25519 sig must be 64 bytes");
    }

    #[test]
    fn short_rsa_signatures_are_left_padded_to_the_modulus() {
        let mut p = split(RSA2048_SHORT_SIG);
        p.sig.insert(0, 0);
        assert_eq!(any(&join(&p), NS, MSG), Ok(blob(RSA2048_PUB)), "the full-length form verifies too");
        p.sig.insert(0, 0);
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::Malformed), "but nothing longer than the modulus");
    }

    #[test]
    fn small_order_ed25519_keys_are_refused() {
        // libsodium's list, written out again so a typo in the constant shows.
        for hex_point in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let mut k = hex::decode(hex_point).unwrap();
            for sign in [0, 0x80] {
                k[31] |= sign;
                let line = key_line("ssh-ed25519", &[b"ssh-ed25519", &k]);
                assert_eq!(parse_public_key(&line), Err(SshError::UnsupportedKey), "{hex_point} sign {sign:#x}");
            }
        }
        // The forgery the list exists for: identity key, R = identity, S = 0.
        let identity = le(1, 0, 0);
        let mut p = split(ED_SIG);
        p.pk = Vec::new();
        put_string(&mut p.pk, b"ssh-ed25519");
        put_string(&mut p.pk, &identity);
        p.sig = [identity, [0; 32]].concat();
        let anything: &[u8] = b"anything at all";
        for msg in [MSG, anything] {
            assert_eq!(any(&join(&p), NS, msg), Err(SshError::UnsupportedKey), "forgery over {msg:?}");
        }
    }

    #[test]
    fn rsa_keys_ring_would_refuse_are_refused_at_parse() {
        let rsa = blob(RSA_PUB);
        let mut r = Rd(&rsa);
        let (_, e, n) = (r.string().unwrap(), r.string().unwrap(), r.string().unwrap());
        let mut even_n = n.to_vec();
        *even_n.last_mut().unwrap() &= 0xfe;
        let rsa_blob = |e: &[u8], n: &[u8]| {
            let mut b = Vec::new();
            for f in [b"ssh-rsa", e, n] {
                put_string(&mut b, f);
            }
            b
        };
        type Case<'a> = (&'a str, &'a [u8], &'a [u8], Result<(), SshError>);
        let cases: [Case; 9] = [
            ("e = 1", &[1], n, Err(SshError::Malformed)),
            ("even e", &[1, 0, 0], n, Err(SshError::Malformed)),
            ("e = 2^33 + 1", &[2, 0, 0, 0, 1], n, Err(SshError::UnsupportedKey)),
            ("6-byte e", &[1, 0, 0, 0, 0, 1], n, Err(SshError::UnsupportedKey)),
            ("9-byte e that folds to 3 in a u64", &[1, 0, 0, 0, 0, 0, 0, 0, 3], n, Err(SshError::UnsupportedKey)),
            ("even n", e, &even_n, Err(SshError::Malformed)),
            ("e = 3", &[3], n, Ok(())),
            ("e = 2^33 - 1", &[1, 0xff, 0xff, 0xff, 0xff], n, Ok(())),
            ("e = 65537", &[1, 0, 1], n, Ok(())),
        ];
        for (name, e, n, want) in cases {
            let line = format!("ssh-rsa {}", STANDARD.encode(rsa_blob(e, n)));
            assert_eq!(parse_public_key(&line).map(|_| ()), want, "{name}");
        }
        let mut p = split(RSA_SIG);
        p.pk = rsa_blob(&[1], n);
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::Malformed), "the signer key gets the same checks");
    }

    #[test]
    fn comments_are_held_to_display_name_rules() {
        let b64 = ED_PUB.split_whitespace().nth(1).unwrap();
        let with = |c: &str| parse_public_key(&format!("ssh-ed25519 {b64} {c}"));
        let long = "\u{e9}".repeat(100);
        let cut = "\u{e9}".repeat(64);
        // ZWJ and ZWNJ stay, as the `comment` doc says: emoji and Persian need them.
        let emoji = "\u{1f469}\u{200d}\u{1f4bb} laptop";
        let persian = "\u{645}\u{6cc}\u{200c}\u{62e}\u{648}\u{627}\u{647}\u{645}";
        for (c, want) in [
            (emoji, emoji),
            (persian, persian),
            ("admin\u{202e}moc.evil", ""),
            ("\u{2066}x\u{2069}", ""),
            ("a\u{200e}b", ""),
            ("a\u{200f}b", ""),
            ("\u{61c}x", ""),
            ("ad\u{200b}min", ""),
            ("x\u{2060}y", ""),
            ("\u{feff}laptop", ""),
            ("my\t\u{a0}  laptop", "my laptop"),
            ("Anna\u{2019} L\u{e4}ptop \u{1f511}", "Anna\u{2019} L\u{e4}ptop \u{1f511}"),
            (&long, &cut),
        ] {
            let k = with(c).expect("the key survives its comment");
            assert_eq!((k.blob, k.comment.as_str()), (blob(ED_PUB), want), "{c:?}");
        }
        let a63 = "a".repeat(63);
        assert_eq!(with(&format!("{a63} b")).unwrap().comment, a63, "no blank left at the cut");
        assert_eq!(with("x\u{2028}ssh-ed25519 AAAA"), Err(SshError::Malformed), "U+2028 is a line break");
        assert_eq!(with("x\u{2029}ssh-ed25519 AAAA"), Err(SshError::Malformed), "so is U+2029");
        // At either end it is one line plus its terminator, like a trailing "\n".
        assert_eq!(with("x\u{2029}").unwrap().comment, "x", "trimmed like a final newline");
    }

    #[test]
    fn every_flipped_bit_and_every_truncation_is_rejected() {
        for sig in [ED_SIG, RSA_SIG, EC_SIG] {
            let raw = dearmor(sig).unwrap();
            for i in 0..raw.len() {
                let mut bad = raw.clone();
                bad[i] ^= 0x01;
                assert!(any(&armor(&bad), NS, MSG).is_err(), "flip at byte {i} accepted");
                assert!(any(&armor(&raw[..i]), NS, MSG).is_err(), "truncation at {i} accepted");
            }
        }
    }

    #[test]
    fn version_magic_and_reserved_are_checked() {
        let mut p = split(ED_SIG);
        p.version = 2;
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::Version));
        let mut p = split(ED_SIG);
        p.version = 0;
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::Version));
        let mut p = split(ED_SIG);
        p.magic = b"SSHSIH".to_vec();
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::Malformed));
        let mut p = split(ED_SIG);
        p.reserved = b"x".to_vec();
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::Malformed));
    }

    #[test]
    fn hash_and_signature_algorithms_are_pinned() {
        let hashes: [&[u8]; 4] = [b"sha1", b"SHA512", b"sha384", b""];
        for h in hashes {
            let mut p = split(ED_SIG);
            p.hash = h.to_vec();
            assert_eq!(any(&join(&p), NS, MSG), Err(SshError::HashAlg), "{:?}", String::from_utf8_lossy(h));
        }
        let mut p = split(RSA_SIG);
        p.algo = b"ssh-rsa".to_vec();
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::SigAlg), "SHA-1 RSA is refused");
        let swaps: [(&str, &[u8]); 5] = [
            (ED_SIG, b"rsa-sha2-512"),
            (ED_SIG, b"ecdsa-sha2-nistp256"),
            (RSA_SIG, b"ssh-ed25519"),
            (EC_SIG, b"ecdsa-sha2-nistp384"),
            (EC_SIG, b"rsa-sha2-256"),
        ];
        for (sig, algo) in swaps {
            let mut p = split(sig);
            p.algo = algo.to_vec();
            assert_eq!(any(&join(&p), NS, MSG), Err(SshError::SigAlg), "{:?}", String::from_utf8_lossy(algo));
        }
        let mut p = split(ED_SIG);
        let mut sk = Vec::new();
        let fields: [&[u8]; 3] = [b"sk-ssh-ed25519@openssh.com", &[7; 32], b"ssh:"];
        for f in fields {
            put_string(&mut sk, f);
        }
        p.pk = sk;
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::UnsupportedKey));
    }

    #[test]
    fn trailing_bytes_are_rejected_everywhere() {
        let mut raw = dearmor(ED_SIG).unwrap();
        raw.push(0);
        assert_eq!(any(&armor(&raw), NS, MSG), Err(SshError::Malformed), "after the envelope");
        let mut p = split(ED_SIG);
        p.sig_tail = vec![0];
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::Malformed), "inside the signature string");
        let mut p = split(ED_SIG);
        p.pk.push(0);
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::Malformed), "inside the public key");
        let mut p = split(EC_SIG);
        p.sig.push(0);
        assert_eq!(any(&join(&p), NS, MSG), Err(SshError::Malformed), "inside the ECDSA r,s string");
    }

    #[test]
    fn ecdsa_scalars_must_be_canonical_and_fit() {
        let p = split(EC_SIG);
        let (r, s) = ec_rs(&p);
        let mut padded_r = vec![0u8];
        padded_r.extend_from_slice(&r);
        let mut wide_r = vec![0x01u8];
        wide_r.extend_from_slice(&r);
        let mut wider_r = vec![0u8, 0x80];
        wider_r.extend_from_slice(&r);
        for (name, r) in [
            ("leading zero before a clear high bit", padded_r),
            ("33 bytes of value", wide_r),
            ("34 bytes", wider_r),
            ("zero", Vec::new()),
            ("negative", vec![0x80; 32]),
        ] {
            let mut q = split(EC_SIG);
            q.sig = ec_sig(&r, &s);
            assert_eq!(any(&join(&q), NS, MSG), Err(SshError::Malformed), "{name}");
        }
        let mut q = split(EC_SIG);
        q.sig = ec_sig(&r, &s);
        assert!(any(&join(&q), NS, MSG).is_ok(), "rebuilding untouched r,s round-trips");
    }

    #[test]
    fn armor_is_strict_but_tolerates_line_endings() {
        let crlf = ED_SIG.replace('\n', "\r\n");
        assert!(any(&format!("\n  {crlf}  \n"), NS, MSG).is_ok(), "CRLF paste with surrounding blanks");
        let at_cap = format!("{ED_SIG}{}", "\n".repeat(MAX_INPUT - ED_SIG.len()));
        assert!(any(&at_cap, NS, MSG).is_ok(), "exactly MAX_INPUT bytes is still allowed");
        let raw = dearmor(ED_SIG).unwrap();
        let one_line = format!("{BEGIN}{}{END}", STANDARD.encode(&raw));
        assert!(any(&one_line, NS, MSG).is_ok(), "line breaks are optional");

        let body = ED_SIG.trim().strip_prefix(BEGIN).unwrap().strip_suffix(END).unwrap();
        for (name, bad) in [
            ("no armor", body.to_string()),
            ("no end", format!("{BEGIN}{body}")),
            ("wrong label", ED_SIG.replace("SSH SIGNATURE", "PGP SIGNATURE")),
            ("text before", format!("Signing file msg\n{ED_SIG}")),
            ("bad base64", format!("{BEGIN}\n{}\n{END}", body.trim().replacen('U', "*", 1))),
            ("over-padded", format!("{BEGIN}\n{}=\n{END}", body.trim())),
            ("unpadded", format!("{BEGIN}\n{}\n{END}", STANDARD_NO_PAD.encode(&raw))),
            // Valid but for trailing blanks: only the size cap can refuse it.
            ("oversized", format!("{ED_SIG}{}", "\n".repeat(MAX_INPUT))),
            ("empty", String::new()),
        ] {
            assert_eq!(any(&bad, NS, MSG), Err(SshError::Malformed), "{name}");
        }
    }

    #[test]
    fn length_fields_cannot_overrun() {
        for sig in [ED_SIG, EC_SIG] {
            let p = split(sig);
            let raw = join_raw(&p);
            // Every u32 length prefix: the five envelope strings, then the
            // algorithm and signature strings inside the last one.
            let mut at = vec![];
            let mut off = 10;
            for f in [&p.pk, &p.ns, &p.reserved, &p.hash] {
                at.push(off);
                off += 4 + f.len();
            }
            at.extend([off, off + 4, off + 8 + p.algo.len()]);
            for o in at {
                for v in [u32::MAX, raw.len() as u32] {
                    let mut bad = raw.clone();
                    bad[o..o + 4].copy_from_slice(&v.to_be_bytes());
                    assert_eq!(any(&armor(&bad), NS, MSG), Err(SshError::Malformed), "length {v} at {o}");
                }
            }
        }
    }

    #[test]
    fn mpint_accepts_only_canonical_positive_values() {
        assert_eq!(mpint(&[0x01]), Ok(&[0x01][..]));
        assert_eq!(mpint(&[0x00, 0x80]), Ok(&[0x80][..]));
        assert_eq!(mpint(&[0x7f, 0x00]), Ok(&[0x7f, 0x00][..]));
        let bads: [&[u8]; 6] = [&[], &[0x00], &[0x00, 0x7f], &[0x80], &[0xff, 0x01], &[0x00, 0x00, 0x80]];
        for bad in bads {
            assert_eq!(mpint(bad), Err(SshError::Malformed), "{bad:02x?}");
        }
        assert_eq!(bits(&[0x01, 0, 0]), 17);
        assert_eq!(bits(&[0x80; 256]), 2048);
        assert_eq!(bits(&[]), 0);
    }
}
