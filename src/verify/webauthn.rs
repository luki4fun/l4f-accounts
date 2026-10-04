//! WebAuthn registration and assertion checks (W3C WebAuthn L3 §7.1, §7.2) on ring.
//!
//! Attestation `none` only, and only ES256 (-7) and RS256 (-257). The public key
//! comes from `response.publicKey` in the browser's `toJSON()`, which is SPKI DER,
//! so neither the attestation object nor the COSE key needs a CBOR parser. With
//! attestation `none` nothing vouches for the authenticator anyway: the browser's
//! SPKI is as trustworthy as the COSE key it was derived from.

use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use serde::{Deserialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::util::{b64u, b64u_dec, ct_eq};

pub const ES256: i64 = -7;
pub const RS256: i64 = -257;

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;
const ED: u8 = 0x80;

/// A real credential is a few KiB at most (an 8192-bit RSA key, a 1023-byte id).
const MAX_JSON: usize = 64 * 1024;

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

#[derive(Debug, Clone, Copy)]
pub struct Rp<'a> {
    /// The RP ID, e.g. "l4f.cc". Never an IP address: browsers refuse those.
    pub id: &'a str,
    /// Exact origins the ceremony may run on, e.g. "https://l4f.cc".
    pub origins: &'a [String],
}

/// With attestation `none` nothing in here is signed: key, flags and counter are
/// the client's word. Only a later [`verify_assertion`] proves the key is held, so
/// a registration is never a login or an MFA step by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCredential {
    pub id: Vec<u8>,
    pub alg: i64,
    /// SPKI DER, as handed to [`verify_assertion`] later.
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backed_up: bool,
    pub user_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    pub sign_count: u32,
    pub user_verified: bool,
    /// Compare with the stored `backup_eligible`: it never changes for a
    /// credential (L3 §7.2), so a flip means another authenticator.
    pub backup_eligible: bool,
    pub backed_up: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WebauthnError {
    /// Unparsable JSON, base64url or authenticator data, or impossible flags.
    Malformed,
    /// Credential type is not "public-key", or the ceremony type is wrong.
    Type,
    Challenge,
    Origin,
    /// Run inside a cross-origin iframe, which this site never asks for.
    CrossOrigin,
    RpId,
    UserPresence,
    UserVerification,
    /// Ids disagree, or the id is outside 16..=1023 bytes.
    CredentialId,
    /// The algorithm does not match the key.
    Algorithm,
    /// The browser gave no SPKI, or the authenticator picked an algorithm we did not offer.
    Unsupported,
    /// The SPKI is malformed, not P-256, or a weak RSA key.
    Key,
    Signature,
    /// The signature counter went backwards: two copies of one key exist.
    Cloned,
}

use WebauthnError as E;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateJson {
    id: String,
    raw_id: String,
    #[serde(rename = "type")]
    typ: String,
    response: CreateResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    authenticator_data: String,
    /// Absent (or null) when the browser cannot express the key as SPKI.
    public_key: Option<String>,
    public_key_algorithm: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetJson {
    id: String,
    raw_id: String,
    #[serde(rename = "type")]
    typ: String,
    response: GetResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    user_handle: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
    cross_origin: Option<bool>,
    top_origin: Option<String>,
}

/// `json` is the browser's `credential.toJSON()` from `create()`. The caller still
/// has to refuse an id that is already registered (a plain INSERT does that).
pub fn verify_registration(rp: &Rp, expected_challenge: &[u8], json: &str, require_uv: bool) -> Result<NewCredential, WebauthnError> {
    let j: CreateJson = parse(json)?;
    if j.typ != "public-key" {
        return Err(E::Type);
    }
    let id = credential_id(&j.id, &j.raw_id)?;
    let client_data = dec(&j.response.client_data_json)?;
    check_client_data(rp, expected_challenge, &client_data, "webauthn.create")?;
    let auth_data = dec(&j.response.authenticator_data)?;
    let ad = check_auth_data(rp, &auth_data, require_uv)?;
    // The credential id is all we read from the attested credential data.
    let attested_id = ad.cred_id.ok_or(E::Malformed)?;
    if attested_id != id {
        return Err(E::CredentialId);
    }
    let alg = j.response.public_key_algorithm;
    if alg != ES256 && alg != RS256 {
        return Err(E::Unsupported);
    }
    let spki = dec(j.response.public_key.as_deref().ok_or(E::Unsupported)?)?;
    let key = parse_spki(&spki)?;
    key.check_alg(alg)?;
    if let Spki::P256(point) = key
        && !p256_point_on_curve(point)
    {
        return Err(E::Key);
    }
    Ok(NewCredential {
        id,
        alg,
        public_key: spki,
        sign_count: ad.sign_count,
        backup_eligible: ad.flags & BE != 0,
        backed_up: ad.flags & BS != 0,
        user_verified: ad.flags & UV != 0,
    })
}

/// Discoverable login sends no allow-list, so the caller learns which stored key
/// to load only from the response itself. Nothing here is verified yet: load the
/// key stored under this credential id; the user handle only says whose it should be.
pub fn parse_assertion_ids(json: &str) -> Result<(Vec<u8>, Option<Vec<u8>>), WebauthnError> {
    assertion_ids(&parse(json)?)
}

/// `json` is `credential.toJSON()` from `get()`. The credential id and the user
/// handle are not signed, so `stored_spki` must be the key stored under exactly
/// this credential id, and the user is that key's owner. In a discoverable login
/// the user handle must be present and be the owner's (W3C L3 §7.2 step 6); with
/// an allow-list it must be absent or the owner's. For MFA and step-up the
/// owner must also be the account already signed in. Then store `sign_count`.
pub fn verify_assertion(
    rp: &Rp,
    expected_challenge: &[u8],
    json: &str,
    stored_alg: i64,
    stored_spki: &[u8],
    stored_sign_count: u32,
    require_uv: bool,
) -> Result<Assertion, WebauthnError> {
    let j: GetJson = parse(json)?;
    let (credential_id, user_handle) = assertion_ids(&j)?;
    let client_data = dec(&j.response.client_data_json)?;
    check_client_data(rp, expected_challenge, &client_data, "webauthn.get")?;
    let auth_data = dec(&j.response.authenticator_data)?;
    let ad = check_auth_data(rp, &auth_data, require_uv)?;
    if ad.cred_id.is_some() {
        return Err(E::Malformed);
    }
    let sig = dec(&j.response.signature)?;
    let key = parse_spki(stored_spki)?;
    key.check_alg(stored_alg)?;
    let (algorithm, public_key): (&'static dyn VerificationAlgorithm, &[u8]) = match key {
        Spki::P256(point) => (&signature::ECDSA_P256_SHA256_ASN1, point),
        Spki::Rsa(rsa_public_key) => (&signature::RSA_PKCS1_2048_8192_SHA256, rsa_public_key),
    };
    let signed = [&auth_data[..], &Sha256::digest(&client_data)[..]].concat();
    UnparsedPublicKey::new(algorithm, public_key).verify(&signed, &sig).map_err(|_| E::Signature)?;
    // W3C L3 §7.2: a counter in use must rise. Synced passkeys report 0 forever and
    // pass; a used counter falling back to 0 is a clone too, or the 0 it stores
    // would switch this check off for good.
    if stored_sign_count != 0 && ad.sign_count <= stored_sign_count {
        return Err(E::Cloned);
    }
    Ok(Assertion {
        credential_id,
        user_handle,
        sign_count: ad.sign_count,
        user_verified: ad.flags & UV != 0,
        backup_eligible: ad.flags & BE != 0,
        backed_up: ad.flags & BS != 0,
    })
}

fn parse<T: DeserializeOwned>(json: &str) -> Result<T, WebauthnError> {
    if json.len() > MAX_JSON {
        return Err(E::Malformed);
    }
    serde_json::from_str(json).map_err(|_| E::Malformed)
}

fn dec(s: &str) -> Result<Vec<u8>, WebauthnError> {
    b64u_dec(s).ok_or(E::Malformed)
}

/// `id` and `rawId` carry the same bytes; a response where they differ was not
/// built by a browser.
fn credential_id(id: &str, raw_id: &str) -> Result<Vec<u8>, WebauthnError> {
    let raw = dec(raw_id)?;
    if b64u_dec(id).as_deref() != Some(&raw[..]) || !(16..=1023).contains(&raw.len()) {
        return Err(E::CredentialId);
    }
    Ok(raw)
}

fn assertion_ids(j: &GetJson) -> Result<(Vec<u8>, Option<Vec<u8>>), WebauthnError> {
    if j.typ != "public-key" {
        return Err(E::Type);
    }
    let id = credential_id(&j.id, &j.raw_id)?;
    // U2F-era authenticators return an empty handle where the spec says null.
    let handle = match j.response.user_handle.as_deref() {
        None | Some("") => None,
        Some(h) => {
            let h = dec(h)?;
            if h.len() > 64 {
                return Err(E::Malformed);
            }
            Some(h)
        }
    };
    Ok((id, handle))
}

fn check_client_data(rp: &Rp, expected_challenge: &[u8], raw: &[u8], typ: &str) -> Result<(), WebauthnError> {
    let c: ClientData = serde_json::from_slice(raw).map_err(|_| E::Malformed)?;
    if c.typ != typ {
        return Err(E::Type);
    }
    // An empty expected challenge would match an empty one from the client.
    if expected_challenge.len() < 16 || !ct_eq(&c.challenge, &b64u(expected_challenge)) {
        return Err(E::Challenge);
    }
    if !rp.origins.contains(&c.origin) {
        return Err(E::Origin);
    }
    if c.cross_origin == Some(true) || c.top_origin.is_some() {
        return Err(E::CrossOrigin);
    }
    Ok(())
}

struct AuthData<'a> {
    flags: u8,
    sign_count: u32,
    /// From the attested credential data, present only when AT is set.
    cred_id: Option<&'a [u8]>,
}

/// rpIdHash(32) | flags(1) | signCount(4) | [aaguid(16) | idLen(2) | id | COSE key] | [extensions]
fn check_auth_data<'a>(rp: &Rp, ad: &'a [u8], require_uv: bool) -> Result<AuthData<'a>, WebauthnError> {
    if ad.len() < 37 {
        return Err(E::Malformed);
    }
    let flags = ad[32];
    let sign_count = u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]);
    let rest = &ad[37..];
    let cred_id = if flags & AT != 0 {
        let len = match rest.get(16..18) {
            Some(&[hi, lo]) => usize::from(u16::from_be_bytes([hi, lo])),
            _ => return Err(E::Malformed),
        };
        // At least one byte must follow: the COSE key, which we do not parse.
        let after = &rest[18..];
        if after.len() <= len {
            return Err(E::Malformed);
        }
        Some(&after[..len])
    } else {
        // Without attested data only extensions may follow, and only when ED says so.
        if (flags & ED != 0) == rest.is_empty() {
            return Err(E::Malformed);
        }
        None
    };
    if flags & BS != 0 && flags & BE == 0 {
        return Err(E::Malformed);
    }
    if ad[..32] != Sha256::digest(rp.id.as_bytes())[..] {
        return Err(E::RpId);
    }
    if flags & UP == 0 {
        return Err(E::UserPresence);
    }
    if require_uv && flags & UV == 0 {
        return Err(E::UserVerification);
    }
    Ok(AuthData { flags, sign_count, cred_id })
}

enum Spki<'a> {
    /// The 65-byte uncompressed point.
    P256(&'a [u8]),
    /// The DER RSAPublicKey ring verifies with.
    Rsa(&'a [u8]),
}

impl Spki<'_> {
    fn check_alg(&self, alg: i64) -> Result<(), WebauthnError> {
        match (self, alg) {
            (Spki::P256(_), ES256) | (Spki::Rsa(_), RS256) => Ok(()),
            _ => Err(E::Algorithm),
        }
    }
}

fn parse_spki(spki: &[u8]) -> Result<Spki<'_>, WebauthnError> {
    spki_key(spki).ok_or(E::Key)
}

/// SEQUENCE { SEQUENCE { OID, params }, BIT STRING }, accepting only P-256 and
/// rsaEncryption keys, with every length exact.
fn spki_key(spki: &[u8]) -> Option<Spki<'_>> {
    let (outer, rest) = tlv(spki, 0x30)?;
    let (alg_id, outer) = tlv(outer, 0x30)?;
    let (bits, outer) = tlv(outer, 0x03)?;
    let (oid, params) = tlv(alg_id, 0x06)?;
    if !rest.is_empty() || !outer.is_empty() {
        return None;
    }
    // The leading byte counts unused bits: always 0 for a key.
    let [0, key @ ..] = bits else { return None };
    match oid {
        OID_EC_PUBLIC_KEY => {
            let (curve, rest) = tlv(params, 0x06)?;
            (curve == OID_P256 && rest.is_empty() && key.len() == 65 && key[0] == 0x04).then_some(Spki::P256(key))
        }
        // RFC 3279 §2.3.1: the parameters MUST be NULL.
        OID_RSA => (params == [0x05, 0x00] && rsa_key_ok(key) == Some(true)).then_some(Spki::Rsa(key)),
        _ => None,
    }
}

/// RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }. The bounds are the ones
/// ring enforces when it verifies, so a stored key can always be used.
fn rsa_key_ok(der: &[u8]) -> Option<bool> {
    let (seq, rest) = tlv(der, 0x30)?;
    let (n, seq) = tlv(seq, 0x02)?;
    let (e, seq) = tlv(seq, 0x02)?;
    let (n, e) = (positive(n)?, positive(e)?);
    let n_bits = n.len() * 8 - n[0].leading_zeros() as usize;
    let e = (e.len() <= 5).then(|| e.iter().fold(0u64, |v, &b| (v << 8) | u64::from(b)))?;
    let n_odd = n.last().is_some_and(|b| b & 1 == 1);
    Some(rest.is_empty() && seq.is_empty() && (2048..=8192).contains(&n_bits) && n_odd && (3..1 << 33).contains(&e) && e & 1 == 1)
}

/// The magnitude of a positive, minimally encoded DER INTEGER.
fn positive(int: &[u8]) -> Option<&[u8]> {
    match int {
        [0, rest @ ..] if rest.first().is_some_and(|b| b & 0x80 != 0) => Some(rest),
        // zero, a superfluous leading zero, a negative number, or nothing
        [] | [0, ..] => None,
        [b, ..] if b & 0x80 != 0 => None,
        _ => Some(int),
    }
}

/// One DER element with the expected tag: (contents, what follows). Only
/// definite, minimal lengths, so two parsers can never read one key differently.
fn tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&[t, first], rest) = input.split_first_chunk::<2>()?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => match rest {
            [l @ 0x80..=0xff, rest @ ..] => (usize::from(*l), rest),
            _ => return None,
        },
        0x82 => match rest {
            [hi @ 1..=0xff, lo, rest @ ..] => (usize::from(u16::from_be_bytes([*hi, *lo])), rest),
            _ => return None,
        },
        // indefinite (0x80) or longer than any key we accept
        _ => return None,
    };
    (t == tag && rest.len() >= len).then(|| rest.split_at(len))
}

/// ring only checks the point when it verifies a signature; checking now keeps
/// a credential that could never sign in out of the database. One ECDH with a
/// throwaway key is ring's public way to validate a P-256 point.
fn p256_point_on_curve(point: &[u8]) -> bool {
    use ring::agreement::{self, ECDH_P256};
    let Ok(mine) = agreement::EphemeralPrivateKey::generate(&ECDH_P256, &ring::rand::SystemRandom::new()) else {
        return false;
    };
    agreement::agree_ephemeral(mine, &agreement::UnparsedPublicKey::new(&ECDH_P256, point), |_| ()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
    };
    use serde_json::{Value, json};

    const RP_ID: &str = "l4f.cc";
    const ORIGIN: &str = "https://l4f.cc";
    const CHALLENGE: [u8; 32] = [7; 32];
    const P256_SPKI_PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
        0x07, 0x03, 0x42, 0x00,
    ];
    /// Test-only key from `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER`,
    /// then `openssl pkcs8 -topk8 -nocrypt`: OpenSSL 3.0 writes PKCS#1 DER, ring only reads PKCS#8.
    const RSA_PKCS8: &[u8] = include_bytes!("../../tests/fixtures/webauthn/rsa2048.pk8");
    /// Its public half, from `openssl pkey -pubout -outform DER`: the encoding a real stack emits.
    const RSA_SPKI: &[u8] = include_bytes!("../../tests/fixtures/webauthn/rsa2048.spki");
    /// The first bytes of an ES256 COSE key; only ever skipped, never parsed.
    const COSE_STUB: &[u8] = &[0xa5, 0x01, 0x02, 0x03, 0x26];

    fn origins() -> Vec<String> {
        vec![ORIGIN.to_string(), "http://localhost:8099".to_string()]
    }

    enum Signer {
        Ec(EcdsaKeyPair),
        Rsa(RsaKeyPair),
    }

    impl Signer {
        fn es256() -> Signer {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            Signer::Ec(EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap())
        }

        fn rs256() -> Signer {
            Signer::Rsa(RsaKeyPair::from_pkcs8(RSA_PKCS8).unwrap())
        }

        fn alg(&self) -> i64 {
            match self {
                Signer::Ec(_) => ES256,
                Signer::Rsa(_) => RS256,
            }
        }

        fn spki(&self) -> Vec<u8> {
            match self {
                Signer::Ec(k) => [&P256_SPKI_PREFIX[..], k.public_key().as_ref()].concat(),
                Signer::Rsa(_) => RSA_SPKI.to_vec(),
            }
        }

        fn sign(&self, msg: &[u8]) -> Vec<u8> {
            let rng = SystemRandom::new();
            match self {
                Signer::Ec(k) => k.sign(&rng, msg).unwrap().as_ref().to_vec(),
                Signer::Rsa(k) => {
                    let mut sig = vec![0; k.public().modulus_len()];
                    k.sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig).unwrap();
                    sig
                }
            }
        }
    }

    /// Everything an authenticator and browser would put into one ceremony;
    /// tests change one field and expect exactly that check to fire.
    struct Ceremony {
        typ: &'static str,
        challenge: Vec<u8>,
        origin: String,
        /// Raw JSON members appended to clientDataJSON, e.g. `,"crossOrigin":true`.
        client_extra: String,
        rp_id: &'static str,
        flags: u8,
        sign_count: u32,
        cred_id: Vec<u8>,
        /// Raw bytes after the attested data (or the counter): extension CBOR.
        extensions: Vec<u8>,
    }

    impl Ceremony {
        fn create() -> Ceremony {
            Ceremony {
                typ: "webauthn.create",
                challenge: CHALLENGE.to_vec(),
                origin: ORIGIN.to_string(),
                client_extra: String::new(),
                rp_id: RP_ID,
                flags: UP | UV | AT,
                sign_count: 0,
                cred_id: (0..32).collect(),
                extensions: Vec::new(),
            }
        }

        fn get() -> Ceremony {
            Ceremony { typ: "webauthn.get", flags: UP | UV, sign_count: 5, ..Ceremony::create() }
        }

        fn client_data(&self) -> Vec<u8> {
            format!(r#"{{"type":"{}","challenge":"{}","origin":"{}"{}}}"#, self.typ, b64u(&self.challenge), self.origin, self.client_extra)
                .into_bytes()
        }

        fn auth_data(&self) -> Vec<u8> {
            let mut ad = Sha256::digest(self.rp_id.as_bytes()).to_vec();
            ad.push(self.flags);
            ad.extend(self.sign_count.to_be_bytes());
            if self.flags & AT != 0 {
                ad.extend([0xaa; 16]);
                ad.extend((self.cred_id.len() as u16).to_be_bytes());
                ad.extend(&self.cred_id);
                ad.extend(COSE_STUB);
            }
            ad.extend(&self.extensions);
            ad
        }

        fn create_json(&self, signer: &Signer) -> String {
            json!({
                "id": b64u(&self.cred_id),
                "rawId": b64u(&self.cred_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": b64u(&self.client_data()),
                    "authenticatorData": b64u(&self.auth_data()),
                    "publicKey": b64u(&signer.spki()),
                    "publicKeyAlgorithm": signer.alg(),
                    "transports": ["hybrid", "internal"],
                    "attestationObject": b64u(b"\xa3cfmtdnone"),
                },
                "authenticatorAttachment": "platform",
                "clientExtensionResults": {},
            })
            .to_string()
        }

        fn get_json(&self, signer: &Signer, user_handle: Option<&[u8]>) -> String {
            let (cd, ad) = (self.client_data(), self.auth_data());
            let sig = signer.sign(&[&ad[..], &Sha256::digest(&cd)[..]].concat());
            json!({
                "id": b64u(&self.cred_id),
                "rawId": b64u(&self.cred_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": b64u(&cd),
                    "authenticatorData": b64u(&ad),
                    "signature": b64u(&sig),
                    "userHandle": user_handle.map(b64u),
                },
                "authenticatorAttachment": "platform",
                "clientExtensionResults": {},
            })
            .to_string()
        }
    }

    fn register(json: &str, require_uv: bool) -> Result<NewCredential, WebauthnError> {
        let origins = origins();
        verify_registration(&Rp { id: RP_ID, origins: &origins }, &CHALLENGE, json, require_uv)
    }

    fn login(json: &str, signer: &Signer, stored_count: u32, require_uv: bool) -> Result<Assertion, WebauthnError> {
        let origins = origins();
        verify_assertion(&Rp { id: RP_ID, origins: &origins }, &CHALLENGE, json, signer.alg(), &signer.spki(), stored_count, require_uv)
    }

    /// Re-serialise `json` after `f` edits it, for fields no honest browser would produce.
    fn tweak(json: &str, f: impl FnOnce(&mut Value)) -> String {
        let mut v: Value = serde_json::from_str(json).unwrap();
        f(&mut v);
        v.to_string()
    }

    /// `json` with `response.publicKey` (and its algorithm) replaced.
    fn with_key(json: &str, spki: &[u8], alg: i64) -> String {
        tweak(json, |v| {
            v["response"]["publicKey"] = b64u(spki).into();
            v["response"]["publicKeyAlgorithm"] = alg.into();
        })
    }

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        match body.len() {
            n if n < 0x80 => v.push(n as u8),
            n if n < 0x100 => v.extend([0x81, n as u8]),
            n => v.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        v.extend(body);
        v
    }

    fn spki(alg_id: &[u8], key: &[u8]) -> Vec<u8> {
        der(0x30, &[der(0x30, alg_id), der(0x03, &[&[0][..], key].concat())].concat())
    }

    fn rsa_spki(n: &[u8], e: &[u8]) -> Vec<u8> {
        let int = |b: &[u8]| der(0x02, &if b[0] & 0x80 != 0 { [&[0][..], b].concat() } else { b.to_vec() });
        let alg_id = [der(0x06, OID_RSA), vec![0x05, 0x00]].concat();
        spki(&alg_id, &der(0x30, &[int(n), int(e)].concat()))
    }

    fn ec_alg_id(curve: &[u8]) -> Vec<u8> {
        [der(0x06, OID_EC_PUBLIC_KEY), der(0x06, curve)].concat()
    }

    // ------------------------------------------------------------ registration

    #[test]
    fn es256_registration_returns_the_credential() {
        let s = Signer::es256();
        let mut c = Ceremony::create();
        c.flags |= BE | BS;
        c.sign_count = 3;
        // Chrome adds this member to make sure nobody string-matches clientDataJSON.
        c.client_extra = r#","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template""#.into();
        let cred = register(&c.create_json(&s), true).expect("a well-formed create() response verifies");
        assert_eq!(cred.id, c.cred_id);
        assert_eq!(cred.alg, ES256);
        assert_eq!(cred.public_key, s.spki(), "the SPKI is stored as sent");
        assert_eq!(cred.sign_count, 3);
        assert!(cred.backup_eligible && cred.backed_up && cred.user_verified);
    }

    #[test]
    fn rs256_registration_accepts_a_real_rsa_spki() {
        let s = Signer::rs256();
        let cred = register(&Ceremony::create().create_json(&s), false).expect("RS256 verifies");
        assert_eq!(cred.alg, RS256);
        assert_eq!(cred.public_key, RSA_SPKI);
        assert!(!cred.backup_eligible && !cred.backed_up);
    }

    #[test]
    fn test_helpers_build_the_same_der_as_real_stacks() {
        let Signer::Rsa(k) = Signer::rs256() else { unreachable!() };
        assert!(RSA_SPKI.ends_with(k.public().as_ref()), "the SPKI fixture belongs to the private key fixture");
        let ec = Signer::es256();
        let point = &ec.spki()[26..];
        assert_eq!(spki(&ec_alg_id(OID_P256), point), ec.spki(), "der() matches the fixed P-256 prefix");
    }

    #[test]
    fn registration_rejects_a_wrong_origin() {
        let s = Signer::es256();
        for origin in
            ["https://evil.example", "https://l4f.cc.evil.example", "https://l4f.cc:443", "http://l4f.cc", "https://sub.l4f.cc", ""]
        {
            let c = Ceremony { origin: origin.into(), ..Ceremony::create() };
            assert_eq!(register(&c.create_json(&s), false), Err(E::Origin), "{origin:?} is not an allowed origin");
        }
        let c = Ceremony { origin: "http://localhost:8099".into(), ..Ceremony::create() };
        assert!(register(&c.create_json(&s), false).is_ok(), "every configured origin is accepted");
    }

    #[test]
    fn registration_rejects_a_wrong_rp_id() {
        let s = Signer::es256();
        for rp_id in ["evil.example", "L4F.cc", "www.l4f.cc", "localhost"] {
            let c = Ceremony { rp_id, ..Ceremony::create() };
            assert_eq!(register(&c.create_json(&s), false), Err(E::RpId), "rpIdHash of {rp_id:?}");
        }
    }

    #[test]
    fn registration_rejects_a_wrong_challenge() {
        let s = Signer::es256();
        let mut other = CHALLENGE.to_vec();
        other[31] ^= 1;
        for challenge in [other, CHALLENGE[..31].to_vec(), Vec::new()] {
            let c = Ceremony { challenge, ..Ceremony::create() };
            assert_eq!(register(&c.create_json(&s), false), Err(E::Challenge));
        }
        // Padding or the standard alphabet is not what a browser sends.
        let c = Ceremony::create();
        let padded = String::from_utf8(c.client_data()).unwrap().replace(&b64u(&CHALLENGE), &format!("{}=", b64u(&CHALLENGE)));
        let json = tweak(&c.create_json(&s), |v| v["response"]["clientDataJSON"] = b64u(padded.as_bytes()).into());
        assert_eq!(register(&json, false), Err(E::Challenge));
        let origins = origins();
        let rp = Rp { id: RP_ID, origins: &origins };
        let c = Ceremony { challenge: Vec::new(), ..Ceremony::create() };
        assert_eq!(
            verify_registration(&rp, &[], &c.create_json(&s), false),
            Err(E::Challenge),
            "an empty expected challenge never matches"
        );
        let c = Ceremony { challenge: vec![7; 15], ..Ceremony::create() };
        assert_eq!(
            verify_registration(&rp, &[7; 15], &c.create_json(&s), false),
            Err(E::Challenge),
            "a matching 15-byte challenge is too short"
        );
    }

    #[test]
    fn registration_rejects_the_wrong_ceremony_or_credential_type() {
        let s = Signer::es256();
        let c = Ceremony { typ: "webauthn.get", ..Ceremony::create() };
        assert_eq!(register(&c.create_json(&s), false), Err(E::Type), "an assertion's clientData cannot register");
        let json = tweak(&Ceremony::create().create_json(&s), |v| v["type"] = "password".into());
        assert_eq!(register(&json, false), Err(E::Type));
    }

    #[test]
    fn registration_rejects_cross_origin_iframes() {
        let s = Signer::es256();
        for extra in [
            r#","crossOrigin":true"#,
            r#","crossOrigin":true,"topOrigin":"https://evil.example""#,
            r#","topOrigin":"https://evil.example""#,
        ] {
            let c = Ceremony { client_extra: extra.into(), ..Ceremony::create() };
            assert_eq!(register(&c.create_json(&s), false), Err(E::CrossOrigin), "{extra}");
        }
        let c = Ceremony { client_extra: r#","crossOrigin":"yes""#.into(), ..Ceremony::create() };
        assert_eq!(register(&c.create_json(&s), false), Err(E::Malformed), "crossOrigin must be a boolean");
    }

    #[test]
    fn registration_requires_user_presence() {
        let c = Ceremony { flags: UV | AT, ..Ceremony::create() };
        assert_eq!(register(&c.create_json(&Signer::es256()), false), Err(E::UserPresence));
    }

    #[test]
    fn registration_requires_user_verification_only_when_asked() {
        let s = Signer::es256();
        let c = Ceremony { flags: UP | AT, ..Ceremony::create() };
        assert_eq!(register(&c.create_json(&s), true), Err(E::UserVerification));
        let cred = register(&c.create_json(&s), false).expect("UV is optional unless required");
        assert!(!cred.user_verified, "and reported as missing");
    }

    #[test]
    fn registration_without_an_spki_is_unsupported() {
        let json = Ceremony::create().create_json(&Signer::es256());
        let null = tweak(&json, |v| v["response"]["publicKey"] = Value::Null);
        assert_eq!(register(&null, false), Err(E::Unsupported), "publicKey: null");
        let absent = tweak(&json, |v| {
            v["response"].as_object_mut().unwrap().remove("publicKey");
        });
        assert_eq!(register(&absent, false), Err(E::Unsupported), "publicKey missing");
    }

    #[test]
    fn registration_rejects_algorithms_that_were_not_offered() {
        let s = Signer::es256();
        for alg in [-8, -35, -37, -258, 0, 7] {
            let json = with_key(&Ceremony::create().create_json(&s), &s.spki(), alg);
            assert_eq!(register(&json, false), Err(E::Unsupported), "alg {alg}");
        }
    }

    #[test]
    fn registration_rejects_a_key_that_does_not_match_its_algorithm() {
        let ec = Signer::es256();
        let json = with_key(&Ceremony::create().create_json(&ec), &ec.spki(), RS256);
        assert_eq!(register(&json, false), Err(E::Algorithm), "P-256 key labelled RS256");
        let json = with_key(&Ceremony::create().create_json(&ec), RSA_SPKI, ES256);
        assert_eq!(register(&json, false), Err(E::Algorithm), "RSA key labelled ES256");
    }

    #[test]
    fn registration_rejects_es256_keys_that_are_not_p256_points() {
        let s = Signer::es256();
        let json = Ceremony::create().create_json(&s);
        let rng = SystemRandom::new();
        let p384 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
        let p384 = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, p384.as_ref(), &rng).unwrap();
        let secp384r1 = [0x2b, 0x81, 0x04, 0x00, 0x22];
        let point = &s.spki()[26..];
        let mut compressed = vec![0x02 | (point[64] & 1)];
        compressed.extend(&point[1..33]);
        let mut off_curve = point.to_vec();
        off_curve[64] ^= 1;
        let ed25519 = spki(&der(0x06, &[0x2b, 0x65, 0x70]), &[9; 32]);
        for (what, key) in [
            ("P-384", spki(&ec_alg_id(&secp384r1), p384.public_key().as_ref())),
            ("P-384 OID on a P-256 point", spki(&ec_alg_id(&secp384r1), point)),
            ("compressed point", spki(&ec_alg_id(OID_P256), &compressed)),
            ("point not on the curve", spki(&ec_alg_id(OID_P256), &off_curve)),
            ("point at infinity", spki(&ec_alg_id(OID_P256), &[0])),
            ("Ed25519", ed25519),
        ] {
            assert_eq!(register(&with_key(&json, &key, ES256), false), Err(E::Key), "{what}");
        }
    }

    #[test]
    fn registration_rejects_weak_or_unusable_rsa_keys() {
        let json = Ceremony::create().create_json(&Signer::es256());
        let e = [0x01, 0x00, 0x01];
        assert!(register(&with_key(&json, &rsa_spki(&[0xc5; 256], &e), RS256), false).is_ok(), "a 2048-bit modulus is enough");
        assert!(register(&with_key(&json, &rsa_spki(&[0xc5; 1024], &e), RS256), false).is_ok(), "8192 bits is ring's maximum");
        // 2055 bits without the zero, so the zero is the only thing wrong with it.
        let mut leading_zero = vec![0];
        leading_zero.extend([0x45; 257]);
        let rsa = |rsa_public_key: Vec<u8>| spki(&[der(0x06, OID_RSA), vec![0x05, 0x00]].concat(), &rsa_public_key);
        let (n, e_int) = (der(0x02, &[&[0][..], &[0xc5; 256]].concat()), der(0x02, &e));
        for (what, key) in [
            ("1024-bit modulus", rsa_spki(&[0xc5; 128], &e)),
            ("2047-bit modulus", rsa_spki(&[&[0x45][..], &[0xc5; 255]].concat(), &e)),
            ("8193-bit modulus", rsa_spki(&[&[0x01][..], &[0xc5; 1024]].concat(), &e)),
            ("superfluous leading zero", rsa_spki(&leading_zero, &e)),
            ("negative modulus", rsa(der(0x30, &[der(0x02, &[0xc5; 256]), e_int.clone()].concat()))),
            ("even modulus", rsa_spki(&[&[0xc5; 255][..], &[0xc4]].concat(), &e)),
            ("even exponent", rsa_spki(&[0xc5; 256], &[0x01, 0x00, 0x00])),
            ("exponent 1", rsa_spki(&[0xc5; 256], &[0x01])),
            ("exponent above 2^33", rsa_spki(&[0xc5; 256], &[0x02, 0x00, 0x00, 0x00, 0x01])),
            // A u64 fold wraps this to 3; ring refuses exponents over 5 bytes.
            ("9-byte exponent", rsa_spki(&[0xc5; 256], &[0x01, 0, 0, 0, 0, 0, 0, 0, 0x03])),
            ("a third INTEGER", rsa(der(0x30, &[n.clone(), e_int.clone(), der(0x02, &[1])].concat()))),
            ("bytes after the RSAPublicKey", rsa([der(0x30, &[n, e_int].concat()), vec![0x05, 0x00]].concat())),
        ] {
            assert_eq!(register(&with_key(&json, &key, RS256), false), Err(E::Key), "{what}");
        }
    }

    #[test]
    fn spki_parsing_is_strict_der() {
        let s = Signer::es256();
        let json = Ceremony::create().create_json(&s);
        let good = s.spki();
        let mut trailing = good.clone();
        trailing.push(0);
        let mut long_form = vec![0x30, 0x81, 0x59];
        long_form.extend(&good[2..]);
        let mut indefinite = vec![0x30, 0x80];
        indefinite.extend(&good[2..]);
        indefinite.extend([0, 0]);
        let mut long_two_bytes = vec![0x30, 0x82, 0x00, 0x59];
        long_two_bytes.extend(&good[2..]);
        let mut set = good.clone();
        set[0] = 0x31;
        let mut octet_string = good.clone();
        octet_string[23] = 0x04;
        let extra_element = der(0x30, &[&good[2..], &[0x05, 0x00][..]].concat());
        let curve_then_null = spki(&[ec_alg_id(OID_P256), vec![0x05, 0x00]].concat(), &good[26..]);
        let mut unused_bits = good.clone();
        unused_bits[25] = 1;
        assert_eq!(&RSA_SPKI[19..24], [0x03, 0x82, 0x01, 0x0f, 0x00], "the fixture layout the next line relies on");
        let rsa_no_null = spki(&der(0x06, OID_RSA), &RSA_SPKI[24..]);
        let ec_null_params = spki(&[der(0x06, OID_EC_PUBLIC_KEY), vec![0x05, 0x00]].concat(), &good[26..]);
        for (what, key, alg) in [
            ("trailing byte", trailing, ES256),
            ("non-minimal length", long_form, ES256),
            ("non-minimal two-byte length", long_two_bytes, ES256),
            ("indefinite length", indefinite, ES256),
            ("SET instead of SEQUENCE", set, ES256),
            ("OCTET STRING instead of BIT STRING", octet_string, ES256),
            ("an element after the BIT STRING", extra_element, ES256),
            ("parameters after the curve", curve_then_null, ES256),
            ("unused bits in the BIT STRING", unused_bits, ES256),
            ("truncated", good[..good.len() - 1].to_vec(), ES256),
            ("empty", Vec::new(), ES256),
            ("RSA without NULL parameters", rsa_no_null, RS256),
            ("EC without a named curve", ec_null_params, ES256),
        ] {
            assert_eq!(register(&with_key(&json, &key, alg), false), Err(E::Key), "{what}");
        }
    }

    #[test]
    fn registration_checks_the_credential_id() {
        let s = Signer::es256();
        let c = Ceremony::create();
        let mut other = c.cred_id.clone();
        other[0] ^= 1;
        let json = tweak(&c.create_json(&s), |v| {
            v["id"] = b64u(&other).into();
            v["rawId"] = b64u(&other).into();
        });
        assert_eq!(register(&json, false), Err(E::CredentialId), "authData holds a different id");
        let json = tweak(&c.create_json(&s), |v| v["id"] = b64u(&other).into());
        assert_eq!(register(&json, false), Err(E::CredentialId), "id and rawId disagree");
        for (len, ok) in [(15, false), (16, true), (1023, true), (1024, false)] {
            let c = Ceremony { cred_id: vec![0x5a; len], ..Ceremony::create() };
            assert_eq!(register(&c.create_json(&s), false).err(), (!ok).then_some(E::CredentialId), "credential id of {len} bytes");
        }
    }

    #[test]
    fn registration_requires_well_formed_attested_credential_data() {
        let s = Signer::es256();
        let c = Ceremony { flags: UP | UV, ..Ceremony::create() };
        assert_eq!(register(&c.create_json(&s), false), Err(E::Malformed), "AT missing");
        let c = Ceremony::create();
        let ad = c.auth_data();
        let attested_end = 37 + 18 + c.cred_id.len();
        for (what, cut) in [
            ("no COSE key", attested_end),
            ("id cut short", attested_end - 1),
            ("no id length", 37 + 17),
            ("bare header", 37),
            ("short header", 36),
        ] {
            let json = tweak(&c.create_json(&s), |v| v["response"]["authenticatorData"] = b64u(&ad[..cut]).into());
            assert_eq!(register(&json, false), Err(E::Malformed), "{what}");
        }
        let c = Ceremony { flags: UP | UV | AT | ED, extensions: vec![0xa1, 0x60, 0x60], ..Ceremony::create() };
        assert!(register(&c.create_json(&s), false).is_ok(), "extensions after the COSE key are fine");
    }

    #[test]
    fn backup_eligible_and_backed_up_are_read_from_their_own_bits() {
        let s = Signer::es256();
        let c = Ceremony { flags: UP | UV | AT | BE, ..Ceremony::create() };
        let cred = register(&c.create_json(&s), false).expect("BE without BS registers");
        assert!(cred.backup_eligible && !cred.backed_up, "eligible for backup, not backed up yet");
        let c = Ceremony { flags: UP | UV | BE, ..Ceremony::get() };
        let a = login(&c.get_json(&s, None), &s, 0, false).expect("BE without BS logs in");
        assert!(!a.backed_up, "BE alone does not mean backed up");
    }

    #[test]
    fn registration_rejects_backed_up_without_backup_eligible() {
        let c = Ceremony { flags: UP | UV | AT | BS, ..Ceremony::create() };
        assert_eq!(register(&c.create_json(&Signer::es256()), false), Err(E::Malformed));
    }

    #[test]
    fn registration_rejects_malformed_input() {
        let s = Signer::es256();
        let json = Ceremony::create().create_json(&s);
        let huge = tweak(&json, |v| v["clientExtensionResults"] = "x".repeat(MAX_JSON).into());
        for (what, bad) in [
            ("not JSON", "{".to_string()),
            ("empty", String::new()),
            ("standard base64", tweak(&json, |v| v["response"]["clientDataJSON"] = "a+b/".into())),
            ("clientData not JSON", tweak(&json, |v| v["response"]["clientDataJSON"] = b64u(b"nope").into())),
            ("authData not base64url", tweak(&json, |v| v["response"]["authenticatorData"] = "!!".into())),
            ("publicKey not base64url", tweak(&json, |v| v["response"]["publicKey"] = "*".into())),
            ("missing response", tweak(&json, |v| v["response"] = Value::Null)),
            ("too large", huge),
        ] {
            assert_eq!(register(&bad, false), Err(E::Malformed), "{what}");
        }
    }

    // --------------------------------------------------------------- assertion

    #[test]
    fn es256_assertion_verifies_and_reports_flags() {
        let s = Signer::es256();
        let c = Ceremony { flags: UP | UV | BE | BS, ..Ceremony::get() };
        let a = login(&c.get_json(&s, Some(b"user-1")), &s, 4, true).expect("a good assertion verifies");
        assert_eq!(a.credential_id, c.cred_id);
        assert_eq!(a.user_handle.as_deref(), Some(&b"user-1"[..]));
        assert_eq!(a.sign_count, 5);
        assert!(a.user_verified && a.backed_up);
    }

    #[test]
    fn rs256_assertion_verifies() {
        let s = Signer::rs256();
        let a = login(&Ceremony::get().get_json(&s, None), &s, 0, true).expect("RS256 verifies");
        assert_eq!(a.user_handle, None);
    }

    #[test]
    fn assertion_registered_key_round_trip() {
        let s = Signer::es256();
        let cred = register(&Ceremony::create().create_json(&s), true).unwrap();
        let origins = origins();
        let json = Ceremony::get().get_json(&s, None);
        let rp = Rp { id: RP_ID, origins: &origins };
        assert!(verify_assertion(&rp, &CHALLENGE, &json, cred.alg, &cred.public_key, cred.sign_count, true).is_ok());
    }

    #[test]
    fn assertion_rejects_wrong_origin_rp_id_challenge_and_type() {
        let s = Signer::es256();
        let cases = [
            (Ceremony { origin: "https://evil.example".into(), ..Ceremony::get() }, E::Origin),
            (Ceremony { rp_id: "evil.example", ..Ceremony::get() }, E::RpId),
            (Ceremony { challenge: vec![8; 32], ..Ceremony::get() }, E::Challenge),
            (Ceremony { typ: "webauthn.create", ..Ceremony::get() }, E::Type),
            (Ceremony { typ: "payment.get", ..Ceremony::get() }, E::Type),
            (Ceremony { client_extra: r#","crossOrigin":true"#.into(), ..Ceremony::get() }, E::CrossOrigin),
            (Ceremony { client_extra: r#","topOrigin":"https://evil.example""#.into(), ..Ceremony::get() }, E::CrossOrigin),
        ];
        for (c, want) in cases {
            let json = c.get_json(&s, None);
            assert_eq!(login(&json, &s, 0, false), Err(want), "properly signed, but {:?}", String::from_utf8(c.client_data()).unwrap());
        }
    }

    #[test]
    fn assertion_requires_user_presence() {
        let s = Signer::es256();
        let c = Ceremony { flags: UV, ..Ceremony::get() };
        assert_eq!(login(&c.get_json(&s, None), &s, 0, false), Err(E::UserPresence));
    }

    #[test]
    fn assertion_requires_user_verification_only_when_asked() {
        let s = Signer::es256();
        let c = Ceremony { flags: UP, ..Ceremony::get() };
        assert_eq!(login(&c.get_json(&s, None), &s, 0, true), Err(E::UserVerification));
        let a = login(&c.get_json(&s, None), &s, 0, false).expect("presence alone is enough as a second factor");
        assert!(!a.user_verified);
    }

    #[test]
    fn assertion_rejects_a_tampered_signature() {
        for s in [Signer::es256(), Signer::rs256()] {
            let json = Ceremony::get().get_json(&s, None);
            let v: Value = serde_json::from_str(&json).unwrap();
            let sig = b64u_dec(v["response"]["signature"].as_str().unwrap()).unwrap();
            for i in [0, sig.len() / 2, sig.len() - 1] {
                let mut bad = sig.clone();
                bad[i] ^= 0x01;
                let json = tweak(&json, |v| v["response"]["signature"] = b64u(&bad).into());
                assert_eq!(login(&json, &s, 0, false), Err(E::Signature), "flipped byte {i} (alg {})", s.alg());
            }
            let json = tweak(&json, |v| v["response"]["signature"] = "".into());
            assert_eq!(login(&json, &s, 0, false), Err(E::Signature), "empty signature");
        }
    }

    #[test]
    fn assertion_signature_covers_auth_data_and_client_data() {
        let s = Signer::es256();
        let c = Ceremony::get();
        let json = c.get_json(&s, None);
        let raised = Ceremony { sign_count: 99, ..Ceremony::get() };
        let json_ad = tweak(&json, |v| v["response"]["authenticatorData"] = b64u(&raised.auth_data()).into());
        assert_eq!(login(&json_ad, &s, 0, false), Err(E::Signature), "counter raised after signing");
        let flagged = Ceremony { flags: UP | UV | BE, ..Ceremony::get() };
        let json_flags = tweak(&json, |v| v["response"]["authenticatorData"] = b64u(&flagged.auth_data()).into());
        assert_eq!(login(&json_flags, &s, 0, false), Err(E::Signature), "flags changed after signing");
        let other_cd = Ceremony { client_extra: r#","extra":1"#.into(), ..Ceremony::get() };
        let json_cd = tweak(&json, |v| v["response"]["clientDataJSON"] = b64u(&other_cd.client_data()).into());
        assert_eq!(login(&json_cd, &s, 0, false), Err(E::Signature), "clientDataJSON changed after signing");
    }

    #[test]
    fn assertion_rejects_a_signature_from_another_key() {
        let (signer, stored) = (Signer::es256(), Signer::es256());
        assert_eq!(login(&Ceremony::get().get_json(&signer, None), &stored, 0, false), Err(E::Signature));
    }

    #[test]
    fn assertion_detects_a_counter_regression() {
        let s = Signer::es256();
        // (5, 0): a clone's 0 would otherwise be stored and end clone detection.
        for (stored, new, ok) in [(4, 5, true), (5, 5, false), (6, 5, false), (0, 5, true), (0, 0, true), (5, 0, false), (1, 0, false)] {
            let c = Ceremony { sign_count: new, ..Ceremony::get() };
            let got = login(&c.get_json(&s, None), &s, stored, false);
            if ok {
                assert_eq!(got.map(|a| a.sign_count), Ok(new), "stored {stored}, new {new}");
            } else {
                assert_eq!(got, Err(E::Cloned), "stored {stored}, new {new}");
            }
        }
    }

    #[test]
    fn assertion_rejects_a_stored_key_of_another_algorithm() {
        let s = Signer::es256();
        let json = Ceremony::get().get_json(&s, None);
        let origins = origins();
        let rp = Rp { id: RP_ID, origins: &origins };
        assert_eq!(verify_assertion(&rp, &CHALLENGE, &json, RS256, &s.spki(), 0, false), Err(E::Algorithm));
        assert_eq!(verify_assertion(&rp, &CHALLENGE, &json, -8, &s.spki(), 0, false), Err(E::Algorithm));
        assert_eq!(verify_assertion(&rp, &CHALLENGE, &json, ES256, b"not der", 0, false), Err(E::Key));
    }

    #[test]
    fn assertion_auth_data_layout_is_exact() {
        let s = Signer::es256();
        let c = Ceremony { flags: UP | UV | AT, ..Ceremony::get() };
        assert_eq!(login(&c.get_json(&s, None), &s, 0, false), Err(E::Malformed), "attested data has no place in an assertion");
        let c = Ceremony { extensions: vec![0xa0], ..Ceremony::get() };
        assert_eq!(login(&c.get_json(&s, None), &s, 0, false), Err(E::Malformed), "stray bytes without ED");
        let c = Ceremony { flags: UP | UV | ED, ..Ceremony::get() };
        assert_eq!(login(&c.get_json(&s, None), &s, 0, false), Err(E::Malformed), "ED with nothing after it");
        let c = Ceremony { flags: UP | UV | BS, ..Ceremony::get() };
        assert_eq!(login(&c.get_json(&s, None), &s, 0, false), Err(E::Malformed), "BS without BE");
        let c = Ceremony { flags: UP | UV | ED, extensions: vec![0xa1, 0x63, b'f', b'o', b'o', 0xf5], ..Ceremony::get() };
        assert!(login(&c.get_json(&s, None), &s, 0, false).is_ok(), "signed extensions are fine");
    }

    #[test]
    fn parse_assertion_ids_reads_the_id_and_user_handle() {
        let s = Signer::es256();
        let c = Ceremony::get();
        let json = c.get_json(&s, Some(b"acct-42"));
        assert_eq!(parse_assertion_ids(&json), Ok((c.cred_id.clone(), Some(b"acct-42".to_vec()))));
        let none = c.get_json(&s, None);
        assert_eq!(parse_assertion_ids(&none), Ok((c.cred_id.clone(), None)), "userHandle: null");
        let absent = tweak(&none, |v| {
            v["response"].as_object_mut().unwrap().remove("userHandle");
        });
        assert_eq!(parse_assertion_ids(&absent), Ok((c.cred_id.clone(), None)), "userHandle missing");
        let empty = tweak(&none, |v| v["response"]["userHandle"] = "".into());
        assert_eq!(parse_assertion_ids(&empty), Ok((c.cred_id.clone(), None)), "empty userHandle");
        let max = c.get_json(&s, Some(&[1; 64]));
        assert_eq!(parse_assertion_ids(&max), Ok((c.cred_id.clone(), Some(vec![1; 64]))), "64 bytes is the largest user.id");
        let long = c.get_json(&s, Some(&[1; 65]));
        assert_eq!(parse_assertion_ids(&long), Err(E::Malformed), "user handles are at most 64 bytes");
        let mismatch = tweak(&json, |v| v["id"] = b64u(&[9; 32]).into());
        assert_eq!(parse_assertion_ids(&mismatch), Err(E::CredentialId));
        let wrong_type = tweak(&json, |v| v["type"] = "otp".into());
        assert_eq!(parse_assertion_ids(&wrong_type), Err(E::Type));
        assert_eq!(parse_assertion_ids("[]"), Err(E::Malformed));
    }

    // ---------------------------------------------------- real browser output

    /// Recorded from Chromium 153's CDP and Firefox 156's Marionette virtual
    /// authenticators; the .txt next to each pair says how. Hand-built ceremonies
    /// only test what we think browsers send. The last field is signCount at
    /// create() and get(): Chrome's authenticator counts from 1, Firefox's keeps none.
    const RECORDED: [(&str, i64, &str, &str, [u32; 2]); 3] = [
        (
            "chrome es256",
            ES256,
            include_str!("../../tests/fixtures/webauthn/chrome-es256-create.json"),
            include_str!("../../tests/fixtures/webauthn/chrome-es256-get.json"),
            [1, 2],
        ),
        (
            "chrome rs256",
            RS256,
            include_str!("../../tests/fixtures/webauthn/chrome-rs256-create.json"),
            include_str!("../../tests/fixtures/webauthn/chrome-rs256-get.json"),
            [1, 2],
        ),
        (
            "firefox es256",
            ES256,
            include_str!("../../tests/fixtures/webauthn/firefox-es256-create.json"),
            include_str!("../../tests/fixtures/webauthn/firefox-es256-get.json"),
            [0, 0],
        ),
    ];
    const RECORDED_RP_ID: &str = "localhost";
    const RECORDED_ORIGIN: &str = "http://localhost:8099";
    const RECORDED_USER: &[u8] = b"l4f-fixture-user";

    fn recorded_create_challenge() -> Vec<u8> {
        (0x00..0x20).collect()
    }

    fn recorded_get_challenge() -> Vec<u8> {
        (0x20..0x40).collect()
    }

    /// A base64url member of a fixture, decoded.
    fn field(json: &str, pointer: &str) -> Vec<u8> {
        let v: Value = serde_json::from_str(json).unwrap();
        b64u_dec(v.pointer(pointer).and_then(Value::as_str).unwrap()).unwrap()
    }

    #[test]
    fn real_browser_credentials_register_and_log_in() {
        let origins = vec![RECORDED_ORIGIN.to_string()];
        let rp = Rp { id: RECORDED_RP_ID, origins: &origins };
        for (name, alg, create, get, [created, used]) in RECORDED {
            let cred = verify_registration(&rp, &recorded_create_challenge(), create, true)
                .unwrap_or_else(|e| panic!("{name}: the browser's create() output must verify, got {e:?}"));
            assert_eq!(cred.id, field(create, "/rawId"), "{name}: the id is the browser's rawId");
            assert_eq!(cred.alg, alg, "{name}");
            assert_eq!(cred.public_key, field(create, "/response/publicKey"), "{name}: the SPKI is stored as sent");
            assert_eq!(cred.sign_count, created, "{name}");
            assert!(cred.user_verified && !cred.backup_eligible && !cred.backed_up, "{name}: flags UP|UV|AT only");

            assert_eq!(parse_assertion_ids(get), Ok((cred.id.clone(), Some(RECORDED_USER.to_vec()))), "{name}");
            let a = verify_assertion(&rp, &recorded_get_challenge(), get, cred.alg, &cred.public_key, cred.sign_count, true)
                .unwrap_or_else(|e| panic!("{name}: the browser's get() output must verify against the stored key, got {e:?}"));
            assert_eq!(a.credential_id, cred.id, "{name}");
            assert_eq!(a.user_handle.as_deref(), Some(RECORDED_USER), "{name}: the user.id given to create()");
            assert_eq!(a.sign_count, used, "{name}");
            assert!(a.user_verified && !a.backed_up, "{name}: flags UP|UV only");
        }
    }

    #[test]
    fn real_browser_output_rejects_a_wrong_origin_rp_challenge_or_counter() {
        let (create_ch, get_ch) = (recorded_create_challenge(), recorded_get_challenge());
        let good = vec![RECORDED_ORIGIN.to_string()];
        let other_port = vec!["http://localhost:8098".to_string(), ORIGIN.to_string()];
        let rp = Rp { id: RECORDED_RP_ID, origins: &good };
        for (name, alg, create, get, [_, used]) in RECORDED {
            let cred = verify_registration(&rp, &create_ch, create, true).unwrap();
            let login = |rp: &Rp, challenge: &[u8], stored_count: u32| {
                verify_assertion(rp, challenge, get, alg, &cred.public_key, stored_count, true)
            };
            let elsewhere = Rp { id: RECORDED_RP_ID, origins: &other_port };
            assert_eq!(verify_registration(&elsewhere, &create_ch, create, true), Err(E::Origin), "{name}: create on another origin");
            assert_eq!(login(&elsewhere, &get_ch, 0), Err(E::Origin), "{name}: get on another origin");
            assert_eq!(verify_registration(&rp, &get_ch, create, true), Err(E::Challenge), "{name}: create with the get challenge");
            assert_eq!(login(&rp, &create_ch, 0), Err(E::Challenge), "{name}: get with the create challenge");
            let other_rp = Rp { id: RP_ID, origins: &good };
            assert_eq!(verify_registration(&other_rp, &create_ch, create, true), Err(E::RpId), "{name}: scoped to localhost");
            assert_eq!(login(&other_rp, &get_ch, 0), Err(E::RpId), "{name}: scoped to localhost");
            // Chrome's assertion replayed after its counter was stored; Firefox's 0 after a used counter.
            let stored = used.max(1);
            assert_eq!(login(&rp, &get_ch, stored), Err(E::Cloned), "{name}: signCount {used} after {stored} was stored");
        }
    }
}
