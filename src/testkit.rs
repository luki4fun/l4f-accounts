//! Test-only: the WebAuthn and SSHSIG builders the verify tests share with
//! the service and router tests, a fake ES256 passkey that answers ceremonies
//! the way a browser and authenticator would, and a log capture for the
//! journal lines they write.

// Without a backend only the verify tests run, and they use the builders alone.
#![cfg_attr(not(feature = "_db"), allow(dead_code))]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::util::b64u;
use crate::verify::sshsig::{BEGIN, END, put_string};
use crate::verify::webauthn::{AT, BE, ES256, RS256, UP, UV};

pub(crate) const RP_ID: &str = "l4f.cc";
pub(crate) const ORIGIN: &str = "https://l4f.cc";
pub(crate) const CHALLENGE: [u8; 32] = [7; 32];
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
    0x07, 0x03, 0x42, 0x00,
];
/// Test-only key from `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER`,
/// then `openssl pkcs8 -topk8 -nocrypt`: OpenSSL 3.0 writes PKCS#1 DER, ring only reads PKCS#8.
const RSA_PKCS8: &[u8] = include_bytes!("../tests/fixtures/webauthn/rsa2048.pk8");
/// Its public half, from `openssl pkey -pubout -outform DER`: the encoding a real stack emits.
pub(crate) const RSA_SPKI: &[u8] = include_bytes!("../tests/fixtures/webauthn/rsa2048.spki");
/// The first bytes of an ES256 COSE key; only ever skipped, never parsed.
const COSE_STUB: &[u8] = &[0xa5, 0x01, 0x02, 0x03, 0x26];

/// A passkey's private key: a fresh P-256 one, or the RSA fixture.
pub(crate) enum Signer {
    Ec(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

impl Signer {
    pub fn es256() -> Signer {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        Signer::Ec(EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap())
    }

    pub fn rs256() -> Signer {
        Signer::Rsa(RsaKeyPair::from_pkcs8(RSA_PKCS8).unwrap())
    }

    pub fn alg(&self) -> i64 {
        match self {
            Signer::Ec(_) => ES256,
            Signer::Rsa(_) => RS256,
        }
    }

    pub fn spki(&self) -> Vec<u8> {
        match self {
            Signer::Ec(k) => [&P256_SPKI_PREFIX[..], k.public_key().as_ref()].concat(),
            Signer::Rsa(_) => RSA_SPKI.to_vec(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
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
pub(crate) struct Ceremony {
    pub typ: &'static str,
    pub challenge: Vec<u8>,
    pub origin: String,
    /// Raw JSON members appended to clientDataJSON, e.g. `,"crossOrigin":true`.
    pub client_extra: String,
    pub rp_id: String,
    pub flags: u8,
    pub sign_count: u32,
    pub cred_id: Vec<u8>,
    /// Raw bytes after the attested data (or the counter): extension CBOR.
    pub extensions: Vec<u8>,
}

impl Ceremony {
    pub fn create() -> Ceremony {
        Ceremony {
            typ: "webauthn.create",
            challenge: CHALLENGE.to_vec(),
            origin: ORIGIN.to_string(),
            client_extra: String::new(),
            rp_id: RP_ID.into(),
            flags: UP | UV | AT,
            sign_count: 0,
            cred_id: (0..32).collect(),
            extensions: Vec::new(),
        }
    }

    pub fn get() -> Ceremony {
        Ceremony { typ: "webauthn.get", flags: UP | UV, sign_count: 5, ..Ceremony::create() }
    }

    pub fn client_data(&self) -> Vec<u8> {
        format!(r#"{{"type":"{}","challenge":"{}","origin":"{}"{}}}"#, self.typ, b64u(&self.challenge), self.origin, self.client_extra)
            .into_bytes()
    }

    pub fn auth_data(&self) -> Vec<u8> {
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

    pub fn create_json(&self, signer: &Signer) -> String {
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

    pub fn get_json(&self, signer: &Signer, user_handle: Option<&[u8]>) -> String {
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

/// A passkey on one authenticator, answering ceremonies as `Ceremony` lays
/// them out.
pub(crate) struct Authenticator {
    key: Signer,
    pub id: Vec<u8>,
    pub count: u32,
    pub backup_eligible: bool,
}

impl Authenticator {
    pub fn new() -> Self {
        Self { key: Signer::es256(), id: crate::util::random::<32>().to_vec(), count: 0, backup_eligible: true }
    }

    /// `c` for `origin` on `rp_id`, as this authenticator answers it: its id,
    /// its counter, and BE when it is backup eligible.
    fn answer(&self, c: Ceremony, challenge: &[u8], origin: &str, rp_id: &str) -> Ceremony {
        let be = if self.backup_eligible { BE } else { 0 };
        Ceremony {
            challenge: challenge.to_vec(),
            origin: origin.into(),
            rp_id: rp_id.into(),
            flags: c.flags | be,
            sign_count: self.count,
            cred_id: self.id.clone(),
            ..c
        }
    }

    /// `credential.toJSON()` for `navigator.credentials.create()`.
    pub fn create(&self, challenge: &[u8], origin: &str, rp_id: &str) -> String {
        self.answer(Ceremony::create(), challenge, origin, rp_id).create_json(&self.key)
    }

    /// `credential.toJSON()` for `navigator.credentials.get()`. Each call
    /// counts up, as a real authenticator does.
    pub fn get(&mut self, challenge: &[u8], origin: &str, rp_id: &str, user_handle: Option<&[u8]>, uv: bool) -> String {
        self.count += 1;
        let c = Ceremony { flags: if uv { UP | UV } else { UP }, ..Ceremony::get() };
        self.answer(c, challenge, origin, rp_id).get_json(&self.key, user_handle)
    }
}

/// An Ed25519 key that signs like `ssh-keygen -Y sign` and like a browser's
/// device key.
pub(crate) struct EdKey(ring::signature::Ed25519KeyPair);

impl EdKey {
    pub fn new() -> Self {
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self(ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
    }

    pub fn raw_public(&self) -> Vec<u8> {
        self.0.public_key().as_ref().to_vec()
    }

    fn ssh_blob(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_string(&mut b, b"ssh-ed25519");
        put_string(&mut b, self.0.public_key().as_ref());
        b
    }

    /// The `authorized_keys` line.
    pub fn ssh_public(&self, comment: &str) -> String {
        format!("ssh-ed25519 {} {comment}", STANDARD.encode(self.ssh_blob()))
    }

    /// `ssh-keygen -Y sign -n <ns>` over `msg`, armored (PROTOCOL.sshsig, sha512).
    pub fn ssh_sign(&self, ns: &str, msg: &[u8]) -> String {
        use sha2::Sha512;
        let mut signed = b"SSHSIG".to_vec();
        put_string(&mut signed, ns.as_bytes());
        put_string(&mut signed, b"");
        put_string(&mut signed, b"sha512");
        put_string(&mut signed, &Sha512::digest(msg));
        let mut sig = Vec::new();
        put_string(&mut sig, b"ssh-ed25519");
        put_string(&mut sig, self.0.sign(&signed).as_ref());
        let mut blob = b"SSHSIG".to_vec();
        blob.extend(1u32.to_be_bytes());
        put_string(&mut blob, &self.ssh_blob());
        put_string(&mut blob, ns.as_bytes());
        put_string(&mut blob, b"");
        put_string(&mut blob, b"sha512");
        put_string(&mut blob, &sig);
        armor(&blob)
    }

    /// A device key's signature over `devkey::message`.
    pub fn devkey_sign(&self, origin: &str, device_id: &[u8], challenge: &[u8]) -> Vec<u8> {
        self.0.sign(&crate::verify::devkey::message(origin, device_id, challenge)).as_ref().to_vec()
    }
}

/// An SSHSIG blob armored the way `ssh-keygen -Y sign` writes it: base64 in
/// lines of 70.
pub(crate) fn armor(raw: &[u8]) -> String {
    let b = STANDARD.encode(raw);
    let lines: Vec<&str> = b.as_bytes().chunks(70).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("{BEGIN}\n{}\n{END}\n", lines.join("\n"))
}

/// The events `f` logs on this thread, with their fields as the fmt subscriber
/// writes them: `name=value`, a string quoted, a `%` value as it displays.
pub(crate) fn logged(f: impl FnOnce()) -> Vec<String> {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};

    struct Line(String);
    impl Visit for Line {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            let sep = if self.0.is_empty() { "" } else { " " };
            self.0 += &format!("{sep}{}={value:?}", field.name());
        }
    }
    struct Capture(Arc<Mutex<Vec<String>>>);
    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, e: &tracing::Event<'_>) {
            let mut line = Line(String::new());
            e.record(&mut line);
            self.0.lock().unwrap().push(line.0);
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }
    let lines = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Capture(lines.clone()), f);
    lines.lock().unwrap().clone()
}
