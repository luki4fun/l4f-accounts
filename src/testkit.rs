//! Test-only: a fake ES256 passkey that answers ceremonies the way a browser
//! and authenticator would, for the service and router tests.

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::util::b64u;

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const AT: u8 = 0x40;
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00,
];

pub(crate) struct Authenticator {
    key: EcdsaKeyPair,
    pub id: Vec<u8>,
    pub count: u32,
    pub backup_eligible: bool,
}

impl Authenticator {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        Self { key, id: crate::util::random::<32>().to_vec(), count: 0, backup_eligible: true }
    }

    fn client_data(typ: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        format!(r#"{{"type":"{typ}","challenge":"{}","origin":"{origin}"}}"#, b64u(challenge)).into_bytes()
    }

    fn auth_data(&self, rp_id: &str, flags: u8, attested: bool) -> Vec<u8> {
        let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
        ad.push(flags | if self.backup_eligible { BE } else { 0 } | if attested { AT } else { 0 });
        ad.extend(self.count.to_be_bytes());
        if attested {
            ad.extend([0xaa; 16]);
            ad.extend((self.id.len() as u16).to_be_bytes());
            ad.extend(&self.id);
            ad.extend([0xa5, 0x01, 0x02, 0x03, 0x26]);
        }
        ad
    }

    /// `credential.toJSON()` for `navigator.credentials.create()`.
    pub fn create(&self, challenge: &[u8], origin: &str, rp_id: &str) -> String {
        let spki = [&P256_SPKI_PREFIX[..], self.key.public_key().as_ref()].concat();
        json!({
            "id": b64u(&self.id), "rawId": b64u(&self.id), "type": "public-key",
            "response": {
                "clientDataJSON": b64u(&Self::client_data("webauthn.create", challenge, origin)),
                "authenticatorData": b64u(&self.auth_data(rp_id, UP | UV, true)),
                "publicKey": b64u(&spki), "publicKeyAlgorithm": -7,
                "transports": ["internal"], "attestationObject": b64u(b"\xa3cfmtdnone"),
            },
            "clientExtensionResults": {},
        })
        .to_string()
    }

    /// `credential.toJSON()` for `navigator.credentials.get()`. Each call
    /// counts up, as a real authenticator does.
    pub fn get(&mut self, challenge: &[u8], origin: &str, rp_id: &str, user_handle: Option<&[u8]>, uv: bool) -> String {
        self.count += 1;
        let cd = Self::client_data("webauthn.get", challenge, origin);
        let ad = self.auth_data(rp_id, if uv { UP | UV } else { UP }, false);
        let msg = [&ad[..], &Sha256::digest(&cd)[..]].concat();
        let sig = self.key.sign(&SystemRandom::new(), &msg).unwrap();
        json!({
            "id": b64u(&self.id), "rawId": b64u(&self.id), "type": "public-key",
            "response": {
                "clientDataJSON": b64u(&cd), "authenticatorData": b64u(&ad),
                "signature": b64u(sig.as_ref()), "userHandle": user_handle.map(b64u),
            },
            "clientExtensionResults": {},
        })
        .to_string()
    }
}

/// An Ed25519 key that signs like `ssh-keygen -Y sign` and like a browser's
/// device key.
pub(crate) struct EdKey(ring::signature::Ed25519KeyPair);

fn ssh_string(out: &mut Vec<u8>, b: &[u8]) {
    out.extend((b.len() as u32).to_be_bytes());
    out.extend(b);
}

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
        ssh_string(&mut b, b"ssh-ed25519");
        ssh_string(&mut b, self.0.public_key().as_ref());
        b
    }

    /// The `authorized_keys` line.
    pub fn ssh_public(&self, comment: &str) -> String {
        use base64::Engine;
        format!("ssh-ed25519 {} {comment}", base64::engine::general_purpose::STANDARD.encode(self.ssh_blob()))
    }

    /// `ssh-keygen -Y sign -n <ns>` over `msg`, armored (PROTOCOL.sshsig, sha512).
    pub fn ssh_sign(&self, ns: &str, msg: &[u8]) -> String {
        use base64::Engine;
        use sha2::Sha512;
        let mut signed = b"SSHSIG".to_vec();
        ssh_string(&mut signed, ns.as_bytes());
        ssh_string(&mut signed, b"");
        ssh_string(&mut signed, b"sha512");
        ssh_string(&mut signed, &Sha512::digest(msg));
        let mut sig = Vec::new();
        ssh_string(&mut sig, b"ssh-ed25519");
        ssh_string(&mut sig, self.0.sign(&signed).as_ref());
        let mut blob = b"SSHSIG".to_vec();
        blob.extend(1u32.to_be_bytes());
        ssh_string(&mut blob, &self.ssh_blob());
        ssh_string(&mut blob, ns.as_bytes());
        ssh_string(&mut blob, b"");
        ssh_string(&mut blob, b"sha512");
        ssh_string(&mut blob, &sig);
        let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
        let lines: Vec<&str> = b64.as_bytes().chunks(70).map(|c| std::str::from_utf8(c).unwrap()).collect();
        format!("-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n", lines.join("\n"))
    }

    /// A device key's signature over `devkey::message`.
    pub fn devkey_sign(&self, origin: &str, device_id: &[u8], challenge: &[u8]) -> Vec<u8> {
        self.0.sign(&crate::verify::devkey::message(origin, device_id, challenge)).as_ref().to_vec()
    }
}
