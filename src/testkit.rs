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
