//! Pins docs/vault-format.md, version 1: vectors made by assets/vault.js
//! (WebCrypto, under Node) must open here with ring, byte for byte. A change
//! that breaks this is a format change and needs `v: 2`, never an edit.

use std::num::NonZeroU32;

use ring::{aead, hkdf, pbkdf2};
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("fixtures/vault/v1.json");

fn b64u(s: &str) -> Vec<u8> {
    l4f_accounts::util::b64u_dec(s).expect("base64url")
}

fn open(key: &[u8], iv: &[u8], aad: &str, ct: &[u8]) -> Vec<u8> {
    let k = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, key).unwrap());
    let mut buf = ct.to_vec();
    let nonce = aead::Nonce::try_assume_unique_for_key(iv).unwrap();
    k.open_in_place(nonce, aead::Aad::from(aad.as_bytes()), &mut buf).expect("decrypts").to_vec()
}

struct Len32;
impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

fn unwrap_slot(account: &str, slot: &Value, kek: &[u8]) -> Vec<u8> {
    let aad = format!("l4f-vault-slot/v1|{account}|{}", slot["id"].as_str().unwrap());
    open(kek, &b64u(slot["iv"].as_str().unwrap()), &aad, &b64u(slot["ct"].as_str().unwrap()))
}

#[test]
fn version_1_vectors_open_with_ring() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let account = v["account"].as_str().unwrap();

    // The passphrase slot: PBKDF2-HMAC-SHA256, 600 000 rounds.
    let ps = &v["pass_slot"];
    assert_eq!(ps["kdf"]["iter"], 600_000);
    let mut kek = [0u8; 32];
    let iter = NonZeroU32::new(ps["kdf"]["iter"].as_u64().unwrap() as u32).unwrap();
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iter, &b64u(ps["kdf"]["salt"].as_str().unwrap()), v["pass"].as_str().unwrap().as_bytes(), &mut kek);
    let dek = unwrap_slot(account, ps, &kek);
    assert_eq!(dek.len(), 32);
    assert_eq!(b64u(ps["dek_id"].as_str().unwrap()), Sha256::digest(&dek)[..8].to_vec(), "dek_id is SHA-256(DEK)[..8]");

    // The recovery slot: HKDF-SHA256 over the key shown as base32.
    let rs = &v["recovery_slot"];
    let secret = l4f_accounts::totp::base32_decode(v["recovery_key"].as_str().unwrap()).unwrap();
    let mut rkek = [0u8; 32];
    hkdf::Salt::new(hkdf::HKDF_SHA256, &b64u(rs["kdf"]["salt"].as_str().unwrap()))
        .extract(&secret)
        .expand(&[b"l4f-vault-kek/v1"], Len32)
        .unwrap()
        .fill(&mut rkek)
        .unwrap();
    assert_eq!(unwrap_slot(account, rs, &rkek), dek, "both slots wrap the same DEK");

    // The item: 0x01 | dek_id | iv | ciphertext, AAD bound to account, kind and id.
    let item = b64u(v["item"].as_str().unwrap());
    assert_eq!((item[0], &item[1..9]), (1, &Sha256::digest(&dek)[..8]));
    let id = v["item_id"].as_str().unwrap();
    let kind = id.split('.').next().unwrap();
    let plain = open(&dek, &item[9..21], &format!("l4f-vault-item/v1|{account}|{kind}|{id}"), &item[21..]);
    assert_eq!(serde_json::from_slice::<Value>(&plain).unwrap(), v["value"]);

    // Bound to the account: another one's AAD does not open it.
    let k = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &dek).unwrap());
    let mut buf = item[21..].to_vec();
    let wrong = format!("l4f-vault-item/v1|{}|{kind}|{id}", "ff".repeat(16));
    assert!(k.open_in_place(aead::Nonce::try_assume_unique_for_key(&item[9..21]).unwrap(), aead::Aad::from(wrong.as_bytes()), &mut buf).is_err());
}
