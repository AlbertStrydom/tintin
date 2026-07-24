use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;

use crate::error::{Result, TinTinError};

/// Derive an encryption key and authentication key from an input key material
/// (IKM) using HKDF-SHA256.
///
/// Returns `(enc_key, auth_key)` where each is 32 bytes.
pub fn derive_keys(ikm: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);

    let mut okm = [0u8; 64];
    hkdf.expand(b"tintin-message-keys", &mut okm)
        .expect("HKDF expand should not fail with valid length");

    let mut enc_key = [0u8; 32];
    let mut auth_key = [0u8; 32];
    enc_key.copy_from_slice(&okm[..32]);
    auth_key.copy_from_slice(&okm[32..]);

    (enc_key, auth_key)
}

/// Derive a chain key and message key from a root key and DH output.
pub fn derive_chain_keys(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut okm = [0u8; 64];
    hkdf.expand(dh_output, &mut okm)
        .expect("HKDF expand should not fail");

    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_root.copy_from_slice(&okm[..32]);
    chain_key.copy_from_slice(&okm[32..]);

    (new_root, chain_key)
}

/// Encrypt a plaintext message using ChaCha20-Poly1305.
///
/// Returns `(ciphertext, nonce)`.
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12])> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| TinTinError::EncryptionFailed(format!("ChaCha20Poly1305: {e}")))?;

    Ok((ciphertext, nonce))
}

/// Decrypt a ciphertext that was encrypted with [`encrypt`].
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| TinTinError::DecryptionFailed(format!("ChaCha20Poly1305: {e}")))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, TinTin! This is a secret message.";
        let (ct, nonce) = encrypt(plaintext, &key).unwrap();
        let pt = decrypt(&ct, &key, &nonce).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = [0x11u8; 32];
        let wrong_key = [0x22u8; 32];
        let plaintext = b"Secret message";
        let (ct, nonce) = encrypt(plaintext, &key).unwrap();
        let result = decrypt(&ct, &wrong_key, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_keys_deterministic() {
        let ikm = b"input key material";
        let salt = b"salty salt";
        let (k1, a1) = derive_keys(ikm, salt);
        let (k2, a2) = derive_keys(ikm, salt);
        assert_eq!(k1, k2);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_derive_chain_keys() {
        let root = [0xABu8; 32];
        let dh = [0xCDu8; 32];
        let (new_root, chain) = derive_chain_keys(&root, &dh);
        assert_ne!(new_root, [0u8; 32]);
        assert_ne!(chain, [0u8; 32]);
    }
}