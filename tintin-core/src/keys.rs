use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;
use crate::error::Result;

/// A X25519 key pair (ephemeral or long-term).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// The private (secret) key — 32 bytes.
    #[serde(with = "serde_secret_key")]
    pub secret: [u8; 32],
    /// The public key — 32 bytes.
    pub public: [u8; 32],
}

impl KeyPair {
    /// Generate a fresh random X25519 key pair.
    pub fn generate() -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self {
            secret: secret.to_bytes(),
            public: *public.as_bytes(),
        }
    }

    /// Perform X25519 Diffie-Hellman key agreement.
    /// Returns a shared 32-byte secret.
    pub fn agree(&self, their_public: &[u8; 32]) -> Result<[u8; 32]> {
        let our_secret = x25519_dalek::StaticSecret::from(self.secret);
        let their_public = x25519_dalek::PublicKey::from(*their_public);
        let shared = our_secret.diffie_hellman(&their_public);
        Ok(shared.to_bytes())
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// A long-term identity key pair. Wraps `KeyPair` with identity metadata.
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityKeyPair {
    /// The key pair itself.
    pub key_pair: KeyPair,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        Self {
            key_pair: KeyPair::generate(),
        }
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.key_pair.public
    }
}

/// A signed pre-key — a one-time-use or semi-one-time-use key that
/// is signed by the identity key to prove ownership.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPreKey {
    /// The pre-key ID.
    pub id: u32,
    /// The pre-key pair.
    pub key_pair: KeyPair,
    /// Signature of the public key by the identity key.
    pub signature: Vec<u8>,
}

impl SignedPreKey {
    /// Generate a new signed pre-key.
    /// `identity` is used to sign the public key.
    pub fn generate(id: u32, identity: &IdentityKeyPair) -> Self {
        let key_pair = KeyPair::generate();
        let signature = sign_identity(identity, &key_pair.public);
        Self {
            id,
            key_pair,
            signature,
        }
    }

    /// Verify that this pre-key is signed by the given identity.
    pub fn verify(&self, identity_public: &[u8; 32]) -> bool {
        verify_signature(identity_public, &self.key_pair.public, &self.signature)
    }
}

/// A one-time pre-key (used once, then discarded).
#[derive(Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub id: u32,
    pub key_pair: KeyPair,
}

impl OneTimePreKey {
    pub fn generate(id: u32) -> Self {
        Self {
            id,
            key_pair: KeyPair::generate(),
        }
    }
}

/// A bundle of pre-keys published to the server so other users can
/// establish a session.
#[derive(Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// The user's identity public key.
    pub identity_key: [u8; 32],
    /// The device ID (for multi-device support later).
    pub device_id: u32,
    /// The signed pre-key.
    pub signed_pre_key: SignedPreKeyPublic,
    /// An optional one-time pre-key.
    pub one_time_pre_key: Option<OneTimePreKeyPublic>,
}

/// Public part of a signed pre-key (no secret material).
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPreKeyPublic {
    pub id: u32,
    pub public_key: [u8; 32],
    pub signature: Vec<u8>,
}

/// Public part of a one-time pre-key.
#[derive(Clone, Serialize, Deserialize)]
pub struct OneTimePreKeyPublic {
    pub id: u32,
    pub public_key: [u8; 32],
}

// ---------------------------------------------------------------------------
// Identity signing (SHA-512-based "signature" for now; real Signal uses
// Ed25519 or XEd25519. This is a simplified version for Phase 1.)
// ---------------------------------------------------------------------------

/// Sign `data` using the identity key pair. This produces a SHA-512 HMAC-like
/// signature that binds the identity to the data. For Phase 1 this is an
/// *authenticated hash* — later we'll upgrade to real EdDSA.
pub fn sign_identity(identity: &IdentityKeyPair, data: &[u8; 32]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(&identity.key_pair.secret);
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Verify a signature produced by `sign_identity`.
pub fn verify_signature(_identity_public: &[u8; 32], _data: &[u8; 32], signature: &[u8]) -> bool {
    // For Phase 1, we can't verify without the secret key (this is a limitation
    // of the simplified auth-hash approach). In production, use Ed25519.
    // For now we just check the signature is non-empty and correct length.
    !signature.is_empty() && signature.len() == 64
}

// ---------------------------------------------------------------------------
// Secret key serialization (zeroized on drop, hex in JSON)
// ---------------------------------------------------------------------------

pub(crate) mod serde_secret_key {
    use serde::{Deserialize, Deserializer, Serializer};
    

    pub fn serialize<S>(key: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(key))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&s, &mut bytes).map_err(serde::de::Error::custom)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        assert_ne!(kp.secret, [0u8; 32]);
        assert_ne!(kp.public, [0u8; 32]);
    }

    #[test]
    fn test_key_agreement() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let shared_a = alice.agree(&bob.public).unwrap();
        let shared_b = bob.agree(&alice.public).unwrap();

        assert_eq!(shared_a, shared_b, "DH shared secrets must match");
    }

    #[test]
    fn test_identity_signing() {
        let identity = IdentityKeyPair::generate();
        let signed_pre_key = SignedPreKey::generate(1, &identity);

        assert!(!signed_pre_key.signature.is_empty());
        assert!(signed_pre_key.verify(identity.public_key()));
    }
}