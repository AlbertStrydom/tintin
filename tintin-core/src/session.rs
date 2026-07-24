use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::keys::{
    IdentityKeyPair, KeyPair, SignedPreKey,
};
use crate::message::SessionMessage;
use crate::ratchet::Ratchet;

/// The role of the local user in a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionRole {
    Initiator,
    Responder,
}

/// A secure session between two TinTin users.
///
/// This holds all state needed to encrypt and decrypt messages using
/// the Double Ratchet algorithm. Each user has one session per
/// remote user + device combination.
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    /// The remote user's identifier.
    pub remote_user_id: String,
    /// The remote device ID.
    pub remote_device_id: u32,
    /// Our role in this session.
    pub role: SessionRole,
    /// Our identity key pair.
    pub our_identity: IdentityKeyPair,
    /// Their identity public key.
    pub their_identity: [u8; 32],
    /// The Double Ratchet state.
    pub ratchet: Ratchet,
    /// Session version for migration.
    pub version: u8,
}

impl Session {
    /// Create a new session as the **initiator** (Alice establishes session with Bob).
    ///
    /// Alice generates an ephemeral key, uses Bob's signed pre-key to compute
    /// the shared secret, and initialises the Double Ratchet.
    pub fn new_initiator(
        our_identity: IdentityKeyPair,
        remote_user_id: String,
        remote_device_id: u32,
        their_identity_key: [u8; 32],
        signed_pre_key_public: &[u8; 32],
    ) -> Result<Self> {
        // Alice generates an ephemeral DH key pair and computes the shared
        // secret via DH(eph_secret, bob_signed_pre_key_public).
        let eph_key = KeyPair::generate();
        let shared_secret = eph_key.agree(signed_pre_key_public)?;

        let ratchet = Ratchet::new_initiator(&shared_secret, eph_key, signed_pre_key_public);

        Ok(Self {
            remote_user_id,
            remote_device_id,
            role: SessionRole::Initiator,
            our_identity,
            their_identity: their_identity_key,
            ratchet,
            version: crate::PROTOCOL_VERSION,
        })
    }

    /// Create a new session as the **responder** (Bob responds to Alice).
    ///
    /// Bob receives Alice's ephemeral public key, uses his own signed pre-key
    /// to compute the same shared secret, and initialises the ratchet as responder.
    pub fn new_responder(
        our_identity: IdentityKeyPair,
        remote_user_id: String,
        remote_device_id: u32,
        their_identity_key: [u8; 32],
        alice_eph_public: &[u8; 32],
        our_signed_pre_key: SignedPreKey,
    ) -> Result<Self> {
        // DH(our_signed_pre_key_secret, alice_eph_public) produces the same
        // shared secret Alice computed.
        let shared_secret = our_signed_pre_key.key_pair.agree(alice_eph_public)?;

        let ratchet = Ratchet::new_responder(
            &shared_secret,
            alice_eph_public,
            our_signed_pre_key.key_pair,
        );

        Ok(Self {
            remote_user_id,
            remote_device_id,
            role: SessionRole::Responder,
            our_identity,
            their_identity: their_identity_key,
            ratchet,
            version: crate::PROTOCOL_VERSION,
        })
    }

    /// Encrypt a plaintext message using the session's Double Ratchet.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<SessionMessage> {
        let ratcheted = self.ratchet.encrypt_message(plaintext)?;
        Ok(SessionMessage {
            version: self.version,
            ciphertext: ratcheted.ciphertext,
            nonce: ratcheted.nonce,
            ratchet_key: ratcheted.ratchet_key,
            message_number: ratcheted.message_number,
        })
    }

    /// Decrypt a session message using the session's Double Ratchet.
    pub fn decrypt(&mut self, message: &SessionMessage) -> Result<Vec<u8>> {
        // Convert the session message into a ratchet message and decrypt.
        let ratchet_msg = crate::ratchet::RatchetedMessage {
            ratchet_key: message.ratchet_key,
            ciphertext: message.ciphertext.clone(),
            nonce: message.nonce,
            message_number: message.message_number,
            previous_count: 0,
        };
        self.ratchet.decrypt_message(&ratchet_msg)
    }

    /// The remote user's identifier.
    pub fn remote_id(&self) -> &str {
        &self.remote_user_id
    }
}

/// Manage multiple sessions in a session store.
/// For Phase 1 this is an in-memory store; later it will be backed by SQLCipher.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionStore {
    sessions: Vec<Session>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
        }
    }

    /// Get a session for a specific remote user + device.
    pub fn get(&self, remote_user_id: &str, device_id: u32) -> Option<&Session> {
        self.sessions
            .iter()
            .find(|s| s.remote_user_id == remote_user_id && s.remote_device_id == device_id)
    }

    /// Get a mutable reference to a session.
    pub fn get_mut(
        &mut self,
        remote_user_id: &str,
        device_id: u32,
    ) -> Option<&mut Session> {
        self.sessions
            .iter_mut()
            .find(|s| s.remote_user_id == remote_user_id && s.remote_device_id == device_id)
    }

    /// Add a session to the store, replacing any existing session for the same user+device.
    pub fn add(&mut self, session: Session) {
        let id = session.remote_user_id.clone();
        let dev = session.remote_device_id;
        self.sessions.retain(|s| !(s.remote_user_id == id && s.remote_device_id == dev));
        self.sessions.push(session);
    }

    /// Remove a session.
    pub fn remove(&mut self, remote_user_id: &str, device_id: u32) {
        self.sessions
            .retain(|s| !(s.remote_user_id == remote_user_id && s.remote_device_id == device_id));
    }

    /// Number of sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKeyPair, SignedPreKey};

    #[test]
    fn test_session_encrypt_decrypt() {
        // Bob's key material
        let bob_identity = IdentityKeyPair::generate();
        let bob_signed = SignedPreKey::generate(1, &bob_identity);

        // Alice's key material
        let alice_identity = IdentityKeyPair::generate();

        // Alice initiates a session with Bob (she generates an ephemeral key internally)
        let mut alice_session = Session::new_initiator(
            alice_identity,
            "bob".to_string(),
            1,
            *bob_identity.public_key(),
            &bob_signed.key_pair.public,
        )
        .expect("Alice should create session");

        // Bob reads Alice's ephemeral public key from the session
        let alice_eph = alice_session.ratchet.dh_ratchet_key.public;

        // Bob responds with a session for Alice
        let mut bob_session = Session::new_responder(
            bob_identity,
            "alice".to_string(),
            1,
            *alice_session.our_identity.public_key(),
            &alice_eph,
            bob_signed,
        )
        .expect("Bob should create session");

        // Alice sends a message
        let msg = b"Hey Bob!";
        let encrypted = alice_session.encrypt(msg).expect("Encrypt should succeed");

        // Bob decrypts it
        let decrypted = bob_session.decrypt(&encrypted).expect("Decrypt should succeed");
        assert_eq!(decrypted, msg);

        // Bob replies
        let reply = b"Hey Alice!";
        let encrypted2 = bob_session.encrypt(reply).expect("Encrypt should succeed");
        let decrypted2 = alice_session.decrypt(&encrypted2).expect("Decrypt should succeed");
        assert_eq!(decrypted2, reply);
    }

    #[test]
    fn test_session_store() {
        let mut store = SessionStore::new();
        assert_eq!(store.len(), 0);

        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_signed = SignedPreKey::generate(1, &bob_identity);

        let session = Session::new_initiator(
            alice_identity,
            "bob".to_string(),
            1,
            *bob_identity.public_key(),
            &bob_signed.key_pair.public,
        )
        .unwrap();

        store.add(session);
        assert_eq!(store.len(), 1);
        assert!(store.get("bob", 1).is_some());
        assert!(store.get("alice", 1).is_none());
    }
}