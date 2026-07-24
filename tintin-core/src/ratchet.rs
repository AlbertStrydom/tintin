use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cipher::{decrypt, encrypt};
use crate::error::Result;
use crate::keys::KeyPair;

/// The Double Ratchet state for one side of a conversation.
///
/// This tracks the sending and receiving chain states as the ratchet
/// advances with each message.
#[derive(Clone, Serialize, Deserialize)]
pub struct Ratchet {
    /// Our current DH ratchet key pair (rotates with each ratchet step).
    pub dh_ratchet_key: KeyPair,
    /// Their current public ratchet key.
    pub their_ratchet_key: [u8; 32],
    /// The root key — used to derive new chain keys after DH exchanges.
    #[serde(with = "crate::keys::serde_secret_key")]
    pub root_key: [u8; 32],
    /// The sending chain key.
    #[serde(with = "crate::keys::serde_secret_key")]
    pub send_chain_key: [u8; 32],
    /// The receiving chain key.
    #[serde(with = "crate::keys::serde_secret_key")]
    pub recv_chain_key: [u8; 32],
    /// Number of messages sent in the current sending chain.
    pub send_msg_number: u32,
    /// Number of messages received in the current receiving chain.
    pub recv_msg_number: u32,
    /// Previous sending chain length (for skipped/missing messages).
    pub prev_send_count: u32,
    /// Maximum number of skipped messages we'll tolerate.
    pub max_skip: u32,
    /// Whether this ratchet is in the initiator (Alice) role.
    pub is_initiator: bool,
}

impl Ratchet {
    /// Create a new ratchet as the **initiator** (Alice).
    ///
    /// shared_secret must already incorporate the DH between Alice's
    /// ephemeral key (eph_key) and Bob's signed pre-key so that when Bob
    /// receives eph_key.public he can recompute the same shared_secret
    /// and the same chain keys.
    pub fn new_initiator(
        shared_secret: &[u8; 32],
        eph_key: KeyPair,
        bob_signed_pre_key: &[u8; 32],
    ) -> Self {
        // Derive root key and initial sending chain key from the X3DH
        // shared secret, using Alice's ephemeral public as the KDF salt.
        let (root_key, chain_key) =
            crate::cipher::derive_chain_keys(shared_secret, &eph_key.public);

        Self {
            dh_ratchet_key: eph_key,
            their_ratchet_key: *bob_signed_pre_key,
            root_key,
            send_chain_key: chain_key,
            recv_chain_key: [0u8; 32],
            send_msg_number: 0,
            recv_msg_number: 0,
            prev_send_count: 0,
            max_skip: 100,
            is_initiator: true,
        }
    }

    /// Create a new ratchet as the **responder** (Bob).
    ///
    /// * `shared_secret` — must be the same X3DH shared secret Alice computed
    ///   (Bob computes it from his pre-key secret + Alice's ephemeral public)
    /// * `alice_eph_public` — Alice's ephemeral public key (so the KDF
    ///   produces the same root and chain keys Alice has)
    /// * `our_identity_key` — Bob's long-term DH key pair
    pub fn new_responder(
        shared_secret: &[u8; 32],
        alice_eph_public: &[u8; 32],
        our_identity_key: KeyPair,
    ) -> Self {
        let (root_key, chain_key) =
            crate::cipher::derive_chain_keys(shared_secret, alice_eph_public);

        Self {
            dh_ratchet_key: our_identity_key,
            their_ratchet_key: *alice_eph_public,
            root_key,
            send_chain_key: [0u8; 32],
            recv_chain_key: chain_key,
            send_msg_number: 0,
            recv_msg_number: 0,
            prev_send_count: 0,
            max_skip: 100,
            is_initiator: false,
        }
    }

    /// Derive the next message key from the sending chain and ratchet forward.
    /// Returns a 32-byte message encryption key.
    pub fn next_send_key(&mut self) -> [u8; 32] {
        let (new_chain, msg_key) = ratchet_chain_key(&self.send_chain_key);
        self.send_chain_key = new_chain;
        self.send_msg_number += 1;
        msg_key
    }

    /// Derive the next message key from the receiving chain.
    /// Returns a 32-byte message decryption key.
    pub fn next_recv_key(&mut self) -> [u8; 32] {
        let (new_chain, msg_key) = ratchet_chain_key(&self.recv_chain_key);
        self.recv_chain_key = new_chain;
        self.recv_msg_number += 1;
        msg_key
    }

    /// Perform a DH ratchet step: generate a new DH key and derive new
    /// root + chain keys from a DH exchange with the current `their_ratchet_key`.
    pub fn dh_ratchet_step(&mut self) {
        // DH ratchet step:
        //   root_key, chain_key = KDF(root_key, DH(our_new, their_current))
        let dh_output = self.dh_ratchet_key.agree(&self.their_ratchet_key)
            .expect("DH agreement should succeed during ratchet step");
        let (new_root, new_chain) =
            crate::cipher::derive_chain_keys(&self.root_key, &dh_output);

        self.root_key = new_root;
        if self.is_initiator {
            self.send_chain_key = new_chain;
        } else {
            self.recv_chain_key = new_chain;
        }

        self.send_msg_number = 0;
        self.recv_msg_number = 0;
    }

    /// Encrypt a plaintext message using the Double Ratchet.
    /// Returns the ciphertext and the ratchet public key to send along.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<RatchetedMessage> {
        let msg_key = self.next_send_key();
        let (ciphertext, nonce) = encrypt(plaintext, &msg_key)?;

        Ok(RatchetedMessage {
            ratchet_key: self.dh_ratchet_key.public,
            ciphertext,
            nonce,
            message_number: self.send_msg_number - 1,
            previous_count: self.prev_send_count,
        })
    }

    /// Decrypt a ratchet message. Handles DH ratchet steps if needed.
    pub fn decrypt_message(
        &mut self,
        msg: &RatchetedMessage,
    ) -> Result<Vec<u8>> {
        // If the message uses a different DH ratchet key, we need to
        // perform a DH ratchet step first.
        if msg.ratchet_key != self.their_ratchet_key {
            self.their_ratchet_key = msg.ratchet_key;
            self.dh_ratchet_step();
        }

        // For now, assume messages arrive in order (no skipping).
        // Skipped message handling will be added in a future iteration.
        let msg_key = self.next_recv_key();
        decrypt(&msg.ciphertext, &msg_key, &msg.nonce)
    }
}

/// A message encrypted under the Double Ratchet.
/// This is what gets sent over the wire (in a session message wrapper).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetedMessage {
    /// The sender's current DH ratchet public key.
    pub ratchet_key: [u8; 32],
    /// The encrypted payload.
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption.
    pub nonce: [u8; 12],
    /// The message number in the sending chain.
    pub message_number: u32,
    /// How many messages were in the previous sending chain.
    pub previous_count: u32,
}

/// Given a chain key (32 bytes), derive the next chain key and
/// a message key using SHA-256 ratcheting:
///
///   next_chain_key = SHA-256(0x02 || chain_key)
///   message_key    = SHA-256(0x01 || chain_key)
fn ratchet_chain_key(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let next = {
        let mut hasher = Sha256::new();
        hasher.update(&[0x02u8]);
        hasher.update(chain_key);
        hasher.finalize()
    };
    let msg = {
        let mut hasher = Sha256::new();
        hasher.update(&[0x01u8]);
        hasher.update(chain_key);
        hasher.finalize()
    };

    let mut next_key = [0u8; 32];
    let mut msg_key = [0u8; 32];
    next_key.copy_from_slice(&next);
    msg_key.copy_from_slice(&msg);
    (next_key, msg_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn test_ratchet_encrypt_decrypt_alice_bob() {
        // Simulate a conversation between Alice (initiator) and Bob (responder).

        // Bob's long-term DH key pair (his "signed pre-key").
        let bob_dh = KeyPair::generate();

        // Alice generates her ephemeral DH key pair for this session.
        let alice_eph = KeyPair::generate();

        // Compute the X3DH shared secret: DH(alice_eph_secret, bob_public)
        let shared = alice_eph.agree(&bob_dh.public).unwrap();

        // Alice initialises her ratchet as initiator.
        let mut alice_ratchet = Ratchet::new_initiator(&shared, alice_eph, &bob_dh.public);

        // Bob receives Alice's ephemeral public key and computes the same
        // shared secret via DH(bob_secret, alice_eph_public).
        let shared_bob = bob_dh.agree(&alice_ratchet.dh_ratchet_key.public).unwrap();
        assert_eq!(shared, shared_bob, "both sides must compute the same shared secret");

        // Bob initialises his ratchet as responder.
        let mut bob_ratchet = Ratchet::new_responder(
            &shared_bob,
            &alice_ratchet.dh_ratchet_key.public,
            bob_dh,
        );

        // Alice sends a message to Bob.
        let plaintext = b"Hello Bob! This is a secret message from Alice.";
        let msg = alice_ratchet.encrypt_message(plaintext).unwrap();

        // Bob receives and decrypts it.
        let decrypted = bob_ratchet.decrypt_message(&msg).unwrap();
        assert_eq!(decrypted, plaintext);

        // Bob replies.
        let reply = b"Hey Alice! Got your message.";
        let msg2 = bob_ratchet.encrypt_message(reply).unwrap();
        let decrypted2 = alice_ratchet.decrypt_message(&msg2).unwrap();
        assert_eq!(decrypted2, reply);
    }

    #[test]
    fn test_chain_key_ratchet() {
        let key = [0xABu8; 32];
        let (next, msg) = ratchet_chain_key(&key);
        assert_ne!(next, key);
        assert_ne!(msg, key);
        assert_ne!(next, msg);

        // Deterministic
        let (next2, msg2) = ratchet_chain_key(&key);
        assert_eq!(next, next2);
        assert_eq!(msg, msg2);
    }
}