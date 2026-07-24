use serde::{Deserialize, Serialize};

/// A message sent over the wire after being encrypted by a session.
///
/// This is what gets serialized to JSON (for now) and sent through the
/// relay server. The server can read the metadata (sender, recipient,
/// timestamps) but cannot decrypt the `ciphertext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMessage {
    /// Protocol version.
    pub version: u8,
    /// The AEAD ciphertext.
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption.
    pub nonce: [u8; 12],
    /// The sender's current DH ratchet public key.
    pub ratchet_key: [u8; 32],
    /// Message number in the sending chain.
    pub message_number: u32,
}

/// A top-level envelope that wraps a session message with routing info.
///
/// This is what the server actually sees and routes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Sender's user ID.
    pub sender_id: String,
    /// Recipient's user ID.
    pub recipient_id: String,
    /// Sender's device ID.
    pub sender_device_id: u32,
    /// Timestamp (milliseconds since epoch).
    pub timestamp: u64,
    /// The encrypted session message (as JSON bytes).
    pub content: Vec<u8>,
    /// Message type.
    pub msg_type: MessageType,
}

/// Types of messages the envelope can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// A normal encrypted message.
    Normal,
    /// A pre-key bundle message (first message in a session).
    PreKeyBundle,
    /// A delivery receipt.
    Receipt,
    /// A typing indicator.
    Typing,
}

/// A plaintext chat message (before encryption).
/// This is what the user actually types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub text: String,
    pub timestamp: u64,
}

/// A pre-key bundle message — used when Alice sends the first message to Bob
/// and includes her initial ephemeral key for the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundleMessage {
    /// Alice's identity key.
    pub identity_key: [u8; 32],
    /// Alice's base ephemeral key.
    pub base_key: [u8; 32],
    /// The encrypted session message (wraps the first normal message).
    pub session_message: SessionMessage,
}

/// Server registration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub user_id: String,
    pub identity_key: [u8; 32],
    pub signed_pre_key: PreKeyBundle,
}

/// Bundle of public keys for session establishment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub identity_key: [u8; 32],
    pub device_id: u32,
    pub signed_pre_key_id: u32,
    pub signed_pre_key: [u8; 32],
    pub signed_pre_key_signature: Vec<u8>,
    pub one_time_pre_key_id: Option<u32>,
    pub one_time_pre_key: Option<[u8; 32]>,
}

/// Server response when fetching keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundleResponse {
    pub user_id: String,
    pub bundle: PreKeyBundle,
    pub found: bool,
}

impl SessionMessage {
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_json(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

impl Envelope {
    pub fn new(
        sender_id: String,
        recipient_id: String,
        content: Vec<u8>,
        msg_type: MessageType,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            sender_id,
            recipient_id,
            sender_device_id: 1,
            timestamp,
            content,
            msg_type,
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_json(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_message_roundtrip() {
        let msg = SessionMessage {
            version: 1,
            ciphertext: vec![1, 2, 3, 4],
            nonce: [0; 12],
            ratchet_key: [0xAB; 32],
            message_number: 0,
        };

        let json = msg.to_json().unwrap();
        let deserialized = SessionMessage::from_json(&json).unwrap();

        assert_eq!(deserialized.version, msg.version);
        assert_eq!(deserialized.ciphertext, msg.ciphertext);
        assert_eq!(deserialized.nonce, msg.nonce);
        assert_eq!(deserialized.message_number, msg.message_number);
    }

    #[test]
    fn test_envelope_roundtrip() {
        let env = Envelope::new(
            "alice".to_string(),
            "bob".to_string(),
            vec![1, 2, 3],
            MessageType::Normal,
        );

        let json = env.to_json().unwrap();
        let deserialized = Envelope::from_json(&json).unwrap();

        assert_eq!(deserialized.sender_id, "alice");
        assert_eq!(deserialized.recipient_id, "bob");
        assert_eq!(deserialized.msg_type, MessageType::Normal);
    }
}