use thiserror::Error;

/// Errors that can occur in the TinTin core library.
#[derive(Error, Debug)]
pub enum TinTinError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Session not found")]
    SessionNotFound,

    #[error("Session is in an invalid state")]
    InvalidSessionState,

    #[error("Protocol version mismatch")]
    ProtocolVersionMismatch,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Key agreement failed: {0}")]
    KeyAgreementFailed(String),
}

/// Convenience type alias.
pub type Result<T> = std::result::Result<T, TinTinError>;