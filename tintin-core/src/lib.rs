//! # TinTin Core
//!
//! The shared Rust library that powers end-to-end encryption for all TinTin clients.
//!
//! ## Architecture
//!
//! This library implements the core cryptographic primitives used in the
//! Signal Protocol — X25519 key exchange, the Double Ratchet algorithm,
//! and AEAD message encryption. Every operation is constant-time where
//! possible, and secrets are zeroed on drop.
//!
//! ## Modules
//!
//! - [`keys`] — Key generation, identity keys, pre-keys
//! - [`cipher`] — Symmetric encryption (ChaCha20-Poly1305, AES-GCM)
//! - [`ratchet`] — Double Ratchet algorithm
//! - [`session`] — Session state management
//! - [`message`] — Wire-format message types
//! - [`error`] — Error types

pub mod cipher;
pub mod error;
pub mod keys;
pub mod message;
pub mod ratchet;
pub mod session;

pub use cipher::*;
pub use error::*;
pub use keys::{
    IdentityKeyPair, KeyPair, OneTimePreKey, OneTimePreKeyPublic, SignedPreKey,
    SignedPreKeyPublic,
};
pub use message::{ChatMessage, Envelope, MessageType, PreKeyBundleMessage, SessionMessage};
pub use ratchet::{Ratchet, RatchetedMessage};
pub use session::{Session, SessionRole, SessionStore};

/// The current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;