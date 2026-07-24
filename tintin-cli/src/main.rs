//! TinTin CLI — Terminal Chat Client (Phase 1)
//!
//! A command-line chat client that connects to the TinTin Relay Server.
//! It handles user registration, session establishment, and sending/
//! receiving end-to-end encrypted messages.

use std::io::{self, Write};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use tintin_core::{
    Envelope, IdentityKeyPair, KeyPair, MessageType, Session, SessionMessage,
    SessionStore, SignedPreKey, TinTinError,
};

/// A connected TinTin client instance.
struct TinTinClient {
    /// Our user ID (phone number or username).
    user_id: String,
    /// Our long-term identity key pair.
    identity: IdentityKeyPair,
    /// Our signed pre-keys (one for now).
    signed_pre_key: SignedPreKey,
    /// Sessions with other users (one per user+device).
    sessions: SessionStore,
    /// Writer half of the TCP stream.
    writer: Option<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    /// Reader half of the TCP stream.
    reader: Option<Mutex<tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>>>,
}

impl TinTinClient {
    /// Create a new client and generate our identity keys.
    fn new(user_id: &str) -> Self {
        let identity = IdentityKeyPair::generate();
        let signed_pre_key = SignedPreKey::generate(1, &identity);

        Self {
            user_id: user_id.to_string(),
            identity,
            signed_pre_key,
            sessions: SessionStore::new(),
            writer: None,
            reader: None,
        }
    }

    /// Connect to the relay server and register.
    async fn connect(&mut self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(addr).await?;
        let (reader, writer) = stream.into_split();
        self.writer = Some(Mutex::new(writer));
        self.reader = Some(Mutex::new(BufReader::new(reader)));

        self.register().await?;
        println!("✓ Connected and registered as '{}'", self.user_id);
        Ok(())
    }

    /// Register our identity and pre-key bundle with the relay server.
    async fn register(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bundle = tintin_core::message::PreKeyBundle {
            identity_key: *self.identity.public_key(),
            device_id: 1,
            signed_pre_key_id: self.signed_pre_key.id,
            signed_pre_key: self.signed_pre_key.key_pair.public,
            signed_pre_key_signature: self.signed_pre_key.signature.clone(),
            one_time_pre_key_id: None,
            one_time_pre_key: None,
        };

        let request = serde_json::json!({
            "cmd": "register",
            "user_id": self.user_id,
            "identity_key": self.identity.public_key(),
            "signed_pre_key": bundle,
        });

        self.send_json(&request).await?;
        let resp = self.recv_json().await?;

        if resp["status"] != "ok" {
            return Err(format!("Registration failed: {}", resp["error"]).into());
        }

        Ok(())
    }

    /// Look up another user's pre-key bundle from the server.
    async fn fetch_bundle(
        &self,
        user_id: &str,
    ) -> Result<tintin_core::message::PreKeyBundle, Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "fetch_keys",
            "user_id": user_id,
        });

        self.send_json(&request).await?;
        let resp = self.recv_json().await?;

        if resp["status"] != "ok" {
            return Err(format!("User '{}' not found", user_id).into());
        }

        let bundle: tintin_core::message::PreKeyBundle =
            serde_json::from_value(resp["data"].clone())?;

        Ok(bundle)
    }

    /// Send an encrypted message to another user.
    async fn send_message(
        &mut self,
        recipient: &str,
        plaintext: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get or create a session with this user.
        let session = if let Some(s) = self.sessions.get_mut(recipient, 1) {
            s
        } else {
            // Fetch their pre-key bundle and establish a session.
            let bundle = self.fetch_bundle(recipient).await?;
            let new_session = Session::new_initiator(
                IdentityKeyPair {
                    key_pair: KeyPair {
                        secret: self.identity.key_pair.secret,
                        public: self.identity.key_pair.public,
                    },
                },
                recipient.to_string(),
                1,
                bundle.identity_key,
                &bundle.signed_pre_key,
            )?;

            self.sessions.add(new_session);
            self.sessions.get_mut(recipient, 1).unwrap()
        };

        // Encrypt the message using the session's Double Ratchet.
        let encrypted = session.encrypt(plaintext.as_bytes())?;

        // Wrap in an envelope and send via the relay.
        let envelope = Envelope::new(
            self.user_id.clone(),
            recipient.to_string(),
            encrypted.to_json()?,
            MessageType::Normal,
        );

        let request = serde_json::json!({
            "cmd": "send",
            "envelope": envelope,
        });

        self.send_json(&request).await?;
        let resp = self.recv_json().await?;

        if resp["status"] != "ok" {
            return Err(format!("Send failed: {}", resp["error"]).into());
        }

        println!("✓ Sent E2E encrypted message to '{}'", recipient);
        Ok(())
    }

    /// Poll for and decrypt incoming messages.
    async fn receive_messages(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "receive",
            "user_id": self.user_id,
        });

        self.send_json(&request).await?;
        let resp = self.recv_json().await?;

        if resp["status"] != "ok" {
            return Err(format!("Receive failed: {}", resp["error"]).into());
        }

        let messages = resp["data"]["messages"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        if messages.is_empty() {
            println!("📭 No new messages.");
            return Ok(());
        }

        println!("📬 {} new message(s):", messages.len());

        for msg_value in &messages {
            let envelope: Envelope = serde_json::from_value(msg_value.clone())?;
            let session_msg = SessionMessage::from_json(&envelope.content)?;

            // Get or create the session for this sender.
            let result = if let Some(session) = self.sessions.get_mut(&envelope.sender_id, 1) {
                session.decrypt(&session_msg)
            } else if envelope.msg_type == MessageType::PreKeyBundle {
                // First message from someone — we need to create a responder session.
                // For now, skip creation and report need for bundle info.
                Err(TinTinError::SessionNotFound)
            } else {
                Err(TinTinError::SessionNotFound)
            };

            match result {
                Ok(plaintext) => {
                    let text = String::from_utf8_lossy(&plaintext);
                    println!("💬 {}: {}", envelope.sender_id, text);
                }
                Err(e) => {
                    println!("⚠️ Could not decrypt message from {}: {}", envelope.sender_id, e);
                }
            }
        }

        Ok(())
    }

    /// Send a raw JSON value to the server.
    async fn send_json(
        &self,
        value: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut json = serde_json::to_string(value)?;
        json.push('\n');
        if let Some(writer) = &self.writer {
            let mut writer = writer.lock().await;
            writer.write_all(json.as_bytes()).await?;
            writer.flush().await?;
        }
        Ok(())
    }

    /// Receive a raw JSON value from the server.
    async fn recv_json(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        if let Some(reader) = &self.reader {
            let mut reader = reader.lock().await;
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                return Err("Connection closed".into());
            }
            Ok(serde_json::from_str(line.trim())?)
        } else {
            Err("Not connected".into())
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════╗");
    println!("║    TinTin CLI v0.1.0         ║");
    println!("║    E2E Encrypted Messaging   ║");
    println!("╚══════════════════════════════╝");
    println!();

    // Get user identity
    print!("Your user ID (e.g. alice): ");
    io::stdout().flush()?;
    let mut user_id = String::new();
    io::stdin().read_line(&mut user_id)?;
    let user_id = user_id.trim();

    let server_addr = "127.0.0.1:9666";
    let mut client = TinTinClient::new(user_id);
    client.connect(server_addr).await?;

    println!();
    println!("Available commands:");
    println!("  /msg username text  — Send an E2E encrypted message");
    println!("         Example: /msg bob Hello Bob!");
    println!("  /recv               — Check for new messages");
    println!("  /help               — Show this help");
    println!("  /quit               — Exit");
    println!();

    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        if input == "/quit" {
            break;
        }

        if input == "/help" {
            println!("Commands:");
            println!("  /msg username text  — Send an E2E encrypted message");
            println!("         Example: /msg bob Hello Bob!");
            println!("  /recv               — Poll for new messages");
            println!("  /help               — Show this help");
            println!("  /quit               — Exit");
            continue;
        }

        if input == "/recv" {
            if let Err(e) = client.receive_messages().await {
                eprintln!("Error: {e}");
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/msg ") {
            // Parse: /msg <recipient> <message text>
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            if parts.len() < 2 {
                eprintln!("Usage: /msg username text");
                eprintln!("  Example: /msg bob Hello Bob!");
                continue;
            }
            let recipient = parts[0];
            let text = parts[1];

            if let Err(e) = client.send_message(recipient, text).await {
                eprintln!("Error: {e}");
            }
            continue;
        }

        eprintln!("Unknown command. Type /help for available commands.");
    }

    println!("Goodbye!");
    Ok(())
}