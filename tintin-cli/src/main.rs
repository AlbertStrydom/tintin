//! TinTin CLI — Terminal Chat Client (Phase 1)
//!
//! A command-line chat client that connects to the TinTin Relay Server.
//! It handles user registration, session establishment, and sending/
//! receiving end-to-end encrypted messages.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use tintin_core::{
    Envelope, IdentityKeyPair, KeyPair, MessageType, PreKeyBundleMessage, ReceiptContent,
    ReceiptType, Session, SessionMessage, SessionStore, SignedPreKey,
};

/// Status of a sent message for ✓/✓✓ tracking.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum MessageStatus {
    Sent,
    Delivered,
    Read,
}

/// A sent message with its delivery status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SentMessage {
    recipient: String,
    text: String,
    timestamp: u64,
    status: MessageStatus,
}

/// A group we belong to.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct GroupInfo {
    group_id: String,
    name: String,
    creator: String,
    role: String,
}

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
    /// Track sent messages for ✓/✓✓ status.
    sent_messages: Vec<SentMessage>,
    /// Groups we belong to (group_id -> info).
    groups: HashMap<String, GroupInfo>,
}

impl TinTinClient {
    /// Create a new client and generate our identity keys.
    fn new(user_id: &str) -> Self {
        let identity = IdentityKeyPair::generate();
        let signed_pre_key = SignedPreKey::generate(1, &identity);

        let mut client = Self {
            user_id: user_id.to_string(),
            identity,
            signed_pre_key,
            sessions: SessionStore::new(),
            writer: None,
            reader: None,
            sent_messages: Vec::new(),
            groups: HashMap::new(),
        };
        client.load_history();
        client.load_groups();
        client
    }

    /// Path to the history file for this user.
    fn history_path(&self) -> PathBuf {
        // Use USERPROFILE (Windows) or HOME (Unix) to find ~/.tintin/<user_id>.json
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        let dir = PathBuf::from(home).join(".tintin");
        // Ensure directory exists.
        let _ = std::fs::create_dir_all(&dir);
        dir.join(format!("{}.json", self.user_id))
    }

    /// Load sent message history from disk.
    fn load_history(&mut self) {
        let path = self.history_path();
        if !path.exists() {
            return;
        }
        match std::fs::read_to_string(&path) {
            Ok(json) => {
                if let Ok(msgs) = serde_json::from_str::<Vec<SentMessage>>(&json) {
                    self.sent_messages = msgs;
                }
            }
            Err(e) => eprintln!("⚠️ Could not load message history: {e}"),
        }
    }

    /// Save sent message history to disk.
    fn save_history(&self) {
        let path = self.history_path();
        match serde_json::to_string_pretty(&self.sent_messages) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, &json) {
                    eprintln!("⚠️ Could not save message history: {e}");
                }
            }
            Err(e) => eprintln!("⚠️ Could not serialize message history: {e}"),
        }
    }

    /// Path to the groups file for this user.
    fn groups_path(&self) -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        let dir = PathBuf::from(home).join(".tintin");
        let _ = std::fs::create_dir_all(&dir);
        dir.join(format!("{}_groups.json", self.user_id))
    }

    /// Load groups from disk.
    fn load_groups(&mut self) {
        let path = self.groups_path();
        if !path.exists() {
            return;
        }
        if let Ok(json) = std::fs::read_to_string(&path) {
            if let Ok(groups) = serde_json::from_str::<HashMap<String, GroupInfo>>(&json) {
                self.groups = groups;
            }
        }
    }

    /// Save groups to disk.
    fn save_groups(&self) {
        let path = self.groups_path();
        if let Ok(json) = serde_json::to_string_pretty(&self.groups) {
            let _ = std::fs::write(&path, &json);
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
            serde_json::from_value(resp["data"]["signed_pre_key"].clone())?;

        Ok(bundle)
    }

    /// Send an encrypted message to another user.
    ///
    /// Messages to yourself ("Saved Messages") skip encryption and are
    /// sent as plaintext — no session needed.
    async fn send_message(
        &mut self,
        recipient: &str,
        plaintext: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Saved Messages — just send raw plaintext, no encryption.
        let (content, msg_type) = if recipient == self.user_id {
            (plaintext.as_bytes().to_vec(), MessageType::Normal)
        } else {
            self.send_encrypted(recipient, plaintext).await?
        };

        // Wrap in an envelope and send via the relay.
        let envelope = Envelope::new(
            self.user_id.clone(),
            recipient.to_string(),
            content,
            msg_type,
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

        // Track this sent message for ✓/✓✓ status.
        self.sent_messages.push(SentMessage {
            recipient: recipient.to_string(),
            text: plaintext.to_string(),
            timestamp: envelope.timestamp,
            status: MessageStatus::Sent,
        });
        self.save_history();
        println!("✓ Sent to '{}' (✓)", recipient);
        Ok(())
    }

    /// Send an E2E encrypted message to another user (not self).
    async fn send_encrypted(
        &mut self,
        recipient: &str,
        plaintext: &str,
    ) -> Result<(Vec<u8>, MessageType), Box<dyn std::error::Error>> {
        // Track whether this is the first message (new session).
        let mut is_new = false;

        // Get or create a session with this user.
        let session = if let Some(s) = self.sessions.get_mut(recipient, 1) {
            s
        } else {
            is_new = true;
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

        // For the first message, wrap in a PreKeyBundle so the recipient
        // can create a responder session.
        Ok(if is_new {
            let prekey = PreKeyBundleMessage {
                identity_key: *self.identity.public_key(),
                base_key: session.ratchet.dh_ratchet_key.public,
                session_message: encrypted,
            };
            (serde_json::to_vec(&prekey)?, MessageType::PreKeyBundle)
        } else {
            (encrypted.to_json()?, MessageType::Normal)
        })
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

            match envelope.msg_type {
                MessageType::PreKeyBundle => {
                    let prekey: PreKeyBundleMessage =
                        serde_json::from_slice(&envelope.content)?;

                    let mut new_session = Session::new_responder(
                        IdentityKeyPair {
                            key_pair: KeyPair {
                                secret: self.identity.key_pair.secret,
                                public: self.identity.key_pair.public,
                            },
                        },
                        envelope.sender_id.clone(),
                        envelope.sender_device_id,
                        prekey.identity_key,
                        &prekey.base_key,
                        self.signed_pre_key.clone(),
                    )?;

                    match new_session.decrypt(&prekey.session_message) {
                        Ok(plaintext) => {
                            self.sessions.add(new_session);
                            Self::display_decrypted(&envelope.sender_id, &plaintext);
                            // Send a read receipt back to the sender.
                            self.send_receipt(
                                &envelope.sender_id,
                                &envelope.sender_id,
                                envelope.timestamp,
                                ReceiptType::Read,
                            )
                            .await
                            .ok();
                        }
                        Err(e) => {
                            println!(
                                "⚠️ Could not decrypt message from {}: {}",
                                envelope.sender_id, e
                            );
                        }
                    }
                }
                MessageType::Normal => {
                    // Saved Messages (self) — display plaintext directly.
                    if envelope.sender_id == self.user_id {
                        let text = String::from_utf8_lossy(&envelope.content);
                        println!("📝 Saved: {}", text);
                        continue;
                    }

                    let session_msg = match SessionMessage::from_json(&envelope.content) {
                        Ok(m) => m,
                        Err(e) => {
                            println!("⚠️ Invalid message from {}: {}", envelope.sender_id, e);
                            continue;
                        }
                    };
                    if let Some(session) = self.sessions.get_mut(&envelope.sender_id, 1) {
                        match session.decrypt(&session_msg) {
                            Ok(plaintext) => {
                                Self::display_decrypted(&envelope.sender_id, &plaintext);
                                // Send a read receipt back to the sender.
                                self.send_receipt(
                                    &envelope.sender_id,
                                    &envelope.sender_id,
                                    envelope.timestamp,
                                    ReceiptType::Read,
                                )
                                .await
                                .ok();
                            }
                            Err(e) => {
                                println!(
                                    "⚠️ Could not decrypt message from {}: {}",
                                    envelope.sender_id, e
                                );
                            }
                        }
                    } else {
                        println!(
                            "⚠️ No session with {}. They need to message you first.",
                            envelope.sender_id
                        );
                    }
                }
                MessageType::Receipt => {
                    match serde_json::from_slice::<ReceiptContent>(&envelope.content) {
                        Ok(receipt) => match receipt.receipt_type {
                            ReceiptType::Delivery => {
                                // Update our sent message to Delivered.
                                let mut found_text = String::new();
                                let updated = self.sent_messages.iter_mut().find(|m| {
                                    m.recipient == envelope.sender_id
                                        && m.timestamp == receipt.original_timestamp
                                });
                                if let Some(msg) = updated {
                                    msg.status = MessageStatus::Delivered;
                                    found_text = msg.text.clone();
                                }
                                if !found_text.is_empty() {
                                    self.save_history();
                                    println!(
                                        "✓✓ '{}' delivered — \"{}\"",
                                        envelope.sender_id, found_text
                                    );
                                }
                            }
                            ReceiptType::Read => {
                                let mut found_text = String::new();
                                let updated = self.sent_messages.iter_mut().find(|m| {
                                    m.recipient == envelope.sender_id
                                        && m.timestamp == receipt.original_timestamp
                                });
                                if let Some(msg) = updated {
                                    msg.status = MessageStatus::Read;
                                    found_text = msg.text.clone();
                                }
                                if !found_text.is_empty() {
                                    self.save_history();
                                    println!(
                                        "✓✓ '{}' read — \"{}\"",
                                        envelope.sender_id, found_text
                                    );
                                }
                            }
                        },
                        Err(_) => {
                            // If we can't parse the receipt, ignore it.
                        }
                    }
                }
                _ => {
                    println!("⚠️ Unknown message type from {}", envelope.sender_id);
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

    /// Send a delivery or read receipt to a user.
    async fn send_receipt(
        &self,
        recipient: &str,
        original_sender: &str,
        original_timestamp: u64,
        receipt_type: ReceiptType,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let receipt = ReceiptContent {
            receipt_type,
            original_sender: original_sender.to_string(),
            original_timestamp,
        };
        let receipt_bytes = serde_json::to_vec(&receipt)?;
        let receipt_env = Envelope::new(
            self.user_id.clone(),
            recipient.to_string(),
            receipt_bytes,
            MessageType::Receipt,
        );
        let request = serde_json::json!({
            "cmd": "send",
            "envelope": receipt_env,
        });
        self.send_json(&request).await?;
        let _resp = self.recv_json().await?; // ignore response
        Ok(())
    }

    /// List all registered users on the server.
    async fn list_users(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let request = serde_json::json!({ "cmd": "list_users" });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to list users: {}", resp["error"]).into());
        }
        let users: Vec<String> = resp["data"]["users"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        Ok(users)
    }

    // ── Group methods ──────────────────────────────────────────

    /// Create a new group on the server.
    async fn create_group(
        &mut self,
        name: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "create_group",
            "name": name,
            "creator": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to create group: {}", resp["error"]).into());
        }
        let group_id = resp["data"]["group_id"]
            .as_str()
            .unwrap_or("")
            .to_string();
        // Store locally.
        self.groups.insert(
            group_id.clone(),
            GroupInfo {
                group_id: group_id.clone(),
                name: name.to_string(),
                creator: self.user_id.clone(),
                role: "admin".to_string(),
            },
        );
        self.save_groups();
        Ok(group_id)
    }

    /// Join an existing group.
    async fn join_group(&mut self, group_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "join_group",
            "group_id": group_id,
            "user_id": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to join group: {}", resp["error"]).into());
        }
        // Refresh local group info.
        self.sync_groups().await?;
        Ok(())
    }

    /// Leave a group.
    async fn leave_group(&mut self, group_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "leave_group",
            "group_id": group_id,
            "user_id": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to leave group: {}", resp["error"]).into());
        }
        self.groups.remove(group_id);
        self.save_groups();
        Ok(())
    }

    /// Sync local group list from server.
    async fn sync_groups(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "my_groups",
            "user_id": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to list groups: {}", resp["error"]).into());
        }
        self.groups.clear();
        if let Some(groups) = resp["data"]["groups"].as_array() {
            for g in groups {
                if let Some(info) = serde_json::from_value::<GroupInfo>(g.clone()).ok() {
                    self.groups.insert(info.group_id.clone(), info);
                }
            }
        }
        self.save_groups();
        Ok(())
    }

    /// Get member list for a group.
    async fn group_members(&self, group_id: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "group_members",
            "group_id": group_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to get members: {}", resp["error"]).into());
        }
        let members: Vec<String> = resp["data"]["members"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        Ok(members)
    }

    /// Send a message to a group — encrypts once per member using
    /// the existing pairwise session.
    async fn send_group_message(
        &mut self,
        group_id: &str,
        plaintext: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get group info and member list.
        let group_name = self
            .groups
            .get(group_id)
            .map(|g| g.name.clone())
            .unwrap_or_else(|| group_id.to_string());

        let members = self.group_members(group_id).await?;
        let others: Vec<&str> = members
            .iter()
            .filter(|m| *m != &self.user_id)
            .map(|m| m.as_str())
            .collect();

        if others.is_empty() {
            // Only ourselves — save as a regular saved message.
            let my_id = self.user_id.clone();
            return self.send_message(&my_id, plaintext).await;
        }

        // Build the group-tagged payload.
        let payload = serde_json::json!({
            "__tintin_type": "group",
            "group_id": group_id,
            "group_name": group_name,
            "text": plaintext,
        });
        let payload_bytes = serde_json::to_vec(&payload)?;

        // Send to each other member encrypted with their session.
        for member in &others {
            // Get or create session for this member.
            let is_new = self.sessions.get_mut(member, 1).is_none();
            if is_new {
                let bundle = self.fetch_bundle(member).await?;
                let new_session = Session::new_initiator(
                    IdentityKeyPair {
                        key_pair: KeyPair {
                            secret: self.identity.key_pair.secret,
                            public: self.identity.key_pair.public,
                        },
                    },
                    member.to_string(),
                    1,
                    bundle.identity_key,
                    &bundle.signed_pre_key,
                )?;
                self.sessions.add(new_session);
            }

            let session = self.sessions.get_mut(member, 1).unwrap();
            let encrypted = session.encrypt(&payload_bytes)?;

            let (content, msg_type) = if is_new {
                let prekey = PreKeyBundleMessage {
                    identity_key: *self.identity.public_key(),
                    base_key: session.ratchet.dh_ratchet_key.public,
                    session_message: encrypted,
                };
                (serde_json::to_vec(&prekey)?, MessageType::PreKeyBundle)
            } else {
                (encrypted.to_json()?, MessageType::Normal)
            };

            let envelope = Envelope::new(
                self.user_id.clone(),
                member.to_string(),
                content,
                msg_type,
            );
            let request = serde_json::json!({ "cmd": "send", "envelope": envelope });
            self.send_json(&request).await?;
            let resp = self.recv_json().await?;
            if resp["status"] != "ok" {
                eprintln!("  ⚠️  Failed to send to {}: {}", member, resp["error"]);
            }
        }

        // Track in sent messages.
        self.sent_messages.push(SentMessage {
            recipient: format!("[{}] {}", group_name, group_id),
            text: plaintext.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            status: MessageStatus::Sent,
        });
        self.save_history();
        println!("✓ Sent to group '{}' ({} members)", group_name, others.len());
        Ok(())
    }

    /// Display decrypted message content, detecting group-tagged payloads.
    fn display_decrypted(sender: &str, plaintext: &[u8]) {
        // Check for TinTin structured message (group chat, etc.)
        if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(plaintext) {
            if let Some(tt_type) = payload.get("__tintin_type").and_then(|v| v.as_str()) {
                match tt_type {
                    "group" => {
                        let gname = payload["group_name"].as_str().unwrap_or("Group");
                        let text = payload["text"].as_str().unwrap_or("");
                        println!("[{}] {}: {}", gname, sender, text);
                        return;
                    }
                    _ => {}
                }
            }
        }
        // Regular message.
        let text = String::from_utf8_lossy(plaintext);
        println!("💬 {}: {}", sender, text);
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
    println!("  /msg <yourname> ... — Saved Messages (message yourself)");
    println!("  /recv               — Check for new messages");
    println!("  /users              — List registered users");
    println!("  /mygroups           — List your groups");
    println!("  /group create name  — Create a new group");
    println!("  /group join id      — Join an existing group");
    println!("  /group leave id     — Leave a group");
    println!("  /group send id text — Send to a group");
    println!("  /status             — Show sent message status (✓/✓✓)");
    println!("  /help               — Show this help");
    println!("  /quit               — Exit");
    println!();
    println!("Status indicators:");
    println!("  ✓   — Sent (stored on server)");
    println!("  ✓✓  — Delivered (recipient's server received it)");
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
            println!("  /msg <yourname> ... — Saved Messages (message yourself)");
            println!("  /recv               — Poll for new messages");
            println!("  /users              — List registered users");
            println!("  /mygroups           — List your groups");
            println!("  /group create name  — Create a new group");
            println!("  /group join id      — Join a group");
            println!("  /group leave id     — Leave a group");
            println!("  /group send id text — Send to a group");
            println!("  /status             — Show sent message status (✓/✓✓)");
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

        if input == "/status" {
            let sent = &client.sent_messages;
            if sent.is_empty() {
                println!("No sent messages yet.");
            } else {
                for msg in sent {
                    let status = match msg.status {
                        MessageStatus::Sent => "✓",
                        MessageStatus::Delivered => "✓✓",
                        MessageStatus::Read => "✓✓",
                    };
                    println!("  {status} {} → {} ({})", msg.text, msg.recipient, status);
                }
            }
            continue;
        }

        if input == "/users" {
            match client.list_users().await {
                Ok(users) => {
                    if users.is_empty() {
                        println!("No registered users.");
                    } else {
                        println!("Registered users ({}):", users.len());
                        for u in &users {
                            let me = if u == &client.user_id { " (you)" } else { "" };
                            println!("  - {}{}", u, me);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {e}"),
            }
            continue;
        }

        if input == "/mygroups" {
            match client.sync_groups().await {
                Ok(()) => {
                    if client.groups.is_empty() {
                        println!("You are not in any groups.");
                    } else {
                        println!("Your groups:");
                        for g in client.groups.values() {
                            let role = if g.role == "admin" { " (admin)" } else { "" };
                            println!("  {}{} — {}", g.name, role, g.group_id);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {e}"),
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/group ") {
            let parts: Vec<&str> = rest.splitn(3, ' ').collect();
            if parts.is_empty() {
                eprintln!("Usage:");
                eprintln!("  /group create <name>");
                eprintln!("  /group join <group_id>");
                eprintln!("  /group leave <group_id>");
                eprintln!("  /group send <group_id> <text>");
                continue;
            }
            let subcmd = parts[0];
            match subcmd {
                "create" => {
                    if parts.len() < 2 {
                        eprintln!("Usage: /group create <name>");
                        continue;
                    }
                    match client.create_group(parts[1]).await {
                        Ok(id) => println!("✓ Group '{}' created (id: {})", parts[1], id),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "join" => {
                    if parts.len() < 2 {
                        eprintln!("Usage: /group join <group_id>");
                        continue;
                    }
                    match client.join_group(parts[1]).await {
                        Ok(()) => println!("✓ Joined group {}", parts[1]),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "leave" => {
                    if parts.len() < 2 {
                        eprintln!("Usage: /group leave <group_id>");
                        continue;
                    }
                    match client.leave_group(parts[1]).await {
                        Ok(()) => println!("✓ Left group {}", parts[1]),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "send" => {
                    if parts.len() < 3 {
                        eprintln!("Usage: /group send <group_id> <text>");
                        continue;
                    }
                    let gid = parts[1];
                    let text = parts[2];
                    match client.send_group_message(gid, text).await {
                        Ok(()) => {}
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                _ => {
                    eprintln!("Unknown group command: {subcmd}");
                    eprintln!("Available: create, join, leave, send");
                }
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