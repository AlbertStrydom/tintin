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

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

use tintin_core::{
    Envelope, IdentityKeyPair, KeyPair, MessageType, PreKeyBundleMessage, ReceiptContent,
    ReceiptType, Session, SessionMessage, SessionStore, SignedPreKey,
};

/// Active call state tracking.
#[derive(Debug, Clone)]
struct ActiveCall {
    peer: String,
    call_id: String,
    media_key_pair: KeyPair,
    peer_media_key: Option<[u8; 32]>,
    shared_media_secret: Option<[u8; 32]>,
    state: CallState,
}

#[derive(Debug, Clone, PartialEq)]
enum CallState {
    Offering,
    Ringing,
    Connected,
}

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
    #[serde(default)]
    edited: bool,
}

/// Direction of a chat message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum MessageDirection {
    Outgoing,
    Incoming,
}

/// A single message in the chat log (incoming or outgoing).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MessageRecord {
    peer: String,
    text: String,
    timestamp: u64,
    direction: MessageDirection,
    is_group: bool,
    group_name: Option<String>,
    #[serde(default)]
    is_channel: bool,
    #[serde(default)]
    channel_name: Option<String>,
    edited: bool,
}

/// A file being received (chunks accumulated before assembly).
#[derive(Debug, Clone)]
struct PendingFile {
    file_name: String,
    file_size: u64,
    total_chunks: usize,
    received_chunks: HashMap<usize, Vec<u8>>,
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
    /// Full chat log for search.
    chat_log: Vec<MessageRecord>,
    /// Incoming file transfers being assembled.
    pending_files: HashMap<String, PendingFile>,
    /// Channels we're subscribed to (channel_id -> name).
    channels: HashMap<i64, String>,
    /// Active call state, if any.
    active_call: Option<ActiveCall>,
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
            chat_log: Vec::new(),
            pending_files: HashMap::new(),
            channels: HashMap::new(),
            active_call: None,
        };
        client.load_history();
        client.load_groups();
        client.load_channels();
        client.load_chat_log();
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

    // ── Channels persistence ────────────────────────────────────

    fn channels_path(&self) -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        let dir = PathBuf::from(home).join(".tintin");
        let _ = std::fs::create_dir_all(&dir);
        dir.join(format!("{}_channels.json", self.user_id))
    }

    fn load_channels(&mut self) {
        let path = self.channels_path();
        if !path.exists() {
            return;
        }
        if let Ok(json) = std::fs::read_to_string(&path) {
            if let Ok(chs) = serde_json::from_str::<HashMap<i64, String>>(&json) {
                self.channels = chs;
            }
        }
    }

    fn save_channels(&self) {
        let path = self.channels_path();
        if let Ok(json) = serde_json::to_string_pretty(&self.channels) {
            let _ = std::fs::write(&path, &json);
        }
    }

    // ── Chat log persistence ────────────────────────────────────

    fn chat_log_path(&self) -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        let dir = PathBuf::from(home).join(".tintin");
        let _ = std::fs::create_dir_all(&dir);
        dir.join(format!("{}_chatlog.json", self.user_id))
    }

    fn load_chat_log(&mut self) {
        let path = self.chat_log_path();
        if !path.exists() {
            return;
        }
        if let Ok(json) = std::fs::read_to_string(&path) {
            if let Ok(log) = serde_json::from_str::<Vec<MessageRecord>>(&json) {
                self.chat_log = log;
            }
        }
    }

    fn save_chat_log(&self) {
        let path = self.chat_log_path();
        if let Ok(json) = serde_json::to_string_pretty(&self.chat_log) {
            let _ = std::fs::write(&path, &json);
        }
    }

    /// Save all persistent state (manual /save command).
    fn save_all(&self) {
        self.save_history();
        self.save_groups();
        self.save_channels();
        self.save_chat_log();
        println!("💾 All data saved.");
    }

    /// Append a message to the chat log and persist.
    fn record_message(&mut self, peer: &str, text: &str, outgoing: bool, is_group: bool, group_name: Option<String>, is_channel: bool, channel_name: Option<String>) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.chat_log.push(MessageRecord {
            peer: peer.to_string(),
            text: text.to_string(),
            timestamp: ts,
            direction: if outgoing { MessageDirection::Outgoing } else { MessageDirection::Incoming },
            is_group,
            group_name,
            is_channel,
            channel_name,
            edited: false,
        });
        self.save_chat_log();
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
            edited: false,
        });
        self.save_history();
        self.record_message(recipient, plaintext, true, false, None, false, None);
        println!("✓ Sent to '{}' (✓)", recipient);
        Ok(())
    }

    /// Edit a previously sent message by index.
    async fn edit_message(&mut self, index: usize, new_text: &str) -> Result<(), Box<dyn std::error::Error>> {
        let Some(msg) = self.sent_messages.get(index) else {
            return Err(format!("Message #{} not found (you have {} messages)", index, self.sent_messages.len()).into());
        };

        let recipient = msg.recipient.clone();
        let original_timestamp = msg.timestamp;
        let is_group = recipient.starts_with('[');

        // Build the edit payload.
        let payload = serde_json::json!({
            "__tintin_type": "edit",
            "original_timestamp": original_timestamp,
            "new_text": new_text,
        });
        let payload_bytes = serde_json::to_vec(&payload)?;

        if recipient == self.user_id {
            // Self-message: send as plaintext.
            let env = Envelope::new(
                self.user_id.clone(),
                self.user_id.clone(),
                new_text.as_bytes().to_vec(),
                MessageType::Normal,
            );
            let req = serde_json::json!({"cmd": "send", "envelope": env});
            self.send_json(&req).await?;
            let _ = self.recv_json().await;
        } else if is_group {
            // Extract group_id from recipient format "[name] id"
            let gid = recipient.split(' ').last().unwrap_or(&recipient);
            let members = self.group_members(gid).await?;
            for member in &members {
                if member == &self.user_id {
                    continue;
                }
                if let Some(session) = self.sessions.get_mut(member, 1) {
                    let encrypted = session.encrypt(&payload_bytes)?;
                    let content = encrypted.to_json()?;
                    let env = Envelope::new(
                        self.user_id.clone(),
                        member.to_string(),
                        content,
                        MessageType::Normal,
                    );
                    let req = serde_json::json!({"cmd": "send", "envelope": env});
                    self.send_json(&req).await?;
                    let _ = self.recv_json().await;
                }
            }
        } else {
            // Private edit: send to the one recipient.
            if let Some(session) = self.sessions.get_mut(&recipient, 1) {
                let encrypted = session.encrypt(&payload_bytes)?;
                let content = encrypted.to_json()?;
                let env = Envelope::new(
                    self.user_id.clone(),
                    recipient.clone(),
                    content,
                    MessageType::Normal,
                );
                let req = serde_json::json!({"cmd": "send", "envelope": env});
                self.send_json(&req).await?;
                let _ = self.recv_json().await;
            }
        }

        // Update local tracking.
        if let Some(msg) = self.sent_messages.get_mut(index) {
            msg.text = new_text.to_string();
            msg.edited = true;
        }
        // Mark the matching outgoing entry in chat log as edited.
        if let Some(record) = self.chat_log.iter_mut().rev().find(|r| {
            matches!(r.direction, MessageDirection::Outgoing)
        }) {
            record.edited = true;
        }
        self.save_history();
        self.save_chat_log();
        println!("✏️ Message #{} edited", index);
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
                            let is_call_signal = self.process_call_signal(&envelope.sender_id, &plaintext);
                            if !is_call_signal && !self.process_file_chunk(&envelope.sender_id, &plaintext) {
                                Self::display_decrypted(&envelope.sender_id, &plaintext);
                                self.record_decrypted(&envelope.sender_id, &plaintext);
                            }
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
                        let my_id = self.user_id.clone();
                        self.record_message(&my_id, &text, false, false, None, false, None);
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
                                let is_call_signal = self.process_call_signal(&envelope.sender_id, &plaintext);
                                if !is_call_signal && !self.process_file_chunk(&envelope.sender_id, &plaintext) {
                                    Self::display_decrypted(&envelope.sender_id, &plaintext);
                                    self.record_decrypted(&envelope.sender_id, &plaintext);
                                }
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
            edited: false,
        });
        self.save_history();
        self.record_message(&group_name, plaintext, true, true, Some(group_name.clone()), false, None);
        println!("✓ Sent to group '{}' ({} members)", group_name, others.len());
        Ok(())
    }

    // ── Channel methods ────────────────────────────────────────

    /// Create a new channel. Returns the channel_id.
    async fn create_channel(&mut self, name: &str) -> Result<i64, Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "create_channel",
            "name": name,
            "owner_id": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to create channel: {}", resp["error"]).into());
        }
        let channel_id = resp["data"]["channel_id"].as_i64().unwrap_or(0);
        // Update local cache.
        self.channels.insert(channel_id, name.to_string());
        self.save_channels();
        Ok(channel_id)
    }

    /// Subscribe to a channel.
    async fn subscribe_channel(&mut self, channel_id: i64) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "subscribe_channel",
            "channel_id": channel_id,
            "user_id": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to subscribe: {}", resp["error"]).into());
        }
        // Update local cache.
        self.channels.insert(channel_id, format!("ch{}", channel_id));
        self.save_channels();
        Ok(())
    }

    /// Unsubscribe from a channel.
    async fn unsubscribe_channel(&mut self, channel_id: i64) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "unsubscribe_channel",
            "channel_id": channel_id,
            "user_id": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to unsubscribe: {}", resp["error"]).into());
        }
        self.channels.remove(&channel_id);
        self.save_channels();
        Ok(())
    }

    /// List all channels on the server.
    async fn list_all_channels(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let request = serde_json::json!({ "cmd": "list_channels" });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to list channels: {}", resp["error"]).into());
        }
        Ok(resp["data"]["channels"].as_array().cloned().unwrap_or_default())
    }

    /// List channels I'm subscribed to.
    async fn list_my_channels(&mut self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "my_channels",
            "user_id": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to list my channels: {}", resp["error"]).into());
        }
        let channels = resp["data"]["channels"].as_array().cloned().unwrap_or_default();
        // Update local cache.
        for ch in &channels {
            if let (Some(cid), Some(name)) = (ch["channel_id"].as_i64(), ch["name"].as_str()) {
                self.channels.insert(cid, name.to_string());
            }
        }
        self.save_channels();
        Ok(channels)
    }

    /// Get subscriber list for a channel.
    async fn channel_members(&self, channel_id: i64) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "channel_members",
            "channel_id": channel_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to get channel members: {}", resp["error"]).into());
        }
        let members: Vec<String> = resp["data"]["members"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        Ok(members)
    }

    /// Send a message to a channel — encrypts once per subscriber.
    async fn send_channel_message(
        &mut self,
        channel_id: i64,
        plaintext: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let channel_name = self
            .channels
            .get(&channel_id)
            .cloned()
            .unwrap_or_else(|| format!("ch{}", channel_id));

        let members = self.channel_members(channel_id).await?;
        let others: Vec<&str> = members
            .iter()
            .filter(|m| *m != &self.user_id)
            .map(|m| m.as_str())
            .collect();

        if others.is_empty() {
            // Only us — save locally.
            println!("📢 [{}] you: {} (no other subscribers)", channel_name, plaintext);
            return Ok(());
        }

        // Build the channel-tagged payload.
        let payload = serde_json::json!({
            "__tintin_type": "channel",
            "channel_id": channel_id,
            "channel_name": channel_name,
            "text": plaintext,
        });
        let payload_bytes = serde_json::to_vec(&payload)?;

        // Send to each subscriber encrypted with their session.
        for member in &others {
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
            recipient: format!("[{}] ch{}", channel_name, channel_id),
            text: plaintext.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            status: MessageStatus::Sent,
            edited: false,
        });
        self.save_history();
        self.record_message(&channel_name, plaintext, true, false, None, true, Some(channel_name.clone()));
        println!("✓ Sent to channel '{}' ({} subscribers)", channel_name, others.len());
        Ok(())
    }

    // ── Poll methods ─────────────────────────────────────────

    /// Create a poll on the server and notify a recipient.
    async fn create_poll(
        &mut self,
        question: &str,
        options: &[String],
        notify_recipient: Option<&str>,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        // Create on server
        let request = serde_json::json!({
            "cmd": "create_poll",
            "creator": self.user_id,
            "question": question,
            "options": options,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to create poll: {}", resp["error"]).into());
        }
        let poll_id = resp["data"]["poll_id"].as_i64().unwrap_or(0);

        // Send notification to recipient if specified
        if let Some(recipient) = notify_recipient {
            let payload = serde_json::json!({
                "__tintin_type": "poll",
                "poll_id": poll_id,
                "question": question,
                "options": options,
            });
            let text = serde_json::to_string(&payload)?;
            self.send_message(recipient, &text).await?;
        }

        println!("📊 Poll created (id: {})", poll_id);
        Ok(poll_id)
    }

    /// Vote on a poll.
    async fn vote_poll(
        &self,
        poll_id: i64,
        option_id: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "vote_poll",
            "poll_id": poll_id,
            "user_id": self.user_id,
            "option_id": option_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Vote failed: {}", resp["error"]).into());
        }
        println!("🗳️  Voted on poll {} (option {})", poll_id, option_id);
        Ok(())
    }

    /// Get poll results.
    async fn poll_results(&self, poll_id: i64) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "poll_results",
            "poll_id": poll_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed: {}", resp["error"]).into());
        }
        Ok(resp["data"].clone())
    }

    /// List active polls.
    async fn list_polls(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let request = serde_json::json!({ "cmd": "list_polls" });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed: {}", resp["error"]).into());
        }
        Ok(resp["data"]["polls"].as_array().cloned().unwrap_or_default())
    }

    /// Close a poll (creator only).
    async fn close_poll(&self, poll_id: i64) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "close_poll",
            "poll_id": poll_id,
            "user_id": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to close poll: {}", resp["error"]).into());
        }
        println!("🔒 Poll {} closed", poll_id);
        Ok(())
    }

    // ── Timeline / Moments ────────────────────────────────────

    /// Post to your timeline (or someone else's wall).
    async fn post_to_timeline(
        &self,
        content: &str,
        target_user: Option<&str>,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        let mut request = serde_json::json!({
            "cmd": "create_post",
            "user_id": self.user_id,
            "content": content,
        });
        if let Some(tu) = target_user {
            request["target_user_id"] = serde_json::Value::String(tu.to_string());
        }
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to post: {}", resp["error"]).into());
        }
        Ok(resp["data"]["post_id"].as_i64().unwrap_or(0))
    }

    /// Get timeline posts.
    async fn get_timeline_posts(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "get_timeline",
            "user_id": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed: {}", resp["error"]).into());
        }
        Ok(resp["data"]["posts"].as_array().cloned().unwrap_or_default())
    }

    /// Comment on a post.
    async fn add_comment(&self, post_id: i64, content: &str) -> Result<i64, Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "add_comment",
            "post_id": post_id,
            "user_id": self.user_id,
            "content": content,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed: {}", resp["error"]).into());
        }
        Ok(resp["data"]["comment_id"].as_i64().unwrap_or(0))
    }

    /// Get comments for a post.
    async fn get_post_comments(&self, post_id: i64) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "get_comments",
            "post_id": post_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed: {}", resp["error"]).into());
        }
        Ok(resp["data"]["comments"].as_array().cloned().unwrap_or_default())
    }

    /// Delete a post.
    async fn delete_post(&self, post_id: i64) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "delete_post",
            "post_id": post_id,
            "user_id": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed: {}", resp["error"]).into());
        }
        println!("🗑️ Post {} deleted", post_id);
        Ok(())
    }

    // ── Call methods ──────────────────────────────────────────

    /// Initiate a call to another user.
    async fn start_call(&mut self, peer: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.active_call.is_some() {
            return Err("Already in a call. Use /end to hang up first.".into());
        }

        let call_id = format!("{}_{}", self.user_id, 
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis());

        let media_key_pair = KeyPair::generate();
        let media_pub_hex = hex::encode(media_key_pair.public);

        let payload = serde_json::json!({
            "__tintin_type": "call_offer",
            "call_id": call_id,
            "media_key_pub": media_pub_hex,
        });

        self.active_call = Some(ActiveCall {
            peer: peer.to_string(),
            call_id: call_id.clone(),
            media_key_pair,
            peer_media_key: None,
            shared_media_secret: None,
            state: CallState::Offering,
        });

        let text = serde_json::to_string(&payload)?;
        self.send_message(peer, &text).await?;
        println!("📞 Calling {}... (call id: {})", peer, call_id);
        println!("  (use /end to cancel)");
        Ok(())
    }

    /// Accept an incoming call.
    async fn accept_call(&mut self, call_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let peer = match &self.active_call {
            Some(c) if c.call_id == call_id => c.peer.clone(),
            Some(_) => return Err("Active call has different ID".into()),
            None => return Err("No incoming call to accept".into()),
        };

        let media_key_pair = KeyPair::generate();
        let media_pub_hex = hex::encode(media_key_pair.public);

        let payload = serde_json::json!({
            "__tintin_type": "call_accept",
            "call_id": call_id,
            "media_key_pub": media_pub_hex,
        });

        // Derive shared media secret from the caller's media key.
        if let Some(ref mut call) = self.active_call {
            call.state = CallState::Connected;
            call.media_key_pair = media_key_pair;
            if let Some(peer_pk) = call.peer_media_key {
                let shared = call.media_key_pair.agree(&peer_pk).ok();
                call.shared_media_secret = shared;
                if shared.is_some() {
                    println!("  🔑 Secure media channel established");
                }
            }
        }

        let text = serde_json::to_string(&payload)?;
        self.send_message(&peer, &text).await?;
        println!("📞 Call {} connected with {}", call_id, peer);
        Ok(())
    }

    /// End the current call.
    async fn end_call(&mut self, reason: &str) -> Result<(), Box<dyn std::error::Error>> {
        let peer = match &self.active_call {
            Some(c) => c.peer.clone(),
            None => return Err("No active call".into()),
        };
        let call_id = self.active_call.as_ref().map(|c| c.call_id.clone()).unwrap_or_default();

        let payload = serde_json::json!({
            "__tintin_type": "call_end",
            "call_id": call_id,
            "reason": reason,
        });

        let text = serde_json::to_string(&payload)?;
        self.send_message(&peer, &text).await?;
        println!("📞 Call with {} ended", peer);
        self.active_call = None;
        Ok(())
    }

    /// Process an incoming call signal (called from receive loop after decrypt).
    fn process_call_signal(&mut self, sender: &str, plaintext: &[u8]) -> bool {
        let payload: serde_json::Value = match serde_json::from_slice(plaintext) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let tt = match payload.get("__tintin_type").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return false,
        };

        match tt {
            "call_offer" => {
                let call_id = payload["call_id"].as_str().unwrap_or("?").to_string();
                let media_pub_hex = payload["media_key_pub"].as_str().unwrap_or("");
                let peer_pk = hex::decode(media_pub_hex).ok()
                    .and_then(|b| b.try_into().ok());

                // Create a pending incoming call state
                let media_kp = KeyPair::generate(); // placeholder, will be replaced on accept
                self.active_call = Some(ActiveCall {
                    peer: sender.to_string(),
                    call_id,
                    media_key_pair: media_kp,
                    peer_media_key: peer_pk,
                    shared_media_secret: None,
                    state: CallState::Ringing,
                });
                true
            }
            "call_accept" => {
                if let Some(ref mut call) = self.active_call {
                    if call.state == CallState::Offering || call.state == CallState::Ringing {
                        let media_pub_hex = payload["media_key_pub"].as_str().unwrap_or("");
                        if let Some(peer_pk) = hex::decode(media_pub_hex)
                            .ok()
                            .and_then(|b: Vec<u8>| <[u8; 32]>::try_from(b).ok())
                        {
                            call.peer_media_key = Some(peer_pk);
                            let shared = call.media_key_pair.agree(&peer_pk).ok();
                            call.shared_media_secret = shared;
                            call.state = CallState::Connected;
                        }
                    }
                }
                true
            }
            "call_end" => {
                self.active_call = None;
                true
            }
            _ => false,
        }
    }

    // ── Sticker packs ─────────────────────────────────────────

    /// Built-in sticker packs: pack_id -> [(sticker_id, emoji, alt_text)].
    const STICKER_PACKS: &'static [(&'static str, &'static [(i64, &'static str, &'static str)])] = &[
        ("wave", &[(1, "👋", "Wave"), (2, "👍", "Thumbs up"), (3, "✌️", "Peace"), (4, "🤙", "Call me")]),
        ("face", &[(1, "😊", "Smile"), (2, "😂", "LOL"), (3, "😍", "Love"), (4, "😢", "Sad"), (5, "😡", "Angry")]),
        ("heart", &[(1, "❤️", "Red heart"), (2, "🧡", "Orange heart"), (3, "💛", "Yellow heart"), (4, "💚", "Green heart"), (5, "💜", "Purple heart")]),
        ("mood", &[(1, "🎉", "Party"), (2, "🔥", "Fire"), (3, "💯", "100"), (4, "⭐", "Star"), (5, "🎂", "Birthday")]),
    ];

    /// Send a sticker to a user.
    async fn send_sticker(
        &mut self,
        recipient: &str,
        pack_id: &str,
        sticker_id: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Look up the emoji and alt text.
        let mut emoji = "🖼️";
        let mut alt = String::new();
        for (pack, stickers) in Self::STICKER_PACKS {
            if *pack == pack_id {
                for (sid, e, a) in *stickers {
                    if *sid == sticker_id {
                        emoji = e;
                        alt = a.to_string();
                        break;
                    }
                }
                break;
            }
        }

        let payload = serde_json::json!({
            "__tintin_type": "sticker",
            "pack_id": pack_id,
            "sticker_id": sticker_id,
            "emoji": emoji,
            "alt": alt,
        });
        let text = serde_json::to_string(&payload)?;
        self.send_message(recipient, &text).await?;
        println!("{} Sent sticker to '{}': {} ({})", emoji, recipient, emoji, alt);
        Ok(())
    }

    // ── Custom Sticker Upload ──────────────────────────────────

    /// Directory for custom stickers.
    fn sticker_dir() -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        let dir = PathBuf::from(home).join(".tintin").join("stickers");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// Add a custom sticker from an image file.
    fn add_custom_sticker(file_path: &str, name: &str) -> Result<(), String> {
        let data = std::fs::read(file_path).map_err(|e| format!("Cannot read '{}': {}", file_path, e))?;
        let img = image::load_from_memory(&data)
            .map_err(|_| format!("'{}' is not a supported image format", file_path))?;
        // Resize to 256×256 max, preserving aspect ratio.
        let (w, h) = (img.width(), img.height());
        let max_dim = 256u32;
        let img = if w > max_dim || h > max_dim {
            let ratio = max_dim as f64 / w.max(h) as f64;
            let nw = (w as f64 * ratio) as u32;
            let nh = (h as f64 * ratio) as u32;
            img.resize(nw, nh, image::imageops::FilterType::Lanczos3)
        } else {
            img
        };
        let out_name = format!("{}.jpg", name);
        let out_path = Self::sticker_dir().join(&out_name);
        img.write_to(
            &mut std::io::BufWriter::new(std::fs::File::create(&out_path).map_err(|e| e.to_string())?),
            image::ImageFormat::Jpeg,
        )
        .map_err(|e| format!("Failed to write sticker: {}", e))?;
        println!("  ✅ Sticker '{}' added ({}×{})", name, img.width(), img.height());
        Ok(())
    }

    /// List custom stickers.
    fn list_custom_stickers() -> Vec<(String, String)> {
        let dir = Self::sticker_dir();
        let mut stickers = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if ext == "jpg" || ext == "png" || ext == "gif" || ext == "webp" {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            let size = std::fs::metadata(&path).ok().map(|m| m.len()).unwrap_or(0);
                            stickers.push((stem.to_string(), format!("{} KB", size / 1024)));
                        }
                    }
                }
            }
        }
        stickers.sort_by(|a, b| a.0.cmp(&b.0));
        stickers
    }

    /// Send a custom image sticker.
    async fn send_custom_sticker(
        &mut self,
        recipient: &str,
        sticker_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sticker_path = Self::sticker_dir().join(format!("{}.jpg", sticker_name));
        if !sticker_path.exists() {
            return Err(format!("Sticker '{}' not found. Use /sticker list to see available stickers.", sticker_name).into());
        }
        let sticker_data = std::fs::read(&sticker_path)?;
        let data_b64 = crate::base64_encode(&sticker_data);
        let payload = serde_json::json!({
            "__tintin_type": "sticker",
            "pack_id": "custom",
            "sticker_name": sticker_name,
            "image_data": data_b64,
        });
        let text = serde_json::to_string(&payload)?;
        self.send_message(recipient, &text).await?;
        println!("🖼️ Sent custom sticker '{}' to '{}'", sticker_name, recipient);
        Ok(())
    }

    // ── Voice Note Recording ─────────────────────────────────

    /// Directory for voice recordings.
    fn recordings_dir() -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        let dir = PathBuf::from(home).join(".tintin").join("recordings");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// Record audio from the default microphone and save as WAV.
    fn record_voice(duration_secs: u64) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let host = cpal::default_host();
        let device = host
            .default_input_device()
            .ok_or("No input device found. Plug in a microphone.")?;

        let config = device.default_input_config()?;
        let sample_format = config.sample_format();
        let channels = config.channels();
        let sample_rate = config.sample_rate().0;

        println!("🎤 Recording from: {} ({} Hz, {} ch, {})",
            device.name()?, sample_rate, channels, sample_format);
        println!("   Recording for {} seconds... Press Ctrl+C to stop early.", duration_secs);
        print!("   [");
        io::stdout().flush()?;

        // We use a channel to receive audio samples from the callback.
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<f32>>(64);

        let err_fn = |err| eprintln!("Audio error: {}", err);
        let stream = device.build_input_stream::<f32, _, _>(
            &config.config(),
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                let chunk = data.to_vec();
                let _ = tx.send(chunk);
            },
            err_fn,
            None,
        )?;
        stream.play()?;

        // Record samples for the given duration (or until Ctrl+C).
        let start = std::time::Instant::now();
        let duration = std::time::Duration::from_secs(duration_secs);
        let mut all_samples: Vec<f32> = Vec::new();
        let mut progress_ticks = 0usize;

        loop {
            // Non-blocking check for Ctrl+C
            if start.elapsed() >= duration {
                break;
            }
            match rx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(chunk) => {
                    all_samples.extend(chunk);
                    let elapsed = start.elapsed().as_secs();
                    let expected_ticks = (elapsed as usize).min(duration_secs as usize);
                    while progress_ticks < expected_ticks {
                        print!("█");
                        io::stdout().flush()?;
                        progress_ticks += 1;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Just continue checking
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        stream.pause()?;
        println!("]");

        let total_samples = all_samples.len();
        let actual_duration = if sample_rate > 0 {
            total_samples as f64 / (sample_rate as f64 * channels as f64)
        } else {
            0.0
        };
        println!("   Captured {} samples ({:.1}s)", total_samples, actual_duration);

        if total_samples == 0 {
            return Err("No audio captured.".into());
        }

        // Write WAV file (16-bit PCM, mono conversion by averaging channels).
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let out_path = Self::recordings_dir().join(format!("voice_note_{}.wav", stamp));

        // Convert f32 samples to 16-bit PCM, average channels to mono.
        let num_frames = total_samples / channels as usize;
        let mut pcm_data: Vec<i16> = Vec::with_capacity(num_frames);
        for frame in 0..num_frames {
            let start_idx = frame * channels as usize;
            let mut sum = 0.0f32;
            for ch in 0..channels as usize {
                let idx = start_idx + ch;
                if idx < total_samples {
                    sum += all_samples[idx];
                }
            }
            let avg = sum / channels as f32;
            // Clamp and convert to i16
            let sample = (avg * 32767.0).clamp(-32768.0, 32767.0) as i16;
            pcm_data.push(sample);
        }

        let data_size = pcm_data.len() * 2; // 16-bit = 2 bytes per sample
        let byte_rate = sample_rate * 2 * 1; // 16-bit mono
        let block_align: u16 = 2;

        use std::io::Write;
        let mut wav = std::io::BufWriter::new(std::fs::File::create(&out_path)?);
        // RIFF header
        wav.write_all(b"RIFF")?;
        wav.write_all(&(36u32 + data_size as u32).to_le_bytes())?;
        wav.write_all(b"WAVE")?;
        // fmt chunk
        wav.write_all(b"fmt ")?;
        wav.write_all(&16u32.to_le_bytes())?;  // chunk size
        wav.write_all(&1u16.to_le_bytes())?;    // PCM format
        wav.write_all(&1u16.to_le_bytes())?;    // mono
        wav.write_all(&sample_rate.to_le_bytes())?;
        wav.write_all(&byte_rate.to_le_bytes())?;
        wav.write_all(&block_align.to_le_bytes())?;
        wav.write_all(&16u16.to_le_bytes())?;   // bits per sample
        // data chunk
        wav.write_all(b"data")?;
        wav.write_all(&data_size.to_le_bytes())?;
        for &s in &pcm_data {
            wav.write_all(&s.to_le_bytes())?;
        }
        wav.flush()?;

        let file_size_kb = out_path.metadata().map(|m| m.len() / 1024).unwrap_or(0);
        println!("   ✅ Saved: {} ({} KB, {:.1}s)", out_path.display(), file_size_kb, actual_duration);
        Ok(out_path)
    }

    /// Generate the contact URI for this user.
    fn contact_uri(&self) -> String {
        let key_hex = hex::encode(self.identity.public_key());
        format!("tintin://add-contact?user_id={}&key={}", self.user_id, key_hex)
    }

    /// Display this user's contact info as a QR code.
    fn show_my_qr(&self) {
        use qrcode::QrCode;
        use qrcode::render::unicode;

        let uri = self.contact_uri();
        let code = match QrCode::new(uri.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to generate QR code: {e}");
                return;
            }
        };
        let image = code.render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Dark)
            .light_color(unicode::Dense1x2::Light)
            .build();
        println!("─── Your TinTin Contact QR ───");
        println!("{}", image);
        println!("───────────────────────────────");
        println!("User ID: {}", self.user_id);
        println!("Identity Key: {}", hex::encode(self.identity.public_key()));
        println!("Share this QR code so others can add you!");
        println!("Use /scan <data> to scan someone's code.");
    }

    /// Parse a contact URI and return (user_id, identity_key_hex).
    fn parse_contact_uri(uri: &str) -> Option<(String, String)> {
        let uri = uri.strip_prefix("tintin://add-contact?")?;
        let mut user_id = None;
        let mut key = None;
        for pair in uri.split('&') {
            let mut parts = pair.splitn(2, '=');
            let name = parts.next()?;
            let value = parts.next()?;
            match name {
                "user_id" => user_id = Some(value.to_string()),
                "key" => key = Some(value.to_string()),
                _ => {}
            }
        }
        Some((user_id?, key?))
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
                "channel" => {
                    let cname = payload["channel_name"].as_str().unwrap_or("Channel");
                    let text = payload["text"].as_str().unwrap_or("");
                    println!("📢 [{}] {}: {}", cname, sender, text);
                    return;
                }
                "call_offer" => {
                    let call_id = payload["call_id"].as_str().unwrap_or("?");
                    println!("📞 Incoming call from {} — /accept {} to answer, /end to reject", sender, call_id);
                    return;
                }
                "call_accept" => {
                    let call_id = payload["call_id"].as_str().unwrap_or("?");
                    println!("📞 {} accepted call {} — call connected!", sender, call_id);
                    if let Some(_pk) = payload["media_key_pub"].as_str() {
                        println!("  🔑 Media key exchanged, secure channel ready");
                    }
                    return;
                }
                "call_end" => {
                    let reason = payload["reason"].as_str().unwrap_or("ended");
                    println!("📞 Call with {} {}", sender, reason);
                    return;
                }
                "sticker" => {
                    let pack = payload["pack_id"].as_str().unwrap_or("?");
                    if pack == "custom" {
                        // Custom image sticker
                        let sticker_name = payload["sticker_name"].as_str().unwrap_or("sticker");
                        let data_b64 = payload["image_data"].as_str().unwrap_or("");
                        if !data_b64.is_empty() {
                            if let Ok(img_data) = crate::base64_decode(data_b64) {
                                let dl_dir = Self::sticker_dir();
                                let stamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0);
                                let out_name = format!("{}_{}.jpg", sticker_name, stamp);
                                let out_path = dl_dir.join(&out_name);
                                if std::fs::write(&out_path, &img_data).is_ok() {
                                    println!("🖼️ {}: [Custom sticker: {}] → saved", sender, sticker_name);
                                } else {
                                    println!("🖼️ {}: [Custom sticker: {}]", sender, sticker_name);
                                }
                            } else {
                                println!("🖼️ {}: [Custom sticker: {}]", sender, sticker_name);
                            }
                        } else {
                            println!("🖼️ {}: [Custom sticker: {}]", sender, sticker_name);
                        }
                    } else {
                        let sid = payload["sticker_id"].as_i64().unwrap_or(0);
                        let emoji = payload["emoji"].as_str().unwrap_or("🖼️");
                        let alt = payload["alt"].as_str().unwrap_or("");
                        if alt.is_empty() {
                            println!("{} {}: {} [{}#{}]", emoji, sender, emoji, pack, sid);
                        } else {
                            println!("{} {}: {} ({})", emoji, sender, emoji, alt);
                        }
                    }
                    return;
                }
                "poll" => {
                    let question = payload["question"].as_str().unwrap_or("Poll");
                    println!("📊 Poll from {}: \"{}\"", sender, question);
                    if let Some(opts) = payload["options"].as_array() {
                        for (i, opt) in opts.iter().enumerate() {
                            let text = opt.as_str().unwrap_or("");
                            println!("      {}. {}", i + 1, text);
                        }
                    }
                    if let Some(pid) = payload["poll_id"].as_i64() {
                        println!("      Vote with: /poll vote {} <number>", pid);
                    }
                    return;
                }
                "edit" => {
                    let new_text = payload["new_text"].as_str().unwrap_or("");
                    println!("✏️ {} edited: {}", sender, new_text);
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

    /// Record a decrypted message in the chat log.
    fn record_decrypted(&mut self, sender: &str, plaintext: &[u8]) {
        let (text, is_group, group_name, is_channel, channel_name) = if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(plaintext) {
            if payload.get("__tintin_type").and_then(|v| v.as_str()) == Some("group") {
                let t = payload["text"].as_str().unwrap_or("").to_string();
                let gn = payload["group_name"].as_str().unwrap_or("Group").to_string();
                (t, true, Some(gn), false, None)
            } else if payload.get("__tintin_type").and_then(|v| v.as_str()) == Some("channel") {
                let t = payload["text"].as_str().unwrap_or("").to_string();
                let cn = payload["channel_name"].as_str().unwrap_or("Channel").to_string();
                (t, false, None, true, Some(cn))
            } else if payload.get("__tintin_type").and_then(|v| v.as_str()) == Some("poll") {
                let question = payload["question"].as_str().unwrap_or("Poll").to_string();
                (format!("[Poll] {}", question), false, None, false, None)
            } else if payload.get("__tintin_type").and_then(|v| v.as_str()) == Some("sticker") {
                let emoji = payload["emoji"].as_str().unwrap_or("🖼️");
                (format!("[Sticker] {}", emoji), false, None, false, None)
            } else if let Some(tt) = payload.get("__tintin_type").and_then(|v| v.as_str()) {
                if tt == "call_offer" || tt == "call_accept" || tt == "call_end" {
                    ("[Call signal]".to_string(), false, None, false, None)
                } else {
                    (String::from_utf8_lossy(plaintext).to_string(), false, None, false, None)
                }
            } else {
                (String::from_utf8_lossy(plaintext).to_string(), false, None, false, None)
            }
        } else {
            (String::from_utf8_lossy(plaintext).to_string(), false, None, false, None)
        };
        self.record_message(sender, &text, false, is_group, group_name, is_channel, channel_name);
    }

    // ── Status / Stories ───────────────────────────────────────

    /// Set your status/story.
    async fn set_story(&self, content: &str) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "set_status",
            "user_id": self.user_id,
            "content": content,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to set status: {}", resp["error"]).into());
        }
        Ok(())
    }

    /// Clear your status/story.
    async fn clear_story(&self) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({
            "cmd": "clear_status",
            "user_id": self.user_id,
        });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to clear status: {}", resp["error"]).into());
        }
        Ok(())
    }

    /// View all active stories.
    async fn get_stories(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let request = serde_json::json!({ "cmd": "get_stories" });
        self.send_json(&request).await?;
        let resp = self.recv_json().await?;
        if resp["status"] != "ok" {
            return Err(format!("Failed to get stories: {}", resp["error"]).into());
        }
        Ok(resp["data"]["stories"].as_array().cloned().unwrap_or_default())
    }

    // ── File Sharing / Voice Messages / HD Photos ─────────────

    /// Send a file to another user (chunked, E2E encrypted).
    async fn send_file(
        &mut self,
        recipient: &str,
        file_path: &str,
        is_hd: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.send_file_inner(recipient, file_path, "file", is_hd).await
    }

    /// Send a voice message (audio file, marked as voice).
    async fn send_voice(
        &mut self,
        recipient: &str,
        file_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.send_file_inner(recipient, file_path, "voice", true).await
    }

    /// Core: send a file (or voice) in chunks, optionally compressing images.
    async fn send_file_inner(
        &mut self,
        recipient: &str,
        file_path: &str,
        msg_type: &str,
        is_hd: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::path::Path::new(file_path);
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        let is_image = matches!(ext.as_str(), "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp");

        let mut file_data = std::fs::read(file_path)?;
        let original_size = file_data.len() as u64;
        let mut thumbnail_b64 = String::new();

        // Compress images unless HD flag is set
        if is_image && !is_hd && msg_type != "voice" {
            if let Ok(img) = image::load_from_memory(&file_data) {
                let (w, h) = (img.width(), img.height());
                // Scale down if larger than 2048px on longest edge
                let max_dim = 2048u32;
                let img = if w > max_dim || h > max_dim {
                    let ratio = max_dim as f64 / w.max(h) as f64;
                    let nw = (w as f64 * ratio) as u32;
                    let nh = (h as f64 * ratio) as u32;
                    img.resize(nw, nh, image::imageops::FilterType::Lanczos3)
                } else {
                    img
                };
                // Save as JPEG quality 85
                let mut compressed = Vec::new();
                img.write_to(&mut std::io::Cursor::new(&mut compressed), image::ImageFormat::Jpeg)?;
                let compression_pct = if original_size > 0 { 100 - (compressed.len() as u64 * 100 / original_size) } else { 0 };
                println!("  🖼️ Compressed {} ({}×{}) — {}% smaller", file_name, w, h, compression_pct);
                file_data = compressed;

                // Generate thumbnail (128px max)
                let thumb = img.thumbnail(128, 128);
                let mut thumb_data = Vec::new();
                thumb.write_to(&mut std::io::Cursor::new(&mut thumb_data), image::ImageFormat::Jpeg)?;
                thumbnail_b64 = crate::base64_encode(&thumb_data);
            }
        }

        let file_size = file_data.len() as u64;

        const CHUNK_SIZE: usize = 256 * 1024; // 256 KB per chunk
        let total_chunks = if file_data.is_empty() {
            1
        } else {
            (file_data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE
        };

        let file_id = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );

        println!(
            "{} Sending '{}' ({} KB, {} chunk(s))...",
            if msg_type == "voice" { "🎤" } else { "📤" },
            file_name,
            file_size / 1024,
            total_chunks
        );

        for (i, chunk) in file_data.chunks(CHUNK_SIZE).enumerate() {
            let mut payload = serde_json::json!({
                "__tintin_type": msg_type,
                "file_id": file_id,
                "file_name": file_name,
                "file_size": file_size,
                "total_chunks": total_chunks,
                "chunk_index": i,
                "data": crate::base64_encode(chunk),
                "is_image": is_image && !thumbnail_b64.is_empty(),
                "original_width": if is_image { 0 } else { 0 },
                "original_height": if is_image { 0 } else { 0 },
            });
            // Add thumbnail to first chunk
            if i == 0 && !thumbnail_b64.is_empty() {
                payload["thumbnail"] = serde_json::Value::String(thumbnail_b64.clone());
            }
            let payload_bytes = serde_json::to_vec(&payload)?;

            // Encrypt and send
            let is_new = self.sessions.get_mut(recipient, 1).is_none();
            if is_new {
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
            }

            let session = self.sessions.get_mut(recipient, 1).unwrap();
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
                recipient.to_string(),
                content,
                msg_type,
            );
            let req = serde_json::json!({"cmd": "send", "envelope": envelope});
            self.send_json(&req).await?;
            let resp = self.recv_json().await?;
            if resp["status"] != "ok" {
                eprintln!("  ⚠️  Chunk {}/{} failed: {}", i + 1, total_chunks, resp["error"]);
            }
        }

        // Track in sent messages.
        let file_label = if is_image && !thumbnail_b64.is_empty() {
            format!("🖼️ {} ({} KB, compressed)", file_name, file_size / 1024)
        } else if msg_type == "voice" {
            format!("🎤 Voice ({})", file_name)
        } else {
            format!("📁 {} ({} KB)", file_name, file_size / 1024)
        };
        self.sent_messages.push(SentMessage {
            recipient: recipient.to_string(),
            text: file_label,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            status: MessageStatus::Sent,
            edited: false,
        });
        self.save_history();
        println!("✓ Sent {} to '{}'", file_name, recipient);
        Ok(())
    }

    /// Process an incoming decrypted message that may be a file or voice chunk.
    /// Returns true if it was a chunk (already displayed).
    fn process_file_chunk(
        &mut self,
        sender: &str,
        plaintext: &[u8],
    ) -> bool {
        let payload: serde_json::Value = match serde_json::from_slice(plaintext) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let chunk_type = payload.get("__tintin_type").and_then(|v| v.as_str());
        if chunk_type != Some("file") && chunk_type != Some("voice") {
            return false;
        }

        let is_voice = chunk_type == Some("voice");
        let is_image = payload.get("is_image").and_then(|v| v.as_bool()).unwrap_or(false);
        let type_label = if is_image { "🖼️" } else if is_voice { "🎤" } else { "📁" };

        let file_id = payload["file_id"].as_str().unwrap_or("").to_string();
        let file_name = payload["file_name"].as_str().unwrap_or("unknown").to_string();
        let file_size = payload["file_size"].as_u64().unwrap_or(0);
        let total_chunks = payload["total_chunks"].as_u64().unwrap_or(0) as usize;
        let chunk_index = payload["chunk_index"].as_u64().unwrap_or(0) as usize;
        let data_b64 = payload["data"].as_str().unwrap_or("");

        let chunk_data = match base64_decode(data_b64) {
            Ok(d) => d,
            Err(_) => return true, // malformed chunk, skip
        };

        // Get or create pending file entry.
        let pending = self.pending_files.entry(file_id.clone()).or_insert_with(|| {
            println!("{} Receiving '{}' ({} KB, {} chunks) from {}...",
                type_label, file_name, file_size / 1024, total_chunks, sender);
            PendingFile {
                file_name: file_name.clone(),
                file_size,
                total_chunks,
                received_chunks: HashMap::new(),
            }
        });
        pending.received_chunks.insert(chunk_index, chunk_data);

        // Check if complete.
        if pending.received_chunks.len() == pending.total_chunks {
            let name = pending.file_name.clone();
            let size = pending.file_size;
            // Reassemble in order.
            let mut full_data = Vec::with_capacity(size as usize);
            for i in 0..pending.total_chunks {
                if let Some(chunk) = pending.received_chunks.remove(&i) {
                    full_data.extend_from_slice(&chunk);
                }
            }
            // Save to downloads directory.
            let home = std::env::var("USERPROFILE")
                .or_else(|_| std::env::var("HOME"))
                .unwrap_or_else(|_| ".".to_string());
            let dl_dir = PathBuf::from(home).join(".tintin").join("downloads");
            let _ = std::fs::create_dir_all(&dl_dir);
            let out_path = dl_dir.join(&name);
            if let Err(e) = std::fs::write(&out_path, &full_data) {
                eprintln!("⚠️ Could not save file '{}': {}", name, e);
            } else {
                println!(
                    "✅ {} '{}' saved ({} KB) → {}",
                    if is_image { "🖼️ Image" } else if is_voice { "🎤 Voice" } else { "📁 File" },
                    name,
                    size / 1024,
                    out_path.display()
                );
            }
            self.pending_files.remove(&file_id);
        } else {
            let pct = pending.received_chunks.len() * 100 / pending.total_chunks;
            println!(
                "  📦 {}/{} chunks ({})", pending.received_chunks.len(), pending.total_chunks, pct
            );
        }
        true
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

/// Base64-encode raw bytes for JSON-safe transport.
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Base64-decode a string back to raw bytes.
fn base64_decode(data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(data)?)
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
    println!("  /edit <idx> text    — Edit a sent message (see /status for index)");
    println!("  /search <text>       — Search message history");
    println!("  /sendfile <user> <path> [--hd] — Send a file (auto-compress images)");
    println!("  /record [secs]         — Record microphone audio (saves as WAV)");
    println!("  /channel create <name>  — Create a broadcast channel");
    println!("  /channel sub <id>       — Subscribe to a channel");
    println!("  /channel unsub <id>     — Unsubscribe from a channel");
    println!("  /channel send <id> <t>  — Send to a channel (owner only)");
    println!("  /channels              — List all available channels");
    println!("  /my_channels           — List your channel subscriptions");
    println!("  /poll create <q>|<o1>|<o2>|... — Create a poll (pipe-separated)");
    println!("  /poll vote <id> <n>             — Vote on a poll");
    println!("  /poll results <id>              — View poll results");
    println!("  /poll close <id>                — Close a poll (creator only)");
    println!("  /polls                          — List active polls");
    println!("  /sticker <user> <pack> <id> — Send emoji sticker");
    println!("  /sticker add <path> <name>  — Add custom image sticker");
    println!("  /sticker list               — List custom stickers");
    println!("  /sticker <user> custom <n>  — Send custom sticker");
    println!("  /moment <text>          — Post to your timeline");
    println!("  /timeline               — View your timeline");
    println!("  /comment <id> <text>    — Comment on a timeline post");
    println!("  /postcomments <id>      — View comments on a post");
    println!("  /deletepost <id>        — Delete your post");
    println!("  /qr                       — Show your contact QR code");
    println!("  /scan <uri>               — Scan a contact QR URI");
    println!("  /call <user>                — Start an encrypted call");
    println!("  /accept <call_id>           — Accept incoming call");
    println!("  /end                       — End/hang up current call");
    println!("  /story <text>        — Post a status story (24h expiry)");
    println!("  /stories             — View friends' active stories");
    println!("  /clearstory          — Remove your story");
    println!("  /status             — Show sent message status (✓/✓✓)");
    println!("  /help               — Show this help");
    println!("  /save               — Save all data to disk");
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
            client.save_all();
            break;
        }

        if input == "/save" {
            client.save_all();
            continue;
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
            println!("  /edit <idx> text    — Edit a sent message");
            println!("  /search <text>       — Search message history");
    println!("  /sendfile <user> <path> [--hd] — Send a file (auto-compress images)");
    println!("  /voice <user> <path>    — Send a voice message (audio file)");
    println!("  /record [secs]         — Record from microphone (default 10s)");
            println!("  /channel create <name>  — Create a broadcast channel");
            println!("  /channel sub <id>       — Subscribe to a channel");
            println!("  /channel unsub <id>     — Unsubscribe from a channel");
            println!("  /channel send <id> <t>  — Send to a channel (owner only)");
            println!("  /channels              — List all available channels");
            println!("  /my_channels           — List your channel subscriptions");
            println!("  /poll create <q>|<o1>|<o2>|... — Create a poll (pipe-separated)");
            println!("  /poll vote <id> <n>             — Vote on a poll");
            println!("  /poll results <id>              — View poll results");
            println!("  /poll close <id>                — Close a poll (creator only)");
            println!("  /polls                          — List active polls");
    println!("  /sticker <user> <pack> <id> — Send emoji sticker");
    println!("  /sticker add <path> <name>  — Add custom image sticker");
    println!("  /sticker list               — List custom stickers");
    println!("  /sticker <user> custom <n>  — Send custom sticker");
    println!("  /moment <text>          — Post to your timeline");
    println!("  /moment <user> <text>   — Post on someone's wall");
            println!("  /timeline               — View your timeline");
            println!("  /comment <id> <text>    — Comment on a timeline post");
            println!("  /postcomments <id>      — View comments on a post");
            println!("  /deletepost <id>        — Delete your post");
            println!("  /qr                       — Show your contact QR code");
            println!("  /scan <uri>               — Scan a contact QR URI");
            println!("  /call <user>                — Start an encrypted call");
            println!("  /accept <call_id>           — Accept incoming call");
            println!("  /end                       — End/hang up current call");
            println!("  /story <text>        — Post a status story (24h expiry)");
            println!("  /stories             — View friends' active stories");
            println!("  /clearstory          — Remove your story");
            println!("  /status             — Show sent message status (✓/✓✓)");
            println!("  /help               — Show this help");
            println!("  /save               — Save all data to disk");
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
                for (i, msg) in sent.iter().enumerate() {
                    let status = match msg.status {
                        MessageStatus::Sent => "✓",
                        MessageStatus::Delivered => "✓✓",
                        MessageStatus::Read => "✓✓",
                    };
                    let edited = if msg.edited { " (edited)" } else { "" };
                    println!("  #{i} {status} {} → {}{}", msg.text, msg.recipient, edited);
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

        if let Some(query) = input.strip_prefix("/search ") {
            let query = query.trim();
            if query.is_empty() {
                eprintln!("Usage: /search <text>");
                continue;
            }
            let results: Vec<&MessageRecord> = client
                .chat_log
                .iter()
                .filter(|r| r.text.to_lowercase().contains(&query.to_lowercase()))
                .collect();
            if results.is_empty() {
                println!("No messages matching '{}'.", query);
            } else {
                println!("{} result(s) for '{}':", results.len(), query);
                for (i, r) in results.iter().enumerate() {
                    let prefix = match r.direction {
                        MessageDirection::Outgoing => "→",
                        MessageDirection::Incoming => "←",
                    };
                    let ctx = if r.is_group {
                        format!("[{}] ", r.group_name.as_deref().unwrap_or("?"))
                    } else {
                        String::new()
                    };
                    let edited = if r.edited { " (edited)" } else { "" };
                    println!("  {}) {}{} {}{}", i, ctx, prefix, r.peer, edited);
                    println!("     {}", r.text);
                }
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

        if let Some(rest) = input.strip_prefix("/edit ") {
            // /edit <index> <new text>
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            if parts.len() < 2 {
                eprintln!("Usage: /edit <index> <new text>");
                eprintln!("  Get the index from /status");
                continue;
            }
            let index: usize = match parts[0].parse() {
                Ok(i) => i,
                Err(_) => {
                    eprintln!("Invalid index. Use /status to see message numbers.");
                    continue;
                }
            };
            let new_text = parts[1];
            if let Err(e) = client.edit_message(index, new_text).await {
                eprintln!("Error: {e}");
            }
            continue;
        }

        if let Some(text) = input.strip_prefix("/story ") {
            if let Err(e) = client.set_story(text).await {
                eprintln!("Error: {e}");
            } else {
                println!("📝 Story posted! (expires in 24h)");
            }
            continue;
        }

        if input == "/clearstory" {
            if let Err(e) = client.clear_story().await {
                eprintln!("Error: {e}");
            } else {
                println!("🗑️ Story cleared.");
            }
            continue;
        }

        if input == "/stories" {
            match client.get_stories().await {
                Ok(stories) => {
                    if stories.is_empty() {
                        println!("No active stories.");
                    } else {
                        println!("📖 Active stories:");
                        for s in &stories {
                            let user = s["user_id"].as_str().unwrap_or("?");
                            let content = s["content"].as_str().unwrap_or("");
                            let ts = s["created_at"].as_i64().unwrap_or(0);
                            let hours_ago = (std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64
                                - ts)
                                / 3600;
                            println!("  {} ({}h ago): {}", user, hours_ago, content);
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

        if let Some(rest) = input.strip_prefix("/channel ") {
            let parts: Vec<&str> = rest.splitn(3, ' ').collect();
            if parts.is_empty() {
                eprintln!("Usage:");
                eprintln!("  /channel create <name>");
                eprintln!("  /channel sub <channel_id>");
                eprintln!("  /channel unsub <channel_id>");
                eprintln!("  /channel send <channel_id> <text>");
                eprintln!("  /channels                   — List all channels");
                eprintln!("  /my_channels                — List my subscriptions");
                continue;
            }
            let subcmd = parts[0];
            match subcmd {
                "create" => {
                    if parts.len() < 2 {
                        eprintln!("Usage: /channel create <name>");
                        continue;
                    }
                    match client.create_channel(parts[1]).await {
                        Ok(id) => println!("✓ Channel '{}' created (id: {})", parts[1], id),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "sub" | "subscribe" => {
                    if parts.len() < 2 {
                        eprintln!("Usage: /channel sub <channel_id>");
                        continue;
                    }
                    let cid: i64 = match parts[1].parse() {
                        Ok(id) => id,
                        Err(_) => { eprintln!("Invalid channel id"); continue; }
                    };
                    match client.subscribe_channel(cid).await {
                        Ok(()) => println!("✓ Subscribed to channel {}", cid),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "unsub" | "unsubscribe" => {
                    if parts.len() < 2 {
                        eprintln!("Usage: /channel unsub <channel_id>");
                        continue;
                    }
                    let cid: i64 = match parts[1].parse() {
                        Ok(id) => id,
                        Err(_) => { eprintln!("Invalid channel id"); continue; }
                    };
                    match client.unsubscribe_channel(cid).await {
                        Ok(()) => println!("✓ Unsubscribed from channel {}", cid),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "send" => {
                    if parts.len() < 3 {
                        eprintln!("Usage: /channel send <channel_id> <text>");
                        continue;
                    }
                    let cid: i64 = match parts[1].parse() {
                        Ok(id) => id,
                        Err(_) => { eprintln!("Invalid channel id"); continue; }
                    };
                    let text = parts[2];
                    match client.send_channel_message(cid, text).await {
                        Ok(()) => {}
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                _ => {
                    eprintln!("Unknown channel command: {subcmd}");
                    eprintln!("Available: create, sub, unsub, send");
                }
            }
            continue;
        }

        if input == "/channels" || input == "/list_channels" {
            match client.list_all_channels().await {
                Ok(chs) => {
                    if chs.is_empty() {
                        println!("No channels exist yet. Create one with /channel create <name>");
                    } else {
                        println!("All channels:");
                        for ch in &chs {
                            println!("  {} — {} (owner: {})", ch["channel_id"], ch["name"], ch["owner_id"]);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {e}"),
            }
            continue;
        }

        if input == "/my_channels" || input == "/mychnl" {
            match client.list_my_channels().await {
                Ok(chs) => {
                    if chs.is_empty() {
                        println!("You're not subscribed to any channels.");
                    } else {
                        println!("My channels:");
                        for ch in &chs {
                            println!("  {} — {} (owner: {})", ch["channel_id"], ch["name"], ch["owner_id"]);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {e}"),
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/poll ") {
            let parts: Vec<&str> = rest.splitn(4, ' ').collect();
            if parts.is_empty() {
                eprintln!("Usage:");
                eprintln!("  /poll create <question>|<opt1>|<opt2>|...  — Create poll");
                eprintln!("  /poll vote <poll_id> <opt_no>            — Vote");
                eprintln!("  /poll results <poll_id>                  — Show results");
                eprintln!("  /poll close <poll_id>                    — Close (creator only)");
                eprintln!("  /polls                                   — List active polls");
                continue;
            }
            let subcmd = parts[0];
            match subcmd {
                "create" => {
                    if parts.len() < 2 {
                        eprintln!("Usage: /poll create <question>|<opt1>|<opt2>|...");
                        continue;
                    }
                    let args: Vec<&str> = parts[1].split('|').collect();
                    if args.len() < 3 {
                        eprintln!("Need at least: question|opt1|opt2");
                        continue;
                    }
                    let question = args[0];
                    let options: Vec<String> = args[1..].iter().map(|s| s.to_string()).collect();
                    match client.create_poll(question, &options, None).await {
                        Ok(id) => println!("✓ Poll created (id: {})", id),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "vote" => {
                    if parts.len() < 3 {
                        eprintln!("Usage: /poll vote <poll_id> <option_number>");
                        continue;
                    }
                    let pid: i64 = match parts[1].parse() { Ok(v) => v, Err(_) => { eprintln!("Invalid poll id"); continue; } };
                    let opt: i64 = match parts[2].parse() { Ok(v) => v, Err(_) => { eprintln!("Invalid option number"); continue; } };
                    match client.vote_poll(pid, opt).await {
                        Ok(()) => {}
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "results" => {
                    if parts.len() < 2 {
                        eprintln!("Usage: /poll results <poll_id>");
                        continue;
                    }
                    let pid: i64 = match parts[1].parse() { Ok(v) => v, Err(_) => { eprintln!("Invalid poll id"); continue; } };
                    match client.poll_results(pid).await {
                        Ok(data) => {
                            println!("📊 Poll: {}", data["question"]);
                            if let Some(opts) = data["options"].as_array() {
                                for opt in opts {
                                    let txt = opt["option_text"].as_str().unwrap_or("");
                                    let votes = opt["votes"].as_i64().unwrap_or(0);
                                    println!("  {} - {} vote(s)", txt, votes);
                                }
                            }
                        }
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "close" => {
                    if parts.len() < 2 {
                        eprintln!("Usage: /poll close <poll_id>");
                        continue;
                    }
                    let pid: i64 = match parts[1].parse() { Ok(v) => v, Err(_) => { eprintln!("Invalid poll id"); continue; } };
                    match client.close_poll(pid).await {
                        Ok(()) => {}
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                _ => {
                    eprintln!("Unknown poll command: {subcmd}");
                    eprintln!("Available: create, vote, results, close");
                }
            }
            continue;
        }

        if input == "/polls" {
            match client.list_polls().await {
                Ok(polls) => {
                    if polls.is_empty() {
                        println!("No active polls.");
                    } else {
                        println!("Active polls:");
                        for p in &polls {
                            println!("  {} — \"{}\" (by {})", p["poll_id"], p["question"], p["creator"]);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {e}"),
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/sticker ") {
            let parts: Vec<&str> = rest.splitn(4, ' ').collect();
            if parts.is_empty() {
                eprintln!("Usage: /sticker <user> <pack_id> <sticker_id>");
                eprintln!("       /sticker add <path> <name>");
                eprintln!("       /sticker list");
                eprintln!("       /sticker <user> custom <name>");
                continue;
            }
            // Subcommand: add
            if parts[0] == "add" && parts.len() >= 3 {
                let path = parts[1];
                let name = parts[2];
                if let Err(e) = TinTinClient::add_custom_sticker(path, name) {
                    eprintln!("Error: {e}");
                }
                continue;
            }
            // Subcommand: list
            if parts[0] == "list" {
                let stickers = TinTinClient::list_custom_stickers();
                if stickers.is_empty() {
                    println!("No custom stickers. Use /sticker add <path> <name>");
                } else {
                    println!("Custom stickers:");
                    for (name, size) in &stickers {
                        println!("  {} ({})", name, size);
                    }
                }
                continue;
            }
            // Send sticker: /sticker <user> <pack> <id_or_custom_name>
            if parts.len() < 3 {
                eprintln!("Usage: /sticker <user> <pack_id> <sticker_id>");
                eprintln!("       /sticker <user> custom <name>");
                continue;
            }
            let user = parts[0];
            let pack = parts[1];
            if pack == "custom" {
                if parts.len() < 3 {
                    eprintln!("Usage: /sticker <user> custom <name>");
                    continue;
                }
                let name = parts[2];
                if let Err(e) = client.send_custom_sticker(user, name).await {
                    eprintln!("Error: {e}");
                }
            } else {
                let sid: i64 = match parts[2].parse() {
                    Ok(v) => v,
                    Err(_) => { eprintln!("Invalid sticker id"); continue; }
                };
                if let Err(e) = client.send_sticker(user, pack, sid).await {
                    eprintln!("Error: {e}");
                }
            }
            continue;
        }

        if input.starts_with("/sticker") && input.len() <= 10 {
            println!("Usage: /sticker <user> <pack_id> <sticker_id>");
            println!("       /sticker add <path> <name>");
            println!("       /sticker list");
            println!("       /sticker <user> custom <name>");
            println!("Emoji packs:");
            println!("  wave  — 👋 Wave, 👍 Thumbs up, ✌️ Peace, 🤙 Call me");
            println!("  face  — 😊 Smile, 😂 LOL, 😍 Love, 😢 Sad, 😡 Angry");
            println!("  heart — ❤️ Red, 🧡 Orange, 💛 Yellow, 💚 Green, 💜 Purple");
            println!("  mood  — 🎉 Party, 🔥 Fire, 💯 100, ⭐ Star, 🎂 Birthday");
            continue;
        }

        if let Some(rest) = input.strip_prefix("/call ") {
            let peer = rest.trim();
            if peer.is_empty() {
                eprintln!("Usage: /call <username>");
                continue;
            }
            if let Err(e) = client.start_call(peer).await {
                eprintln!("Error: {e}");
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/accept ") {
            let call_id = rest.trim();
            if call_id.is_empty() {
                eprintln!("Usage: /accept <call_id>");
                continue;
            }
            if let Err(e) = client.accept_call(call_id).await {
                eprintln!("Error: {e}");
            }
            continue;
        }

        if input == "/end" || input == "/hangup" {
            if let Err(e) = client.end_call("ended").await {
                eprintln!("Error: {e}");
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/moment ") {
            let rest = rest.trim();
            if rest.is_empty() {
                eprintln!("Usage: /moment <text> or /moment <user> <text>");
                continue;
            }
            // Check if it has two parts (user + text)
            if let Some((target, text)) = rest.split_once(' ') {
                if !text.is_empty() {
                    match client.post_to_timeline(text, Some(target)).await {
                        Ok(id) => println!("📝 Posted on {}'s timeline (id: {})", target, id),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                    continue;
                }
            }
            // Single argument — own timeline
            match client.post_to_timeline(rest, None).await {
                Ok(id) => println!("📝 Posted to your timeline (id: {})", id),
                Err(e) => eprintln!("Error: {e}"),
            }
            continue;
        }

        if input == "/timeline" || input == "/tl" {
            match client.get_timeline_posts().await {
                Ok(posts) => {
                    if posts.is_empty() {
                        println!("Your timeline is empty. Post with /moment <text>");
                    } else {
                        println!("─── Timeline ───");
                        for p in &posts {
                            let uid = p["user_id"].as_str().unwrap_or("?");
                            let content = p["content"].as_str().unwrap_or("");
                            let cc = p["comment_count"].as_i64().unwrap_or(0);
                            let target = p["target_user_id"].as_str().and_then(|t| if t.is_empty() { None } else { Some(t) });
                            match target {
                                Some(tu) => println!("[{}] {} → {}: {}", p["post_id"], uid, tu, content),
                                None => println!("[{}] {}: {}", p["post_id"], uid, content),
                            }
                            if cc > 0 {
                                println!("     💬 {} comment(s) — /postcomments {}", cc, p["post_id"]);
                            }
                            println!("     /comment {} <text> to reply", p["post_id"]);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {e}"),
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/comment ") {
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            if parts.len() < 2 {
                eprintln!("Usage: /comment <post_id> <text>");
                continue;
            }
            let pid: i64 = match parts[0].parse() {
                Ok(v) => v,
                Err(_) => { eprintln!("Invalid post id"); continue; }
            };
            match client.add_comment(pid, parts[1]).await {
                Ok(_) => println!("💬 Comment added"),
                Err(e) => eprintln!("Error: {e}"),
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/postcomments ") {
            let pid: i64 = match rest.trim().parse() {
                Ok(v) => v,
                Err(_) => { eprintln!("Usage: /postcomments <post_id>"); continue; }
            };
            match client.get_post_comments(pid).await {
                Ok(comments) => {
                    if comments.is_empty() {
                        println!("No comments on post {}", pid);
                    } else {
                        println!("─── Comments on post {} ───", pid);
                        for c in &comments {
                            let uid = c["user_id"].as_str().unwrap_or("?");
                            let text = c["content"].as_str().unwrap_or("");
                            println!("  {}: {}", uid, text);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {e}"),
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/deletepost ") {
            let pid: i64 = match rest.trim().parse() {
                Ok(v) => v,
                Err(_) => { eprintln!("Usage: /deletepost <post_id>"); continue; }
            };
            if let Err(e) = client.delete_post(pid).await {
                eprintln!("Error: {e}");
            }
            continue;
        }

        if input == "/qr" || input == "/myqr" {
            client.show_my_qr();
            continue;
        }

        if let Some(rest) = input.strip_prefix("/scan ") {
            let data = rest.trim();
            if let Some((uid, key)) = TinTinClient::parse_contact_uri(data) {
                println!("✓ Scanned contact:");
                println!("  User ID: {}", uid);
                println!("  Identity Key: {}", key);
                println!("  Use /msg {} to start chatting!", uid);
            } else {
                eprintln!("Invalid contact URI. Expected: tintin://add-contact?user_id=...&key=...");
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/sendfile ") {
            let parts: Vec<&str> = rest.splitn(3, ' ').collect();
            if parts.len() < 2 {
                eprintln!("Usage: /sendfile <user> <filepath> [--hd]");
                continue;
            }
            let (user, filepath, is_hd) = if parts.len() >= 3 && parts[2] == "--hd" {
                (parts[0], parts[1], true)
            } else if parts.len() >= 2 {
                (parts[0], parts[1], false)
            } else {
                eprintln!("Usage: /sendfile <user> <filepath> [--hd]");
                continue;
            };
            if let Err(e) = client.send_file(user, filepath, is_hd).await {
                eprintln!("Error: {e}");
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/record ") {
            let secs: u64 = rest.trim().parse().unwrap_or(10);
            match TinTinClient::record_voice(secs) {
                Ok(_path) => println!("  Use /voice <user> <path> to send this recording."),
                Err(e) => eprintln!("Recording failed: {e}"),
            }
            continue;
        }
        if input == "/record" {
            match TinTinClient::record_voice(10) {
                Ok(_path) => println!("  Use /voice <user> <path> to send this recording."),
                Err(e) => eprintln!("Recording failed: {e}"),
            }
            continue;
        }

        if let Some(rest) = input.strip_prefix("/voice ") {
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            if parts.len() < 2 {
                eprintln!("Usage: /voice <user> <audiopath>");
                continue;
            }
            if let Err(e) = client.send_voice(parts[0], parts[1]).await {
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