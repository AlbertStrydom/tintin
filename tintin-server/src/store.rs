//! Persistent SQLite store for the TinTin relay server.
//!
//! Replaces the earlier in-memory HashMap approach so that
//! key bundles and queued messages survive server restarts.

use rusqlite::{params, Connection};
use std::sync::Mutex;
use tintin_core::{Envelope, MessageType, ReceiptContent, ReceiptType};

/// Thread-safe wrapper around a single SQLite connection.
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Open (or create) the database at `path` and ensure tables exist.
    pub fn open(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open(path)?;

        // Enable WAL mode for better concurrent read performance.
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                user_id         TEXT PRIMARY KEY,
                identity_key    BLOB NOT NULL,
                signed_pre_key  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_id   TEXT NOT NULL,
                envelope       TEXT NOT NULL,
                created_at     TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_messages_recipient
                ON messages(recipient_id);",
        )?;

        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    /// Register a new user with their identity key and signed pre-key bundle.
    pub fn register_user(
        &self,
        user_id: &str,
        identity_key: &[u8],
        signed_pre_key: &str,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO users (user_id, identity_key, signed_pre_key)
             VALUES (?1, ?2, ?3)",
            params![user_id, identity_key, signed_pre_key],
        )?;
        Ok(())
    }

    /// Retrieve a registered user's key bundle, or `None` if unknown.
    pub fn get_key_bundle(&self, user_id: &str) -> Result<Option<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT identity_key, signed_pre_key FROM users WHERE user_id = ?1",
        )?;

        let mut rows = stmt.query(params![user_id])?;
        match rows.next()? {
            Some(row) => {
                let identity_key: Vec<u8> = row.get(0)?;
                let signed_pre_key_str: String = row.get(1)?;
                let signed_pre_key: serde_json::Value =
                    serde_json::from_str(&signed_pre_key_str).unwrap_or(serde_json::Value::Null);

                Ok(Some(serde_json::json!({
                    "identity_key": identity_key,
                    "signed_pre_key": signed_pre_key,
                })))
            }
            None => Ok(None),
        }
    }

    /// Queue an envelope for the recipient.
    pub fn queue_message(&self, envelope: &Envelope) -> Result<(), rusqlite::Error> {
        let envelope_json = serde_json::to_string(envelope).unwrap_or_default();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO messages (recipient_id, envelope) VALUES (?1, ?2)",
            params![envelope.recipient_id, envelope_json],
        )?;
        Ok(())
    }

    /// Fetch (and remove) all queued messages for a user.
    ///
    /// Automatically queues delivery receipts for `Normal` and `PreKeyBundle`
    /// messages (but never for `Receipt` messages, avoiding infinite loops).
    pub fn fetch_messages(
        &self,
        user_id: &str,
    ) -> Result<Vec<Envelope>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        // 1. Read all pending messages for this user.
        let mut stmt = conn.prepare(
            "SELECT id, envelope FROM messages WHERE recipient_id = ?1 ORDER BY id",
        )?;
        let rows: Vec<(i64, String)> = stmt
            .query_map(params![user_id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();

        // 2. Delete them.
        conn.execute("DELETE FROM messages WHERE recipient_id = ?1", params![user_id])?;

        // 3. Deserialize envelopes.
        let mut envelopes: Vec<Envelope> = Vec::with_capacity(rows.len());
        for (_id, json) in &rows {
            if let Ok(env) = serde_json::from_str::<Envelope>(json) {
                envelopes.push(env);
            }
        }

        // 4. Queue delivery receipts for non-receipt messages.
        for msg in &envelopes {
            if msg.msg_type == MessageType::Normal || msg.msg_type == MessageType::PreKeyBundle {
                let receipt = ReceiptContent {
                    receipt_type: ReceiptType::Delivery,
                    original_sender: msg.sender_id.clone(),
                    original_timestamp: msg.timestamp,
                };
                let receipt_bytes = serde_json::to_vec(&receipt).unwrap_or_default();
                let receipt_env = Envelope::new(
                    user_id.to_string(),       // "sender" of the receipt
                    msg.sender_id.clone(),     // original sender gets it
                    receipt_bytes,
                    MessageType::Receipt,
                );
                let receipt_json = serde_json::to_string(&receipt_env).unwrap_or_default();
                conn.execute(
                    "INSERT INTO messages (recipient_id, envelope) VALUES (?1, ?2)",
                    params![msg.sender_id, receipt_json],
                )?;
            }
        }

        Ok(envelopes)
    }
}
