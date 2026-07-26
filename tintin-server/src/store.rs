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
                ON messages(recipient_id);

            CREATE TABLE IF NOT EXISTS groups (
                group_id        TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                creator         TEXT NOT NULL,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS group_members (
                group_id        TEXT NOT NULL REFERENCES groups(group_id),
                user_id         TEXT NOT NULL,
                role            TEXT NOT NULL DEFAULT 'member',
                PRIMARY KEY (group_id, user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_group_members_user
                ON group_members(user_id);

            CREATE TABLE IF NOT EXISTS statuses (
                user_id         TEXT PRIMARY KEY,
                content         TEXT NOT NULL,
                created_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS channels (
                channel_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL,
                owner_id        TEXT NOT NULL,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS channel_subscribers (
                channel_id      INTEGER NOT NULL REFERENCES channels(channel_id),
                user_id         TEXT NOT NULL,
                PRIMARY KEY (channel_id, user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_channel_subscribers_user
                ON channel_subscribers(user_id);

            CREATE TABLE IF NOT EXISTS polls (
                poll_id         INTEGER PRIMARY KEY AUTOINCREMENT,
                creator         TEXT NOT NULL,
                question        TEXT NOT NULL,
                active          INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS poll_options (
                option_id       INTEGER PRIMARY KEY AUTOINCREMENT,
                poll_id         INTEGER NOT NULL REFERENCES polls(poll_id),
                option_text     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS poll_votes (
                poll_id         INTEGER NOT NULL REFERENCES polls(poll_id),
                user_id         TEXT NOT NULL,
                option_id       INTEGER NOT NULL,
                PRIMARY KEY (poll_id, user_id)
            );",
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

    /// Generate a short unique group ID (8 hex chars = ~4 billion namespace).
    fn generate_group_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let rnd = rand::random::<u16>() as u64;
        format!("{:08x}", (millis & 0xFFFF_FFFF) ^ rnd)
    }

    /// Create a new group. Returns the generated group_id.
    pub fn create_group(
        &self,
        name: &str,
        creator: &str,
    ) -> Result<String, rusqlite::Error> {
        let group_id = Self::generate_group_id();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO groups (group_id, name, creator) VALUES (?1, ?2, ?3)",
            params![group_id, name, creator],
        )?;
        // Creator is automatically an admin member.
        conn.execute(
            "INSERT INTO group_members (group_id, user_id, role) VALUES (?1, ?2, 'admin')",
            params![group_id, creator],
        )?;
        Ok(group_id)
    }

    /// Add a member to a group.
    pub fn add_group_member(
        &self,
        group_id: &str,
        user_id: &str,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_id, user_id, role) VALUES (?1, ?2, 'member')",
            params![group_id, user_id],
        )?;
        Ok(())
    }

    /// Remove a member from a group.
    pub fn remove_group_member(
        &self,
        group_id: &str,
        user_id: &str,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM group_members WHERE group_id = ?1 AND user_id = ?2",
            params![group_id, user_id],
        )?;
        Ok(())
    }

    /// List all groups that a user belongs to.
    pub fn list_my_groups(
        &self,
        user_id: &str,
    ) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT g.group_id, g.name, g.creator, gm.role
             FROM groups g
             JOIN group_members gm ON g.group_id = gm.group_id
             WHERE gm.user_id = ?1
             ORDER BY g.name",
        )?;
        let rows = stmt
            .query_map(params![user_id], |row| {
                Ok(serde_json::json!({
                    "group_id": row.get::<_, String>(0)?,
                    "name": row.get::<_, String>(1)?,
                    "creator": row.get::<_, String>(2)?,
                    "role": row.get::<_, String>(3)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// List all members of a group.
    pub fn list_group_members(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT user_id FROM group_members WHERE group_id = ?1 ORDER BY user_id",
        )?;
        let users = stmt.query_map(params![group_id], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(users)
    }

    /// Check if a group exists.
    pub fn group_exists(&self, group_id: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM groups WHERE group_id = ?1")?;
        let count: i64 = stmt.query_row(params![group_id], |row| row.get(0))?;
        Ok(count > 0)
    }

    // ── Channels ──────────────────────────────────────────────

    /// Create a new channel. Returns the generated channel_id.
    pub fn create_channel(
        &self,
        name: &str,
        owner_id: &str,
    ) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO channels (name, owner_id) VALUES (?1, ?2)",
            params![name, owner_id],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Subscribe a user to a channel.
    pub fn subscribe_channel(
        &self,
        channel_id: i64,
        user_id: &str,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO channel_subscribers (channel_id, user_id) VALUES (?1, ?2)",
            params![channel_id, user_id],
        )?;
        Ok(())
    }

    /// Unsubscribe a user from a channel.
    pub fn unsubscribe_channel(
        &self,
        channel_id: i64,
        user_id: &str,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM channel_subscribers WHERE channel_id = ?1 AND user_id = ?2",
            params![channel_id, user_id],
        )?;
        Ok(())
    }

    /// Check if a channel exists and return its owner.
    pub fn get_channel_owner(&self, channel_id: i64) -> Result<Option<String>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT owner_id FROM channels WHERE channel_id = ?1")?;
        let mut rows = stmt.query(params![channel_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// List all subscribers of a channel.
    pub fn list_channel_subscribers(
        &self,
        channel_id: i64,
    ) -> Result<Vec<String>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT user_id FROM channel_subscribers WHERE channel_id = ?1 ORDER BY user_id",
        )?;
        let users = stmt.query_map(params![channel_id], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(users)
    }

    /// List all channels a user is subscribed to.
    pub fn list_my_channels(
        &self,
        user_id: &str,
    ) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT c.channel_id, c.name, c.owner_id
             FROM channels c
             JOIN channel_subscribers cs ON c.channel_id = cs.channel_id
             WHERE cs.user_id = ?1
             ORDER BY c.name",
        )?;
        let rows = stmt
            .query_map(params![user_id], |row| {
                Ok(serde_json::json!({
                    "channel_id": row.get::<_, i64>(0)?,
                    "name": row.get::<_, String>(1)?,
                    "owner_id": row.get::<_, String>(2)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// List all channels (for discovery).
    pub fn list_all_channels(&self) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT channel_id, name, owner_id FROM channels ORDER BY name",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(serde_json::json!({
                    "channel_id": row.get::<_, i64>(0)?,
                    "name": row.get::<_, String>(1)?,
                    "owner_id": row.get::<_, String>(2)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    // ── Status / Stories ───────────────────────────────────────

    /// Set (or update) a user's status/story. Returns the created_at timestamp.
    pub fn set_status(&self, user_id: &str, content: &str) -> Result<u64, rusqlite::Error> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO statuses (user_id, content, created_at) VALUES (?1, ?2, ?3)",
            params![user_id, content, ts],
        )?;
        Ok(ts)
    }

    /// Clear a user's status.
    pub fn clear_status(&self, user_id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM statuses WHERE user_id = ?1", params![user_id])?;
        Ok(())
    }

    /// Get all active statuses (younger than 24 hours).
    pub fn get_active_statuses(&self) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            - 86400; // 24 hours
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT user_id, content, created_at FROM statuses WHERE created_at > ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map(params![cutoff as i64], |row| {
                Ok(serde_json::json!({
                    "user_id": row.get::<_, String>(0)?,
                    "content": row.get::<_, String>(1)?,
                    "created_at": row.get::<_, i64>(2)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// List registered user IDs, optionally filtered by a search query.
    pub fn list_users(&self, query: Option<&str>) -> Result<Vec<String>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        let users = if let Some(q) = query {
            let pattern = format!("%{}%", q);
            let mut stmt = conn.prepare(
                "SELECT user_id FROM users WHERE user_id LIKE ?1 ORDER BY user_id",
            )?;
            stmt.query_map(params![pattern], |row| row.get(0))?
                .filter_map(|r| r.ok())
                .collect()
        } else {
            let mut stmt = conn.prepare("SELECT user_id FROM users ORDER BY user_id")?;
            stmt.query_map([], |row| row.get(0))?
                .filter_map(|r| r.ok())
                .collect()
        };

        Ok(users)
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

    // ── Polls ─────────────────────────────────────────────────

    /// Create a new poll with options. Returns the poll_id.
    pub fn create_poll(
        &self,
        creator: &str,
        question: &str,
        options: &[String],
    ) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO polls (creator, question) VALUES (?1, ?2)",
            params![creator, question],
        )?;
        let poll_id = conn.last_insert_rowid();
        for opt in options {
            conn.execute(
                "INSERT INTO poll_options (poll_id, option_text) VALUES (?1, ?2)",
                params![poll_id, opt],
            )?;
        }
        Ok(poll_id)
    }

    /// Record a vote (replaces previous vote if user already voted).
    pub fn vote_poll(
        &self,
        poll_id: i64,
        user_id: &str,
        option_id: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = self.conn.lock().unwrap();

        // Check poll is active
        let mut stmt = conn.prepare("SELECT active FROM polls WHERE poll_id = ?1")?;
        let active: bool = stmt
            .query_row(params![poll_id], |row| row.get::<_, i64>(0))
            .map(|v| v != 0)
            .unwrap_or(false);
        if !active {
            return Err("Poll is closed".into());
        }

        // Check option exists
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM poll_options WHERE option_id = ?1 AND poll_id = ?2",
        )?;
        let count: i64 = stmt.query_row(params![option_id, poll_id], |row| row.get(0))?;
        if count == 0 {
            return Err("Option not found".into());
        }

        // Upsert vote
        conn.execute(
            "INSERT OR REPLACE INTO poll_votes (poll_id, user_id, option_id) VALUES (?1, ?2, ?3)",
            params![poll_id, user_id, option_id],
        )?;
        Ok(())
    }

    /// Get poll results.
    pub fn poll_results(&self, poll_id: i64) -> Result<Option<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        // Get poll info
        let mut stmt = conn.prepare(
            "SELECT question, creator, active FROM polls WHERE poll_id = ?1",
        )?;
        let poll = stmt.query_row(params![poll_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        }).ok();

        let (question, creator, active) = match poll {
            Some(p) => p,
            None => return Ok(None),
        };

        // Get options with vote counts
        let mut stmt = conn.prepare(
            "SELECT o.option_id, o.option_text, COUNT(v.user_id) as votes
             FROM poll_options o
             LEFT JOIN poll_votes v ON o.option_id = v.option_id
             WHERE o.poll_id = ?1
             GROUP BY o.option_id
             ORDER BY o.option_id",
        )?;
        let options: Vec<serde_json::Value> = stmt
            .query_map(params![poll_id], |row| {
                Ok(serde_json::json!({
                    "option_id": row.get::<_, i64>(0)?,
                    "option_text": row.get::<_, String>(1)?,
                    "votes": row.get::<_, i64>(2)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(Some(serde_json::json!({
            "poll_id": poll_id,
            "question": question,
            "creator": creator,
            "active": active != 0,
            "options": options,
        })))
    }

    /// List all active polls.
    pub fn list_active_polls(&self) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT poll_id, question, creator FROM polls WHERE active = 1 ORDER BY created_at DESC",
        )?;
        let polls = stmt
            .query_map([], |row| {
                Ok(serde_json::json!({
                    "poll_id": row.get::<_, i64>(0)?,
                    "question": row.get::<_, String>(1)?,
                    "creator": row.get::<_, String>(2)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(polls)
    }

    /// Close a poll (creator only).
    pub fn close_poll(&self, poll_id: i64, user_id: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT creator FROM polls WHERE poll_id = ?1")?;
        let creator: Option<String> = stmt
            .query_row(params![poll_id], |row| row.get(0))
            .ok();
        match creator {
            Some(c) if c == user_id => {
                conn.execute(
                    "UPDATE polls SET active = 0 WHERE poll_id = ?1",
                    params![poll_id],
                )?;
                Ok(true)
            }
            Some(_) => Ok(false), // not the creator
            None => Ok(false),    // not found
        }
    }
}
