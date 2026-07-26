//! TinTin Relay Server (Phase 1)
//!
//! A minimal store-and-forward relay that holds pre-key bundles and
//! message queues. The server **never** sees plaintext — all messages
//! are E2E encrypted before they arrive.
//!
//! ## Protocol
//!
//! The server uses newline-delimited JSON over TCP on port 9666.
//!
//! Commands:
//! - `{"cmd":"register","user_id":"alice","identity_key":[...],"signed_pre_key":{...}}`
//! - `{"cmd":"fetch_keys","user_id":"bob"}`
//! - `{"cmd":"send","envelope":{...}}`
//! - `{"cmd":"receive","user_id":"alice"}`

use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tintin_core::Envelope;

mod store;
use store::Store;

struct AppState {
    store: Store,
}

/// Default database path (relative to cwd).
const DB_PATH: &str = "tintin-server.db";

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:9666";
    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    let store = Store::open(DB_PATH).expect("Failed to open database");

    let state = Arc::new(AppState { store });

    eprintln!("🚀 TinTin Relay Server listening on {addr}");

    loop {
        let (stream, addr) = listener.accept().await.unwrap();
        eprintln!("+ Connection from {addr}");
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            handle_client(stream, state).await;
            eprintln!("- Connection closed: {addr}");
        });
    }
}

async fn handle_client(stream: TcpStream, state: Arc<AppState>) {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = match buf_reader
            .read_line(&mut line)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                eprintln!("  ⚠ Read error from client: {e}");
                break;
            }
        };

        if bytes_read == 0 {
            break; // connection closed
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let response = handle_command(trimmed, &state).await;
        if let Ok(json) = serde_json::to_string(&response) {
            let _ = writer.write_all(format!("{json}\n").as_bytes()).await;
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ServerResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct RegisterCmd {
    cmd: String,
    user_id: String,
    identity_key: [u8; 32],
    signed_pre_key: tintin_core::message::PreKeyBundle,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FetchKeysCmd {
    cmd: String,
    user_id: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct SendCmd {
    cmd: String,
    envelope: Envelope,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ReceiveCmd {
    cmd: String,
    user_id: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ListUsersCmd {
    cmd: String,
    #[serde(default)]
    query: Option<String>,
}

async fn handle_command(line: &str, state: &AppState) -> ServerResponse {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid JSON: {e}")),
            }
        }
    };

    let cmd = match value.get("cmd").and_then(|c| c.as_str()) {
        Some(c) => c,
        None => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some("Missing 'cmd' field".to_string()),
            }
        }
    };

    match cmd {
        "register" => handle_register(&value, state).await,
        "fetch_keys" => handle_fetch_keys(&value, state).await,
        "send" => handle_send(&value, state).await,
        "receive" => handle_receive(&value, state).await,
        "list_users" => handle_list_users(&value, state).await,
        _ => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("Unknown command: {cmd}")),
        },
    }
}

async fn handle_register(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: RegisterCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid register payload: {e}")),
            }
        }
    };

    let signed_pre_key_json =
        serde_json::to_string(&cmd.signed_pre_key).unwrap_or_default();

    match state
        .store
        .register_user(&cmd.user_id, &cmd.identity_key, &signed_pre_key_json)
    {
        Ok(()) => {
            eprintln!("  ✓ Registered user '{}'", cmd.user_id);
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"user_id": cmd.user_id})),
                error: None,
            }
        }
        Err(e) => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("Database error: {e}")),
        },
    }
}

async fn handle_fetch_keys(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: FetchKeysCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid fetch_keys payload: {e}")),
            }
        }
    };

    match state.store.get_key_bundle(&cmd.user_id) {
        Ok(Some(bundle)) => {
            eprintln!("  → Sent key bundle for '{}'", cmd.user_id);
            ServerResponse {
                status: "ok".to_string(),
                data: Some(bundle),
                error: None,
            }
        }
        Ok(None) => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("User '{}' not found", cmd.user_id)),
        },
        Err(e) => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("Database error: {e}")),
        },
    }
}

async fn handle_send(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: SendCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid send payload: {e}")),
            }
        }
    };

    let recipient = cmd.envelope.recipient_id.clone();

    match state.store.queue_message(&cmd.envelope) {
        Ok(()) => {
            eprintln!("  📨 Queued message for '{}'", recipient);
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"queued_for": recipient})),
                error: None,
            }
        }
        Err(e) => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("Database error: {e}")),
        },
    }
}

async fn handle_receive(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: ReceiveCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid receive payload: {e}")),
            }
        }
    };

    match state.store.fetch_messages(&cmd.user_id) {
        Ok(messages) => {
            eprintln!("  → {} messages for '{}'", messages.len(), cmd.user_id);
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"messages": messages})),
                error: None,
            }
        }
        Err(e) => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("Database error: {e}")),
        },
    }
}

async fn handle_list_users(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: ListUsersCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };

    match state.store.list_users(cmd.query.as_deref()) {
        Ok(users) => {
            eprintln!("  → {} user(s) listed", users.len());
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"users": users})),
                error: None,
            }
        }
        Err(e) => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("Database error: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tintin_core::{Envelope, MessageType};

    /// Helper: create an AppState backed by a temporary in-memory database.
    fn test_state() -> Arc<AppState> {
        let path = std::env::temp_dir().join(format!(
            "tintin-test-{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path_str = path.to_str().unwrap();
        let store = Store::open(path_str).expect("Failed to create test store");
        Arc::new(AppState { store })
    }

    #[tokio::test]
    async fn test_register_and_fetch() {
        let state = test_state();

        // Register alice
        let identity_key: Vec<u8> = vec![0u8; 32];
        let spk_pub: Vec<u8> = vec![1u8; 32];
        let spk_sig: Vec<u8> = vec![2u8; 64];

        let register = serde_json::json!({
            "cmd": "register",
            "user_id": "alice",
            "identity_key": identity_key,
            "signed_pre_key": {
                "identity_key": identity_key,
                "device_id": 1,
                "signed_pre_key_id": 1,
                "signed_pre_key": spk_pub,
                "signed_pre_key_signature": spk_sig,
                "one_time_pre_key_id": null,
                "one_time_pre_key": null
            }
        });

        let resp = handle_command(&register.to_string(), &state).await;
        assert_eq!(resp.status, "ok");

        // Fetch alice
        let fetch = serde_json::json!({
            "cmd": "fetch_keys",
            "user_id": "alice"
        });
        let resp = handle_command(&fetch.to_string(), &state).await;
        assert_eq!(resp.status, "ok");
        assert!(resp.data.is_some());
    }

    #[tokio::test]
    async fn test_send_receive() {
        let state = test_state();

        let envelope = Envelope::new(
            "alice".to_string(),
            "bob".to_string(),
            vec![1, 2, 3],
            MessageType::Normal,
        );

        let send = serde_json::json!({
            "cmd": "send",
            "envelope": envelope
        });
        let resp = handle_command(&send.to_string(), &state).await;
        assert_eq!(resp.status, "ok");

        let recv = serde_json::json!({
            "cmd": "receive",
            "user_id": "bob"
        });
        let resp = handle_command(&recv.to_string(), &state).await;
        assert_eq!(resp.status, "ok");
        let data = resp.data.unwrap();
        let msgs = data["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
    }

    #[tokio::test]
    async fn test_persistence_across_reconnect() {
        // Simulate server restart by creating two sequential store instances
        // pointing at the same file.
        let path = std::env::temp_dir().join(format!(
            "tintin-persist-{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = path.to_str().unwrap().to_string();

        // First "session" — register and send.
        {
            let store = Store::open(&path).expect("open #1");
            let state = Arc::new(AppState { store });

            let identity_key: Vec<u8> = vec![0u8; 32];
            let spk_pub: Vec<u8> = vec![1u8; 32];
            let spk_sig: Vec<u8> = vec![2u8; 64];

            let register = serde_json::json!({
                "cmd": "register",
                "user_id": "alice",
                "identity_key": identity_key,
                "signed_pre_key": {
                    "identity_key": identity_key,
                    "device_id": 1,
                    "signed_pre_key_id": 1,
                    "signed_pre_key": spk_pub,
                    "signed_pre_key_signature": spk_sig,
                    "one_time_pre_key_id": null,
                    "one_time_pre_key": null
                }
            });
            let resp = handle_command(&register.to_string(), &state).await;
            assert_eq!(resp.status, "ok", "register should work");

            let env = Envelope::new(
                "alice".to_string(),
                "bob".to_string(),
                vec![10, 20, 30],
                MessageType::Normal,
            );
            let send = serde_json::json!({"cmd": "send", "envelope": env});
            let resp = handle_command(&send.to_string(), &state).await;
            assert_eq!(resp.status, "ok", "send should work");
        }
        // store dropped — "server restarted"

        // Second "session" — verify data survived.
        {
            let store = Store::open(&path).expect("open #2");
            let state = Arc::new(AppState { store });

            // Fetch alice keys should still work.
            let fetch = serde_json::json!({"cmd": "fetch_keys", "user_id": "alice"});
            let resp = handle_command(&fetch.to_string(), &state).await;
            assert_eq!(resp.status, "ok", "fetch should work after restart");
            assert!(resp.data.is_some(), "key bundle should persist");

            // Bob should still have the queued message.
            let recv = serde_json::json!({"cmd": "receive", "user_id": "bob"});
            let resp = handle_command(&recv.to_string(), &state).await;
            assert_eq!(resp.status, "ok", "receive should work after restart");
            let data = resp.data.unwrap();
            let msgs = data["messages"].as_array().unwrap();
            assert_eq!(msgs.len(), 1, "message should survive restart");
            assert_eq!(
                msgs[0]["sender_id"].as_str().unwrap(),
                "alice",
                "sender should match"
            );
        }

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[tokio::test]
    async fn test_list_users() {
        let state = test_state();

        // No users yet.
        let list = serde_json::json!({"cmd": "list_users"});
        let resp = handle_command(&list.to_string(), &state).await;
        assert_eq!(resp.status, "ok");
        let data = resp.data.unwrap();
        let users = data["users"].as_array().unwrap();
        assert!(users.is_empty(), "should start empty");

        // Register alice.
        let identity_key: Vec<u8> = vec![0u8; 32];
        let spk_pub: Vec<u8> = vec![1u8; 32];
        let spk_sig: Vec<u8> = vec![2u8; 64];
        let register = serde_json::json!({
            "cmd": "register",
            "user_id": "alice",
            "identity_key": identity_key,
            "signed_pre_key": {
                "identity_key": identity_key,
                "device_id": 1,
                "signed_pre_key_id": 1,
                "signed_pre_key": spk_pub,
                "signed_pre_key_signature": spk_sig,
                "one_time_pre_key_id": null,
                "one_time_pre_key": null
            }
        });
        let resp = handle_command(&register.to_string(), &state).await;
        assert_eq!(resp.status, "ok");

        // Now list_users should include alice.
        let resp = handle_command(&list.to_string(), &state).await;
        assert_eq!(resp.status, "ok");
        let data = resp.data.unwrap();
        let users = data["users"].as_array().unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].as_str().unwrap(), "alice");
    }
}