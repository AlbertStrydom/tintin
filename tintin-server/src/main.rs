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

use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tintin_core::{Envelope, MessageType, ReceiptContent, ReceiptType};

type KeyStore = Arc<Mutex<HashMap<String, serde_json::Value>>>;
type MessageQueue = Arc<Mutex<HashMap<String, Vec<Envelope>>>>;

struct AppState {
    keys: KeyStore,
    queues: MessageQueue,
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:9666";
    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    let state = Arc::new(AppState {
        keys: Arc::new(Mutex::new(HashMap::new())),
        queues: Arc::new(Mutex::new(HashMap::new())),
    });

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

    let bundle = serde_json::json!({
        "identity_key": cmd.identity_key,
        "signed_pre_key": cmd.signed_pre_key,
    });

    let mut keys = state.keys.lock().await;
    keys.insert(cmd.user_id.clone(), bundle);

    eprintln!("  ✓ Registered user '{}'", cmd.user_id);

    ServerResponse {
        status: "ok".to_string(),
        data: Some(serde_json::json!({"user_id": cmd.user_id})),
        error: None,
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

    let keys = state.keys.lock().await;
    match keys.get(&cmd.user_id) {
        Some(bundle) => {
            eprintln!("  → Sent key bundle for '{}'", cmd.user_id);
            ServerResponse {
                status: "ok".to_string(),
                data: Some(bundle.clone()),
                error: None,
            }
        }
        None => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("User '{}' not found", cmd.user_id)),
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
    let mut queues = state.queues.lock().await;
    queues
        .entry(recipient.clone())
        .or_default()
        .push(cmd.envelope);

    eprintln!("  📨 Queued message for '{}'", recipient);

    ServerResponse {
        status: "ok".to_string(),
        data: Some(serde_json::json!({"queued_for": recipient})),
        error: None,
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

    let mut queues = state.queues.lock().await;
    let messages = queues.remove(&cmd.user_id).unwrap_or_default();

    // Auto-queue delivery receipts for Normal / PreKeyBundle messages.
    for msg in &messages {
        if msg.msg_type == MessageType::Normal || msg.msg_type == MessageType::PreKeyBundle {
            let receipt = ReceiptContent {
                receipt_type: ReceiptType::Delivery,
                original_sender: msg.sender_id.clone(),
                original_timestamp: msg.timestamp,
            };
            let receipt_bytes = serde_json::to_vec(&receipt).unwrap_or_default();
            let receipt_env = Envelope::new(
                cmd.user_id.clone(),    // "sender" of the receipt
                msg.sender_id.clone(),  // original sender gets the receipt
                receipt_bytes,
                MessageType::Receipt,
            );
            queues
                .entry(msg.sender_id.clone())
                .or_default()
                .push(receipt_env);
            eprintln!("  📬 Delivery receipt queued for '{}'", msg.sender_id);
        }
    }

    eprintln!("  → {} messages for '{}'", messages.len(), cmd.user_id);

    ServerResponse {
        status: "ok".to_string(),
        data: Some(serde_json::json!({"messages": messages})),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tintin_core::{Envelope, MessageType};

    #[tokio::test]
    async fn test_register_and_fetch() {
        let state = Arc::new(AppState {
            keys: Arc::new(Mutex::new(HashMap::new())),
            queues: Arc::new(Mutex::new(HashMap::new())),
        });

        // Register alice — build programmatically because json! macro
        // can't handle byte array expressions like [0u8; 32].
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
        let state = Arc::new(AppState {
            keys: Arc::new(Mutex::new(HashMap::new())),
            queues: Arc::new(Mutex::new(HashMap::new())),
        });

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
}