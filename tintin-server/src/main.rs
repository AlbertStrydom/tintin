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

// ── Group commands ──────────────────────────────────────────────

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct CreateGroupCmd {
    cmd: String,
    name: String,
    creator: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct JoinGroupCmd {
    cmd: String,
    group_id: String,
    user_id: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct LeaveGroupCmd {
    cmd: String,
    group_id: String,
    user_id: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct MyGroupsCmd {
    cmd: String,
    user_id: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct GroupMembersCmd {
    cmd: String,
    group_id: String,
}

// ── Status / Stories ───────────────────────────────────────────

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct SetStatusCmd {
    cmd: String,
    user_id: String,
    content: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ClearStatusCmd {
    cmd: String,
    user_id: String,
}

// ── Channel commands ────────────────────────────────────────────

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct CreateChannelCmd {
    cmd: String,
    name: String,
    owner_id: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct SubscribeChannelCmd {
    cmd: String,
    channel_id: i64,
    user_id: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct UnsubscribeChannelCmd {
    cmd: String,
    channel_id: i64,
    user_id: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ChannelMembersCmd {
    cmd: String,
    channel_id: i64,
}

// ── Poll commands ───────────────────────────────────────────────

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct CreatePollCmd {
    cmd: String,
    creator: String,
    question: String,
    options: Vec<String>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct VotePollCmd {
    cmd: String,
    poll_id: i64,
    user_id: String,
    option_id: i64,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct PollByIdCmd {
    cmd: String,
    poll_id: i64,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ClosePollCmd {
    cmd: String,
    poll_id: i64,
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
        "list_users" => handle_list_users(&value, state).await,
        "create_group" => handle_create_group(&value, state).await,
        "join_group" => handle_join_group(&value, state).await,
        "leave_group" => handle_leave_group(&value, state).await,
        "my_groups" => handle_my_groups(&value, state).await,
        "group_members" => handle_group_members(&value, state).await,
        "set_status" => handle_set_status(&value, state).await,
        "clear_status" => handle_clear_status(&value, state).await,
        "get_stories" => handle_get_stories(&value, state).await,
        "create_channel" => handle_create_channel(&value, state).await,
        "subscribe_channel" => handle_subscribe_channel(&value, state).await,
        "unsubscribe_channel" => handle_unsubscribe_channel(&value, state).await,
        "list_channels" => handle_list_channels(&value, state).await,
        "my_channels" => handle_my_channels(&value, state).await,
        "channel_members" => handle_channel_members(&value, state).await,
        "create_poll" => handle_create_poll(&value, state).await,
        "vote_poll" => handle_vote_poll(&value, state).await,
        "poll_results" => handle_poll_results(&value, state).await,
        "list_polls" => handle_list_polls(&value, state).await,
        "close_poll" => handle_close_poll(&value, state).await,
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

async fn handle_create_group(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: CreateGroupCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.create_group(&cmd.name, &cmd.creator) {
        Ok(group_id) => {
            eprintln!("  👥 Group '{}' created (id={})", cmd.name, group_id);
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"group_id": group_id})),
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

async fn handle_join_group(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: JoinGroupCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    if !state.store.group_exists(&cmd.group_id).unwrap_or(false) {
        return ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("Group '{}' not found", cmd.group_id)),
        };
    }
    match state.store.add_group_member(&cmd.group_id, &cmd.user_id) {
        Ok(()) => {
            eprintln!("  👤 {} joined group '{}'", cmd.user_id, cmd.group_id);
            ServerResponse {
                status: "ok".to_string(),
                data: None,
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

async fn handle_leave_group(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: LeaveGroupCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.remove_group_member(&cmd.group_id, &cmd.user_id) {
        Ok(()) => {
            eprintln!("  👤 {} left group '{}'", cmd.user_id, cmd.group_id);
            ServerResponse {
                status: "ok".to_string(),
                data: None,
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

async fn handle_my_groups(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: MyGroupsCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.list_my_groups(&cmd.user_id) {
        Ok(groups) => {
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"groups": groups})),
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

async fn handle_group_members(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: GroupMembersCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.list_group_members(&cmd.group_id) {
        Ok(members) => {
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"members": members})),
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

// ── Status / Stories handlers ──────────────────────────────────

async fn handle_set_status(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: SetStatusCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.set_status(&cmd.user_id, &cmd.content) {
        Ok(ts) => {
            eprintln!("  📝 Status set for '{}'", cmd.user_id);
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"created_at": ts})),
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

async fn handle_clear_status(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: ClearStatusCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.clear_status(&cmd.user_id) {
        Ok(()) => {
            eprintln!("  🗑️ Status cleared for '{}'", cmd.user_id);
            ServerResponse {
                status: "ok".to_string(),
                data: None,
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

async fn handle_get_stories(_value: &serde_json::Value, state: &AppState) -> ServerResponse {
    match state.store.get_active_statuses() {
        Ok(statuses) => {
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"stories": statuses})),
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

// ── Channel handlers ──────────────────────────────────────────

async fn handle_create_channel(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: CreateChannelCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.create_channel(&cmd.name, &cmd.owner_id) {
        Ok(channel_id) => {
            // Auto-subscribe the owner.
            state.store.subscribe_channel(channel_id, &cmd.owner_id).ok();
            eprintln!("  📢 Channel '{}' created (id={})", cmd.name, channel_id);
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"channel_id": channel_id})),
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

async fn handle_subscribe_channel(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: SubscribeChannelCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    // Verify channel exists.
    if state.store.get_channel_owner(cmd.channel_id).unwrap_or(None).is_none() {
        return ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("Channel '{}' not found", cmd.channel_id)),
        };
    }
    match state.store.subscribe_channel(cmd.channel_id, &cmd.user_id) {
        Ok(()) => {
            eprintln!("  👤 {} subscribed to channel {}", cmd.user_id, cmd.channel_id);
            ServerResponse {
                status: "ok".to_string(),
                data: None,
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

async fn handle_unsubscribe_channel(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: UnsubscribeChannelCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.unsubscribe_channel(cmd.channel_id, &cmd.user_id) {
        Ok(()) => {
            eprintln!("  👤 {} unsubscribed from channel {}", cmd.user_id, cmd.channel_id);
            ServerResponse {
                status: "ok".to_string(),
                data: None,
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

async fn handle_list_channels(_value: &serde_json::Value, state: &AppState) -> ServerResponse {
    match state.store.list_all_channels() {
        Ok(channels) => {
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"channels": channels})),
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

async fn handle_my_channels(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: SubscribeChannelCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.list_my_channels(&cmd.user_id) {
        Ok(channels) => {
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"channels": channels})),
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

async fn handle_channel_members(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: ChannelMembersCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.list_channel_subscribers(cmd.channel_id) {
        Ok(members) => {
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"members": members})),
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

// ── Poll handlers ─────────────────────────────────────────────

async fn handle_create_poll(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: CreatePollCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    if cmd.options.len() < 2 {
        return ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some("Poll must have at least 2 options".to_string()),
        };
    }
    match state.store.create_poll(&cmd.creator, &cmd.question, &cmd.options) {
        Ok(poll_id) => {
            eprintln!("  📊 Poll '{}' created (id={})", cmd.question, poll_id);
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"poll_id": poll_id})),
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

async fn handle_vote_poll(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: VotePollCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.vote_poll(cmd.poll_id, &cmd.user_id, cmd.option_id) {
        Ok(()) => {
            eprintln!("  🗳️ {} voted on poll {}", cmd.user_id, cmd.poll_id);
            ServerResponse {
                status: "ok".to_string(),
                data: None,
                error: None,
            }
        }
        Err(e) => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("Vote error: {e}")),
        },
    }
}

async fn handle_poll_results(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: PollByIdCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.poll_results(cmd.poll_id) {
        Ok(Some(results)) => {
            ServerResponse {
                status: "ok".to_string(),
                data: Some(results),
                error: None,
            }
        }
        Ok(None) => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("Poll '{}' not found", cmd.poll_id)),
        },
        Err(e) => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some(format!("Database error: {e}")),
        },
    }
}

async fn handle_list_polls(_value: &serde_json::Value, state: &AppState) -> ServerResponse {
    match state.store.list_active_polls() {
        Ok(polls) => {
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"polls": polls})),
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

async fn handle_close_poll(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: ClosePollCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(),
                data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.close_poll(cmd.poll_id, &cmd.user_id) {
        Ok(true) => {
            eprintln!("  🔒 Poll {} closed by {}", cmd.poll_id, cmd.user_id);
            ServerResponse {
                status: "ok".to_string(),
                data: None,
                error: None,
            }
        }
        Ok(false) => ServerResponse {
            status: "error".to_string(),
            data: None,
            error: Some("Poll not found or you are not the creator".to_string()),
        },
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