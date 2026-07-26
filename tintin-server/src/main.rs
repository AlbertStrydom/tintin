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
        "create_post" => handle_create_post(&value, state).await,
        "get_timeline" => handle_get_timeline(&value, state).await,
        "add_comment" => handle_add_comment(&value, state).await,
        "delete_post" => handle_delete_post(&value, state).await,
        "get_comments" => handle_get_comments(&value, state).await,
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

// ── Timeline / Moments ────────────────────────────────────────

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct CreatePostCmd {
    cmd: String,
    user_id: String,
    content: String,
    #[serde(default)]
    target_user_id: Option<String>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct TimelineCmd {
    cmd: String,
    user_id: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct AddCommentCmd {
    cmd: String,
    post_id: i64,
    user_id: String,
    content: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct PostIdCmd {
    cmd: String,
    post_id: i64,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct DeletePostCmd {
    cmd: String,
    post_id: i64,
    user_id: String,
}

async fn handle_create_post(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: CreatePostCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(), data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.create_post(&cmd.user_id, &cmd.content, cmd.target_user_id.as_deref()) {
        Ok(post_id) => {
            eprintln!("  📝 {} posted to timeline (id={})", cmd.user_id, post_id);
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"post_id": post_id})),
                error: None,
            }
        }
        Err(e) => ServerResponse {
            status: "error".to_string(), data: None,
            error: Some(format!("Database error: {e}")),
        },
    }
}

async fn handle_get_timeline(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: TimelineCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(), data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.get_timeline(&cmd.user_id) {
        Ok(posts) => {
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"posts": posts})),
                error: None,
            }
        }
        Err(e) => ServerResponse {
            status: "error".to_string(), data: None,
            error: Some(format!("Database error: {e}")),
        },
    }
}

async fn handle_add_comment(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: AddCommentCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(), data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.add_comment(cmd.post_id, &cmd.user_id, &cmd.content) {
        Ok(comment_id) => {
            eprintln!("  💬 {} commented on post {}", cmd.user_id, cmd.post_id);
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"comment_id": comment_id})),
                error: None,
            }
        }
        Err(e) => ServerResponse {
            status: "error".to_string(), data: None,
            error: Some(format!("Database error: {e}")),
        },
    }
}

async fn handle_delete_post(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: DeletePostCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(), data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.delete_post(cmd.post_id, &cmd.user_id) {
        Ok(true) => {
            eprintln!("  🗑️ Post {} deleted by {}", cmd.post_id, cmd.user_id);
            ServerResponse { status: "ok".to_string(), data: None, error: None }
        }
        Ok(false) => ServerResponse {
            status: "error".to_string(), data: None,
            error: Some("Post not found or not yours".to_string()),
        },
        Err(e) => ServerResponse {
            status: "error".to_string(), data: None,
            error: Some(format!("Database error: {e}")),
        },
    }
}

async fn handle_get_comments(value: &serde_json::Value, state: &AppState) -> ServerResponse {
    let cmd: PostIdCmd = match serde_json::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ServerResponse {
                status: "error".to_string(), data: None,
                error: Some(format!("Invalid payload: {e}")),
            }
        }
    };
    match state.store.get_comments(cmd.post_id) {
        Ok(comments) => {
            ServerResponse {
                status: "ok".to_string(),
                data: Some(serde_json::json!({"comments": comments})),
                error: None,
            }
        }
        Err(e) => ServerResponse {
            status: "error".to_string(), data: None,
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
        use std::time::{SystemTime, UNIX_EPOCH};
        let path = std::env::temp_dir().join(format!(
            "tintin-test-{}-{}.db",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
            std::process::id(),
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
        use std::time::{SystemTime, UNIX_EPOCH};
        let path = std::env::temp_dir().join(format!(
            "tintin-persist-{}-{}.db",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
            std::process::id(),
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

    // ── Channel tests ────────────────────────────────────────────

    #[tokio::test]
    async fn test_channel_create_subscribe_list() {
        let state = test_state();

        // Create a channel.
        let create = serde_json::json!({
            "cmd": "create_channel",
            "name": "test-channel",
            "owner_id": "alice",
        });
        let resp = handle_command(&create.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "create channel");
        let channel_id = resp.data.unwrap()["channel_id"].as_i64().unwrap();

        // List all channels.
        let list = serde_json::json!({"cmd": "list_channels"});
        let resp = handle_command(&list.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "list channels");
        let channels = resp.data.unwrap()["channels"].as_array().unwrap().clone();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0]["name"].as_str().unwrap(), "test-channel");

        // Subscribe bob.
        let sub = serde_json::json!({
            "cmd": "subscribe_channel",
            "channel_id": channel_id,
            "user_id": "bob",
        });
        let resp = handle_command(&sub.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "subscribe bob");

        // My channels (bob).
        let my = serde_json::json!({
            "cmd": "my_channels",
            "channel_id": channel_id,
            "user_id": "bob",
        });
        let resp = handle_command(&my.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "bob my_channels");
        let bob_channels = resp.data.unwrap()["channels"].as_array().unwrap().clone();
        assert_eq!(bob_channels.len(), 1);

        // Channel members.
        let members = serde_json::json!({
            "cmd": "channel_members",
            "channel_id": channel_id,
        });
        let resp = handle_command(&members.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "channel members");
        let member_list = resp.data.unwrap()["members"].as_array().unwrap().clone();
        assert_eq!(member_list.len(), 2);
        let names: Vec<&str> = member_list.iter().map(|m| m.as_str().unwrap()).collect();
        assert!(names.contains(&"alice"));
        assert!(names.contains(&"bob"));

        // Unsubscribe bob.
        let unsub = serde_json::json!({
            "cmd": "unsubscribe_channel",
            "channel_id": channel_id,
            "user_id": "bob",
        });
        let resp = handle_command(&unsub.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "unsubscribe bob");

        // Bob's channels should now be empty.
        let resp = handle_command(&my.to_string(), &state).await;
        assert_eq!(resp.status, "ok");
        let bob_channels = resp.data.unwrap()["channels"].as_array().unwrap().clone();
        assert_eq!(bob_channels.len(), 0);
    }

    #[tokio::test]
    async fn test_channel_subscribe_nonexistent() {
        let state = test_state();
        let sub = serde_json::json!({
            "cmd": "subscribe_channel",
            "channel_id": 999,
            "user_id": "alice",
        });
        let resp = handle_command(&sub.to_string(), &state).await;
        assert_eq!(resp.status, "error", "subscribing to nonexistent channel");
        assert!(resp.error.unwrap().contains("not found"));
    }

    // ── Poll tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_poll_create_vote_results_close() {
        let state = test_state();

        // Create a poll.
        let create = serde_json::json!({
            "cmd": "create_poll",
            "creator": "alice",
            "question": "Best color?",
            "options": ["Red", "Blue", "Green"],
        });
        let resp = handle_command(&create.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "create poll");
        let poll_id = resp.data.unwrap()["poll_id"].as_i64().unwrap();

        // List polls.
        let list = serde_json::json!({"cmd": "list_polls"});
        let resp = handle_command(&list.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "list polls");
        let polls = resp.data.unwrap()["polls"].as_array().unwrap().clone();
        assert_eq!(polls.len(), 1);
        assert_eq!(polls[0]["question"].as_str().unwrap(), "Best color?");

        // Alice votes for Red (option_id = 1).
        let vote = serde_json::json!({
            "cmd": "vote_poll",
            "poll_id": poll_id,
            "user_id": "alice",
            "option_id": 1,
        });
        let resp = handle_command(&vote.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "alice vote");

        // Bob votes for Blue (option_id = 2).
        let vote2 = serde_json::json!({
            "cmd": "vote_poll",
            "poll_id": poll_id,
            "user_id": "bob",
            "option_id": 2,
        });
        let resp = handle_command(&vote2.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "bob vote");

        // Poll results should show 1 vote each for Red and Blue.
        let results = serde_json::json!({
            "cmd": "poll_results",
            "poll_id": poll_id,
        });
        let resp = handle_command(&results.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "poll results");
        let data = resp.data.unwrap();
        assert_eq!(data["question"].as_str().unwrap(), "Best color?");
        assert_eq!(data["active"].as_bool().unwrap(), true);
        let opts = data["options"].as_array().unwrap();
        // Options should contain vote counts.
        let red = opts.iter().find(|o| o["option_text"].as_str() == Some("Red")).unwrap();
        assert_eq!(red["votes"].as_i64().unwrap(), 1);
        let blue = opts.iter().find(|o| o["option_text"].as_str() == Some("Blue")).unwrap();
        assert_eq!(blue["votes"].as_i64().unwrap(), 1);
        let green = opts.iter().find(|o| o["option_text"].as_str() == Some("Green")).unwrap();
        assert_eq!(green["votes"].as_i64().unwrap(), 0);

        // Duplicate vote (same option) is allowed — vote changing is supported.
        let resp = handle_command(&vote.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "duplicate vote (vote changing)");

        // Close poll.
        let close = serde_json::json!({
            "cmd": "close_poll",
            "poll_id": poll_id,
            "user_id": "alice",
        });
        let resp = handle_command(&close.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "close poll");

        // Confirm closed.
        let resp = handle_command(&results.to_string(), &state).await;
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.data.unwrap()["active"].as_bool().unwrap(), false);

        // Voting on closed poll should fail.
        let resp = handle_command(&vote2.to_string(), &state).await;
        assert_eq!(resp.status, "error", "vote on closed poll");
    }

    #[tokio::test]
    async fn test_poll_too_few_options() {
        let state = test_state();
        let create = serde_json::json!({
            "cmd": "create_poll",
            "creator": "alice",
            "question": "Yes or no?",
            "options": ["Yes"],
        });
        let resp = handle_command(&create.to_string(), &state).await;
        assert_eq!(resp.status, "error", "less than 2 options");
    }

    // ── Timeline tests ───────────────────────────────────────────

    #[tokio::test]
    async fn test_timeline_post_comment_delete() {
        let state = test_state();

        // Post to timeline.
        let post = serde_json::json!({
            "cmd": "create_post",
            "user_id": "alice",
            "content": "Hello from alice!",
        });
        let resp = handle_command(&post.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "create post");
        let post_id = resp.data.unwrap()["post_id"].as_i64().unwrap();

        // Get alice's timeline should include her own post.
        let tl = serde_json::json!({
            "cmd": "get_timeline",
            "user_id": "alice",
        });
        let resp = handle_command(&tl.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "get timeline");
        let posts = resp.data.unwrap()["posts"].as_array().unwrap().clone();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0]["user_id"].as_str().unwrap(), "alice");
        assert_eq!(posts[0]["content"].as_str().unwrap(), "Hello from alice!");
        assert_eq!(posts[0]["comment_count"].as_i64().unwrap(), 0);

        // Add a comment.
        let comment = serde_json::json!({
            "cmd": "add_comment",
            "post_id": post_id,
            "user_id": "bob",
            "content": "Hi alice!",
        });
        let resp = handle_command(&comment.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "add comment");

        // Get comments.
        let comments = serde_json::json!({
            "cmd": "get_comments",
            "post_id": post_id,
        });
        let resp = handle_command(&comments.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "get comments");
        let cmts = resp.data.unwrap()["comments"].as_array().unwrap().clone();
        assert_eq!(cmts.len(), 1);
        assert_eq!(cmts[0]["user_id"].as_str().unwrap(), "bob");
        assert_eq!(cmts[0]["content"].as_str().unwrap(), "Hi alice!");

        // Comment count should be 1 now.
        let resp = handle_command(&tl.to_string(), &state).await;
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.data.unwrap()["posts"][0]["comment_count"].as_i64().unwrap(), 1);

        // Delete post.
        let del = serde_json::json!({
            "cmd": "delete_post",
            "post_id": post_id,
            "user_id": "alice",
        });
        let resp = handle_command(&del.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "delete post");

        // Timeline should be empty.
        let resp = handle_command(&tl.to_string(), &state).await;
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.data.unwrap()["posts"].as_array().unwrap().len(), 0);

        // Comments should be gone too.
        let resp = handle_command(&comments.to_string(), &state).await;
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.data.unwrap()["comments"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_timeline_wall_post() {
        let state = test_state();

        // Bob posts on alice's wall.
        let post = serde_json::json!({
            "cmd": "create_post",
            "user_id": "bob",
            "content": "Hey alice!",
            "target_user_id": "alice",
        });
        let resp = handle_command(&post.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "wall post");
        let post_id = resp.data.unwrap()["post_id"].as_i64().unwrap();

        // Alice should see it in her timeline.
        let tl = serde_json::json!({
            "cmd": "get_timeline",
            "user_id": "alice",
        });
        let resp = handle_command(&tl.to_string(), &state).await;
        assert_eq!(resp.status, "ok", "alice sees wall post");
        let posts = resp.data.unwrap()["posts"].as_array().unwrap().clone();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0]["user_id"].as_str().unwrap(), "bob");
        assert_eq!(posts[0]["target_user_id"].as_str().unwrap(), "alice");

        // Only bob can delete his own post.
        let del = serde_json::json!({
            "cmd": "delete_post",
            "post_id": post_id,
            "user_id": "charlie",
        });
        let resp = handle_command(&del.to_string(), &state).await;
        assert_eq!(resp.status, "error", "charlie cannot delete bob's post");
    }

    #[tokio::test]
    async fn test_timeline_own_post_on_contact_timeline() {
        let state = test_state();

        // Own post (no target_user_id) appears in the user's timeline.
        let post = serde_json::json!({
            "cmd": "create_post",
            "user_id": "alice",
            "content": "My own moment",
        });
        let resp = handle_command(&post.to_string(), &state).await;
        assert_eq!(resp.status, "ok");

        let tl = serde_json::json!({
            "cmd": "get_timeline",
            "user_id": "alice",
        });
        let resp = handle_command(&tl.to_string(), &state).await;
        assert_eq!(resp.status, "ok");
        let posts = resp.data.unwrap()["posts"].as_array().unwrap().clone();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0]["content"].as_str().unwrap(), "My own moment");
        // target_user_id should be null for own posts.
        assert!(posts[0]["target_user_id"].is_null());
    }
}