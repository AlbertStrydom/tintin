# TinTin — Secure E2E Encrypted Super App

**Designed by A.Strydom**

A secure, open-source messaging super app combining the best of WhatsApp, Telegram, and WeChat — with end-to-end encryption by default. Feature-complete prototype with 30+ CLI commands.

## Quick Start

```bash
# Terminal 1 — Server
cargo run --bin tintin-server

# Terminal 2 — Alice
cargo run --bin tintin-cli

# Terminal 3 — Bob
cargo run --bin tintin-cli
```

Or with Docker:

```bash
docker compose up --build
```

## Features (31 CLI Commands)

| # | Feature | CLI Command | Details |
|---|---------|-------------|---------|
| 1 | **E2E Messaging** | `/msg <user> <text>` | X25519 + Double Ratchet + ChaCha20-Poly1305 |
| 2 | **Read Receipts** | `/status` | ✓ delivery + ✓✓ read tracking |
| 3 | **Saved Messages** | Self-messages | Bypasses encryption, auto-saved |
| 4 | **Contact Discovery** | `/users` | Lists all registered users |
| 5 | **Group Chats** | `/group create/join/leave/send` | Pairwise E2E per member |
| 6 | **Edit Messages** | `/edit <idx> <text>` | Shows ✏️ edited marker |
| 7 | **Message Search** | `/search <text>` | Persistent local chat log |
| 8 | **Status / Stories** | `/story /stories /clearstory` | 24-hour auto-expiry |
| 9 | **File Sharing** | `/sendfile <user> <path>` | 256KB chunked E2E transfer |
| 10 | **Channels** | `/channel create/sub/unsub/send` | Broadcast channels, E2E |
| 11 | **Polls** | `/poll create/vote/results/close` | Server-side tally |
| 12 | **P2P Calls** | `/call /accept /end` | Encrypted signalling, X25519 media key |
| 13 | **Stickers** | `/sticker <user> <pack> <id>` | 4 emoji packs (wave/face/heart/mood) |
| 14 | **Timeline / Moments** | `/moment /timeline /comment` | Social feed with wall posting |
| 15 | **QR Contact Sharing** | `/qr /scan` | ASCII QR + `tintin://` URIs |
| 16 | **Voice Messages** | `/voice <user> <path>` | Audio files, E2E encrypted |
| 17 | **Mini-app SDK** | `tintin-sdk` crate (MIT) | Sandboxed WebView mini-apps |

All messages are end-to-end encrypted by default — the server never sees plaintext.

## Project Structure (8 crates)

```
tintin/
├── tintin-core/        # Rust crypto (X25519, Double Ratchet, ChaCha20-Poly1305)
├── tintin-server/      # TCP relay server (port 9666, SQLite persistence)
├── tintin-cli/         # Terminal client (31 commands, all features)
├── tintin-ffi/         # C FFI for iOS
├── tintin-ios/         # SwiftUI iOS app source
├── tintin-jni/         # JNI for Android
├── tintin-android/     # Jetpack Compose Android app source
├── tintin-sdk/         # Mini-app SDK crate (MIT license)
├── Dockerfile          # Production server container
├── docker-compose.yml  # One-command server deployment
├── TINTIN_CONCEPT.md   # Full 10-section project specification
└── TINTIN_MINIAPPS.md  # Mini-app SDK specification
```

## Architecture

- **Client-server**: TCP relay with line-delimited JSON on port 9666
- **Encryption**: Signal Protocol — X25519 key exchange, Double Ratchet, ChaCha20-Poly1305 AEAD
- **Persistence**: SQLite via `rusqlite` (server) + JSON files (CLI)
- **Groups & Channels**: Pairwise E2E (one encrypted copy per member/subscriber)
- **File/Voice Transfer**: Client-side 256KB base64 chunks, each E2E encrypted
- **Server tables**: `users`, `messages`, `groups`, `group_members`, `statuses`, `channels`, `channel_subscribers`, `polls`, `poll_options`, `poll_votes`, `timeline_posts`, `timeline_comments`

## Configuration

| Env Variable | Default | Description |
|---|---|---|
| `TINTIN_DB_PATH` | `tintin-server.db` | Server database path |

## Tests

```bash
cargo test --workspace
```

**37 tests pass** — 13 core crypto + 11 server + 2 FFI + 2 JNI + 9 SDK. Zero warnings.

## CLI Commands Reference

```
/msg <user> <text>        Send E2E encrypted message
/recv                     Poll for new messages
/group create/join/...    Group chat management
/channel create/sub/...   Broadcast channels
/poll create/vote/...     Polls with tally
/call /accept /end        Encrypted P2P call signalling
/sticker <user> <p> <id>  Send emoji sticker
/sendfile <user> <path>   Send file (E2E chunked)
/voice <user> <path>      Send voice message
/moment <text>            Post to your timeline
/moment <u> <t>           Post on someone's wall
/timeline                 View social feed
/comment <id> <text>      Comment on a timeline post
/postcomments <id>        View comments
/deletepost <id>          Delete your post
/search <text>            Search message history
/edit <idx> <text>        Edit sent message
/status                   Show message delivery status
/story <text>             Post status (24h)
/stories                  View contacts' stories
/clearstory               Clear your story
/qr                       Show your contact QR code
/scan <uri>               Scan a contact QR URI
/users                    List registered users
/mygroups                 List your groups
/my_channels              List subscribed channels
/channels                 List all channels
/polls                    List active polls
/help                     Show this help
/quit                     Exit
/save                     Save session
```

## How to Build

### Server (any platform)

```bash
cargo build --release -p tintin-server
```

### iOS (needs Mac)

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cd tintin-ios && ./build_rust.sh && xcodegen generate
```

### Android (needs NDK)

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk
cd tintin-android && ./build_rust.sh
```

## Docker

```bash
docker compose up --build
```

Starts the relay server on port 9666 with persistent SQLite storage in a Docker volume.

## License

- **Clients + Server**: AGPL v3 (see [LICENSE](LICENSE))
- **Mini-app SDK** (`tintin-sdk/`): MIT — to encourage third-party adoption
