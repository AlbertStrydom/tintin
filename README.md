# TinTin — Secure E2E Encrypted Messaging

**Designed by A.Strydom**

A secure, open-source messaging app that combines the best of WhatsApp, Telegram, and WeChat — with end-to-end encryption by default.

## Phase 1 — Rust Foundations ✓

The core Rust library, relay server, and CLI chat client with E2E encryption.

### Architecture

```
tintin/
├── tintin-core/      # Shared Rust library: crypto, keys, Double Ratchet
├── tintin-ffi/       # C-compatible FFI layer for iOS/Android clients
├── tintin-server/    # Minimal relay server (store-and-forward)
├── tintin-cli/       # Terminal chat client
├── tintin-ios/       # iOS SwiftUI app (Phase 2)
└── Cargo.toml        # Workspace definition
```

### Status

| Component | Status |
|---|---|
| **E2E Encryption** | ✅ ChaCha20-Poly1305 AEAD |
| **Key Exchange** | ✅ X25519 Diffie-Hellman |
| **Double Ratchet** | ✅ Send/receive chains, DH ratchet steps |
| **Session Management** | ✅ Session creation, in-memory store |
| **Relay Server** | ✅ TCP with JSON protocol, key store, message queue |
| **CLI Client** | ✅ Register, send, receive encrypted messages |
| **C FFI Layer** | ✅ Identity, signed pre-key, session encrypt/decrypt via C |
| **iOS SwiftUI App** | ✅ All source files + XcodeGen project spec |
| **Tests** | ✅ 17 passing (core crypto + server relay + FFI) |

## How to Run

### 1. Start the Relay Server

Open **Terminal 1**:

```bash
cd tintin
cargo run --bin tintin-server
```

You'll see:
```
🚀 TinTin Relay Server listening on 127.0.0.1:9666
```

### 2. Start Alice (Terminal 2)

Open **Terminal 2**:

```bash
cd tintin
cargo run --bin tintin-cli
```

Enter your user ID when prompted: `alice`

### 3. Start Bob (Terminal 3)

Open **Terminal 3**:

```bash
cd tintin
cargo run --bin tintin-cli
```

Enter your user ID when prompted: `bob`

### 4. Send your first E2E message

In Alice's terminal:
```
> /msg bob Hello Bob! This message is end-to-end encrypted.
```

In Bob's terminal:
```
> /recv
📬 1 new message(s):
💬 alice: Hello Bob! This message is end-to-end encrypted.
```

Bob can reply:
```
> /msg alice Hey Alice! Got your encrypted message loud and clear.
```

Alice checks:
```
> /recv
📬 1 new message(s):
💬 bob: Hey Alice! Got your encrypted message loud and clear.
```

### Available CLI Commands

| Command | Description |
|---|---|
| `/msg <user> <text>` | Send an E2E encrypted message |
| `/recv` | Poll for new messages |
| `/help` | Show help |
| `/quit` | Exit |

## How It Works

1. **Registration**: Each client generates an X25519 identity key pair and a signed pre-key, then registers the public keys with the relay server.

2. **Session Establishment**: When Alice messages Bob for the first time, she fetches his pre-key bundle, generates an ephemeral key, and computes a shared secret via X25519 Diffie-Hellman. This initializes the Double Ratchet.

3. **Encryption**: Each message is encrypted with ChaCha20-Poly1305 using a key derived from the Double Ratchet's sending chain. A new message key is derived for every message (forward secrecy).

4. **Relay**: The server stores and forwards encrypted envelopes. It never sees plaintext — only ciphertext, routing info, and metadata.

5. **Decryption**: The recipient uses their session's receiving chain (which advanced in sync with the sender's chain) to derive the correct message key and decrypt.

## Run Tests

```bash
cd tintin
cargo test --workspace
```

## Phase 2 — iOS App (SwiftUI + Rust FFI) 🏗️

The `tintin-ios/` directory contains a complete SwiftUI client that calls into Rust through a C FFI bridge.

### How to Build on Mac

You need a Mac with Xcode 15+, Rust, and the iOS Rust targets installed:

```bash
# 1. Install dependencies
brew install xcodegen
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# 2. Build the Rust library for all iOS targets
cd tintin-ios
./build_rust.sh

# 3. Generate the Xcode project
xcodegen generate

# 4. Open TinTin.xcodeproj, set your team in Signing & Capabilities, and run
```

### iOS App Architecture

```
tintin-ios/
├── project.yml              # XcodeGen project spec
├── build_rust.sh            # Cross-compiles Rust for iOS
├── TinTin/
│   ├── TinTinApp.swift       # @main entry — navigation flow
│   ├── Info.plist
│   ├── Models/               # Swift data types
│   │   ├── ServerConfig.swift
│   │   ├── UserModel.swift
│   │   └── MessageModel.swift
│   ├── Services/             # Business logic
│   │   ├── RustCoreService.swift   # Safe Swift wrapper around C FFI
│   │   └── RelayService.swift      # TCP relay client (NWConnection)
│   ├── Views/                # SwiftUI screens
│   │   ├── ConnectView.swift
│   │   ├── RegisterView.swift
│   │   ├── ChatListView.swift
│   │   └── ChatView.swift
│   └── Bridge/               # C bridging header + Rust lib
│       ├── tintin_core.h
│       └── TinTin-Bridging-Header.h
```

### App Flow

1. **Connect** — enter server host/port and your user ID
2. **Register** — generates identity keys, uploads public key bundle to relay
3. **Chat List** — shows contacts; tap "+" to start a new encrypted conversation (fetches remote keys, creates Double Ratchet session)
4. **Chat** — messages are encrypted in Rust, sent as JSON via TCP, decrypted on the receiving side

### Current Limitations (Phase 2)

- Polling-based message receive (3s interval) — push notifications come later
- Pre-key bundle messages not fully implemented on the responder side
- No message persistence (sessions stored in UserDefaults)
- Single device (device_id always 1)

## Roadmap

- **Phase 2**: ✅ iOS SwiftUI app (source complete, needs Mac build) 🏗️
- **Phase 3**: Android app (Jetpack Compose) with same Rust core
- **Phase 4**: Group chats, voice messages, calls
- **Phase 5**: Channels, stickers, mini-apps

## License

AGPL v3 (clients + server)