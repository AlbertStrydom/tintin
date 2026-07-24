# TinTin — Secure E2E Encrypted Messaging

**Designed by A.Strydom**

A secure, open-source messaging app that combines the best of WhatsApp, Telegram, and WeChat — with end-to-end encryption by default.

## Phase 1 — Rust Foundations ✓

This is the first phase of the TinTin project: a **Rust-based CLI chat client with E2E encryption**.

### Architecture

```
tintin/
├── tintin-core/      # Shared Rust library: crypto, keys, Double Ratchet
├── tintin-server/    # Minimal relay server (store-and-forward)
├── tintin-cli/       # Terminal chat client
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
| **Tests** | ✅ 15 passing (core crypto + server relay) |

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

## Roadmap

- **Phase 2**: iOS app (SwiftUI) with Rust core via FFI
- **Phase 3**: Android app (Jetpack Compose) with same Rust core
- **Phase 4**: Group chats, voice messages, calls
- **Phase 5**: Channels, stickers, mini-apps

## License

AGPL v3 (clients + server)