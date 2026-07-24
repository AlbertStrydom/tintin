// TinTin Core C FFI — Bridging header for Swift
// ==============================================
// Source of truth: tintin-ffi/tintin_core.h
// Copy this file into the iOS Xcode project's Bridge folder.
//
// All opaque handles are heap-allocated by Rust. Each `_free` function
// must be called exactly once per handle. Byte buffers returned via
// `(*out, *out_len)` must be freed with `tintin_free_buffer`.
// Strings returned by `tintin_last_error` must be freed with
// `tintin_free_string`.

#ifndef TINTIN_CORE_H
#define TINTIN_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Error reporting
// ---------------------------------------------------------------------------

/// Return the last error message. Caller must free with `tintin_free_string`.
char* tintin_last_error(void);

/// Free a string returned by `tintin_last_error`.
void  tintin_free_string(char* s);

/// Free a heap-allocated buffer returned via `(*out, *out_len)`.
void  tintin_free_buffer(uint8_t* ptr, size_t len);

// ---------------------------------------------------------------------------
// Identity Key Pair
// ---------------------------------------------------------------------------

/// Generate a fresh identity key pair. Returns an opaque handle.
void* tintin_identity_generate(void);

/// Free an identity handle.
void  tintin_identity_free(void* ptr);

/// Copy the 32-byte public key into `out[0..32]`. Returns 0 on success.
int   tintin_identity_get_public(const void* ptr, uint8_t* out);

/// Serialise identity to JSON. Returns a C string (free with `tintin_free_string`).
char* tintin_identity_to_json(const void* ptr);

/// Deserialise identity from JSON. Returns an opaque handle or null.
void* tintin_identity_from_json(const char* json);

// ---------------------------------------------------------------------------
// Signed Pre-Key
// ---------------------------------------------------------------------------

/// Generate a signed pre-key signed by `identity`. Returns an opaque handle.
void* tintin_signed_prekey_generate(uint32_t id, const void* identity);

/// Free a signed pre-key handle.
void  tintin_signed_prekey_free(void* ptr);

/// Copy the 32-byte public key into `out[0..32]`. Returns 0 on success.
int   tintin_signed_prekey_get_public(const void* ptr, uint8_t* out);

/// Return the pre-key id.
uint32_t tintin_signed_prekey_get_id(const void* ptr);

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Create a session as **initiator** (Alice starting a chat with Bob).
///
/// - `identity` — our identity handle.
/// - `remote_user_id` — C string, e.g. "bob".
/// - `device_id` — remote device id (typically 1).
/// - `their_identity_32` — 32 bytes, remote user's identity public key.
/// - `signed_prekey_public_32` — 32 bytes, remote user's signed pre-key public.
///
/// Returns an opaque session handle, or null on error.
void* tintin_session_new_initiator(
    const void* identity,
    const char* remote_user_id,
    uint32_t    device_id,
    const uint8_t* their_identity_32,
    const uint8_t* signed_prekey_public_32
);

/// Create a session as **responder** (Bob responding to Alice).
///
/// - `identity` — our identity handle.
/// - `remote_user_id` — C string, e.g. "alice".
/// - `device_id` — remote device id.
/// - `their_identity_32` — 32 bytes, remote user's identity public key.
/// - `alice_eph_32` — 32 bytes, Alice's ephemeral public key.
/// - `our_signed_prekey` — **our** signed pre-key handle (we need the secret).
///
/// Returns an opaque session handle, or null on error.
void* tintin_session_new_responder(
    const void* identity,
    const char* remote_user_id,
    uint32_t    device_id,
    const uint8_t* their_identity_32,
    const uint8_t* alice_eph_32,
    const void* our_signed_prekey
);

/// Free a session handle.
void tintin_session_free(void* ptr);

/// Encrypt plaintext bytes using the session.
///
/// `(*out, *out_len)` receives a buffer of JSON-serialised SessionMessage.
/// Caller must free with `tintin_free_buffer`.
/// Returns 0 on success, -1 on error.
int tintin_session_encrypt(
    void* session,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t** out,
    size_t* out_len
);

/// Decrypt a JSON-serialised SessionMessage using the session.
///
/// `(*out, *out_len)` receives the plaintext bytes.
/// Caller must free with `tintin_free_buffer`.
/// Returns 0 on success, -1 on error.
int tintin_session_decrypt(
    void* session,
    const uint8_t* data,
    size_t data_len,
    uint8_t** out,
    size_t* out_len
);

/// Serialise a session to JSON (for persistence).
/// Returns a C string (free with `tintin_free_string`), or null on error.
char* tintin_session_to_json(const void* session);

/// Deserialise a session from JSON.
/// Returns an opaque handle, or null on error.
void* tintin_session_from_json(const char* json);

/// Copy the current DH ratchet public key into `out[0..32]`.
/// Returns 0 on success, -1 on error.
int tintin_session_get_ratchet_key(const void* session, uint8_t* out);

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Serialise a ChatMessage to JSON bytes (for plaintext).
/// `(*out, *out_len)` receives the buffer. Free with `tintin_free_buffer`.
/// Returns 0 on success, -1 on error.
int tintin_chat_message_to_json(
    const char* text,
    uint64_t timestamp,
    uint8_t** out,
    size_t* out_len
);

#ifdef __cplusplus
}
#endif

#endif // TINTIN_CORE_H
