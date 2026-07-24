//! # TinTin FFI — C-compatible bridge for iOS (SwiftUI)
//!
//! This crate exposes TinTin's cryptographic core as plain C functions
//! that Swift can call through a bridging header. All complex objects
//! are returned as opaque `*mut c_void` handles; all byte arrays are
//! passed via pointer + length pairs.
//!
//! ## Memory rules
//!
//! 1. Every `*mut c_void` returned by a `tintin_*_new` / `tintin_*_generate`
//!    function must be freed by its matching `tintin_*_free` function.
//! 2. Every `char*` returned by `tintin_last_error` must be freed with
//!    `tintin_free_string`.
//! 3. Every buffer written to `*out` / `*out_len` must be freed with
//!    `tintin_free_buffer`.

use std::ffi::{c_char, CStr, CString};
use std::sync::Mutex;

use tintin_core::*;

// ---------------------------------------------------------------------------
// Global last-error slot
// ---------------------------------------------------------------------------

static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_error(msg: impl Into<String>) {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = Some(msg.into());
    }
}

fn clear_error() {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = None;
    }
}

/// Helper: write 32 bytes from `src` to `dst`.
unsafe fn write_32(dst: *mut u8, src: &[u8; 32]) {
    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst, 32) }
}

// ---------------------------------------------------------------------------
// Error reporting
// ---------------------------------------------------------------------------

/// Return the last error message. The caller **must** free the returned string
/// with `tintin_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_last_error() -> *mut c_char {
    let msg = LAST_ERROR
        .lock()
        .ok()
        .and_then(|e| e.clone())
        .unwrap_or_default();
    CString::new(msg).unwrap_or_default().into_raw()
}

/// Free a string previously returned by `tintin_last_error`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)); }
    }
}

/// Free a heap-allocated buffer returned by any function that writes to
/// `(*out, *out_len)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_free_buffer(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        unsafe { drop(Vec::from_raw_parts(ptr, len, len)); }
    }
}

// ===========================================================================
// Identity Key Pair
// ===========================================================================

/// Generate a fresh identity key pair.
/// Returns an opaque handle, or null on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_identity_generate() -> *mut IdentityKeyPair {
    clear_error();
    Box::into_raw(Box::new(IdentityKeyPair::generate()))
}

/// Free an identity handle created by `tintin_identity_generate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_identity_free(ptr: *mut IdentityKeyPair) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
    }
}

/// Copy the 32-byte public key of an identity into `out[0..32]`.
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_identity_get_public(
    ptr: *const IdentityKeyPair,
    out: *mut u8,
) -> i32 {
    if ptr.is_null() || out.is_null() {
        set_error("null pointer");
        return -1;
    }
    let identity = unsafe { &*ptr };
    unsafe { write_32(out, identity.public_key()) };
    0
}

/// Serialise an identity key pair to a JSON string.
/// Returns a null-terminated C string that must be freed with `tintin_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_identity_to_json(ptr: *const IdentityKeyPair) -> *mut c_char {
    clear_error();
    if ptr.is_null() {
        set_error("null ptr");
        return std::ptr::null_mut();
    }
    let identity = unsafe { &*ptr };
    match serde_json::to_string(identity) {
        Ok(json) => CString::new(json).unwrap_or_default().into_raw(),
        Err(e) => {
            set_error(format!("serialize identity: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Deserialise an identity key pair from a JSON string.
/// Returns an opaque handle, or null on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_identity_from_json(json: *const c_char) -> *mut IdentityKeyPair {
    clear_error();
    if json.is_null() {
        set_error("null ptr");
        return std::ptr::null_mut();
    }
    let s = match unsafe { CStr::from_ptr(json) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("invalid utf-8: {e}"));
            return std::ptr::null_mut();
        }
    };
    match serde_json::from_str::<IdentityKeyPair>(s) {
        Ok(ident) => Box::into_raw(Box::new(ident)),
        Err(e) => {
            set_error(format!("deserialize identity: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ===========================================================================
// Signed Pre-Key
// ===========================================================================

/// Generate a signed pre-key.
/// `identity` must be a valid handle from `tintin_identity_generate`.
/// Returns an opaque handle, or null on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_signed_prekey_generate(
    id: u32,
    identity: *const IdentityKeyPair,
) -> *mut SignedPreKey {
    clear_error();
    if identity.is_null() {
        set_error("null identity ptr");
        return std::ptr::null_mut();
    }
    let ident = unsafe { &*identity };
    Box::into_raw(Box::new(SignedPreKey::generate(id, ident)))
}

/// Free a signed pre-key handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_signed_prekey_free(ptr: *mut SignedPreKey) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
    }
}

/// Copy the 32-byte public key of a signed pre-key into `out[0..32]`.
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_signed_prekey_get_public(
    ptr: *const SignedPreKey,
    out: *mut u8,
) -> i32 {
    if ptr.is_null() || out.is_null() {
        set_error("null pointer");
        return -1;
    }
    let spk = unsafe { &*ptr };
    unsafe { write_32(out, &spk.key_pair.public) };
    0
}

/// Return the id of a signed pre-key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_signed_prekey_get_id(ptr: *const SignedPreKey) -> u32 {
    if ptr.is_null() {
        set_error("null ptr");
        return 0;
    }
    let spk = unsafe { &*ptr };
    spk.id
}

// ===========================================================================
// Session
// ===========================================================================

/// Create a new session as **initiator** (Alice starting a chat with Bob).
///
/// * `identity` — our identity (opaque handle).
/// * `remote_user_id` — C string (e.g. "bob").
/// * `device_id` — remote device id (usually 1).
/// * `their_identity_32` — 32-byte identity public key of the remote user.
/// * `signed_prekey_public_32` — 32-byte signed pre-key public of the remote user.
///
/// Returns an opaque session handle, or null on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_session_new_initiator(
    identity: *const IdentityKeyPair,
    remote_user_id: *const c_char,
    device_id: u32,
    their_identity_32: *const u8,
    signed_prekey_public_32: *const u8,
) -> *mut Session {
    clear_error();
    if identity.is_null()
        || remote_user_id.is_null()
        || their_identity_32.is_null()
        || signed_prekey_public_32.is_null()
    {
        set_error("null pointer argument");
        return std::ptr::null_mut();
    }

    let ident = unsafe { &*identity };
    let uid = match unsafe { CStr::from_ptr(remote_user_id) }.to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            set_error(format!("invalid remote_user_id utf-8: {e}"));
            return std::ptr::null_mut();
        }
    };
    let their_id = unsafe { *(their_identity_32 as *const [u8; 32]) };
    let spk_pub = unsafe { *(signed_prekey_public_32 as *const [u8; 32]) };

    match Session::new_initiator(ident.clone(), uid, device_id, their_id, &spk_pub) {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(e) => {
            set_error(format!("session initiator: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Create a new session as **responder** (Bob responding to Alice).
///
/// * `identity` — our identity (opaque handle).
/// * `remote_user_id` — C string (the other user's id, e.g. "alice").
/// * `device_id` — remote device id.
/// * `their_identity_32` — 32-byte identity public key of the remote user.
/// * `alice_eph_32` — 32-byte ephemeral public key that Alice sent.
/// * `our_signed_prekey` — **our** signed pre-key (opaque handle, we need the secret).
///
/// Returns an opaque session handle, or null on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_session_new_responder(
    identity: *const IdentityKeyPair,
    remote_user_id: *const c_char,
    device_id: u32,
    their_identity_32: *const u8,
    alice_eph_32: *const u8,
    our_signed_prekey: *const SignedPreKey,
) -> *mut Session {
    clear_error();
    if identity.is_null()
        || remote_user_id.is_null()
        || their_identity_32.is_null()
        || alice_eph_32.is_null()
        || our_signed_prekey.is_null()
    {
        set_error("null pointer argument");
        return std::ptr::null_mut();
    }

    let ident = unsafe { &*identity };
    let uid = match unsafe { CStr::from_ptr(remote_user_id) }.to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            set_error(format!("invalid remote_user_id utf-8: {e}"));
            return std::ptr::null_mut();
        }
    };
    let their_id = unsafe { *(their_identity_32 as *const [u8; 32]) };
    let alice_eph = unsafe { *(alice_eph_32 as *const [u8; 32]) };
    let spk = unsafe { &*our_signed_prekey };

    match Session::new_responder(ident.clone(), uid, device_id, their_id, &alice_eph, spk.clone())
    {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(e) => {
            set_error(format!("session responder: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Free a session handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_session_free(ptr: *mut Session) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
    }
}

/// Encrypt a plaintext message using a session.
///
/// * `session` — mutable session handle.
/// * `plaintext` — pointer to plaintext bytes.
/// * `plaintext_len` — length in bytes.
/// * `out` — receives a pointer to the allocated ciphertext buffer.
/// * `out_len` — receives the length of the ciphertext.
///
/// Returns 0 on success, -1 on error. The output buffer must be freed with
/// `tintin_free_buffer`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_session_encrypt(
    session: *mut Session,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    clear_error();
    if session.is_null() || plaintext.is_null() || out.is_null() || out_len.is_null() {
        set_error("null pointer");
        return -1;
    }

    let session = unsafe { &mut *session };
    let pt_slice = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };

    match session.encrypt(pt_slice) {
        Ok(session_msg) => {
            let json_bytes = serde_json::to_vec(&session_msg).unwrap_or_default();
            let len = json_bytes.len();
            let buf = json_bytes.leak().as_mut_ptr();
            unsafe {
                *out = buf;
                *out_len = len;
            }
            0
        }
        Err(e) => {
            set_error(format!("encrypt: {e}"));
            -1
        }
    }
}

/// Decrypt a ciphertext (JSON-serialised SessionMessage) using a session.
///
/// Arguments follow the same pattern as `tintin_session_encrypt`.
/// The output buffer (plaintext) must be freed with `tintin_free_buffer`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_session_decrypt(
    session: *mut Session,
    data: *const u8,
    data_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    clear_error();
    if session.is_null() || data.is_null() || out.is_null() || out_len.is_null() {
        set_error("null pointer");
        return -1;
    }

    let session = unsafe { &mut *session };
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };

    let session_msg: SessionMessage = match serde_json::from_slice(data_slice) {
        Ok(m) => m,
        Err(e) => {
            set_error(format!("deserialize session message: {e}"));
            return -1;
        }
    };

    match session.decrypt(&session_msg) {
        Ok(plaintext) => {
            let len = plaintext.len();
            let buf = plaintext.leak().as_mut_ptr();
            unsafe {
                *out = buf;
                *out_len = len;
            }
            0
        }
        Err(e) => {
            set_error(format!("decrypt: {e}"));
            -1
        }
    }
}

/// Serialise a session to a JSON string (for persistence on device).
/// Returns a C string that must be freed with `tintin_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_session_to_json(session: *const Session) -> *mut c_char {
    clear_error();
    if session.is_null() {
        set_error("null ptr");
        return std::ptr::null_mut();
    }
    let s = unsafe { &*session };
    match serde_json::to_string(s) {
        Ok(json) => CString::new(json).unwrap_or_default().into_raw(),
        Err(e) => {
            set_error(format!("serialize session: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Deserialise a session from a JSON string.
/// Returns an opaque handle, or null on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_session_from_json(json: *const c_char) -> *mut Session {
    clear_error();
    if json.is_null() {
        set_error("null ptr");
        return std::ptr::null_mut();
    }
    let s = match unsafe { CStr::from_ptr(json) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("invalid utf-8: {e}"));
            return std::ptr::null_mut();
        }
    };
    match serde_json::from_str::<Session>(s) {
        Ok(sess) => Box::into_raw(Box::new(sess)),
        Err(e) => {
            set_error(format!("deserialize session: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Copy the current DH ratchet public key of a session into `out[0..32]`.
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_session_get_ratchet_key(
    session: *const Session,
    out: *mut u8,
) -> i32 {
    if session.is_null() || out.is_null() {
        set_error("null pointer");
        return -1;
    }
    let s = unsafe { &*session };
    unsafe { write_32(out, &s.ratchet.dh_ratchet_key.public) };
    0
}

// ===========================================================================
// Convenience: serialise a ChatMessage to/from JSON bytes
// ===========================================================================

/// Serialise a ChatMessage to JSON bytes (output buffer must be freed with
/// `tintin_free_buffer`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tintin_chat_message_to_json(
    text: *const c_char,
    timestamp: u64,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    clear_error();
    if text.is_null() || out.is_null() || out_len.is_null() {
        set_error("null pointer");
        return -1;
    }
    let text_str = match unsafe { CStr::from_ptr(text) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("invalid utf-8: {e}"));
            return -1;
        }
    };
    let msg = ChatMessage {
        text: text_str.to_string(),
        timestamp,
    };
    let json_bytes = serde_json::to_vec(&msg).unwrap_or_default();
    let len = json_bytes.len();
    let buf = json_bytes.leak().as_mut_ptr();
    unsafe {
        *out = buf;
        *out_len = len;
    }
    0
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Round-trip identity generation → JSON → from JSON.
    #[test]
    fn test_identity_json_roundtrip() {
        unsafe {
            let id = tintin_identity_generate();
            assert!(!id.is_null());

            let json = tintin_identity_to_json(id);
            assert!(!json.is_null());

            let id2 = tintin_identity_from_json(json);
            assert!(!id2.is_null());

            // Public keys should match
            let mut pub1 = [0u8; 32];
            let mut pub2 = [0u8; 32];
            assert_eq!(tintin_identity_get_public(id, pub1.as_mut_ptr()), 0);
            assert_eq!(tintin_identity_get_public(id2, pub2.as_mut_ptr()), 0);
            assert_eq!(pub1, pub2);

            tintin_identity_free(id);
            tintin_identity_free(id2);
            tintin_free_string(json);
        }
    }

    /// Round-trip session initiator → JSON → from JSON → encrypt/decrypt.
    #[test]
    fn test_session_ffi_encrypt_decrypt() {
        unsafe {
            // Bob's key material
            let bob_identity = tintin_identity_generate();
            let bob_spk = tintin_signed_prekey_generate(1, bob_identity);

            let mut bob_spk_pub = [0u8; 32];
            assert_eq!(tintin_signed_prekey_get_public(bob_spk, bob_spk_pub.as_mut_ptr()), 0);

            // Alice's key material
            let alice_identity = tintin_identity_generate();
            let mut alice_id_pub = [0u8; 32];
            tintin_identity_get_public(alice_identity, alice_id_pub.as_mut_ptr());

            let mut bob_id_pub = [0u8; 32];
            tintin_identity_get_public(bob_identity, bob_id_pub.as_mut_ptr());

            let alice_name = CString::new("bob").unwrap();
            let bob_name = CString::new("alice").unwrap();

            // Alice creates initiator session
            let alice_session = tintin_session_new_initiator(
                alice_identity,
                alice_name.as_ptr(),
                1,
                bob_id_pub.as_ptr(),
                bob_spk_pub.as_ptr(),
            );
            assert!(!alice_session.is_null(), "alice session creation failed: {:?}", {
                let err = CStr::from_ptr(tintin_last_error());
                err.to_str().unwrap_or("?").to_string()
            });

            // Get Alice's ephemeral key from session
            let mut alice_eph = [0u8; 32];
            tintin_session_get_ratchet_key(alice_session, alice_eph.as_mut_ptr());

            // Bob creates responder session
            let bob_session = tintin_session_new_responder(
                bob_identity,
                bob_name.as_ptr(),
                1,
                alice_id_pub.as_ptr(),
                alice_eph.as_ptr(),
                bob_spk,
            );
            assert!(!bob_session.is_null(), "bob session creation failed: {:?}", {
                let err = CStr::from_ptr(tintin_last_error());
                err.to_str().unwrap_or("?").to_string()
            });

            // Alice encrypts a message
            let msg = b"Hello from Alice via FFI!";
            let mut cipher_buf: *mut u8 = std::ptr::null_mut();
            let mut cipher_len: usize = 0;
            let ret = tintin_session_encrypt(
                alice_session,
                msg.as_ptr(),
                msg.len(),
                &mut cipher_buf as *mut *mut u8,
                &mut cipher_len as *mut usize,
            );
            assert_eq!(ret, 0, "encrypt failed: {:?}", {
                let err = CStr::from_ptr(tintin_last_error());
                err.to_str().unwrap_or("?").to_string()
            });
            assert!(cipher_len > 0);

            // Bob decrypts
            let mut plain_buf: *mut u8 = std::ptr::null_mut();
            let mut plain_len: usize = 0;
            let ret2 = tintin_session_decrypt(
                bob_session,
                cipher_buf,
                cipher_len,
                &mut plain_buf as *mut *mut u8,
                &mut plain_len as *mut usize,
            );
            assert_eq!(ret2, 0, "decrypt failed: {:?}", {
                let err = CStr::from_ptr(tintin_last_error());
                err.to_str().unwrap_or("?").to_string()
            });
            assert_eq!(plain_len, msg.len());

            let decrypted = std::slice::from_raw_parts(plain_buf, plain_len);
            assert_eq!(decrypted, msg);

            // Cleanup
            tintin_session_free(alice_session);
            tintin_session_free(bob_session);
            tintin_identity_free(alice_identity);
            tintin_identity_free(bob_identity);
            tintin_signed_prekey_free(bob_spk);
            tintin_free_buffer(cipher_buf, cipher_len);
            tintin_free_buffer(plain_buf, plain_len);
        }
    }
}
