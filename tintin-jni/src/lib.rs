//! # TinTin JNI — Java/Kotlin bridge for Android
//!
//! This crate exposes TinTin's cryptographic core via JNI so the
//! Android (Jetpack Compose) app can call Rust functions directly.
//!
//! ## Convention
//!
//! All functions follow the JNI naming scheme:
//! `Java_com_tintin_app_RustBridge_<methodName>`.
//!
//! Opaque handles are stored as `jlong` (pointer-sized) on the Java side.
//! Every handle must be freed with its matching `_free` function.

use std::panic::catch_unwind;
use std::sync::Mutex;

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;

// Import specific items from tintin-core to avoid shadowing std::result::Result.
use tintin_core::{
    IdentityKeyPair, Session, SessionMessage, SignedPreKey,
};

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

/// Convert a pointer to a jlong.
fn ptr_to_jlong<T>(ptr: *mut T) -> jlong {
    ptr as jlong
}

/// Convert a jlong back to a pointer (returns null if 0).
fn jlong_to_ptr<T>(val: jlong) -> *mut T {
    val as *mut T
}

/// Helper: extract jbytearray contents into Vec<u8>.
fn byte_array_to_vec(env: &mut JNIEnv, array: &JByteArray) -> Result<Vec<u8>, String> {
    let bytes = env
        .convert_byte_array(array)
        .map_err(|e| format!("JNI byte array: {e}"))?;
    Ok(bytes)
}

/// Helper: create a jbytearray from &[u8].
fn vec_to_byte_array(env: &mut JNIEnv, data: &[u8]) -> Result<jbyteArray, String> {
    let arr = env
        .byte_array_from_slice(data)
        .map_err(|e| format!("JNI create byte array: {e}"))?;
    Ok(arr.into_raw())
}

/// Helper: get Rust string from a JNI jstring.
fn jstring_to_string(env: &mut JNIEnv, s: &JString) -> Result<String, String> {
    env.get_string(s)
        .map(|js| js.into())
        .map_err(|e| format!("JNI string: {e}"))
}

// ===========================================================================
// Identity Key Pair
// ===========================================================================

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_identityGenerate(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    catch_unwind(|| {
        clear_error();
        let ident = IdentityKeyPair::generate();
        ptr_to_jlong(Box::into_raw(Box::new(ident)))
    })
    .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_identityFree(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        let ptr = jlong_to_ptr::<IdentityKeyPair>(handle);
        unsafe { drop(Box::from_raw(ptr)) };
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_identityGetPublic(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let result = catch_unwind(move || -> Result<jbyteArray, String> {
        clear_error();
        let ptr = jlong_to_ptr::<IdentityKeyPair>(handle);
        if ptr.is_null() {
            set_error("null identity handle");
            return Err("null handle".into());
        }
        let ident = unsafe { &*ptr };
        vec_to_byte_array(&mut env, ident.public_key())
    });

    match result {
        Ok(Ok(arr)) => arr,
        _ => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_identityToJson(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let result = catch_unwind(move || -> Result<jstring, String> {
        clear_error();
        let ptr = jlong_to_ptr::<IdentityKeyPair>(handle);
        if ptr.is_null() {
            set_error("null identity handle");
            return Err("null handle".into());
        }
        let ident = unsafe { &*ptr };
        let json = serde_json::to_string(ident).map_err(|e| format!("serialize: {e}"))?;
        let output = env
            .new_string(&json)
            .map_err(|e| format!("JNI new_string: {e}"))?;
        Ok(output.into_raw())
    });

    match result {
        Ok(Ok(s)) => s,
        _ => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_identityFromJson(
    mut env: JNIEnv,
    _class: JClass,
    json: JString,
) -> jlong {
    let result = catch_unwind(move || -> Result<jlong, String> {
        clear_error();
        let s = jstring_to_string(&mut env, &json)?;
        let ident: IdentityKeyPair =
            serde_json::from_str(&s).map_err(|e| format!("deserialize: {e}"))?;
        Ok(ptr_to_jlong(Box::into_raw(Box::new(ident))))
    });

    match result {
        Ok(Ok(h)) => h,
        _ => 0,
    }
}

// ===========================================================================
// Signed Pre-Key
// ===========================================================================

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_signedPrekeyGenerate(
    _env: JNIEnv,
    _class: JClass,
    id: jint,
    identity_handle: jlong,
) -> jlong {
    let result = catch_unwind(move || -> Result<jlong, String> {
        clear_error();
        let ident_ptr = jlong_to_ptr::<IdentityKeyPair>(identity_handle);
        if ident_ptr.is_null() {
            set_error("null identity handle");
            return Err("null handle".into());
        }
        let ident = unsafe { &*ident_ptr };
        let spk = SignedPreKey::generate(id as u32, ident);
        Ok(ptr_to_jlong(Box::into_raw(Box::new(spk))))
    });

    match result {
        Ok(Ok(h)) => h,
        _ => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_signedPrekeyFree(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        let ptr = jlong_to_ptr::<SignedPreKey>(handle);
        unsafe { drop(Box::from_raw(ptr)) };
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_signedPrekeyGetPublic(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let result = catch_unwind(move || -> Result<jbyteArray, String> {
        clear_error();
        let ptr = jlong_to_ptr::<SignedPreKey>(handle);
        if ptr.is_null() {
            set_error("null signed pre-key handle");
            return Err("null handle".into());
        }
        let spk = unsafe { &*ptr };
        vec_to_byte_array(&mut env, &spk.key_pair.public)
    });

    match result {
        Ok(Ok(arr)) => arr,
        _ => std::ptr::null_mut(),
    }
}

// ===========================================================================
// Session
// ===========================================================================

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_sessionNewInitiator(
    mut env: JNIEnv,
    _class: JClass,
    identity_handle: jlong,
    remote_user_id: JString,
    device_id: jint,
    their_identity: JByteArray,
    signed_prekey_public: JByteArray,
) -> jlong {
    let result = catch_unwind(move || -> Result<jlong, String> {
        clear_error();
        let ident_ptr = jlong_to_ptr::<IdentityKeyPair>(identity_handle);
        if ident_ptr.is_null() {
            return Err("null identity".into());
        }
        let ident = unsafe { &*ident_ptr };
        let uid = jstring_to_string(&mut env, &remote_user_id)?;
        let their_id_bytes = byte_array_to_vec(&mut env, &their_identity)?;
        let spk_bytes = byte_array_to_vec(&mut env, &signed_prekey_public)?;

        if their_id_bytes.len() != 32 || spk_bytes.len() != 32 {
            return Err("key arrays must be 32 bytes".into());
        }

        let mut their_id_arr = [0u8; 32];
        let mut spk_arr = [0u8; 32];
        their_id_arr.copy_from_slice(&their_id_bytes);
        spk_arr.copy_from_slice(&spk_bytes);

        let session = Session::new_initiator(
            ident.clone(),
            uid,
            device_id as u32,
            their_id_arr,
            &spk_arr,
        )
        .map_err(|e| format!("new_initiator: {e}"))?;

        Ok(ptr_to_jlong(Box::into_raw(Box::new(session))))
    });

    match result {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            set_error(e);
            0
        }
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_sessionNewResponder(
    mut env: JNIEnv,
    _class: JClass,
    identity_handle: jlong,
    remote_user_id: JString,
    device_id: jint,
    their_identity: JByteArray,
    alice_eph: JByteArray,
    signed_prekey_handle: jlong,
) -> jlong {
    let result = catch_unwind(move || -> Result<jlong, String> {
        clear_error();
        let ident_ptr = jlong_to_ptr::<IdentityKeyPair>(identity_handle);
        let spk_ptr = jlong_to_ptr::<SignedPreKey>(signed_prekey_handle);
        if ident_ptr.is_null() || spk_ptr.is_null() {
            return Err("null handle".into());
        }
        let ident = unsafe { &*ident_ptr };
        let spk = unsafe { &*spk_ptr };
        let uid = jstring_to_string(&mut env, &remote_user_id)?;
        let their_id_bytes = byte_array_to_vec(&mut env, &their_identity)?;
        let alice_eph_bytes = byte_array_to_vec(&mut env, &alice_eph)?;

        if their_id_bytes.len() != 32 || alice_eph_bytes.len() != 32 {
            return Err("key arrays must be 32 bytes".into());
        }

        let mut their_id_arr = [0u8; 32];
        let mut alice_eph_arr = [0u8; 32];
        their_id_arr.copy_from_slice(&their_id_bytes);
        alice_eph_arr.copy_from_slice(&alice_eph_bytes);

        let session = Session::new_responder(
            ident.clone(),
            uid,
            device_id as u32,
            their_id_arr,
            &alice_eph_arr,
            spk.clone(),
        )
        .map_err(|e| format!("new_responder: {e}"))?;

        Ok(ptr_to_jlong(Box::into_raw(Box::new(session))))
    });

    match result {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            set_error(e);
            0
        }
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_sessionFree(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        let ptr = jlong_to_ptr::<Session>(handle);
        unsafe { drop(Box::from_raw(ptr)) };
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_sessionEncrypt(
    mut env: JNIEnv,
    _class: JClass,
    session_handle: jlong,
    plaintext: JByteArray,
) -> jbyteArray {
    let result = catch_unwind(move || -> Result<jbyteArray, String> {
        clear_error();
        let ptr = jlong_to_ptr::<Session>(session_handle);
        if ptr.is_null() {
            return Err("null session".into());
        }
        let session = unsafe { &mut *ptr };
        let pt = byte_array_to_vec(&mut env, &plaintext)?;
        let session_msg = session
            .encrypt(&pt)
            .map_err(|e| format!("encrypt: {e}"))?;
        let json = serde_json::to_vec(&session_msg).map_err(|e| format!("serialize: {e}"))?;
        vec_to_byte_array(&mut env, &json)
    });

    match result {
        Ok(Ok(arr)) => arr,
        _ => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_sessionDecrypt(
    mut env: JNIEnv,
    _class: JClass,
    session_handle: jlong,
    ciphertext: JByteArray,
) -> jbyteArray {
    let result = catch_unwind(move || -> Result<jbyteArray, String> {
        clear_error();
        let ptr = jlong_to_ptr::<Session>(session_handle);
        if ptr.is_null() {
            return Err("null session".into());
        }
        let session = unsafe { &mut *ptr };
        let ct = byte_array_to_vec(&mut env, &ciphertext)?;
        let session_msg: SessionMessage =
            serde_json::from_slice(&ct).map_err(|e| format!("deserialize session msg: {e}"))?;
        let plaintext = session
            .decrypt(&session_msg)
            .map_err(|e| format!("decrypt: {e}"))?;
        vec_to_byte_array(&mut env, &plaintext)
    });

    match result {
        Ok(Ok(arr)) => arr,
        _ => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_sessionToJson(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let result = catch_unwind(move || -> Result<jstring, String> {
        clear_error();
        let ptr = jlong_to_ptr::<Session>(handle);
        if ptr.is_null() {
            return Err("null session".into());
        }
        let session = unsafe { &*ptr };
        let json = serde_json::to_string(session).map_err(|e| format!("serialize: {e}"))?;
        let output = env
            .new_string(&json)
            .map_err(|e| format!("JNI string: {e}"))?;
        Ok(output.into_raw())
    });

    match result {
        Ok(Ok(s)) => s,
        _ => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_sessionFromJson(
    mut env: JNIEnv,
    _class: JClass,
    json: JString,
) -> jlong {
    let result = catch_unwind(move || -> Result<jlong, String> {
        clear_error();
        let s = jstring_to_string(&mut env, &json)?;
        let session: Session =
            serde_json::from_str(&s).map_err(|e| format!("deserialize session: {e}"))?;
        Ok(ptr_to_jlong(Box::into_raw(Box::new(session))))
    });

    match result {
        Ok(Ok(h)) => h,
        _ => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_sessionGetRatchetKey(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let result = catch_unwind(move || -> Result<jbyteArray, String> {
        clear_error();
        let ptr = jlong_to_ptr::<Session>(handle);
        if ptr.is_null() {
            return Err("null session".into());
        }
        let session = unsafe { &*ptr };
        vec_to_byte_array(&mut env, &session.ratchet.dh_ratchet_key.public)
    });

    match result {
        Ok(Ok(arr)) => arr,
        _ => std::ptr::null_mut(),
    }
}

// ===========================================================================
// Last error
// ===========================================================================

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tintin_app_RustBridge_getLastError(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let msg = LAST_ERROR
        .lock()
        .ok()
        .and_then(|e| e.clone())
        .unwrap_or_default();
    let output = env
        .new_string(&msg)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut());
    output
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that identity generation and JSON round-trip work.
    #[test]
    fn test_identity_json_roundtrip() {
        let ident = IdentityKeyPair::generate();
        let json = serde_json::to_string(&ident).unwrap();
        let ident2: IdentityKeyPair = serde_json::from_str(&json).unwrap();
        assert_eq!(ident.public_key(), ident2.public_key());
    }

    /// Test that session initiator/responder encrypt/decrypt works.
    #[test]
    fn test_session_encrypt_decrypt() {
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity);
        let alice_identity = IdentityKeyPair::generate();

        let mut alice_session = Session::new_initiator(
            alice_identity,
            "bob".to_string(),
            1,
            *bob_identity.public_key(),
            &bob_spk.key_pair.public,
        )
        .unwrap();

        let alice_eph = alice_session.ratchet.dh_ratchet_key.public;

        let mut bob_session = Session::new_responder(
            bob_identity,
            "alice".to_string(),
            1,
            *alice_session.our_identity.public_key(),
            &alice_eph,
            bob_spk,
        )
        .unwrap();

        let msg = b"Hello from JNI!";
        let encrypted = alice_session.encrypt(msg).unwrap();
        let json = serde_json::to_vec(&encrypted).unwrap();
        let decrypted_msg: SessionMessage = serde_json::from_slice(&json).unwrap();
        let decrypted = bob_session.decrypt(&decrypted_msg).unwrap();
        assert_eq!(decrypted, msg);
    }
}
