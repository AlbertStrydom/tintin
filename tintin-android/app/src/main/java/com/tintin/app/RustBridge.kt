package com.tintin.app

/**
 * JNI bridge to the Rust tintin-core library.
 *
 * All handles (Long) are opaque pointers to Rust heap-allocated objects.
 * Every handle must be freed with its matching `_free` function.
 */
object RustBridge {
    init {
        System.loadLibrary("tintin_android")
    }

    // ------------------------------------------------------------------
    // Identity
    // ------------------------------------------------------------------

    /** Generate a fresh identity key pair. Returns an opaque handle. */
    external fun identityGenerate(): Long

    /** Free an identity handle. */
    external fun identityFree(handle: Long)

    /** Get the 32-byte public key. */
    external fun identityGetPublic(handle: Long): ByteArray

    /** Serialise identity to JSON. */
    external fun identityToJson(handle: Long): String

    /** Deserialise identity from JSON. Returns a handle. */
    external fun identityFromJson(json: String): Long

    // ------------------------------------------------------------------
    // Signed Pre-Key
    // ------------------------------------------------------------------

    /** Generate a signed pre-key. Returns an opaque handle. */
    external fun signedPrekeyGenerate(id: Int, identityHandle: Long): Long

    /** Free a signed pre-key handle. */
    external fun signedPrekeyFree(handle: Long)

    /** Get the 32-byte public key. */
    external fun signedPrekeyGetPublic(handle: Long): ByteArray

    // ------------------------------------------------------------------
    // Session
    // ------------------------------------------------------------------

    /** Create a session as initiator. Returns an opaque handle. */
    external fun sessionNewInitiator(
        identityHandle: Long,
        remoteUserId: String,
        deviceId: Int,
        theirIdentity: ByteArray,
        signedPrekeyPublic: ByteArray,
    ): Long

    /** Create a session as responder. Returns an opaque handle. */
    external fun sessionNewResponder(
        identityHandle: Long,
        remoteUserId: String,
        deviceId: Int,
        theirIdentity: ByteArray,
        aliceEph: ByteArray,
        signedPrekeyHandle: Long,
    ): Long

    /** Free a session handle. */
    external fun sessionFree(handle: Long)

    /** Encrypt plaintext bytes. Returns JSON-serialised SessionMessage bytes. */
    external fun sessionEncrypt(sessionHandle: Long, plaintext: ByteArray): ByteArray

    /** Decrypt JSON-serialised SessionMessage bytes. Returns plaintext bytes. */
    external fun sessionDecrypt(sessionHandle: Long, ciphertext: ByteArray): ByteArray

    /** Serialise session to JSON for persistence. */
    external fun sessionToJson(handle: Long): String

    /** Deserialise session from JSON. Returns a handle. */
    external fun sessionFromJson(json: String): Long

    /** Get the current DH ratchet public key (32 bytes). */
    external fun sessionGetRatchetKey(handle: Long): ByteArray

    // ------------------------------------------------------------------
    // Error
    // ------------------------------------------------------------------

    /** Get the last error message from Rust. */
    external fun getLastError(): String
}
