import Foundation

// MARK: - Error type

enum RustCoreError: LocalizedError {
    case nullPointer(String)
    case operationFailed(String)

    var errorDescription: String? {
        switch self {
        case .nullPointer(let msg): return "Null pointer: \(msg)"
        case .operationFailed(let msg): return msg
        }
    }
}

// MARK: - Identity Key Pair

/// A wrapper around a Rust-allocated `IdentityKeyPair`.
final class IdentityHandle {
    fileprivate let ptr: OpaquePointer

    init(ptr: OpaquePointer) {
        self.ptr = ptr
    }

    deinit {
        tintin_identity_free(OpaquePointer(ptr))
    }

    /// The 32-byte public key.
    var publicKey: Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let rc = tintin_identity_get_public(OpaquePointer(ptr), &bytes)
        precondition(rc == 0, "tintin_identity_get_public failed")
        return Data(bytes)
    }

    /// Serialise to JSON for persistence.
    func toJSON() throws -> String {
        guard let cStr = tintin_identity_to_json(OpaquePointer(ptr)) else {
            throw RustCoreError.nullPointer("identity_to_json returned null")
        }
        defer { tintin_free_string(cStr) }
        return String(cString: cStr)
    }

    /// Deserialise from JSON.
    static func fromJSON(_ json: String) throws -> IdentityHandle {
        let cStr = (json as NSString).utf8String!
        guard let ptr = tintin_identity_from_json(cStr) else {
            throw RustCoreError.operationFailed("failed to deserialise identity")
        }
        return IdentityHandle(ptr: OpaquePointer(ptr))
    }

    /// Generate a fresh identity key pair.
    static func generate() throws -> IdentityHandle {
        guard let ptr = tintin_identity_generate() else {
            throw RustCoreError.nullPointer("identity_generate returned null")
        }
        return IdentityHandle(ptr: OpaquePointer(ptr))
    }
}

// MARK: - Signed Pre-Key

/// A wrapper around a Rust-allocated `SignedPreKey`.
final class SignedPreKeyHandle {
    fileprivate let ptr: OpaquePointer

    init(ptr: OpaquePointer) {
        self.ptr = ptr
    }

    deinit {
        tintin_signed_prekey_free(OpaquePointer(ptr))
    }

    var id: UInt32 {
        tintin_signed_prekey_get_id(OpaquePointer(ptr))
    }

    /// The 32-byte public key.
    var publicKey: Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let rc = tintin_signed_prekey_get_public(OpaquePointer(ptr), &bytes)
        precondition(rc == 0, "tintin_signed_prekey_get_public failed")
        return Data(bytes)
    }

    static func generate(id: UInt32, identity: IdentityHandle) throws -> SignedPreKeyHandle {
        guard let ptr = tintin_signed_prekey_generate(id, OpaquePointer(identity.ptr)) else {
            throw RustCoreError.nullPointer("signed_prekey_generate returned null")
        }
        return SignedPreKeyHandle(ptr: OpaquePointer(ptr))
    }
}

// MARK: - Session

/// A wrapper around a Rust-allocated `Session`.
final class SessionHandle {
    fileprivate let ptr: OpaquePointer

    init(ptr: OpaquePointer) {
        self.ptr = ptr
    }

    deinit {
        tintin_session_free(OpaquePointer(ptr))
    }

    /// The current DH ratchet public key (32 bytes).
    var ratchetKey: Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let rc = tintin_session_get_ratchet_key(OpaquePointer(ptr), &bytes)
        precondition(rc == 0, "tintin_session_get_ratchet_key failed")
        return Data(bytes)
    }

    // MARK: - Create

    /// Create a session as **initiator** (Alice starting a chat with Bob).
    static func newInitiator(
        identity: IdentityHandle,
        remoteUserId: String,
        deviceId: UInt32,
        theirIdentity: Data,
        signedPrekeyPublic: Data
    ) throws -> SessionHandle {
        let rc = theirIdentity.withUnsafeBytes { (idPtr: UnsafeRawBufferPointer) -> OpaquePointer? in
            signedPrekeyPublic.withUnsafeBytes { (spkPtr: UnsafeRawBufferPointer) -> OpaquePointer? in
                guard let cStr = (remoteUserId as NSString).utf8String else { return nil }
                guard let ptr = tintin_session_new_initiator(
                    OpaquePointer(identity.ptr),
                    cStr,
                    deviceId,
                    idPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    spkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                ) else { return nil }
                return OpaquePointer(ptr)
            }
        }
        guard let ptr = rc else {
            throw RustCoreError.operationFailed("newInitiator: \(lastError())")
        }
        return SessionHandle(ptr: ptr)
    }

    /// Create a session as **responder** (Bob responding to Alice).
    static func newResponder(
        identity: IdentityHandle,
        remoteUserId: String,
        deviceId: UInt32,
        theirIdentity: Data,
        aliceEphemeral: Data,
        ourSignedPrekey: SignedPreKeyHandle
    ) throws -> SessionHandle {
        let rc = theirIdentity.withUnsafeBytes { (idPtr: UnsafeRawBufferPointer) -> OpaquePointer? in
            aliceEphemeral.withUnsafeBytes { (ephPtr: UnsafeRawBufferPointer) -> OpaquePointer? in
                guard let cStr = (remoteUserId as NSString).utf8String else { return nil }
                guard let ptr = tintin_session_new_responder(
                    OpaquePointer(identity.ptr),
                    cStr,
                    deviceId,
                    idPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    ephPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    OpaquePointer(ourSignedPrekey.ptr)
                ) else { return nil }
                return OpaquePointer(ptr)
            }
        }
        guard let ptr = rc else {
            throw RustCoreError.operationFailed("newResponder: \(lastError())")
        }
        return SessionHandle(ptr: ptr)
    }

    // MARK: - Encrypt / Decrypt

    /// Encrypt plaintext bytes. Returns JSON bytes of the SessionMessage.
    func encrypt(_ plaintext: Data) throws -> Data {
        var outBuf: UnsafeMutablePointer<UInt8>?
        var outLen: Int = 0
        let rc = plaintext.withUnsafeBytes { (ptPtr: UnsafeRawBufferPointer) -> Int32 in
            tintin_session_encrypt(
                OpaquePointer(ptr),
                ptPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                ptPtr.count,
                &outBuf,
                &outLen
            )
        }
        guard rc == 0, let buf = outBuf else {
            throw RustCoreError.operationFailed("encrypt: \(lastError())")
        }
        let data = Data(bytes: buf, count: outLen)
        tintin_free_buffer(buf, outLen)
        return data
    }

    /// Decrypt JSON bytes of a SessionMessage. Returns plaintext bytes.
    func decrypt(_ ciphertext: Data) throws -> Data {
        var outBuf: UnsafeMutablePointer<UInt8>?
        var outLen: Int = 0
        let rc = ciphertext.withUnsafeBytes { (ctPtr: UnsafeRawBufferPointer) -> Int32 in
            tintin_session_decrypt(
                OpaquePointer(ptr),
                ctPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                ctPtr.count,
                &outBuf,
                &outLen
            )
        }
        guard rc == 0, let buf = outBuf else {
            throw RustCoreError.operationFailed("decrypt: \(lastError())")
        }
        let data = Data(bytes: buf, count: outLen)
        tintin_free_buffer(buf, outLen)
        return data
    }

    // MARK: - Serialisation

    /// Serialise session to JSON for persistence.
    func toJSON() throws -> String {
        guard let cStr = tintin_session_to_json(OpaquePointer(ptr)) else {
            throw RustCoreError.nullPointer("session_to_json returned null")
        }
        defer { tintin_free_string(cStr) }
        return String(cString: cStr)
    }

    /// Deserialise session from JSON.
    static func fromJSON(_ json: String) throws -> SessionHandle {
        let cStr = (json as NSString).utf8String!
        guard let ptr = tintin_session_from_json(cStr) else {
            throw RustCoreError.operationFailed("deserialise session: \(lastError())")
        }
        return SessionHandle(ptr: OpaquePointer(ptr))
    }
}

// MARK: - Helpers

/// Read the last Rust error message.
private func lastError() -> String {
    guard let cStr = tintin_last_error() else { return "unknown error" }
    defer { tintin_free_string(cStr) }
    return String(cString: cStr)
}
