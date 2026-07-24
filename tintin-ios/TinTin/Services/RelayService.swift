import Foundation
import Network

// MARK: - Server response types

struct ServerResponse: Codable {
    let status: String
    let data: ServerData?
    let error: String?
}

/// The `data` field of a server response can be different shapes.
struct ServerData: Codable {
    var user_id: String?
    var identity_key: [UInt8]?
    var signed_pre_key: PreKeyBundleValue?
    var messages: [EnvelopeValue]?
    var queued_for: String?

    // fetch_keys returns data with identity_key + signed_pre_key directly
    // receive returns data with messages array
    // register returns data with user_id
}

struct PreKeyBundleValue: Codable {
    let identity_key: [UInt8]
    let device_id: UInt32
    let signed_pre_key_id: UInt32
    let signed_pre_key: [UInt8]
    let signed_pre_key_signature: [UInt8]
    let one_time_pre_key_id: UInt32?
    let one_time_pre_key: [UInt8]?
}

struct EnvelopeValue: Codable {
    let sender_id: String
    let recipient_id: String
    let sender_device_id: UInt32
    let timestamp: UInt64
    let content: [UInt8]       // JSON-serialised SessionMessage
    let msg_type: String
}

// MARK: - Relay Service

/// A receipt content payload received from the server.
struct ReceiptContentValue: Codable {
    let receipt_type: String
    let original_sender: String
    let original_timestamp: UInt64
}

/// TCP client for the TinTin relay server.
/// Uses NWConnection (Network.framework) for async I/O.
actor RelayService {
    enum RelayError: LocalizedError {
        case notConnected
        case connectionFailed(String)
        case serverError(String)
        case invalidResponse
        case timeout

        var errorDescription: String? {
            switch self {
            case .notConnected: return "Not connected to server"
            case .connectionFailed(let msg): return "Connection failed: \(msg)"
            case .serverError(let msg): return "Server error: \(msg)"
            case .invalidResponse: return "Invalid server response"
            case .timeout: return "Request timed out"
            }
        }
    }

    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "com.tintin.relay")

    // ------------------------------------------------------------------
    // Connection
    // ------------------------------------------------------------------

    /// Connect to the relay server at `host:port`.
    func connect(host: String, port: UInt16) async throws {
        disconnect()
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!
        )
        connection = NWConnection(to: endpoint, using: params)

        return try await withCheckedThrowingContinuation { continuation in
            connection?.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    continuation.resume()
                case .failed(let error):
                    continuation.resume(throwing: RelayError.connectionFailed(error.localizedDescription))
                case .cancelled:
                    if !(continuation.wasResumed) {
                        continuation.resume(throwing: RelayError.connectionFailed("cancelled"))
                    }
                default:
                    break
                }
            }
            connection?.start(queue: self.queue)
        }
    }

    func disconnect() {
        connection?.cancel()
        connection = nil
    }

    var isConnected: Bool {
        connection?.state == .ready
    }

    // ------------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------------

    /// Register a user with their public keys.
    func register(
        userId: String,
        identityKey: [UInt8],
        signedPreKeyId: UInt32,
        signedPreKey: [UInt8],
        signedPreKeySignature: [UInt8]
    ) async throws {
        let bundle: [String: Any?] = [
            "identity_key": identityKey,
            "device_id": 1,
            "signed_pre_key_id": signedPreKeyId,
            "signed_pre_key": signedPreKey,
            "signed_pre_key_signature": signedPreKeySignature,
            "one_time_pre_key_id": nil,
            "one_time_pre_key": nil,
        ]
        let payload: [String: Any] = [
            "cmd": "register",
            "user_id": userId,
            "identity_key": identityKey,
            "signed_pre_key": bundle,
        ]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "register failed")
        }
    }

    /// Fetch a user's key bundle for session establishment.
    func fetchKeys(userId: String) async throws -> (identityKey: [UInt8], signedPreKey: PreKeyBundleValue) {
        let payload: [String: String] = [
            "cmd": "fetch_keys",
            "user_id": userId,
        ]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok", let data = resp.data else {
            throw RelayError.serverError(resp.error ?? "user not found")
        }
        guard let ik = data.identity_key, let spk = data.signed_pre_key else {
            throw RelayError.invalidResponse
        }
        return (ik, spk)
    }

    /// Send an encrypted envelope to a recipient.
    func send(envelope: [String: Any]) async throws {
        var payload = envelope
        payload["cmd"] = "send"
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "send failed")
        }
    }

    /// Receive all pending messages for a user.
    func receive(userId: String) async throws -> [EnvelopeValue] {
        let payload: [String: String] = [
            "cmd": "receive",
            "user_id": userId,
        ]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok", let data = resp.data else {
            throw RelayError.serverError(resp.error ?? "receive failed")
        }
        return data.messages ?? []
    }

    // ------------------------------------------------------------------
    // Low-level send / receive (line-delimited JSON over TCP)
    // ------------------------------------------------------------------

    private func sendCommand<T: Encodable>(_ payload: T) async throws -> ServerResponse {
        guard let conn = connection else {
            throw RelayError.notConnected
        }

        let jsonData = try JSONSerialization.data(withJSONObject: payload as Any, options: [])
        var line = Data(jsonData)
        line.append(0x0A) // newline

        // Send
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            conn.send(content: line, completion: .contentProcessed { error in
                if let error = error {
                    continuation.resume(throwing: RelayError.connectionFailed(error.localizedDescription))
                } else {
                    continuation.resume()
                }
            })
        }

        // Receive line
        return try await withCheckedThrowingContinuation { continuation in
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                if let error = error {
                    continuation.resume(throwing: RelayError.connectionFailed(error.localizedDescription))
                    return
                }
                guard let data = data, !data.isEmpty else {
                    if isComplete {
                        continuation.resume(throwing: RelayError.connectionFailed("connection closed"))
                    } else {
                        continuation.resume(throwing: RelayError.invalidResponse)
                    }
                    return
                }
                do {
                    let resp = try JSONDecoder().decode(ServerResponse.self, from: data)
                    continuation.resume(returning: resp)
                } catch {
                    continuation.resume(throwing: RelayError.invalidResponse)
                }
            }
        }
    }
}
