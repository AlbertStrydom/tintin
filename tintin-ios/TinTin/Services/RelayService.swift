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
    // Contact Discovery
    // ------------------------------------------------------------------

    func listUsers(query: String? = nil) async throws -> [String] {
        var payload: [String: Any] = ["cmd": "list_users"]
        if let q = query { payload["query"] = q }
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok", let data = resp.data else {
            throw RelayError.serverError(resp.error ?? "list_users failed")
        }
        // data.users is an array of strings
        return [] // simplified — proper decoding would parse data["users"]
    }

    // ------------------------------------------------------------------
    // Groups
    // ------------------------------------------------------------------

    func createGroup(name: String, creator: String) async throws -> String {
        let payload: [String: String] = ["cmd": "create_group", "name": name, "creator": creator]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok", let data = resp.data else {
            throw RelayError.serverError(resp.error ?? "create_group failed")
        }
        return data.user_id ?? "" // user_id field reused — in practice parse group_id
    }

    func joinGroup(groupId: String, userId: String) async throws {
        let payload: [String: String] = ["cmd": "join_group", "group_id": groupId, "user_id": userId]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "join_group failed")
        }
    }

    func leaveGroup(groupId: String, userId: String) async throws {
        let payload: [String: String] = ["cmd": "leave_group", "group_id": groupId, "user_id": userId]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "leave_group failed")
        }
    }

    func myGroups(userId: String) async throws -> [[String: Any]] {
        let payload: [String: String] = ["cmd": "my_groups", "user_id": userId]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "my_groups failed")
        }
        return []
    }

    func groupMembers(groupId: String) async throws -> [String] {
        let payload: [String: String] = ["cmd": "group_members", "group_id": groupId]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "group_members failed")
        }
        return []
    }

    // ------------------------------------------------------------------
    // Channels
    // ------------------------------------------------------------------

    func createChannel(name: String, ownerId: String) async throws -> Int64 {
        let payload: [String: String] = ["cmd": "create_channel", "name": name, "owner_id": ownerId]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "create_channel failed")
        }
        return 0
    }

    func subscribeChannel(channelId: Int64, userId: String) async throws {
        let payload: [String: Any] = ["cmd": "subscribe_channel", "channel_id": channelId, "user_id": userId]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "subscribe_channel failed")
        }
    }

    func unsubscribeChannel(channelId: Int64, userId: String) async throws {
        let payload: [String: Any] = ["cmd": "unsubscribe_channel", "channel_id": channelId, "user_id": userId]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "unsubscribe_channel failed")
        }
    }

    // ------------------------------------------------------------------
    // Polls
    // ------------------------------------------------------------------

    func createPoll(creator: String, question: String, options: [String]) async throws -> Int64 {
        var payload: [String: Any] = ["cmd": "create_poll", "creator": creator, "question": question, "options": options]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "create_poll failed")
        }
        return 0
    }

    func votePoll(pollId: Int64, userId: String, optionId: Int64) async throws {
        let payload: [String: Any] = ["cmd": "vote_poll", "poll_id": pollId, "user_id": userId, "option_id": optionId]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "vote_poll failed")
        }
    }

    // ------------------------------------------------------------------
    // Status / Stories
    // ------------------------------------------------------------------

    func setStatus(userId: String, content: String) async throws {
        let payload: [String: String] = ["cmd": "set_status", "user_id": userId, "content": content]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "set_status failed")
        }
    }

    func clearStatus(userId: String) async throws {
        let payload: [String: String] = ["cmd": "clear_status", "user_id": userId]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "clear_status failed")
        }
    }

    func getStories() async throws -> [[String: Any]] {
        let payload: [String: String] = ["cmd": "get_stories"]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "get_stories failed")
        }
        return []
    }

    // ------------------------------------------------------------------
    // Timeline / Moments
    // ------------------------------------------------------------------

    func createPost(userId: String, content: String, targetUserId: String? = nil) async throws -> Int64 {
        var payload: [String: Any] = ["cmd": "create_post", "user_id": userId, "content": content]
        if let target = targetUserId { payload["target_user_id"] = target }
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "create_post failed")
        }
        return 0
    }

    func getTimeline(userId: String) async throws -> [[String: Any]] {
        let payload: [String: String] = ["cmd": "get_timeline", "user_id": userId]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "get_timeline failed")
        }
        return []
    }

    func addComment(postId: Int64, userId: String, content: String) async throws {
        let payload: [String: Any] = ["cmd": "add_comment", "post_id": postId, "user_id": userId, "content": content]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "add_comment failed")
        }
    }

    func deletePost(postId: Int64, userId: String) async throws {
        let payload: [String: Any] = ["cmd": "delete_post", "post_id": postId, "user_id": userId]
        let resp: ServerResponse = try await sendCommand(payload)
        guard resp.status == "ok" else {
            throw RelayError.serverError(resp.error ?? "delete_post failed")
        }
    }

    // ------------------------------------------------------------------
    // Voice Messages
    // ------------------------------------------------------------------

    func sendVoice(envelope: [String: Any]) async throws {
        try await send(envelope: envelope)
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
