import SwiftUI

@main
struct TinTinApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            Group {
                if !appState.isConnected {
                    ConnectView()
                        .environmentObject(appState)
                } else if !appState.isRegistered {
                    RegisterView()
                        .environmentObject(appState)
                } else {
                    ChatListView()
                        .environmentObject(appState)
                }
            }
        }
    }
}

// MARK: - Global App State

@MainActor
class AppState: ObservableObject {
    @Published var isConnected = false
    @Published var isRegistered = false

    // Server
    @Published var serverHost = "127.0.0.1"
    @Published var serverPort: UInt16 = 9666
    @Published var userId = ""

    // Crypto handles (persisted to UserDefaults as JSON)
    private var identityHandle: IdentityHandle?
    private var signedPreKeyHandle: SignedPreKeyHandle?

    let relay = RelayService()

    // Persisted sessions keyed by remote user id
    @Published var sessions: [String: String] = [:] // remoteId -> session JSON

    // Contacts discovered
    @Published var contacts: [UserModel] = []

    var myIdentityKey: Data? {
        identityHandle?.publicKey
    }

    // MARK: - Setup

    func initializeIdentity() throws {
        // Try loading persisted identity
        if let json = UserDefaults.standard.string(forKey: "tintin_identity") {
            identityHandle = try IdentityHandle.fromJSON(json)
        } else {
            // Generate new identity and persist
            let handle = try IdentityHandle.generate()
            let json = try handle.toJSON()
            UserDefaults.standard.set(json, forKey: "tintin_identity")
            identityHandle = handle
        }

        // Load or generate signed pre-key
        if let json = UserDefaults.standard.string(forKey: "tintin_signed_prekey") {
            // For simplicity, re-generate each time; in production persist
        }
        signedPreKeyHandle = try SignedPreKeyHandle.generate(
            id: 1,
            identity: identityHandle!
        )
        // Persist signed pre-key (simplified: we'd store the full key material)
    }

    func getIdentityHandle() throws -> IdentityHandle {
        guard let handle = identityHandle else {
            throw RustCoreError.nullPointer("identity not initialised")
        }
        return handle
    }

    func getSignedPreKeyHandle() throws -> SignedPreKeyHandle {
        guard let handle = signedPreKeyHandle else {
            throw RustCoreError.nullPointer("signed pre-key not initialised")
        }
        return handle
    }

    func saveSessionJSON(_ json: String, for remoteId: String) {
        sessions[remoteId] = json
        UserDefaults.standard.set(sessions, forKey: "tintin_sessions")
    }

    func loadSessions() {
        if let saved = UserDefaults.standard.dictionary(forKey: "tintin_sessions") as? [String: String] {
            sessions = saved
        }
    }
}
