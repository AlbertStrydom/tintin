import SwiftUI

/// Main conversation list: shows registered contacts and lets you start
/// or continue conversations.
struct ChatListView: View {
    @EnvironmentObject var appState: AppState
    @State private var showingNewChat = false
    @State private var newChatUserId = ""
    @State private var messages: [String: [MessageModel]] = [:]
    @State private var errorMessage: String?
    @State private var pollTimer: Timer?

    var body: some View {
        NavigationView {
            List {
                if appState.contacts.isEmpty {
                    Section {
                        Text("No conversations yet")
                            .foregroundColor(.secondary)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding()
                    }
                }

                ForEach(appState.contacts) { contact in
                    NavigationLink(
                        destination: ChatView(contact: contact, messages: binding(for: contact.id))
                    ) {
                        HStack {
                            Circle()
                                .fill(Color.blue)
                                .frame(width: 44, height: 44)
                                .overlay(
                                    Text(String(contact.displayName.prefix(1).uppercased()))
                                        .foregroundColor(.white)
                                        .fontWeight(.semibold)
                                )

                            VStack(alignment: .leading, spacing: 4) {
                                Text(contact.displayName)
                                    .fontWeight(.medium)
                                Text(lastMessage(for: contact.id))
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                    .lineLimit(1)
                            }
                            .padding(.leading, 8)
                        }
                        .padding(.vertical, 4)
                    }
                }
            }
            .navigationTitle("Chats")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showingNewChat = true }) {
                        Image(systemName: "plus.message")
                    }
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Disconnect") {
                        appState.relay.disconnect()
                        appState.isConnected = false
                        appState.isRegistered = false
                    }
                    .font(.caption)
                }
            }
            .alert("New Chat", isPresented: $showingNewChat) {
                TextField("User ID", text: $newChatUserId)
                Button("Start") { startChat(with: newChatUserId) }
                Button("Cancel", role: .cancel) { newChatUserId = "" }
            } message: {
                Text("Enter the user ID to start an encrypted conversation.")
            }
            .onAppear {
                startPolling()
            }
            .onDisappear {
                pollTimer?.invalidate()
            }
        }
    }

    /// Mutable binding to the message array for a contact.
    private func binding(for contactId: String) -> Binding<[MessageModel]> {
        Binding(
            get: { messages[contactId] ?? [] },
            set: { messages[contactId] = $0 }
        )
    }

    private func lastMessage(for contactId: String) -> String {
        messages[contactId]?.last.map { $0.text } ?? "No messages yet"
    }

    // ------------------------------------------------------------------
    // Start a new chat — fetch keys and create session
    // ------------------------------------------------------------------

    private func startChat(with userId: String) {
        guard !userId.isEmpty else { return }
        Task {
            do {
                // Fetch the user's key bundle from the server
                let (identityKey, spk) = try await appState.relay.fetchKeys(userId: userId)

                let identityBytes = Data(identityKey)
                let spkBytes = Data(spk.signed_pre_key)

                // Create initiator session (Alice starting with Bob)
                let identity = try appState.getIdentityHandle()
                let session = try SessionHandle.newInitiator(
                    identity: identity,
                    remoteUserId: userId,
                    deviceId: 1,
                    theirIdentity: identityBytes,
                    signedPrekeyPublic: spkBytes
                )

                // Persist session
                let sessionJSON = try session.toJSON()
                appState.saveSessionJSON(sessionJSON, for: userId)

                // Add to contacts if not already present
                let contact = UserModel(
                    id: userId,
                    identityKey: identityBytes,
                    displayName: userId
                )
                if !appState.contacts.contains(contact) {
                    await MainActor.run {
                        appState.contacts.append(contact)
                    }
                }

                await MainActor.run {
                    newChatUserId = ""
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Poll for incoming messages (simplified polling)
    // ------------------------------------------------------------------

    private func startPolling() {
        pollTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { _ in
            Task {
                await pollIncoming()
            }
        }
    }

    private func pollIncoming() async {
        do {
            let envelopes = try await appState.relay.receive(userId: appState.userId)
            for env in envelopes {
                let senderId = env.sender_id
                let contentData = Data(env.content)

                // Skip receipts — they're not encrypted.
                if env.msg_type == "Receipt" {
                    if let receipt = try? JSONDecoder().decode(
                        ReceiptContentValue.self, from: contentData
                    ) {
                        print("Receipt: \(receipt.receipt_type) from \(senderId)")
                    }
                    continue
                }

                // Load the session for this sender (as responder)
                if let sessionJSON = appState.sessions[senderId] {
                    let session = try SessionHandle.fromJSON(sessionJSON)
                    let plaintext = try session.decrypt(contentData)
                    let updatedJSON = try session.toJSON()
                    appState.saveSessionJSON(updatedJSON, for: senderId)

                    if let text = String(data: plaintext, encoding: .utf8) {
                        // Check for structured payload
                        if let payloadData = text.data(using: .utf8),
                           let payload = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
                           payload["__tintin_type"] != nil {
                            let parsed = MessageModel.parseStructuredPayload(payload, senderId: senderId)
                            let msg = MessageModel(
                                senderId: senderId,
                                text: parsed.text,
                                timestamp: Date(),
                                direction: .incoming,
                                structuredType: parsed.type,
                                groupName: parsed.groupName,
                                channelName: parsed.channelName,
                                pollQuestion: parsed.pollQuestion,
                                stickerEmoji: parsed.stickerEmoji
                            )
                            await MainActor.run {
                                if !appState.contacts.contains(where: { $0.id == senderId }) {
                                    appState.contacts.append(
                                        UserModel(id: senderId, identityKey: Data(), displayName: senderId)
                                    )
                                }
                                var msgs = messages[senderId] ?? []
                                msgs.append(msg)
                                messages[senderId] = msgs
                            }
                        } else {
                            let msg = MessageModel(
                                senderId: senderId,
                                text: text,
                                timestamp: Date(),
                                direction: .incoming
                            )
                            await MainActor.run {
                                if !appState.contacts.contains(where: { $0.id == senderId }) {
                                    appState.contacts.append(
                                        UserModel(id: senderId, identityKey: Data(), displayName: senderId)
                                    )
                                }
                                var msgs = messages[senderId] ?? []
                                msgs.append(msg)
                                messages[senderId] = msgs
                            }
                        }
                    }
                } else {
                    // First message from this sender — need to establish session
                    // For Phase 2, this is simplified; full X3DH handling comes later
                    print("Received message from unknown session: \(senderId)")
                }
            }
        } catch {
            // Silently handle polling errors (server may have no messages)
        }
    }
}

#Preview {
    ChatListView()
        .environmentObject(AppState())
}
