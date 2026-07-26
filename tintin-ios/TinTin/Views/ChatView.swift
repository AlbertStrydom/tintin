import SwiftUI

/// The actual conversation view — shows messages and a text input.
struct ChatView: View {
    let contact: UserModel
    @Binding var messages: [MessageModel]
    @EnvironmentObject var appState: AppState
    @State private var textInput = ""
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            // Message list
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(messages) { msg in
                            MessageBubble(message: msg)
                                .id(msg.id)
                        }
                    }
                    .padding(.horizontal)
                    .padding(.vertical, 8)
                }
                .onChange(of: messages.count) { _ in
                    if let last = messages.last {
                        withAnimation {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }

            // Error
            if let error = errorMessage {
                Text(error)
                    .foregroundColor(.red)
                    .font(.caption)
                    .padding(.horizontal)
            }

            // Input bar
            HStack(spacing: 8) {
                TextField("Message", text: $textInput)
                    .textFieldStyle(.roundedBorder)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                Button(action: sendMessage) {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.title2)
                }
                .disabled(textInput.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding()
            .background(Color(.systemGroupedBackground))
        }
        .navigationTitle(contact.displayName)
        .navigationBarTitleDisplayMode(.inline)
    }

    // ------------------------------------------------------------------
    // Send
    // ------------------------------------------------------------------

    private func sendMessage() {
        let text = textInput.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        textInput = ""

        Task {
            do {
                // Load or create session
                let session: SessionHandle
                if let json = appState.sessions[contact.id] {
                    session = try SessionHandle.fromJSON(json)
                } else {
                    // First message — fetch keys and create session
                    let (identityKey, spk) = try await appState.relay.fetchKeys(userId: contact.id)
                    let identity = try appState.getIdentityHandle()
                    session = try SessionHandle.newInitiator(
                        identity: identity,
                        remoteUserId: contact.id,
                        deviceId: 1,
                        theirIdentity: Data(identityKey),
                        signedPrekeyPublic: Data(spk.signed_pre_key)
                    )
                }

                // Encrypt
                let plaintext = Data(text.utf8)
                let ciphertext = try session.encrypt(plaintext)

                // Persist updated session
                let updatedJSON = try session.toJSON()
                appState.saveSessionJSON(updatedJSON, for: contact.id)

                // Send via relay
                let identity = try appState.getIdentityHandle()
                let envelope: [String: Any] = [
                    "envelope": [
                        "sender_id": appState.userId,
                        "recipient_id": contact.id,
                        "sender_device_id": 1,
                        "timestamp": UInt64(Date().timeIntervalSince1970 * 1000),
                        "content": [UInt8](ciphertext),
                        "msg_type": "Normal",
                    ] as [String: Any]
                ]
                try await appState.relay.send(envelope: envelope)

                // Add to local messages
                let msg = MessageModel(
                    senderId: appState.userId,
                    text: text,
                    timestamp: Date(),
                    direction: .outgoing
                )
                await MainActor.run {
                    messages.append(msg)
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                }
            }
        }
    }
}

// MARK: - Message Bubble

struct MessageBubble: View {
    let message: MessageModel

    var body: some View {
        HStack {
            if message.direction == .outgoing {
                Spacer(minLength: 60)
            }

            // Choose display style based on message type
            Group {
                if let emoji = message.stickerEmoji {
                    // Sticker — show large emoji
                    Text(emoji)
                        .font(.system(size: 48))
                } else if let _ = message.structuredType {
                    // Structured message — use styled text
                    VStack(alignment: .leading, spacing: 4) {
                        Text(message.text)
                            .font(message.structuredType == .sticker ? .title : .body)
                        if message.isEdited {
                            Text("(edited)")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(12)
                    .background(message.direction == .outgoing ? Color.blue : Color(.systemGray5))
                    .foregroundColor(message.direction == .outgoing ? .white : .primary)
                    .cornerRadius(16)
                } else {
                    // Regular text message
                    VStack(alignment: .leading, spacing: 2) {
                        Text(message.text)
                        if message.isEdited {
                            Text("(edited)")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(12)
                    .background(message.direction == .outgoing ? Color.blue : Color(.systemGray5))
                    .foregroundColor(message.direction == .outgoing ? .white : .primary)
                    .cornerRadius(16)
                }
            }

            if message.direction == .incoming {
                Spacer(minLength: 60)
            }
        }
    }
}

#Preview {
    NavigationView {
        ChatView(
            contact: UserModel(id: "bob", identityKey: Data(), displayName: "Bob"),
            messages: .constant([
                MessageModel(senderId: "bob", text: "Hey!", timestamp: Date(), direction: .incoming),
                MessageModel(senderId: "alice", text: "Hi Bob!", timestamp: Date(), direction: .outgoing),
            ])
        )
        .environmentObject(AppState())
    }
}
