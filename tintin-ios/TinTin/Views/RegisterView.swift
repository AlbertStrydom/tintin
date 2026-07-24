import SwiftUI

/// Second screen: register with the relay server.
struct RegisterView: View {
    @EnvironmentObject var appState: AppState
    @State private var isRegistering = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                Spacer()

                Image(systemName: "shield.checkered")
                    .font(.system(size: 64))
                    .foregroundColor(.green)

                Text("Identity Created")
                    .font(.title)
                    .fontWeight(.bold)

                Text("Your identity key pair has been generated.\n"
                     + "Now register with the relay server to\n"
                     + "start messaging.")
                    .multilineTextAlignment(.center)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)

                if let error = errorMessage {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.caption)
                }

                Button(action: register) {
                    HStack {
                        Spacer()
                        if isRegistering {
                            ProgressView()
                        } else {
                            Text("Register with Server")
                                .fontWeight(.semibold)
                        }
                        Spacer()
                    }
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(12)
                }
                .disabled(isRegistering)
                .padding(.horizontal, 40)

                Spacer()
            }
            .navigationTitle("Register")
        }
    }

    private func register() {
        isRegistering = true
        errorMessage = nil

        Task {
            do {
                let identity = try appState.getIdentityHandle()
                let spk = try appState.getSignedPreKeyHandle()

                let identityKeyBytes = [UInt8](identity.publicKey)
                let spkBytes = [UInt8](spk.publicKey)

                try await appState.relay.register(
                    userId: appState.userId,
                    identityKey: identityKeyBytes,
                    signedPreKeyId: spk.id,
                    signedPreKey: spkBytes,
                    signedPreKeySignature: [] // simplified for Phase 2
                )

                await MainActor.run {
                    appState.isRegistered = true
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    isRegistering = false
                }
            }
        }
    }
}

#Preview {
    RegisterView()
        .environmentObject(AppState())
}
