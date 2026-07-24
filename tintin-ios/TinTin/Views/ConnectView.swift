import SwiftUI

/// First screen: connect to a relay server.
struct ConnectView: View {
    @EnvironmentObject var appState: AppState
    @State private var host = "127.0.0.1"
    @State private var portText = "9666"
    @State private var userId = ""
    @State private var isConnecting = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationView {
            Form {
                Section("Server") {
                    TextField("Host", text: $host)
                        .textContentType(.URL)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)

                    TextField("Port", text: $portText)
                        .keyboardType(.numberPad)
                }

                Section("Your ID") {
                    TextField("User ID (e.g. alice)", text: $userId)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                }

                if let error = errorMessage {
                    Section {
                        Text(error)
                            .foregroundColor(.red)
                            .font(.caption)
                    }
                }

                Section {
                    Button(action: connect) {
                        HStack {
                            Spacer()
                            if isConnecting {
                                ProgressView()
                            } else {
                                Text("Connect")
                                    .fontWeight(.semibold)
                            }
                            Spacer()
                        }
                    }
                    .disabled(isConnecting || host.isEmpty || userId.isEmpty)
                }
            }
            .navigationTitle("TinTin")
        }
    }

    private func connect() {
        guard let port = UInt16(portText) else {
            errorMessage = "Invalid port number"
            return
        }
        isConnecting = true
        errorMessage = nil

        Task {
            do {
                appState.serverHost = host
                appState.serverPort = port
                appState.userId = userId

                try appState.initializeIdentity()
                try await appState.relay.connect(host: host, port: port)

                await MainActor.run {
                    appState.isConnected = true
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    isConnecting = false
                }
            }
        }
    }
}

#Preview {
    ConnectView()
        .environmentObject(AppState())
}
