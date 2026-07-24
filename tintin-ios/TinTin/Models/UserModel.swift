import Foundation

/// Represents a contact in the user's address book.
struct UserModel: Identifiable, Codable, Equatable {
    let id: String            // user id (phone number / handle)
    let identityKey: Data     // 32-byte public identity key
    let deviceId: UInt32

    /// Display name (falls back to id if no friendly name)
    var displayName: String

    init(id: String, identityKey: Data, deviceId: UInt32 = 1, displayName: String? = nil) {
        self.id = id
        self.identityKey = identityKey
        self.deviceId = deviceId
        self.displayName = displayName ?? id
    }
}
