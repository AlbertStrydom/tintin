import Foundation

/// The direction of a message in the conversation.
enum MessageDirection: String, Codable {
    case outgoing
    case incoming
}

/// A single chat message displayed in the UI.
struct MessageModel: Identifiable, Codable, Equatable {
    let id: UUID
    let senderId: String
    let text: String
    let timestamp: Date
    let direction: MessageDirection

    init(senderId: String, text: String, timestamp: Date, direction: MessageDirection) {
        self.id = UUID()
        self.senderId = senderId
        self.text = text
        self.timestamp = timestamp
        self.direction = direction
    }
}
