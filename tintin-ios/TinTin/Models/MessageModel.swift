import Foundation

/// The direction of a message in the conversation.
enum MessageDirection: String, Codable {
    case outgoing
    case incoming
}

/// Structured message type detected from __tintin_type payloads.
enum StructuredType: String, Codable {
    case group
    case channel
    case poll
    case sticker
    case callOffer = "call_offer"
    case callAccept = "call_accept"
    case callEnd = "call_end"
    case edit
    case file
    case voice
}

/// A single chat message displayed in the UI.
struct MessageModel: Identifiable, Codable, Equatable {
    let id: UUID
    let senderId: String
    var text: String
    let timestamp: Date
    let direction: MessageDirection

    // Structured message support
    var structuredType: StructuredType?
    var groupName: String?
    var channelName: String?
    var pollQuestion: String?
    var stickerEmoji: String?
    var fileName: String?
    var fileSize: Int64?
    var isEdited: Bool = false
    var voiceFileName: String?

    init(senderId: String, text: String, timestamp: Date, direction: MessageDirection,
         structuredType: StructuredType? = nil, groupName: String? = nil,
         channelName: String? = nil, pollQuestion: String? = nil,
         stickerEmoji: String? = nil, fileName: String? = nil,
         fileSize: Int64? = nil, isEdited: Bool = false,
         voiceFileName: String? = nil) {
        self.id = UUID()
        self.senderId = senderId
        self.text = text
        self.timestamp = timestamp
        self.direction = direction
        self.structuredType = structuredType
        self.groupName = groupName
        self.channelName = channelName
        self.pollQuestion = pollQuestion
        self.stickerEmoji = stickerEmoji
        self.fileName = fileName
        self.fileSize = fileSize
        self.isEdited = isEdited
        self.voiceFileName = voiceFileName
    }

    /// Parse a structured message payload and return an appropriate display string.
    static func parseStructuredPayload(_ payload: [String: Any], senderId: String) -> (text: String, type: StructuredType?, groupName: String?, channelName: String?, pollQuestion: String?, stickerEmoji: String?, voiceFileName: String?) {
        guard let tt = payload["__tintin_type"] as? String else {
            return (payload["text"] as? String ?? String(data: try? JSONSerialization.data(withJSONObject: payload), encoding: .utf8) ?? "", nil, nil, nil, nil, nil, nil)
        }

        switch tt {
        case "group":
            let gn = payload["group_name"] as? String ?? "Group"
            let t = payload["text"] as? String ?? ""
            return ("[\(gn)] \(t)", .group, gn, nil, nil, nil, nil)
        case "channel":
            let cn = payload["channel_name"] as? String ?? "Channel"
            let t = payload["text"] as? String ?? ""
            return ("📢 [\(cn)] \(t)", .channel, nil, cn, nil, nil, nil)
        case "poll":
            let q = payload["question"] as? String ?? "Poll"
            return ("📊 Poll: \(q)", .poll, nil, nil, q, nil, nil)
        case "sticker":
            let e = payload["emoji"] as? String ?? "🖼️"
            return ("\(e) Sticker", .sticker, nil, nil, nil, e, nil)
        case "call_offer", "call_accept", "call_end":
            let t = payload["reason"] as? String ?? "📞 Call signal"
            return ("📞 \(t)", tt == "call_offer" ? .callOffer : tt == "call_accept" ? .callAccept : .callEnd, nil, nil, nil, nil, nil)
        case "file":
            let fn = payload["file_name"] as? String ?? "File"
            return ("📁 File: \(fn)", .file, nil, nil, nil, nil, nil)
        case "voice":
            let fn = payload["file_name"] as? String ?? "Voice"
            return ("🎤 Voice: \(fn)", .voice, nil, nil, nil, nil, fn)
        default:
            return (payload["text"] as? String ?? "", nil, nil, nil, nil, nil, nil)
        }
    }
}
