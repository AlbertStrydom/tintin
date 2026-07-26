package com.tintin.app.models

import java.util.Date
import java.util.UUID

enum class MessageDirection { Outgoing, Incoming }

enum class StructuredType {
    Group, Channel, Poll, Sticker, CallOffer, CallAccept, CallEnd, Edit, File, Voice
}

data class MessageModel(
    val id: String = UUID.randomUUID().toString(),
    val senderId: String,
    val text: String,
    val timestamp: Date = Date(),
    val direction: MessageDirection,
    // Structured message support
    val structuredType: StructuredType? = null,
    val groupName: String? = null,
    val channelName: String? = null,
    val pollQuestion: String? = null,
    val stickerEmoji: String? = null,
    val fileName: String? = null,
    val fileSize: Long? = null,
    val isEdited: Boolean = false,
    val voiceFileName: String? = null,
) {
    companion object {
        /** Parse a __tintin_type payload into display info. */
        fun parseStructuredPayload(payload: Map<String, Any>, senderId: String): ParseResult {
            val tt = payload["__tintin_type"] as? String ?: return ParseResult(
                text = payload["text"] as? String ?: payload.toString(), type = null
            )
            return when (tt) {
                "group" -> {
                    val gn = payload["group_name"] as? String ?: "Group"
                    val t = payload["text"] as? String ?: ""
                    ParseResult("[${gn}] $t", StructuredType.Group, groupName = gn)
                }
                "channel" -> {
                    val cn = payload["channel_name"] as? String ?: "Channel"
                    val t = payload["text"] as? String ?: ""
                    ParseResult("📢 [$cn] $t", StructuredType.Channel, channelName = cn)
                }
                "poll" -> {
                    val q = payload["question"] as? String ?: "Poll"
                    ParseResult("📊 Poll: $q", StructuredType.Poll, pollQuestion = q)
                }
                "sticker" -> {
                    val e = payload["emoji"] as? String ?: "🖼️"
                    ParseResult("$e Sticker", StructuredType.Sticker, stickerEmoji = e)
                }
                "call_offer" -> ParseResult("📞 Incoming call", StructuredType.CallOffer)
                "call_accept" -> ParseResult("📞 Call connected", StructuredType.CallAccept)
                "call_end" -> ParseResult("📞 Call ended", StructuredType.CallEnd)
                "file" -> {
                    val fn = payload["file_name"] as? String ?: "File"
                    ParseResult("📁 File: $fn", StructuredType.File, fileName = fn)
                }
                "voice" -> {
                    val fn = payload["file_name"] as? String ?: "Voice"
                    ParseResult("🎤 Voice: $fn", StructuredType.Voice, voiceFileName = fn)
                }
                else -> ParseResult(payload["text"] as? String ?: "", null)
            }
        }

        data class ParseResult(
            val text: String,
            val type: StructuredType?,
            val groupName: String? = null,
            val channelName: String? = null,
            val pollQuestion: String? = null,
            val stickerEmoji: String? = null,
            val fileName: String? = null,
            val voiceFileName: String? = null,
        )
    }
}
