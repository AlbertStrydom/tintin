package com.tintin.app.models

import java.util.Date
import java.util.UUID

enum class MessageDirection { Outgoing, Incoming }

data class MessageModel(
    val id: String = UUID.randomUUID().toString(),
    val senderId: String,
    val text: String,
    val timestamp: Date = Date(),
    val direction: MessageDirection,
)
