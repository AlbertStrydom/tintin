package com.tintin.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.tintin.app.AppState
import com.tintin.app.RustBridge
import com.tintin.app.models.MessageDirection
import com.tintin.app.models.MessageModel
import kotlinx.coroutines.launch
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    appState: AppState,
    contactId: String,
) {
    var textInput by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()
    val messages = appState.messages.getOrPut(contactId) { mutableListOf() }

    Scaffold(
        topBar = { TopAppBar(title = { Text(contactId) }) },
        bottomBar = {
            Surface(tonalElevation = 2.dp) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedTextField(
                        value = textInput, onValueChange = { textInput = it },
                        placeholder = { Text("Message") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(Modifier.width(8.dp))
                    IconButton(onClick = {
                        val text = textInput.trim()
                        if (text.isEmpty()) return@IconButton
                        textInput = ""
                        scope.launch {
                            sendMessage(appState, contactId, text) { err ->
                                error = err
                            }
                        }
                    }) {
                        Icon(Icons.Default.Send, contentDescription = "Send")
                    }
                }
            }
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 12.dp),
            state = listState,
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            items(messages) { msg ->
                MessageBubble(msg)
            }
        }
    }

    if (error != null) {
        LaunchedEffect(error) { kotlinx.coroutines.delay(3000); error = null }
        Snackbar { Text(error!!) }
    }

    // Auto-scroll to bottom
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }
}

@Composable
fun MessageBubble(message: MessageModel) {
    val isOutgoing = message.direction == MessageDirection.Outgoing
    val bgColor = if (isOutgoing) Color(0xFF1A73E8) else MaterialTheme.colorScheme.surfaceVariant
    val textColor = if (isOutgoing) Color.White else MaterialTheme.colorScheme.onSurface
    val shape = RoundedCornerShape(16.dp)

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = if (isOutgoing) Arrangement.End else Arrangement.Start,
    ) {
        if (message.stickerEmoji != null) {
            // Sticker: show large emoji
            Text(
                text = message.stickerEmoji!!,
                fontSize = MaterialTheme.typography.displaySmall.fontSize,
                modifier = Modifier.padding(4.dp),
            )
        } else {
            Column(modifier = Modifier
                .padding(vertical = 2.dp)
                .clip(shape)
                .background(bgColor)
                .padding(horizontal = 14.dp, vertical = 10.dp)
            ) {
                Text(text = message.text, color = textColor)
                if (message.isEdited) {
                    Text(
                        text = "(edited)",
                        color = if (isOutgoing) Color.White.copy(alpha = 0.7f)
                                else Color.Gray,
                        fontSize = MaterialTheme.typography.labelSmall.fontSize,
                    )
                }
            }
        }
    }
}

private suspend fun sendMessage(
    appState: AppState,
    remoteId: String,
    text: String,
    onError: (String) -> Unit,
) {
    try {
        val relay = appState.relay ?: return

        // Ensure session exists
        var sessionJson = appState.sessionManager.getSessionJson(remoteId)
        if (sessionJson == null) {
            // First message — fetch keys and create session
            val fetchResult = relay.fetchKeys(remoteId)
            fetchResult.onSuccess { bundle ->
                val identity = appState.sessionManager.identityHandle
                val sessionHandle = RustBridge.sessionNewInitiator(
                    identity, remoteId, 1,
                    bundle.identityKey, bundle.signedPreKey,
                )
                if (sessionHandle != 0L) {
                    sessionJson = RustBridge.sessionToJson(sessionHandle)
                    appState.sessionManager.saveSession(sessionJson, remoteId)
                    RustBridge.sessionFree(sessionHandle)
                }
            }
            fetchResult.onFailure { e ->
                onError(e.message ?: "Failed to start chat")
                return
            }
        }

        // Encrypt and send
        val plaintext = text.toByteArray()
        val ct = appState.sessionManager.encryptMessage(remoteId, plaintext)
        if (ct == null) {
            onError("Encryption failed")
            return
        }

        val envelope = mapOf<String, Any>(
            "sender_id" to appState.serverConfig.userId,
            "recipient_id" to remoteId,
            "sender_device_id" to 1,
            "timestamp" to (System.currentTimeMillis()),
            "content" to ct.toList().map { it.toInt() and 0xFF },
            "msg_type" to "Normal",
        )
        val sendResult = relay.send(envelope)
        sendResult.onSuccess {
            val msg = MessageModel(
                senderId = appState.serverConfig.userId,
                text = text,
                direction = MessageDirection.Outgoing,
            )
            appState.messages.getOrPut(remoteId) { mutableListOf() }.add(msg)
        }
        sendResult.onFailure { e ->
            onError(e.message ?: "Send failed")
        }
    } catch (e: Exception) {
        onError(e.message ?: "Unknown error")
    }
}
