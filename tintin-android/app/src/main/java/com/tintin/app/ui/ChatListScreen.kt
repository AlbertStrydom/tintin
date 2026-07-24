package com.tintin.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import com.tintin.app.AppState
import com.tintin.app.RustBridge
import com.tintin.app.models.MessageModel
import com.tintin.app.models.UserModel
import com.tintin.app.services.EnvelopeResponse
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatListScreen(
    appState: AppState,
    onChatClick: (String) -> Unit,
) {
    var showNewChat by remember { mutableStateOf(false) }
    var newUserId by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    // Poll for incoming messages
    LaunchedEffect(Unit) {
        while (true) {
            delay(3000)
            val relay = appState.relay ?: continue
            val userId = appState.serverConfig.userId
            val result = relay.receive(userId)
            result.onSuccess { envelopes ->
                for (env in envelopes) {
                    handleIncoming(appState, env)
                }
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Chats") },
                actions = {
                    IconButton(onClick = { showNewChat = true }) {
                        Icon(Icons.Default.Add, contentDescription = "New chat")
                    }
                }
            )
        }
    ) { padding ->
        if (appState.sessionManager.contacts.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("No conversations yet", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize().padding(padding)) {
                items(appState.sessionManager.contacts.toList()) { contact ->
                    val msgs = appState.messages[contact.id]
                    val lastText = if (msgs.isNullOrEmpty()) "No messages yet" else msgs.last().text
                    ListItem(
                        headlineContent = { Text(contact.displayName) },
                        supportingContent = { Text(lastText, style = MaterialTheme.typography.bodySmall) },
                        leadingContent = {
                            Surface(shape = CircleShape, modifier = Modifier.size(44.dp)) {
                                Box(contentAlignment = Alignment.Center) {
                                    Text(
                                        contact.displayName.take(1).uppercase(),
                                        style = MaterialTheme.typography.titleMedium,
                                        color = MaterialTheme.colorScheme.onPrimary,
                                    )
                                }
                            }
                        },
                        modifier = Modifier.clickable { onChatClick(contact.id) },
                    )
                }
            }
        }
    }

    if (showNewChat) {
        AlertDialog(
            onDismissRequest = { showNewChat = false; newUserId = "" },
            title = { Text("New Chat") },
            text = {
                OutlinedTextField(
                    value = newUserId, onValueChange = { newUserId = it },
                    label = { Text("User ID") },
                    singleLine = true,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val uid = newUserId.trim()
                    if (uid.isNotEmpty()) {
                        scope.launch {
                            startChat(appState, uid)
                        }
                    }
                    showNewChat = false
                    newUserId = ""
                }) { Text("Start") }
            },
            dismissButton = { TextButton(onClick = { showNewChat = false; newUserId = "" }) { Text("Cancel") } },
        )
    }

    if (error != null) {
        LaunchedEffect(error) { delay(3000); error = null }
        Snackbar { Text(error!!) }
    }
}

private suspend fun startChat(appState: AppState, remoteId: String) {
    try {
        val relay = appState.relay ?: return
        val result = relay.fetchKeys(remoteId)
        result.onSuccess { bundle ->
            val identity = appState.sessionManager.identityHandle
            val sessionHandle = RustBridge.sessionNewInitiator(
                identity, remoteId, 1,
                bundle.identityKey, bundle.signedPreKey,
            )
            if (sessionHandle != 0L) {
                val json = RustBridge.sessionToJson(sessionHandle)
                appState.sessionManager.saveSession(json, remoteId)
                RustBridge.sessionFree(sessionHandle)
            }
            val contact = UserModel(id = remoteId, identityKey = bundle.identityKey)
            if (contact !in appState.sessionManager.contacts) {
                appState.sessionManager.contacts.add(contact)
            }
        }
        result.onFailure { e ->
            // error handled by caller
        }
    } catch (_: Exception) {}
}

private fun handleIncoming(appState: AppState, env: EnvelopeResponse) {
    val remoteId = env.senderId

    // Skip receipts — they're not encrypted.
    if (env.msgType == "Receipt") {
        try {
            val json = String(env.content)
            val obj = com.google.gson.JsonParser.parseString(json).asJsonObject
            val type = obj.get("receipt_type")?.asString ?: return
            val sender = obj.get("original_sender")?.asString ?: return
            android.util.Log.d("TinTin", "Receipt: $type from $sender")
        } catch (_: Exception) {}
        return
    }

    try {
        val pt = appState.sessionManager.decryptMessage(remoteId, env.content)
        if (pt != null) {
            val text = String(pt)
            val msg = MessageModel(
                senderId = remoteId, text = text,
                direction = com.tintin.app.models.MessageDirection.Incoming,
            )
            appState.messages.getOrPut(remoteId) { mutableListOf() }.add(msg)
            // Ensure contact exists
            if (appState.sessionManager.contacts.none { it.id == remoteId }) {
                appState.sessionManager.contacts.add(UserModel(id = remoteId, identityKey = byteArrayOf()))
            }
        }
    } catch (_: Exception) {}
}
