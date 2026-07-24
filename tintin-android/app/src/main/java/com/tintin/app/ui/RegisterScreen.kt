package com.tintin.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tintin.app.AppState
import com.tintin.app.RustBridge
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RegisterScreen(
    appState: AppState,
    onRegistered: () -> Unit,
) {
    var registering by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    Scaffold(topBar = { TopAppBar(title = { Text("Register") }) }) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(64.dp))

            Icon(Icons.Default.Shield, contentDescription = null, modifier = Modifier.size(72.dp),
                tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(16.dp))

            Text("Identity Created", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(8.dp))

            Text(
                "Your identity key pair has been generated. " +
                        "Now register with the relay server.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(24.dp))

            if (error != null) {
                Text(error!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(12.dp))
            }

            Button(
                onClick = {
                    registering = true
                    error = null
                    scope.launch {
                        try {
                            val relay = appState.relay ?: return@launch
                            val userId = appState.serverConfig.userId
                            val ik = RustBridge.identityGetPublic(appState.sessionManager.identityHandle)
                            val spk = RustBridge.signedPrekeyGetPublic(appState.sessionManager.signedPreKeyHandle)

                            val result = relay.register(
                                userId = userId,
                                identityKey = ik.toList().map { it.toInt() and 0xFF },
                                signedPreKeyId = 1,
                                signedPreKey = spk.toList().map { it.toInt() and 0xFF },
                                signedPreKeySignature = emptyList(),
                            )
                            if (result.isSuccess) {
                                onRegistered()
                            } else {
                                error = result.exceptionOrNull()?.message ?: "Registration failed"
                                registering = false
                            }
                        } catch (e: Exception) {
                            error = e.message
                            registering = false
                        }
                    }
                },
                enabled = !registering,
                modifier = Modifier.fillMaxWidth().height(48.dp),
            ) {
                if (registering) CircularProgressIndicator(modifier = Modifier.size(20.dp), color = MaterialTheme.colorScheme.onPrimary)
                else Text("Register with Server")
            }
        }
    }
}
