package com.tintin.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tintin.app.AppState
import com.tintin.app.services.RelayService
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectScreen(
    appState: AppState,
    onConnected: () -> Unit,
) {
    var host by remember { mutableStateOf("127.0.0.1") }
    var portText by remember { mutableStateOf("9666") }
    var userId by remember { mutableStateOf("") }
    var connecting by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    Scaffold(topBar = { TopAppBar(title = { Text("TinTin") }) }) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(48.dp))

            OutlinedTextField(
                value = host, onValueChange = { host = it },
                label = { Text("Host") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = portText, onValueChange = { portText = it },
                label = { Text("Port") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = userId, onValueChange = { userId = it },
                label = { Text("User ID (e.g. alice)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(24.dp))

            if (error != null) {
                Text(error!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(12.dp))
            }

            Button(
                onClick = {
                    val port = portText.toIntOrNull() ?: return@Button
                    connecting = true
                    error = null
                    appState.serverConfig = appState.serverConfig.copy(host = host, port = port, userId = userId)
                    scope.launch {
                        val relay = RelayService(host, port)
                        val result = relay.connect()
                        if (result.isSuccess) {
                            appState.relay = relay
                            onConnected()
                        } else {
                            error = result.exceptionOrNull()?.message ?: "Connection failed"
                            connecting = false
                        }
                    }
                },
                enabled = !connecting && host.isNotBlank() && userId.isNotBlank(),
                modifier = Modifier.fillMaxWidth().height(48.dp),
            ) {
                if (connecting) CircularProgressIndicator(modifier = Modifier.size(20.dp), color = MaterialTheme.colorScheme.onPrimary)
                else Text("Connect")
            }
        }
    }
}
