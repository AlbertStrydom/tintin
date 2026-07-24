package com.tintin.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.tintin.app.models.MessageModel
import com.tintin.app.models.ServerConfig
import com.tintin.app.models.UserModel
import com.tintin.app.services.RelayService
import com.tintin.app.services.SessionManager
import com.tintin.app.ui.theme.TinTinTheme
import com.tintin.app.ui.*

/** Global app state held at the activity level. */
class AppState(context: android.content.Context) {
    val sessionManager = SessionManager(context)
    var relay: RelayService? = null
    var serverConfig by mutableStateOf(ServerConfig())

    // Messages keyed by remote user id
    val messages = mutableStateMapOf<String, MutableList<MessageModel>>()

    init { sessionManager.initialize() }
    fun destroy() { sessionManager.destroy() }
}

class MainActivity : ComponentActivity() {
    private lateinit var appState: AppState

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        appState = AppState(applicationContext)

        setContent {
            TinTinTheme {
                TinTinNavigation(appState)
            }
        }
    }

    override fun onDestroy() {
        appState.destroy()
        super.onDestroy()
    }
}

@Composable
fun TinTinNavigation(appState: AppState) {
    val navController = rememberNavController()

    NavHost(navController = navController, startDestination = "connect") {
        composable("connect") {
            ConnectScreen(
                appState = appState,
                onConnected = { navController.navigate("register") }
            )
        }
        composable("register") {
            RegisterScreen(
                appState = appState,
                onRegistered = { navController.navigate("chat_list") }
            )
        }
        composable("chat_list") {
            ChatListScreen(
                appState = appState,
                onChatClick = { userId -> navController.navigate("chat/$userId") }
            )
        }
        composable("chat/{userId}") { backStackEntry ->
            val userId = backStackEntry.arguments?.getString("userId") ?: return@composable
            ChatScreen(
                appState = appState,
                contactId = userId,
            )
        }
    }
}
