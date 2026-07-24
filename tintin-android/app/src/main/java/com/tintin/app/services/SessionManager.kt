package com.tintin.app.services

import android.content.Context
import android.content.SharedPreferences
import com.tintin.app.RustBridge
import com.tintin.app.models.MessageDirection
import com.tintin.app.models.MessageModel
import com.tintin.app.models.UserModel
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.util.Date

/**
 * Manages the Rust crypto handles and session persistence for the Android app.
 * Mirrors the iOS AppState pattern.
 */
class SessionManager(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("tintin_sessions", Context.MODE_PRIVATE)
    private val gson = Gson()

    /** Our identity handle (loaded or generated). */
    var identityHandle: Long = 0
        private set

    /** Our signed pre-key handle. */
    var signedPreKeyHandle: Long = 0
        private set

    /** Cached session JSON strings, keyed by remote user id. */
    private val sessionCache = mutableMapOf<String, String>()

    /** Contacts discovered. */
    val contacts = mutableListOf<UserModel>()

    val myIdentityKey: ByteArray?
        get() = if (identityHandle != 0L) RustBridge.identityGetPublic(identityHandle) else null

    // ------------------------------------------------------------------
    // Initialisation
    // ------------------------------------------------------------------

    /** Load or generate identity and signed pre-key. */
    fun initialize() {
        // Load persisted identity
        val savedIdentity = prefs.getString("identity_json", null)
        identityHandle = if (savedIdentity != null) {
            RustBridge.identityFromJson(savedIdentity)
        } else {
            val h = RustBridge.identityGenerate()
            val json = RustBridge.identityToJson(h)
            prefs.edit().putString("identity_json", json).apply()
            h
        }

        // Always generate a fresh signed pre-key for now
        signedPreKeyHandle = RustBridge.signedPrekeyGenerate(1, identityHandle)

        // Load session cache
        val saved = prefs.getString("sessions_json", null)
        if (saved != null) {
            val type = object : TypeToken<Map<String, String>>() {}.type
            val map: Map<String, String> = gson.fromJson(saved, type)
            sessionCache.putAll(map)
        }
    }

    /** Clean up Rust handles. */
    fun destroy() {
        if (identityHandle != 0L) RustBridge.identityFree(identityHandle)
        if (signedPreKeyHandle != 0L) RustBridge.signedPrekeyFree(signedPreKeyHandle)
        sessionCache.keys.forEach { key ->
            val json = sessionCache[key] ?: return@forEach
            val h = RustBridge.sessionFromJson(json)
            if (h != 0L) RustBridge.sessionFree(h)
        }
    }

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------

    /** Save a session JSON for a remote user. */
    fun saveSession(json: String, remoteId: String) {
        sessionCache[remoteId] = json
        persistSessions()
    }

    /** Get the session JSON for a remote user, if any. */
    fun getSessionJson(remoteId: String): String? = sessionCache[remoteId]

    private fun persistSessions() {
        prefs.edit().putString("sessions_json", gson.toJson(sessionCache)).apply()
    }

    // ------------------------------------------------------------------
    // Messaging helpers
    // ------------------------------------------------------------------

    /** Encrypt and send, returning the ciphertext bytes. */
    fun encryptMessage(remoteId: String, plaintext: ByteArray): ByteArray? {
        var sessionHandle = 0L
        val sessionJson = sessionCache[remoteId]

        try {
            if (sessionJson != null) {
                sessionHandle = RustBridge.sessionFromJson(sessionJson)
            }
            // sessionHandle remains 0 if no session — caller should create one first
            if (sessionHandle == 0L) return null

            val ct = RustBridge.sessionEncrypt(sessionHandle, plaintext)
            val updatedJson = RustBridge.sessionToJson(sessionHandle)
            saveSession(updatedJson, remoteId)
            return ct
        } finally {
            if (sessionHandle != 0L) RustBridge.sessionFree(sessionHandle)
        }
    }

    /** Decrypt a message, returning plaintext bytes. */
    fun decryptMessage(remoteId: String, ciphertext: ByteArray): ByteArray? {
        val sessionJson = sessionCache[remoteId] ?: return null
        val sessionHandle = RustBridge.sessionFromJson(sessionJson)
        if (sessionHandle == 0L) return null

        try {
            val pt = RustBridge.sessionDecrypt(sessionHandle, ciphertext)
            val updatedJson = RustBridge.sessionToJson(sessionHandle)
            saveSession(updatedJson, remoteId)
            return pt
        } finally {
            RustBridge.sessionFree(sessionHandle)
        }
    }
}
