package com.tintin.app.services

import com.google.gson.Gson
import com.google.gson.JsonParser
import com.tintin.app.models.UserModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * TCP relay client for the TinTin server.
 * Uses blocking I/O on a background thread (Dispatchers.IO).
 */
class RelayService(private val host: String, private val port: Int) {
    private var socket: Socket? = null
    private var writer: OutputStreamWriter? = null
    private var reader: BufferedReader? = null
    private val gson = Gson()

    /** Connect to the relay server. */
    suspend fun connect(): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val sock = Socket(host, port)
            sock.soTimeout = 10_000
            socket = sock
            writer = OutputStreamWriter(sock.getOutputStream())
            reader = BufferedReader(InputStreamReader(sock.getInputStream()))
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun disconnect() {
        try { socket?.close() } catch (_: Exception) {}
        socket = null
        writer = null
        reader = null
    }

    val isConnected: Boolean get() = socket?.isConnected == true && !socket!!.isClosed

    /** Register a user with their public keys. */
    suspend fun register(
        userId: String,
        identityKey: List<Int>,
        signedPreKeyId: Int,
        signedPreKey: List<Int>,
        signedPreKeySignature: List<Int>,
    ): Result<Unit> = sendCommand {
        val bundle = mapOf(
            "identity_key" to identityKey,
            "device_id" to 1,
            "signed_pre_key_id" to signedPreKeyId,
            "signed_pre_key" to signedPreKey,
            "signed_pre_key_signature" to signedPreKeySignature,
            "one_time_pre_key_id" to null,
            "one_time_pre_key" to null,
        )
        mapOf(
            "cmd" to "register",
            "user_id" to userId,
            "identity_key" to identityKey,
            "signed_pre_key" to bundle,
        )
    }

    /** Fetch another user's key bundle. */
    suspend fun fetchKeys(userId: String): Result<KeyBundleResponse> = withContext(Dispatchers.IO) {
        try {
            val resp = sendJsonGet(mapOf("cmd" to "fetch_keys", "user_id" to userId))
            val obj = JsonParser.parseString(resp).asJsonObject
            if (obj.get("status")?.asString != "ok") {
                return@withContext Result.failure(Exception(obj.get("error")?.asString ?: "fetch_keys failed"))
            }
            val data = obj.getAsJsonObject("data")
            val identityKey = data.getAsJsonArray("identity_key").map { it.asInt.toByte() }.toByteArray()
            val spkObj = data.getAsJsonObject("signed_pre_key")
            val bundle = KeyBundleResponse(
                identityKey = identityKey,
                signedPreKeyId = spkObj.get("signed_pre_key_id").asInt,
                signedPreKey = spkObj.getAsJsonArray("signed_pre_key").map { it.asInt.toByte() }.toByteArray(),
                signedPreKeySignature = spkObj.getAsJsonArray("signed_pre_key_signature").map { it.asInt.toByte() }.toByteArray(),
            )
            Result.success(bundle)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /** Send an encrypted envelope. */
    suspend fun send(envelope: Map<String, Any>): Result<Unit> = sendCommand {
        mapOf("cmd" to "send", "envelope" to envelope)
    }

    /** Receive pending messages for a user. */
    suspend fun receive(userId: String): Result<List<EnvelopeResponse>> = withContext(Dispatchers.IO) {
        try {
            val resp = sendJsonGet(mapOf("cmd" to "receive", "user_id" to userId))
            val obj = JsonParser.parseString(resp).asJsonObject
            if (obj.get("status")?.asString != "ok") {
                return@withContext Result.failure(Exception(obj.get("error")?.asString ?: "receive failed"))
            }
            val msgs = obj.getAsJsonObject("data")?.getAsJsonArray("messages") ?: return@withContext Result.success(emptyList())
            val list = msgs.map { msg ->
                val m = msg.asJsonObject
                EnvelopeResponse(
                    senderId = m.get("sender_id").asString,
                    recipientId = m.get("recipient_id").asString,
                    senderDeviceId = m.get("sender_device_id").asInt,
                    timestamp = m.get("timestamp").asLong,
                    content = m.getAsJsonArray("content").map { it.asInt.toByte() }.toByteArray(),
                    msgType = m.get("msg_type").asString,
                )
            }
            Result.success(list)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    private fun sendCommand(body: () -> Map<String, Any>): Result<Unit> = try {
        val json = gson.toJson(body())
        sendJson(json)
        val response = reader?.readLine() ?: return Result.failure(Exception("No response"))
        val obj = JsonParser.parseString(response).asJsonObject
        if (obj.get("status")?.asString == "ok") Result.success(Unit)
        else Result.failure(Exception(obj.get("error")?.asString ?: "command failed"))
    } catch (e: Exception) {
        Result.failure(e)
    }

    @Synchronized
    private fun sendJson(json: String) {
        writer?.write("$json\n")
        writer?.flush()
    }

    private fun sendJsonGet(json: String): String {
        sendJson(json)
        return reader?.readLine() ?: throw Exception("No response from server")
    }

    private fun sendJsonGet(body: Map<String, String>): String {
        val json = gson.toJson(body)
        return sendJsonGet(json)
    }
}

data class KeyBundleResponse(
    val identityKey: ByteArray,
    val signedPreKeyId: Int,
    val signedPreKey: ByteArray,
    val signedPreKeySignature: ByteArray,
)

data class EnvelopeResponse(
    val senderId: String,
    val recipientId: String,
    val senderDeviceId: Int,
    val timestamp: Long,
    val content: ByteArray,
    val msgType: String,
)
