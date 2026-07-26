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
    // Contact Discovery
    // ------------------------------------------------------------------

    suspend fun listUsers(query: String? = null): Result<List<String>> = withContext(Dispatchers.IO) {
        try {
            val m = mutableMapOf<String, Any>("cmd" to "list_users")
            query?.let { m["query"] = it }
            val resp = sendJsonGet(m as Map<String, Any>)
            val obj = JsonParser.parseString(resp).asJsonObject
            if (obj.get("status")?.asString != "ok") {
                return@withContext Result.failure(Exception(obj.get("error")?.asString))
            }
            val users = obj.getAsJsonObject("data")?.getAsJsonArray("users")
                ?.map { it.asString } ?: emptyList()
            Result.success(users)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // ------------------------------------------------------------------
    // Groups
    // ------------------------------------------------------------------

    suspend fun createGroup(name: String, creator: String): Result<String> = withContext(Dispatchers.IO) {
        try {
            val resp = sendJsonGet(mapOf("cmd" to "create_group", "name" to name, "creator" to creator))
            val obj = JsonParser.parseString(resp).asJsonObject
            if (obj.get("status")?.asString != "ok") {
                return@withContext Result.failure(Exception(obj.get("error")?.asString))
            }
            val gid = obj.getAsJsonObject("data")?.get("group_id")?.asString ?: ""
            Result.success(gid)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun joinGroup(groupId: String, userId: String): Result<Unit> = sendCommand {
        mapOf("cmd" to "join_group", "group_id" to groupId, "user_id" to userId)
    }

    suspend fun leaveGroup(groupId: String, userId: String): Result<Unit> = sendCommand {
        mapOf("cmd" to "leave_group", "group_id" to groupId, "user_id" to userId)
    }

    // ------------------------------------------------------------------
    // Polls
    // ------------------------------------------------------------------

    suspend fun createPoll(creator: String, question: String, options: List<String>): Result<Long> = withContext(Dispatchers.IO) {
        try {
            val resp = sendJsonGet(mapOf("cmd" to "create_poll", "creator" to creator, "question" to question, "options" to options))
            val obj = JsonParser.parseString(resp).asJsonObject
            if (obj.get("status")?.asString != "ok") {
                return@withContext Result.failure(Exception(obj.get("error")?.asString))
            }
            Result.success(obj.getAsJsonObject("data")?.get("poll_id")?.asLong ?: 0)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun votePoll(pollId: Long, userId: String, optionId: Long): Result<Unit> = sendCommand {
        mapOf("cmd" to "vote_poll", "poll_id" to pollId, "user_id" to userId, "option_id" to optionId)
    }

    // ------------------------------------------------------------------
    // Timeline / Moments
    // ------------------------------------------------------------------

    suspend fun createPost(userId: String, content: String, targetUserId: String? = null): Result<Long> = withContext(Dispatchers.IO) {
        try {
            val m = mutableMapOf<String, Any>("cmd" to "create_post", "user_id" to userId, "content" to content)
            targetUserId?.let { m["target_user_id"] = it }
            val resp = sendJsonGet(m as Map<String, Any>)
            val obj = JsonParser.parseString(resp).asJsonObject
            if (obj.get("status")?.asString != "ok") {
                return@withContext Result.failure(Exception(obj.get("error")?.asString))
            }
            Result.success(obj.getAsJsonObject("data")?.get("post_id")?.asLong ?: 0)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun getTimeline(userId: String): Result<List<Map<String, Any>>> = withContext(Dispatchers.IO) {
        try {
            val resp = sendJsonGet(mapOf("cmd" to "get_timeline", "user_id" to userId))
            val obj = JsonParser.parseString(resp).asJsonObject
            if (obj.get("status")?.asString != "ok") {
                return@withContext Result.failure(Exception(obj.get("error")?.asString))
            }
            val posts = obj.getAsJsonObject("data")?.getAsJsonArray("posts")
                ?.map { it.asJsonObject.entrySet().associate { (k, v) -> k to (v.asString ?: v.toString()) } }
                ?: emptyList()
            Result.success(posts)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun addComment(postId: Long, userId: String, content: String): Result<Unit> = sendCommand {
        mapOf("cmd" to "add_comment", "post_id" to postId, "user_id" to userId, "content" to content)
    }

    suspend fun deletePost(postId: Long, userId: String): Result<Unit> = sendCommand {
        mapOf("cmd" to "delete_post", "post_id" to postId, "user_id" to userId)
    }

    // ------------------------------------------------------------------
    // Status / Stories
    // ------------------------------------------------------------------

    suspend fun setStatus(userId: String, content: String): Result<Unit> = sendCommand {
        mapOf("cmd" to "set_status", "user_id" to userId, "content" to content)
    }

    suspend fun clearStatus(userId: String): Result<Unit> = sendCommand {
        mapOf("cmd" to "clear_status", "user_id" to userId)
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    private fun sendJsonGet(body: Map<String, Any>): String {
        val json = gson.toJson(body)
        return sendJsonGet(json)
    }

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
