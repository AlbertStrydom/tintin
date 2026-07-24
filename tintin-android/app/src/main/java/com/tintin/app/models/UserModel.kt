package com.tintin.app.models

data class UserModel(
    val id: String,
    val identityKey: ByteArray,
    val deviceId: Int = 1,
    val displayName: String = id,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UserModel) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}
