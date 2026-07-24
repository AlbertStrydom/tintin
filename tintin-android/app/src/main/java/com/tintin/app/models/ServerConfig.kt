package com.tintin.app.models

data class ServerConfig(
    val host: String = "127.0.0.1",
    val port: Int = 9666,
    val userId: String = "",
)
