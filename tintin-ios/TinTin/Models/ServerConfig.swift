import Foundation

/// Configuration for connecting to a TinTin relay server.
struct ServerConfig: Codable, Equatable {
    var host: String
    var port: UInt16
    var userId: String

    static let `default` = ServerConfig(
        host: "127.0.0.1",
        port: 9666,
        userId: ""
    )
}
