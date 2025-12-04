// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

public struct PeerConfiguration {
    public var publicKey: PublicKey
    public var preSharedKey: PreSharedKey?
    public var allowedIPs = [IPAddressRange]()
    public var excludeIPs = [IPAddressRange]()
    public var endpoint: Endpoint?
    public var persistentKeepAlive: UInt16?
    public var rxBytes: UInt64?
    public var txBytes: UInt64?
    public var lastHandshakeTime: Date?

    /// Optional udptlspipe configuration for wrapping UDP traffic with TLS
    public var udpTlsPipeConfig: UdpTlsPipeConfiguration?

    public init(publicKey: PublicKey) {
        self.publicKey = publicKey
    }
}

extension PeerConfiguration: Equatable {
    public static func == (lhs: PeerConfiguration, rhs: PeerConfiguration) -> Bool {
        return lhs.publicKey == rhs.publicKey &&
            lhs.preSharedKey == rhs.preSharedKey &&
            Set(lhs.allowedIPs) == Set(rhs.allowedIPs) &&
            lhs.endpoint == rhs.endpoint &&
            lhs.persistentKeepAlive == rhs.persistentKeepAlive &&
            lhs.udpTlsPipeConfig == rhs.udpTlsPipeConfig
    }
}

extension PeerConfiguration: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
        hasher.combine(preSharedKey)
        hasher.combine(Set(allowedIPs))
        hasher.combine(endpoint)
        hasher.combine(persistentKeepAlive)
        hasher.combine(udpTlsPipeConfig)
    }
}
