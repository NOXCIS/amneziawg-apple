// SPDX-License-Identifier: MIT
// Copyright © 2024 AmneziaWG. All Rights Reserved.

import Foundation

/// Configuration for udptlspipe TLS wrapper
public struct UdpTlsPipeConfiguration: Codable, Equatable, Hashable {
    /// Whether udptlspipe is enabled for this peer
    public var enabled: Bool

    /// Password for authentication with the udptlspipe server
    public var password: String

    /// TLS server name for SNI (Server Name Indication)
    /// If nil, the endpoint hostname will be used
    public var tlsServerName: String?

    /// Whether to verify the server's TLS certificate
    public var secure: Bool

    /// Optional proxy URL (e.g., "socks5://user:pass@host:port")
    public var proxy: String?

    /// TLS fingerprint profile for evading fingerprint detection
    /// Valid values: "chrome", "firefox", "safari", "edge", "okhttp", "ios", "randomized"
    /// Default is "okhttp" for backward compatibility
    public var fingerprintProfile: String?

    public init(
        enabled: Bool = false,
        password: String = "",
        tlsServerName: String? = nil,
        secure: Bool = false,
        proxy: String? = nil,
        fingerprintProfile: String? = nil
    ) {
        self.enabled = enabled
        self.password = password
        self.tlsServerName = tlsServerName
        self.secure = secure
        self.proxy = proxy
        self.fingerprintProfile = fingerprintProfile
    }

    /// Returns true if the configuration is valid and can be used
    public var isValid: Bool {
        return enabled
    }
}

extension UdpTlsPipeConfiguration {
    /// Creates a configuration from WireGuard config key-value pairs
    /// Keys expected: udptlspipe, udptlspipepassword, udptlspipetlsservername, udptlspipesecure, udptlspipeproxy, udptlspipefingerprintprofile
    public init?(from attributes: [String: String]) {
        // Check if udptlspipe is enabled
        guard let enabledStr = attributes["udptlspipe"],
              let enabled = Self.parseBool(enabledStr),
              enabled else {
            return nil
        }

        self.enabled = true
        self.password = attributes["udptlspipepassword"] ?? ""
        self.tlsServerName = attributes["udptlspipetlsservername"]
        self.secure = Self.parseBool(attributes["udptlspipesecure"] ?? "false") ?? false
        self.proxy = attributes["udptlspipeproxy"]
        self.fingerprintProfile = attributes["udptlspipefingerprintprofile"]
    }

    private static func parseBool(_ value: String) -> Bool? {
        let lowercased = value.lowercased()
        if lowercased == "true" || lowercased == "yes" || lowercased == "1" || lowercased == "on" {
            return true
        } else if lowercased == "false" || lowercased == "no" || lowercased == "0" || lowercased == "off" {
            return false
        }
        return nil
    }
}

extension UdpTlsPipeConfiguration {
    /// Returns the configuration as WireGuard config format string
    public func asWgQuickConfig() -> String {
        guard enabled else { return "" }

        var output = "UdpTlsPipe = true\n"

        if !password.isEmpty {
            output += "UdpTlsPipePassword = \(password)\n"
        }

        if let tlsServerName = tlsServerName, !tlsServerName.isEmpty {
            output += "UdpTlsPipeTlsServerName = \(tlsServerName)\n"
        }

        if secure {
            output += "UdpTlsPipeSecure = true\n"
        }

        if let proxy = proxy, !proxy.isEmpty {
            output += "UdpTlsPipeProxy = \(proxy)\n"
        }

        if let fingerprintProfile = fingerprintProfile, !fingerprintProfile.isEmpty {
            output += "UdpTlsPipeFingerprintProfile = \(fingerprintProfile)\n"
        }

        return output
    }
}
