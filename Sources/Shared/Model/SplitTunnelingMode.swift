// SPDX-License-Identifier: MIT
// Copyright © 2024 WireGuard LLC. All Rights Reserved.

import Foundation

/// Split tunneling mode for VPN routing
public enum SplitTunnelingMode: Int, Codable {
    /// All traffic goes through VPN (default)
    case allSites = 0

    /// Only specified sites go through VPN
    case onlyForwardSites = 1

    /// All traffic except specified sites goes through VPN
    case allExceptSites = 2
}

/// Split tunneling settings for a tunnel
public struct SplitTunnelingSettings: Codable, Equatable {
    public var mode: SplitTunnelingMode
    /// Map of site (domain/IP) to resolved IP address (empty string if not resolved yet)
    public var sites: [String: String]

    public init(mode: SplitTunnelingMode = .allSites, sites: [String: String] = [:]) {
        self.mode = mode
        self.sites = sites
    }
}

/// Manager for split tunneling settings persistence
public class SplitTunnelingSettingsManager {
    private static let storageKeyPrefix = "splitTunnelingSettings_"

    public static func loadSettings(for tunnelName: String) -> SplitTunnelingSettings {
        let key = storageKeyPrefix + tunnelName
        guard let data: Data = AppGroupStorage.getData(forKey: key),
              let settings = try? JSONDecoder().decode(SplitTunnelingSettings.self, from: data) else {
            wg_log(.info, message: "loadSettings: No saved settings for tunnel: \(tunnelName)")
            return SplitTunnelingSettings()
        }

        wg_log(.info, message: "loadSettings: Loaded for \(tunnelName): mode=\(settings.mode.rawValue), sites=\(settings.sites)")
        return settings
    }

    public static func saveSettings(_ settings: SplitTunnelingSettings, for tunnelName: String) {
        guard !tunnelName.isEmpty else {
            wg_log(.error, message: "saveSettings: Empty tunnel name!")
            return
        }

        let key = storageKeyPrefix + tunnelName
        if let data = try? JSONEncoder().encode(settings) {
            AppGroupStorage.setValue(data, forKey: key)
            wg_log(.info, message: "saveSettings: Saved for \(tunnelName): mode=\(settings.mode.rawValue), sites=\(settings.sites)")
        } else {
            wg_log(.error, message: "saveSettings: Failed to encode settings for tunnel: \(tunnelName)")
        }
    }

    public static func deleteSettings(for tunnelName: String) {
        let key = storageKeyPrefix + tunnelName
        AppGroupStorage.removeValue(forKey: key)
    }
}
