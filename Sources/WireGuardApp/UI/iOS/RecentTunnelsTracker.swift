// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

class RecentTunnelsTracker {

    private static let keyRecentlyActivatedTunnelNames = "recentlyActivatedTunnelNames"
    private static let maxNumberOfTunnels = 10

    static func handleTunnelActivated(tunnelName: String) {
        var recentTunnels = AppGroupStorage.getStringArray(forKey: keyRecentlyActivatedTunnelNames) ?? []
        if let existingIndex = recentTunnels.firstIndex(of: tunnelName) {
            recentTunnels.remove(at: existingIndex)
        }
        recentTunnels.insert(tunnelName, at: 0)
        if recentTunnels.count > maxNumberOfTunnels {
            recentTunnels.removeLast(recentTunnels.count - maxNumberOfTunnels)
        }
        AppGroupStorage.setValue(recentTunnels, forKey: keyRecentlyActivatedTunnelNames)
    }

    static func handleTunnelRemoved(tunnelName: String) {
        var recentTunnels = AppGroupStorage.getStringArray(forKey: keyRecentlyActivatedTunnelNames) ?? []
        if let existingIndex = recentTunnels.firstIndex(of: tunnelName) {
            recentTunnels.remove(at: existingIndex)
            AppGroupStorage.setValue(recentTunnels, forKey: keyRecentlyActivatedTunnelNames)
        }
    }

    static func handleTunnelRenamed(oldName: String, newName: String) {
        var recentTunnels = AppGroupStorage.getStringArray(forKey: keyRecentlyActivatedTunnelNames) ?? []
        if let existingIndex = recentTunnels.firstIndex(of: oldName) {
            recentTunnels[existingIndex] = newName
            AppGroupStorage.setValue(recentTunnels, forKey: keyRecentlyActivatedTunnelNames)
        }
    }

    static func cleanupTunnels(except tunnelNamesToKeep: Set<String>) {
        var recentTunnels = AppGroupStorage.getStringArray(forKey: keyRecentlyActivatedTunnelNames) ?? []
        let oldCount = recentTunnels.count
        recentTunnels.removeAll { !tunnelNamesToKeep.contains($0) }
        if oldCount != recentTunnels.count {
            AppGroupStorage.setValue(recentTunnels, forKey: keyRecentlyActivatedTunnelNames)
        }
    }

    static func recentlyActivatedTunnelNames(limit: Int) -> [String] {
        var recentTunnels = AppGroupStorage.getStringArray(forKey: keyRecentlyActivatedTunnelNames) ?? []
        if limit < recentTunnels.count {
            recentTunnels.removeLast(recentTunnels.count - limit)
        }
        return recentTunnels
    }
}
