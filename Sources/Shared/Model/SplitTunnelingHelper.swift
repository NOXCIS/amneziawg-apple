// SPDX-License-Identifier: MIT
// Copyright © 2024 WireGuard LLC. All Rights Reserved.

import Foundation
import Network
#if os(macOS) || os(iOS)
import Darwin
#endif

/// Helper to apply split tunneling settings to tunnel configuration
public class SplitTunnelingHelper {
    /// Apply split tunneling settings to a tunnel configuration
    /// This method modifies the tunnelConfiguration directly (it's a class)
    /// Following the same approach as amnezia-client
    /// - Parameters:
    ///   - tunnelConfiguration: Tunnel configuration to modify (modified in place)
    ///   - settings: Split tunneling settings
    public static func applySplitTunneling(to tunnelConfiguration: TunnelConfiguration, settings: SplitTunnelingSettings) {
        guard settings.mode != .allSites else {
            // No changes needed for allSites mode
            return
        }

        // Get site IPs from settings
        let siteIPs = getSiteIPs(from: settings.sites)

        // Process each peer
        for index in tunnelConfiguration.peers.indices {
            let originalAllowedIPs = tunnelConfiguration.peers[index].allowedIPs.map { $0.stringRepresentation }
            wg_log(.info, message: "Split tunneling: Processing peer \(index), original allowedIPs: \(originalAllowedIPs)")

            // Always ensure allowedIPs is 0.0.0.0/0, ::/0 when split tunneling is enabled
            tunnelConfiguration.peers[index].allowedIPs.removeAll()
            if let ipv4Default = IPAddressRange(from: "0.0.0.0/0") {
                tunnelConfiguration.peers[index].allowedIPs.append(ipv4Default)
                wg_log(.info, message: "Split tunneling: set allowedIPs to include 0.0.0.0/0")
            }
            if let ipv6Default = IPAddressRange(from: "::/0") {
                tunnelConfiguration.peers[index].allowedIPs.append(ipv6Default)
                wg_log(.info, message: "Split tunneling: set allowedIPs to include ::/0")
            }

            switch settings.mode {
            case .onlyForwardSites:
                // Only forward specified sites - keep allowedIPs as 0.0.0.0/0, ::/0
                // The filtering will be handled via excluded routes in the network extension
                // Clear excludeIPs as we'll handle exclusion at the route level
                tunnelConfiguration.peers[index].excludeIPs.removeAll()
                wg_log(.info, message: "Split tunneling: onlyForwardSites mode - keeping allowedIPs as 0.0.0.0/0, ::/0")
                // Note: The actual filtering for onlyForwardSites needs to be handled
                // in PacketTunnelSettingsGenerator.excludedRoutes() by excluding everything
                // except the site IPs

            case .allExceptSites:
                // All except specified sites - set excludeIPs to the sites
                if !siteIPs.isEmpty {
                    tunnelConfiguration.peers[index].excludeIPs = siteIPs
                    wg_log(.info, message: "Split tunneling: set excludeIPs to \(siteIPs.map { $0.stringRepresentation })")
                } else {
                    wg_log(.error, message: "Split tunneling: No site IPs to exclude for allExceptSites mode")
                }

            case .allSites:
                // No changes
                wg_log(.info, message: "Split tunneling: allSites mode - no changes")
            }

            let finalAllowedIPs = tunnelConfiguration.peers[index].allowedIPs.map { $0.stringRepresentation }
            let finalExcludeIPs = tunnelConfiguration.peers[index].excludeIPs.map { $0.stringRepresentation }
            wg_log(.info, message: "Split tunneling: Peer \(index) final allowedIPs: \(finalAllowedIPs)")
            wg_log(.info, message: "Split tunneling: Peer \(index) final excludeIPs: \(finalExcludeIPs)")
        }
    }

    /// Extract IP addresses from sites dictionary
    /// - Parameter sites: Dictionary mapping site names to resolved IPs
    /// - Returns: Array of IPAddressRange objects
    private static func getSiteIPs(from sites: [String: String]) -> [IPAddressRange] {
        var ipRanges: [IPAddressRange] = []

        for (site, resolvedIP) in sites {
            var ipRange: IPAddressRange?

            // If it's already an IP/subnet, use it directly
            if let range = IPAddressRange(from: site) {
                ipRange = range
                wg_log(.info, message: "Split tunneling: Using site as IP range: \(site) -> \(range.stringRepresentation)")
            } else if !resolvedIP.isEmpty {
                // Use resolved IP - try with /32 for IPv4 or /128 for IPv6
                if let range = IPAddressRange(from: resolvedIP) {
                    ipRange = range
                    wg_log(.info, message: "Split tunneling: Using resolved IP: \(resolvedIP) -> \(range.stringRepresentation)")
                } else if let range = IPAddressRange(from: "\(resolvedIP)/32") {
                    ipRange = range
                    wg_log(.info, message: "Split tunneling: Using resolved IP with /32: \(resolvedIP)/32 -> \(range.stringRepresentation)")
                } else if let range = IPAddressRange(from: "\(resolvedIP)/128") {
                    ipRange = range
                    wg_log(.info, message: "Split tunneling: Using resolved IP with /128: \(resolvedIP)/128 -> \(range.stringRepresentation)")
                } else {
                    wg_log(.error, message: "Split tunneling: Failed to create IPAddressRange from resolved IP: \(resolvedIP)")
                }
            } else {
                wg_log(.error, message: "Split tunneling: No resolved IP for site: \(site)")
            }

            if let range = ipRange {
                ipRanges.append(range)
            }
        }

        wg_log(.info, message: "Split tunneling: getSiteIPs returning \(ipRanges.count) IP ranges: \(ipRanges.map { $0.stringRepresentation })")
        return ipRanges
    }

    /// Check if split tunneling can be enabled for a tunnel configuration
    /// Split tunneling requires that allowedIPs contains default routes (0.0.0.0/0 or ::/0)
    /// - Parameter configuration: Tunnel configuration to check
    /// - Returns: True if split tunneling can be enabled
    public static func canEnableSplitTunneling(for configuration: TunnelConfiguration) -> Bool {
        for peer in configuration.peers {
            let hasDefaultRoute = peer.allowedIPs.contains { range in
                range.stringRepresentation == "0.0.0.0/0" || range.stringRepresentation == "::/0"
            }
            if hasDefaultRoute {
                return true
            }
        }
        return false
    }

    /// Resolve domain names in split tunneling settings synchronously
    /// - Parameter settings: Split tunneling settings that may contain unresolved domains
    /// - Returns: Settings with all domains resolved to IP addresses
    public static func resolveSplitTunnelingSitesSynchronously(settings: SplitTunnelingSettings) -> SplitTunnelingSettings {
        var resolvedSettings = settings
        wg_log(.info, message: "resolveSplitTunnelingSitesSynchronously: Starting with \(settings.sites.count) sites")

        for (site, resolvedIP) in settings.sites {
            // Skip if already an IP address
            if IPAddressRange(from: site) != nil {
                wg_log(.info, message: "resolveSplitTunnelingSitesSynchronously: \(site) is already an IP address, skipping")
                continue
            }

            // Use existing resolved IP if available
            if !resolvedIP.isEmpty {
                wg_log(.info, message: "resolveSplitTunnelingSitesSynchronously: \(site) already resolved to \(resolvedIP), skipping")
                continue
            }

            // Resolve domain name synchronously
            wg_log(.info, message: "resolveSplitTunnelingSitesSynchronously: Resolving domain: \(site)")

            #if os(macOS) || os(iOS)
            var hints = addrinfo()
            hints.ai_flags = AI_ALL
            hints.ai_family = AF_INET // IPv4 only for now
            hints.ai_socktype = SOCK_DGRAM
            hints.ai_protocol = IPPROTO_UDP

            var resultPointer: UnsafeMutablePointer<addrinfo>?
            defer {
                resultPointer.flatMap { freeaddrinfo($0) }
            }

            let errorCode = getaddrinfo(site, nil, &hints, &resultPointer)
            if errorCode == 0, let addrInfo = resultPointer?.pointee, addrInfo.ai_family == AF_INET {
                let ipAddress = addrInfo.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ptr -> String in
                    var addr = ptr.pointee.sin_addr
                    var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    inet_ntop(AF_INET, &addr, &buffer, socklen_t(INET_ADDRSTRLEN))
                    return String(cString: buffer)
                }
                wg_log(.info, message: "resolveSplitTunnelingSitesSynchronously: Successfully resolved \(site) to \(ipAddress)")
                resolvedSettings.sites[site] = ipAddress
            } else {
                let errorString = String(cString: gai_strerror(errorCode))
                wg_log(.error, message: "resolveSplitTunnelingSitesSynchronously: Failed to resolve \(site): error \(errorCode) - \(errorString)")
            }
            #else
            wg_log(.error, message: "resolveSplitTunnelingSitesSynchronously: DNS resolution not implemented for this platform")
            #endif
        }

        wg_log(.info, message: "resolveSplitTunnelingSitesSynchronously: Final resolved sites: \(resolvedSettings.sites)")
        return resolvedSettings
    }
}
