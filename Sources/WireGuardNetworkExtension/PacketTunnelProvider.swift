// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension
import Network
import os

class PacketTunnelProvider: NEPacketTunnelProvider {

    private lazy var adapter: WireGuardAdapter = {
        return WireGuardAdapter(with: self) { logLevel, message in
            wg_log(logLevel.osLogLevel, message: message)
        }
    }()

    /// UdpTlsPipe adapter for wrapping UDP traffic with TLS
    private var udpTlsPipeAdapter: UdpTlsPipeAdapter?

    /// Store original endpoint for reference
    private var originalEndpoint: Endpoint?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let activationAttemptId = options?["activationAttemptId"] as? String
        let errorNotifier = ErrorNotifier(activationAttemptId: activationAttemptId)

        Logger.configureGlobal(tagged: "NET", withFilePath: FileManager.logFileURL?.path)

        wg_log(.info, message: "Starting tunnel from the " + (activationAttemptId == nil ? "OS directly, rather than the app" : "app"))

        guard let tunnelProviderProtocol = self.protocolConfiguration as? NETunnelProviderProtocol,
              let tunnelConfiguration = tunnelProviderProtocol.asTunnelConfiguration() else {
            errorNotifier.notify(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            return
        }

        // Get tunnel name from configuration or providerConfiguration
        var tunnelName = tunnelConfiguration.name
        wg_log(.info, message: "Tunnel configuration name: \(tunnelName ?? "nil")")

        // Try to get tunnel name from providerConfiguration if configuration name is nil
        if tunnelName == nil, let nameFromProvider = tunnelProviderProtocol.providerConfiguration?["TunnelName"] as? String {
            tunnelName = nameFromProvider
            wg_log(.info, message: "Using tunnel name from providerConfiguration: \(nameFromProvider)")
        }

        // Try to get tunnel name from options as last resort
        if tunnelName == nil, let tunnelNameFromOptions = options?["tunnelName"] as? String {
            tunnelName = tunnelNameFromOptions
            wg_log(.info, message: "Using tunnel name from options: \(tunnelNameFromOptions)")
        }

        wg_log(.info, message: "Protocol serverAddress: \(protocolConfiguration.serverAddress ?? "nil")")
        wg_log(.info, message: "Tunnel has \(tunnelConfiguration.peers.count) peer(s)")

        // Load split tunneling settings - try providerConfiguration first, then UserDefaults
        var splitTunnelingSettings: SplitTunnelingSettings?

        // First, try to load from providerConfiguration (new approach, like amnezia-client)
        if let providerConfig = tunnelProviderProtocol.providerConfiguration {
            wg_log(.info, message: "providerConfiguration keys: \(providerConfig.keys.joined(separator: ", "))")
            if let splitTunnelingData = providerConfig["SplitTunnelingSettings"] as? Data {
                wg_log(.info, message: "Found SplitTunnelingSettings data: \(splitTunnelingData.count) bytes")
                if let decodedSettings = try? JSONDecoder().decode(SplitTunnelingSettings.self, from: splitTunnelingData) {
                    splitTunnelingSettings = decodedSettings
                    wg_log(.info, message: "Split tunneling settings loaded from providerConfiguration: mode=\(decodedSettings.mode.rawValue), sites=\(decodedSettings.sites)")
                } else {
                    wg_log(.error, message: "Failed to decode SplitTunnelingSettings from providerConfiguration")
                }
            } else {
                wg_log(.info, message: "No SplitTunnelingSettings found in providerConfiguration")
            }
        } else {
            wg_log(.info, message: "No providerConfiguration available")
        }

        // Fallback to UserDefaults for backward compatibility
        if splitTunnelingSettings == nil, let tunnelName = tunnelName {
            let loadedSettings = SplitTunnelingSettingsManager.loadSettings(for: tunnelName)
            if loadedSettings.mode != .allSites || !loadedSettings.sites.isEmpty {
                splitTunnelingSettings = loadedSettings
                wg_log(.info, message: "Split tunneling settings loaded from UserDefaults: mode=\(loadedSettings.mode.rawValue), sites=\(loadedSettings.sites)")
            }
        }

        // Apply split tunneling settings if configured
        // Force allowedIPs to be full tunnel (0.0.0.0/0, ::/0) when split tunneling is enabled
        // This ensures split tunneling works correctly, following amnezia-client approach
        if let settings = splitTunnelingSettings, settings.mode != .allSites {
            // Force allowedIPs to be full tunnel for split tunneling to work
            for index in tunnelConfiguration.peers.indices {
                let originalAllowedIPs = tunnelConfiguration.peers[index].allowedIPs.map { $0.stringRepresentation }
                wg_log(.info, message: "Forcing allowedIPs to full tunnel for split tunneling. Original: \(originalAllowedIPs.joined(separator: ", "))")

                tunnelConfiguration.peers[index].allowedIPs.removeAll()
                if let ipv4Default = IPAddressRange(from: "0.0.0.0/0") {
                    tunnelConfiguration.peers[index].allowedIPs.append(ipv4Default)
                }
                if let ipv6Default = IPAddressRange(from: "::/0") {
                    tunnelConfiguration.peers[index].allowedIPs.append(ipv6Default)
                }
            }
            wg_log(.info, message: "Forced allowedIPs to 0.0.0.0/0, ::/0 for split tunneling")

            // Resolve any unresolved domains synchronously before starting tunnel
            let resolvedSettings = resolveSplitTunnelingSites(settings: settings)
            wg_log(.info, message: "After resolution: sites=\(resolvedSettings.sites)")

            // Log original config
            for (idx, peer) in tunnelConfiguration.peers.enumerated() {
                wg_log(.info, message: "Before split tunneling - Peer \(idx) allowedIPs: \(peer.allowedIPs.map { $0.stringRepresentation })")
                wg_log(.info, message: "Before split tunneling - Peer \(idx) excludeIPs: \(peer.excludeIPs.map { $0.stringRepresentation })")
            }

            // Apply split tunneling (modifies tunnelConfiguration in place)
            SplitTunnelingHelper.applySplitTunneling(to: tunnelConfiguration, settings: resolvedSettings)

            // Log modified config
            for (idx, peer) in tunnelConfiguration.peers.enumerated() {
                wg_log(.info, message: "After split tunneling - Peer \(idx) allowedIPs: \(peer.allowedIPs.map { $0.stringRepresentation })")
                wg_log(.info, message: "After split tunneling - Peer \(idx) excludeIPs: \(peer.excludeIPs.map { $0.stringRepresentation })")
            }
        } else {
            wg_log(.info, message: "No split tunneling settings to apply (mode=allSites or no settings found)")
        }

        // Check if any peer has UdpTlsPipe configured and start it before WireGuard
        startUdpTlsPipeIfNeeded(for: tunnelConfiguration, errorNotifier: errorNotifier) { [weak self] udpTlsPipeError in
            guard let self = self else {
                completionHandler(PacketTunnelProviderError.couldNotStartBackend)
                return
            }

            if let udpTlsPipeError = udpTlsPipeError {
                wg_log(.error, message: "Failed to start UdpTlsPipe: \(udpTlsPipeError)")
                errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                completionHandler(PacketTunnelProviderError.couldNotStartBackend)
                return
            }

            // Start the tunnel
            self.adapter.start(tunnelConfiguration: tunnelConfiguration) { adapterError in
                guard let adapterError = adapterError else {
                    let interfaceName = self.adapter.interfaceName ?? "unknown"

                    wg_log(.info, message: "Tunnel interface is \(interfaceName)")

                    completionHandler(nil)
                    return
                }

                switch adapterError {
                case .cannotLocateTunnelFileDescriptor:
                    wg_log(.error, staticMessage: "Starting tunnel failed: could not determine file descriptor")
                    self.stopUdpTlsPipe()
                    errorNotifier.notify(PacketTunnelProviderError.couldNotDetermineFileDescriptor)
                    completionHandler(PacketTunnelProviderError.couldNotDetermineFileDescriptor)

                case .dnsResolution(let dnsErrors):
                    let hostnamesWithDnsResolutionFailure = dnsErrors.map { $0.address }
                        .joined(separator: ", ")
                    wg_log(.error, message: "DNS resolution failed for the following hostnames: \(hostnamesWithDnsResolutionFailure)")
                    self.stopUdpTlsPipe()
                    errorNotifier.notify(PacketTunnelProviderError.dnsResolutionFailure)
                    completionHandler(PacketTunnelProviderError.dnsResolutionFailure)

                case .setNetworkSettings(let error):
                    wg_log(.error, message: "Starting tunnel failed with setTunnelNetworkSettings returning \(error.localizedDescription)")
                    self.stopUdpTlsPipe()
                    errorNotifier.notify(PacketTunnelProviderError.couldNotSetNetworkSettings)
                    completionHandler(PacketTunnelProviderError.couldNotSetNetworkSettings)

                case .startWireGuardBackend(let errorCode):
                    wg_log(.error, message: "Starting tunnel failed with wgTurnOn returning \(errorCode)")
                    self.stopUdpTlsPipe()
                    errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                    completionHandler(PacketTunnelProviderError.couldNotStartBackend)

                case .invalidState:
                    // Must never happen
                    fatalError()
                }
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        wg_log(.info, staticMessage: "Stopping tunnel")

        adapter.stop { [weak self] error in
            ErrorNotifier.removeLastErrorFile()

            if let error = error {
                wg_log(.error, message: "Failed to stop WireGuard adapter: \(error.localizedDescription)")
            }

            // Stop UdpTlsPipe if running
            self?.stopUdpTlsPipe()

            completionHandler()

            #if os(macOS)
            // HACK: This is a filthy hack to work around Apple bug 32073323 (dup'd by us as 47526107).
            // Remove it when they finally fix this upstream and the fix has been rolled out to
            // sufficient quantities of users.
            exit(0)
            #endif
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }

        if messageData.count == 1 && messageData[0] == 0 {
            adapter.getRuntimeConfiguration { settings in
                var data: Data?
                if let settings = settings {
                    data = settings.data(using: .utf8)!
                }
                completionHandler(data)
            }
        } else {
            completionHandler(nil)
        }
    }

    /// Resolve domain names in split tunneling settings synchronously
    private func resolveSplitTunnelingSites(settings: SplitTunnelingSettings) -> SplitTunnelingSettings {
        var resolvedSettings = settings
        wg_log(.info, message: "resolveSplitTunnelingSites: Starting with \(settings.sites.count) sites")

        for (site, resolvedIP) in settings.sites {
            // Skip if already an IP address
            if IPAddressRange(from: site) != nil {
                wg_log(.info, message: "resolveSplitTunnelingSites: \(site) is already an IP address, skipping")
                continue
            }

            // Use existing resolved IP if available
            if !resolvedIP.isEmpty {
                wg_log(.info, message: "resolveSplitTunnelingSites: \(site) already resolved to \(resolvedIP), skipping")
                continue
            }

            // Resolve domain name synchronously
            wg_log(.info, message: "resolveSplitTunnelingSites: Resolving domain: \(site)")

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
                wg_log(.info, message: "resolveSplitTunnelingSites: Successfully resolved \(site) to \(ipAddress)")
                resolvedSettings.sites[site] = ipAddress
            } else {
                let errorString = String(cString: gai_strerror(errorCode))
                wg_log(.error, message: "resolveSplitTunnelingSites: Failed to resolve \(site): error \(errorCode) - \(errorString)")
            }
        }

        wg_log(.info, message: "resolveSplitTunnelingSites: Final resolved sites: \(resolvedSettings.sites)")
        return resolvedSettings
    }

    // MARK: - UdpTlsPipe Methods

    /// Starts UdpTlsPipe client if any peer has it configured
    /// - Parameters:
    ///   - tunnelConfiguration: The tunnel configuration
    ///   - errorNotifier: Error notifier
    ///   - completionHandler: Called when complete, with error if any
    private func startUdpTlsPipeIfNeeded(
        for tunnelConfiguration: TunnelConfiguration,
        errorNotifier: ErrorNotifier,
        completionHandler: @escaping (Error?) -> Void
    ) {
        // Find the first peer with UdpTlsPipe configuration
        guard let peerIndex = tunnelConfiguration.peers.firstIndex(where: { $0.udpTlsPipeConfig?.enabled == true }),
              let udpTlsPipeConfig = tunnelConfiguration.peers[peerIndex].udpTlsPipeConfig,
              let originalEndpoint = tunnelConfiguration.peers[peerIndex].endpoint else {
            // No UdpTlsPipe configuration found, proceed normally
            wg_log(.info, message: "No UdpTlsPipe configuration found, proceeding without TLS wrapper")
            completionHandler(nil)
            return
        }

        wg_log(.info, message: "UdpTlsPipe is configured for peer \(peerIndex)")
        wg_log(.info, message: "Original endpoint: \(originalEndpoint.stringRepresentation)")

        // Store original endpoint
        self.originalEndpoint = originalEndpoint

        // Create UdpTlsPipe adapter
        let adapter = UdpTlsPipeAdapter { logLevel, message in
            wg_log(logLevel.osLogLevel, message: message)
        }
        self.udpTlsPipeAdapter = adapter

        // Determine the destination for udptlspipe
        // The destination should be the original endpoint but on the TLS port (typically 443)
        // or use the same port if it's already TLS
        let destination = originalEndpoint.stringRepresentation

        wg_log(.info, message: "Starting UdpTlsPipe client to \(destination)")

        // Start the udptlspipe client
        adapter.start(destination: destination, config: udpTlsPipeConfig) { [weak self] result in
            switch result {
            case .success(let localPort):
                wg_log(.info, message: "UdpTlsPipe started successfully, local port: \(localPort)")

                // Modify the endpoint to point to localhost:localPort
                let newEndpoint = Endpoint(host: NWEndpoint.Host("127.0.0.1"), port: NWEndpoint.Port(integerLiteral: localPort))
                tunnelConfiguration.peers[peerIndex].endpoint = newEndpoint

                wg_log(.info, message: "Modified endpoint from \(originalEndpoint.stringRepresentation) to \(newEndpoint.stringRepresentation)")

                completionHandler(nil)

            case .failure(let error):
                wg_log(.error, message: "Failed to start UdpTlsPipe: \(error)")
                self?.udpTlsPipeAdapter = nil
                completionHandler(error)
            }
        }
    }

    /// Stops the UdpTlsPipe client if running
    private func stopUdpTlsPipe() {
        guard let adapter = udpTlsPipeAdapter else { return }

        wg_log(.info, message: "Stopping UdpTlsPipe client")
        adapter.stopSync()
        udpTlsPipeAdapter = nil
        wg_log(.info, message: "UdpTlsPipe client stopped")
    }
}

extension WireGuardLogLevel {
    var osLogLevel: OSLogType {
        switch self {
        case .verbose:
            return .debug
        case .error:
            return .error
        }
    }
}
