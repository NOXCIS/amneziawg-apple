// SPDX-License-Identifier: MIT
// Copyright © 2024 WireGuard LLC. All Rights Reserved.

import Cocoa

class SplitTunnelingControlsRow: NSView {
    let keyLabel: NSTextField = {
        let keyLabel = NSTextField()
        keyLabel.stringValue = tr("tunnelSectionTitleSplitTunneling")
        keyLabel.isEditable = false
        keyLabel.isSelectable = false
        keyLabel.isBordered = false
        keyLabel.alignment = .right
        keyLabel.maximumNumberOfLines = 1
        keyLabel.lineBreakMode = .byTruncatingTail
        keyLabel.backgroundColor = .clear
        return keyLabel
    }()

    static let splitTunnelingModes: [SplitTunnelingMode] = [
        .allSites, .onlyForwardSites, .allExceptSites
    ]

    let modePopup: NSPopUpButton = {
        let popup = NSPopUpButton()
        return popup
    }()

    let sitesLabel: NSTextField = {
        let label = NSTextField()
        label.stringValue = tr("splitTunnelingSites") + ":"
        label.isEditable = false
        label.isSelectable = false
        label.isBordered = false
        label.alignment = .right
        label.maximumNumberOfLines = 1
        label.lineBreakMode = .byTruncatingTail
        label.backgroundColor = .clear
        return label
    }()

    let sitesField: NSTokenField = {
        let tokenField = NSTokenField()
        tokenField.tokenizingCharacterSet = CharacterSet([",", " "])
        tokenField.tokenStyle = .squared
        tokenField.placeholderString = tr("splitTunnelingSitesPlaceholder")
        NSLayoutConstraint.activate([
            tokenField.widthAnchor.constraint(greaterThanOrEqualToConstant: 200)
        ])
        return tokenField
    }()

    override var intrinsicContentSize: NSSize {
        let minHeight: CGFloat = 22
        let height = max(minHeight, keyLabel.intrinsicContentSize.height,
                         modePopup.intrinsicContentSize.height,
                         sitesField.intrinsicContentSize.height)
        return NSSize(width: NSView.noIntrinsicMetric, height: height * 2 + 8)
    }

    var splitTunnelingSettings: SplitTunnelingSettings = SplitTunnelingSettings() {
        didSet { updateControls() }
    }

    init() {
        super.init(frame: CGRect.zero)

        // Add mode options
        modePopup.addItems(withTitles: [
            tr("splitTunnelingModeAllSites"),
            tr("splitTunnelingModeOnlyForwardSites"),
            tr("splitTunnelingModeAllExceptSites")
        ])

        // First row: Mode selection
        let modeStackView = NSStackView()
        modeStackView.setViews([keyLabel, modePopup], in: .leading)
        modeStackView.orientation = .horizontal
        modeStackView.spacing = 5

        // Second row: Sites
        let sitesStackView = NSStackView()
        sitesStackView.setViews([sitesLabel, sitesField], in: .leading)
        sitesStackView.orientation = .horizontal
        sitesStackView.spacing = 5

        // Main stack
        let mainStackView = NSStackView()
        mainStackView.setViews([modeStackView, sitesStackView], in: .top)
        mainStackView.orientation = .vertical
        mainStackView.alignment = .leading
        mainStackView.spacing = 8

        addSubview(mainStackView)
        mainStackView.translatesAutoresizingMaskIntoConstraints = false

        NSLayoutConstraint.activate([
            mainStackView.topAnchor.constraint(equalTo: self.topAnchor),
            mainStackView.bottomAnchor.constraint(equalTo: self.bottomAnchor),
            mainStackView.leadingAnchor.constraint(equalTo: self.leadingAnchor),
            mainStackView.trailingAnchor.constraint(equalTo: self.trailingAnchor)
        ])

        keyLabel.setContentCompressionResistancePriority(.defaultHigh + 2, for: .horizontal)
        keyLabel.setContentHuggingPriority(.defaultHigh, for: .horizontal)

        let keyWidthConstraint = keyLabel.widthAnchor.constraint(equalToConstant: 150)
        keyWidthConstraint.priority = .defaultHigh + 1
        keyWidthConstraint.isActive = true

        let sitesLabelWidthConstraint = sitesLabel.widthAnchor.constraint(equalToConstant: 150)
        sitesLabelWidthConstraint.priority = .defaultHigh + 1
        sitesLabelWidthConstraint.isActive = true

        sitesField.setContentHuggingPriority(.defaultLow, for: .horizontal)

        modePopup.target = self
        modePopup.action = #selector(modePopupValueChanged)

        sitesField.delegate = self

        updateControls()
    }

    required init?(coder decoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func saveToSettings() -> SplitTunnelingSettings {
        let modeIndex = modePopup.indexOfSelectedItem
        let mode = SplitTunnelingControlsRow.splitTunnelingModes[modeIndex]

        var sites: [String: String] = [:]

        // First, get tokenized values
        if let sitesArray = sitesField.objectValue as? [String] {
            for site in sitesArray {
                let trimmedSite = site.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmedSite.isEmpty {
                    sites[trimmedSite] = splitTunnelingSettings.sites[trimmedSite] ?? ""
                }
            }
        }

        // Also capture any un-tokenized text in the field
        let currentText = sitesField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !currentText.isEmpty {
            // Parse comma/space-separated values
            let additionalSites = currentText.components(separatedBy: CharacterSet([",", " "]))
            for site in additionalSites {
                let trimmedSite = site.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmedSite.isEmpty && sites[trimmedSite] == nil {
                    sites[trimmedSite] = splitTunnelingSettings.sites[trimmedSite] ?? ""
                }
            }
        }

        // Synchronously resolve any unresolved domains before returning
        for (site, resolvedIP) in sites {
            if resolvedIP.isEmpty && !DNSResolver.isIPAddress(site) {
                // Try synchronous resolution
                if let ip = resolveHostnameSync(site) {
                    sites[site] = ip
                    NSLog("Resolved \(site) to \(ip)")
                } else {
                    NSLog("Failed to resolve \(site)")
                }
            }
        }

        NSLog("SplitTunnelingControlsRow.saveToSettings: mode=\(mode.rawValue), sites=\(sites)")
        return SplitTunnelingSettings(mode: mode, sites: sites)
    }

    /// Synchronously resolve a hostname to IP address
    private func resolveHostnameSync(_ hostname: String) -> String? {
        var hints = addrinfo()
        hints.ai_flags = AI_ALL
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP

        var resultPointer: UnsafeMutablePointer<addrinfo>?
        defer {
            resultPointer.flatMap { freeaddrinfo($0) }
        }

        let errorCode = getaddrinfo(hostname, nil, &hints, &resultPointer)
        if errorCode == 0, let addrInfo = resultPointer?.pointee, addrInfo.ai_family == AF_INET {
            let ipAddress = addrInfo.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ptr -> String in
                var addr = ptr.pointee.sin_addr
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                inet_ntop(AF_INET, &addr, &buffer, socklen_t(INET_ADDRSTRLEN))
                return String(cString: buffer)
            }
            return ipAddress
        }
        return nil
    }

    func updateControls() {
        let modeIndex = SplitTunnelingControlsRow.splitTunnelingModes.firstIndex(of: splitTunnelingSettings.mode) ?? 0
        modePopup.selectItem(at: modeIndex)

        let sitesList = splitTunnelingSettings.sites.keys.sorted()
        sitesField.objectValue = sitesList

        // Show/hide sites based on mode
        let showSites = splitTunnelingSettings.mode != .allSites
        sitesLabel.isHidden = !showSites
        sitesField.isHidden = !showSites
    }

    @objc func modePopupValueChanged() {
        let selectedIndex = modePopup.indexOfSelectedItem
        splitTunnelingSettings.mode = SplitTunnelingControlsRow.splitTunnelingModes[selectedIndex]
        updateControls()
    }

    func resolveSites() {
        let unresolvedSites = splitTunnelingSettings.sites.filter { site, resolvedIP in
            !DNSResolver.isIPAddress(site) && resolvedIP.isEmpty
        }.map { $0.key }

        guard !unresolvedSites.isEmpty else { return }

        DNSResolver.resolveMultipleIPv4(hostnames: unresolvedSites) { [weak self] (results: [String: String]) in
            guard let self = self else { return }
            for (hostname, ip) in results {
                self.splitTunnelingSettings.sites[hostname] = ip
            }
        }
    }
}

extension SplitTunnelingControlsRow: NSTokenFieldDelegate {
    func controlTextDidEndEditing(_ obj: Notification) {
        // When editing ends, parse the sites and resolve domains
        if let sitesArray = sitesField.objectValue as? [String] {
            var newSites: [String: String] = [:]
            for site in sitesArray {
                let trimmedSite = site.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmedSite.isEmpty {
                    newSites[trimmedSite] = splitTunnelingSettings.sites[trimmedSite] ?? ""
                }
            }
            splitTunnelingSettings.sites = newSites
            resolveSites()
        }
    }
}

