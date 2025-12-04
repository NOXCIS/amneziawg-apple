// SPDX-License-Identifier: MIT
// Copyright © 2024 AmneziaWG. All Rights Reserved.

import Foundation

#if SWIFT_PACKAGE
import WireGuardKitGo
import UdpTlsPipeKit
#endif

/// Errors that can occur when working with UdpTlsPipe
public enum UdpTlsPipeError: Error {
    /// Failed to start the udptlspipe client
    case failedToStart
    /// The client is not running
    case notRunning
    /// Invalid configuration
    case invalidConfiguration(String)
}

/// Adapter for managing udptlspipe client instances
public class UdpTlsPipeAdapter {
    public typealias LogHandler = (WireGuardLogLevel, String) -> Void

    /// Handle returned by the native udptlspipe library
    private var handle: Int32 = -1

    /// The local port the udptlspipe client is listening on
    public private(set) var localPort: UInt16 = 0

    /// Whether the client is currently running
    public var isRunning: Bool {
        return handle > 0
    }

    /// Log handler closure
    private let logHandler: LogHandler

    /// Queue for synchronizing access
    private let workQueue = DispatchQueue(label: "UdpTlsPipeAdapterWorkQueue")

    /// Returns the udptlspipe version
    public class var version: String {
        guard let ver = udptlspipeVersion() else { return "unknown" }
        let str = String(cString: ver)
        free(UnsafeMutableRawPointer(mutating: ver))
        return str
    }

    /// Initialize the adapter with a log handler
    /// - Parameter logHandler: Closure to handle log messages
    public init(logHandler: @escaping LogHandler) {
        self.logHandler = logHandler
        setupLogHandler()
    }

    deinit {
        // Force remove logger to make sure that no further calls to the instance of this class
        // can happen after deallocation.
        udptlspipeSetLogger(nil, nil)

        if handle > 0 {
            udptlspipeStop(handle)
        }
    }

    // MARK: - Public Methods

    /// Start the udptlspipe client
    /// - Parameters:
    ///   - destination: The remote server address (e.g., "server.example.com:443")
    ///   - config: The udptlspipe configuration
    ///   - completionHandler: Called when the operation completes
    public func start(
        destination: String,
        config: UdpTlsPipeConfiguration,
        completionHandler: @escaping (Result<UInt16, UdpTlsPipeError>) -> Void
    ) {
        workQueue.async { [weak self] in
            guard let self = self else {
                completionHandler(.failure(.failedToStart))
                return
            }

            guard config.enabled else {
                completionHandler(.failure(.invalidConfiguration("UdpTlsPipe is not enabled")))
                return
            }

            // Stop any existing client
            if self.handle > 0 {
                udptlspipeStop(self.handle)
                self.handle = -1
                self.localPort = 0
            }

            let fingerprintProfile = config.fingerprintProfile ?? "okhttp"
            self.logHandler(.verbose, "UdpTlsPipe: Starting client to \(destination) (fingerprint: \(fingerprintProfile))")

            // Start the client
            let newHandle = udptlspipeStart(
                destination,
                config.password,
                config.tlsServerName,
                config.secure ? 1 : 0,
                config.proxy,
                fingerprintProfile,
                0 // Auto-assign port
            )

            if newHandle <= 0 {
                self.logHandler(.error, "UdpTlsPipe: Failed to start client, error code: \(newHandle)")
                completionHandler(.failure(.failedToStart))
                return
            }

            // Get the assigned local port
            let port = udptlspipeGetLocalPort(newHandle)
            if port <= 0 {
                self.logHandler(.error, "UdpTlsPipe: Failed to get local port")
                udptlspipeStop(newHandle)
                completionHandler(.failure(.failedToStart))
                return
            }

            self.handle = newHandle
            self.localPort = UInt16(port)

            self.logHandler(.verbose, "UdpTlsPipe: Started with handle \(newHandle), local port \(port)")
            completionHandler(.success(self.localPort))
        }
    }

    /// Stop the udptlspipe client
    /// - Parameter completionHandler: Called when the operation completes
    public func stop(completionHandler: @escaping () -> Void) {
        workQueue.async { [weak self] in
            guard let self = self else {
                completionHandler()
                return
            }

            if self.handle > 0 {
                self.logHandler(.verbose, "UdpTlsPipe: Stopping client with handle \(self.handle)")
                udptlspipeStop(self.handle)
                self.handle = -1
                self.localPort = 0
                self.logHandler(.verbose, "UdpTlsPipe: Client stopped")
            }

            completionHandler()
        }
    }

    /// Stop the udptlspipe client synchronously
    public func stopSync() {
        workQueue.sync {
            if self.handle > 0 {
                self.logHandler(.verbose, "UdpTlsPipe: Stopping client with handle \(self.handle)")
                udptlspipeStop(self.handle)
                self.handle = -1
                self.localPort = 0
                self.logHandler(.verbose, "UdpTlsPipe: Client stopped")
            }
        }
    }

    // MARK: - Private Methods

    /// Setup the log handler for the native library
    private func setupLogHandler() {
        let context = Unmanaged.passUnretained(self).toOpaque()
        udptlspipeSetLogger(context) { context, logLevel, message in
            guard let context = context, let message = message else { return }

            let unretainedSelf = Unmanaged<UdpTlsPipeAdapter>.fromOpaque(context)
                .takeUnretainedValue()

            let swiftString = String(cString: message).trimmingCharacters(in: .newlines)
            let tunnelLogLevel = logLevel == 0 ? WireGuardLogLevel.verbose : WireGuardLogLevel.error

            unretainedSelf.logHandler(tunnelLogLevel, swiftString)
        }
    }
}
