// SPDX-License-Identifier: MIT
// Copyright © 2024 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

/// Helper for DNS resolution of domain names for split tunneling
class DNSResolver {
    /// Resolve a domain name to IPv4 address
    /// - Parameters:
    ///   - hostname: Domain name to resolve
    ///   - completion: Completion handler with resolved IP address or nil if failed
    static func resolveIPv4(hostname: String, completion: @escaping (String?) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            var hints = addrinfo()
            hints.ai_flags = AI_ALL // Get v4 addresses even on DNS64 networks
            hints.ai_family = AF_INET // IPv4 only
            hints.ai_socktype = SOCK_DGRAM
            hints.ai_protocol = IPPROTO_UDP

            var resultPointer: UnsafeMutablePointer<addrinfo>?
            defer {
                resultPointer.flatMap { freeaddrinfo($0) }
            }

            let errorCode = getaddrinfo(hostname, nil, &hints, &resultPointer)
            if errorCode != 0 {
                wg_log(.error, message: "DNS resolution failed for \(hostname): \(String(cString: gai_strerror(errorCode)))")
                DispatchQueue.main.async {
                    completion(nil)
                }
                return
            }

            // Get the first IPv4 address
            if let addrInfo = resultPointer?.pointee,
               addrInfo.ai_family == AF_INET {
                let addressData = addrInfo.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ptr -> Data in
                    return Data(bytes: &ptr.pointee.sin_addr, count: MemoryLayout<in_addr>.size)
                }
                if let ipv4Address = IPv4Address(addressData) {
                    DispatchQueue.main.async {
                        completion("\(ipv4Address)")
                    }
                    return
                }
            }
            DispatchQueue.main.async {
                completion(nil)
            }
        }
    }

    /// Resolve multiple hostnames asynchronously
    /// - Parameters:
    ///   - hostnames: Array of domain names to resolve
    ///   - completion: Completion handler with dictionary mapping hostname to resolved IP
    static func resolveMultipleIPv4(hostnames: [String], completion: @escaping ([String: String]) -> Void) {
        guard !hostnames.isEmpty else {
            completion([:])
            return
        }

        var results: [String: String] = [:]
        let group = DispatchGroup()

        for hostname in hostnames {
            group.enter()
            resolveIPv4(hostname: hostname) { ip in
                if let ip = ip {
                    results[hostname] = ip
                }
                group.leave()
            }
        }

        group.notify(queue: .main) {
            completion(results)
        }
    }

    /// Check if a string is a valid IP address or subnet
    /// - Parameter string: String to check
    /// - Returns: True if it's a valid IP/subnet format
    static func isIPAddress(_ string: String) -> Bool {
        // Check if it's a valid IPAddressRange
        return IPAddressRange(from: string) != nil
    }
}
