// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import os.log

/// File-based storage for App Group data.
/// This avoids the CFPreferences kCFPreferencesAnyUser warning that occurs with UserDefaults(suiteName:).
struct AppGroupStorage {
    private static var storageDirectoryURL: URL? {
        guard let sharedFolderURL = FileManager.sharedFolderURL else {
            return nil
        }
        let storageURL = sharedFolderURL.appendingPathComponent("appGroupPreferences", isDirectory: true)
        
        // Create directory if it doesn't exist
        if !FileManager.default.fileExists(atPath: storageURL.path) {
            do {
                try FileManager.default.createDirectory(at: storageURL, withIntermediateDirectories: true)
            } catch {
                wg_log(.error, message: "Failed to create storage directory: \(error.localizedDescription)")
                return nil
            }
        }
        return storageURL
    }
    
    private static func fileURL(forKey key: String) -> URL? {
        guard let storageDir = storageDirectoryURL else { return nil }
        // Sanitize key for filename (replace invalid characters)
        let sanitizedKey = key.replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: ":", with: "_")
        return storageDir.appendingPathComponent("\(sanitizedKey).plist")
    }
    
    /// Gets a value from file-based storage
    static func getValue<T: Codable>(forKey key: String) -> T? {
        guard let fileURL = fileURL(forKey: key) else {
            wg_log(.error, message: "AppGroupStorage: Cannot get file URL for key: \(key)")
            return nil
        }
        
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        
        do {
            let data = try Data(contentsOf: fileURL)
            let decoder = PropertyListDecoder()
            return try decoder.decode(T.self, from: data)
        } catch {
            wg_log(.error, message: "AppGroupStorage: Failed to read value for key '\(key)': \(error.localizedDescription)")
            return nil
        }
    }
    
    /// Sets a value in file-based storage
    static func setValue<T: Codable>(_ value: T, forKey key: String) {
        guard let fileURL = fileURL(forKey: key) else {
            wg_log(.error, message: "AppGroupStorage: Cannot get file URL for key: \(key)")
            return
        }
        
        do {
            let encoder = PropertyListEncoder()
            encoder.outputFormat = .binary
            let data = try encoder.encode(value)
            try data.write(to: fileURL, options: .atomic)
        } catch {
            wg_log(.error, message: "AppGroupStorage: Failed to write value for key '\(key)': \(error.localizedDescription)")
        }
    }
    
    /// Removes a value from file-based storage
    static func removeValue(forKey key: String) {
        guard let fileURL = fileURL(forKey: key) else {
            return
        }
        
        if FileManager.default.fileExists(atPath: fileURL.path) {
            do {
                try FileManager.default.removeItem(at: fileURL)
            } catch {
                wg_log(.error, message: "AppGroupStorage: Failed to remove value for key '\(key)': \(error.localizedDescription)")
            }
        }
    }
    
    /// Convenience method to get a String array
    static func getStringArray(forKey key: String) -> [String]? {
        return getValue(forKey: key)
    }
    
    /// Convenience method to get Data
    static func getData(forKey key: String) -> Data? {
        return getValue(forKey: key)
    }
}

extension FileManager {
    static var appGroupId: String? {
        #if os(iOS)
        let appGroupIdInfoDictionaryKey = "com.wireguard.ios.app_group_id"
        #elseif os(macOS)
        let appGroupIdInfoDictionaryKey = "com.wireguard.macos.app_group_id"
        #else
        #error("Unimplemented")
        #endif
        return Bundle.main.object(forInfoDictionaryKey: appGroupIdInfoDictionaryKey) as? String
    }
    
    fileprivate static var sharedFolderURL: URL? {
        guard let appGroupId = FileManager.appGroupId else {
            os_log("Cannot obtain app group ID from bundle", log: OSLog.default, type: .error)
            return nil
        }
        guard let sharedFolderURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupId) else {
            wg_log(.error, message: "Cannot obtain shared folder URL")
            return nil
        }
        return sharedFolderURL
    }

    static var logFileURL: URL? {
        return sharedFolderURL?.appendingPathComponent("tunnel-log.bin")
    }

    static var networkExtensionLastErrorFileURL: URL? {
        return sharedFolderURL?.appendingPathComponent("last-error.txt")
    }

    static var loginHelperTimestampURL: URL? {
        return sharedFolderURL?.appendingPathComponent("login-helper-timestamp.bin")
    }

    static func deleteFile(at url: URL) -> Bool {
        do {
            try FileManager.default.removeItem(at: url)
        } catch {
            return false
        }
        return true
    }
}
