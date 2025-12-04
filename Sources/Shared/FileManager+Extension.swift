// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import os.log

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
    
    /// Creates a UserDefaults instance for the app group.
    ///
    /// - Important: This produces a harmless system warning:
    ///   "Couldn't read values in CFPrefsPlistSource... Using kCFPreferencesAnyUser with a container
    ///   is only allowed for System Containers"
    ///
    ///   This is a known iOS/macOS system behavior when using UserDefaults with App Group suite names.
    ///   The warning does not affect functionality and can be safely ignored. This is because the system
    ///   internally attempts to access the preferences using kCFPreferencesAnyUser, which is not permitted
    ///   for App Group containers (only System Containers), but the call still succeeds for the current user.
    static var appGroupUserDefaults: UserDefaults? {
        guard let appGroupId = appGroupId else {
            os_log("Cannot obtain app group ID from bundle", log: OSLog.default, type: .error)
            return nil
        }
        
        // Note: The next line triggers a harmless CFPreferences warning about kCFPreferencesAnyUser.
        // This is expected system behavior and does not affect functionality.
        return UserDefaults(suiteName: appGroupId)
    }
    private static var sharedFolderURL: URL? {
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
