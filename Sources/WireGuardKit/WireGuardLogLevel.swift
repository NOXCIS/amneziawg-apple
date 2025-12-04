// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

/// A enum describing WireGuard log levels defined in `api-apple.go`.
public enum WireGuardLogLevel: Int32 {
    case verbose = 0
    case error = 1
}
