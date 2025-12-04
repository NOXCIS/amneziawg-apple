#!/bin/bash
# ci_post_clone.sh - Xcode Cloud post-clone script
# Installs Go for building WireGuardKitGo and UdpTlsPipeKit

set -e

echo "=== Installing Go for Xcode Cloud ==="

# Install Homebrew if not present
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    eval "$(/opt/homebrew/bin/brew shellenv)"
fi

# Install Go
echo "Installing Go..."
brew install go

# Install SwiftLint
echo "Installing SwiftLint..."
brew install swiftlint

# Add Go to PATH for this session
export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

# Verify installation
echo "Go version: $(go version)"
echo "GOROOT: $(go env GOROOT)"

echo "=== Pre-downloading Go dependencies ==="

# Set Go proxy for faster downloads
export GOPROXY="https://proxy.golang.org,direct"

# Pre-download dependencies for WireGuardKitGo
cd "$CI_PRIMARY_REPOSITORY_PATH/Sources/WireGuardKitGo"
echo "Downloading WireGuardKitGo dependencies..."
for i in 1 2 3; do
    if go mod download -x; then
        echo "WireGuardKitGo dependencies downloaded successfully"
        break
    fi
    echo "Retry $i/3 for WireGuardKitGo dependencies..."
    sleep 5
done

# Pre-download dependencies for UdpTlsPipeKit
cd "$CI_PRIMARY_REPOSITORY_PATH/Sources/UdpTlsPipeKit"
echo "Downloading UdpTlsPipeKit dependencies..."
for i in 1 2 3; do
    if go mod download -x; then
        echo "UdpTlsPipeKit dependencies downloaded successfully"
        break
    fi
    echo "Retry $i/3 for UdpTlsPipeKit dependencies..."
    sleep 5
done

echo "=== Go setup complete ==="

