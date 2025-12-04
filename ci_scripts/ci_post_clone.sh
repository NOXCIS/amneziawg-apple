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

# Verify installation
echo "Go version: $(go version)"
echo "GOROOT: $(go env GOROOT)"

echo "=== Go installation complete ==="

