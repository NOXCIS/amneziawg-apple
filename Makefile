# SPDX-License-Identifier: MIT
#
# Copyright (C) 2024 AmneziaWG. All Rights Reserved.
#
# Top-level Makefile for building WireGuardKitGo and UdpTlsPipeKit libraries
# These must be built before Xcode can compile the Swift packages.

# Default platform (can be overridden)
PLATFORM_NAME ?= macosx
ARCHS ?= x86_64 arm64

# Directories
WIREGUARD_KIT_GO_DIR = Sources/WireGuardKitGo
UDPTLSPIPE_KIT_DIR = Sources/UdpTlsPipeKit

.PHONY: all clean build-wireguard build-udptlspipe help

help:
	@echo "WireGuard Apple Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build both WireGuardKitGo and UdpTlsPipeKit (default)"
	@echo "  build-wireguard  - Build only WireGuardKitGo library"
	@echo "  build-udptlspipe - Build only UdpTlsPipeKit library"
	@echo "  clean            - Clean all build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  PLATFORM_NAME    - Target platform (macosx or iphoneos, default: macosx)"
	@echo "  ARCHS            - Architectures to build (default: x86_64 arm64)"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build for macOS"
	@echo "  make PLATFORM_NAME=iphoneos ARCHS=arm64  # Build for iOS (arm64 only)"

all: build-wireguard build-udptlspipe
	@echo ""
	@echo "✓ All libraries built successfully!"

build-wireguard:
	@echo "Building WireGuardKitGo..."
	@cd $(WIREGUARD_KIT_GO_DIR) && \
		$(MAKE) build \
		PLATFORM_NAME=$(PLATFORM_NAME) \
		ARCHS="$(ARCHS)"
	@echo "✓ WireGuardKitGo built successfully"

build-udptlspipe: build-wireguard
	@echo "Building UdpTlsPipeKit..."
	@cd $(UDPTLSPIPE_KIT_DIR) && \
		$(MAKE) build \
		PLATFORM_NAME=$(PLATFORM_NAME) \
		ARCHS="$(ARCHS)"
	@echo "✓ UdpTlsPipeKit built successfully"

clean:
	@echo "Cleaning WireGuardKitGo..."
	@cd $(WIREGUARD_KIT_GO_DIR) && $(MAKE) clean
	@echo "Cleaning UdpTlsPipeKit..."
	@cd $(UDPTLSPIPE_KIT_DIR) && $(MAKE) clean
	@echo "✓ Clean complete"

