# SPDX-License-Identifier: MIT
#
# Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

# These are generally passed to us by xcode, but we set working defaults for standalone compilation too.
ARCHS ?= x86_64 arm64
PLATFORM_NAME ?= macosx
SDKROOT ?= $(shell xcrun --sdk $(PLATFORM_NAME) --show-sdk-path)
CONFIGURATION_BUILD_DIR ?= $(CURDIR)/out
# Use /tmp for standalone builds to avoid polluting source tree and Swift module issues
CONFIGURATION_TEMP_DIR ?= /tmp/amneziawg-build

export PATH := $(PATH):/usr/local/bin:/opt/homebrew/bin
export CC ?= clang
LIPO ?= lipo
DESTDIR ?= $(CONFIGURATION_BUILD_DIR)
BUILDDIR ?= $(CONFIGURATION_TEMP_DIR)/wireguard-go-bridge

# Deployment target - use Xcode's if provided, otherwise default to minimum supported versions
DEPLOYMENT_TARGET_macosx ?= 12.0
DEPLOYMENT_TARGET_iphoneos ?= 15.0
DEPLOYMENT_TARGET_FLAG_macosx := -mmacosx-version-min=
DEPLOYMENT_TARGET_FLAG_iphoneos := -miphoneos-version-min=
DEPLOYMENT_TARGET_FLAG := $(if $(DEPLOYMENT_TARGET_CLANG_FLAG_NAME),-$(DEPLOYMENT_TARGET_CLANG_FLAG_NAME)=$($(DEPLOYMENT_TARGET_CLANG_ENV_NAME)),$(DEPLOYMENT_TARGET_FLAG_$(PLATFORM_NAME))$(DEPLOYMENT_TARGET_$(PLATFORM_NAME)))
CFLAGS_PREFIX := $(DEPLOYMENT_TARGET_FLAG) -isysroot $(SDKROOT) -arch
GOARCH_arm64 := arm64
GOARCH_x86_64 := amd64
GOOS_macosx := darwin
GOOS_iphoneos := ios

# Find Go - check common locations
GO_BINARY := $(firstword $(wildcard /opt/homebrew/bin/go /usr/local/bin/go) $(shell which go 2>/dev/null))
REAL_GOROOT := $(shell $(GO_BINARY) env GOROOT 2>/dev/null)

# Default target - handle gracefully for documentation builds
.PHONY: build docbuild

# Build target that checks at runtime if it should actually build
build:
	@if [ "$(ACTION)" != "build" ] && [ -n "$(ACTION)" ]; then \
		echo "Skipping build for action: $(ACTION)"; \
		exit 0; \
	fi
	@$(MAKE) -f $(firstword $(MAKEFILE_LIST)) _actual_build GO_BINARY="$(GO_BINARY)" REAL_GOROOT="$(REAL_GOROOT)"

# Documentation build target - no-op for doc generation
docbuild:
	@echo "Skipping build for documentation generation"
	@exit 0

# Actual build target (internal)
_actual_build: $(DESTDIR)/libwg-go.a

version-header: $(DESTDIR)/wireguard-go-version.h
export GOROOT := $(BUILDDIR)/goroot
$(GOROOT)/.prepared:
	[ -n "$(REAL_GOROOT)" ]
	mkdir -p "$(GOROOT)"
	rsync -a --delete --exclude=pkg/obj/go-build "$(REAL_GOROOT)/" "$(GOROOT)/"
	cat goruntime-*.diff | patch -p1 -f -N -r- -d "$(GOROOT)"
	touch "$@"

define libwg-go-a
$(BUILDDIR)/libwg-go-$(1).a: export CGO_ENABLED := 1
$(BUILDDIR)/libwg-go-$(1).a: export CGO_CFLAGS := $(CFLAGS_PREFIX) $(ARCH)
$(BUILDDIR)/libwg-go-$(1).a: export CGO_LDFLAGS := $(CFLAGS_PREFIX) $(ARCH) -lresolv
$(BUILDDIR)/libwg-go-$(1).a: export GOOS := $(GOOS_$(PLATFORM_NAME))
$(BUILDDIR)/libwg-go-$(1).a: export GOARCH := $(GOARCH_$(1))
$(BUILDDIR)/libwg-go-$(1).a: $(GOROOT)/.prepared go.mod api-apple.go api-xray.go
	go build -ldflags=-w -trimpath -v -o "$(BUILDDIR)/libwg-go-$(1).a" -buildmode c-archive
	rm -f "$(BUILDDIR)/libwg-go-$(1).h"
endef
$(foreach ARCH,$(ARCHS),$(eval $(call libwg-go-a,$(ARCH))))

$(DESTDIR)/wireguard-go-version.h: go.mod $(GOROOT)/.prepared
	 sed -E -n 's/.*golang\.zx2c4\.com\/wireguard +v[0-9.]+-[0-9]+-([0-9a-f]{8})[0-9a-f]{4}.*/#define WIREGUARD_GO_VERSION "\1"/p' "$<" > "$@"

$(DESTDIR)/libwg-go.a: $(foreach ARCH,$(ARCHS),$(BUILDDIR)/libwg-go-$(ARCH).a)
	@mkdir -vp "$(DESTDIR)"
	$(LIPO) -create -output "$@" $^

clean:
	rm -rf "$(BUILDDIR)" "$(DESTDIR)/libwg-go.a" "$(DESTDIR)/wireguard-go-version.h"

install: build

.PHONY: clean build docbuild _actual_build version-header install
