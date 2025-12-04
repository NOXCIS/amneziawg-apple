# SPDX-License-Identifier: MIT
#
# Copyright (C) 2024 AmneziaWG. All Rights Reserved.

# These are generally passed to us by xcode, but we set working defaults for standalone compilation too.
ARCHS ?= x86_64 arm64
PLATFORM_NAME ?= macosx
SDKROOT ?= $(shell xcrun --sdk $(PLATFORM_NAME) --show-sdk-path)
CONFIGURATION_BUILD_DIR ?= $(CURDIR)/out
CONFIGURATION_TEMP_DIR ?= $(CURDIR)/.tmp

export PATH := $(PATH):/usr/local/bin:/opt/homebrew/bin
export CC ?= clang
LIPO ?= lipo
DESTDIR ?= $(CONFIGURATION_BUILD_DIR)
BUILDDIR ?= $(CONFIGURATION_TEMP_DIR)/udptlspipe-bridge

CFLAGS_PREFIX := $(if $(DEPLOYMENT_TARGET_CLANG_FLAG_NAME),-$(DEPLOYMENT_TARGET_CLANG_FLAG_NAME)=$($(DEPLOYMENT_TARGET_CLANG_ENV_NAME)),) -isysroot $(SDKROOT) -arch
GOARCH_arm64 := arm64
GOARCH_x86_64 := amd64
GOOS_macosx := darwin
GOOS_iphoneos := ios

# Default target - handle gracefully for documentation builds
.PHONY: build docbuild

# Build target that checks at runtime if it should actually build
build:
	@if [ "$(ACTION)" != "build" ] && [ -n "$(ACTION)" ]; then \
		echo "Skipping build for action: $(ACTION)"; \
		exit 0; \
	fi
	@$(MAKE) -f $(firstword $(MAKEFILE_LIST)) _actual_build

# Documentation build target - no-op for doc generation
docbuild:
	@echo "Skipping build for documentation generation"
	@exit 0

# Actual build target (internal)
_actual_build: $(DESTDIR)/libudptlspipe.a

version-header: $(DESTDIR)/udptlspipe-version.h

REAL_GOROOT := $(shell go env GOROOT 2>/dev/null)
export GOROOT := $(BUILDDIR)/goroot
$(GOROOT)/.prepared:
	[ -n "$(REAL_GOROOT)" ]
	mkdir -p "$(GOROOT)"
	rsync -a --delete --exclude=pkg/obj/go-build "$(REAL_GOROOT)/" "$(GOROOT)/"
	touch "$@"

define libudptlspipe-a
$(BUILDDIR)/libudptlspipe-$(1).a: export CGO_ENABLED := 1
$(BUILDDIR)/libudptlspipe-$(1).a: export CGO_CFLAGS := $(CFLAGS_PREFIX) $(ARCH)
$(BUILDDIR)/libudptlspipe-$(1).a: export CGO_LDFLAGS := $(CFLAGS_PREFIX) $(ARCH)
$(BUILDDIR)/libudptlspipe-$(1).a: export GOOS := $(GOOS_$(PLATFORM_NAME))
$(BUILDDIR)/libudptlspipe-$(1).a: export GOARCH := $(GOARCH_$(1))
$(BUILDDIR)/libudptlspipe-$(1).a: $(GOROOT)/.prepared go.mod
	go build -ldflags=-w -trimpath -v -o "$(BUILDDIR)/libudptlspipe-$(1).a" -buildmode c-archive
	rm -f "$(BUILDDIR)/libudptlspipe-$(1).h"
endef
$(foreach ARCH,$(ARCHS),$(eval $(call libudptlspipe-a,$(ARCH))))

$(DESTDIR)/udptlspipe-version.h: go.mod $(GOROOT)/.prepared
	echo '#define UDPTLSPIPE_VERSION "1.3.1"' > "$@"

$(DESTDIR)/libudptlspipe.a: $(foreach ARCH,$(ARCHS),$(BUILDDIR)/libudptlspipe-$(ARCH).a)
	@mkdir -vp "$(DESTDIR)"
	$(LIPO) -create -output "$@" $^

clean:
	rm -rf "$(BUILDDIR)" "$(DESTDIR)/libudptlspipe.a" "$(DESTDIR)/udptlspipe-version.h"

install: build

.PHONY: clean build docbuild _actual_build version-header install

