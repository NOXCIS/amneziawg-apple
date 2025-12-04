/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 AmneziaWG. All Rights Reserved.
 */

package main

// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
import "C"

import (
	"context"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

// UdpTlsPipeHandle represents a running udptlspipe client instance
type UdpTlsPipeHandle struct {
	cancel    context.CancelFunc
	localAddr string
	localPort int
	wg        sync.WaitGroup
}

var (
	handlesMu sync.Mutex
	handles         = make(map[int32]*UdpTlsPipeHandle)
	nextID    int32 = 1
)

//export udptlspipeSetLogger
func udptlspipeSetLogger(context unsafe.Pointer, loggerFn unsafe.Pointer) {
	loggerCtx = context
	loggerFunc = loggerFn
}

// udptlspipeStart starts a udptlspipe client.
// Parameters:
//   - destination: the remote server address (e.g., "server.example.com:443")
//   - password: the password for authentication (can be empty)
//   - tlsServerName: TLS server name for SNI (can be empty to use destination host)
//   - secure: if 1, enables TLS certificate verification
//   - proxy: proxy URL (can be empty)
//   - fingerprintProfile: TLS fingerprint profile ("chrome", "firefox", "safari", "edge", "okhttp", "ios", "randomized")
//   - listenPort: local port to listen on (0 for auto-assign)
//
// Returns: handle ID on success (>0), or negative error code on failure
//
//export udptlspipeStart
func udptlspipeStart(
	destination *C.char,
	password *C.char,
	tlsServerName *C.char,
	secure C.int,
	proxy *C.char,
	fingerprintProfile *C.char,
	listenPort C.int,
) C.int {
	logger := CLogger(0)

	destStr := C.GoString(destination)
	passwordStr := C.GoString(password)
	tlsServerNameStr := C.GoString(tlsServerName)
	proxyStr := C.GoString(proxy)
	fingerprintStr := C.GoString(fingerprintProfile)
	secureMode := secure != 0
	localPort := int(listenPort)

	// Default to okhttp if not specified
	if fingerprintStr == "" {
		fingerprintStr = "okhttp"
	}

	logger.Printf("udptlspipe: Starting client to %s (fingerprint: %s)", destStr, fingerprintStr)

	// Determine local listen address
	var listenAddr string
	if localPort > 0 {
		listenAddr = fmt.Sprintf("127.0.0.1:%d", localPort)
	} else {
		// Find a free port
		listener, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			setLastError(fmt.Errorf("failed to find free port: %w", err))
			logger.Printf("udptlspipe: Failed to find free port: %v", err)
			return -1
		}
		addr := listener.LocalAddr().(*net.UDPAddr)
		localPort = addr.Port
		listenAddr = fmt.Sprintf("127.0.0.1:%d", localPort)
		listener.Close()
	}

	logger.Printf("udptlspipe: Listening on %s, destination %s", listenAddr, destStr)

	ctx, cancel := context.WithCancel(context.Background())

	handle := &UdpTlsPipeHandle{
		cancel:    cancel,
		localAddr: listenAddr,
		localPort: localPort,
	}

	// Start the udptlspipe client in a goroutine
	handle.wg.Add(1)
	go func() {
		defer handle.wg.Done()
		err := runUdpTlsPipeClient(ctx, listenAddr, destStr, passwordStr, tlsServerNameStr, secureMode, proxyStr, fingerprintStr, logger)
		if err != nil && ctx.Err() == nil {
			setLastError(err)
			logger.Printf("udptlspipe: Client error: %v", err)
		}
		logger.Printf("udptlspipe: Client stopped")
	}()

	handlesMu.Lock()
	id := nextID
	nextID++
	handles[id] = handle
	handlesMu.Unlock()

	logger.Printf("udptlspipe: Started with handle %d, local port %d", id, localPort)
	return C.int(id)
}

// udptlspipeStop stops a running udptlspipe client.
// Parameters:
//   - handle: the handle ID returned by udptlspipeStart
//
//export udptlspipeStop
func udptlspipeStop(handle C.int) {
	logger := CLogger(0)
	id := int32(handle)

	handlesMu.Lock()
	h, ok := handles[id]
	if !ok {
		handlesMu.Unlock()
		logger.Printf("udptlspipe: Invalid handle %d", id)
		return
	}
	delete(handles, id)
	handlesMu.Unlock()

	logger.Printf("udptlspipe: Stopping handle %d", id)
	h.cancel()
	h.wg.Wait()
	logger.Printf("udptlspipe: Handle %d stopped", id)
}

// udptlspipeGetLocalPort returns the local port for a running client.
// Parameters:
//   - handle: the handle ID returned by udptlspipeStart
//
// Returns: local port number, or 0 if handle is invalid
//
//export udptlspipeGetLocalPort
func udptlspipeGetLocalPort(handle C.int) C.int {
	id := int32(handle)

	handlesMu.Lock()
	h, ok := handles[id]
	handlesMu.Unlock()

	if !ok {
		return 0
	}
	return C.int(h.localPort)
}

//export udptlspipeVersion
func udptlspipeVersion() *C.char {
	return C.CString("1.3.1")
}

// udptlspipeResetFingerprint resets the cached randomized fingerprint pair.
// This should be called when reconnecting to get a fresh fingerprint.
// Only useful when using the "randomized" fingerprint profile.
//
//export udptlspipeResetFingerprint
func udptlspipeResetFingerprint() {
	ResetRandomizedPair()
}

// Error handling for better debugging
var (
	lastErrorMu sync.Mutex
	lastError   string
)

func setLastError(err error) {
	lastErrorMu.Lock()
	defer lastErrorMu.Unlock()
	if err != nil {
		lastError = err.Error()
	} else {
		lastError = ""
	}
}

func getLastError() string {
	lastErrorMu.Lock()
	defer lastErrorMu.Unlock()
	return lastError
}

// udptlspipeGetLastError returns the last error message, if any.
// Returns NULL if there's no error. The caller should free the returned string.
//
//export udptlspipeGetLastError
func udptlspipeGetLastError() *C.char {
	err := getLastError()
	if err == "" {
		return nil
	}
	return C.CString(err)
}

// udptlspipeClearLastError clears the last error message.
//
//export udptlspipeClearLastError
func udptlspipeClearLastError() {
	setLastError(nil)
}

func main() {}
