/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
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
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/gorilla/websocket"
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

type tunnelHandle struct {
	*device.Device
	*device.Logger
}

var tunnelHandles = make(map[int32]tunnelHandle)

func init() {
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)

	err = dev.IpcSet(C.GoString(settings))
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	dev.Up()
	logger.Verbosef("Device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		unix.Close(dupTunFd)
		return -1
	}
	tunnelHandles[i] = tunnelHandle{dev, logger}
	return i
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	delete(tunnelHandles, tunnelHandle)
	dev.Close()
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return 0
	}
	err := dev.IpcSet(C.GoString(settings))
	if err != nil {
		dev.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	device, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}
	settings, err := device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := dev.BindUpdate()
			if err == nil {
				dev.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			dev.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		dev.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()
}

//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/amnezia-vpn/amneziawg-go" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

// UdpTlsPipe code - separate logger variables to avoid conflicts
var udptlspipeLoggerFunc unsafe.Pointer
var udptlspipeLoggerCtx unsafe.Pointer

type UdpTlsPipeLogger int

func (l UdpTlsPipeLogger) Printf(format string, args ...interface{}) {
	if uintptr(udptlspipeLoggerFunc) == 0 {
		return
	}
	C.callLogger(udptlspipeLoggerFunc, udptlspipeLoggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

// UdpTlsPipeHandle represents a running udptlspipe client instance
type UdpTlsPipeHandle struct {
	cancel    context.CancelFunc
	localAddr string
	localPort int
	wg        sync.WaitGroup
}

var (
	udptlspipeHandlesMu sync.Mutex
	udptlspipeHandles         = make(map[int32]*UdpTlsPipeHandle)
	udptlspipeNextID    int32 = 1
)

//export udptlspipeSetLogger
func udptlspipeSetLogger(context unsafe.Pointer, loggerFn unsafe.Pointer) {
	udptlspipeLoggerCtx = context
	udptlspipeLoggerFunc = loggerFn
}

//export udptlspipeStart
func udptlspipeStart(
	destination *C.char,
	password *C.char,
	tlsServerName *C.char,
	secure C.int,
	proxy *C.char,
	listenPort C.int,
) C.int {
	logger := UdpTlsPipeLogger(0)

	destStr := C.GoString(destination)
	passwordStr := C.GoString(password)
	tlsServerNameStr := C.GoString(tlsServerName)
	proxyStr := C.GoString(proxy)
	secureMode := secure != 0
	localPort := int(listenPort)

	logger.Printf("udptlspipe: Starting client to %s", destStr)

	// Determine local listen address
	var listenAddr string
	if localPort > 0 {
		listenAddr = fmt.Sprintf("127.0.0.1:%d", localPort)
	} else {
		// Find a free port
		listener, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
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
		err := runUdpTlsPipeClient(ctx, listenAddr, destStr, passwordStr, tlsServerNameStr, secureMode, proxyStr, logger)
		if err != nil && ctx.Err() == nil {
			logger.Printf("udptlspipe: Client error: %v", err)
		}
		logger.Printf("udptlspipe: Client stopped")
	}()

	udptlspipeHandlesMu.Lock()
	id := udptlspipeNextID
	udptlspipeNextID++
	udptlspipeHandles[id] = handle
	udptlspipeHandlesMu.Unlock()

	logger.Printf("udptlspipe: Started with handle %d, local port %d", id, localPort)
	return C.int(id)
}

//export udptlspipeStop
func udptlspipeStop(handle C.int) {
	logger := UdpTlsPipeLogger(0)
	id := int32(handle)

	udptlspipeHandlesMu.Lock()
	h, ok := udptlspipeHandles[id]
	if !ok {
		udptlspipeHandlesMu.Unlock()
		logger.Printf("udptlspipe: Invalid handle %d", id)
		return
	}
	delete(udptlspipeHandles, id)
	udptlspipeHandlesMu.Unlock()

	logger.Printf("udptlspipe: Stopping handle %d", id)
	h.cancel()
	h.wg.Wait()
	logger.Printf("udptlspipe: Handle %d stopped", id)
}

//export udptlspipeGetLocalPort
func udptlspipeGetLocalPort(handle C.int) C.int {
	id := int32(handle)

	udptlspipeHandlesMu.Lock()
	h, ok := udptlspipeHandles[id]
	udptlspipeHandlesMu.Unlock()

	if !ok {
		return 0
	}
	return C.int(h.localPort)
}

//export udptlspipeVersion
func udptlspipeVersion() *C.char {
	return C.CString("1.3.1")
}

// UdpTlsPipe client implementation
const (
	udptlspipeWsPath       = "/ws"
	udptlspipeBufferSize   = 65535
	udptlspipeDialTimeout  = 30 * time.Second
	udptlspipeWriteTimeout = 10 * time.Second
	udptlspipePingInterval = 30 * time.Second
)

func runUdpTlsPipeClient(
	ctx context.Context,
	listenAddr string,
	destination string,
	password string,
	tlsServerName string,
	secure bool,
	proxyURL string,
	logger UdpTlsPipeLogger,
) error {
	// Parse destination to get host for TLS
	destHost, _, err := net.SplitHostPort(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %w", err)
	}

	// Use provided TLS server name or destination host
	serverName := tlsServerName
	if serverName == "" {
		serverName = destHost
	}

	// Start UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer udpConn.Close()

	logger.Printf("udptlspipe: UDP listener started on %s", listenAddr)

	// Track client sessions (one WebSocket per UDP client)
	sessions := &udptlspipeSessionManager{
		sessions: make(map[string]*udptlspipeClientSession),
		logger:   logger,
	}
	defer sessions.closeAll()

	// Create a channel for stopping
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		udpConn.Close()
		close(done)
	}()

	buf := make([]byte, udptlspipeBufferSize)
	for {
		select {
		case <-done:
			return nil
		default:
		}

		// Set read deadline to allow checking for context cancellation
		udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			logger.Printf("udptlspipe: UDP read error: %v", err)
			continue
		}

		// Get or create session for this client
		session := sessions.getOrCreate(clientAddr.String(), func() *udptlspipeClientSession {
			return newUdpTlsPipeClientSession(
				ctx,
				clientAddr,
				udpConn,
				destination,
				serverName,
				password,
				secure,
				proxyURL,
				logger,
			)
		})

		if session == nil {
			continue
		}

		// Send data through WebSocket
		data := make([]byte, n)
		copy(data, buf[:n])
		session.send(data)
	}
}

type udptlspipeSessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*udptlspipeClientSession
	logger   UdpTlsPipeLogger
}

func (m *udptlspipeSessionManager) getOrCreate(key string, create func() *udptlspipeClientSession) *udptlspipeClientSession {
	m.mu.RLock()
	session, ok := m.sessions[key]
	m.mu.RUnlock()

	if ok && session.isAlive() {
		return session
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	session, ok = m.sessions[key]
	if ok && session.isAlive() {
		return session
	}

	// Create new session
	session = create()
	if session != nil {
		m.sessions[key] = session
	}
	return session
}

func (m *udptlspipeSessionManager) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, session := range m.sessions {
		session.close()
	}
	m.sessions = make(map[string]*udptlspipeClientSession)
}

type udptlspipeClientSession struct {
	ctx        context.Context
	cancel     context.CancelFunc
	clientAddr *net.UDPAddr
	udpConn    *net.UDPConn
	wsConn     *websocket.Conn
	wsMu       sync.Mutex
	sendCh     chan []byte
	logger     UdpTlsPipeLogger
	alive      bool
	aliveMu    sync.RWMutex
}

func newUdpTlsPipeClientSession(
	parentCtx context.Context,
	clientAddr *net.UDPAddr,
	udpConn *net.UDPConn,
	destination string,
	serverName string,
	password string,
	secure bool,
	proxyURL string,
	logger UdpTlsPipeLogger,
) *udptlspipeClientSession {
	ctx, cancel := context.WithCancel(parentCtx)

	session := &udptlspipeClientSession{
		ctx:        ctx,
		cancel:     cancel,
		clientAddr: clientAddr,
		udpConn:    udpConn,
		sendCh:     make(chan []byte, 256),
		logger:     logger,
		alive:      true,
	}

	// Connect to server in a goroutine
	go session.run(destination, serverName, password, secure, proxyURL)

	return session
}

func (s *udptlspipeClientSession) run(destination, serverName, password string, secure bool, proxyURL string) {
	defer func() {
		s.aliveMu.Lock()
		s.alive = false
		s.aliveMu.Unlock()
		s.cancel()
	}()

	// Build WebSocket URL
	wsURL := fmt.Sprintf("wss://%s%s", destination, udptlspipeWsPath)
	if password != "" {
		wsURL = fmt.Sprintf("%s?p=%s", wsURL, url.QueryEscape(password))
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: !secure,
	}

	// Configure dialer
	dialer := websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: udptlspipeDialTimeout,
	}

	// Configure proxy if specified
	if proxyURL != "" {
		proxyURLParsed, err := url.Parse(proxyURL)
		if err == nil {
			dialer.Proxy = http.ProxyURL(proxyURLParsed)
		} else {
			s.logger.Printf("udptlspipe: Invalid proxy URL: %v", err)
		}
	}

	s.logger.Printf("udptlspipe: Connecting to %s (SNI: %s)", destination, serverName)

	// Connect to WebSocket server
	headers := http.Header{}
	headers.Set("User-Agent", "okhttp/4.9.3")

	conn, _, err := dialer.DialContext(s.ctx, wsURL, headers)
	if err != nil {
		s.logger.Printf("udptlspipe: Failed to connect: %v", err)
		return
	}
	defer conn.Close()

	s.wsMu.Lock()
	s.wsConn = conn
	s.wsMu.Unlock()

	s.logger.Printf("udptlspipe: Connected to %s", destination)

	// Start writer goroutine
	go s.writer()

	// Start ping goroutine
	go s.pinger()

	// Read from WebSocket and send to UDP client
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			if s.ctx.Err() == nil && err != io.EOF {
				s.logger.Printf("udptlspipe: WebSocket read error: %v", err)
			}
			return
		}

		_, err = s.udpConn.WriteToUDP(data, s.clientAddr)
		if err != nil {
			s.logger.Printf("udptlspipe: UDP write error: %v", err)
		}
	}
}

func (s *udptlspipeClientSession) writer() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case data := <-s.sendCh:
			s.wsMu.Lock()
			if s.wsConn != nil {
				s.wsConn.SetWriteDeadline(time.Now().Add(udptlspipeWriteTimeout))
				err := s.wsConn.WriteMessage(websocket.BinaryMessage, data)
				if err != nil {
					s.logger.Printf("udptlspipe: WebSocket write error: %v", err)
				}
			}
			s.wsMu.Unlock()
		}
	}
}

func (s *udptlspipeClientSession) pinger() {
	ticker := time.NewTicker(udptlspipePingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.wsMu.Lock()
			if s.wsConn != nil {
				s.wsConn.SetWriteDeadline(time.Now().Add(udptlspipeWriteTimeout))
				err := s.wsConn.WriteMessage(websocket.PingMessage, nil)
				if err != nil {
					s.logger.Printf("udptlspipe: Ping error: %v", err)
				}
			}
			s.wsMu.Unlock()
		}
	}
}

func (s *udptlspipeClientSession) send(data []byte) {
	select {
	case s.sendCh <- data:
	default:
		// Channel full, drop packet
		s.logger.Printf("udptlspipe: Send channel full, dropping packet")
	}
}

func (s *udptlspipeClientSession) isAlive() bool {
	s.aliveMu.RLock()
	defer s.aliveMu.RUnlock()
	return s.alive
}

func (s *udptlspipeClientSession) close() {
	s.cancel()
	s.wsMu.Lock()
	if s.wsConn != nil {
		s.wsConn.Close()
	}
	s.wsMu.Unlock()
}

func main() {}
