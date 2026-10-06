// Copyright 2026 Stefan Meinecke <meinecke@greensec.de>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udp

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kzemek/go-mmproxy/internal/buffers"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

func udpTestConfig(closeAfter time.Duration) utils.Config {
	return utils.Config{
		Opts: &utils.Options{
			Protocol:      utils.UDP,
			ListenAddr:    netip.MustParseAddrPort("127.0.0.1:0"),
			TargetAddr4:   netip.MustParseAddrPort("127.0.0.1:9"),
			UDPCloseAfter: closeAfter,
		},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		BufferPool: buffers.New(),
	}
}

// An invalid PROXY source addr means the backend socket is dialed without a
// transparent local bind, so the test needs no CAP_NET_ADMIN.
func newConnInfo(
	t *testing.T, config utils.Config, closures chan netip.AddrPort,
) *connectionInfo {
	t.Helper()

	frontend, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to open frontend socket: %v", err)
	}
	t.Cleanup(func() { _ = frontend.Close() })

	connMap := make(map[netip.AddrPort]*connectionInfo)
	connInfo, err := getSocketFromMap(frontend,
		netip.MustParseAddrPort("127.0.0.1:1000"),
		netip.AddrPort{}, netip.AddrPort{},
		connMap, closures, config)
	if err != nil {
		t.Fatalf("getSocketFromMap failed: %v", err)
	}
	return connInfo
}

// -close-after 0 must disable inactivity cleanup instead of closing the
// socket ~immediately after creation.
func TestCloseAfterZeroDisablesCleanup(t *testing.T) {
	closures := make(chan netip.AddrPort, 1)
	connInfo := newConnInfo(t, udpTestConfig(0), closures)
	defer func() { _ = connInfo.backendConn.Close() }()

	time.Sleep(100 * time.Millisecond)

	select {
	case key := <-closures:
		t.Fatalf("socket closed despite -close-after 0 (key %v)", key)
	default:
	}
	if _, err := connInfo.backendConn.Write([]byte("x")); err != nil {
		t.Fatalf("backend socket closed despite -close-after 0: %v", err)
	}
}

// Positive control: a nonzero -close-after still expires the socket.
func TestCloseAfterExpires(t *testing.T) {
	closures := make(chan netip.AddrPort, 1)
	connInfo := newConnInfo(t, udpTestConfig(30*time.Millisecond), closures)

	select {
	case <-closures:
	case <-time.After(2 * time.Second):
		t.Fatal("socket was not closed after inactivity timeout")
	}
	if _, err := connInfo.backendConn.Write([]byte("x")); err == nil {
		t.Fatal("backend socket still writable after inactivity timeout")
	}
}

// AcceptLoop must return instead of busy-looping once the listener socket
// is closed.
func TestAcceptLoopReturnsOnListenerClose(t *testing.T) {
	config := udpTestConfig(time.Minute)
	listener, err := Listen(t.Context(), &net.ListenConfig{}, config)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- AcceptLoop(listener, config) }()

	if err := listener.Close(); err != nil {
		t.Fatalf("Failed to close listener: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("AcceptLoop returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AcceptLoop did not return after listener close")
	}
}
