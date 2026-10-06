// Copyright 2026 Stefan Meinecke <meinecke@greensec.de>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udp_test

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kzemek/go-mmproxy/internal/buffers"
	"github.com/kzemek/go-mmproxy/internal/udp"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

// localProxyHeader builds a PROXY v2 header with command LOCAL, which is
// accepted without a source address, so the backend dial needs no
// IP_TRANSPARENT bind and the test can run unprivileged.
func localProxyHeader(payload string) []byte {
	buf := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51,
		0x55, 0x49, 0x54, 0x0A, 0x20, 0x00, 0x00, 0x00,
	}
	return append(buf, payload...)
}

func startUDPEchoBackend(t *testing.T) net.PacketConn {
	t.Helper()

	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start echo backend: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	go func() {
		buf := make([]byte, 65535)
		for {
			numBytesRead, addr, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteTo(buf[:numBytesRead], addr)
		}
	}()

	return backend
}

// A zero-length datagram from the backend must not terminate the
// backend->frontend reader goroutine. Previously copyFromBackend returned on
// the first empty datagram or transient socket error, leaving the connection
// in the map while silently dropping all subsequent replies.
func TestListenUDP_EmptyBackendDatagram(t *testing.T) {
	backend := startUDPEchoBackend(t)

	opts := udpOpts()
	opts.ListenAddr = netip.MustParseAddrPort("127.0.0.1:0")
	opts.TargetAddr4 = netip.MustParseAddrPort(backend.LocalAddr().String())
	opts.UDPCloseAfter = time.Minute

	config := utils.Config{
		Opts:       opts,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		BufferPool: buffers.New(),
	}

	listener, err := udp.Listen(t.Context(), &net.ListenConfig{}, config)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() { _ = udp.AcceptLoop(listener, config) }()

	frontend, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to open frontend socket: %v", err)
	}
	t.Cleanup(func() { _ = frontend.Close() })

	buf := make([]byte, 1500)
	exchange := func(payload string) string {
		t.Helper()
		if _, err := frontend.WriteTo(localProxyHeader(payload), listener.LocalAddr()); err != nil {
			t.Fatalf("Failed to send packet: %v", err)
		}
		_ = frontend.SetReadDeadline(time.Now().Add(2 * time.Second))
		numBytesRead, _, err := frontend.ReadFrom(buf)
		if err != nil {
			t.Fatalf("No reply for %q: %v", payload, err)
		}
		return string(buf[:numBytesRead])
	}

	if got, want := exchange("hello"), "hello"; got != want {
		t.Fatalf("reply=%q, want=%q", got, want)
	}

	// empty payload -> backend echoes an empty datagram
	if got := exchange(""); got != "" {
		t.Fatalf("reply=%q, want empty datagram", got)
	}

	// the reader goroutine must still be alive after the empty datagram
	if got, want := exchange("world"), "world"; got != want {
		t.Fatalf("reply=%q after empty datagram, want=%q", got, want)
	}
}
