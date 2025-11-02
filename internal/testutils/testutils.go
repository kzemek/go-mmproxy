// Copyright 2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testutils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/kzemek/go-mmproxy/internal/buffers"
	"github.com/kzemek/go-mmproxy/internal/tcp"
	"github.com/kzemek/go-mmproxy/internal/udp"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

type ListenResult struct {
	Message string
	Saddr   netip.AddrPort
}

func ConnectToGoMmproxy(t *testing.T, opts *utils.Options) net.Conn {
	t.Helper()

	protocol := "tcp"
	if opts.Protocol == utils.UDP {
		protocol = "udp"
	}

	conn, err := net.Dial(protocol, fmt.Sprintf("127.0.0.1:%d", opts.ListenAddr.Port()))
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func SendProxyV1Message(t *testing.T, conn net.Conn, opts *utils.Options,
	proxiedClientAddr string, proxiedServerAddr string, message string) {
	t.Helper()

	proxiedClientAddrPort := netip.MustParseAddrPort(proxiedClientAddr)
	proxiedServerAddrPort := netip.MustParseAddrPort(proxiedServerAddr)

	protocol := "TCP4"
	if opts.Protocol == utils.UDP {
		protocol = "UDP4"
	}

	_, err := fmt.Fprintf(conn, "PROXY %s %s %s %d %d\r\n%s",
		protocol, proxiedClientAddrPort.Addr().String(), proxiedServerAddrPort.Addr().String(),
		proxiedClientAddrPort.Port(), proxiedServerAddrPort.Port(), message)

	if err != nil {
		t.Fatalf("Failed to send proxy message: %v", err)
	}
}

func SendProxyV2Message(t *testing.T, conn net.Conn, opts *utils.Options,
	proxiedClientAddr string, proxiedServerAddr string, message string) {
	t.Helper()

	proxiedClientAddrPort := netip.MustParseAddrPort(proxiedClientAddr)
	proxiedServerAddrPort := netip.MustParseAddrPort(proxiedServerAddr)

	proxiedClientAddrBytes := proxiedClientAddrPort.Addr().As4()
	proxiedServerAddrBytes := proxiedServerAddrPort.Addr().As4()

	buf := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	buf = append(buf, 0x21) // PROXY
	if opts.Protocol == utils.TCP {
		buf = append(buf, 0x11) // TCP4
	} else {
		buf = append(buf, 0x12) // UDP4
	}
	buf = append(buf, 0x00, 0x0C) // 12 bytes
	buf = append(buf, proxiedClientAddrBytes[:]...)
	buf = append(buf, proxiedServerAddrBytes[:]...)
	buf = append(buf, byte(proxiedClientAddrPort.Port()>>8), byte(proxiedClientAddrPort.Port()&0xFF))
	buf = append(buf, byte(proxiedServerAddrPort.Port()>>8), byte(proxiedServerAddrPort.Port()&0xFF))
	buf = append(buf, []byte(message)...)

	_, err := conn.Write(buf)
	if err != nil {
		t.Fatalf("Failed to send proxy message: %v", err)
	}
}

func ReadData(t *testing.T, conn net.Conn) string {
	t.Helper()

	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && errors.Is(err, io.EOF) {
		t.Fatalf("Failed to read data: %v", err)
	}
	return string(buf[:n])
}

func RunGoMmproxy(opts *utils.Options) {
	lvl := slog.LevelInfo
	if opts.Verbose > 0 {
		lvl = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))

	config := utils.Config{
		Opts:       opts,
		Logger:     logger,
		BufferPool: buffers.New(),
	}

	var listener any
	var err error
	if opts.Protocol == utils.TCP {
		listener, err = tcp.Listen(context.Background(), &net.ListenConfig{}, config)
	} else {
		listener, err = udp.Listen(context.Background(), &net.ListenConfig{}, config)
	}
	if err != nil {
		panic(fmt.Errorf("failed to bind listener: %w", err))
	}

	go func() {
		if opts.Protocol == utils.TCP {
			_ = tcp.AcceptLoop(listener.(*net.TCPListener), config)
		} else {
			_ = udp.AcceptLoop(listener.(*net.UDPConn), config)
		}
		panic("AcceptLoop returned")
	}()
}

func RunTargetServer(t *testing.T, opts *utils.Options) <-chan ListenResult {
	t.Helper()

	if opts.Protocol == utils.TCP {
		return RunTcpTargetServer(t, opts.TargetAddr4)
	} else {
		return RunUdpTargetServer(t, opts.TargetAddr4)
	}
}

func RunTcpTargetServer(t *testing.T, targetAddr4 netip.AddrPort) <-chan ListenResult {
	t.Helper()

	receivedData := make(chan ListenResult, 10)

	server, err := net.Listen("tcp", targetAddr4.String())
	if err != nil {
		t.Fatalf("Failed to listen on server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	go tcpTargetServerProcess(t, server, receivedData)

	return receivedData
}

func tcpTargetServerProcess(t *testing.T, server net.Listener, receivedData chan<- ListenResult) {
	t.Helper()

	conn, err := server.Accept()
	if err != nil {
		t.Errorf("Failed to accept connection: %v", err)
		return
	}

	buf := make([]byte, 1024)

	for {
		numBytesRead, err := conn.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("Failed to read data: %v", err)
			return
		}

		message := string(buf[:numBytesRead])

		if _, err := fmt.Fprintf(conn, "response: %s", message); err != nil {
			t.Errorf("Failed to write data: %v", err)
			return
		}

		if errors.Is(err, io.EOF) {
			break
		}

		receivedData <- ListenResult{
			Message: message,
			Saddr:   netip.MustParseAddrPort(conn.RemoteAddr().String()),
		}
	}
}

func RunUdpTargetServer(t *testing.T, targetAddr4 netip.AddrPort) <-chan ListenResult {
	t.Helper()

	receivedData := make(chan ListenResult, 10)

	server, err := net.ListenPacket("udp", targetAddr4.String())
	if err != nil {
		t.Fatalf("Failed to listen on server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	go udpTargetServerProcess(t, server, receivedData)

	return receivedData
}

func udpTargetServerProcess(t *testing.T, server net.PacketConn, receivedData chan<- ListenResult) {
	t.Helper()

	buf := make([]byte, 1024)

	for {
		numBytesRead, addr, err := server.ReadFrom(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			t.Errorf("Failed to read data: %v", err)
			return
		}

		message := string(buf[:numBytesRead])

		receivedData <- ListenResult{
			Message: message,
			Saddr:   netip.MustParseAddrPort(addr.String()),
		}
	}
}
