// Copyright 2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

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

type listenResult struct {
	message string
	saddr   netip.AddrPort
}

func TestMain(m *testing.M) {
	runGoMmproxy(tcpOpts())
	runGoMmproxy(udpOpts())
	os.Exit(m.Run())
}

func connectToGoMmproxy(t *testing.T, opts *utils.Options) net.Conn {
	protocol := "tcp"
	if opts.Protocol == utils.UDP {
		protocol = "udp"
	}

	conn, err := net.Dial(protocol, fmt.Sprintf("127.0.0.1:%d", opts.ListenAddr.Port()))
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func sendProxyV1Message(t *testing.T, conn net.Conn, opts *utils.Options,
	proxiedClientAddr string, proxiedServerAddr string, message string) {

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

func sendProxyV2Message(t *testing.T, conn net.Conn, opts *utils.Options,
	proxiedClientAddr string, proxiedServerAddr string, message string) {

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

func readData(t *testing.T, conn net.Conn) string {
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Failed to read data: %v", err)
	}
	return string(buf[:n])
}

func runGoMmproxy(opts *utils.Options) {
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

	var ln interface{}
	var err error
	if opts.Protocol == utils.TCP {
		ln, err = tcp.Listen(context.Background(), &net.ListenConfig{}, config)
	} else {
		ln, err = udp.Listen(context.Background(), &net.ListenConfig{}, config)
	}
	if err != nil {
		panic(fmt.Errorf("failed to bind listener: %w", err))
	}

	go func() {
		if opts.Protocol == utils.TCP {
			tcp.AcceptLoop(ln.(*net.TCPListener), config)
		} else {
			udp.AcceptLoop(ln.(*net.UDPConn), config)
		}
		panic("AcceptLoop returned")
	}()
}

func runTargetServer(t *testing.T, opts *utils.Options) <-chan listenResult {
	if opts.Protocol == utils.TCP {
		return runTcpTargetServer(t, opts.TargetAddr4)
	} else {
		return runUdpTargetServer(t, opts.TargetAddr4)
	}
}

func runTcpTargetServer(t *testing.T, targetAddr4 netip.AddrPort) <-chan listenResult {
	receivedData := make(chan listenResult, 10)

	server, err := net.Listen("tcp", targetAddr4.String())
	if err != nil {
		t.Fatalf("Failed to listen on server: %v", err)
	}
	t.Cleanup(func() { server.Close() })

	go tcpTargetServerProcess(t, server, receivedData)

	return receivedData
}

func tcpTargetServerProcess(t *testing.T, server net.Listener, receivedData chan<- listenResult) {
	conn, err := server.Accept()
	if err != nil {
		t.Errorf("Failed to accept connection: %v", err)
		return
	}

	buf := make([]byte, 1024)

	for {
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			t.Errorf("Failed to read data: %v", err)
			return
		}

		message := string(buf[:n])

		if _, err := fmt.Fprintf(conn, "response: %s", message); err != nil {
			t.Errorf("Failed to write data: %v", err)
			return
		}

		if err == io.EOF {
			break
		}

		receivedData <- listenResult{
			message: message,
			saddr:   netip.MustParseAddrPort(conn.RemoteAddr().String()),
		}
	}
}

func runUdpTargetServer(t *testing.T, targetAddr4 netip.AddrPort) <-chan listenResult {
	receivedData := make(chan listenResult, 10)

	server, err := net.ListenPacket("udp", targetAddr4.String())
	if err != nil {
		t.Fatalf("Failed to listen on server: %v", err)
	}
	t.Cleanup(func() { server.Close() })

	go udpTargetServerProcess(t, server, receivedData)

	return receivedData
}

func udpTargetServerProcess(t *testing.T, server net.PacketConn, receivedData chan<- listenResult) {
	buf := make([]byte, 1024)

	for {
		n, addr, err := server.ReadFrom(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			t.Errorf("Failed to read data: %v", err)
			return
		}

		message := string(buf[:n])

		receivedData <- listenResult{
			message: message,
			saddr:   netip.MustParseAddrPort(addr.String()),
		}
	}
}
