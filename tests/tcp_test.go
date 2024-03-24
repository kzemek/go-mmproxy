// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/kzemek/go-mmproxy/tcp"
	"github.com/kzemek/go-mmproxy/utils"
)

type listenResult struct {
	data  []byte
	saddr netip.AddrPort
}

func runServer(t *testing.T, addr string, receivedData chan<- listenResult) {
	server, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to listen on server: %v", err)
	}
	defer server.Close()

	conn, err := server.Accept()
	if err != nil {
		t.Fatalf("Failed to accept connection: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read data: %v", err)
	}

	receivedData <- listenResult{
		data:  buf[:n],
		saddr: netip.MustParseAddrPort(conn.RemoteAddr().String()),
	}
}

func TestListen(t *testing.T) {
	opts := utils.Options{
		Protocol:       utils.TCP,
		ListenAddr:     netip.MustParseAddrPort("0.0.0.0:12345"),
		TargetAddr4:    netip.MustParseAddrPort("127.0.0.1:54321"),
		TargetAddr6:    netip.MustParseAddrPort("[::1]:54321"),
		Mark:           0,
		AllowedSubnets: nil,
		Verbose:        2,
	}

	lvl := slog.LevelInfo
	if opts.Verbose > 0 {
		lvl = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))

	listenConfig := net.ListenConfig{}
	errors := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go tcp.Listen(ctx, &listenConfig, &opts, logger, errors)

	receivedData4 := make(chan listenResult, 1)
	go runServer(t, "127.0.0.1:54321", receivedData4)

	time.Sleep(1 * time.Second)

	conn, err := net.Dial("tcp", "127.0.0.1:12345")
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nmoredata"))
	result := <-receivedData4

	if !reflect.DeepEqual(result.data, []byte("moredata")) {
		t.Errorf("Unexpected data: %v", result.data)
	}

	if result.saddr.String() != "192.168.0.1:56324" {
		t.Errorf("Unexpected source address: %v", result.saddr)
	}
}

func TestListen_unknown(t *testing.T) {
	opts := utils.Options{
		Protocol:       utils.TCP,
		ListenAddr:     netip.MustParseAddrPort("0.0.0.0:12346"),
		TargetAddr4:    netip.MustParseAddrPort("127.0.0.1:54322"),
		TargetAddr6:    netip.MustParseAddrPort("[::1]:54322"),
		Mark:           0,
		AllowedSubnets: nil,
		Verbose:        2,
	}

	lvl := slog.LevelInfo
	if opts.Verbose > 0 {
		lvl = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))

	listenConfig := net.ListenConfig{}
	errors := make(chan error, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tcp.Listen(ctx, &listenConfig, &opts, logger, errors)

	receivedData4 := make(chan listenResult, 1)
	go runServer(t, "127.0.0.1:54322", receivedData4)

	time.Sleep(1 * time.Second)

	conn, err := net.Dial("tcp", "127.0.0.1:12346")
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("PROXY UNKNOWN\r\nmoredata"))
	result := <-receivedData4

	if !reflect.DeepEqual(result.data, []byte("moredata")) {
		t.Errorf("Unexpected data: %v", result.data)
	}

	if result.saddr.Addr().String() != "127.0.0.1" {
		t.Errorf("Unexpected source address: %v", result.saddr)
	}
}

func TestListen_proxyV2(t *testing.T) {
	opts := utils.Options{
		Protocol:       utils.TCP,
		ListenAddr:     netip.MustParseAddrPort("0.0.0.0:12347"),
		TargetAddr4:    netip.MustParseAddrPort("127.0.0.1:54323"),
		TargetAddr6:    netip.MustParseAddrPort("[::1]:54323"),
		Mark:           0,
		AllowedSubnets: nil,
		Verbose:        2,
	}

	lvl := slog.LevelInfo
	if opts.Verbose > 0 {
		lvl = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))

	listenConfig := net.ListenConfig{}
	errors := make(chan error, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tcp.Listen(ctx, &listenConfig, &opts, logger, errors)

	receivedData4 := make(chan listenResult, 1)
	go runServer(t, "127.0.0.1:54323", receivedData4)

	time.Sleep(1 * time.Second)

	conn, err := net.Dial("tcp", "127.0.0.1:12347")
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	buf := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	buf = append(buf, 0x21)            // PROXY
	buf = append(buf, 0x11)            // TCP4
	buf = append(buf, 0x00, 0x0C)      // 12 bytes
	buf = append(buf, 192, 168, 0, 1)  // saddr
	buf = append(buf, 192, 168, 0, 11) // daddr
	buf = append(buf, 0xDC, 0x04)      // sport 56324
	buf = append(buf, 0x01, 0xBB)      // dport 443
	buf = append(buf, []byte("moredata")...)

	conn.Write(buf)
	result := <-receivedData4

	if !reflect.DeepEqual(result.data, []byte("moredata")) {
		t.Errorf("Unexpected data: %v", result.data)
	}

	if result.saddr.String() != "192.168.0.1:56324" {
		t.Errorf("Unexpected source address: %v", result.saddr)
	}
}
