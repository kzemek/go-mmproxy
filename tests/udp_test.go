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

	"github.com/kzemek/go-mmproxy/udp"
	"github.com/kzemek/go-mmproxy/utils"
)

func runUDPServer(t *testing.T, addr string, receivedData chan<- listenResult) {
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr)))
	if err != nil {
		t.Fatalf("Failed to listen on server: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	n, from, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Failed to read data: %v", err)
	}

	receivedData <- listenResult{
		data:  buf[:n],
		saddr: netip.MustParseAddrPort(from.String()),
	}
}

func TestListenUDP(t *testing.T) {
	opts := utils.Options{
		Protocol:       utils.UDP,
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
	go udp.Listen(ctx, &listenConfig, &opts, logger, errors)

	receivedData4 := make(chan listenResult, 1)
	go runUDPServer(t, "127.0.0.1:54323", receivedData4)

	time.Sleep(1 * time.Second)

	conn, err := net.Dial("udp", "127.0.0.1:12347")
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	buf := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	buf = append(buf, 0x21)            // PROXY
	buf = append(buf, 0x12)            // UDP4
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
