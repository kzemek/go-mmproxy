// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"net"
	"net/netip"
	"testing"

	"github.com/kzemek/go-mmproxy/internal/utils"
)

func tcpOpts() *utils.Options {
	return &utils.Options{
		Protocol:       utils.TCP,
		ListenAddr:     netip.MustParseAddrPort("0.0.0.0:12345"),
		TargetAddr4:    netip.MustParseAddrPort("127.0.0.1:54321"),
		TargetAddr6:    netip.MustParseAddrPort("[::1]:54321"),
		Mark:           0,
		AllowedSubnets: nil,
		Verbose:        0,
	}
}

func TestListenTCP(t *testing.T) {
	opts := tcpOpts()

	receivedData4 := runTargetServer(t, opts)

	conn := connectToGoMmproxy(t, opts)
	sendProxyV1Message(t, conn, opts, "192.168.0.1:56324", "192.168.0.11:443", "moredata")

	result := <-receivedData4

	if got, want := result.message, "moredata"; got != want {
		t.Errorf("result.message=%s, want=%s", got, want)
	}

	if got, want := result.saddr.String(), "192.168.0.1:56324"; got != want {
		t.Errorf("result.saddr.String()=%s, want=%s", got, want)
	}
}

func TestListenTCP_unknown(t *testing.T) {
	opts := tcpOpts()

	receivedData4 := runTargetServer(t, opts)

	conn := connectToGoMmproxy(t, opts)
	conn.Write([]byte("PROXY UNKNOWN\r\nmoredata"))

	result := <-receivedData4

	if got, want := result.message, "moredata"; got != want {
		t.Errorf("result.message=%s, want=%s", got, want)
	}

	if got, want := result.saddr.Addr().String(), "127.0.0.1"; got != want {
		t.Errorf("result.saddr.Addr().String()=%s, want=%s", got, want)
	}
}

func TestListenTCP_proxyV2(t *testing.T) {
	opts := tcpOpts()

	receivedData4 := runTargetServer(t, opts)

	conn := connectToGoMmproxy(t, opts)
	sendProxyV2Message(t, conn, opts, "192.168.0.1:56324", "192.168.0.11:443", "moredata")

	result := <-receivedData4

	if got, want := result.message, "moredata"; got != want {
		t.Errorf("result.message=%s, want=%s", got, want)
	}

	if got, want := result.saddr.String(), "192.168.0.1:56324"; got != want {
		t.Errorf("result.saddr.String()=%s, want=%s", got, want)
	}
}

func TestListenTCP_DynamicDestination(t *testing.T) {
	opts := tcpOpts()
	opts.ListenAddr = netip.MustParseAddrPort("0.0.0.0:12350")
	opts.DynamicDestination = true

	runGoMmproxy(opts)

	// connect to a different port than the one in TargetAddr4
	proxyTargetAddr := netip.MustParseAddrPort("127.0.0.1:55443")
	receivedData4 := runTcpTargetServer(t, proxyTargetAddr)

	conn := connectToGoMmproxy(t, opts)
	sendProxyV1Message(t, conn, opts, "192.168.0.1:56324", proxyTargetAddr.String(), "moredata")

	result := <-receivedData4

	if got, want := result.message, "moredata"; got != want {
		t.Errorf("result.message=%s, want=%s", got, want)
	}

	if got, want := result.saddr.String(), "192.168.0.1:56324"; got != want {
		t.Errorf("result.saddr.String()=%s, want=%s", got, want)
	}
}

func TestListenTCP_HalfClose(t *testing.T) {
	opts := tcpOpts()

	runTargetServer(t, opts)

	conn := connectToGoMmproxy(t, opts)
	sendProxyV2Message(t, conn, opts, "192.168.0.1:56324", "192.168.0.11:443", "moredata")

	response := readData(t, conn)
	if got, want := response, "response: moredata"; got != want {
		t.Errorf("response=%s, want=%s", got, want)
	}

	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("Failed to close write side: %v", err)
	}

	finalResponse := readData(t, conn)
	if got, want := finalResponse, "response: "; got != want {
		t.Errorf("finalResponse=%s, want=%s", got, want)
	}
}
