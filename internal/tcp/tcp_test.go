// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp_test

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/kzemek/go-mmproxy/internal/testutils"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

func TestMain(m *testing.M) {
	testutils.RunGoMmproxy(tcpOpts())
	os.Exit(m.Run())
}

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

	receivedData4 := testutils.RunTargetServer(t, opts)

	conn := testutils.ConnectToGoMmproxy(t, opts)
	testutils.SendProxyV1Message(t, conn, opts, "192.168.0.1:56324", "192.168.0.11:443", "moredata")

	result := <-receivedData4

	if got, want := result.Message, "moredata"; got != want {
		t.Errorf("result.message=%s, want=%s", got, want)
	}

	if got, want := result.Saddr.String(), "192.168.0.1:56324"; got != want {
		t.Errorf("result.saddr.String()=%s, want=%s", got, want)
	}
}

func TestListenTCP_unknown(t *testing.T) {
	opts := tcpOpts()

	receivedData4 := testutils.RunTargetServer(t, opts)

	conn := testutils.ConnectToGoMmproxy(t, opts)
	_, _ = conn.Write([]byte("PROXY UNKNOWN\r\nmoredata"))

	result := <-receivedData4

	if got, want := result.Message, "moredata"; got != want {
		t.Errorf("result.message=%s, want=%s", got, want)
	}

	if got, want := result.Saddr.Addr().String(), "127.0.0.1"; got != want {
		t.Errorf("result.saddr.Addr().String()=%s, want=%s", got, want)
	}
}

func TestListenTCP_proxyV2(t *testing.T) {
	opts := tcpOpts()

	receivedData4 := testutils.RunTargetServer(t, opts)

	conn := testutils.ConnectToGoMmproxy(t, opts)
	testutils.SendProxyV2Message(t, conn, opts, "192.168.0.1:56324", "192.168.0.11:443", "moredata")

	result := <-receivedData4

	if got, want := result.Message, "moredata"; got != want {
		t.Errorf("result.message=%s, want=%s", got, want)
	}

	if got, want := result.Saddr.String(), "192.168.0.1:56324"; got != want {
		t.Errorf("result.saddr.String()=%s, want=%s", got, want)
	}
}

func TestListenTCP_DynamicDestination(t *testing.T) {
	opts := tcpOpts()
	opts.ListenAddr = netip.MustParseAddrPort("0.0.0.0:12350")
	opts.DynamicDestination = true

	testutils.RunGoMmproxy(opts)

	// connect to a different port than the one in TargetAddr4
	proxyTargetAddr := netip.MustParseAddrPort("127.0.0.1:55443")
	receivedData4 := testutils.RunTcpTargetServer(t, proxyTargetAddr)

	conn := testutils.ConnectToGoMmproxy(t, opts)
	testutils.SendProxyV1Message(t, conn, opts, "192.168.0.1:56324", proxyTargetAddr.String(), "moredata")

	result := <-receivedData4

	if got, want := result.Message, "moredata"; got != want {
		t.Errorf("result.message=%s, want=%s", got, want)
	}

	if got, want := result.Saddr.String(), "192.168.0.1:56324"; got != want {
		t.Errorf("result.saddr.String()=%s, want=%s", got, want)
	}
}

func TestListenTCP_HalfClose(t *testing.T) {
	opts := tcpOpts()

	testutils.RunTargetServer(t, opts)

	conn := testutils.ConnectToGoMmproxy(t, opts)
	testutils.SendProxyV2Message(t, conn, opts, "192.168.0.1:56324", "192.168.0.11:443", "moredata")

	response := testutils.ReadData(t, conn)
	if got, want := response, "response: moredata"; got != want {
		t.Errorf("response=%s, want=%s", got, want)
	}

	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("Failed to close write side: %v", err)
	}

	finalResponse := testutils.ReadData(t, conn)
	if got, want := finalResponse, "response: "; got != want {
		t.Errorf("finalResponse=%s, want=%s", got, want)
	}
}
