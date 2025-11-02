// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udp_test

import (
	"net/netip"
	"os"
	"testing"

	"github.com/kzemek/go-mmproxy/internal/testutils"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

func udpOpts() *utils.Options {
	return &utils.Options{
		Protocol:       utils.UDP,
		ListenAddr:     netip.MustParseAddrPort("0.0.0.0:12347"),
		TargetAddr4:    netip.MustParseAddrPort("127.0.0.1:54323"),
		TargetAddr6:    netip.MustParseAddrPort("[::1]:54323"),
		Mark:           0,
		AllowedSubnets: nil,
		Verbose:        0,
	}
}

func TestMain(m *testing.M) {
	testutils.RunGoMmproxy(udpOpts())
	os.Exit(m.Run())
}

func TestListenUDP(t *testing.T) {
	opts := udpOpts()

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

func TestListenUDP_DynamicDestination(t *testing.T) {
	opts := udpOpts()

	opts.ListenAddr = netip.MustParseAddrPort("0.0.0.0:12348")
	opts.DynamicDestination = true

	testutils.RunGoMmproxy(opts)

	// connect to a different port than the one in TargetAddr4
	proxyTargetAddr := netip.MustParseAddrPort("127.0.0.1:55443")
	receivedData4 := testutils.RunUdpTargetServer(t, proxyTargetAddr)

	conn := testutils.ConnectToGoMmproxy(t, opts)
	testutils.SendProxyV2Message(
		t, conn, opts,
		"192.168.0.1:56324", proxyTargetAddr.String(), "moredata",
	)

	result := <-receivedData4

	if got, want := result.Message, "moredata"; got != want {
		t.Errorf("result.message=%s, want=%s", got, want)
	}

	if got, want := result.Saddr.String(), "192.168.0.1:56324"; got != want {
		t.Errorf("result.saddr.String()=%s, want=%s", got, want)
	}
}
