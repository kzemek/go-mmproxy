// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxyprotocol_test

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/kzemek/go-mmproxy/internal/proxyprotocol"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

func TestProxyProtocolV1(t *testing.T) {
	buf := []byte("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nmoredata")

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buf, utils.TCP)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if proxyHeader.SrcAddr.String() != "192.168.0.1:56324" {
		t.Errorf("Unexpected source address: %v", proxyHeader.SrcAddr)
	}

	if proxyHeader.DstAddr.String() != "192.168.0.11:443" {
		t.Errorf("Unexpected destination address: %v", proxyHeader.DstAddr)
	}

	if !reflect.DeepEqual(proxyHeader.TrailingData, []byte("moredata")) {
		t.Errorf("Unexpected rest: %v", proxyHeader.TrailingData)
	}
}

func TestProxyProtocolV1_nontcp(t *testing.T) {
	buf := []byte("PROXY UDP4 192.168.0.1 192.168.0.11 56324 443\r\nmoredata")

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buf, utils.TCP)
	if err == nil {
		t.Errorf("Error was expected, yet returned %v", proxyHeader)
	}
}

func TestProxyProtocolV1_Unknown(t *testing.T) {
	buf := []byte("PROXY UNKNOWN\r\nmoredata")

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buf, utils.TCP)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if proxyHeader.SrcAddr.IsValid() {
		t.Errorf("Unexpected source address: %v", proxyHeader.SrcAddr)
	}

	if proxyHeader.DstAddr.IsValid() {
		t.Errorf("Unexpected destination address: %v", proxyHeader.DstAddr)
	}

	if !reflect.DeepEqual(proxyHeader.TrailingData, []byte("moredata")) {
		t.Errorf("Unexpected rest: %v", proxyHeader.TrailingData)
	}
}

func TestProxyProtocolV1_UnknownWithAddrs(t *testing.T) {
	buf := []byte("PROXY UNKNOWN ffff::1 ffff::1 1234 1234\r\nmoredata")

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buf, utils.TCP)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if proxyHeader.SrcAddr.IsValid() {
		t.Errorf("Unexpected source address: %v", proxyHeader.SrcAddr)
	}

	if proxyHeader.DstAddr.IsValid() {
		t.Errorf("Unexpected destination address: %v", proxyHeader.DstAddr)
	}

	if !reflect.DeepEqual(proxyHeader.TrailingData, []byte("moredata")) {
		t.Errorf("Unexpected rest: %v", proxyHeader.TrailingData)
	}
}

func TestProxyProtocolV1_ExtraTokens(t *testing.T) {
	buf := []byte("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443 extra\r\nmoredata")

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buf, utils.TCP)
	if err == nil {
		t.Errorf("Error was expected, yet returned %v", proxyHeader)
	}
}

func TestProxyProtocolV1_ProtocolAddrMismatch(t *testing.T) {
	buf := []byte("PROXY TCP4 2001:db8::1 2001:db8::2 56324 443\r\nmoredata")

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buf, utils.TCP)
	if err == nil {
		t.Errorf("Error was expected, yet returned %v", proxyHeader)
	}
	if !errors.Is(err, proxyprotocol.ErrProtocolAddrMismatch) {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestProxyProtocolV2(t *testing.T) {
	buf := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	buf = append(buf, 0x21)            // PROXY
	buf = append(buf, 0x11)            // TCP4
	buf = append(buf, 0x00, 0x0C)      // 12 bytes
	buf = append(buf, 192, 168, 0, 1)  // saddr
	buf = append(buf, 192, 168, 0, 11) // daddr
	buf = append(buf, 0xDC, 0x04)      // sport 56324
	buf = append(buf, 0x01, 0xBB)      // dport 443
	buf = append(buf, []byte("moredata")...)

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buf, utils.TCP)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if proxyHeader.SrcAddr.String() != "192.168.0.1:56324" {
		t.Errorf("Unexpected source address: %v", proxyHeader.SrcAddr)
	}

	if proxyHeader.DstAddr.String() != "192.168.0.11:443" {
		t.Errorf("Unexpected destination address: %v", proxyHeader.DstAddr)
	}

	if !reflect.DeepEqual(proxyHeader.TrailingData, []byte("moredata")) {
		t.Errorf("Unexpected rest: %v", proxyHeader.TrailingData)
	}
}

func TestProxyProtocolV2_ShortIPv4AddressData(t *testing.T) {
	buf := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	buf = append(buf, 0x21)                  // PROXY
	buf = append(buf, 0x11)                  // TCP4
	buf = append(buf, 0x00, 0x08)            // 8 bytes
	buf = append(buf, 192, 168, 0, 1)        // saddr
	buf = append(buf, 192, 168, 0, 11)       // daddr
	buf = append(buf, []byte("moredata")...) // trailing data

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buf, utils.TCP)
	if err == nil {
		t.Errorf("Error was expected, yet returned %v", proxyHeader)
	}
	if !errors.Is(err, proxyprotocol.ErrInvalidAddressDataLength) {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestProxyProtocolV2_ZeroAddressDataLength(t *testing.T) {
	buf := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	buf = append(buf, 0x21)       // PROXY
	buf = append(buf, 0x11)       // TCP4
	buf = append(buf, 0x00, 0x00) // 0 bytes
	buf = append(buf, []byte("moredata")...)

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buf, utils.TCP)
	if err == nil {
		t.Errorf("Error was expected, yet returned %v", proxyHeader)
	}
	if !errors.Is(err, proxyprotocol.ErrInvalidAddressDataLength) {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestProxyProtocolV2_udp6(t *testing.T) {
	expectedSaddr := netip.MustParseAddr("2001:db8::1")
	expectedDaddr := netip.MustParseAddr("2001:db8::2")

	buf := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	buf = append(buf, 0x21)       // PROXY
	buf = append(buf, 0x22)       // UDP6
	buf = append(buf, 0x00, 0x24) // 36 bytes
	buf = append(buf, expectedSaddr.AsSlice()...)
	buf = append(buf, expectedDaddr.AsSlice()...)
	buf = append(buf, 0xDC, 0x04) // sport 56324
	buf = append(buf, 0x01, 0xBB) // dport 443
	buf = append(buf, []byte("moredata")...)

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buf, utils.UDP)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if proxyHeader.SrcAddr != netip.AddrPortFrom(expectedSaddr, 56324) {
		t.Errorf("Unexpected source address: %v", proxyHeader.SrcAddr)
	}

	if proxyHeader.DstAddr != netip.AddrPortFrom(expectedDaddr, 443) {
		t.Errorf("Unexpected destination address: %v", proxyHeader.DstAddr)
	}

	if !reflect.DeepEqual(proxyHeader.TrailingData, []byte("moredata")) {
		t.Errorf("Unexpected rest: %v", proxyHeader.TrailingData)
	}
}

func TestProxyProtocolV2_ShortIPv6AddressData(t *testing.T) {
	expectedSaddr := netip.MustParseAddr("2001:db8::1")
	expectedDaddr := netip.MustParseAddr("2001:db8::2")

	buf := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	buf = append(buf, 0x21)       // PROXY
	buf = append(buf, 0x22)       // UDP6
	buf = append(buf, 0x00, 0x20) // 32 bytes
	buf = append(buf, expectedSaddr.AsSlice()...)
	buf = append(buf, expectedDaddr.AsSlice()...)

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buf, utils.UDP)
	if err == nil {
		t.Errorf("Error was expected, yet returned %v", proxyHeader)
	}
	if !errors.Is(err, proxyprotocol.ErrInvalidAddressDataLength) {
		t.Errorf("Unexpected error: %v", err)
	}
}
