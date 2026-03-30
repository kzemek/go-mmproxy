// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024-2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxyprotocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/kzemek/go-mmproxy/internal/utils"
)

var (
	// Proxy Protocol V2 errors
	ErrUnknownProcotolVersion   = errors.New("unknown protocol version")
	ErrUnknownCommand           = errors.New("unknown command")
	ErrInvalidFamily            = errors.New("invalid family")
	ErrInvalidProtocol          = errors.New("invalid protocol")
	ErrDecodeAddressDataLength  = errors.New("failed to decode address data length")
	ErrInvalidAddressDataLength = errors.New("invalid address data length")
	ErrIncompleteProxyHeader    = errors.New("incomplete PROXY header")
	ErrDecodeSourcePort         = errors.New("failed to decode source port")
	ErrDecodeDestinationPort    = errors.New("failed to decode destination port")

	// Proxy Protocol V1 errors
	ErrNoTerminator            = errors.New("did not find \\r\\n in first data segment")
	ErrInvalidFormat           = errors.New("failed to decode elements")
	ErrUnknownProtocol         = errors.New("unknown protocol")
	ErrParseSourceAddress      = errors.New("failed to parse source address")
	ErrParseDestinationAddress = errors.New("failed to parse destination address")
	ErrParseAddress            = errors.New("failed to parse address")
	ErrProtocolAddrMismatch    = errors.New("protocol address mismatch")

	// Common errors
	ErrInvalidSourcePort      = errors.New("invalid source port")
	ErrInvalidDestinationPort = errors.New("invalid destination port")

	// Parent errors
	ErrProxyProtocolV1      = errors.New("v1")
	ErrProxyProtocolV2      = errors.New("v2")
	ErrProxyProtocolMissing = errors.New("PROXY header missing")
)

type proxyHeader struct {
	SrcAddr      netip.AddrPort
	DstAddr      netip.AddrPort
	TrailingData []byte
}

// PROXY Protocol V2 constants
const (
	commandLocal = 0
	commandProxy = 1

	addressFamilyInet  = 1
	addressFamilyInet6 = 2

	protocolStream = 1
	protocolDgram  = 2
)

//gocyclo:ignore
func readRemoteAddrPROXYv2(ctrlBuf []byte, expectedProtocol utils.Protocol) (*proxyHeader, error) {
	protocolVersion := (ctrlBuf[12] >> 4)
	if protocolVersion != 2 {
		return nil, fmt.Errorf("%w %d", ErrUnknownProcotolVersion, protocolVersion)
	}

	command := ctrlBuf[12] & 0xF
	if command > 1 {
		return nil, fmt.Errorf("%w %d", ErrUnknownCommand, command)
	}

	addressFamily := ctrlBuf[13] >> 4
	protocol := ctrlBuf[13] & 0xF

	if command == commandProxy {
		if addressFamily != addressFamilyInet && addressFamily != addressFamilyInet6 {
			return nil, fmt.Errorf("%w %d", ErrInvalidFamily, addressFamily)
		}
		if (expectedProtocol == utils.TCP && protocol != protocolStream) ||
			(expectedProtocol == utils.UDP && protocol != protocolDgram) {
			return nil, fmt.Errorf("%w %d", ErrInvalidProtocol, protocol)
		}
	}

	var dataLen uint16
	reader := bytes.NewReader(ctrlBuf[14:16])
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeAddressDataLength, err)
	}

	if len(ctrlBuf) < 16+int(dataLen) {
		return nil, ErrIncompleteProxyHeader
	}
	if addressFamily == addressFamilyInet && dataLen < 12 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidAddressDataLength, dataLen)
	}
	if addressFamily == addressFamilyInet6 && dataLen < 36 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidAddressDataLength, dataLen)
	}

	if command == commandLocal {
		return &proxyHeader{
			TrailingData: ctrlBuf[16+dataLen:],
		}, nil
	}

	var srcIP, dstIP netip.Addr
	if addressFamily == addressFamilyInet {
		srcIP, _ = netip.AddrFromSlice(ctrlBuf[16:20])
		dstIP, _ = netip.AddrFromSlice(ctrlBuf[20:24])
		reader = bytes.NewReader(ctrlBuf[24:])
	} else {
		srcIP, _ = netip.AddrFromSlice(ctrlBuf[16:32])
		dstIP, _ = netip.AddrFromSlice(ctrlBuf[32:48])
		reader = bytes.NewReader(ctrlBuf[48:])
	}

	var sport, dport uint16
	if err := binary.Read(reader, binary.BigEndian, &sport); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeSourcePort, err)
	}
	if sport == 0 {
		return nil, fmt.Errorf("%w %d", ErrInvalidSourcePort, sport)
	}
	if err := binary.Read(reader, binary.BigEndian, &dport); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeDestinationPort, err)
	}
	if dport == 0 {
		return nil, fmt.Errorf("%w %d", ErrInvalidDestinationPort, dport)
	}

	return &proxyHeader{
		SrcAddr:      netip.AddrPortFrom(srcIP, sport),
		DstAddr:      netip.AddrPortFrom(dstIP, dport),
		TrailingData: ctrlBuf[16+dataLen:],
	}, nil
}

func readRemoteAddrPROXYv1(ctrlBuf []byte) (*proxyHeader, error) {
	str := string(ctrlBuf)
	idx := strings.Index(str, "\r\n")
	if idx < 0 {
		return nil, ErrNoTerminator
	}

	parts := strings.Split(str[:idx], " ")
	if slices.Contains(parts, "") || len(parts) < 2 || len(parts) > 6 || parts[0] != "PROXY" {
		return nil, fmt.Errorf("%w", ErrInvalidFormat)
	}

	headerProtocol := parts[1]
	if headerProtocol == "UNKNOWN" {
		return &proxyHeader{TrailingData: ctrlBuf[idx+2:]}, nil
	}
	if headerProtocol != "TCP4" && headerProtocol != "TCP6" {
		return nil, fmt.Errorf("%w %s", ErrUnknownProtocol, headerProtocol)
	}
	if len(parts) != 6 {
		return nil, fmt.Errorf("%w", ErrInvalidFormat)
	}

	srcIP, err := parseAddress(parts[2], headerProtocol)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %w", ErrParseSourceAddress, parts[2], err)
	}
	dstIP, err := parseAddress(parts[3], headerProtocol)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %w", ErrParseDestinationAddress, parts[3], err)
	}
	sport, ok := convertPort(parts[4])
	if !ok {
		return nil, fmt.Errorf("%w %s", ErrInvalidSourcePort, parts[4])
	}
	dport, ok := convertPort(parts[5])
	if !ok {
		return nil, fmt.Errorf("%w %s", ErrInvalidDestinationPort, parts[5])
	}

	return &proxyHeader{
		SrcAddr:      netip.AddrPortFrom(srcIP, sport),
		DstAddr:      netip.AddrPortFrom(dstIP, dport),
		TrailingData: ctrlBuf[idx+2:],
	}, nil
}

func ReadRemoteAddr(buf []byte, protocol utils.Protocol) (*proxyHeader, error) {
	proxyv2header := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

	if len(buf) >= 16 && bytes.Equal(buf[:12], proxyv2header) {
		result, err := readRemoteAddrPROXYv2(buf, protocol)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrProxyProtocolV2, err)
		}
		return result, nil
	}

	// PROXYv1 only works with TCP
	if protocol == utils.TCP && len(buf) >= 8 && bytes.Equal(buf[:5], []byte("PROXY")) {
		result, err := readRemoteAddrPROXYv1(buf)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrProxyProtocolV1, err)
		}
		return result, nil
	}

	return nil, ErrProxyProtocolMissing
}

func parseAddress(addrStr, protocol string) (netip.Addr, error) {
	ipAddr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return ipAddr, fmt.Errorf("%w: %w", ErrParseAddress, err)
	}
	if ipAddr.Is4() != (protocol == "TCP4") {
		return ipAddr, ErrProtocolAddrMismatch
	}
	return ipAddr, nil
}

func convertPort(portStr string) (uint16, bool) {
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port <= 0 || port > 65535 {
		return 0, false
	}
	return uint16(port), true
}
