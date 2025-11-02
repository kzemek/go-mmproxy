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
	"strings"

	"github.com/kzemek/go-mmproxy/internal/utils"
)

var (
	// Proxy Protocol V2 errors
	ErrUnknownProcotolVersion  = errors.New("unknown protocol version")
	ErrUnknownCommand          = errors.New("unknown command")
	ErrInvalidFamily           = errors.New("invalid family")
	ErrInvalidProtocol         = errors.New("invalid protocol")
	ErrDecodeAddressDataLength = errors.New("failed to decode address data length")
	ErrIncompleteProxyHeader   = errors.New("incomplete PROXY header")
	ErrDecodeSourcePort        = errors.New("failed to decode source port")
	ErrDecodeDestinationPort   = errors.New("failed to decode destination port")

	// Proxy Protocol V1 errors
	ErrNoTerminator            = errors.New("did not find \\r\\n in first data segment")
	ErrInvalidFormat           = errors.New("failed to decode elements")
	ErrUnknownProtocol         = errors.New("unknown protocol")
	ErrParseSourceAddress      = errors.New("failed to parse source address")
	ErrParseDestinationAddress = errors.New("failed to parse destination address")

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

	if command == commandLocal {
		return &proxyHeader{
			TrailingData: ctrlBuf[16+dataLen:],
		}, nil
	}

	var sport, dport uint16
	if addressFamily == addressFamilyInet {
		reader = bytes.NewReader(ctrlBuf[24:])
	} else {
		reader = bytes.NewReader(ctrlBuf[48:])
	}
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

	var srcIP, dstIP netip.Addr
	if addressFamily == addressFamilyInet {
		srcIP, _ = netip.AddrFromSlice(ctrlBuf[16:20])
		dstIP, _ = netip.AddrFromSlice(ctrlBuf[20:24])
	} else {
		srcIP, _ = netip.AddrFromSlice(ctrlBuf[16:32])
		dstIP, _ = netip.AddrFromSlice(ctrlBuf[32:48])
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

	var headerProtocol string
	numItemsParsed, err := fmt.Sscanf(str, "PROXY %s", &headerProtocol)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFormat, err)
	}
	if numItemsParsed != 1 {
		return nil, ErrInvalidFormat
	}
	if headerProtocol == "UNKNOWN" {
		return &proxyHeader{
			TrailingData: ctrlBuf[idx+2:],
		}, nil
	}
	if headerProtocol != "TCP4" && headerProtocol != "TCP6" {
		return nil, fmt.Errorf("%w %s", ErrUnknownProtocol, headerProtocol)
	}

	var src, dst string
	var sportInt, dportInt int
	numItemsParsed, err = fmt.Sscanf(
		str,
		"PROXY %s %s %s %d %d",
		&headerProtocol, &src, &dst, &sportInt, &dportInt,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFormat, err)
	}
	if numItemsParsed != 5 {
		return nil, ErrInvalidFormat
	}
	sport, ok := convertPort(sportInt)
	if !ok {
		return nil, fmt.Errorf("%w %d", ErrInvalidSourcePort, sport)
	}
	dport, ok := convertPort(dportInt)
	if !ok {
		return nil, fmt.Errorf("%w %d", ErrInvalidDestinationPort, dport)
	}
	srcIP, err := netip.ParseAddr(src)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %w", ErrParseSourceAddress, src, err)
	}
	dstIP, err := netip.ParseAddr(dst)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %w", ErrParseDestinationAddress, dst, err)
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

func convertPort(port int) (uint16, bool) {
	if port <= 0 || port > 65535 {
		return 0, false
	}
	return uint16(port), true
}
