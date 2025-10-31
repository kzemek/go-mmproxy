// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxyprotocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"github.com/kzemek/go-mmproxy/internal/utils"
)

func readRemoteAddrPROXYv2(ctrlBuf []byte, protocol utils.Protocol) (proxyHeaderSrcAddr, proxyHeaderDstAddr netip.AddrPort, data []byte, resultErr error) {
	if (ctrlBuf[12] >> 4) != 2 {
		resultErr = fmt.Errorf("unknown protocol version %d", ctrlBuf[12]>>4)
		return
	}

	if ctrlBuf[12]&0xF > 1 {
		resultErr = fmt.Errorf("unknown command %d", ctrlBuf[12]&0xF)
		return
	}

	if ctrlBuf[12]&0xF == 1 && ((protocol == utils.TCP && ctrlBuf[13] != 0x11 && ctrlBuf[13] != 0x21) ||
		(protocol == utils.UDP && ctrlBuf[13] != 0x12 && ctrlBuf[13] != 0x22)) {
		resultErr = fmt.Errorf("invalid family/protocol %d/%d", ctrlBuf[13]>>4, ctrlBuf[13]&0xF)
		return
	}

	var dataLen uint16
	reader := bytes.NewReader(ctrlBuf[14:16])
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		resultErr = fmt.Errorf("failed to decode address data length: %w", err)
		return
	}

	if len(ctrlBuf) < 16+int(dataLen) {
		resultErr = fmt.Errorf("incomplete PROXY header")
		return
	}

	if ctrlBuf[12]&0xF == 0 { // LOCAL
		data = ctrlBuf[16+dataLen:]
		return
	}

	var sport, dport uint16
	if ctrlBuf[13]>>4 == 0x1 { // IPv4
		reader = bytes.NewReader(ctrlBuf[24:])
	} else {
		reader = bytes.NewReader(ctrlBuf[48:])
	}
	if err := binary.Read(reader, binary.BigEndian, &sport); err != nil {
		resultErr = fmt.Errorf("failed to decode source port: %w", err)
		return
	}
	if sport == 0 {
		resultErr = fmt.Errorf("invalid source port %d", sport)
		return
	}
	if err := binary.Read(reader, binary.BigEndian, &dport); err != nil {
		resultErr = fmt.Errorf("failed to decode destination port: %w", err)
		return
	}
	if dport == 0 {
		resultErr = fmt.Errorf("invalid destination port %d", dport)
		return
	}

	var srcIP, dstIP netip.Addr
	if ctrlBuf[13]>>4 == 0x1 { // IPv4
		srcIP, _ = netip.AddrFromSlice(ctrlBuf[16:20])
		dstIP, _ = netip.AddrFromSlice(ctrlBuf[20:24])
	} else {
		srcIP, _ = netip.AddrFromSlice(ctrlBuf[16:32])
		dstIP, _ = netip.AddrFromSlice(ctrlBuf[32:48])
	}

	proxyHeaderSrcAddr = netip.AddrPortFrom(srcIP, sport)
	proxyHeaderDstAddr = netip.AddrPortFrom(dstIP, dport)
	data = ctrlBuf[16+dataLen:]
	return
}

func readRemoteAddrPROXYv1(ctrlBuf []byte) (proxyHeaderSrcAddr, proxyHeaderDstAddr netip.AddrPort, data []byte, resultErr error) {
	str := string(ctrlBuf)
	idx := strings.Index(str, "\r\n")
	if idx < 0 {
		resultErr = fmt.Errorf("did not find \\r\\n in first data segment")
		return
	}

	var headerProtocol string
	n, err := fmt.Sscanf(str, "PROXY %s", &headerProtocol)
	if err != nil {
		resultErr = err
		return
	}
	if n != 1 {
		resultErr = fmt.Errorf("failed to decode elements")
		return
	}
	if headerProtocol == "UNKNOWN" {
		data = ctrlBuf[idx+2:]
		return
	}
	if headerProtocol != "TCP4" && headerProtocol != "TCP6" {
		resultErr = fmt.Errorf("unknown protocol %s", headerProtocol)
		return
	}

	var src, dst string
	var sport, dport int
	n, err = fmt.Sscanf(str, "PROXY %s %s %s %d %d", &headerProtocol, &src, &dst, &sport, &dport)
	if err != nil {
		resultErr = err
		return
	}
	if n != 5 {
		resultErr = fmt.Errorf("failed to decode elements")
		return
	}
	if sport <= 0 || sport > 65535 {
		resultErr = fmt.Errorf("invalid source port %d", sport)
		return
	}
	if dport <= 0 || dport > 65535 {
		resultErr = fmt.Errorf("invalid destination port %d", dport)
		return
	}
	srcIP, err := netip.ParseAddr(src)
	if err != nil {
		resultErr = fmt.Errorf("failed to parse source IP address %s: %w", src, err)
		return
	}
	dstIP, err := netip.ParseAddr(dst)
	if err != nil {
		resultErr = fmt.Errorf("failed to parse destination IP address %s: %w", dst, err)
		return
	}

	proxyHeaderSrcAddr = netip.AddrPortFrom(srcIP, uint16(sport))
	proxyHeaderDstAddr = netip.AddrPortFrom(dstIP, uint16(dport))
	data = ctrlBuf[idx+2:]
	return
}

var proxyv2header = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

func ReadRemoteAddr(buf []byte, protocol utils.Protocol) (proxyHeaderSrcAddr, proxyHeaderDstAddr netip.AddrPort, rest []byte, err error) {
	if len(buf) >= 16 && bytes.Equal(buf[:12], proxyv2header) {
		proxyHeaderSrcAddr, proxyHeaderDstAddr, rest, err = readRemoteAddrPROXYv2(buf, protocol)
		if err != nil {
			err = fmt.Errorf("failed to parse PROXY v2 header: %w", err)
		}
		return
	}

	// PROXYv1 only works with TCP
	if protocol == utils.TCP && len(buf) >= 8 && bytes.Equal(buf[:5], []byte("PROXY")) {
		proxyHeaderSrcAddr, proxyHeaderDstAddr, rest, err = readRemoteAddrPROXYv1(buf)
		if err != nil {
			err = fmt.Errorf("failed to parse PROXY v1 header: %w", err)
		}
		return
	}

	err = fmt.Errorf("PROXY header missing")
	return
}
