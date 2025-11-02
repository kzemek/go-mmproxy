// Copyright 2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package setsockopt

import (
	"errors"
	"fmt"
	"syscall"
)

var ErrSetsockoptTCPSynCnt = errors.New("IPPROTO_TCP, TCP_SYNCNT")
var ErrSetsockoptIPTransparent = errors.New("IPPROTO_IP, IP_TRANSPARENT")
var ErrSetsockoptReuseAddr = errors.New("SOL_SOCKET, SO_REUSEADDR")
var ErrSetsockoptReusePort = errors.New("SOL_SOCKET, SO_REUSEPORT")
var ErrSetsockoptIPBindAddressNoPort = errors.New("IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT")
var ErrSetsockoptSoMark = errors.New("SOL_SOCKET, SO_MARK")
var ErrSetsockoptIPv6V6Only = errors.New("IPPROTO_IPV6, IPV6_V6ONLY")

// Parent error
var ErrSetsockopt = errors.New("setsockopt")

func TCPSynCnt(fd uintptr, value int) error {
	err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_SYNCNT, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrSetsockoptTCPSynCnt, value, err)
	}
	return nil
}

func IPTransparent(fd uintptr, transparent bool) error {
	value := boolToInt(transparent)
	err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrSetsockoptIPTransparent, value, err)
	}
	return nil
}

func ReuseAddr(fd uintptr, reuseAddr bool) error {
	value := boolToInt(reuseAddr)
	err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrSetsockoptReuseAddr, value, err)
	}
	return nil
}

func ReusePort(fd uintptr, reusePort bool) error {
	value := boolToInt(reusePort)
	soReusePort := 15
	err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrSetsockoptReusePort, value, err)
	}
	return nil
}

func IPBindAddressNoPort(fd uintptr, bindAddressNoPort bool) error {
	value := boolToInt(bindAddressNoPort)
	ipBindAddressNoPort := 24
	err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBindAddressNoPort, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrSetsockoptIPBindAddressNoPort, value, err)
	}
	return nil
}

func SoMark(fd uintptr, mark int) error {
	value := mark
	err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrSetsockoptSoMark, value, err)
	}
	return nil
}

func IPv6V6Only(fd uintptr, v6Only bool) error {
	value := boolToInt(v6Only)
	err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrSetsockoptIPv6V6Only, value, err)
	}
	return nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
