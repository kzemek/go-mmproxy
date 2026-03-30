// Copyright 2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package setsockopt

import (
	"errors"
	"fmt"
	"syscall"
)

var (
	ErrTCPSynCnt           = errors.New("IPPROTO_TCP, TCP_SYNCNT")
	ErrIPTransparent       = errors.New("IPPROTO_IP, IP_TRANSPARENT")
	ErrReuseAddr           = errors.New("SOL_SOCKET, SO_REUSEADDR")
	ErrReusePort           = errors.New("SOL_SOCKET, SO_REUSEPORT")
	ErrIPBindAddressNoPort = errors.New("IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT")
	ErrSoMark              = errors.New("SOL_SOCKET, SO_MARK")
	ErrIPv6V6Only          = errors.New("IPPROTO_IPV6, IPV6_V6ONLY")
)

// Parent error
var ErrSetsockopt = errors.New("setsockopt")

func TCPSynCnt(fdUintptr uintptr, value int) error {
	fd := int(fdUintptr) // #nosec G115
	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_SYNCNT, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrTCPSynCnt, value, err)
	}
	return nil
}

func IPTransparent(fdUintptr uintptr, transparent bool) error {
	fd := int(fdUintptr) // #nosec G115
	value := boolToInt(transparent)
	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrIPTransparent, value, err)
	}
	return nil
}

func ReuseAddr(fdUintptr uintptr, reuseAddr bool) error {
	fd := int(fdUintptr) // #nosec G115
	value := boolToInt(reuseAddr)
	err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrReuseAddr, value, err)
	}
	return nil
}

func ReusePort(fdUintptr uintptr, reusePort bool) error {
	fd := int(fdUintptr) // #nosec G115
	value := boolToInt(reusePort)
	soReusePort := 15
	err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soReusePort, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrReusePort, value, err)
	}
	return nil
}

func IPBindAddressNoPort(fdUintptr uintptr, bindAddressNoPort bool) error {
	fd := int(fdUintptr) // #nosec G115
	value := boolToInt(bindAddressNoPort)
	ipBindAddressNoPort := 24
	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, ipBindAddressNoPort, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrIPBindAddressNoPort, value, err)
	}
	return nil
}

func SoMark(fdUintptr uintptr, mark int) error {
	fd := int(fdUintptr) // #nosec G115
	value := mark
	err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrSoMark, value, err)
	}
	return nil
}

func IPv6V6Only(fdUintptr uintptr, v6Only bool) error {
	fd := int(fdUintptr) // #nosec G115
	value := boolToInt(v6Only)
	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, value)
	if err != nil {
		return fmt.Errorf("%w(%w, %d): %w", ErrSetsockopt, ErrIPv6V6Only, value, err)
	}
	return nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
