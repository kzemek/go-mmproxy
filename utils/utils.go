// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utils

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

type Protocol int

const (
	TCP Protocol = iota
	UDP
)

type Options struct {
	Protocol       Protocol
	ListenAddr     netip.AddrPort
	TargetAddr4    netip.AddrPort
	TargetAddr6    netip.AddrPort
	Mark           int
	Verbose        int
	AllowedSubnets []netip.Prefix
	UDPCloseAfter  time.Duration
}

func CheckOriginAllowed(remoteIP netip.Addr, allowedSubnets []netip.Prefix) bool {
	if len(allowedSubnets) == 0 {
		return true
	}

	for _, ipNet := range allowedSubnets {
		if ipNet.Contains(remoteIP) {
			return true
		}
	}
	return false
}

func ParseHostPort(hostport string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to parse host and port: %w", err)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to lookup IP addresses: %w", err)
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no IP addresses found")
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to parse port: %w", err)
	}

	ip, _ := netip.AddrFromSlice(ips[0])
	return netip.AddrPortFrom(ip, uint16(port)), nil
}

func DialUpstreamControl(sport uint16, protocol Protocol, mark int) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var syscallErr error
		err := c.Control(func(fd uintptr) {
			if protocol == TCP {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_SYNCNT, 2)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_TCP, TCP_SYNCTNT, 2): %w", syscallErr)
					return
				}
			}

			syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(IPPROTO_IP, IP_TRANSPARENT, 1): %w", syscallErr)
				return
			}

			syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(SOL_SOCKET, SO_REUSEADDR, 1): %w", syscallErr)
				return
			}

			if sport == 0 {
				ipBindAddressNoPort := 24
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBindAddressNoPort, 1)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, 1): %w", syscallErr)
					return
				}
			}

			if mark != 0 {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(SOL_SOCK, SO_MARK, %d): %w", mark, syscallErr)
					return
				}
			}

			if network == "tcp6" || network == "udp6" {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_IP, IPV6_ONLY, 0): %w", syscallErr)
					return
				}
			}
		})

		if err != nil {
			return err
		}
		return syscallErr
	}
}
