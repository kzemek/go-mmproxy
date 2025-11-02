// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024-2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utils

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/kzemek/go-mmproxy/internal/buffers"
)

type Protocol int

const (
	TCP Protocol = 6
	UDP Protocol = 17
)

func (p Protocol) String() string {
	switch p {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	default:
		panic(fmt.Sprintf("invalid protocol %d", int(p)))
	}
}

type Options struct {
	Protocol           Protocol
	ListenAddr         netip.AddrPort
	TargetAddr4        netip.AddrPort
	TargetAddr6        netip.AddrPort
	DynamicDestination bool
	Mark               int
	Verbose            int
	AllowedSubnets     []netip.Prefix
	UDPCloseAfter      time.Duration
	ListenTransparent  bool
	Listeners          int
}

func (o *Options) CheckOriginAllowed(remoteIP netip.Addr) bool {
	if len(o.AllowedSubnets) == 0 {
		return true
	}

	for _, ipNet := range o.AllowedSubnets {
		if ipNet.Contains(remoteIP) {
			return true
		}
	}
	return false
}

type Config struct {
	Opts       *Options
	Logger     *slog.Logger
	BufferPool buffers.BufferPool
}

// LogDebugConn logs a debug message for a connection (only logged if verbose > 1).
func (c *Config) LogDebugConn(msg string, vars ...any) {
	if c.Opts.Verbose > 1 {
		c.Logger.Debug(msg, vars...)
	}
}

func ParseHostPort(hostport string, ipVersion int) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to parse host and port: %w", err)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to lookup IP addresses: %w", err)
	}

	filteredIPs := make([]netip.Addr, 0, len(ips))
	for _, stdip := range ips {
		ip := netip.MustParseAddr(stdip.String())
		if ipVersion == 0 || (ip.Is4() && ipVersion == 4) || (ip.Is6() && ipVersion == 6) {
			filteredIPs = append(filteredIPs, ip)
		}
	}

	if len(filteredIPs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no IP addresses found")
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to parse port: %w", err)
	}

	return netip.AddrPortFrom(filteredIPs[0], uint16(port)), nil
}

func DialBackendControl(sport uint16, protocol Protocol, mark int) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var syscallErr error
		err := c.Control(func(fd uintptr) {
			if protocol == TCP {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_SYNCNT, 2)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_TCP, TCP_SYNCNT, 2): %w", syscallErr)
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
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0): %w", syscallErr)
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
