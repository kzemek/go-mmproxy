// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024-2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utils

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/kzemek/go-mmproxy/internal/buffers"
	"github.com/kzemek/go-mmproxy/internal/setsockopt"
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

// ParseHostPort errors
var ErrParseHostPort = errors.New("failed to parse host and port")
var ErrLookupIP = errors.New("failed to lookup IP addresses")
var ErrNoIPAddressesFound = errors.New("no IP addresses found")
var ErrFailedToParsePort = errors.New("failed to parse port")

func ParseHostPort(hostport string, ipVersion int) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %w", ErrParseHostPort, err)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %w", ErrLookupIP, err)
	}

	filteredIPs := make([]netip.Addr, 0, len(ips))
	for _, stdip := range ips {
		ip := netip.MustParseAddr(stdip.String())
		if ipVersion == 0 || (ip.Is4() && ipVersion == 4) || (ip.Is6() && ipVersion == 6) {
			filteredIPs = append(filteredIPs, ip)
		}
	}

	if len(filteredIPs) == 0 {
		return netip.AddrPort{}, ErrNoIPAddressesFound
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %w", ErrFailedToParsePort, err)
	}

	return netip.AddrPortFrom(filteredIPs[0], uint16(port)), nil
}

func DialBackendControl(sport uint16, protocol Protocol, mark int) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var syscallErr error
		controlErr := c.Control(func(fd uintptr) {
			syscallErr = doDialBackendControl(int(fd), protocol, network, sport, mark)
		})

		if controlErr != nil {
			return fmt.Errorf("failed to control backend socket: %w", controlErr)
		}
		return syscallErr
	}
}

func doDialBackendControl(fd int, protocol Protocol, network string, sport uint16, mark int) error {
	if protocol == TCP {
		if err := setsockopt.TCPSynCnt(fd, 2); err != nil {
			return err
		}
	}

	if err := setsockopt.IPTransparent(fd, true); err != nil {
		return err
	}

	if err := setsockopt.ReuseAddr(fd, true); err != nil {
		return err
	}

	if sport == 0 {
		if err := setsockopt.IPBindAddressNoPort(fd, true); err != nil {
			return err
		}
	}

	if mark != 0 {
		if err := setsockopt.SoMark(fd, mark); err != nil {
			return err
		}
	}

	if network == "tcp6" || network == "udp6" {
		if err := setsockopt.IPv6V6Only(fd, false); err != nil {
			return err
		}
	}

	return nil
}

func CloseWithLogOnError(closer io.Closer, logger *slog.Logger, what string) {
	err := closer.Close()
	if err != nil {
		logger.Warn("failed to close "+what, slog.Any("error", err))
	}
}
