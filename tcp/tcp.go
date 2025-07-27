// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"github.com/kzemek/go-mmproxy/buffers"
	"github.com/kzemek/go-mmproxy/proxyprotocol"
	"github.com/kzemek/go-mmproxy/utils"
)

func copyData(dst net.Conn, src net.Conn, ch chan<- error) {
	_, err := io.Copy(dst, src)
	if err == nil {
		dst.(*net.TCPConn).CloseWrite()
	}
	ch <- err
}

func handleConnection(conn net.Conn, opts *utils.Options, logger *slog.Logger) {
	defer conn.Close()

	remoteAddr := netip.MustParseAddrPort(conn.RemoteAddr().String())

	logger = logger.With(slog.String("remoteAddr", remoteAddr.String()),
		slog.String("localAddr", conn.LocalAddr().String()))

	if !utils.CheckOriginAllowed(remoteAddr.Addr(), opts.AllowedSubnets) {
		logger.Debug("connection origin not in allowed subnets", slog.Bool("dropConnection", true))
		return
	}

	if opts.Verbose > 1 {
		logger.Debug("new connection")
	}

	buffer := buffers.Get()
	defer func() {
		if buffer != nil {
			buffers.Put(buffer)
		}
	}()

	n, err := conn.Read(buffer)
	if err != nil {
		logger.Debug("failed to read PROXY header", "error", err, slog.Bool("dropConnection", true))
		return
	}

	saddr, daddr, restBytes, err := proxyprotocol.ReadRemoteAddr(buffer[:n], utils.TCP)
	if err != nil {
		logger.Debug("failed to parse PROXY header", "error", err, slog.Bool("dropConnection", true))
		return
	}

	targetAddr := opts.TargetAddr6
	if saddr.IsValid() {
		if opts.DynamicDestination && daddr.IsValid() {
			targetAddr = daddr
		} else if saddr.Addr().Is4() {
			targetAddr = opts.TargetAddr4
		}
	} else {
		if remoteAddr.Addr().Is4() {
			targetAddr = opts.TargetAddr4
		}
	}

	clientAddr := "UNKNOWN"
	if saddr.IsValid() {
		clientAddr = saddr.String()
	}
	logger = logger.With(slog.String("clientAddr", clientAddr), slog.String("targetAddr", targetAddr.String()))
	if opts.Verbose > 1 {
		logger.Debug("successfully parsed PROXY header")
	}

	dialer := net.Dialer{}
	if saddr.IsValid() {
		dialer.LocalAddr = net.TCPAddrFromAddrPort(saddr)
		dialer.Control = utils.DialUpstreamControl(saddr.Port(), opts.Protocol, opts.Mark)
	}
	upstreamConn, err := dialer.Dial("tcp", targetAddr.String())
	if err != nil {
		logger.Debug("failed to establish upstream connection", "error", err, slog.Bool("dropConnection", true))
		return
	}

	defer upstreamConn.Close()
	if opts.Verbose > 1 {
		logger.Debug("successfully established upstream connection")
	}

	if err := conn.(*net.TCPConn).SetNoDelay(true); err != nil {
		logger.Debug("failed to set nodelay on downstream connection", "error", err, slog.Bool("dropConnection", true))
	} else if opts.Verbose > 1 {
		logger.Debug("successfully set NoDelay on downstream connection")
	}

	if err := upstreamConn.(*net.TCPConn).SetNoDelay(true); err != nil {
		logger.Debug("failed to set nodelay on upstream connection", "error", err, slog.Bool("dropConnection", true))
	} else if opts.Verbose > 1 {
		logger.Debug("successfully set NoDelay on upstream connection")
	}

	for len(restBytes) > 0 {
		n, err := upstreamConn.Write(restBytes)
		if err != nil {
			logger.Debug("failed to write data to upstream connection",
				"error", err, slog.Bool("dropConnection", true))
			return
		}
		restBytes = restBytes[n:]
	}

	buffers.Put(buffer)
	buffer = nil

	readConnErr := make(chan error, 1)
	readUpstreamErr := make(chan error, 1)
	go copyData(upstreamConn, conn, readConnErr)
	go copyData(conn, upstreamConn, readUpstreamErr)

	for i := 0; i < 2; i++ {
		direction := ""
		select {
		case err = <-readConnErr:
			direction = "read conn -> write upstream"
		case err = <-readUpstreamErr:
			direction = "read upstream -> write conn"
		}

		if err != nil {
			logger.Debug("connection broken", slog.Any("error", err), slog.String("direction", direction), slog.Bool("dropConnection", true))
			return
		}

		if opts.Verbose > 1 {
			logger.Debug("connection shutdown for read", slog.String("direction", direction))
		}
	}

	if opts.Verbose > 1 {
		logger.Debug("connection closing")
	}
}

func Listen(ctx context.Context, listenConfig *net.ListenConfig, opts *utils.Options) (*net.TCPListener, error) {
	ln, err := listenConfig.Listen(ctx, "tcp", opts.ListenAddr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to bind listener: %w", err)
	}
	return ln.(*net.TCPListener), nil
}

func AcceptLoop(ln *net.TCPListener, opts *utils.Options, logger *slog.Logger) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept new connection: %w", err)
		}

		go handleConnection(conn, opts, logger)
	}
}
