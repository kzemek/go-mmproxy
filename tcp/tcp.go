// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"context"
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

	outErr := make(chan error, 2)
	go copyData(upstreamConn, conn, outErr)
	go copyData(conn, upstreamConn, outErr)

	err = <-outErr
	if err != nil {
		logger.Debug("connection broken", "error", err, slog.Bool("dropConnection", true))
	} else if opts.Verbose > 1 {
		logger.Debug("connection closing")
	}
}

func Listen(ctx context.Context, listenConfig *net.ListenConfig, opts *utils.Options, logger *slog.Logger, errors chan<- error) {
	ln, err := listenConfig.Listen(ctx, "tcp", opts.ListenAddr.String())
	if err != nil {
		logger.Error("failed to bind listener", "error", err)
		errors <- err
		return
	}

	logger.Info("listening")

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("failed to accept new connection", "error", err)
			errors <- err
			return
		}

		go handleConnection(conn, opts, logger)
	}
}
