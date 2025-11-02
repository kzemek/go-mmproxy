// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024-2025 Konrad Zemek <konrad.zemek@gmail.com>
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

	"github.com/kzemek/go-mmproxy/internal/proxyprotocol"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

func copyData(dst net.Conn, src net.Conn, ch chan<- error) {
	_, err := io.Copy(dst, src)
	if err == nil {
		ch <- dst.(*net.TCPConn).CloseWrite()
	} else {
		ch <- err
	}
}

func handleConnection(frontendConn net.Conn, config utils.Config) {
	defer utils.CloseWithLogOnError(frontendConn, config.Logger, "frontend connection")

	frontendRemoteAddr := netip.MustParseAddrPort(frontendConn.RemoteAddr().String())

	config.Logger = config.Logger.With(
		slog.String("frontendRemoteAddr", frontendRemoteAddr.String()),
		slog.String("frontendLocalAddr", frontendConn.LocalAddr().String()))

	if !config.Opts.CheckOriginAllowed(frontendRemoteAddr.Addr()) {
		config.Logger.Debug("connection origin not in allowed subnets",
			slog.Bool("dropConnection", true))

		return
	}

	config.LogDebugConn("new connection")

	buffer := config.BufferPool.Get()
	defer func() {
		if buffer != nil {
			config.BufferPool.Put(buffer)
		}
	}()

	n, err := frontendConn.Read(buffer)
	if err != nil {
		config.Logger.Debug("failed to read PROXY header",
			slog.Any("error", err),
			slog.Bool("dropConnection", true))

		return
	}

	proxyHeaderSrcAddr, proxyHeaderDstAddr, restBytes, err := proxyprotocol.ReadRemoteAddr(buffer[:n], utils.TCP)
	if err != nil {
		config.Logger.Debug("failed to parse PROXY header",
			slog.Any("error", err),
			slog.Bool("dropConnection", true))

		return
	}

	targetAddr := config.Opts.TargetAddr6
	if proxyHeaderSrcAddr.IsValid() {
		if config.Opts.DynamicDestination && proxyHeaderDstAddr.IsValid() {
			targetAddr = proxyHeaderDstAddr
		} else if proxyHeaderSrcAddr.Addr().Is4() {
			targetAddr = config.Opts.TargetAddr4
		}
	} else if frontendRemoteAddr.Addr().Is4() {
		targetAddr = config.Opts.TargetAddr4
	}

	clientAddr := "UNKNOWN"
	if proxyHeaderSrcAddr.IsValid() {
		clientAddr = proxyHeaderSrcAddr.String()
	}
	config.Logger = config.Logger.With(
		slog.String("clientAddr", clientAddr),
		slog.String("targetAddr", targetAddr.String()))

	config.LogDebugConn("successfully parsed PROXY header")

	dialer := net.Dialer{}
	if proxyHeaderSrcAddr.IsValid() {
		dialer.LocalAddr = net.TCPAddrFromAddrPort(proxyHeaderSrcAddr)
		dialer.Control = utils.DialBackendControl(proxyHeaderSrcAddr.Port(), config.Opts.Protocol, config.Opts.Mark)
	}
	backendConn, err := dialer.Dial("tcp", targetAddr.String())
	if err != nil {
		config.Logger.Debug("failed to establish backend connection",
			slog.Any("error", err),
			slog.Bool("dropConnection", true))

		return
	}

	defer utils.CloseWithLogOnError(backendConn, config.Logger, "backend connection")
	config.LogDebugConn("successfully established backend connection")

	if err := frontendConn.(*net.TCPConn).SetNoDelay(true); err != nil {
		config.Logger.Debug("failed to set nodelay on frontend connection",
			slog.Any("error", err),
			slog.Bool("dropConnection", true))
	} else {
		config.LogDebugConn("successfully set NoDelay on frontend connection")
	}

	if err := backendConn.(*net.TCPConn).SetNoDelay(true); err != nil {
		config.Logger.Debug("failed to set nodelay on backend connection",
			slog.Any("error", err),
			slog.Bool("dropConnection", true))
	} else {
		config.LogDebugConn("successfully set NoDelay on backend connection")
	}

	for len(restBytes) > 0 {
		n, err := backendConn.Write(restBytes)
		if err != nil {
			config.Logger.Debug("failed to write data to backend connection",
				slog.Any("error", err),
				slog.Bool("dropConnection", true))

			return
		}
		restBytes = restBytes[n:]
	}

	config.BufferPool.Put(buffer)
	buffer = nil

	readFrontendErr := make(chan error, 1)
	readBackendErr := make(chan error, 1)
	go copyData(backendConn, frontendConn, readFrontendErr)
	go copyData(frontendConn, backendConn, readBackendErr)

	for i := 0; i < 2; i++ {
		direction := ""
		select {
		case err = <-readFrontendErr:
			direction = "read frontend -> write backend"
		case err = <-readBackendErr:
			direction = "read backend -> write frontend"
		}

		if err != nil {
			config.Logger.Debug("connection broken",
				slog.Any("error", err),
				slog.String("direction", direction),
				slog.Bool("dropConnection", true))

			return
		}

		config.LogDebugConn("connection shutdown for read", slog.String("direction", direction))
	}

	config.LogDebugConn("connection closing")
}

func Listen(ctx context.Context, listenConfig *net.ListenConfig, config utils.Config) (*net.TCPListener, error) {
	ln, err := listenConfig.Listen(ctx, "tcp", config.Opts.ListenAddr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to bind listener: %w", err)
	}
	return ln.(*net.TCPListener), nil
}

func AcceptLoop(ln *net.TCPListener, config utils.Config) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept new connection: %w", err)
		}

		go handleConnection(conn, config)
	}
}
