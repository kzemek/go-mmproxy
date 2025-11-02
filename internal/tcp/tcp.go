// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024-2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"github.com/kzemek/go-mmproxy/internal/proxyprotocol"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

func copyData(dst, src *net.TCPConn, ch chan<- error) {
	_, err := io.Copy(dst, src)
	if err == nil {
		ch <- dst.CloseWrite()
	} else {
		ch <- err
	}
}

func handleConnection(frontendConn *net.TCPConn, config utils.Config) {
	defer utils.CloseWithLogOnError(frontendConn, config.Logger, "frontend connection")

	config, err := doHandleConnection(frontendConn, config)
	if err != nil {
		config.Logger.Debug("dropping connection", slog.Any("error", err))
	} else {
		config.LogDebugConn("connection closing")
	}
}

var (
	errConnectionOriginNotAllowed = errors.New("connection origin not in allowed subnets")
	errReadProxyHeader            = errors.New("failed to read PROXY header")
	errParseProxyHeader           = errors.New("failed to parse PROXY header")
	errEstablishBackendConnection = errors.New("failed to establish backend connection")
	errWriteAllToBackend          = errors.New("failed to write data to backend connection")
	errConnectionBroken           = errors.New("connection broken")
)

func doHandleConnection(frontendConn *net.TCPConn, config utils.Config) (utils.Config, error) {
	frontendRemoteAddr := netip.MustParseAddrPort(frontendConn.RemoteAddr().String())

	config.Logger = config.Logger.With(
		slog.String("frontendRemoteAddr", frontendRemoteAddr.String()),
		slog.String("frontendLocalAddr", frontendConn.LocalAddr().String()))

	if !config.Opts.CheckOriginAllowed(frontendRemoteAddr.Addr()) {
		return config, errConnectionOriginNotAllowed
	}

	config.LogDebugConn("new connection")

	buffer := config.BufferPool.Get()
	defer func() {
		if buffer != nil {
			config.BufferPool.Put(buffer)
		}
	}()

	numBytesRead, err := frontendConn.Read(buffer)
	if err != nil {
		return config, fmt.Errorf("%w: %w", errReadProxyHeader, err)
	}

	proxyHeader, err := proxyprotocol.ReadRemoteAddr(buffer[:numBytesRead], utils.TCP)
	if err != nil {
		return config, fmt.Errorf("%w: %w", errParseProxyHeader, err)
	}

	targetAddr := chooseTargetAddr(
		proxyHeader.SrcAddr,
		proxyHeader.DstAddr,
		frontendRemoteAddr,
		config,
	)

	clientAddr := "UNKNOWN"
	if proxyHeader.SrcAddr.IsValid() {
		clientAddr = proxyHeader.SrcAddr.String()
	}
	config.Logger = config.Logger.With(
		slog.String("clientAddr", clientAddr),
		slog.String("targetAddr", targetAddr.String()))

	config.LogDebugConn("successfully parsed PROXY header")

	backendConn, err := establishBackendConnection(proxyHeader.SrcAddr, targetAddr, config)
	if err != nil {
		return config, err
	}
	defer utils.CloseWithLogOnError(backendConn, config.Logger, "backend connection")
	config.LogDebugConn("successfully established backend connection")

	if err := frontendConn.SetNoDelay(true); err != nil {
		config.Logger.Debug("failed to set nodelay on frontend connection",
			slog.Any("error", err),
			slog.Bool("dropConnection", true))
	} else {
		config.LogDebugConn("successfully set NoDelay on frontend connection")
	}

	if err := backendConn.SetNoDelay(true); err != nil {
		config.Logger.Debug("failed to set nodelay on backend connection",
			slog.Any("error", err),
			slog.Bool("dropConnection", true))
	} else {
		config.LogDebugConn("successfully set NoDelay on backend connection")
	}

	if err := writeAllToBackend(backendConn, proxyHeader.TrailingData); err != nil {
		return config, err
	}

	config.BufferPool.Put(buffer)
	buffer = nil

	readFrontendErr := make(chan error, 1)
	readBackendErr := make(chan error, 1)
	go copyData(backendConn, frontendConn, readFrontendErr)
	go copyData(frontendConn, backendConn, readBackendErr)

	for range 2 {
		var direction string
		select {
		case err = <-readFrontendErr:
			direction = "read frontend -> write backend"
		case err = <-readBackendErr:
			direction = "read backend -> write frontend"
		}

		if err != nil {
			return config, fmt.Errorf("%w: %w", errConnectionBroken, err)
		}

		config.LogDebugConn("connection shutdown for read", slog.String("direction", direction))
	}

	return config, nil
}

func chooseTargetAddr(
	proxyHeaderSrcAddr, proxyHeaderDstAddr, frontendRemoteAddr netip.AddrPort,
	config utils.Config,
) netip.AddrPort {
	if proxyHeaderSrcAddr.IsValid() {
		if config.Opts.DynamicDestination && proxyHeaderDstAddr.IsValid() {
			return proxyHeaderDstAddr
		}

		if proxyHeaderSrcAddr.Addr().Is4() {
			return config.Opts.TargetAddr4
		}
	}

	if frontendRemoteAddr.Addr().Is4() {
		return config.Opts.TargetAddr4
	}

	return config.Opts.TargetAddr6
}

func establishBackendConnection(
	proxyHeaderSrcAddr, targetAddr netip.AddrPort,
	config utils.Config,
) (*net.TCPConn, error) {
	dialer := net.Dialer{}
	if proxyHeaderSrcAddr.IsValid() {
		dialer.LocalAddr = net.TCPAddrFromAddrPort(proxyHeaderSrcAddr)
		dialer.Control = utils.DialBackendControl(
			proxyHeaderSrcAddr.Port(),
			config.Opts.Protocol,
			config.Opts.Mark,
		)
	}
	backendConn, err := dialer.Dial("tcp", targetAddr.String())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errEstablishBackendConnection, err)
	}

	return backendConn.(*net.TCPConn), nil
}

func writeAllToBackend(conn *net.TCPConn, data []byte) error {
	for len(data) > 0 {
		numBytesWritten, err := conn.Write(data)
		if err != nil {
			return fmt.Errorf("%w: %w", errWriteAllToBackend, err)
		}
		data = data[numBytesWritten:]
	}
	return nil
}

func Listen(
	ctx context.Context,
	listenConfig *net.ListenConfig,
	config utils.Config,
) (*net.TCPListener, error) {
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

		go handleConnection(conn.(*net.TCPConn), config)
	}
}
