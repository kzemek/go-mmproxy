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

	"github.com/kzemek/go-mmproxy/internal/buffers"
	"github.com/kzemek/go-mmproxy/internal/proxyprotocol"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

func copyData(dst net.Conn, src net.Conn, ch chan<- error) {
	_, err := io.Copy(dst, src)
	if err == nil {
		dst.(*net.TCPConn).CloseWrite()
	}
	ch <- err
}

func handleConnection(frontendConn net.Conn, opts *utils.Options, logger *slog.Logger) {
	defer frontendConn.Close()

	frontendRemoteAddr := netip.MustParseAddrPort(frontendConn.RemoteAddr().String())

	logger = logger.With(slog.String("frontendRemoteAddr", frontendRemoteAddr.String()),
		slog.String("frontendLocalAddr", frontendConn.LocalAddr().String()))

	if !utils.CheckOriginAllowed(frontendRemoteAddr.Addr(), opts.AllowedSubnets) {
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

	n, err := frontendConn.Read(buffer)
	if err != nil {
		logger.Debug("failed to read PROXY header", "error", err, slog.Bool("dropConnection", true))
		return
	}

	proxyHeaderSrcAddr, proxyHeaderDstAddr, restBytes, err := proxyprotocol.ReadRemoteAddr(buffer[:n], utils.TCP)
	if err != nil {
		logger.Debug("failed to parse PROXY header", "error", err, slog.Bool("dropConnection", true))
		return
	}

	targetAddr := opts.TargetAddr6
	if proxyHeaderSrcAddr.IsValid() {
		if opts.DynamicDestination && proxyHeaderDstAddr.IsValid() {
			targetAddr = proxyHeaderDstAddr
		} else if proxyHeaderSrcAddr.Addr().Is4() {
			targetAddr = opts.TargetAddr4
		}
	} else {
		if frontendRemoteAddr.Addr().Is4() {
			targetAddr = opts.TargetAddr4
		}
	}

	clientAddr := "UNKNOWN"
	if proxyHeaderSrcAddr.IsValid() {
		clientAddr = proxyHeaderSrcAddr.String()
	}
	logger = logger.With(slog.String("clientAddr", clientAddr), slog.String("targetAddr", targetAddr.String()))
	if opts.Verbose > 1 {
		logger.Debug("successfully parsed PROXY header")
	}

	dialer := net.Dialer{}
	if proxyHeaderSrcAddr.IsValid() {
		dialer.LocalAddr = net.TCPAddrFromAddrPort(proxyHeaderSrcAddr)
		dialer.Control = utils.DialBackendControl(proxyHeaderSrcAddr.Port(), opts.Protocol, opts.Mark)
	}
	backendConn, err := dialer.Dial("tcp", targetAddr.String())
	if err != nil {
		logger.Debug("failed to establish backend connection", "error", err, slog.Bool("dropConnection", true))
		return
	}

	defer backendConn.Close()
	if opts.Verbose > 1 {
		logger.Debug("successfully established backend connection")
	}

	if err := frontendConn.(*net.TCPConn).SetNoDelay(true); err != nil {
		logger.Debug("failed to set nodelay on frontend connection", "error", err, slog.Bool("dropConnection", true))
	} else if opts.Verbose > 1 {
		logger.Debug("successfully set NoDelay on frontend connection")
	}

	if err := backendConn.(*net.TCPConn).SetNoDelay(true); err != nil {
		logger.Debug("failed to set nodelay on backend connection", "error", err, slog.Bool("dropConnection", true))
	} else if opts.Verbose > 1 {
		logger.Debug("successfully set NoDelay on backend connection")
	}

	for len(restBytes) > 0 {
		n, err := backendConn.Write(restBytes)
		if err != nil {
			logger.Debug("failed to write data to backend connection",
				"error", err, slog.Bool("dropConnection", true))
			return
		}
		restBytes = restBytes[n:]
	}

	buffers.Put(buffer)
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
