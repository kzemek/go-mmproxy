// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kzemek/go-mmproxy/internal/buffers"
	"github.com/kzemek/go-mmproxy/internal/proxyprotocol"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

type connection struct {
	lastActivity       *int64
	proxyHeaderSrcAddr netip.AddrPort
	frontendRemoteAddr netip.AddrPort
	backendConn        *net.UDPConn
	logger             *slog.Logger
}

func closeAfterInactivity(conn *connection, closeAfter time.Duration, socketClosures chan<- netip.AddrPort) {
	for {
		lastActivity := atomic.LoadInt64(conn.lastActivity)
		<-time.After(closeAfter)
		if atomic.LoadInt64(conn.lastActivity) == lastActivity {
			break
		}
	}
	conn.backendConn.Close()
	socketClosures <- conn.proxyHeaderSrcAddr
}

func copyFromBackend(frontendConn net.PacketConn, conn *connection) {
	rawConn, err := conn.backendConn.SyscallConn()
	if err != nil {
		conn.logger.Error("failed to retrieve raw connection from backend socket", "error", err)
		return
	}

	var syscallErr error

	err = rawConn.Read(func(fd uintptr) bool {
		buf := buffers.Get()
		defer buffers.Put(buf)

		for {
			n, _, serr := syscall.Recvfrom(int(fd), buf, syscall.MSG_DONTWAIT)
			if errors.Is(serr, syscall.EWOULDBLOCK) {
				return false
			}
			if serr != nil {
				syscallErr = serr
				return true
			}
			if n == 0 {
				return true
			}

			atomic.AddInt64(conn.lastActivity, 1)

			if _, serr := frontendConn.WriteTo(buf[:n], net.UDPAddrFromAddrPort(conn.frontendRemoteAddr)); serr != nil {
				syscallErr = serr
				return true
			}
		}
	})

	if err == nil {
		err = syscallErr
	}
	if err != nil {
		conn.logger.Debug("failed to read from backend", "error", err)
	}
}

func getSocketFromMap(frontendConn net.PacketConn, opts *utils.Options,
	frontendRemoteAddr, proxyHeaderSrcAddr, proxyHeaderDstAddr netip.AddrPort,
	logger *slog.Logger, connMap map[netip.AddrPort]*connection, socketClosures chan<- netip.AddrPort) (*connection, error) {
	if conn := connMap[proxyHeaderSrcAddr]; conn != nil {
		atomic.AddInt64(conn.lastActivity, 1)
		return conn, nil
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

	logger = logger.With(
		slog.String("frontendRemoteAddr", frontendRemoteAddr.String()),
		slog.String("targetAddr", targetAddr.String()))

	dialer := net.Dialer{}
	if proxyHeaderSrcAddr.IsValid() {
		logger = logger.With(slog.String("clientAddr", proxyHeaderSrcAddr.String()))
		dialer.LocalAddr = net.UDPAddrFromAddrPort(proxyHeaderSrcAddr)
		dialer.Control = utils.DialBackendControl(proxyHeaderSrcAddr.Port(), opts.Protocol, opts.Mark)
	}

	if opts.Verbose > 1 {
		logger.Debug("new connection")
	}

	conn, err := dialer.Dial("udp", targetAddr.String())
	if err != nil {
		logger.Debug("failed to connect to backend", "error", err)
		return nil, err
	}

	udpConn := &connection{
		backendConn:        conn.(*net.UDPConn),
		logger:             logger,
		lastActivity:       new(int64),
		proxyHeaderSrcAddr: proxyHeaderSrcAddr,
		frontendRemoteAddr: frontendRemoteAddr}

	go copyFromBackend(frontendConn, udpConn)
	go closeAfterInactivity(udpConn, opts.UDPCloseAfter, socketClosures)

	connMap[proxyHeaderSrcAddr] = udpConn
	return udpConn, nil
}

func Listen(ctx context.Context, listenConfig *net.ListenConfig, opts *utils.Options) (*net.UDPConn, error) {
	ln, err := listenConfig.ListenPacket(ctx, "udp", opts.ListenAddr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to bind listener: %w", err)
	}
	return ln.(*net.UDPConn), nil
}

func AcceptLoop(ln *net.UDPConn, opts *utils.Options, logger *slog.Logger) error {
	socketClosures := make(chan netip.AddrPort, 1024)
	connectionMap := make(map[netip.AddrPort]*connection)

	buffer := buffers.Get()
	defer buffers.Put(buffer)

	for {
		n, frontendRemoteAddrNet, err := ln.ReadFrom(buffer)
		if err != nil {
			logger.Error("failed to read from socket", "error", err)
			continue
		}

		frontendRemoteAddr := netip.MustParseAddrPort(frontendRemoteAddrNet.String())

		if !utils.CheckOriginAllowed(frontendRemoteAddr.Addr(), opts.AllowedSubnets) {
			logger.Debug("packet origin not in allowed subnets", slog.String("frontendRemoteAddr", frontendRemoteAddr.String()))
			continue
		}

		proxyHeaderSrcAddr, proxyHeaderDstAddr, restBytes, err := proxyprotocol.ReadRemoteAddr(buffer[:n], utils.UDP)
		if err != nil {
			logger.Debug("failed to parse PROXY header", "error", err, slog.String("frontendRemoteAddr", frontendRemoteAddr.String()))
			continue
		}

		for {
			doneClosing := false
			select {
			case mapKey := <-socketClosures:
				delete(connectionMap, mapKey)
			default:
				doneClosing = true
			}
			if doneClosing {
				break
			}
		}

		conn, err := getSocketFromMap(ln, opts, frontendRemoteAddr, proxyHeaderSrcAddr, proxyHeaderDstAddr, logger, connectionMap, socketClosures)
		if err != nil {
			continue
		}

		_, err = conn.backendConn.Write(restBytes)
		if err != nil {
			conn.logger.Error("failed to write to backend socket", "error", err)
		}
	}
}
