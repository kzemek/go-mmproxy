// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024-2025 Konrad Zemek <konrad.zemek@gmail.com>
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

	"github.com/kzemek/go-mmproxy/internal/proxyprotocol"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

type connectionInfo struct {
	lastActivity       *int64
	proxyHeaderSrcAddr netip.AddrPort
	frontendRemoteAddr netip.AddrPort
	backendConn        *net.UDPConn
	logger             *slog.Logger
}

func closeAfterInactivity(
	connInfo *connectionInfo,
	closeAfter time.Duration,
	socketClosures chan<- netip.AddrPort,
) {
	for {
		lastActivity := atomic.LoadInt64(connInfo.lastActivity)
		<-time.After(closeAfter)
		if atomic.LoadInt64(connInfo.lastActivity) == lastActivity {
			break
		}
	}

	err := connInfo.backendConn.Close()
	if err != nil {
		connInfo.logger.Error("failed to close backend socket", slog.Any("error", err))
	}

	socketClosures <- connInfo.proxyHeaderSrcAddr
}

func copyFromBackend(frontendConn net.PacketConn, connInfo *connectionInfo, config utils.Config) {
	rawConn, err := connInfo.backendConn.SyscallConn()
	if err != nil {
		connInfo.logger.Error("failed to retrieve raw connection from backend socket",
			slog.Any("error", err))

		return
	}

	var syscallErr error

	err = rawConn.Read(func(fd uintptr) bool {
		buf := config.BufferPool.Get()
		defer config.BufferPool.Put(buf)

		for {
			numBytesRead, _, serr := syscall.Recvfrom(int(fd), buf, syscall.MSG_DONTWAIT)
			if errors.Is(serr, syscall.EWOULDBLOCK) {
				return false
			}
			if serr != nil {
				syscallErr = serr
				return true
			}
			if numBytesRead == 0 {
				return true
			}

			atomic.AddInt64(connInfo.lastActivity, 1)

			if _, serr := frontendConn.WriteTo(buf[:numBytesRead], net.UDPAddrFromAddrPort(connInfo.frontendRemoteAddr)); serr != nil {
				syscallErr = serr
				return true
			}
		}
	})

	if err == nil {
		err = syscallErr
	}

	if err != nil {
		connInfo.logger.Debug("failed to read from backend", slog.Any("error", err))
	}
}

func getSocketFromMap(
	frontendConn net.PacketConn,
	frontendRemoteAddr, proxyHeaderSrcAddr, proxyHeaderDstAddr netip.AddrPort,
	connMap map[netip.AddrPort]*connectionInfo,
	socketClosures chan<- netip.AddrPort,
	config utils.Config,
) (*connectionInfo, error) {
	if connInfo := connMap[proxyHeaderSrcAddr]; connInfo != nil {
		atomic.AddInt64(connInfo.lastActivity, 1)
		return connInfo, nil
	}

	targetAddr := chooseTargetAddr(
		proxyHeaderSrcAddr,
		proxyHeaderDstAddr,
		frontendRemoteAddr,
		config,
	)

	config.Logger = config.Logger.With(
		slog.String("frontendRemoteAddr", frontendRemoteAddr.String()),
		slog.String("targetAddr", targetAddr.String()))

	dialer := net.Dialer{}
	if proxyHeaderSrcAddr.IsValid() {
		config.Logger = config.Logger.With(slog.String("clientAddr", proxyHeaderSrcAddr.String()))
		dialer.LocalAddr = net.UDPAddrFromAddrPort(proxyHeaderSrcAddr)
		dialer.Control = utils.DialBackendControl(
			proxyHeaderSrcAddr.Port(),
			config.Opts.Protocol,
			config.Opts.Mark,
		)
	}

	config.LogDebugConn("new connection")

	conn, err := dialer.Dial("udp", targetAddr.String())
	if err != nil {
		config.Logger.Debug("failed to connect to backend", slog.Any("error", err))
		return nil, fmt.Errorf("failed to connect to backend: %w", err)
	}

	connInfo := &connectionInfo{
		backendConn:        conn.(*net.UDPConn),
		logger:             config.Logger,
		lastActivity:       new(int64),
		proxyHeaderSrcAddr: proxyHeaderSrcAddr,
		frontendRemoteAddr: frontendRemoteAddr,
	}

	go copyFromBackend(frontendConn, connInfo, config)
	go closeAfterInactivity(connInfo, config.Opts.UDPCloseAfter, socketClosures)

	connMap[proxyHeaderSrcAddr] = connInfo
	return connInfo, nil
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

func Listen(
	ctx context.Context,
	listenConfig *net.ListenConfig,
	config utils.Config,
) (*net.UDPConn, error) {
	ln, err := listenConfig.ListenPacket(ctx, "udp", config.Opts.ListenAddr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to bind listener: %w", err)
	}
	return ln.(*net.UDPConn), nil
}

func AcceptLoop(listener *net.UDPConn, config utils.Config) error {
	socketClosures := make(chan netip.AddrPort, 1024)
	connectionMap := make(map[netip.AddrPort]*connectionInfo)

	buffer := config.BufferPool.Get()
	defer config.BufferPool.Put(buffer)

	for {
		numBytesRead, frontendRemoteAddrNet, err := listener.ReadFrom(buffer)
		if err != nil {
			config.Logger.Error("failed to read from socket", slog.Any("error", err))
			continue
		}

		frontendRemoteAddr := netip.MustParseAddrPort(frontendRemoteAddrNet.String())

		if !config.Opts.CheckOriginAllowed(frontendRemoteAddr.Addr()) {
			config.Logger.Debug("packet origin not in allowed subnets",
				slog.String("frontendRemoteAddr", frontendRemoteAddr.String()))

			continue
		}

		proxyHeader, err := proxyprotocol.ReadRemoteAddr(buffer[:numBytesRead], utils.UDP)
		if err != nil {
			config.Logger.Debug("failed to parse PROXY header",
				slog.Any("error", err),
				slog.String("frontendRemoteAddr", frontendRemoteAddr.String()))

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

		connInfo, err := getSocketFromMap(listener,
			frontendRemoteAddr, proxyHeader.SrcAddr, proxyHeader.DstAddr,
			connectionMap, socketClosures, config)
		if err != nil {
			continue
		}

		_, err = connInfo.backendConn.Write(proxyHeader.TrailingData)
		if err != nil {
			connInfo.logger.Error("failed to write to backend socket", slog.Any("error", err))
		}
	}
}
