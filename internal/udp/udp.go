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
	lastActivity   *int64
	clientAddr     netip.AddrPort
	downstreamAddr netip.AddrPort
	upstream       *net.UDPConn
	logger         *slog.Logger
}

func closeAfterInactivity(conn *connection, closeAfter time.Duration, socketClosures chan<- netip.AddrPort) {
	for {
		lastActivity := atomic.LoadInt64(conn.lastActivity)
		<-time.After(closeAfter)
		if atomic.LoadInt64(conn.lastActivity) == lastActivity {
			break
		}
	}
	conn.upstream.Close()
	socketClosures <- conn.clientAddr
}

func copyFromUpstream(downstream net.PacketConn, conn *connection) {
	rawConn, err := conn.upstream.SyscallConn()
	if err != nil {
		conn.logger.Error("failed to retrieve raw connection from upstream socket", "error", err)
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

			if _, serr := downstream.WriteTo(buf[:n], net.UDPAddrFromAddrPort(conn.downstreamAddr)); serr != nil {
				syscallErr = serr
				return true
			}
		}
	})

	if err == nil {
		err = syscallErr
	}
	if err != nil {
		conn.logger.Debug("failed to read from upstream", "error", err)
	}
}

func getSocketFromMap(downstream net.PacketConn, opts *utils.Options, downstreamAddr, saddr, daddr netip.AddrPort,
	logger *slog.Logger, connMap map[netip.AddrPort]*connection, socketClosures chan<- netip.AddrPort) (*connection, error) {
	if conn := connMap[saddr]; conn != nil {
		atomic.AddInt64(conn.lastActivity, 1)
		return conn, nil
	}

	targetAddr := opts.TargetAddr6
	if saddr.IsValid() {
		if opts.DynamicDestination && daddr.IsValid() {
			targetAddr = daddr
		} else if saddr.Addr().Is4() {
			targetAddr = opts.TargetAddr4
		}
	} else {
		if downstreamAddr.Addr().Is4() {
			targetAddr = opts.TargetAddr4
		}
	}

	logger = logger.With(slog.String("downstreamAddr", downstreamAddr.String()), slog.String("targetAddr", targetAddr.String()))
	dialer := net.Dialer{}
	if saddr.IsValid() {
		logger = logger.With(slog.String("clientAddr", saddr.String()))
		dialer.LocalAddr = net.UDPAddrFromAddrPort(saddr)
		dialer.Control = utils.DialUpstreamControl(saddr.Port(), opts.Protocol, opts.Mark)
	}

	if opts.Verbose > 1 {
		logger.Debug("new connection")
	}

	conn, err := dialer.Dial("udp", targetAddr.String())
	if err != nil {
		logger.Debug("failed to connect to upstream", "error", err)
		return nil, err
	}

	udpConn := &connection{upstream: conn.(*net.UDPConn),
		logger:         logger,
		lastActivity:   new(int64),
		clientAddr:     saddr,
		downstreamAddr: downstreamAddr}

	go copyFromUpstream(downstream, udpConn)
	go closeAfterInactivity(udpConn, opts.UDPCloseAfter, socketClosures)

	connMap[saddr] = udpConn
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
		n, remoteAddrNet, err := ln.ReadFrom(buffer)
		if err != nil {
			logger.Error("failed to read from socket", "error", err)
			continue
		}

		remoteAddr := netip.MustParseAddrPort(remoteAddrNet.String())

		if !utils.CheckOriginAllowed(remoteAddr.Addr(), opts.AllowedSubnets) {
			logger.Debug("packet origin not in allowed subnets", slog.String("remoteAddr", remoteAddr.String()))
			continue
		}

		saddr, daddr, restBytes, err := proxyprotocol.ReadRemoteAddr(buffer[:n], utils.UDP)
		if err != nil {
			logger.Debug("failed to parse PROXY header", "error", err, slog.String("remoteAddr", remoteAddr.String()))
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

		conn, err := getSocketFromMap(ln, opts, remoteAddr, saddr, daddr, logger, connectionMap, socketClosures)
		if err != nil {
			continue
		}

		_, err = conn.upstream.Write(restBytes)
		if err != nil {
			conn.logger.Error("failed to write to upstream socket", "error", err)
		}
	}
}
