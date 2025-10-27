// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"flag"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kzemek/go-mmproxy/tcp"
	"github.com/kzemek/go-mmproxy/udp"
	"github.com/kzemek/go-mmproxy/utils"
)

var protocolStr string
var listenAddrStr string
var targetAddr4Str string
var targetAddr6Str string
var allowedSubnetsPath string
var udpCloseAfterInt int
var listeners int

var opts utils.Options

func init() {
	flag.StringVar(&protocolStr, "p", "tcp", "Protocol that will be proxied: tcp, udp")
	flag.StringVar(&listenAddrStr, "l", "0.0.0.0:8443", "Address the proxy listens on")
	flag.StringVar(&targetAddr4Str, "4", "127.0.0.1:443", "Address to which IPv4 traffic will be forwarded to")
	flag.StringVar(&targetAddr6Str, "6", "[::1]:443", "Address to which IPv6 traffic will be forwarded to")
	flag.BoolVar(&opts.DynamicDestination, "dynamic-destination", false, "Traffic will be forwarded to the destination specified in the PROXY protocol header")
	flag.IntVar(&opts.Mark, "mark", 0, "The mark that will be set on outbound packets")
	flag.IntVar(&opts.Verbose, "v", 0, `0 - no logging of individual connections
1 - log errors occurring in individual connections
2 - log all state changes of individual connections`)
	flag.StringVar(&allowedSubnetsPath, "allowed-subnets", "",
		"Path to a file that contains allowed subnets of the proxy servers")
	flag.IntVar(&listeners, "listeners", 1,
		"Number of listener sockets that will be opened for the listen address (Linux 3.9+)")
	flag.IntVar(&udpCloseAfterInt, "close-after", 60, "Number of seconds after which UDP socket will be cleaned up on inactivity")
}

func listen(ctx context.Context, listenerNum int, parentLogger *slog.Logger, wg *sync.WaitGroup) {
	defer wg.Done()

	logger := parentLogger.With(slog.Int("listenerNum", listenerNum),
		slog.String("protocol", protocolStr), slog.String("listenAddr", opts.ListenAddr.String()))

	listenConfig := net.ListenConfig{}
	if listeners > 1 {
		listenConfig.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				soReusePort := 15
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1); err != nil {
					logger.Warn("failed to set SO_REUSEPORT - only one listener setup will succeed")
				}
			})
		}
	}

	if err := doListen(ctx, &listenConfig, logger); err != nil {
		logger.Error("lister error", slog.Any("error", err))
	}
}

func doListen(ctx context.Context, listenConfig *net.ListenConfig, logger *slog.Logger) error {
	if opts.Protocol == utils.TCP {
		return doListenTCP(ctx, listenConfig, logger)
	} else {
		return doListenUDP(ctx, listenConfig, logger)
	}
}

func doListenTCP(ctx context.Context, listenConfig *net.ListenConfig, logger *slog.Logger) error {
	ln, err := tcp.Listen(ctx, listenConfig, &opts)
	if err != nil {
		return err
	}
	defer ln.Close()
	logger.Info("listening")
	return tcp.AcceptLoop(ln, &opts, logger)
}

func doListenUDP(ctx context.Context, listenConfig *net.ListenConfig, logger *slog.Logger) error {
	ln, err := udp.Listen(ctx, listenConfig, &opts)
	if err != nil {
		return err
	}
	defer ln.Close()
	logger.Info("listening")
	return udp.AcceptLoop(ln, &opts, logger)
}

func loadAllowedSubnets(logger *slog.Logger) error {
	file, err := os.Open(allowedSubnetsPath)
	if err != nil {
		return err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		splitText := strings.SplitN(scanner.Text(), "#", 2)
		text := strings.TrimSpace(splitText[0])
		if text == "" {
			continue
		}
		ipNet, err := netip.ParsePrefix(text)
		if err != nil {
			return err
		}
		opts.AllowedSubnets = append(opts.AllowedSubnets, ipNet)
		logger.Info("allowed subnet", slog.String("subnet", ipNet.String()))
	}

	return nil
}

func main() {
	flag.Parse()
	lvl := slog.LevelInfo
	if opts.Verbose > 0 {
		lvl = slog.LevelDebug
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))

	if allowedSubnetsPath != "" {
		if err := loadAllowedSubnets(logger); err != nil {
			logger.Error("failed to load allowed subnets file", "path", allowedSubnetsPath, "error", err)
		}
	}

	if protocolStr == "tcp" {
		opts.Protocol = utils.TCP
	} else if protocolStr == "udp" {
		opts.Protocol = utils.UDP
	} else {
		logger.Error("--protocol has to be one of udp, tcp", slog.String("protocol", protocolStr))
		os.Exit(1)
	}

	if opts.Mark < 0 {
		logger.Error("--mark has to be >= 0", slog.Int("mark", opts.Mark))
		os.Exit(1)
	}

	if opts.Verbose < 0 {
		logger.Error("-v has to be >= 0", slog.Int("verbose", opts.Verbose))
		os.Exit(1)
	}

	if listeners < 1 {
		logger.Error("--listeners has to be >= 1")
		os.Exit(1)
	}

	var err error
	if opts.ListenAddr, err = utils.ParseHostPort(listenAddrStr, 0); err != nil {
		logger.Error("listen address is malformed", "error", err)
		os.Exit(1)
	}

	if opts.TargetAddr4, err = utils.ParseHostPort(targetAddr4Str, 4); err != nil {
		logger.Error("ipv4 target address is malformed", "error", err)
		os.Exit(1)
	}
	if !opts.TargetAddr4.Addr().Is4() {
		logger.Error("ipv4 target address is not IPv4")
		os.Exit(1)
	}

	if opts.TargetAddr6, err = utils.ParseHostPort(targetAddr6Str, 6); err != nil {
		logger.Error("ipv6 target address is malformed", "error", err)
		os.Exit(1)
	}
	if !opts.TargetAddr6.Addr().Is6() {
		logger.Error("ipv6 target address is not IPv6")
		os.Exit(1)
	}

	if udpCloseAfterInt < 0 {
		logger.Error("--close-after has to be >= 0", slog.Int("close-after", udpCloseAfterInt))
		os.Exit(1)
	}
	opts.UDPCloseAfter = time.Duration(udpCloseAfterInt) * time.Second

	wg := sync.WaitGroup{}
	ctxs := make([]context.Context, listeners)
	for i := range ctxs {
		ctxs[i] = context.Background()
		wg.Add(1)
		go listen(ctxs[i], i, logger, &wg)
	}

	wg.Wait()
}
