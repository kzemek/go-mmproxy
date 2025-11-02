// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024-2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kzemek/go-mmproxy/internal/buffers"
	"github.com/kzemek/go-mmproxy/internal/tcp"
	"github.com/kzemek/go-mmproxy/internal/udp"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

func listen(ctx context.Context, listenerNum int, wg *sync.WaitGroup, config utils.Config) {
	defer wg.Done()

	config.Logger = config.Logger.With(
		slog.Int("listenerNum", listenerNum),
		slog.String("protocol", config.Opts.Protocol.String()),
		slog.String("listenAddr", config.Opts.ListenAddr.String()))

	listenConfig := net.ListenConfig{}
	listenConfig.Control = func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if config.Opts.ListenTransparent {
				if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1); err != nil {
					config.Logger.Warn("failed to set IP_TRANSPARENT on listen port",
						slog.String("error", err.Error()))
				}
			}

			if config.Opts.Listeners > 1 {
				soReusePort := 15
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1); err != nil {
					config.Logger.Warn("failed to set SO_REUSEPORT - only one listener setup will succeed",
						slog.String("error", err.Error()))
				}
			}
		})
	}

	if err := doListen(ctx, &listenConfig, config); err != nil {
		config.Logger.Error("listen error", slog.Any("error", err))
	}
}

func doListen(ctx context.Context, listenConfig *net.ListenConfig, config utils.Config) error {
	switch config.Opts.Protocol {
	case utils.TCP:
		return doListenTCP(ctx, listenConfig, config)
	case utils.UDP:
		return doListenUDP(ctx, listenConfig, config)
	default:
		panic(fmt.Sprintf("invalid protocol %d", config.Opts.Protocol))
	}
}

func doListenTCP(ctx context.Context, listenConfig *net.ListenConfig, config utils.Config) error {
	ln, err := tcp.Listen(ctx, listenConfig, config)
	if err != nil {
		return err
	}
	defer utils.CloseWithLogOnError(ln, config.Logger, "listener")

	config.Logger.Info("listening")
	return tcp.AcceptLoop(ln, config)
}

func doListenUDP(ctx context.Context, listenConfig *net.ListenConfig, config utils.Config) error {
	ln, err := udp.Listen(ctx, listenConfig, config)
	if err != nil {
		return err
	}
	defer utils.CloseWithLogOnError(ln, config.Logger, "listener")
	config.Logger.Info("listening")
	return udp.AcceptLoop(ln, config)
}

func loadAllowedSubnets(allowedSubnetsPath string) ([]netip.Prefix, error) {
	file, err := os.Open(allowedSubnetsPath)
	if err != nil {
		return nil, err
	}

	defer func() { _ = file.Close() }()

	allowedSubnets := make([]netip.Prefix, 0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		splitText := strings.SplitN(scanner.Text(), "#", 2)
		text := strings.TrimSpace(splitText[0])
		if text == "" {
			continue
		}
		ipNet, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, err
		}
		allowedSubnets = append(allowedSubnets, ipNet)
	}

	return allowedSubnets, nil
}

func parseOptions() (*utils.Options, error) {
	var protocolStr string
	var listenAddrStr string
	var targetAddr4Str string
	var targetAddr6Str string
	var allowedSubnetsPath string
	var udpCloseAfterInt int

	opts := &utils.Options{}

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
	flag.IntVar(&opts.Listeners, "listeners", 1,
		"Number of listener sockets that will be opened for the listen address (Linux 3.9+)")
	flag.IntVar(&udpCloseAfterInt, "close-after", 60, "Number of seconds after which UDP socket will be cleaned up on inactivity")
	flag.BoolVar(&opts.ListenTransparent, "listen-transparent", false, "Set IP_TRANSPARENT on the listen ports")

	flag.Parse()

	switch protocolStr {
	case "tcp":
		opts.Protocol = utils.TCP
	case "udp":
		opts.Protocol = utils.UDP
	default:
		return nil, fmt.Errorf("--protocol has to be one of udp, tcp")
	}

	if opts.Mark < 0 {
		return nil, fmt.Errorf("--mark has to be >= 0")
	}

	if opts.Verbose < 0 || opts.Verbose > 2 {
		return nil, fmt.Errorf("-v has to be between 0 and 2")
	}

	if opts.Listeners < 1 {
		return nil, fmt.Errorf("--listeners has to be >= 1")
	}

	var err error
	if opts.ListenAddr, err = utils.ParseHostPort(listenAddrStr, 0); err != nil {
		return nil, fmt.Errorf("-l listen address is malformed: %w", err)
	}

	if opts.TargetAddr4, err = utils.ParseHostPort(targetAddr4Str, 4); err != nil {
		return nil, fmt.Errorf("-4 ipv4 target address is malformed: %w", err)
	}
	if !opts.TargetAddr4.Addr().Is4() {
		return nil, fmt.Errorf("-4 ipv4 target address is not IPv4")
	}

	if opts.TargetAddr6, err = utils.ParseHostPort(targetAddr6Str, 6); err != nil {
		return nil, fmt.Errorf("-6 ipv6 target address is malformed: %w", err)
	}
	if !opts.TargetAddr6.Addr().Is6() {
		return nil, fmt.Errorf("-6 ipv6 target address is not IPv6")
	}

	if udpCloseAfterInt < 0 {
		return nil, fmt.Errorf("-close-after has to be >= 0")
	}
	opts.UDPCloseAfter = time.Duration(udpCloseAfterInt) * time.Second

	if allowedSubnetsPath != "" {
		opts.AllowedSubnets, err = loadAllowedSubnets(allowedSubnetsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load allowed subnets: %w", err)
		}
    }

	return opts, nil
}

func initLogger(opts *utils.Options) *slog.Logger {
	logLvl := slog.LevelInfo
	if opts.Verbose > 0 {
		logLvl = slog.LevelDebug
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLvl}))
}

func main() {
	opts, err := parseOptions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	config := utils.Config{
		Opts:       opts,
		Logger:     initLogger(opts),
		BufferPool: buffers.New(),
	}

	for _, allowedSubnet := range opts.AllowedSubnets {
		config.Logger.Info("allowed subnet", slog.String("subnet", allowedSubnet.String()))
	}

	wg := sync.WaitGroup{}
	ctxs := make([]context.Context, opts.Listeners)
	for i := range ctxs {
		ctxs[i] = context.Background()
		wg.Add(1)
		go listen(ctxs[i], i, &wg, config)
	}

	wg.Wait()
}
