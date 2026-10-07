// Copyright 2024-2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"syscall"
	"testing"

	"github.com/kzemek/go-mmproxy/internal/setsockopt"
	"github.com/kzemek/go-mmproxy/internal/utils"
)

func transparentSupported(t *testing.T) bool {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("failed to create probe socket: %v", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	return setsockopt.IPTransparent(uintptr(fd), true) == nil
}

func TestListenControl_TransparentFailureFailsListen(t *testing.T) {
	config := utils.Config{
		Opts:   &utils.Options{ListenTransparent: true, Listeners: 1},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	listenConfig := net.ListenConfig{Control: listenControl(config)}

	listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if transparentSupported(t) {
		if err != nil {
			t.Fatalf("listen failed although IP_TRANSPARENT could be set: %v", err)
		}
		_ = listener.Close()
		return
	}

	if err == nil {
		_ = listener.Close()
		t.Fatal("expected listen to fail when IP_TRANSPARENT cannot be set")
	}
}
