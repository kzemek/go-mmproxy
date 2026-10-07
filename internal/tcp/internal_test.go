// Copyright 2024-2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"syscall"
	"testing"

	"github.com/kzemek/go-mmproxy/internal/utils"
)

func testConfig() utils.Config {
	return utils.Config{
		Opts:   &utils.Options{},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestAcceptLoop_ReturnsOnClosedListener(t *testing.T) {
	calls := 0
	accept := func() (*net.TCPConn, error) {
		calls++
		return nil, net.ErrClosed
	}

	err := acceptLoop(accept, testConfig())
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected accept to be called once, got %d calls", calls)
	}
}

func TestAcceptLoop_RetriesTransientErrors(t *testing.T) {
	calls := 0
	accept := func() (*net.TCPConn, error) {
		calls++
		if calls <= 2 {
			return nil, &net.OpError{Op: "accept", Err: syscall.EMFILE}
		}
		return nil, net.ErrClosed
	}

	err := acceptLoop(accept, testConfig())
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected accept to be retried on transient errors, got %d calls", calls)
	}
}
