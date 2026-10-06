// Copyright 2026 Stefan Meinecke <meinecke@greensec.de>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSubnetsFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "allowed-subnets.txt")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("Failed to write subnets file: %v", err)
	}
	return path
}

func TestLoadAllowedSubnets(t *testing.T) {
	subnets, err := loadAllowedSubnets(
		writeSubnetsFile(t, "10.0.0.0/8\n# comment\n\n 192.168.0.0/16 # trailing\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subnets) != 2 {
		t.Fatalf("got %d subnets, want 2", len(subnets))
	}
}

// A line beyond bufio.Scanner's 64KiB token limit must surface an error
// instead of silently truncating the parsed allowlist.
func TestLoadAllowedSubnets_oversizedLine(t *testing.T) {
	_, err := loadAllowedSubnets(writeSubnetsFile(t, strings.Repeat("a", 70_000)+"\n"))
	if err == nil {
		t.Fatal("expected error for oversized line, got nil")
	}
}

// An empty allowlist would silently allow every origin - fail closed instead.
func TestLoadAllowedSubnets_empty(t *testing.T) {
	for _, contents := range []string{"", "# only comments\n", "\n\n"} {
		if _, err := loadAllowedSubnets(writeSubnetsFile(t, contents)); err == nil {
			t.Fatalf("expected error for contents %q, got nil", contents)
		}
	}
}
