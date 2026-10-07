// Copyright 2024-2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"math"
	"testing"
	"time"
)

func TestParseUDPCloseAfter(t *testing.T) {
	maxSeconds := int(math.MaxInt64 / int64(time.Second))
	for _, testCase := range []struct {
		name    string
		seconds int
		want    time.Duration
		wantOk  bool
	}{
		{name: "zero", seconds: 0, want: 0, wantOk: true},
		{name: "one minute", seconds: 60, want: time.Minute, wantOk: true},
		{name: "negative", seconds: -1, wantOk: false},
		{
			name: "max duration", seconds: maxSeconds,
			want: time.Duration(maxSeconds) * time.Second, wantOk: true,
		},
		{name: "overflow", seconds: maxSeconds + 1, wantOk: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, valid := parseUDPCloseAfter(testCase.seconds)
			if valid != testCase.wantOk {
				t.Fatalf(
					"expected valid=%v for %d seconds, got %v",
					testCase.wantOk,
					testCase.seconds,
					valid,
				)
			}
			if valid && got != testCase.want {
				t.Fatalf("expected %v, got %v", testCase.want, got)
			}
		})
	}
}
