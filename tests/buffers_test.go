// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"testing"

	"github.com/kzemek/go-mmproxy/buffers"
)

func TestGetGetsAPutBuffer(t *testing.T) {
	buf1 := buffers.Get()
	buf2 := buffers.Get()

	for i := range buf1 {
		buf1[i] = 127
	}

	buffers.Put(buf1)

	buf3 := buffers.Get()

	for i := range buf3 {
		if buf3[i] != 127 {
			t.Errorf("Expected to retrieve previously stored buffer")
		}
	}

	buffers.Put(buf3)
	buffers.Put(buf2)
}
