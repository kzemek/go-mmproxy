// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buffers

import (
	"testing"
)

func TestGetGetsAPutBuffer(t *testing.T) {
	buf1 := Get()
	buf2 := Get()

	for i := range buf1 {
		buf1[i] = 127
	}

	Put(buf1)

	buf3 := Get()

	for i := range buf3 {
		if buf3[i] != 127 {
			t.Errorf("Expected to retrieve previously stored buffer")
		}
	}

	Put(buf3)
	Put(buf2)
}
