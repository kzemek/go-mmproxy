// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buffers

import (
	"math"
	"sync"
)

var buffers sync.Pool

func init() {
	buffers.New = func() any {
		slice := make([]byte, math.MaxUint16)
		return &slice
	}
}

func Get() []byte {
	return *buffers.Get().(*[]byte)
}

func Put(buf []byte) {
	buffers.Put(&buf)
}
