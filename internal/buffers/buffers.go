// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024-2025 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buffers

import (
	"math"
	"sync"
)

type BufferPool interface {
	Get() []byte
	Put(buf []byte)
}

type bufferPool struct {
	pool sync.Pool
}

func New() BufferPool {
	return &bufferPool{
		pool: sync.Pool{
			New: func() any {
				slice := make([]byte, math.MaxUint16)
				return &slice
			},
		},
	}
}

func (p *bufferPool) Get() []byte {
	return *p.pool.Get().(*[]byte)
}

func (p *bufferPool) Put(buf []byte) {
	p.pool.Put(&buf)
}
