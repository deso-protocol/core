// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3m

// This file provides functions for creating instances of the SHA-3m function

import (
	"hash"
)

// New256 creates a new SHA3-256 hash.
// Its generic security strength is 256 bits against preimage attacks,
// and 128 bits against collision attacks.
func New256() hash.Hash {
	return &state{rate: 136, outputLen: 32, dsbyte: 0x06}
}

// Sum256 returns the SHA3-256 digest of the data.
func Sum256(data []byte) (digest [32]byte) {
	h := New256()
	h.Write(data)
	h.Sum(digest[:0])
	return
}
