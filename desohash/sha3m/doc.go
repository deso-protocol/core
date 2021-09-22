// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha3m implements the SHA-3 fixed-output-length hash functions with modifications for DeSo proof-of-work
//
// Guidance
//
// Security strengths
//
// The SHA3-x (x equals 224, 256, 384, or 512) functions have a security
// strength against preimage attacks of x bits. Since they only produce "x"
// bits of output, their collision-resistance is only "x/2" bits.
//
// The sponge construction
//
// A sponge builds a pseudo-random function from a public pseudo-random
// permutation, by applying the permutation to a state of "rate + capacity"
// bytes, but hiding "capacity" of the bytes.
//
// A sponge starts out with a zero state. To hash an input using a sponge, up
// to "rate" bytes of the input are XORed into the sponge's state. The sponge
// is then "full" and the permutation is applied to "empty" it. This process is
// repeated until all the input has been "absorbed". The input is then padded.
// The digest is "squeezed" from the sponge in the same way, except that output
// is copied out instead of input being XORed in.
//
// A sponge is parameterized by its generic security strength, which is equal
// to half its capacity; capacity + rate is equal to the permutation's width.
// Since the KeccakF-1600 permutation is 1600 bits (200 bytes) wide, this means
// that the security strength of a sponge instance is equal to (1600 - bitrate) / 2.
//
// The SHA-3 functions are "drop-in" replacements for the SHA-2 functions.
// They produce output of the same length, with the same security strengths
// against all attacks. This means, in particular, that SHA3-256 only has
// 128-bit collision resistance, because its output length is 32 bytes.
package sha3m // import "github.com/deso-protocol/lib/sha3m"
