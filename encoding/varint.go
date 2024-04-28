package encoding

// This file implements "varint" encoding of 64-bit integers.
// The encoding is:
// - unsigned integers are serialized 7 bits at a time, starting with the
//   least significant bits
// - the most significant bit (msb) in each output byte indicates if there
//   is a continuation byte (msb = 1)
// - signed integers are mapped to unsigned integers using "zig-zag"
//   encoding: Positive values x are written as 2*x + 0, negative values
//   are written as 2*(^x) + 1; that is, negative numbers are complemented
//   and whether to complement is encoded in bit 0.
//
// Design note:
// At most 10 bytes are needed for 64-bit values. The encoding could
// be more dense: a full 64-bit value needs an extra byte just to hold bit 63.
// Instead, the msb of the previous byte could be used to hold bit 63 since we
// know there can't be more than 64 bits. This is a trivial improvement and
// would reduce the maximum encoding length to 9 bytes. However, it breaks the
// invariant that the msb is always the "continuation bit" and thus makes the
// format incompatible with a varint encoding for larger numbers (say 128-bit).

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"io"
)

// MaxVarintLenN is the maximum length of a varint-encoded N-bit integer.
const (
	MaxVarintLen16 = 3
	MaxVarintLen32 = 5
	MaxVarintLen64 = 10
)

func UintToBuf(xx uint64) []byte {
	scratchBytes := make([]byte, MaxVarintLen64)
	nn := PutUvarint(scratchBytes, xx)
	return scratchBytes[:nn]
}

// PutUvarint encodes a uint64 into buf and returns the number of bytes written.
// If the buffer is too small, PutUvarint will panic.
func PutUvarint(buf []byte, x uint64) int {
	i := 0
	for x >= 0x80 {
		buf[i] = byte(x) | 0x80
		x >>= 7
		i++
	}
	buf[i] = byte(x)
	return i + 1
}

// Uvarint decodes a uint64 from buf and returns that value and the
// number of bytes read (> 0). If an error occurred, the value is 0
// and the number of bytes n is <= 0 meaning:
//
//	n == 0: buf too small
//	n  < 0: value larger than 64 bits (overflow)
//	        and -n is the number of bytes read
func Uvarint(buf []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, b := range buf {
		if b < 0x80 {
			if i > 9 || i == 9 && b > 1 {
				return 0, -(i + 1) // overflow
			}
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0
}

func IntToBuf(xx int64) []byte {
	scratchBytes := make([]byte, MaxVarintLen64)
	nn := PutVarint(scratchBytes, xx)
	return scratchBytes[:nn]
}

// PutVarint encodes an int64 into buf and returns the number of bytes written.
// If the buffer is too small, PutVarint will panic.
func PutVarint(buf []byte, x int64) int {
	ux := uint64(x) << 1
	if x < 0 {
		ux = ^ux
	}
	return PutUvarint(buf, ux)
}

// Varint decodes an int64 from buf and returns that value and the
// number of bytes read (> 0). If an error occurred, the value is 0
// and the number of bytes n is <= 0 with the following meaning:
//
//	n == 0: buf too small
//	n  < 0: value larger than 64 bits (overflow)
//	        and -n is the number of bytes read
func Varint(buf []byte) (int64, int) {
	ux, n := Uvarint(buf) // ok to continue in presence of error
	x := int64(ux >> 1)
	if ux&1 != 0 {
		x = ^x
	}
	return x, n
}

var overflow = errors.New("binary: varint overflows a 64-bit integer")

// ReadUvarint reads an encoded unsigned integer from r and returns it as a uint64.
func ReadUvarint(r io.Reader) (uint64, error) {
	var x uint64
	var s uint
	buf := []byte{0x00}
	for i := 0; ; i++ {
		nn, err := io.ReadFull(r, buf)
		if err != nil || nn != 1 {
			return x, err
		}
		b := buf[0]
		if b < 0x80 {
			if i > 9 || i == 9 && b > 1 {
				return x, overflow
			}
			return x | uint64(b)<<s, nil
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
}

// ReadVarint reads an encoded signed integer from r and returns it as an int64.
func ReadVarint(r io.Reader) (int64, error) {
	ux, err := ReadUvarint(r) // ok to continue in presence of error
	x := int64(ux >> 1)
	if ux&1 != 0 {
		x = ^x
	}
	return x, err
}

func EncodeUint64Array(nums []uint64) []byte {
	var data []byte

	data = append(data, UintToBuf(uint64(len(nums)))...)
	for _, vv := range nums {
		data = append(data, UintToBuf(vv)...)
	}
	return data
}

func DecodeUint64Array(rr *bytes.Reader) ([]uint64, error) {
	numsLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeUint64Array: Problem reading lenght")
	}

	if numsLen > 0 {
		var nums []uint64
		nums, err = SafeMakeSliceWithLength[uint64](numsLen)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeUint64Array: Problem creating slice")
		}

		for ii := 0; ii < int(numsLen); ii++ {
			nums[ii], err = ReadUvarint(rr)
			if err != nil {
				return nil, errors.Wrapf(err, "DecodeUint64Array: Problem reading number")
			}
		}
		return nums, nil
	} else {
		return nil, nil
	}
}

// SafeMakeSliceWithLength catches a panic in the make function and returns and
// error if the make function panics. Note that we typically do not allow named return
// value in function signatures. However, in this case, we must use a named return value
// for the error, so we can properly return an error if make panics.
func SafeMakeSliceWithLength[T any](length uint64) (_ []T, outputError error) {
	defer SafeMakeRecover(&outputError)
	return make([]T, length), outputError
}

// SafeMakeRecover recovers from a panic and sets the value of error parameter.
// This function should be called with defer so it ALWAYS runs after the execution of a function.
// This way if a function execution ends with a panic, SafeMakeRecover will "recover" the panic
// and set the error appropriately. We set the value of the pointer to the output error such
// that the calling function will return an error instead of a nil value. Unfortunately,
// there is no way to overwrite the return value of the calling function with a deferred function
// without the usage of named return values.
func SafeMakeRecover(outputError *error) {
	if err := recover(); err != nil {
		*outputError = errors.New(fmt.Sprintf("Error in make: %v", err))
	}
}
