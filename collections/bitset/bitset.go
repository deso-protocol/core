package bitset

import (
	"math/big"
)

// A Bitset is an ordered list of bits with arbitrary length. It uses
// the built-in big.Int as the underlying storage scheme. The big.Int maintains
// an ordered list of bits and provides an interface where we can flip each bit
// individually. The Bitset type acts as a wrapper and a clean interface on top.
//
// We implement a custom Bitset data structure using Big.Int rather than using
// an off-the-shelf solution because we need to support byte encoding and decoding
// with known endianness. Out of the box, the built-in big.Int supports individual
// bit operations, safe indexing & boundary checks, dynamic resizing, and big
// endian byte encoding/decoding. It allows us to implement a straightforward
// Bitset data structure while having full transparency into the underlying
// implementation, and no reliance on 3rd party libraries.
type Bitset struct {
	store *big.Int
}

// Initializes a new Bitset with zero value for all bits.
func NewBitset() *Bitset {
	return &Bitset{
		store: big.NewInt(0),
	}
}

// Gets the value of the bit at the given index.
func (b *Bitset) Get(index int) bool {
	return b.store.Bit(index) == 1
}

// Set the value of the bit at the given index, and returns the updated Bitset
// for method chaining.
func (b *Bitset) Set(index int, newValue bool) *Bitset {
	booleanValue := uint(0)
	if newValue {
		booleanValue = 1
	}

	b.store.SetBit(b.store, index, booleanValue)
	return b
}

// Returns the total number of bits used by this bitset. This is
// equivalent to the length of the absolute value of the underlying
// big.Int.
//
// This also means that the highest index set to true is b.Size() - 1.
// All indices beyond are implicitly false.
//
// Example:
// Given a sequence of values 11 values:
// - [true, true, true, false, false, false, false, false, true, false, false]
// This function returns a size of 9. The highest index set to true is 8, and
// all other indices beyond are implicitly false.
func (b *Bitset) Size() int {
	return b.store.BitLen()
}

// Return the absolute value of the underlying the BigInt as a big-endian
// byte slice. The output is compressed such that if the underlying
// big.Int had zeros at the highest bits, they will be removed
// from the output.
//
// Example:
// Given a sequence of values 11 values:
// - [true, true, true, false, false, false, false, false, true, false, false]
// This function returns the byte slice:
// - [00000001, 00000111]
func (b *Bitset) ToBytes() []byte {
	if b == nil || b.store == nil {
		return []byte{}
	}
	return b.store.Bytes()
}

// Populates the BitSet from a big-endian byte slice.
func (b *Bitset) FromBytes(bytes []byte) *Bitset {
	if b.store == nil {
		b.store = big.NewInt(0)
	}
	b.store.SetBytes(bytes)
	return b
}

func (b *Bitset) Eq(other *Bitset) bool {
	if b == nil || other == nil {
		return false
	}
	return b.store.Cmp(other.store) == 0
}
