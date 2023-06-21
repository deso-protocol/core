package bitset

import (
	"math/big"
)

type Bitset struct {
	store *big.Int
}

// NewBitSet creates a new ordered bit list of arbitrary length, using a
// big.Int as the underlying storage. It maintains an ordered bit list
// of arbitrary length, where the bit at index i has value 1 or 0, and
// represents if the value i is in the set to true or false.
//
// We implement a custom Bitset data structure rather than using an
// off-the-shelf solution because we need to support byte encoding and
// decoding with a known endianness. Out of the box, the built in big.Int
// supports bit operations, dynamic resizing, and big endian byte
// encoding/decoding.
//
// This allows us to implement a straightforward  Bitset data structure while
// having full transparency into the underlying implementation, and no reliance
// on 3rd party libraries.
func NewBitset() Bitset {
	return Bitset{
		store: big.NewInt(0),
	}
}

func (b *Bitset) Get(index int) bool {
	return b.store.Bit(index) == 1
}

func (b *Bitset) Set(index int, newValue bool) {
	booleanValue := uint(0)
	if newValue {
		booleanValue = 1
	}

	b.store.SetBit(b.store, index, booleanValue)
}

// Returns the total number of bits used by this bitset. This is
// equivalent to the length of the absolute value of the underlying
// big.Int.
//
// This also means that the highest index set to true is b.Size() - 1.
// All indices beyond are implicitly false.
func (b *Bitset) Size() int {
	return b.store.BitLen()
}

// Return the absolute value of the underlying the BigSet as a big-endian
// byte slice. The output is compressed such that if the underlying
// big.Int had zeros at the highest bits, they will be removed
// from the output.
func (b *Bitset) ToBytes() []byte {
	return b.store.Bytes()
}

// Populates the BitSet from a big-endian byte slice.
func (b *Bitset) FromBytes(bytes []byte) {
	if b.store == nil {
		b.store = big.NewInt(0)
	}
	b.store.SetBytes(bytes)
}
