package encoding

import (
	"bytes"
	"github.com/bits-and-blooms/bitset"
	"github.com/pkg/errors"
	"math"
	"sort"
)

// Elias-Fano encoding is a simple yet powerful algorithm that allows for lossless compression of a list of sorted
// positive integers. Given a list of positive integers (uint64) in ascending order with [size] elements in the
// range of [0, upperBound], the algorithm can represent the list using about (2 + log(upperBound / size)) * size
// bits. In many instances, this will turn out to be a fraction of the naive encoding size of 64 * size bits.
// Assuming we start with a sorted list, the computational complexity of the Elias-Fano encoding is O(size)
// for both the compression and decompression.
//
// We make a further optimization by normalizing the input integer sequence. If lowerBound is the smallest
// element in the sequence, we normalize each number to the range [0, upperBound - lowerBound] by simply
// subtracting lowerBound from each number. This makes the compression rate dependent on the variance of
// the input sequence, rather than the magnitude of the max element. As a result the size of the encoding
// becomes: ( 2 + log( (upperBound - lowerBound) / size ) ) * size bits.
//
// You can learn more about the inner-workings of the EF encoding from this article:
// 	https://www.antoniomallia.it/sorted-integers-compression-with-elias-fano-encoding.html
// And this paper on Quasi-Succinct Indices:
// 	https://arxiv.org/pdf/1206.4300.pdf
//
// Implementation is adapted from:
//	https://github.com/amallia/go-ef
// Most credit due to Antonio Mallia, who authored of the above repository.

// EncodingVersion is used during encoding for the sake of forward-compatibility.
const EncodingVersion = byte(0)

// RuleError is a wrapper around returned error messages.
type RuleError string

func (e RuleError) Error() string {
	return string(e)
}

const (
	ErrorIteratorOverflow = RuleError("ErrorIteratorOverflow")
	ErrorInvalidEncoding  = RuleError("ErrorInvalidEncoding")
	ErrorEmptyEncoding    = RuleError("ErrorEmptyEncoding")
)

// EFEncoder is the Elias-Fano Encoding data structure
type EFEncoder struct {
	// size is the number of elements in the encoded list.
	size uint64

	// upperBound is the largest number in the encoded list.
	upperBound uint64
	// lowerBound is the smallest number in the encoded list.
	lowerBound uint64

	// lowBits is the number of low bits of the number that will be encoded in the lowBitsEncoding.
	// Each number is encoded using log(upperBound) bits. We split these into log(upperBound) - lowBits
	// high bits, and the remaining lowBits of lower bits.
	lowBits uint64

	// highBitsEncoding store the information about the high bits of the input sequence.
	highBitsEncoding *bitset.BitSet

	// lowBitsEncoding store the information about the low bits of the input sequence.
	lowBitsEncoding *bitset.BitSet
}

// NewEFEncoder creates a new EFEncoder object containing the encoding of the provided input sequence.
func NewEFEncoder(sequence []uint64) *EFEncoder {

	// Return nil on empty input sequence.
	if len(sequence) == 0 {
		return nil
	}

	// Check if input sequence is sorted.
	normalizedSequence := make([]uint64, len(sequence))
	copy(normalizedSequence, sequence[:])

	// The input sequence is sorted for convenience. The encoding does not maintain information
	// about the position of each element. The sequence will be encoded/decoded in ascending order
	shouldSort := false
	for ii := 1; ii < len(sequence); ii++ {
		if sequence[ii-1] > sequence[ii] {
			shouldSort = true
		}
	}
	if shouldSort {
		sort.Slice(normalizedSequence, func(ii, jj int) bool {
			return normalizedSequence[ii] < normalizedSequence[jj]
		})
	}

	// Find the size of the input sequence.
	size := uint64(len(normalizedSequence))
	// Find the largest number in the input sequence, this will be our upperBound.
	upperBound := normalizedSequence[size-1]
	// Find the smallest number in the input sequence, this will be our lowerBound.
	lowerBound := normalizedSequence[0]

	// Normalize each element in the sequence by subtracting lowerBound.
	normalizedUpperBound := normalize(upperBound, lowerBound)
	for ii := 0; ii < len(sequence); ii++ {
		normalizedSequence[ii] = normalize(normalizedSequence[ii], lowerBound)
	}

	lowBits := uint64(0)
	if normalizedUpperBound > size {
		// Calculate the number of low bits per number in the sequence as
		// 	lowBits = Ceil( log_2( upperBound / size) )
		lowBits = uint64(math.Ceil(math.Log2(float64(normalizedUpperBound / size))))
	}

	// Calculate the total number of high bits.
	// We add +1 because we include the zero. Note that there is x+1 numbers in range [0, x].
	highBitsLength := size + (normalizedUpperBound >> lowBits) + 1
	// Also calculate the total number of low bits. The number of low bits is the
	// size of the input list times the number of low bits used to encode each number.
	lowBitsLength := size * lowBits

	// The size of the encoding will be the number of high bits + the number of low bits.
	highBitsEncoding := bitset.New(uint(highBitsLength))
	lowBitsEncoding := bitset.New(uint(lowBitsLength))

	// We use the mask to extract the low bits from the numbers in the sequence.
	// The AND operation will be applied to the number and the mask.
	mask := (uint64(1) << lowBits) - 1

	for ii, elem := range normalizedSequence {
		// We will first encode the high bits of the number. At the beginning, the highBitsEncoding
		// list has only 0-bits, and for each number in the sequence we process, we set a single 1-bit.
		// At the end, the highBitsEncoding will have: size x 1-bits, and the remaining bits set to 0.
		// The 0-bits in the highBitsEncoding correspond to numbers in the range [0, upperbound >> lowBits].
		// Simply, the i-th 0-bit corresponds to the number i. To determine which bit we should set for
		// a given number elem in the sequence, we count the number of 0s and 1s that were set for
		// numbers smaller than elem. This is equal to the elem >> lowBits (number of 0s) + ii (number of 1s).
		high := (elem >> lowBits) + uint64(ii)
		highBitsEncoding.Set(uint(high))

		// For lower bits, we will set the lowBits section of [ii*lowBits, (ii + 1)*lowBits - 1]
		offset := uint64(ii) * lowBits
		// Get the lower bits of the element by applying the mask.
		low := elem & mask
		for jj := uint64(0); jj < lowBits; jj++ {
			// Encode the low bits.
			// We subtract -1 because jj is in range [0, lowBits - 1] so the bit shift would be in range
			// [1, lowBits], but we want the bit shift to be in range [0, lowBits - 1]. Notice that
			// 1 << (lowBits - 1) gives us the most significant bit of numbers in range 2**lowBits - 1.
			val := low & (1 << (lowBits - jj - 1))
			lowBitsEncoding.SetTo(uint(offset+jj), val > 0)
		}
	}

	return &EFEncoder{
		size:             size,
		upperBound:       upperBound,
		lowerBound:       lowerBound,
		lowBits:          lowBits,
		highBitsEncoding: highBitsEncoding,
		lowBitsEncoding:  lowBitsEncoding,
	}
}

// GetSize returns the number of elements encoded.
func (ef *EFEncoder) GetSize() uint64 {
	return ef.size
}

// GetUpperBound returns the upperBound.
func (ef *EFEncoder) GetUpperBound() uint64 {
	return ef.upperBound
}

// GetLowerBound returns the lowerBound.
func (ef *EFEncoder) GetLowerBound() uint64 {
	return ef.lowerBound
}

// GetHighBitsReadOnly returns a copy of the encoded high bits.
func (ef *EFEncoder) GetHighBitsReadOnly() *bitset.BitSet {
	highBitsReadOnly := ef.highBitsEncoding.Clone()
	return highBitsReadOnly
}

// GetLowBitsReadOnly returns a copy of the encoded low bits.
func (ef *EFEncoder) GetLowBitsReadOnly() *bitset.BitSet {
	lowBitsReadOnly := ef.lowBitsEncoding.Clone()
	return lowBitsReadOnly
}

// GetSequence retrieves the encoded sequence.
func (ef *EFEncoder) GetSequence() ([]uint64, error) {

	// Define a new iterator.
	it, err := ef.GetIterator()
	if err != nil {
		return nil, errors.Wrapf(err, "GetSequence: ")
	}

	// Retrieve the sequence by iterating through the encoded sequence.
	sequence := make([]uint64, ef.size)
	for ; it.Valid(); _, err = it.Next() {
		if err != nil {
			return nil, errors.Wrapf(err, "GetSequence: ")
		}

		// Sanity-check that the iterator's position doesn't exceed the size of the sequence.
		if it.position >= ef.size {
			return nil, errors.Wrapf(ErrorIteratorOverflow, "GetSequence: Problem with iterator ")
		}
		sequence[it.position] = it.GetValue()
	}

	return sequence, nil
}

// ToBytes encodes the compressed sequence into a byte array.
func (ef *EFEncoder) ToBytes() []byte {
	data := []byte{}

	data = append(data, EncodingVersion)
	data = append(data, UintToBuf(ef.size)...)
	data = append(data, UintToBuf(ef.upperBound)...)
	data = append(data, UintToBuf(ef.lowerBound)...)
	data = append(data, UintToBuf(ef.lowBits)...)
	data = append(data, EncodeUint64Array(ef.highBitsEncoding.Bytes())...)
	data = append(data, EncodeUint64Array(ef.lowBitsEncoding.Bytes())...)

	// Prepend the size of the encoding to the bytes. The size of the encoding is used as a forward-compatibility
	// mechanism in the event we want to expand the encoding in the future.
	return append(UintToBuf(uint64(len(data))), data...)
}

// FromBytes decodes the EFEncoder from a reader.
func (ef *EFEncoder) FromBytes(rr *bytes.Reader) error {

	// Length is not currently used, but it might in the future.
	_, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "FromBytes: Problem decoding lenght ")
	}

	// Version is not currently used, but it might in the future.
	_, err = rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "FromBytes: Problem decoding version ")
	}

	size, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "FromBytes: Problem decoding size")
	}

	upperBound, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "FromBytes: Problem decoding upperBound")
	}

	lowerBound, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "FromBytes: Problem decoding lowerBound")
	}

	lowBits, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "FromBytes: Problem decoding lowBits")
	}

	highBitsUint64, err := DecodeUint64Array(rr)
	if err != nil {
		return errors.Wrapf(err, "FromBytes: Problem decoding highBitsEncoding")
	}
	highBitsEncoding := bitset.From(highBitsUint64)

	lowBitsUint64, err := DecodeUint64Array(rr)
	if err != nil {
		return errors.Wrapf(err, "FromBytes: Problem decoding lowBitsEncoding")
	}
	lowBitsEncoding := bitset.From(lowBitsUint64)

	// Now update all the fields of the EFEncoder.
	ef.size = size
	ef.upperBound = upperBound
	ef.lowerBound = lowerBound
	ef.lowBits = lowBits
	ef.highBitsEncoding = highBitsEncoding
	ef.lowBitsEncoding = lowBitsEncoding

	return nil
}

// GetIterator returns a new iterator pointed to the first element in the encoded sequence.
func (ef *EFEncoder) GetIterator() (*EFEncoderIterator, error) {
	it, err := NewEFEncoderIterator(ef)
	if err != nil {
		return nil, errors.Wrapf(err, "GetIterator: ")
	}

	return it, nil
}

// EFEncoderIterator is used to iterate through the encoded sequence in the EFEncoder.
type EFEncoderIterator struct {
	encoder          *EFEncoder
	position         uint64
	highBitsPosition uint64
}

// NewEFEncoderIterator creates a new iterator instance pointed to the first element in the encoded sequence.
func NewEFEncoderIterator(encoder *EFEncoder) (*EFEncoderIterator, error) {
	it := &EFEncoderIterator{
		encoder:          encoder,
		position:         0,
		highBitsPosition: 0,
	}
	if err := it.Reset(); err != nil {
		return nil, errors.Wrapf(err, "NewEFEncoderIterator: ")
	}

	return it, nil
}

// GetPosition retrieves the current position of the iterator.
func (it *EFEncoderIterator) GetPosition() uint64 {
	return it.position
}

// GetValue retrieves the value stored at the current iterator position.
func (it *EFEncoderIterator) GetValue() uint64 {
	// If the iterator reached the capacity of the encoded sequence, return the largest element, or the upper bound.
	if !it.Valid() {
		return it.encoder.upperBound
	}

	// First get the high bits of the number.
	// it.highBitsPosition points to the "1" in the high bits encoding corresponding to the current value.
	// To determine the number encoded in the high bits, we count the number of "0"s preceding the highBitsPosition.
	// This is equal to the high bits position subtract the number of "1"s present in the [0, highBitsPosition] prefix.
	highBits := uint64(0)
	highBits = (it.highBitsPosition - it.position) << it.encoder.lowBits

	// To get the low bits of the number, we need to read [lowBits] x bits from the low bits encoding.
	// We retrieve the section [it.position * lowBits, (it.position + 1) * lowBits [
	lowBits := uint64(0)
	lowPosition := it.position * it.encoder.lowBits
	for ii := uint64(0); ii < it.encoder.lowBits; ii++ {
		// Set the bit.
		if it.encoder.lowBitsEncoding.Test(uint(lowPosition + ii)) {
			lowBits++
		}
		lowBits <<= 1
	}
	// Shift right once, since we shifted one too many times in the loop.
	lowBits >>= 1

	// Concatenate the highBits | lowBits and denormalize the value using the lower bound.
	return denormalize(highBits|lowBits, it.encoder.lowerBound)
}

// Valid is used to test whether the iterator reached the end of the encoded sequence.
// returns:
//
//	true  - if the iterator can be pushed forward.
//	false - if the iterator reached the end of the encoded list.
func (it *EFEncoderIterator) Valid() bool {
	return it.position < it.encoder.size
}

// Reset points the iterator to the first element in the encoded sequence.
func (it *EFEncoderIterator) Reset() error {
	highBitsPosition, exists := it.encoder.highBitsEncoding.NextSet(0)
	if !exists {
		return errors.Wrapf(ErrorEmptyEncoding, "Reset: ")
	}

	it.highBitsPosition = uint64(highBitsPosition)
	it.position = 0
	return nil
}

// Next pushes the iterator to the next element in the encoded sequence. The function returns
// whether the iterator can be pushed further:
//
//	(true, nil)    - iterator was pushed forward.
//	(false, nil)   - iterator end reached so the iterator wasn't pushed.
//	(false, error) - failed
func (it *EFEncoderIterator) Next() (_success bool, _err error) {
	// Increment the position of the iterator.
	it.position++

	// If we exceed the capacity of the encoded array, we can't push forward.
	if !it.Valid() {
		return false, nil
	}

	// Look for the next "1" bit in the high bits encoding. Update the iterator high bits position
	// to point to this element in the encoded sequence.
	var exists bool
	highBitsPosition := uint(it.highBitsPosition) + 1
	highBitsPosition, exists = it.encoder.highBitsEncoding.NextSet(highBitsPosition)
	if !exists {
		return false, errors.Wrapf(ErrorInvalidEncoding, "Next: ")
	}
	it.highBitsPosition = uint64(highBitsPosition)
	return true, nil
}

// JumpTo points the iterator to the provided position in the encoded sequence.
func (it *EFEncoderIterator) JumpTo(position uint64) error {
	if position >= it.encoder.size {
		return errors.Wrapf(ErrorIteratorOverflow, "JumpTo: Position exceeds size of the encoded sequence ")
	}

	if position == it.position {
		return nil
	}

	var err error
	if position < it.position {
		if err = it.Reset(); err != nil {
			return errors.Wrapf(err, "JumpTo: ")
		}
	}

	for ; it.position != position; _, err = it.Next() {
		if err != nil {
			return errors.Wrapf(err, "JumpTo: ")
		}
	}

	return nil
}

func normalize(elem uint64, lowerBound uint64) (_normalizedElem uint64) {
	return elem - lowerBound
}

func denormalize(normalizedElem uint64, lowerBound uint64) uint64 {
	return normalizedElem + lowerBound
}
