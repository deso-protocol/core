package lib

import (
	"bytes"
	"github.com/pkg/errors"
)

// Generic Set object. Retains the order elements are addd to the set.
type Set[T comparable] struct {
	_innerMap map[T]struct{}
}

func NewSet[T comparable](elements []T) *Set[T] {
	set := &Set[T]{_innerMap: make(map[T]struct{})}
	for _, element := range elements {
		set.Add(element)
	}
	return set
}

func (set *Set[T]) Add(element T) {
	// Add element to set.
	if !set.Includes(element) {
		set._innerMap[element] = struct{}{}
	}
}

func (set *Set[T]) Remove(element T) {
	// Remove element from set.
	if set.Includes(element) {
		delete(set._innerMap, element)
	}
}

func (set *Set[T]) Size() int {
	// Return size of set.
	return len(set._innerMap)
}

func (set *Set[T]) Includes(element T) bool {
	// True if the element exists in the set.
	_, exists := set._innerMap[element]
	return exists
}

func (set *Set[T]) ForEach(applyFunc func(elem T) error) error {
	for mapKey := range set._innerMap {
		if err := applyFunc(mapKey); err != nil {
			return err
		}
	}
	return nil
}

func (set *Set[T]) ToSlice() []T {
	// Convert the set to a slice.
	var results []T
	for element := range set._innerMap {
		results = append(results, element)
	}
	return results
}

func MapSet[T comparable, K any](set *Set[T], mapFunc func(elem T) (K, error)) ([]K, error) {
	var results []K
	err := set.ForEach(func(elem T) error {
		mappedResult, innerErr := mapFunc(elem)
		if innerErr != nil {
			return innerErr
		}
		results = append(results, mappedResult)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// Pass in nil as the entry
func DecodeDeSoEncoder[T DeSoEncoder](entry T, rr *bytes.Reader) (T, error) {
	var emptyEntry T
	exist, err := DecodeFromBytes(entry, rr)
	if !exist {
		return emptyEntry, nil
	}
	if err != nil {
		return emptyEntry, errors.Wrapf(err, "DecodeDeSoEncoder: Problem decoding from bytes")
	}
	return entry, nil
}

func EncodeDeSoEncoderSlice[T DeSoEncoder](inputSlice []T, blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	numItems := uint64(len(inputSlice))
	data = append(data, UintToBuf(numItems)...)
	for _, item := range inputSlice {
		data = append(data, EncodeToBytes(blockHeight, item, skipMetadata...)...)
	}
	return data
}

func DecodeDeSoEncoderSlice[T DeSoEncoder](rr *bytes.Reader) ([]T, error) {
	numItems, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeSlice: Problem decoding numItems")
	}
	// Note: is it more efficient to do a make with specific length and set at each index?
	inputs := make([]T, numItems)
	var results []T
	for ii := uint64(0); ii < numItems; ii++ {
		entry, err := DecodeDeSoEncoder[T](inputs[ii].GetEncoderType().New().(T), rr)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeSlice: Problem decoding item %d of %d", ii, numItems)
		}
		if entry != nil {
			results = append(results, entry)
		}
	}
	return results, nil
}
