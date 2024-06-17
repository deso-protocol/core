package collections

import (
	"fmt"
	"math/rand"
	"sort"
	"time"
)

func All[T any](slice []T, predicate func(T) bool) bool {
	negatedPredicate := func(val T) bool {
		return !predicate(val)
	}
	return !Any(slice, negatedPredicate)
}

func Any[T any](slice []T, predicate func(T) bool) bool {
	for _, val := range slice {
		if predicate(val) {
			return true
		}
	}
	return false
}

func Contains[T comparable](slice []T, value T) bool {
	return Any(slice, func(val T) bool {
		return val == value
	})
}

func Transform[TInput any, TOutput any](slice []TInput, transformFn func(TInput) TOutput) []TOutput {
	var result []TOutput
	for _, val := range slice {
		result = append(result, transformFn(val))
	}
	return result
}

func RandomElement[T any](slice []T) (T, error) {
	if len(slice) == 0 {
		return *new(T), fmt.Errorf("RandomElement: input slice is empty")
	}

	src := rand.NewSource(time.Now().UnixNano())
	index := src.Int63() % int64(len(slice))
	return slice[index], nil
}

// SortStable wraps the built-in sort.SliceStable function to return a sorted slice
// given an input slice, without any side effects on the input. Params:
//   - input: the original slice whose contents will be sorted
//   - comparator: anonymous function that takes in two values A and B, and returns true if
//     A precedes B in the intended sorting
func SortStable[T any](slice []T, lessFn func(T, T) bool) []T {
	result := make([]T, len(slice))
	copy(result, slice)
	sort.SliceStable(result, func(ii, jj int) bool {
		return lessFn(result[ii], result[jj])
	})
	return result
}

func ToMap[TKey comparable, TValue any](slice []TValue, keyFn func(TValue) TKey) map[TKey]TValue {
	result := make(map[TKey]TValue)
	for _, val := range slice {
		result[keyFn(val)] = val
	}
	return result
}

func Reverse[T any](input []T) []T {
	output := make([]T, len(input))
	for ii := 0; ii < len(input); ii++ {
		output[len(input)-1-ii] = input[ii]
	}
	return output
}

// RemoveDuplicates takes in two slices A and B and returns two slices A' and B' such that
// A' contains all elements of A that are not in B, and B' contains all elements of B that
// are not in A. The order of the elements in the output slices is maintained from the originals.
func RemoveDuplicates[T comparable](slice1 []T, slice2 []T) (_slice1Unique []T, _slice2Unique []T) {
	slice1Contents := ToMap(slice1, func(val T) T { return val })
	slice2Contents := ToMap(slice2, func(val T) T { return val })

	var slice1Unique []T
	var slice2Unique []T

	for _, val := range slice1 {
		if !MapContains(slice2Contents, val) {
			slice1Unique = append(slice1Unique, val)
		}
	}

	for _, val := range slice2 {
		if !MapContains(slice1Contents, val) {
			slice2Unique = append(slice2Unique, val)
		}
	}

	return slice1Unique, slice2Unique
}

func Filter[T any](slice []T, predicate func(T) bool) []T {
	var result []T
	for _, val := range slice {
		if predicate(val) {
			result = append(result, val)
		}
	}
	return result
}
