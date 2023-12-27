package collections

import "sort"

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
