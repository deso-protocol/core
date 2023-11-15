package collections

import "sort"

func TransformSlice[TInput any, TOutput any](slice []TInput, transformFn func(TInput) TOutput) []TOutput {
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
