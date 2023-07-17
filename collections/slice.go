package collections

func SliceFilter[T any](slice []T, filterFn func(T) bool) []T {
	var result []T
	for _, val := range slice {
		if filterFn(val) {
			result = append(result, val)
		}
	}
	return result
}
