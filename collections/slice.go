package collections

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

func Transform[TInput any, TOutput any](slice []TInput, transformFn func(TInput) TOutput) []TOutput {
	var result []TOutput
	for _, val := range slice {
		result = append(result, transformFn(val))
	}
	return result
}

func ToMap[TKey comparable, TValue any](slice []TValue, keyFn func(TValue) TKey) map[TKey]TValue {
	result := make(map[TKey]TValue)
	for _, val := range slice {
		result[keyFn(val)] = val
	}
	return result
}
