package collections

func MapValues[TKey comparable, TValue any](m map[TKey]TValue) []TValue {
	var result []TValue
	for _, val := range m {
		result = append(result, val)
	}
	return result
}
