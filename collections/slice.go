package collections

func TransformSlice[TInput any, TOutput any](slice []TInput, transformFn func(TInput) TOutput) []TOutput {
	var result []TOutput
	for _, val := range slice {
		result = append(result, transformFn(val))
	}
	return result
}
