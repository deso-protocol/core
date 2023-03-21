package lib

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
