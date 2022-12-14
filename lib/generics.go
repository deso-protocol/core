package lib

import "sort"

// Generic Set object. Retains the order elements are addd to the set.
// Use set.ToOrderedSlice() to retrieve in original order.
type Set[T comparable] struct {
	_counter  int
	_innerMap map[T]int
}

func NewSet[T comparable](elements []T) *Set[T] {
	set := &Set[T]{_counter: 0, _innerMap: make(map[T]int)}
	for _, element := range elements {
		set.Add(element)
	}
	return set
}

func (set *Set[T]) Add(element T) {
	// Add element to set.
	if !set.Includes(element) {
		set._innerMap[element] = set._counter
		set._counter += 1
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

func (set *Set[T]) ToSlice() []T {
	// Convert the set to a slice.
	var results []T
	for element := range set._innerMap {
		results = append(results, element)
	}
	return results
}

func (set *Set[T]) ToOrderedSlice() []T {
	// Convert the set to an ordered slice.
	results := set.ToSlice()
	sort.Slice(results, func(ii, jj int) bool {
		return set._innerMap[results[ii]] < set._innerMap[results[jj]]
	})
	return results
}
