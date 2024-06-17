package collections

import (
	"fmt"
	"testing"
)

func TestConcurrentMap(t *testing.T) {
	m := NewConcurrentMap[string, int]()
	control := make(map[string]int)

	// test add
	for ii := 0; ii < 100; ii++ {
		key := fmt.Sprintf("%v", ii)
		m.Set(key, ii)
		control[key] = ii
	}

	for key, val := range control {
		if mVal, ok := m.Get(key); !ok || mVal != val {
			t.Errorf("Expected %d, got %d", val, m.m[key])
		}
	}

	// test remove
	for ii := 0; ii < 50; ii++ {
		key := fmt.Sprintf("%v", ii)
		m.Remove(key)
		delete(control, key)
	}

	// test remove not exists
	m.Remove("not exists")

	for key, val := range control {
		if mVal, ok := m.Get(key); !ok || mVal != val {
			t.Errorf("Expected %d, got %d", val, m.m[key])
		}
	}

	// test Clone
	mClone := m.Clone()
	for key, val := range control {
		if mVal, ok := mClone.Get(key); !ok || mVal != val {
			t.Errorf("Expected %d, got %d", val, m.m[key])
		}
	}

	// test toMap
	mapCopy := m.ToMap()
	for key, val := range control {
		if mVal, ok := mapCopy[key]; !ok || mVal != val {
			t.Errorf("Expected %d, got %d", val, m.m[key])
		}
	}
	if len(mapCopy) != len(control) {
		t.Errorf("Expected %d, got %d", len(control), len(mapCopy))
	}

	// test get all
	vals := m.GetAll()
	for _, val := range vals {
		if _, ok := control[fmt.Sprintf("%v", val)]; !ok {
			t.Errorf("Expected %d, got %d", val, m.m[fmt.Sprintf("%v", val)])
		}
	}

	// test size
	if m.Count() != len(control) {
		t.Errorf("Expected %d, got %d", len(control), m.Count())
	}
}
