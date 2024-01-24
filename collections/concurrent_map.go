package collections

import "sync"

type ConcurrentMap[Key comparable, Value any] struct {
	mtx sync.RWMutex
	m   map[Key]Value
}

func NewConcurrentMap[Key comparable, Value any]() *ConcurrentMap[Key, Value] {
	return &ConcurrentMap[Key, Value]{
		m: make(map[Key]Value),
	}
}

func (cm *ConcurrentMap[Key, Value]) Set(key Key, val Value) {
	cm.mtx.Lock()
	defer cm.mtx.Unlock()

	cm.m[key] = val
}

func (cm *ConcurrentMap[Key, Value]) Remove(key Key) {
	cm.mtx.Lock()
	defer cm.mtx.Unlock()

	_, ok := cm.m[key]
	if !ok {
		return
	}
	delete(cm.m, key)
}

func (cm *ConcurrentMap[Key, Value]) Get(key Key) (Value, bool) {
	cm.mtx.RLock()
	defer cm.mtx.RUnlock()

	val, ok := cm.m[key]
	return val, ok
}

func (cm *ConcurrentMap[Key, Value]) Clone() *ConcurrentMap[Key, Value] {
	cm.mtx.RLock()
	defer cm.mtx.RUnlock()

	clone := NewConcurrentMap[Key, Value]()
	for key, val := range cm.m {
		clone.Set(key, val)
	}
	return clone
}

func (cm *ConcurrentMap[Key, Value]) ToMap() map[Key]Value {
	cm.mtx.RLock()
	defer cm.mtx.RUnlock()

	index := make(map[Key]Value)
	for key, node := range cm.m {
		index[key] = node
	}
	return index
}

func (cm *ConcurrentMap[Key, Value]) GetAll() []Value {
	cm.mtx.RLock()
	defer cm.mtx.RUnlock()

	var vals []Value
	for _, val := range cm.m {
		vals = append(vals, val)
	}
	return vals
}

func (cm *ConcurrentMap[Key, Value]) Count() int {
	cm.mtx.RLock()
	defer cm.mtx.RUnlock()

	return len(cm.m)
}
