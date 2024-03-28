package collections

import "sync"

type ConcurrentList[T any] struct {
	mtx  sync.RWMutex
	list []T
}

func NewConcurrentList[T any]() *ConcurrentList[T] {
	return &ConcurrentList[T]{
		list: []T{},
	}
}

func (cl *ConcurrentList[T]) Add(item T) {
	cl.mtx.Lock()
	defer cl.mtx.Unlock()
	cl.list = append(cl.list, item)
}

func (cl *ConcurrentList[T]) GetAll() []T {
	cl.mtx.RLock()
	defer cl.mtx.RUnlock()
	tmp := make([]T, len(cl.list))
	copy(tmp, cl.list)
	return tmp
}
