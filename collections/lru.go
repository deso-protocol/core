package collections

import lru "github.com/hashicorp/golang-lru/v2"

// We implement our own LRU cache as a wrapper around a dependency. This allows us to
// easily change the underlying implementation in the future if needed with minimal
// changes outside of this file.

type LruCache[K comparable, V any] struct {
	underlyingCache *lru.Cache[K, V]
}

func NewLruCache[K comparable, V any](maxSize int) (*LruCache[K, V], error) {
	underlyingCache, err := lru.New[K, V](maxSize)
	if err != nil {
		return nil, err
	}
	return &LruCache[K, V]{underlyingCache}, nil
}

func (lruCache *LruCache[K, V]) Put(key K, value V) {
	lruCache.underlyingCache.Add(key, value)
}

func (lruCache *LruCache[K, V]) Get(key K) (V, bool) {
	return lruCache.underlyingCache.Get(key)
}

func (lruCache *LruCache[K, V]) Exists(key K) bool {
	return lruCache.underlyingCache.Contains(key)
}

func (lruCache *LruCache[K, V]) Delete(key K) {
	lruCache.underlyingCache.Remove(key)
}

func (lruCache *LruCache[K, V]) Purge() {
	lruCache.underlyingCache.Purge()
}

func (lruCache *LruCache[K, V]) Keys() []K {
	return lruCache.underlyingCache.Keys()
}

type LruSet[K comparable] struct {
	underlyingCache *lru.Cache[K, struct{}]
}

func NewLruSet[K comparable](maxSize int) (*LruSet[K], error) {
	underlyingCache, err := lru.New[K, struct{}](maxSize)
	if err != nil {
		return nil, err
	}
	return &LruSet[K]{underlyingCache}, nil
}

func (lruSet *LruSet[K]) Put(key K) {
	lruSet.underlyingCache.Add(key, struct{}{})
}

func (lruSet *LruSet[K]) Contains(key K) bool {
	return lruSet.underlyingCache.Contains(key)
}

func (lruSet *LruSet[K]) Delete(key K) {
	lruSet.underlyingCache.Remove(key)
}

func (lruSet *LruSet[K]) Purge() {
	lruSet.underlyingCache.Purge()
}

func (lruSet *LruSet[K]) Items() []K {
	return lruSet.underlyingCache.Keys()
}
