package lib

import (
	"github.com/emirpasic/gods/sets/treeset"
	"testing"
)

type TestRegister struct {
	buckets *FeeBucket
}

func TestTreeSet(t *testing.T) {
	set := treeset.NewWithIntComparator(7, 10, 15, 22, 13, 200, 5, 0)
	it := set.Iterator()
	for it.Next() {
		t.Log(it.Value())
	}
}
