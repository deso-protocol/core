package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMissingDatabaseDoesNotCreateOne(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "typo")
	if err := maintain(dir, 100, 1); err == nil {
		t.Fatal("missing database must be rejected")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("maintenance created a directory for an invalid DB path: %v", err)
	}
}

func fullDigest(t *testing.T, db *badger.DB) string {
	t.Helper()
	h := sha256.New()
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			if err := addItem(h, it.Item()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
func TestFlattenPreservesLatestValuesAndDeletion(t *testing.T) {
	dir := t.TempDir()
	opt := options(dir).WithMemTableSize(64 << 20).WithNumVersionsToKeep(1000).WithBaseTableSize(32 << 10)
	db, err := badger.Open(opt)
	if err != nil {
		t.Fatal(err)
	}
	for v := 0; v < 100; v++ {
		err = db.Update(func(txn *badger.Txn) error {
			for k := 0; k < 100; k++ {
				if err := txn.Set([]byte(fmt.Sprintf("key-%03d", k)), []byte(fmt.Sprintf("version-%d", v))); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if v%20 == 19 {
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = badger.Open(opt)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	err = db.Update(func(txn *badger.Txn) error {
		if err := txn.Delete([]byte("key-007")); err != nil {
			return err
		}
		return txn.SetEntry(badger.NewEntry([]byte("key-008"), []byte("expired")).WithTTL(-time.Hour))
	})
	if err != nil {
		t.Fatal(err)
	}
	want := fullDigest(t, db)
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = maintain(dir, 100, 1); err != nil {
		t.Fatal(err)
	}
	db, err = badger.Open(options(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := fullDigest(t, db); got != want {
		t.Fatalf("full logical digest changed: %s -> %s", want, got)
	}
	var retainedVersions int
	err = db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.AllVersions = true
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			retainedVersions++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if retainedVersions != 98 {
		t.Fatalf("expected 98 current records after pruning 100 versions and two deleted/expired keys; got %d", retainedVersions)
	}
	for _, key := range []string{"key-007", "key-008"} {
		err = db.View(func(txn *badger.Txn) error { _, e := txn.Get([]byte(key)); return e })
		if err != badger.ErrKeyNotFound {
			t.Fatalf("deleted/expired key resurrected: %s %v", key, err)
		}
	}
}
