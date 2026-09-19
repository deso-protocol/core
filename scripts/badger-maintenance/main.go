// Offline maintenance only. No writes to application keys; use the exact deployed Badger version.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v3"
)

type probeResult struct {
	HighestIndexedHeight uint32      `json:"highestIndexedHeight"`
	Digest               string      `json:"digest"`
	Sampled              int         `json:"sampledKeys"`
	LookupMillis         []float64   `json:"heightLookupMillis"`
	BestHashVersions     uint64      `json:"bestHashVersions"`
	Tables               map[int]int `json:"tablesPerLevel"`
	MaxVersion           uint64      `json:"maxVersion"`
}

func emit(v interface{}) {
	if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
		panic(err)
	}
}
func options(dir string) badger.Options {
	return badger.DefaultOptions(dir).WithMemTableSize(1024 << 20).WithValueLogFileSize(128 << 20).
		WithNumVersionsToKeep(1).WithNumCompactors(0).WithBlockCacheSize(100 << 20).
		WithIndexCacheSize(200 << 20).WithLoggingLevel(badger.WARNING)
}
func addItem(h hash.Hash, item *badger.Item) error {
	value, err := item.ValueCopy(nil)
	if err != nil {
		return err
	}
	var buf [8]byte
	for _, v := range [][]byte{item.Key(), value} {
		binary.BigEndian.PutUint64(buf[:], uint64(len(v)))
		h.Write(buf[:])
		h.Write(v)
	}
	binary.BigEndian.PutUint64(buf[:], item.ExpiresAt())
	h.Write(buf[:])
	h.Write([]byte{item.UserMeta()})
	return nil
}
func probe(db *badger.DB, height uint32) (probeResult, error) {
	r := probeResult{Tables: map[int]int{}, MaxVersion: db.MaxVersion()}
	h := sha256.New()
	for _, t := range db.Tables() {
		r.Tables[t.Level]++
	}
	err := db.View(func(txn *badger.Txn) error {
		// Include empty next-height lookups at the actual offline tip, not only the earlier RPC tip.
		reverse := badger.DefaultIteratorOptions
		reverse.Reverse = true
		reverse.PrefetchValues = false
		reverse.Prefix = []byte{1}
		last := txn.NewIterator(reverse)
		upper := bytes.Repeat([]byte{255}, 37)
		upper[0] = 1
		for last.Seek(upper); last.ValidForPrefix([]byte{1}); last.Next() {
			if !last.Item().IsDeletedOrExpired() && len(last.Item().Key()) == 37 {
				height = binary.BigEndian.Uint32(last.Item().Key()[1:5])
				break
			}
		}
		last.Close()
		r.HighestIndexedHeight = height
		// Exact production iterator options, including its two-item internal prefetch.
		for i := -8; i <= 3; i++ {
			prefix := make([]byte, 5)
			prefix[0] = 1
			binary.BigEndian.PutUint32(prefix[1:], uint32(int64(height)+int64(i)))
			opt := badger.DefaultIteratorOptions
			opt.PrefetchValues = false
			opt.Prefix = prefix
			it := txn.NewIterator(opt)
			start := time.Now()
			for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
				if err := addItem(h, it.Item()); err != nil {
					it.Close()
					return err
				}
				r.Sampled++
			}
			r.LookupMillis = append(r.LookupMillis, float64(time.Since(start).Microseconds())/1000)
			it.Close()
		}
		// Deterministic current-value samples across every byte prefix; never print values.
		opt := badger.DefaultIteratorOptions
		opt.PrefetchValues = false
		opt.AllVersions = true
		it := txn.NewIterator(opt)
		defer it.Close()
		for p := 0; p < 256; p++ {
			seek := []byte{byte(p)}
			for n := 0; n < 8; {
				it.Seek(seek)
				if !it.Valid() || it.Item().Key()[0] != byte(p) {
					break
				}
				item := it.Item()
				key := item.KeyCopy(nil)
				if !item.IsDeletedOrExpired() {
					if err := addItem(h, item); err != nil {
						return err
					}
					r.Sampled++
					n++
				}
				// Lexicographic successor after this exact variable-length logical key.
				seek = append(key, 0)
			}
		}
		it.Seek([]byte{3})
		for ; it.Valid() && bytes.Equal(it.Item().Key(), []byte{3}); it.Next() {
			r.BestHashVersions++
		}
		return nil
	})
	r.Digest = hex.EncodeToString(h.Sum(nil))
	return r, err
}

func maintain(dir string, height uint32, workers int) error {
	// A typo must never create a new, empty database and pass validation.
	if _, err := os.Stat(filepath.Join(dir, "MANIFEST")); err != nil {
		return fmt.Errorf("existing Badger MANIFEST required: %w", err)
	}
	// Flush any recovered memtables before Flatten, without introducing application writes.
	db, err := badger.Open(options(dir))
	if err != nil {
		return err
	}
	if err = db.Close(); err != nil {
		return err
	}
	db, err = badger.Open(options(dir))
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			db.Close()
		}
	}()
	before, err := probe(db, height)
	if err != nil {
		return err
	}
	emit(map[string]interface{}{"stage": "before", "result": before})
	start := time.Now()
	emit(map[string]interface{}{"stage": "flatten-start", "workers": workers})
	if err = db.Flatten(workers); err != nil {
		return err
	}
	emit(map[string]interface{}{"stage": "flatten-complete", "seconds": time.Since(start).Seconds()})
	if err = db.Close(); err != nil {
		return err
	}
	closed = true
	db, err = badger.Open(options(dir).WithReadOnly(true))
	if err != nil {
		return err
	}
	defer db.Close()
	after, err := probe(db, height)
	if err != nil {
		return err
	}
	emit(map[string]interface{}{"stage": "after", "result": after})
	// MaxVersion may decrease when the newest transaction contained only a
	// deleted/expired record whose tombstone was compacted away. Never increase it.
	if before.Digest != after.Digest || before.Sampled != after.Sampled || after.MaxVersion > before.MaxVersion || after.HighestIndexedHeight != before.HighestIndexedHeight {
		return fmt.Errorf("logical sample/version changed; reject trial disk")
	}
	emit(map[string]interface{}{"stage": "validated", "sampleMatches": true, "allApplicationKeysWereNotScanned": true})
	return nil
}
func main() {
	dir := flag.String("dir", "", "offline chain DB directory")
	height := flag.Uint("height", 0, "baseline height")
	workers := flag.Int("workers", 1, "compaction workers")
	confirm := flag.Bool("confirm-offline-copy", false, "required: this is an isolated copy with no running node using it")
	flag.Parse()
	if *dir == "" || *height < 10 || *workers != 1 || !*confirm {
		fmt.Fprintln(os.Stderr, "required: --dir, --height >=10, --workers=1, --confirm-offline-copy")
		os.Exit(2)
	}
	if err := maintain(*dir, uint32(*height), *workers); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
