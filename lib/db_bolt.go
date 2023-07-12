package lib

import (
	"github.com/boltdb/bolt"
	"github.com/pkg/errors"
	"os"
	"path/filepath"
)

// ==========================
// BoltDatabase
// ==========================

type BoltDatabase struct {
	db  *bolt.DB
	dir string
}

func NewBoltDatabase(dir string) *BoltDatabase {
	return &BoltDatabase{
		db:  nil,
		dir: dir,
	}
}

func (bdb *BoltDatabase) Setup() error {
	dbFile := filepath.Join(bdb.dir, "bolt.db")
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		return err
	}
	bdb.db = db
	return nil
}

func (bdb *BoltDatabase) GetContext(id []byte) Context {
	return NewBoltContext(id)
}

func (bdb *BoltDatabase) Update(ctx Context, fn func(Transaction, Context) error) error {
	return bdb.db.Update(func(tx *bolt.Tx) error {
		T := NewBoltTransaction(tx)
		return fn(T, ctx)
	})
}

func (bdb *BoltDatabase) Close() error {
	return bdb.db.Close()
}

func (bdb *BoltDatabase) Cleanup() error {
	return os.RemoveAll(bdb.dir)
}

func (bdb *BoltDatabase) Id() DatabaseId {
	return BOLTDB
}

// ==========================
// BoltTransaction
// ==========================

type BoltTransaction struct {
	tx *bolt.Tx
}

func NewBoltTransaction(tx *bolt.Tx) *BoltTransaction {
	return &BoltTransaction{
		tx: tx,
	}
}

func (bt *BoltTransaction) Set(key []byte, value []byte, ctx Context) error {
	bucket, err := castBoltContextAndGetBucket(bt.tx, ctx)
	if err != nil {
		return errors.Wrap(err, "Set:")
	}
	return bucket.Put(key, value)
}

func (bt *BoltTransaction) Delete(key []byte, ctx Context) error {
	bucket, err := castBoltContextAndGetBucket(bt.tx, ctx)
	if err != nil {
		return errors.Wrap(err, "Delete:")
	}

	return bucket.Delete(key)
}

func (bt *BoltTransaction) Get(key []byte, ctx Context) ([]byte, error) {
	bucket, err := castBoltContextAndGetBucket(bt.tx, ctx)
	if err != nil {
		return nil, errors.Wrap(err, "Get:")
	}

	return bucket.Get(key), nil
}

func (bt *BoltTransaction) GetIterator(ctx Context) (Iterator, error) {
	boltCtx, err := AssertDatabaseContext[*BoltContext](ctx, BOLTDB)
	if err != nil {
		return nil, errors.Wrapf(err, "Set:")
	}

	bucket, err := boltCtx.GetNestedBucket(bt.tx)
	if err != nil {
		return nil, errors.Wrapf(err, "Set: Problem creating bucket")
	}

	return NewBoltIterator(bucket.Cursor(), boltCtx), nil
}

// ==========================
// BoltIterator
// ==========================

type BoltIterator struct {
	it           *bolt.Cursor
	ctx          *BoltContext
	currentValue []byte
	currentKey   []byte
}

func NewBoltIterator(it *bolt.Cursor, ctx *BoltContext) *BoltIterator {
	k, v := it.First()
	return &BoltIterator{
		it:           it,
		ctx:          ctx,
		currentKey:   k,
		currentValue: v,
	}
}

func (bi *BoltIterator) GetContext() Context {
	return bi.ctx
}

func (bi *BoltIterator) Value() ([]byte, error) {
	return bi.currentValue, nil
}

func (bi *BoltIterator) Key() []byte {
	return bi.currentKey
}

func (bi *BoltIterator) Next() bool {
	k, v := bi.it.Next()
	if k == nil {
		return false
	}
	bi.currentKey = k
	bi.currentValue = v
	return true
}

func (bi *BoltIterator) Close() {
	bi.it = nil
}

// ==========================
// BoltContext
// ==========================

type BucketId []byte

func MakeBucketId(id []byte) BucketId {
	return id
}

func (bi BucketId) Bytes() []byte {
	return bi
}

type BoltContext struct {
	bucketIds []BucketId
}

func NewBoltContext(bucketId []byte) *BoltContext {
	return &BoltContext{
		bucketIds: []BucketId{MakeBucketId(bucketId)},
	}
}

func NewBoltNestedContext(bucketId []byte, parent *BoltContext) *BoltContext {
	return &BoltContext{
		bucketIds: append(parent.bucketIds, MakeBucketId(bucketId)),
	}
}

func (bc *BoltContext) DatabaseId() DatabaseId {
	return BOLTDB
}

func (bc *BoltContext) GetNestedBucket(txn *bolt.Tx) (*bolt.Bucket, error) {
	if len(bc.bucketIds) == 0 {
		return nil, errors.New("GetNestedBucket: No bucketIds")
	}

	bucket, err := txn.CreateBucketIfNotExists(bc.bucketIds[0].Bytes())
	if err != nil {
		return nil, errors.Wrapf(err, "GetNestedBucket: Problem getting bucket")
	}
	finalBucket := bucket
	for ii := 1; ii < len(bc.bucketIds); ii++ {
		finalBucket, err = finalBucket.CreateBucketIfNotExists(bc.bucketIds[ii].Bytes())
		if err != nil {
			return nil, errors.Wrapf(err, "GetNestedBucket: Problem creating bucket")
		}
	}

	return finalBucket, nil
}

func castBoltContextAndGetBucket(tx *bolt.Tx, ctx Context) (*bolt.Bucket, error) {
	boltCtx, err := AssertDatabaseContext[*BoltContext](ctx, BOLTDB)
	if err != nil {
		return nil, errors.Wrapf(err, "Set:")
	}

	bucket, err := boltCtx.GetNestedBucket(tx)
	if err != nil {
		return nil, errors.Wrapf(err, "Set: Problem creating bucket")
	}

	return bucket, nil
}
