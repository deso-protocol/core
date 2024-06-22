package storage

import "sync"

type DatabaseContext struct {
	sync.RWMutex

	Db  Database
	Ctx Context
}

func NewDatabaseContext(db Database, ctx Context) *DatabaseContext {
	return &DatabaseContext{Db: db, Ctx: ctx}
}

func (cdb *DatabaseContext) Setup() error {
	cdb.Lock()
	defer cdb.Unlock()

	return cdb.Db.Setup()
}

func (cdb *DatabaseContext) GetContext(id []byte) Context {
	return cdb.Db.GetContext(id)
}

func (cdb *DatabaseContext) Update(ctx Context, f func(Transaction, Context) error) error {
	cdb.Lock()
	defer cdb.Unlock()

	return cdb.Db.Update(ctx, f)
}

func (cdb *DatabaseContext) View(ctx Context, f func(Transaction, Context) error) error {
	cdb.RLock()
	defer cdb.RUnlock()

	return cdb.Db.View(ctx, f)
}

func (cdb *DatabaseContext) Close() error {
	cdb.Lock()
	defer cdb.Unlock()

	return cdb.Db.Close()
}

func (cdb *DatabaseContext) Erase() error {
	cdb.Lock()
	defer cdb.Unlock()

	return cdb.Db.Erase()
}

func (cdb *DatabaseContext) Id() DatabaseId {
	return cdb.Db.Id()
}

func (cdb *DatabaseContext) NestContext(localId []byte) Context {
	return cdb.Ctx.NestContext(localId)
}
