package migrate

import "github.com/golang/glog"

// LoadMigrations forces Go to call init() on all the files in this package.
// The library we use for migrations, go-pg-migrations, needs to be refactored to
// not use this terrible loading pattern. It's hard to test, can cause weird side effects,
// and is the reason we need this weird LoadMigrations method
func LoadMigrations() {
	glog.Info("Loading all migrations...")
}
