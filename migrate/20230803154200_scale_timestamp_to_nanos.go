package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`
			UPDATE pg_blocks SET timestamp = timestamp * 1000000000;
		`)
		return err
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			UPDATE pg_blocks SET timestamp = timestamp / 1000000000;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}
	migrations.Register("20230803154200_scale_timestamp_to_nanos", up, down, opts)
}
