package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`ALTER TABLE pg_posts ADD COLUMN is_frozen BOOL DEFAULT FALSE;`)
		return err
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`ALTER TABLE pg_posts DROP COLUMN is_frozen;`)
		return err
	}

	opts := migrations.MigrationOptions{}
	migrations.Register("20230110155900_add_is_frozen_to_posts", up, down, opts)
}
