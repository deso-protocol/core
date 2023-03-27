package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`ALTER TABLE pg_global_params ADD COLUMN max_nonce_expiration_block_height_offset BIGINT;`)
		return err
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`ALTER TABLE pg_global_params DROP COLUMN max_nonce_expiration_block_height_offset;`)
		return err
	}

	opts := migrations.MigrationOptions{}
	migrations.Register("20230322185600_add_max_nonce_expiration_block_height_offset_to_global_params", up, down, opts)
}
