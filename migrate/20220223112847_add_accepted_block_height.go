package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {

		_, err := db.Exec(`
			ALTER TABLE pg_nft_bids
				ADD COLUMN accepted_block_height BIGINT;
		`)
		return err
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			ALTER TABLE pg_nft_bids
				DROP COLUMN accepted_block_height;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20220223112847_add_accepted_block_height", up, down, opts)
}
