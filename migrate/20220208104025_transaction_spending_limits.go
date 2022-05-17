package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {

		_, err := db.Exec(`
			ALTER TABLE pg_derived_keys
				ADD COLUMN transaction_spending_limit_tracker BYTEA,
				ADD COLUMN memo BYTEA;
			`)
		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			ALTER TABLE pg_derived_keys
				DROP COLUMN transaction_spending_limit_tracker,
				DROP COLUMN memo;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20220208104025_transaction_spending_limits", up, down, opts)
}
