package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		if _, err := db.Exec(`
			ALTER TABLE pg_derived_keys
				ADD COLUMN block_height BIGINT;
		`); err != nil {
			return err
		}

		if _, err := db.Exec(`
			ALTER TABLE pg_transactions
				ADD COLUMN recovery_id INT,
				ADD COLUMN is_recoverable BOOL;
		`); err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		if _, err := db.Exec(`
			ALTER TABLE pg_derived_keys
				DROP COLUMN block_height;
		`); err != nil {
			return err
		}

		if _, err := db.Exec(`
			ALTER TABLE pg_transactions
				DROP COLUMN recovery_id,
				DROP COLUMN is_recoverable;
		`); err != nil {
			return err
		}

		return nil
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20220711054349_recoverable_signatures_and_unlimited_derived_keys", up, down, opts)
}
