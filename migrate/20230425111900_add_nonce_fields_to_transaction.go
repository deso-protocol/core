package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`
			ALTER TABLE pg_transactions 
			    ADD COLUMN txn_version BIGINT DEFAULT 0,
			    ADD COLUMN txn_fee_nanos BIGINT DEFAULT 0,
			    ADD COLUMN txn_nonce_expiration_block_height BIGINT
			    ADD COLUMN txn_nonce_partial_id BIGINT;`)
		return err
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			ALTER TABLE pg_transactions 
				DROP COLUMN txn_version,
				DROP COLUMN txn_fee_nanos,
				DROP COLUMN txn_nonce_expiration_block_height,
				DROP COLUMN txn_nonce_partial_id;`)
		return err
	}

	opts := migrations.MigrationOptions{}
	migrations.Register("20230425111900_add_nonce_fields_to_transaction", up, down, opts)
}
