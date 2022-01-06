package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`
			CREATE TABLE pg_metadata_derived_keys (
				transaction_hash   BYTEA PRIMARY KEY,
				derived_public_key BYTEA NOT NULL,
				expiration_block   BIGINT NOT NULL,
				operation_type     SMALLINT NOT NULL,
				access_signature   BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_derived_keys (
				owner_public_key   BYTEA NOT NULL,
				derived_public_key BYTEA NOT NULL,
				expiration_block   BIGINT NOT NULL,
				operation_type     SMALLINT NOT NULL,

				PRIMARY KEY (owner_public_key, derived_public_key)
			);
		`)
		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE pg_metadata_derived_keys;
			DROP TABLE pg_derived_keys;
		`)
		if err != nil {
			return err
		}

		return nil
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20210907001756_derived_keys_update", up, down, opts)
}
