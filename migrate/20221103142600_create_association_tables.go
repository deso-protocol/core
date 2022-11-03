package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		// Create pg_metadata_create_user_association table.
		_, err := db.Exec(`
			CREATE TABLE pg_metadata_create_user_association (
			    transaction_hash       BYTEA PRIMARY KEY,
			    target_user_public_key BYTEA NOT NULL,
			    association_type       TEXT NOT NULL,
			    association_value      TEXT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		// Create pg_metadata_delete_user_association table.
		_, err = db.Exec(`
			CREATE TABLE pg_metadata_delete_user_association (
			    transaction_hash BYTEA PRIMARY KEY,
			    association_id   BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		// Create pg_metadata_create_post_association table.
		_, err = db.Exec(`
			CREATE TABLE pg_metadata_create_post_association (
			    transaction_hash  BYTEA PRIMARY KEY,
			    post_hash_hex     TEXT NOT NULL,
			    association_type  TEXT NOT NULL,
			    association_value TEXT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		// Create pg_metadata_delete_post_association_table.
		_, err = db.Exec(`
			CREATE TABLE pg_metadata_delete_post_association (
			    transaction_hash BYTEA PRIMARY KEY,
			    association_id   BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		// Crease pg_user_associations table.
		_, err = db.Exec(`
			CREATE TABLE pg_user_associations (
				association_id    BYTEA PRIMARY KEY,
				transactor_pkid   BYTEA NOT NULL,
				target_user_pkid  BYTEA NOT NULL,
				association_type  TEXT NOT NULL,
				association_value TEXT NOT NULL,
				block_height      BIGINT NOT NULL
			)
		`)
		if err != nil {
			return err
		}

		// Create pg_post_associations table.
		_, err = db.Exec(`
			CREATE TABLE pg_post_associations (
				association_id    BYTEA PRIMARY KEY,
				post_hash         BYTEA NOT NULL,
				target_user_pkid  BYTEA NOT NULL,
				association_type  TEXT NOT NULL,
				association_value TEXT NOT NULL,
				block_height      BIGINT NOT NULL
			)
		`)
		if err != nil {
			return err
		}
		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE pg_metadata_create_user_association;
			DROP TABLE pg_metadata_delete_user_association;
			DROP TABLE pg_metadata_create_post_association;
			DROP TABLE pg_metadata_delete_post_association;
			DROP TABLE pg_user_associations;
			DROP TABLE pg_post_associations;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}
	migrations.Register("20221103142600_create_association_tables", up, down, opts)
}
