package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {

		_, err := db.Exec(`
			CREATE TABLE pg_messaging_group (
				group_owner_public_key BYTEA NOT NULL,
				messaging_public_key BYTEA NOT NULL,
				messaging_group_key_name  BYTEA NOT NULL,
				messaging_group_members  BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_messaging_group (
				messaging_public_key            BYTEA NOT NULL,
				messaging_group_key_name            BYTEA NOT NULL,
				group_owner_signature     BYTEA NOT NULL,
				messaging_group_members    BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE pg_messaging_group;
			DROP TABLE pg_metadata_messaging_group;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20220207000000_create_messaging_group", up, down, opts)
}
