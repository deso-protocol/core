package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`
			CREATE TABLE IF NOT EXISTS pg_access_group_entries_by_access_group_id (
				access_group_owner_public_key BYTEA NOT NULL,
				access_group_key_name         BYTEA NOT NULL,
				access_group_public_key       BYTEA,
				extra_data                    JSONB,

				PRIMARY KEY (access_group_owner_public_key, access_group_key_name)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS pg_access_group_membership_index (
				access_group_member_public_key BYTEA NOT NULL,
				access_group_owner_public_key  BYTEA NOT NULL,
				access_group_key_name          BYTEA NOT NULL,
				access_group_member_key_name   BYTEA NOT NULL,
				encrypted_key                  BYTEA,
				extra_data                     JSONB,

				PRIMARY KEY (access_group_member_public_key, access_group_owner_public_key, access_group_key_name)
			);

			CREATE INDEX pg_access_group_membership_index_member
			ON pg_access_group_membership_index(access_group_member_public_key);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS pg_access_group_member_enumeration_index (
				access_group_owner_public_key  BYTEA NOT NULL,
				access_group_key_name          BYTEA NOT NULL,
				access_group_member_public_key BYTEA NOT NULL,

				PRIMARY KEY (access_group_owner_public_key, access_group_key_name, access_group_member_public_key)
			);

			CREATE INDEX pg_access_group_member_enumeration_index_owner
			ON pg_access_group_member_enumeration_index (access_group_owner_public_key, access_group_key_name);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS pg_metadata_access_group_create (
				transaction_hash              BYTEA PRIMARY KEY,
				access_group_owner_public_key BYTEA NOT NULL,
				access_group_key_name         BYTEA NOT NULL,
				access_group_public_key       BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS pg_metadata_access_group_members (
				transaction_hash              BYTEA PRIMARY KEY,
				access_group_owner_public_key BYTEA NOT NULL,
				access_group_key_name         BYTEA NOT NULL,
				access_group_members_list     BYTEA NOT NULL,
				operation_type                SMALLINT
			);
		`)
		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE IF EXISTS pg_access_group_entries_by_access_group_id;
			DROP TABLE IF EXISTS pg_access_group_membership_index;
			DROP TABLE IF EXISTS pg_access_group_member_enumeration_index;
			DROP TABLE IF EXISTS pg_metadata_access_group_create;
			DROP TABLE IF EXISTS pg_metadata_access_group_members;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20221116170236_access_groups_and_group_chats", up, down, opts)
}
