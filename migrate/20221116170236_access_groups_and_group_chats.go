package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {

		//
		// Access Groups
		//
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
				access_group_public_key       BYTEA NOT NULL,
				operation_type                SMALLINT
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

		//
		// Dms & Group Chats
		//
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS pg_new_message_dm_entries (
				minor_access_group_owner_public_key BYTEA NOT NULL,
				minor_access_group_key_name         BYTEA,
				sender_access_group_public_key      BYTEA NOT NULL,
				major_access_group_owner_public_key BYTEA NOT NULL,
				major_access_group_key_name         BYTEA,
				recipient_access_group_public_key   BYTEA NOT NULL,
				encrypted_text                      BYTEA,
				timestamp_nanos                     BIGINT NOT NULL,
				is_sender_minor                     BOOL,
				extra_data                          JSONB,

				PRIMARY KEY (minor_access_group_owner_public_key, minor_access_group_key_name, 
					major_access_group_owner_public_key, major_access_group_key_name, timestamp_nanos)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS pg_new_message_dm_thread_entries (
				user_access_group_owner_public_key  BYTEA NOT NULL,
				user_access_group_key_name          BYTEA NOT NULL,
				party_access_group_owner_public_key BYTEA NOT NULL,
				party_access_group_key_name         BYTEA NOT NULL,

				PRIMARY KEY (user_access_group_owner_public_key, user_access_group_key_name, 
					party_access_group_owner_public_key, party_access_group_key_name)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS pg_new_message_group_chat_entries (
				access_group_owner_public_key        BYTEA NOT NULL,
				access_group_key_name                BYTEA,
				access_group_public_key              BYTEA NOT NULL,
				sender_access_group_owner_public_key BYTEA NOT NULL,
				sender_access_group_key_name         BYTEA,
				sender_access_group_public_key       BYTEA NOT NULL,
				encrypted_text                       BYTEA,
				timestamp_nanos                      BIGINT NOT NULL,
				extra_data                           JSONB,

				PRIMARY KEY (access_group_owner_public_key, access_group_key_name, timestamp_nanos)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS pg_new_message_group_chat_thread_entries (
				access_group_owner_public_key  BYTEA NOT NULL,
				access_group_key_name          BYTEA NOT NULL,
				
				PRIMARY KEY (access_group_owner_public_key, access_group_key_name)
			);
		`)
		if err != nil {
			return err
		}

		// ThreadAttributesEntry data
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS pg_new_message_thread_attributes_entries (
				user_access_group_owner_public_key  BYTEA NOT NULL,
				user_access_group_key_name          BYTEA NOT NULL,
				party_access_group_owner_public_key BYTEA NOT NULL,
				party_access_group_key_name         BYTEA NOT NULL,
				new_message_type                    SMALLINT,
				attribute_data                      JSONB,

				PRIMARY KEY (user_access_group_owner_public_key, user_access_group_key_name,
					party_access_group_owner_public_key, party_access_group_key_name, new_message_type)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS pg_metadata_new_message (
				transaction_hash                        BYTEA PRIMARY KEY,
				sender_access_group_owner_public_key    BYTEA NOT NULL,
				sender_access_group_key_name            BYTEA,
				sender_access_group_public_key          BYTEA NOT NULL,
				recipient_access_group_owner_public_key BYTEA NOT NULL,
				recipient_access_group_key_name         BYTEA,
				recipient_access_group_public_key       BYTEA NOT NULL,
				encrypted_text                          BYTEA,
				timestamp_nanos                         BIGINT NOT NULL,
				new_message_type                        SMALLINT,
				new_message_operation                   SMALLINT
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
			DROP TABLE IF EXISTS pg_new_message_dm_entries;
			DROP TABLE IF EXISTS pg_new_message_dm_thread_entries;
			DROP TABLE IF EXISTS pg_new_message_group_chat_entries;
			DROP TABLE IF EXISTS pg_new_message_group_chat_thread_entries;
			DROP TABLE IF EXISTS pg_new_message_thread_attributes_entries;
			DROP TABLE IF EXISTS pg_metadata_new_message;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20221116170236_access_groups_and_group_chats", up, down, opts)
}
