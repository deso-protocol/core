package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`
			CREATE TABLE pg_metadata_nft_transfer (
				transaction_hash    BYTEA PRIMARY KEY,
				nft_post_hash       BYTEA NOT NULL,
				serial_number       BIGINT NOT NULL,
				receiver_public_key BYTEA NOT NULL,
				unlockable_text     BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_accept_nft_transfer (
				transaction_hash BYTEA PRIMARY KEY,
				nft_post_hash    BYTEA NOT NULL,
				serial_number    BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_burn_nft (
				transaction_hash BYTEA PRIMARY KEY,
				nft_post_hash    BYTEA NOT NULL,
				serial_number    BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			ALTER TABLE IF EXISTS pg_posts
				ADD num_nft_copies_for_sale BIGINT,
				ADD num_nft_copies_burned   BIGINT
			;
			ALTER TABLE IF EXISTS pg_nfts
				ADD is_pending BOOL
			;
		`)

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE pg_metadata_nft_transfer;
			DROP TABLE pg_metadata_accept_nft_transfer;
			DROP TABLE pg_metadata_burn_nft;
			ALTER TABLE IF EXISTS pg_posts
				DROP COLUMN IF EXISTS num_nft_copies_for_sale,
				DROP COLUMN IF EXISTS num_nft_copies_burned
			;
			ALTER TABLE IF EXISTS pg_nfts
				DROP COLUMN IF EXISTS is_pending
			;
		`)
		if err != nil {
			return err
		}

		return nil
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20210917204532_nft_transfer_and_burn_update", up, down, opts)
}
