package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {

		_, err := db.Exec(`
			CREATE TABLE pg_metadata_dao_coins (
				transaction_hash            BYTEA PRIMARY KEY,
				profile_public_key          BYTEA NOT NULL,
				operation_type              SMALLINT NOT NULL,
				coins_to_mint_nanos         BIGINT NOT NULL,
				coins_to_burn_nanos         BIGINT NOT NULL,
				transfer_restriction_status SMALLINT
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_dao_coin_transfers (
				transaction_hash           BYTEA PRIMARY KEY,
				profile_public_key         BYTEA NOT NULL,
				dao_coin_to_transfer_nanos BIGINT NOT NULL,
				receiver_public_key        BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}
		_, err = db.Exec(`
			CREATE TABLE pg_dao_coin_balances (
				holder_pkid   BYTEA,
				creator_pkid  BYTEA,
				balance_nanos BIGINT,
				has_purchased BOOL,

				PRIMARY KEY (holder_pkid, creator_pkid)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			ALTER TABLE pg_profiles
				ADD COLUMN minting_disabled                     BOOL,
				ADD COLUMN dao_coin_number_of_holders           BIGINT,
				ADD COLUMN dao_coin_coins_in_circulation_nanos  BIGINT,
				ADD COLUMN dao_coin_minting_disabled            BOOL,
				ADD COLUMN dao_coin_transfer_restriction_status SMALLINT;
			`)
		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE pg_metadata_dao_coins;
			DROP TABLE pg_metadata_dao_coin_transfers;
			DROP TABLE pg_dao_coin_balances;
			ALTER TABLE pg_profiles
				DROP COLUMN minting_disabled,
				DROP COLUMN dao_coin_number_of_holders,
				DROP COLUMN dao_coin_coins_in_circulation_nanos,
				DROP COLUMN dao_coin_minting_disabled,
				DROP COLUMN dao_coin_transfer_restriction_status; 
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20220106162320_create_dao_coin_tables", up, down, opts)
}
