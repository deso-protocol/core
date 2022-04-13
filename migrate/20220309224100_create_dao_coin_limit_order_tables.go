package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		// Create pg_metadata_dao_coin_limit_orders table.
		_, err := db.Exec(`
			CREATE TABLE pg_metadata_dao_coin_limit_orders (
				transaction_hash                                   BYTEA PRIMARY KEY,
				buying_dao_coin_creator_public_key                 BYTEA NOT NULL,
				selling_dao_coin_creator_public_key                BYTEA NOT NULL,
				scaled_exchange_rate_coins_to_sell_per_coin_to_buy TEXT NOT NULL,
				quantity_to_fill_in_base_units                     TEXT NOT NULL,
				operation_type                                     BIGINT NOT NULL,
				cancel_order_id                                    BYTEA NOT NULL,
				fee_nanos                                          BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		// Create the bidder inputs table.
		_, err = db.Exec(`
			CREATE TABLE pg_metadata_dao_coin_limit_order_bidder_inputs (
				transaction_hash BYTEA NOT NULL,
				input_hash       BYTEA NOT NULL,
				input_index      BIGINT NOT NULL,

				PRIMARY KEY (transaction_hash, input_hash, input_index)
			);
		`)
		if err != nil {
			return err
		}

		// Create pg_dao_coin_limit_orders table.
		_, err = db.Exec(`
			CREATE TABLE pg_dao_coin_limit_orders (
				order_id                                           BYTEA PRIMARY KEY,
				transactor_pkid                                    BYTEA NOT NULL,
				buying_dao_coin_creator_pkid                       BYTEA NOT NULL,
				selling_dao_coin_creator_pkid                      BYTEA NOT NULL,
				scaled_exchange_rate_coins_to_sell_per_coin_to_buy TEXT NOT NULL,
				quantity_to_fill_in_base_units                     TEXT NOT NULL,
				operation_type                                     BIGINT NOT NULL,
				block_height                                       BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE pg_dao_coin_limit_orders;
			DROP TABLE pg_metadata_dao_coin_limit_order_bidder_inputs; 
			DROP TABLE pg_metadata_dao_coin_limit_orders;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}
	migrations.Register("20220309224100_create_dao_coin_limit_order_tables", up, down, opts)
}
