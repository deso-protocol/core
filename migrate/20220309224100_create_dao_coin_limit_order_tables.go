package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		// TODO: what indices should we add?
		// Create pg_metadata_dao_coin_limit_orders table.
		_, err := db.Exec(`
			CREATE TABLE pg_metadata_dao_coin_limit_orders (
				transaction_hash              BYTEA PRIMARY KEY,
				buying_dao_coin_creator_pkid  BYTEA NOT NULL,
				selling_dao_coin_creator_pkid BYTEA NOT NULL,
				price                         DECIMAL NOT NULL,
				quantity_nanos                TEXT NOT NULL,
				cancel_existing_order         BOOL NOT NULL
			);
		`)

		if err != nil {
			return err
		}

		// Create pg_dao_coin_limit_orders table.
		_, err = db.Exec(`
			CREATE TABLE pg_dao_coin_limit_orders (
				transactor_pkid               BYTEA NOT NULL,
				buying_dao_coin_creator_pkid  BYTEA NOT NULL,
				selling_dao_coin_creator_pkid BYTEA NOT NULL,
				price                         DECIMAL NOT NULL,
                quantity_nanos                TEXT NOT NULL,
				block_height				  BIGINT NOT NULL,

				PRIMARY KEY (
					transactor_pkid,
					buying_dao_coin_creator_pkid,
					selling_dao_coin_creator_pkid,
					price,
					block_height
				)
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
			DROP TABLE pg_metadata_dao_coin_limit_orders;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20220309224100_create_dao_coin_limit_order_tables", up, down, opts)
}
