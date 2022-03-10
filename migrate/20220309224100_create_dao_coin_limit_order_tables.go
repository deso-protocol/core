package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`
			CREATE TABLE pg_metadata_dao_coin_limit_orders (
				transaction_hash              BYTEA PRIMARY KEY,
				denominated_coin_type         SMALLINT NOT NULL,
				denominated_coin_creator_pkid BYTEA NOT NULL,
				dao_coin_creator_pkid         BYTEA NOT NULL,
				operation_type                SMALLINT NOT NULL,
				price_nanos                   TEXT NOT NULL,
				quantity                      TEXT NOT NULL
			);
		`)

		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE pg_metadata_dao_coin_limit_orders;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20220309224100_create_dao_coin_limit_order_tables", up, down, opts)
}
