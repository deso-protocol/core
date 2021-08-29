package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`
			CREATE TABLE pg_trends (
				pkid                 BYTEA,
				block_height         BIGINT,
				founder_reward_nanos BIGINT,
				diamond_nanos        BIGINT,
				nft_seller_nanos     BIGINT,
				nft_royalty_nanos    BIGINT,
				num_holders          BIGINT,
				coins_in_circulation BIGINT,
				locked_nanos         BIGINT,
				balance_nanos        BIGINT,
				holding_nanos        BIGINT,

				PRIMARY KEY (pkid, block_height)
			)
		`)
		return err
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE pg_trends;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20210827123218_create_trends_table", up, down, opts)
}
