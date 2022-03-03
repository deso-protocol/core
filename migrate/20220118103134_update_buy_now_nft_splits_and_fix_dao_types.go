package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {

		_, err := db.Exec(`
			ALTER TABLE pg_profiles
				ALTER COLUMN dao_coin_coins_in_circulation_nanos TYPE TEXT USING '0x' || to_hex(dao_coin_coins_in_circulation_nanos);
			`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			ALTER TABLE pg_metadata_dao_coins
				ALTER COLUMN coins_to_mint_nanos TYPE TEXT USING '0x' || to_hex(coins_to_mint_nanos),
				ALTER COLUMN coins_to_burn_nanos TYPE TEXT USING '0x' || to_hex(coins_to_burn_nanos) ;
			`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			ALTER TABLE pg_metadata_dao_coin_transfers
				ALTER COLUMN dao_coin_to_transfer_nanos TYPE TEXT USING '0x' || to_hex(dao_coin_to_transfer_nanos);
			`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			ALTER TABLE pg_dao_coin_balances
				ALTER COLUMN balance_nanos TYPE TEXT USING '0x' || to_hex(balance_nanos);
			`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			ALTER TABLE pg_posts
				ADD COLUMN additional_nft_royalties_to_coins_basis_points    JSONB,
				ADD COLUMN additional_nft_royalties_to_creators_basis_points JSONB;
			`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			ALTER TABLE pg_nfts
				ADD COLUMN is_buy_now BOOL,
				ADD COLUMN buy_now_price_nanos BIGINT; 
			`)
		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			ALTER TABLE pg_nfts
				DROP COLUMN additional_nft_royalties_to_coins_basis_points,
				DROP COLUMN additional_nft_royalties_to_creators_basis_points; 
			ALTER TABLE pg_posts
				DROP COLUMN is_buy_now,
				DROP COLUMN buy_now_price_nanos;
			ALTER TABLE pg_dao_coin_balances
				ALTER COLUMN balance_nanos TYPE BIGINT USING lpad(balance_nanos, 16, '0')::bit(64)::bigint;
			ALTER TABLE pg_metadata_dao_coin_transfers
				ALTER COLUMN dao_coin_to_transfer_nanos TYPE BIGINT USING lpad(dao_coin_to_transfer_nanos, 16, '0')::bit(64)::bigint;
			ALTER TABLE pg_metadata_dao_coins
				ALTER COLUMN coins_to_mint_nanos TYPE BIGINT USING lpad(coins_to_mint_nanos, 16, '0')::bit(64)::bigint,
				ALTER COLUMN coins_to_burn_nanos TYPE BIGINT USING lpad(coins_to_burn_nanos, 16, '0')::bit(64)::bigint;
			ALTER TABLE pg_profiles
				ALTER COLUMN dao_coin_coins_in_circulation_nanos TYPE BIGINT USING lpad(dao_coin_coins_in_circulation_nanos, 16, '0')::bit(64)::bigint; 
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20220118103134_update_buy_now_nft_splits_and_fix_dao_types", up, down, opts)
}
