package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`
			CREATE TABLE pg_chains (
                name     TEXT  NOT NULL PRIMARY KEY,
				tip_hash BYTEA NOT NULL
			)
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_blocks (
				hash              BYTEA PRIMARY KEY,
				parent_hash       BYTEA,
				height            BIGINT NOT NULL,
				difficulty_target BYTEA  NOT NULL,
				cum_work          BYTEA  NOT NULL,
				status            TEXT   NOT NULL,
				tx_merkle_root    BYTEA  NOT NULL,
				timestamp         BIGINT NOT NULL,
				nonce             BIGINT NOT NULL,
				extra_nonce       BIGINT,
				version           INT,
				notified          BOOL NOT NULL
			)
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_transactions (
				hash       BYTEA PRIMARY KEY,
				block_hash BYTEA NOT NULL,
				type       SMALLINT NOT NULL,
				public_key BYTEA,
				extra_data JSONB,
				r          BYTEA,
				s          BYTEA
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_transaction_outputs (
				output_hash  BYTEA    NOT NULL,
				output_index INT      NOT NULL,
				output_type  SMALLINT NOT NULL,
				height       BIGINT   NOT NULL,
				public_key   BYTEA    NOT NULL,
				amount_nanos BIGINT   NOT NULL,
				spent        BOOL     NOT NULL,
				input_hash   BYTEA,
				input_index  INT,

				PRIMARY KEY (output_hash, output_index)
			);

			CREATE INDEX pg_transaction_outputs_public_key ON pg_transaction_outputs(public_key);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_block_rewards (
				transaction_hash BYTEA PRIMARY KEY,
				extra_data       BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_bitcoin_exchanges (
				transaction_hash    BYTEA PRIMARY KEY,
				bitcoin_block_hash  BYTEA NOT NULL,
				bitcoin_merkle_root BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_private_messages (
				transaction_hash     BYTEA PRIMARY KEY,
				recipient_public_key BYTEA  NOT NULL,
				encrypted_text       BYTEA  NOT NULL,
				timestamp_nanos      BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_submit_posts (
				transaction_hash    BYTEA PRIMARY KEY,
				post_hash_to_modify BYTEA  NOT NULL,
				parent_stake_id     BYTEA  NOT NULL,
				body                BYTEA  NOT NULL,
				timestamp_nanos     BIGINT NOT NULL,
				is_hidden           BOOL   NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_update_exchange_rates (
				transaction_hash      BYTEA PRIMARY KEY,
				usd_cents_per_bitcoin BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_update_profiles (
				transaction_hash         BYTEA PRIMARY KEY,
				profile_public_key       BYTEA,
				new_username             BYTEA,
				new_description          BYTEA,
				new_profile_pic          BYTEA,
				new_creator_basis_points BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_follows (
				transaction_hash    BYTEA PRIMARY KEY,
				followed_public_key BYTEA NOT NULL,
				is_unfollow         BOOL NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_likes (
				transaction_hash BYTEA PRIMARY KEY,
				liked_post_hash  BYTEA NOT NULL,
				is_unlike        BOOL NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_creator_coins (
				transaction_hash                BYTEA PRIMARY KEY,
				profile_public_key              BYTEA NOT NULL,
				operation_type                  SMALLINT NOT NULL,
				de_so_to_sell_nanos         BIGINT NOT NULL,
				creator_coin_to_sell_nanos      BIGINT NOT NULL,
				de_so_to_add_nanos          BIGINT NOT NULL,
				min_de_so_expected_nanos    BIGINT NOT NULL,
				min_creator_coin_expected_nanos BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_swap_identities (
				transaction_hash BYTEA PRIMARY KEY,
				from_public_key  BYTEA NOT NULL,
				to_public_key    BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_creator_coin_transfers (
				transaction_hash               BYTEA PRIMARY KEY,
				profile_public_key             BYTEA NOT NULL,
				creator_coin_to_transfer_nanos BIGINT NOT NULL,
				receiver_public_key            BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_create_nfts (
				transaction_hash             BYTEA PRIMARY KEY,
				nft_post_hash                BYTEA NOT NULL,
				num_copies                   BIGINT NOT NULL,
				has_unlockable               BOOL NOT NULL,
				is_for_sale                  BOOL NOT NULL,
				min_bid_amount_nanos         BIGINT NOT NULL,
				creator_royalty_basis_points BIGINT NOT NULL,
				coin_royalty_basis_points    BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_update_nfts (
				transaction_hash     BYTEA PRIMARY KEY,
				nft_post_hash        BYTEA NOT NULL,
				serial_number        BIGINT NOT NULL,
				is_for_sale          BOOL NOT NULL,
				min_bid_amount_nanos BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_accept_nft_bids (
				transaction_hash BYTEA PRIMARY KEY,
				nft_post_hash    BYTEA NOT NULL,
				serial_number    BIGINT NOT NULL,
				bidder_pkid      BYTEA NOT NULL,
				bid_amount_nanos BIGINT NOT NULL,
				unlockable_text  BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_bid_inputs (
				transaction_hash BYTEA NOT NULL,
				input_hash       BYTEA NOT NULL,
				input_index      BIGINT NOT NULL,

				PRIMARY KEY (transaction_hash, input_hash, input_index)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_metadata_nft_bids (
				transaction_hash BYTEA PRIMARY KEY,
				nft_post_hash    BYTEA NOT NULL,
				serial_number    BIGINT NOT NULL,
				bid_amount_nanos BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_notifications (
				transaction_hash BYTEA PRIMARY KEY,
				mined            BOOL NOT NULL,
				to_user          BYTEA NOT NULL,
				from_user        BYTEA NOT NULL,
				other_user       BYTEA,
				type             SMALLINT NOT NULL,
				amount           BIGINT,
				post_hash        BYTEA,
				timestamp        BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_profiles (
				pkid                       BYTEA PRIMARY KEY,
				public_key                 BYTEA NOT NULL,
                username                   TEXT,
				description                TEXT,
				profile_pic                BYTEA,
				creator_basis_points       BIGINT,
				de_so_locked_nanos         BIGINT,
				number_of_holders          BIGINT,
				coins_in_circulation_nanos BIGINT,
				coin_watermark_nanos       BIGINT
			);

			CREATE INDEX pg_profiles_public_key ON pg_profiles(public_key);
			CREATE INDEX pg_profiles_username ON pg_profiles(username);
			CREATE INDEX pg_profiles_lower_username ON pg_profiles(LOWER(username));
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_posts (
				post_hash                    BYTEA PRIMARY KEY,
				poster_public_key            BYTEA NOT NULL,
				parent_post_hash             BYTEA,
                body                         TEXT,
				reposted_post_hash          BYTEA,
				quoted_repost               BOOL,
				timestamp                    BIGINT,
				hidden                       BOOL,
				like_count                   BIGINT,
				repost_count                BIGINT,
				quote_repost_count          BIGINT,
				diamond_count                BIGINT,
				comment_count                BIGINT,
				pinned                       BOOL,
				nft                          BOOL,
				num_nft_copies               BIGINT,
				unlockable                   BOOL,
				creator_royalty_basis_points BIGINT,
				coin_royalty_basis_points    BIGINT,
				extra_data                   JSONB
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_likes (
				liker_public_key BYTEA,
				liked_post_hash  BYTEA,

				PRIMARY KEY (liker_public_key, liked_post_hash)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_follows (
				follower_pkid BYTEA,
				followed_pkid BYTEA,

				PRIMARY KEY (follower_pkid, followed_pkid)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_diamonds (
				sender_pkid       BYTEA,
				receiver_pkid     BYTEA,
				diamond_post_hash BYTEA,
				diamond_level     SMALLINT,

				PRIMARY KEY (sender_pkid, receiver_pkid, diamond_post_hash)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_messages (
				message_hash         BYTEA PRIMARY KEY,
				sender_public_key    BYTEA,
				recipient_public_key BYTEA,
				encrypted_text       BYTEA,
				timestamp_nanos      BIGINT
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_creator_coin_balances (
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
			CREATE TABLE pg_balances (
				public_key    BYTEA PRIMARY KEY,
				balance_nanos BIGINT
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_global_params (
				id                           BIGSERIAL PRIMARY KEY,
				usd_cents_per_bitcoin        BIGINT,
				create_profile_fee_nanos     BIGINT,
				create_nft_fee_nanos         BIGINT,
				max_copies_per_nft           BIGINT,
				min_network_fee_nanos_per_kb BIGINT
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_reposts (
				reposter_public_key BYTEA,
				reposted_post_hash  BYTEA,
				repost_post_hash    BYTEA,

				PRIMARY KEY (reposter_public_key, reposted_post_hash)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_forbidden_keys (
				public_key BYTEA PRIMARY KEY
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_nfts (
				nft_post_hash                  BYTEA,
				serial_number                  BIGINT,
				last_owner_pkid                BYTEA,
				owner_pkid                     BYTEA,
				for_sale                       BOOL,
				min_bid_amount_nanos           BIGINT,
				unlockable_text                TEXT,
				last_accepted_bid_amount_nanos BIGINT,

				PRIMARY KEY (nft_post_hash, serial_number)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE pg_nft_bids (
				bidder_pkid      BYTEA,
				nft_post_hash    BYTEA,
				serial_number    BIGINT,
				bid_amount_nanos BIGINT,
				accepted         BOOL,

				PRIMARY KEY (bidder_pkid, nft_post_hash, serial_number)
			);
		`)
		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE pg_chains;
			DROP TABLE pg_blocks;
			DROP TABLE pg_transactions;
			DROP TABLE pg_transaction_outputs;
			DROP TABLE pg_metadata_block_rewards;
			DROP TABLE pg_metadata_bitcoin_exchanges;
			DROP TABLE pg_metadata_private_messages;
			DROP TABLE pg_metadata_submit_posts;
			DROP TABLE pg_metadata_update_exchange_rates;
			DROP TABLE pg_metadata_update_profiles;
			DROP TABLE pg_metadata_follows;
			DROP TABLE pg_metadata_likes;
			DROP TABLE pg_metadata_creator_coins;
			DROP TABLE pg_metadata_swap_identities;
			DROP TABLE pg_metadata_creator_coin_transfers;
			DROP TABLE pg_metadata_create_nfts;
			DROP TABLE pg_metadata_update_nfts;
			DROP TABLE pg_metadata_accept_nft_bids;
			DROP TABLE pg_metadata_bid_inputs;
			DROP TABLE pg_metadata_nft_bids;
			DROP TABLE pg_notifications;
			DROP TABLE pg_profiles;
			DROP TABLE pg_posts;
			DROP TABLE pg_likes;
			DROP TABLE pg_follows;
			DROP TABLE pg_diamonds;
			DROP TABLE pg_messages;
			DROP TABLE pg_creator_coin_balances;
			DROP TABLE pg_balances;
			DROP TABLE pg_global_params;
			DROP TABLE pg_reposts;
			DROP TABLE pg_forbidden_keys;
			DROP TABLE pg_nfts;
			DROP TABLE pg_nft_bids;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20210623152412_create_tables", up, down, opts)
}
