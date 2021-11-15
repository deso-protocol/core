CREATE TABLE pg_chains (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name     TEXT(32) NOT NULL,
    tip_hash VARCHAR(54) NOT NULL,

    UNIQUE INDEX (name(32))
);

--bun:split

CREATE TABLE pg_blocks (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    hash              VARCHAR(54) NOT NULL,
    parent_hash       VARCHAR(54),
    height            BIGINT NOT NULL,
    difficulty_target VARCHAR(54)  NOT NULL,
    cum_work          VARCHAR(54)  NOT NULL,
    status            TEXT   NOT NULL,
    tx_merkle_root    VARCHAR(54)  NOT NULL,
    timestamp         BIGINT NOT NULL,
    nonce             BIGINT NOT NULL,
    extra_nonce       BIGINT,
    version           INT,
    notified          BOOL NOT NULL,

    UNIQUE INDEX (hash)
);

--bun:split

CREATE TABLE pg_transactions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    hash       VARCHAR(54),
    block_hash VARCHAR(54) NOT NULL,
    type       SMALLINT NOT NULL,
    public_key VARCHAR(56),
    extra_data JSON,
    r          VARCHAR(54),
    s          VARCHAR(54),

    UNIQUE INDEX (hash)
);

--bun:split

CREATE TABLE pg_transaction_outputs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    output_hash  VARCHAR(54)    NOT NULL,
    output_index INT      NOT NULL,
    output_type  SMALLINT NOT NULL,
    height       BIGINT   NOT NULL,
    public_key   VARCHAR(56)    NOT NULL,
    amount_nanos BIGINT   NOT NULL,
    spent        BOOL     NOT NULL,
    input_hash   VARCHAR(54),
    input_index  INT,

    UNIQUE INDEX (output_hash, output_index),
    INDEX (output_hash, output_index, spent),
    INDEX (public_key)
);

--bun:split

CREATE TABLE pg_metadata_block_rewards (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash VARCHAR(54) NOT NULL,
    extra_data       VARCHAR(54) NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_bitcoin_exchanges (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash    VARCHAR(54) NOT NULL,
    bitcoin_block_hash  VARCHAR(54) NOT NULL,
    bitcoin_merkle_root VARCHAR(54) NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_private_messages (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash     VARCHAR(54)  NOT NULL,
    recipient_public_key VARCHAR(56)  NOT NULL,
    encrypted_text       MEDIUMBLOB  NOT NULL,
    timestamp_nanos      BIGINT NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_submit_posts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash    VARCHAR(54)  NOT NULL,
    post_hash_to_modify VARCHAR(54)  NOT NULL,
    parent_stake_id     VARCHAR(54)  NOT NULL,
    body                MEDIUMTEXT  NOT NULL,
    timestamp_nanos     BIGINT NOT NULL,
    is_hidden           BOOL   NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_update_exchange_rates (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash      VARCHAR(54) NOT NULL,
    usd_cents_per_bitcoin BIGINT NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_update_profiles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash         VARCHAR(54) NOT NULL,
    profile_public_key       VARCHAR(56),
    new_username             VARCHAR(54),
    new_description          VARCHAR(54),
    new_profile_pic          MEDIUMBLOB,
    new_creator_basis_points BIGINT NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_follows (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash    VARCHAR(54) NOT NULL,
    followed_public_key VARCHAR(56) NOT NULL,
    is_unfollow         BOOL NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_likes (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash VARCHAR(54) NOT NULL,
    liked_post_hash  VARCHAR(54) NOT NULL,
    is_unlike        BOOL NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_creator_coins (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash                VARCHAR(54) NOT NULL,
    profile_public_key              VARCHAR(56) NOT NULL,
    operation_type                  SMALLINT NOT NULL,
    deso_to_sell_nanos              BIGINT NOT NULL,
    creator_coin_to_sell_nanos      BIGINT NOT NULL,
    deso_to_add_nanos               BIGINT NOT NULL,
    min_deso_expected_nanos         BIGINT NOT NULL,
    min_creator_coin_expected_nanos BIGINT NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_swap_identities (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash VARCHAR(54) NOT NULL,
    from_public_key  VARCHAR(56) NOT NULL,
    to_public_key    VARCHAR(56) NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_creator_coin_transfers (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash               VARCHAR(54) NOT NULL,
    profile_public_key             VARCHAR(56) NOT NULL,
    creator_coin_to_transfer_nanos BIGINT NOT NULL,
    receiver_public_key            VARCHAR(56) NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_create_nfts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash             VARCHAR(54) NOT NULL,
    nft_post_hash                VARCHAR(54) NOT NULL,
    num_copies                   BIGINT NOT NULL,
    has_unlockable               BOOL NOT NULL,
    is_for_sale                  BOOL NOT NULL,
    min_bid_amount_nanos         BIGINT NOT NULL,
    creator_royalty_basis_points BIGINT NOT NULL,
    coin_royalty_basis_points    BIGINT NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_update_nfts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash     VARCHAR(54) NOT NULL,
    nft_post_hash        VARCHAR(54) NOT NULL,
    serial_number        BIGINT NOT NULL,
    is_for_sale          BOOL NOT NULL,
    min_bid_amount_nanos BIGINT NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_accept_nft_bids (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash VARCHAR(54) NOT NULL,
    nft_post_hash    VARCHAR(54) NOT NULL,
    serial_number    BIGINT NOT NULL,
    bidder_pkid      VARCHAR(56) NOT NULL,
    bid_amount_nanos BIGINT NOT NULL,
    unlockable_text  VARCHAR(54) NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_bid_inputs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash VARCHAR(54) NOT NULL,
    input_hash       VARCHAR(54) NOT NULL,
    input_index      BIGINT NOT NULL,

    UNIQUE INDEX (transaction_hash, input_hash, input_index)
);

--bun:split

CREATE TABLE pg_metadata_nft_bids (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash VARCHAR(54) NOT NULL,
    nft_post_hash    VARCHAR(54) NOT NULL,
    serial_number    BIGINT NOT NULL,
    bid_amount_nanos BIGINT NOT NULL
);

--bun:split

CREATE TABLE pg_notifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash VARCHAR(54) NOT NULL,
    mined            BOOL NOT NULL,
    to_user          VARCHAR(54) NOT NULL,
    from_user        VARCHAR(54) NOT NULL,
    other_user       VARCHAR(54),
    type             SMALLINT NOT NULL,
    amount           BIGINT,
    post_hash        VARCHAR(54),
    timestamp        BIGINT NOT NULL
);

--bun:split

CREATE TABLE pg_profiles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    pkid                       VARCHAR(56) NOT NULL,
    public_key                 VARCHAR(56) NOT NULL,
    username                   TEXT(25),
    description                TEXT,
    profile_pic                MEDIUMBLOB,
    creator_basis_points       BIGINT,
    deso_locked_nanos          BIGINT,
    number_of_holders          BIGINT,
    coins_in_circulation_nanos BIGINT,
    coin_watermark_nanos       BIGINT,

    UNIQUE INDEX (pkid),
    INDEX (public_key),
    INDEX (username(25)),
    INDEX ((LOWER(username)))
);

--bun:split

CREATE TABLE pg_posts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    post_hash                    VARCHAR(54) NOT NULL,
    poster_public_key            VARCHAR(56) NOT NULL,
    parent_post_hash             VARCHAR(54),
    body                         MEDIUMTEXT,
    reposted_post_hash           VARCHAR(54),
    quoted_repost                BOOL,
    timestamp                    BIGINT,
    hidden                       BOOL,
    like_count                   BIGINT,
    repost_count                 BIGINT,
    quote_repost_count           BIGINT,
    diamond_count                BIGINT,
    comment_count                BIGINT,
    pinned                       BOOL,
    nft                          BOOL,
    num_nft_copies               BIGINT,
    unlockable                   BOOL,
    creator_royalty_basis_points BIGINT,
    coin_royalty_basis_points    BIGINT,
    extra_data                   JSON,
    num_nft_copies_for_sale      BIGINT,
    num_nft_copies_burned        BIGINT,

    UNIQUE INDEX (post_hash)
);

--bun:split

CREATE TABLE pg_likes (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    liker_public_key VARCHAR(56) NOT NULL,
    liked_post_hash  VARCHAR(54) NOT NULL,

    UNIQUE INDEX (liker_public_key, liked_post_hash)
);

--bun:split

CREATE TABLE pg_follows (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    follower_pkid VARCHAR(56) NOT NULL,
    followed_pkid VARCHAR(56) NOT NULL,

    UNIQUE INDEX (follower_pkid, followed_pkid)
);

--bun:split

CREATE TABLE pg_diamonds (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    sender_pkid       VARCHAR(56) NOT NULL,
    receiver_pkid     VARCHAR(56) NOT NULL,
    diamond_post_hash VARCHAR(54) NOT NULL,
    diamond_level     SMALLINT,

    UNIQUE INDEX (sender_pkid, receiver_pkid, diamond_post_hash)
);

--bun:split

CREATE TABLE pg_messages (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    message_hash         VARCHAR(54) NOT NULL,
    sender_public_key    VARCHAR(56),
    recipient_public_key VARCHAR(56),
    encrypted_text       MEDIUMBLOB,
    timestamp_nanos      BIGINT,

    UNIQUE INDEX (message_hash)
);

--bun:split

CREATE TABLE pg_creator_coin_balances (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    holder_pkid   VARCHAR(56) NOT NULL,
    creator_pkid  VARCHAR(56) NOT NULL,
    balance_nanos BIGINT UNSIGNED,
    has_purchased BOOL,

    UNIQUE INDEX (holder_pkid, creator_pkid)
);

--bun:split

CREATE TABLE pg_balances (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    public_key    VARCHAR(56) NOT NULL,
    balance_nanos BIGINT UNSIGNED,

    UNIQUE INDEX (public_key)
);

--bun:split

CREATE TABLE pg_global_params (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    usd_cents_per_bitcoin        BIGINT,
    create_profile_fee_nanos     BIGINT,
    create_nft_fee_nanos         BIGINT,
    max_copies_per_nft           BIGINT,
    min_network_fee_nanos_per_kb BIGINT
);

--bun:split

CREATE TABLE pg_reposts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    reposter_public_key VARCHAR(56) NOT NULL,
    reposted_post_hash  VARCHAR(54) NOT NULL,
    repost_post_hash    VARCHAR(54),

    UNIQUE INDEX (reposter_public_key, reposted_post_hash)
);

--bun:split

CREATE TABLE pg_forbidden_keys (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    public_key VARCHAR(56) NOT NULL,

    UNIQUE INDEX (public_key)
);

--bun:split

CREATE TABLE pg_nfts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    nft_post_hash                  VARCHAR(54) NOT NULL,
    serial_number                  BIGINT NOT NULL,
    last_owner_pkid                VARCHAR(56),
    owner_pkid                     VARCHAR(56),
    for_sale                       BOOL,
    min_bid_amount_nanos           BIGINT,
    unlockable_text                TEXT,
    last_accepted_bid_amount_nanos BIGINT,
    is_pending BOOL,

    UNIQUE INDEX (nft_post_hash, serial_number)
);

--bun:split

CREATE TABLE pg_nft_bids (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    bidder_pkid      VARCHAR(56) NOT NULL,
    nft_post_hash    VARCHAR(54) NOT NULL,
    serial_number    BIGINT NOT NULL,
    bid_amount_nanos BIGINT,
    accepted         BOOL,

    UNIQUE INDEX (bidder_pkid, nft_post_hash, serial_number)
);

--bun:split

CREATE TABLE pg_metadata_derived_keys (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash   VARCHAR(54) NOT NULL,
    derived_public_key VARCHAR(56) NOT NULL,
    expiration_block   BIGINT NOT NULL,
    operation_type     SMALLINT NOT NULL,
    access_signature   VARCHAR(54) NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_derived_keys (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    owner_public_key   VARCHAR(56) NOT NULL,
    derived_public_key VARCHAR(56) NOT NULL,
    expiration_block   BIGINT NOT NULL,
    operation_type     SMALLINT NOT NULL,

    UNIQUE INDEX (owner_public_key, derived_public_key)
);

--bun:split

CREATE TABLE pg_metadata_nft_transfer (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash    VARCHAR(54) NOT NULL,
    nft_post_hash       VARCHAR(54) NOT NULL,
    serial_number       BIGINT NOT NULL,
    receiver_public_key VARCHAR(56) NOT NULL,
    unlockable_text     VARCHAR(54) NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_accept_nft_transfer (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash VARCHAR(54) NOT NULL,
    nft_post_hash    VARCHAR(54) NOT NULL,
    serial_number    BIGINT NOT NULL,

    UNIQUE INDEX (transaction_hash)
);

--bun:split

CREATE TABLE pg_metadata_burn_nft (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_hash VARCHAR(54) NOT NULL,
    nft_post_hash    VARCHAR(54) NOT NULL,
    serial_number    BIGINT NOT NULL,

    UNIQUE INDEX (transaction_hash)
);
