package main

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`
			CREATE TABLE chains (
                name     TEXT  NOT NULL PRIMARY KEY,
				tip_hash BYTEA NOT NULL
			)
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE blocks (
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
			CREATE TABLE transactions (
				hash       BYTEA PRIMARY KEY,
				block_hash BYTEA NOT NULL,
				type       SMALLINT NOT NULL,
				public_key BYTEA,
				extra_data JSONB,
				r BYTEA,
				s BYTEA
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE transaction_outputs (
				output_hash  BYTEA  NOT NULL,
				output_index INT    NOT NULL,
				output_type  SMALLINT NOT NULL,
				public_key   BYTEA  NOT NULL,
				amount_nanos BIGINT NOT NULL,
				spent        BOOL   NOT NULL,
				input_hash   BYTEA,
				input_index  INT,

				PRIMARY KEY (output_hash, output_index)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_block_rewards (
				transaction BYTEA PRIMARY KEY,
				extra_data BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_bitcoin_exchanges (
				transaction BYTEA PRIMARY KEY,
				bitcoin_block_hash  BYTEA NOT NULL,
				bitcoin_merkle_root BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_private_messages (
				transaction BYTEA PRIMARY KEY,
				recipient_public_key BYTEA  NOT NULL,
				encrypted_text       BYTEA  NOT NULL,
				timestamp_nanos      BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_submit_posts (
				transaction BYTEA PRIMARY KEY,
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
			CREATE TABLE metadata_update_bitcoin_usd_exchange_rates (
				transaction BYTEA PRIMARY KEY,
				usd_cents_per_bitcoin BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_update_profiles (
				transaction BYTEA PRIMARY KEY,
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
			CREATE TABLE metadata_follows (
				transaction BYTEA PRIMARY KEY,
				followed_public_key BYTEA NOT NULL,
				is_unfollow         BOOL NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_likes (
				transaction BYTEA PRIMARY KEY,
				liked_post_hash BYTEA NOT NULL,
				is_unlike       BOOL NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_creator_coins (
				transaction BYTEA PRIMARY KEY,
				profile_public_key              BYTEA NOT NULL,
				operation_type                  SMALLINT NOT NULL,
				bit_clout_to_sell_nanos         BIGINT NOT NULL,
				creator_coin_to_sell_nanos      BIGINT NOT NULL,
				bit_clout_to_add_nanos          BIGINT NOT NULL,
				min_bit_clout_expected_nanos    BIGINT NOT NULL,
				min_creator_coin_expected_nanos BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_creator_coin_transfers (
				transaction BYTEA PRIMARY KEY,
				profile_public_key             BYTEA NOT NULL,
				creator_coin_to_transfer_nanos BIGINT NOT NULL,
				receiver_public_key            BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_swap_identities (
				transaction BYTEA PRIMARY KEY,
				from_public_key BYTEA NOT NULL,
				to_public_key   BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE notifications (
				transaction BYTEA PRIMARY KEY,
				mined       BOOL NOT NULL,
				to_user     BYTEA NOT NULL,
				from_user   BYTEA NOT NULL,
				action      TEXT NOT NULL,
				amount      BIGINT,
				post_hash   BYTEA,
				timestamp   BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE chains;
			DROP TABLE blocks;
			DROP TABLE transactions;
			DROP TABLE transaction_outputs;
			DROP TABLE metadata_block_rewards;
			DROP TABLE metadata_bitcoin_exchanges;
			DROP TABLE metadata_private_messages;
			DROP TABLE metadata_submit_posts;
			DROP TABLE metadata_update_bitcoin_usd_exchange_rates;
			DROP TABLE metadata_update_profiles;
			DROP TABLE metadata_follows;
			DROP TABLE metadata_likes;
			DROP TABLE metadata_creator_coins;
			DROP TABLE metadata_creator_coin_transfers;
			DROP TABLE metadata_swap_identities;
			DROP TABLE notifications;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20210623152412_create_tables", up, down, opts)
}
