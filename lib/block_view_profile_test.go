package lib

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"runtime/pprof"
	"testing"
	"time"
)

func TestUpdateProfile(t *testing.T) {
	// For testing purposes, we set the fix block height to be 0 for the ParamUpdaterProfileUpdateFixBlockHeight.
	ParamUpdaterProfileUpdateFixBlockHeight = 0
	UpdateProfileFixBlockHeight = 0

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true

	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// Setup some convenience functions for the test.
	txnOps := [][]*UtxoOperation{}
	txns := []*MsgDeSoTxn{}
	expectedSenderBalances := []uint64{}

	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPk))

		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPk, recipientPk,
			senderPriv, 70 /*amount to send*/, 11 /*feerate*/)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Fund all the keys.
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)

	// Fund key to test CreateProfile fee
	registerOrTransfer("", senderPkString, m4Pub, senderPrivString)

	updateProfile := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string, profilePubKey []byte, newUsername string,
		newDescription string, newProfilePic string, newCreatorBasisPoints uint64,
		newStakeMultipleBasisPoints uint64, isHidden bool) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, updaterPkBase58Check))

		currentOps, currentTxn, _, err := _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB, updaterPkBase58Check,
			updaterPrivBase58Check, profilePubKey, newUsername,
			newDescription, newProfilePic, newCreatorBasisPoints,
			newStakeMultipleBasisPoints, isHidden)

		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_, _, _ = m2Priv, m3Priv, updateProfile

	updateGlobalParamsEntry := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string,
		USDCentsPerBitcoinExchangeRate int64,
		minimumNetworkFeeNanosPerKb int64,
		createProfileFeeNanos int64) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, updaterPkBase58Check))

		currentOps, currentTxn, _, err := _updateGlobalParamsEntry(t, chain, db, params,
			feeRateNanosPerKB,
			updaterPkBase58Check,
			updaterPrivBase58Check,
			int64(InitialUSDCentsPerBitcoinExchangeRate),
			minimumNetworkFeeNanosPerKb,
			createProfileFeeNanos,
			0,  /*createNFTFeeNanos*/
			-1, /*maxCopiesPerNFT*/
			true)
		require.NoError(err)
		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// ===================================================================================
	// Do some UpdateProfile transactions
	// ===================================================================================

	// Zero input txn should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			0,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"I am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			2*100*100,     /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorTxnMustHaveAtLeastOneInput)
	}

	// Username too long should fail.
	{
		badUsername := string(append([]byte("badUsername: "),
			RandomBytes(int32(params.MaxUsernameLengthBytes))...))
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			badUsername,   /*newUsername*/
			"I am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			2*100*100,     /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameTooLong)
	}

	// Description too long should fail.
	{
		badDescription := string(append([]byte("badDescription: "),
			RandomBytes(int32(params.MaxUserDescriptionLengthBytes))...))
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			2,              /*feeRateNanosPerKB*/
			m0Pub,          /*updaterPkBase58Check*/
			m0Priv,         /*updaterPrivBase58Check*/
			[]byte{},       /*profilePubKey*/
			"m0",           /*newUsername*/
			badDescription, /*newDescription*/
			shortPic,       /*newProfilePic*/
			10*100,         /*newCreatorBasisPoints*/
			2*100*100,      /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileDescriptionTooLong)
	}

	// Profile pic too long should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			longPic,       /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			2*100*100,     /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorMaxProfilePicSize)
	}

	// Stake multiple too large should fail long too long should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			100*100*100,   /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileStakeMultipleSize)
	}

	// Stake multiple too small should fail long too long should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			.99*100*100,   /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileStakeMultipleSize)
	}

	// Creator percentage too large should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			101*100,       /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileCreatorPercentageSize)
	}

	// Invalid profile public key should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,               /*feeRateNanosPerKB*/
			m0Pub,           /*updaterPkBase58Check*/
			m0Priv,          /*updaterPrivBase58Check*/
			RandomBytes(33), /*profilePubKey*/
			"m0",            /*newUsername*/
			"i am the m0",   /*newDescription*/
			shortPic,        /*newProfilePic*/
			10*100,          /*newCreatorBasisPoints*/
			1.25*100*100,    /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		// This returned RuleErrorProfilePubKeyNotAuthorized for me once
		// "ConnectTransaction: : _connectUpdateProfile: ... RuleErrorProfilePubKeyNotAuthorized"
		require.Contains(err.Error(), RuleErrorProfileBadPublicKey)
	}

	// Profile public key that is not authorized should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			m1PkBytes,     /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfilePubKeyNotAuthorized)
	}

	// A simple registration should succeed
	{
		updateProfile(
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Username that does not match our regex should fail
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,            /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0\x00",      /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidUsername)

		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,                /*feeRateNanosPerKB*/
			m1Pub,             /*updaterPkBase58Check*/
			m1Priv,            /*updaterPrivBase58Check*/
			[]byte{},          /*profilePubKey*/
			"m0 with a space", /*newUsername*/
			"i am the m0",     /*newDescription*/
			shortPic,          /*newProfilePic*/
			10*100,            /*newCreatorBasisPoints*/
			1.25*100*100,      /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidUsername)

		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,                  /*feeRateNanosPerKB*/
			m1Pub,               /*updaterPkBase58Check*/
			m1Priv,              /*updaterPrivBase58Check*/
			[]byte{},            /*profilePubKey*/
			"m0TraillingSpace ", /*newUsername*/
			"i am the m0",       /*newDescription*/
			shortPic,            /*newProfilePic*/
			10*100,              /*newCreatorBasisPoints*/
			1.25*100*100,        /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidUsername)

		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,            /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0-Hyphen",   /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidUsername)

		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,                    /*feeRateNanosPerKB*/
			m1Pub,                 /*updaterPkBase58Check*/
			m1Priv,                /*updaterPrivBase58Check*/
			[]byte{},              /*profilePubKey*/
			" m0SpaceAtBeginning", /*newUsername*/
			"i am the m0",         /*newDescription*/
			shortPic,              /*newProfilePic*/
			10*100,                /*newCreatorBasisPoints*/
			1.25*100*100,          /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidUsername)
	}

	// Trying to take an already-registered username should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameExists)

		// The username should be case-insensitive so creating a duplicate
		// with different casing should fail.
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"M0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameExists)

		// Register m1 and then try to steal the username
		updateProfile(
			1,             /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m1",          /*newUsername*/
			"i am the m1", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)

		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameExists)

		// The username should be case-insensitive so creating a duplicate
		// with different casing should fail.
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"M0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameExists)

		// The username should be case-insensitive so creating a duplicate
		// with different casing should fail.
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"M1",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameExists)
	}

	// Register m2 (should succeed)
	{
		updateProfile(
			1,             /*feeRateNanosPerKB*/
			m2Pub,         /*updaterPkBase58Check*/
			m2Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Leaving username, description, and pic blank should result in a noop.
	{
		updateProfile(
			10,           /*feeRateNanosPerKB*/
			m2Pub,        /*updaterPkBase58Check*/
			m2Priv,       /*updaterPrivBase58Check*/
			[]byte{},     /*profilePubKey*/
			"",           /*newUsername*/
			"",           /*newDescription*/
			"",           /*newProfilePic*/
			10*100,       /*newCreatorBasisPoints*/
			1.25*100*100, /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// An update followed by a reversion should result in no change.
	{
		updateProfile(
			1,                    /*feeRateNanosPerKB*/
			m2Pub,                /*updaterPkBase58Check*/
			m2Priv,               /*updaterPrivBase58Check*/
			[]byte{},             /*profilePubKey*/
			"m2_update",          /*newUsername*/
			"i am the m2 update", /*newDescription*/
			shortPic+"woohoo",    /*newProfilePic*/
			15*100,               /*newCreatorBasisPoints*/
			1.7*100*100,          /*newStakeMultipleBasisPoints*/
			true /*isHidden*/)

		updateProfile(
			1,             /*feeRateNanosPerKB*/
			m2Pub,         /*updaterPkBase58Check*/
			m2Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// A normal user updating their profile should succeed.
	{
		updateProfile(
			1,                  /*feeRateNanosPerKB*/
			m1Pub,              /*updaterPkBase58Check*/
			m1Priv,             /*updaterPrivBase58Check*/
			[]byte{},           /*profilePubKey*/
			"m1_updated_by_m1", /*newUsername*/
			"m1 updated by m1", /*newDescription*/
			otherShortPic,      /*newProfilePic*/
			12*100,             /*newCreatorBasisPoints*/
			1.6*100*100,        /*newStakeMultipleBasisPoints*/
			true /*isHidden*/)
	}

	// Normal user updating another user's profile should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,                /*feeRateNanosPerKB*/
			m1Pub,            /*updaterPkBase58Check*/
			m1Priv,           /*updaterPrivBase58Check*/
			m0PkBytes,        /*profilePubKey*/
			"m0_actually_m1", /*newUsername*/
			"i am the m1",    /*newDescription*/
			shortPic,         /*newProfilePic*/
			10*100,           /*newCreatorBasisPoints*/
			1.25*100*100,     /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfilePubKeyNotAuthorized)
	}

	// ParamUpdater updating another user's profile should succeed.
	{
		updateProfile(
			1,                            /*feeRateNanosPerKB*/
			m3Pub,                        /*updaterPkBase58Check*/
			m3Priv,                       /*updaterPrivBase58Check*/
			m0PkBytes,                    /*profilePubKey*/
			"m0_paramUpdater",            /*newUsername*/
			"m0 updated by paramUpdater", /*newDescription*/
			otherShortPic,                /*newProfilePic*/
			11*100,                       /*newCreatorBasisPoints*/
			1.5*100*100,                  /*newStakeMultipleBasisPoints*/
			true /*isHidden*/)
	}

	// ParamUpdater creating another user's profile should succeed.
	{
		updateProfile(
			1,                            /*feeRateNanosPerKB*/
			m3Pub,                        /*updaterPkBase58Check*/
			m3Priv,                       /*updaterPrivBase58Check*/
			m5PkBytes,                    /*profilePubKey*/
			"m5_paramUpdater",            /*newUsername*/
			"m5 created by paramUpdater", /*newDescription*/
			otherShortPic,                /*newProfilePic*/
			11*100,                       /*newCreatorBasisPoints*/
			1.5*100*100,                  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Create Profile Fee and Minimum Network Fee tests
	{
		// Set the create profile fee to 100 nanos
		updateGlobalParamsEntry(
			100,
			m3Pub,
			m3Priv,
			int64(InitialUSDCentsPerBitcoinExchangeRate),
			0,
			100)

		// m4 does not have enough to create a profile including fee
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,
			m4Pub,
			m4Priv,
			m4PkBytes,
			"m4_username",
			"m4 desc",
			shortPic,
			11*100,
			1.5*100*100,
			false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreateProfileTxnOutputExceedsInput)
		// Reduce the create profile fee, Set minimum network fee to 10 nanos per kb

		updateGlobalParamsEntry(
			100,
			m3Pub,
			m3Priv,
			int64(InitialUSDCentsPerBitcoinExchangeRate),
			5,
			1)

		// Update profile fails as the fee is too low
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,
			m4Pub,
			m4Priv,
			m4PkBytes,
			"m4_username",
			"m4 description",
			otherShortPic,
			11*100,
			1.5*100*100,
			false,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorTxnFeeBelowNetworkMinimum)
		// Update succeeds because fee is high enough and user has enough to meet fee.
		updateProfile(
			10,
			m4Pub,
			m4Priv,
			m4PkBytes,
			"m4",
			"m4 description",
			otherShortPic,
			11*100,
			1.5*100*100,
			false,
		)
		// Reset the create profile fee to 0 nanos (no fee) and set network minimum back to 0.
		updateGlobalParamsEntry(
			100,
			m3Pub,
			m3Priv,
			int64(InitialUSDCentsPerBitcoinExchangeRate),
			0,
			0)

	}

	// user0
	// m0Pub, m0_updated_by_paramUpdater, m0 updated by paramUpdater, otherShortPic, 11*100, 1.5*100*100, true
	// user1
	// m1Pub, m1_updated_by_m1, m1 updated by m1, otherShortPic, 12*100, 1.6*100*100, true
	// user2
	// m2Pub, m2, i am m2, 10*100, 1.25*100*100
	// user5
	// m5Pub, m5_paramUpdater, m5 created by paramUpdater, otherShortPic, 11*100, 1.5*100*100, false
	checkProfilesExist := func() {
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		profileEntriesByPublicKey, _, _, _, err := utxoView.GetAllProfiles(nil)
		require.NoError(err)
		// 3 profiles from seed txns
		require.Equal(8, len(profileEntriesByPublicKey))
		{
			m0Entry, m0Exists := profileEntriesByPublicKey[MakePkMapKey(m0PkBytes)]
			require.True(m0Exists)
			require.Equal(string(m0Entry.Username), "m0_paramUpdater")
			require.Equal(string(m0Entry.Description), "m0 updated by paramUpdater")
			require.Equal(string(m0Entry.ProfilePic), otherShortPic)
			require.Equal(int64(m0Entry.CreatorBasisPoints), int64(11*100))
			require.True(m0Entry.IsHidden)
		}
		{
			m1Entry, m1Exists := profileEntriesByPublicKey[MakePkMapKey(m1PkBytes)]
			require.True(m1Exists)
			require.Equal(string(m1Entry.Username), "m1_updated_by_m1")
			require.Equal(string(m1Entry.Description), "m1 updated by m1")
			require.Equal(string(m1Entry.ProfilePic), otherShortPic)
			require.Equal(int64(m1Entry.CreatorBasisPoints), int64(12*100))
			require.True(m1Entry.IsHidden)
		}
		{
			m2Entry, m2Exists := profileEntriesByPublicKey[MakePkMapKey(m2PkBytes)]
			require.True(m2Exists)
			require.Equal(string(m2Entry.Username), "m2")
			require.Equal(string(m2Entry.Description), "i am the m2")
			require.Equal(string(m2Entry.ProfilePic), shortPic)
			require.Equal(int64(m2Entry.CreatorBasisPoints), int64(10*100))
			require.False(m2Entry.IsHidden)
		}
		{
			m4Entry, m4Exists := profileEntriesByPublicKey[MakePkMapKey(m4PkBytes)]
			require.True(m4Exists)
			require.Equal(string(m4Entry.Username), "m4")
			require.Equal(string(m4Entry.Description), "m4 description")
			require.Equal(string(m4Entry.ProfilePic), otherShortPic)
			require.Equal(int64(m4Entry.CreatorBasisPoints), int64(11*100))
			require.False(m4Entry.IsHidden)
		}
		{
			m5Entry, m5Exists := profileEntriesByPublicKey[MakePkMapKey(m5PkBytes)]
			require.True(m5Exists)
			require.Equal(string(m5Entry.Username), "m5_paramUpdater")
			require.Equal(string(m5Entry.Description), "m5 created by paramUpdater")
			require.Equal(string(m5Entry.ProfilePic), otherShortPic)
			require.Equal(int64(m5Entry.CreatorBasisPoints), int64(11*100))
			require.False(m5Entry.IsHidden)
		}
	}
	checkProfilesExist()

	checkProfilesDeleted := func() {
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		profileEntriesByPublicKey, _, _, _, err := utxoView.GetAllProfiles(nil)
		require.NoError(err)
		// 3 remain because of the seed txns
		require.Equal(3, len(profileEntriesByPublicKey))
	}

	// ===================================================================================
	// Finish it off with some transactions
	// ===================================================================================
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]
		fmt.Printf("Disconnecting transaction with type %v index %d (going backwards)\n", currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, PkToStringTestnet(currentTxn.PublicKey)))
	}

	// Verify that all the profiles have been deleted.
	checkProfilesDeleted()

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(
			t, chain, mempool, PkToStringTestnet(tx.PublicKey)))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(err)
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb())

	// Verify the profiles exist.
	checkProfilesExist()

	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)
	}
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))

	// Verify that all the profiles have been deleted.
	checkProfilesDeleted()

	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it.
	block, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(txnOps)+1, len(block.Txns))

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(block, txHashes, utxoOps))

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// Verify that all the profiles have been deleted.
	checkProfilesDeleted()
}

func TestSpamUpdateProfile(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	f, err := os.Create("/tmp/perf")
	if err != nil {
		log.Fatal(err)
	}
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	chain, params, _ := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	numTxns := 250
	for ii := 0; ii < numTxns; ii++ {
		fmt.Println("Creating txns: ", ii)
		startTimeCreateTxn := time.Now()
		moneyPkBytes, _, _ := Base58CheckDecode(moneyPkString)
		txn, _, _, _, err := chain.CreateUpdateProfileTxn(
			moneyPkBytes,
			nil,
			"money",
			fmt.Sprintf("this is a new description: %v", ii),
			"profile pic",
			5000,  /*CreatorBasisPoints*/
			12500, /*StakeMultiple*/
			false, /*isHidden*/
			0,
			feeRateNanosPerKB, /*feeRateNanosPerKB*/
			mempool,           /*mempool*/
			[]*DeSoOutput{})
		require.NoError(err)
		_signTxn(t, txn, moneyPrivString)
		fmt.Printf("Creating txn took: %v seconds\n", time.Since(startTimeCreateTxn).Seconds())

		fmt.Println("Running txns through mempool: ", ii)
		startTimeMempoolAdd := time.Now()
		mempoolTxsAdded, err := mempool.processTransaction(
			txn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
			true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxsAdded))
		fmt.Printf("Adding to mempool took: %v seconds\n", time.Since(startTimeMempoolAdd).Seconds())
	}
}

func TestUpdateProfileChangeBack(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// This test fails non-deterministically so we wrap it in a loop to make it
	// not flake.
	for ii := 0; ii < 10; ii++ {
		chain, params, db := NewLowDifficultyBlockchain()
		mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
		// Make m3 a paramUpdater for this test
		params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true

		// Mine a few blocks to give the senderPkString some money.
		_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)

		_, _, _ = _doBasicTransferWithViewFlush(
			t, chain, db, params, moneyPkString, m0Pub,
			moneyPrivString, 10000 /*amount to send*/, 11 /*feerate*/)
		_, _, _ = _doBasicTransferWithViewFlush(
			t, chain, db, params, moneyPkString, m1Pub,
			moneyPrivString, 10000 /*amount to send*/, 11 /*feerate*/)
		_, _, _ = _doBasicTransferWithViewFlush(
			t, chain, db, params, moneyPkString, m2Pub,
			moneyPrivString, 10000 /*amount to send*/, 11 /*feerate*/)
		_, _, _ = _doBasicTransferWithViewFlush(
			t, chain, db, params, moneyPkString, m3Pub,
			moneyPrivString, 10000 /*amount to send*/, 11 /*feerate*/)

		// m0 takes m0
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m0PkBytes,
				m0PkBytes,
				"m0",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m0Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m1PkBytes,
				m1PkBytes,
				"m1",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m1Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
		// Write to db
		block, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		// one for the block reward, two for the new profiles
		require.Equal(1+2, len(block.Txns))

		// m1 takes m2
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m1PkBytes,
				m1PkBytes,
				"m2",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m1Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
		// m0 takes m1
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m0PkBytes,
				m0PkBytes,
				"m1",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m0Priv)
			require.NoError(err)

			// This ensure that the read-only version of the utxoView accurately reflects the current set of profile names taken.
			utxoViewCopy, err := mempool.universalUtxoView.CopyUtxoView()
			require.NoError(err)
			txnSize := getTxnSize(*txn)
			_, _, _, _, err = utxoViewCopy.ConnectTransaction(txn, txn.Hash(), txnSize, chain.blockTip().Height+1, false, false)
			require.NoError(err)

			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
		// m1 takes m0
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m1PkBytes,
				m1PkBytes,
				"m0",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m1Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
		// Write to db
		block, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		// one for the block reward, three for the new txns
		require.Equal(1+3, len(block.Txns))

		// m2 takes m0 should fail
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m2PkBytes,
				m2PkBytes,
				"m0",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m2Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.Error(err)
			require.Equal(0, len(mempoolTxsAdded))
		}
		// m3 takes m0 should fail
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m3PkBytes,
				m3PkBytes,
				"m0",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m3Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.Error(err)
			require.Equal(0, len(mempoolTxsAdded))
		}
	}
}
