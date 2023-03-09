package lib

import (
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

type _CreatorCoinTestData struct {
	// These are the transaction params
	UpdaterPublicKeyBase58Check  string
	UpdaterPrivateKeyBase58Check string
	ProfilePublicKeyBase58Check  string
	OperationType                CreatorCoinOperationType
	DeSoToSellNanos              uint64
	CreatorCoinToSellNanos       uint64
	DeSoToAddNanos               uint64
	MinDeSoExpectedNanos         uint64
	MinCreatorCoinExpectedNanos  uint64

	// The Diamond info
	DiamondPostHashIndex int
	DiamondLevel         int64

	// SubmitPost info
	SubmitPostBody string
	PostIsHidden   bool
	// We save all post hashes of posts that are created into
	// an array ordered by the time when they were created. To
	// reference a previous post, one just needs to set these
	// indexes to the index of the post in this array.
	PostHashToModifyIndex int
	ParentPostHashIndex   int

	// For creator coin transfers.
	CreatorCoinToTransferNanos   uint64
	ReceiverPublicKeyBase58Check string

	// The type of txn we're having the helper execute. When unset, this defaults to
	// a CreatorCoin transaction to avoid having to change existing code.
	TxnType TxnType

	// Extra fields for UpdateProfile txns
	ProfileUsername           string
	ProfileDescription        string
	ProfilePic                string
	ProfileCreatorBasisPoints uint64
	ProfileIsHidden           bool

	// Extra fields for SwapIdentity
	FromPublicKey []byte
	ToPublicKey   []byte

	// Extra fields for Follow
	FollowedPublicKey []byte
	IsUnfollow        bool

	// When set, the checks are skipped
	SkipChecks bool

	// These are the expectations (skipped when SkipChecks is set)
	CoinsInCirculationNanos uint64
	DeSoLockedNanos         uint64
	CoinWatermarkNanos      uint64
	m0CCBalance             uint64
	m1CCBalance             uint64
	m2CCBalance             uint64
	m3CCBalance             uint64
	m4CCBalance             uint64
	m5CCBalance             uint64
	m6CCBalance             uint64
	m0DeSoBalance           uint64
	m1DeSoBalance           uint64
	m2DeSoBalance           uint64
	m3DeSoBalance           uint64
	m4DeSoBalance           uint64
	m5DeSoBalance           uint64
	m6DeSoBalance           uint64
	m0HasPurchased          bool
	m1HasPurchased          bool
	m2HasPurchased          bool
	m3HasPurchased          bool
	m4HasPurchased          bool
	m5HasPurchased          bool
	m6HasPurchased          bool

	// These fields allow us to fetch and check profile data during validation.
	ProfilesToCheckPublicKeysBase58Check []string
	ProfilesToCheckUsernames             []string
	ProfilesToCheckDescriptions          []string
	ProfilesToCheckProfilePic            []string

	// These fields allow us to check follows
	FollowPublicKeysToCheck           []string
	FollowPublicKeysUserIsFollowing   []map[string]bool
	FollowPublicKeysFollowingThisUser []map[string]bool
}

// Sets up a test harness for running and checking various permutations
// of buy/sell transactions on creator coins. m0 is the creator coin being
// traded and m1 and m2 are other users.
func _helpTestCreatorCoinBuySell(
	t *testing.T,
	creatorCoinTests []*_CreatorCoinTestData,
	desoFounderReward bool) {

	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	// Create a paramUpdater for this test
	params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// These are block heights where deso forked.
	params.ForkHeights.SalomonFixBlockHeight = 0
	params.ForkHeights.BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight = 0
	params.ForkHeights.DeSoFounderRewardBlockHeight = 0
	if !desoFounderReward {
		params.ForkHeights.DeSoFounderRewardBlockHeight = 1e9
	}

	// Give paramUpdater some mony
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, paramUpdaterPub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Send money to people from moneyPk
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m0Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m1Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m2Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m3Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m4Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m5Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m6Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	m0StartNanos := _getBalance(t, chain, nil, m0Pub)
	m1StartNanos := _getBalance(t, chain, nil, m1Pub)
	m2StartNanos := _getBalance(t, chain, nil, m2Pub)
	m3StartNanos := _getBalance(t, chain, nil, m3Pub)
	m4StartNanos := _getBalance(t, chain, nil, m4Pub)
	m5StartNanos := _getBalance(t, chain, nil, m5Pub)
	m6StartNanos := _getBalance(t, chain, nil, m6Pub)

	testUtxoOps := [][]*UtxoOperation{}
	testTxns := []*MsgDeSoTxn{}
	_checkTestData := func(
		testData *_CreatorCoinTestData, message string, utxoView *UtxoView, mempool *DeSoMempool) {

		// If we were instructed to skip these checks then skip them.
		if testData.SkipChecks {
			return
		}

		// If a mempool object is provided then just check balances and return
		if mempool != nil {
			// DeSo balances
			if _getBalance(t, chain, mempool, m0Pub) != 6*NanosPerUnit && testData.m0DeSoBalance != 0 {
				assert.Equalf(int64(testData.m0DeSoBalance),
					int64(_getBalance(t, chain, mempool, m0Pub)), "MempoolIncrementalBalanceCheck: m0 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m1Pub) != 6*NanosPerUnit && testData.m1DeSoBalance != 0 {
				assert.Equalf(int64(testData.m1DeSoBalance),
					int64(_getBalance(t, chain, mempool, m1Pub)), "MempoolIncrementalBalanceCheck: m1 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m2Pub) != 6*NanosPerUnit && testData.m2DeSoBalance != 0 {
				assert.Equalf(int64(testData.m2DeSoBalance),
					int64(_getBalance(t, chain, mempool, m2Pub)), "MempoolIncrementalBalanceCheck: m2 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m3Pub) != 6*NanosPerUnit && testData.m3DeSoBalance != 0 {
				assert.Equalf(int64(testData.m3DeSoBalance),
					int64(_getBalance(t, chain, mempool, m3Pub)), "MempoolIncrementalBalanceCheck: m3 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m4Pub) != 6*NanosPerUnit && testData.m4DeSoBalance != 0 {
				assert.Equalf(int64(testData.m4DeSoBalance),
					int64(_getBalance(t, chain, mempool, m4Pub)), "MempoolIncrementalBalanceCheck: m4 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m5Pub) != 6*NanosPerUnit && testData.m5DeSoBalance != 0 {
				assert.Equalf(int64(testData.m5DeSoBalance),
					int64(_getBalance(t, chain, mempool, m5Pub)), "MempoolIncrementalBalanceCheck: m5 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m6Pub) != 6*NanosPerUnit && testData.m6DeSoBalance != 0 {
				assert.Equalf(int64(testData.m6DeSoBalance),
					int64(_getBalance(t, chain, mempool, m6Pub)), "MempoolIncrementalBalanceCheck: m6 DeSo balance: %v", message)
			}

			return
		}

		// If no UtxoView is passed, use a new one to run our checks.
		if utxoView == nil {
			var err error
			utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
			require.NoError(err)
		}

		// Profile fields
		creatorPkBytes, _, _ := Base58CheckDecode(testData.ProfilePublicKeyBase58Check)
		creatorProfile := utxoView.GetProfileEntryForPublicKey(creatorPkBytes)
		require.NotNil(creatorProfile)

		assert.Equalf(int64(testData.CoinsInCirculationNanos),
			int64(creatorProfile.CreatorCoinEntry.CoinsInCirculationNanos.Uint64()), "CoinsInCirculationNanos: %v", message)
		assert.Equalf(int64(testData.DeSoLockedNanos),
			int64(creatorProfile.CreatorCoinEntry.DeSoLockedNanos), "DeSoLockedNanos: %v", message)
		assert.Equalf(int64(testData.CoinWatermarkNanos),
			int64(creatorProfile.CreatorCoinEntry.CoinWatermarkNanos), "CoinWatermarkNanos: %v", message)

		// Coin balances, also used for figuring out how many holders hold a creator.
		// m0
		actualNumberOfHolders := uint64(0)
		m0BalanceEntry, _, _ := utxoView.GetCreatorCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, creatorPkBytes)
		if m0BalanceEntry != nil && !m0BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m0CCBalance),
				int64(m0BalanceEntry.BalanceNanos.Uint64()), "m0CCBalance: %v", message)
			if m0BalanceEntry.BalanceNanos.Uint64() > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m0HasPurchased, m0BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m0CCBalance),
				int64(0), "m0CCBalance: %v", message)
			assert.Equal(testData.m0HasPurchased, false)
		}
		// m1
		m1BalanceEntry, _, _ := utxoView.GetCreatorCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m1PkBytes, creatorPkBytes)
		if m1BalanceEntry != nil && !m1BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m1CCBalance),
				int64(m1BalanceEntry.BalanceNanos.Uint64()), "m1CCBalance: %v", message)
			if m1BalanceEntry.BalanceNanos.Uint64() > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m1HasPurchased, m1BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m1CCBalance),
				int64(0), "m1CCBalance: %v", message)
			assert.Equal(testData.m1HasPurchased, false)
		}
		// m2
		m2BalanceEntry, _, _ := utxoView.GetCreatorCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m2PkBytes, creatorPkBytes)
		if m2BalanceEntry != nil && !m2BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m2CCBalance),
				int64(m2BalanceEntry.BalanceNanos.Uint64()), "%v", message)
			if m2BalanceEntry.BalanceNanos.Uint64() > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m2HasPurchased, m2BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m2CCBalance),
				int64(0), "m2CCBalance: %v", message)
			assert.Equal(testData.m2HasPurchased, false)
		}
		// m3
		m3BalanceEntry, _, _ := utxoView.GetCreatorCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m3PkBytes, creatorPkBytes)
		if m3BalanceEntry != nil && !m3BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m3CCBalance),
				int64(m3BalanceEntry.BalanceNanos.Uint64()), "%v", message)
			if m3BalanceEntry.BalanceNanos.Uint64() > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m3HasPurchased, m3BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m3CCBalance),
				int64(0), "m3CCBalance: %v", message)
			assert.Equal(testData.m3HasPurchased, false)
		}
		// m4
		m4BalanceEntry, _, _ := utxoView.GetCreatorCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m4PkBytes, creatorPkBytes)
		if m4BalanceEntry != nil && !m4BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m4CCBalance),
				int64(m4BalanceEntry.BalanceNanos.Uint64()), "%v", message)
			if m4BalanceEntry.BalanceNanos.Uint64() > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m4HasPurchased, m4BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m4CCBalance),
				int64(0), "m4CCBalance: %v", message)
			assert.Equal(testData.m4HasPurchased, false)
		}
		// m5
		m5BalanceEntry, _, _ := utxoView.GetCreatorCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m5PkBytes, creatorPkBytes)
		if m5BalanceEntry != nil && !m5BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m5CCBalance),
				int64(m5BalanceEntry.BalanceNanos.Uint64()), "%v", message)
			if m5BalanceEntry.BalanceNanos.Uint64() > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m5HasPurchased, m5BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m5CCBalance),
				int64(0), "m5CCBalance: %v", message)
			assert.Equal(testData.m5HasPurchased, false)
		}
		// m6
		m6BalanceEntry, _, _ := utxoView.GetCreatorCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m6PkBytes, creatorPkBytes)
		if m6BalanceEntry != nil && !m6BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m6CCBalance),
				int64(m6BalanceEntry.BalanceNanos.Uint64()), "%v", message)
			if m6BalanceEntry.BalanceNanos.Uint64() > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m6HasPurchased, m6BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m6CCBalance),
				int64(0), "m6CCBalance: %v", message)
			assert.Equal(testData.m6HasPurchased, false)
		}

		// creatorNumberOfHolders must equal creatorProfile.NumberOfHolders
		assert.Equalf(actualNumberOfHolders, creatorProfile.CreatorCoinEntry.NumberOfHolders,
			"Actual number of creators != creatorProfile.NumberOfHolders: %v", message)

		// Coins in m0+m1+m2+m3+m4+m5+m6 must equal the circulating supply
		assert.Equalf(
			int64(testData.m0CCBalance+testData.m1CCBalance+testData.m2CCBalance+testData.m3CCBalance+
				testData.m4CCBalance+testData.m5CCBalance+testData.m6CCBalance),
			int64(creatorProfile.CreatorCoinEntry.CoinsInCirculationNanos.Uint64()),
			"m0+m1+m2+m3+m4+m5+m6 != CoinsInCirculationNanos: %v", message)

		// DeSo balances
		if _getBalanceWithView(t, utxoView, m0Pub) != 6*NanosPerUnit && testData.m0DeSoBalance != 0 {
			assert.Equalf(int64(testData.m0DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m0Pub)), "m0 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m1Pub) != 6*NanosPerUnit && testData.m1DeSoBalance != 0 {
			assert.Equalf(int64(testData.m1DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m1Pub)), "m1 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m2Pub) != 6*NanosPerUnit && testData.m2DeSoBalance != 0 {
			assert.Equalf(int64(testData.m2DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m2Pub)), "m2 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m3Pub) != 6*NanosPerUnit && testData.m3DeSoBalance != 0 {
			assert.Equalf(int64(testData.m3DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m3Pub)), "m3 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m4Pub) != 6*NanosPerUnit && testData.m4DeSoBalance != 0 {
			assert.Equalf(int64(testData.m4DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m4Pub)), "m4 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m5Pub) != 6*NanosPerUnit && testData.m5DeSoBalance != 0 {
			assert.Equalf(int64(testData.m5DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m5Pub)), "m5 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m6Pub) != 6*NanosPerUnit && testData.m6DeSoBalance != 0 {
			assert.Equalf(int64(testData.m6DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m6Pub)), "m6 DeSo balance: %v", message)
		}

		for ii, profilePubStr := range testData.ProfilesToCheckPublicKeysBase58Check {
			// Look up the profile for the public key.
			profilePkBytes, _, _ := Base58CheckDecode(profilePubStr)
			profileEntry := utxoView.GetProfileEntryForPublicKey(profilePkBytes)
			if testData.ProfilesToCheckUsernames[ii] == "" {
				if profileEntry != nil && !profileEntry.isDeleted {
					require.Fail("Profile for pub key %v should not exist but does: index %v: %v", profilePubStr, ii, message)
				}
				continue
			} else {
				require.NotNil(profileEntry, "Profile for pub key %v does not exist: index %v: %v", profilePubStr, ii, message)
			}
			require.Equalf(profilePkBytes, profileEntry.PublicKey, "Profile public keys don't match: index %v: %v", ii, message)
			require.Equalf(string(profileEntry.Username), testData.ProfilesToCheckUsernames[ii], "Profile usernames don't match: index %v: %v", ii, message)
			require.Equalf(string(profileEntry.Description), testData.ProfilesToCheckDescriptions[ii], "Profile descripptions don't match: index %v: %v", ii, message)
			require.Equalf(string(profileEntry.ProfilePic), testData.ProfilesToCheckProfilePic[ii], "Profile profile pics don't match: index %v: %v", ii, message)
		}

		for ii, userPubStr := range testData.FollowPublicKeysToCheck {
			// Look up the profile for the public key.
			userPkBytes, _, _ := Base58CheckDecode(userPubStr)

			userIsFollowing := testData.FollowPublicKeysUserIsFollowing[ii]
			followingUser := testData.FollowPublicKeysFollowingThisUser[ii]

			// Look up the public keys that are following this user.
			{
				followEntries, err := utxoView.GetFollowEntriesForPublicKey(
					userPkBytes, true /*followingPublicKey*/)
				require.NoError(err)

				require.Equal(len(followEntries), len(followingUser))

				for _, followEntry := range followEntries {
					followPk := utxoView.GetPublicKeyForPKID(followEntry.FollowerPKID)
					if _, exists := followingUser[PkToString(followPk, params)]; !exists {
						require.Fail(fmt.Sprintf("Pub key %v should be following user %v but is not: %v %v",
							PkToString(followPk, params), userPubStr, ii, message))
					}
				}
			}
			// Look up the public keys this user is following
			{
				followEntries, err := utxoView.GetFollowEntriesForPublicKey(
					userPkBytes, false /*followingPublicKey*/)
				require.NoError(err)

				require.Equal(len(followEntries), len(userIsFollowing))

				for _, followEntry := range followEntries {
					followPk := utxoView.GetPublicKeyForPKID(followEntry.FollowedPKID)
					if _, exists := userIsFollowing[PkToString(followPk, params)]; !exists {
						require.Fail(fmt.Sprintf("Pub key %v should be in the users this one is following %v but is not: %v %v",
							PkToString(followPk, params), userPubStr, ii, message))
					}
				}
			}
		}
	}

	postHashes := []*BlockHash{}
	for testIndex, testData := range creatorCoinTests {
		fmt.Printf("Applying test index: %v\n", testIndex)

		// If this is a profile swap, then execute that.
		var utxoOps []*UtxoOperation
		var txn *MsgDeSoTxn
		var err error
		if testData.TxnType == TxnTypeSwapIdentity {
			utxoOps, txn, _, err = _swapIdentity(
				t, chain, db, params, feeRateNanosPerKB,
				paramUpdaterPub,
				paramUpdaterPriv,
				testData.FromPublicKey, testData.ToPublicKey)
			require.NoError(err)
		} else if testData.TxnType == TxnTypeUpdateProfile {
			// Create a profile using the testData params
			profilePkBytes, _, _ := Base58CheckDecode(testData.ProfilePublicKeyBase58Check)
			utxoOps, txn, _, err = _updateProfile(
				t, chain, db, params,
				feeRateNanosPerKB /*feerate*/, testData.UpdaterPublicKeyBase58Check,
				testData.UpdaterPrivateKeyBase58Check, profilePkBytes, testData.ProfileUsername,
				testData.ProfileDescription, testData.ProfilePic,
				testData.ProfileCreatorBasisPoints, /*CreatorBasisPoints*/
				12500 /*stakeMultipleBasisPoints*/, testData.ProfileIsHidden /*isHidden*/)
			require.NoError(err)
		} else if testData.TxnType == TxnTypeFollow {
			utxoOps, txn, _, err = _doFollowTxn(
				t, chain, db, params, feeRateNanosPerKB /*feeRateNanosPerKB*/, testData.UpdaterPublicKeyBase58Check,
				PkToString(testData.FollowedPublicKey, params),
				testData.UpdaterPrivateKeyBase58Check, testData.IsUnfollow /*isUnfollow*/)
			require.NoError(err)
		} else if testData.TxnType == TxnTypeSubmitPost {

			var postHashToModify []byte
			if testData.PostHashToModifyIndex >= 0 {
				postHashToModify = postHashes[testData.PostHashToModifyIndex][:]
			}
			var parentPostHash []byte
			if testData.ParentPostHashIndex >= 0 {
				parentPostHash = postHashes[testData.ParentPostHashIndex][:]
			}

			utxoOps, txn, _, err = _doSubmitPostTxn(
				t, chain, db, params, feeRateNanosPerKB,
				testData.UpdaterPublicKeyBase58Check, testData.UpdaterPrivateKeyBase58Check,
				postHashToModify,
				parentPostHash,
				testData.SubmitPostBody,
				make(map[string][]byte),
				testData.PostIsHidden)
			require.NoError(err)

			// If this transaction was not modifying an existing post then
			// add its post hash to the list.
			if len(postHashToModify) == 0 {
				postHashes = append(postHashes, txn.Hash())
			}

		} else if testData.TxnType == TxnTypeCreatorCoinTransfer {
			var diamondPostHash *BlockHash
			if testData.DiamondLevel > 0 {
				diamondPostHash = postHashes[testData.DiamondPostHashIndex]
			}
			// If we have a DiamondPostHash then do a diamond txn
			if diamondPostHash != nil {
				utxoOps, txn, _, err = _doCreatorCoinTransferTxnWithDiamonds(
					t, chain, db, params, feeRateNanosPerKB,
					testData.UpdaterPublicKeyBase58Check, testData.UpdaterPrivateKeyBase58Check,
					testData.ReceiverPublicKeyBase58Check,
					diamondPostHash,
					testData.DiamondLevel)
				require.NoError(err)
			} else {
				// Apply the txn according to the test spec
				utxoOps, txn, _, err = _doCreatorCoinTransferTxn(
					t, chain, db, params, feeRateNanosPerKB,
					testData.UpdaterPublicKeyBase58Check, testData.UpdaterPrivateKeyBase58Check,
					testData.ProfilePublicKeyBase58Check,
					testData.ReceiverPublicKeyBase58Check,
					testData.CreatorCoinToTransferNanos)
				require.NoError(err)
			}

		} else {
			// When TxnType is 0 aka "unset," we assume we're doing a CreatorCoin txn.

			// Apply the txn according to the test spec
			utxoOps, txn, _, err = _creatorCoinTxn(
				t, chain, db, params, feeRateNanosPerKB,
				testData.UpdaterPublicKeyBase58Check, testData.UpdaterPrivateKeyBase58Check, /*updater*/
				testData.ProfilePublicKeyBase58Check, /*profile*/
				testData.OperationType,               /*buy/sell*/
				testData.DeSoToSellNanos,             /*DeSoToSellNanos*/
				testData.CreatorCoinToSellNanos,      /*CreatorCoinToSellNanos*/
				testData.DeSoToAddNanos,              /*DeSoToAddNanos*/
				testData.MinDeSoExpectedNanos,        /*MinDeSoExpectedNanos*/
				testData.MinCreatorCoinExpectedNanos /*MinCreatorCoinExpectedNanos*/)
			require.NoError(err)
		}

		// Append the txn we just created to our list
		testTxns = append(testTxns, txn)
		testUtxoOps = append(testUtxoOps, utxoOps)

		// Check the txn according to the test spec.
		_checkTestData(testData, fmt.Sprintf("SimpleConnect: Index: %v", testIndex), nil, nil)
	}

	// The sum of all the balances shouldn't exceed what we started with.
	assert.Less(
		int64(_getBalance(t, chain, nil, m0Pub)+_getBalance(t, chain, nil, m1Pub)+
			_getBalance(t, chain, nil, m2Pub)+_getBalance(t, chain, nil, m3Pub)+
			_getBalance(t, chain, nil, m4Pub)+_getBalance(t, chain, nil, m5Pub)+
			_getBalance(t, chain, nil, m6Pub)),
		int64(m0StartNanos+m1StartNanos+m2StartNanos+m3StartNanos+m4StartNanos+m5StartNanos+m6StartNanos))

	// Disconnect each txn and rerun the checks in the reverse direction
	for iterIndex := range creatorCoinTests {
		testIndex := len(creatorCoinTests) - 1 - iterIndex
		testData := creatorCoinTests[testIndex]
		currentTxn := testTxns[testIndex]
		currentUtxoOps := testUtxoOps[testIndex]

		// Check that the state lines up with the test data
		fmt.Printf("Running checks before disconnecting test index: %v\n", testIndex)
		_checkTestData(testData, fmt.Sprintf("SimpleDisconnect: Index: %v", testIndex), nil, nil)

		// Disconnect the transaction
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		blockHeight := chain.blockTip().Height + 1
		fmt.Printf("Disconnecting test index: %v\n", testIndex)
		require.NoError(utxoView.DisconnectTransaction(
			currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
		fmt.Printf("Disconnected test index: %v\n", testIndex)
		require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
	}

	// Verify the DeSo balances are back to where they started after disconnecting all the txns.
	assert.Equalf(int64(m0StartNanos),
		int64(_getBalance(t, chain, nil, m0Pub)), "m0 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m1StartNanos),
		int64(_getBalance(t, chain, nil, m1Pub)), "m1 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m2StartNanos),
		int64(_getBalance(t, chain, nil, m2Pub)), "m2 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m3StartNanos),
		int64(_getBalance(t, chain, nil, m3Pub)), "m3 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m4StartNanos),
		int64(_getBalance(t, chain, nil, m4Pub)), "m4 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m5StartNanos),
		int64(_getBalance(t, chain, nil, m5Pub)), "m5 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m6StartNanos),
		int64(_getBalance(t, chain, nil, m6Pub)), "m6 DeSo balance after SimpleDisconnect is incorrect")

	// Connect all the txns to a single UtxoView without flushing
	{
		// Create a new UtxoView to check on the state of things
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		for testIndex, testData := range creatorCoinTests {
			fmt.Printf("Applying test index: %v\n", testIndex)
			txn := testTxns[testIndex]
			blockHeight := chain.blockTip().Height + 1
			txnSize := getTxnSize(*txn)
			_, _, _, _, err :=
				utxoView.ConnectTransaction(
					txn, txn.Hash(), txnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)
			_checkTestData(testData, fmt.Sprintf("SimpleConnect: Index: %v", testIndex), utxoView, nil)
		}

		// Now flush at the end.
		require.NoError(utxoView.FlushToDb(0))

		// Check that the state matches the final testData.
		testIndex := len(creatorCoinTests) - 1
		testData := creatorCoinTests[testIndex]
		_checkTestData(testData, fmt.Sprintf("OnebigFlush: %v", testIndex), nil, nil)
	}

	// Disconnect all the txns on a single view and flush at the end
	{
		// Create a new UtxoView to check on the state of things
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		blockHeight := chain.blockTip().Height + 1
		for iterIndex := range creatorCoinTests {
			testIndex := len(creatorCoinTests) - 1 - iterIndex
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			txn := testTxns[testIndex]
			require.NoError(utxoView.DisconnectTransaction(
				txn, txn.Hash(), testUtxoOps[testIndex], blockHeight))

			// Check that the testData lines up
			if testIndex > 0 {
				testData := creatorCoinTests[testIndex-1]
				_checkTestData(testData, fmt.Sprintf("OneBigFlush: %v", testIndex), utxoView, nil)
			}
		}

		// Now flush at the end.
		require.NoError(utxoView.FlushToDb(0))

		// Verify the DeSo balances are back to where they started after disconnecting all the txns.
		assert.Equalf(int64(m0StartNanos),
			int64(_getBalance(t, chain, nil, m0Pub)), "m0 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m1StartNanos),
			int64(_getBalance(t, chain, nil, m1Pub)), "m1 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m2StartNanos),
			int64(_getBalance(t, chain, nil, m2Pub)), "m2 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m3StartNanos),
			int64(_getBalance(t, chain, nil, m3Pub)), "m3 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m4StartNanos),
			int64(_getBalance(t, chain, nil, m4Pub)), "m4 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m5StartNanos),
			int64(_getBalance(t, chain, nil, m5Pub)), "m5 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m6StartNanos),
			int64(_getBalance(t, chain, nil, m6Pub)), "m6 DeSo balance after BatchDisconnect is incorrect")
	}

	// Running all the transactions through the mempool should work and result
	// in all of them being added.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))

			// This will check the balances according to the mempool
			_checkTestData(creatorCoinTests[ii], fmt.Sprintf("MempoolIncrementalBalances: %v", ii), nil, mempool)
		}
	}

	// Remove all the transactions from the mempool.
	for _, burnTxn := range testTxns {
		mempool.inefficientRemoveTransaction(burnTxn)
	}

	// The balances should be reset after removing transactions from the mempool.
	assert.Equalf(int64(m0StartNanos),
		int64(_getBalance(t, chain, nil, m0Pub)), "m0 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m1StartNanos),
		int64(_getBalance(t, chain, nil, m1Pub)), "m1 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m2StartNanos),
		int64(_getBalance(t, chain, nil, m2Pub)), "m2 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m3StartNanos),
		int64(_getBalance(t, chain, nil, m3Pub)), "m3 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m4StartNanos),
		int64(_getBalance(t, chain, nil, m4Pub)), "m4 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m5StartNanos),
		int64(_getBalance(t, chain, nil, m5Pub)), "m5 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m6StartNanos),
		int64(_getBalance(t, chain, nil, m6Pub)), "m6 DeSo balance after BatchDisconnect is incorrect")

	// Re-add all of the transactions to the mempool so we can mine them into a block.
	{
		for _, burnTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				burnTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
	}

	// Mine a block with all the mempool transactions.
	//
	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it. Note we need to mine two blocks since the first
	// one just makes the DeSo chain time-current.
	finalBlock1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_ = finalBlock1
	finalBlock2, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	require.Equal(0, len(mempool.poolMap))

	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(finalBlock1.Txns), 1)
	require.Equal(len(finalBlock2.Txns), len(creatorCoinTests)+1)

	// The balances after mining the block should match the last testData
	{
		// Check that the state matches the final testData.
		testIndex := len(creatorCoinTests) - 1
		testData := creatorCoinTests[testIndex]
		// DeSo balances
		if _getBalance(t, chain, nil, m0Pub) != 6*NanosPerUnit && testData.m0DeSoBalance != 0 {
			assert.Equalf(int64(testData.m0DeSoBalance),
				int64(_getBalance(t, chain, nil, m0Pub)), "BlockConnect: m0 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m1Pub) != 6*NanosPerUnit && testData.m1DeSoBalance != 0 {
			assert.Equalf(int64(testData.m1DeSoBalance),
				int64(_getBalance(t, chain, nil, m1Pub)), "BlockConnect: m1 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m2Pub) != 6*NanosPerUnit && testData.m2DeSoBalance != 0 {
			assert.Equalf(int64(testData.m2DeSoBalance),
				int64(_getBalance(t, chain, nil, m2Pub)), "BlockConnect: m2 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m3Pub) != 6*NanosPerUnit && testData.m3DeSoBalance != 0 {
			assert.Equalf(int64(testData.m3DeSoBalance),
				int64(_getBalance(t, chain, nil, m3Pub)), "BlockConnect: m3 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m4Pub) != 6*NanosPerUnit && testData.m4DeSoBalance != 0 {
			assert.Equalf(int64(testData.m4DeSoBalance),
				int64(_getBalance(t, chain, nil, m4Pub)), "BlockConnect: m4 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m5Pub) != 6*NanosPerUnit && testData.m5DeSoBalance != 0 {
			assert.Equalf(int64(testData.m5DeSoBalance),
				int64(_getBalance(t, chain, nil, m5Pub)), "BlockConnect: m5 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m6Pub) != 6*NanosPerUnit && testData.m5DeSoBalance != 0 {
			assert.Equalf(int64(testData.m6DeSoBalance),
				int64(_getBalance(t, chain, nil, m6Pub)), "BlockConnect: m6 DeSo balance: %v", testIndex)
		}

	}

	// Roll back the blocks and make sure we don't hit any errors.
	disconnectSingleBlock := func(blockToDisconnect *MsgDeSoBlock, utxoView *UtxoView) {
		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := blockToDisconnect.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(blockToDisconnect.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(blockToDisconnect, txHashes, utxoOps, 0))
	}
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		disconnectSingleBlock(finalBlock2, utxoView)
		disconnectSingleBlock(finalBlock1, utxoView)

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb(0))
	}

	// The DeSo balances should line up with what they were initially after
	// disconnecting the blocks.
	assert.Equalf(int64(m0StartNanos),
		int64(_getBalance(t, chain, nil, m0Pub)), "m0 DeSo balance after BlockDisconnect is incorrect")
	assert.Equalf(int64(m1StartNanos),
		int64(_getBalance(t, chain, nil, m1Pub)), "m1 DeSo balance after BlockDisconnect is incorrect")
	assert.Equalf(int64(m2StartNanos),
		int64(_getBalance(t, chain, nil, m2Pub)), "m2 DeSo balance after BlockDisconnect is incorrect")
	assert.Equalf(int64(m3StartNanos),
		int64(_getBalance(t, chain, nil, m3Pub)), "m3 DeSo balance after BlockDisconnect is incorrect")
	assert.Equalf(int64(m5StartNanos),
		int64(_getBalance(t, chain, nil, m5Pub)), "m5 DeSo balance after BlockDisconnect is incorrect")
	assert.Equalf(int64(m6StartNanos),
		int64(_getBalance(t, chain, nil, m6Pub)), "m6 DeSo balance after BlockDisconnect is incorrect")
}

func TestCreatorCoinWithDiamonds(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m0 buy some of their own coin
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10832150315,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           4728876540,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Create a post for m0
		{
			TxnType:                      TxnTypeSubmitPost,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,

			PostHashToModifyIndex: -1,
			ParentPostHashIndex:   -1,
			SubmitPostBody:        "this is a post for m0",
			PostIsHidden:          false,

			SkipChecks: true,
		},
		// Create a post from m1 that is a comment on m0
		{
			TxnType:                      TxnTypeSubmitPost,
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			PostHashToModifyIndex:        -1,
			ParentPostHashIndex:          0,
			SubmitPostBody:               "this is a comment for m1",
			PostIsHidden:                 false,

			SkipChecks: true,
		},
		// Create a post from m2 that is a comment on m0
		{
			TxnType:                      TxnTypeSubmitPost,
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			PostHashToModifyIndex:        -1,
			ParentPostHashIndex:          0,
			SubmitPostBody:               "this is a comment for m2",
			PostIsHidden:                 false,

			SkipChecks: true,
		},
		// Have m0 throw a diamond on m1's comment
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ReceiverPublicKeyBase58Check: m1Pub,
			ProfilePublicKeyBase58Check:  m0Pub,
			// This field is ignored when giving a diamond. It's computed
			// by the functions called.
			CreatorCoinToTransferNanos: 0,
			DiamondPostHashIndex:       1,
			DiamondLevel:               3,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10817255342,
			m0HasPurchased:          true,
			m1CCBalance:             14894973,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           4728876535,
			m1DeSoBalance:           5999999998,
			m2DeSoBalance:           5999999998,
		},
		// m0 upgrading the diamond level should work
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ReceiverPublicKeyBase58Check: m1Pub,
			ProfilePublicKeyBase58Check:  m0Pub,
			// This field is ignored when giving a diamond. It's computed
			// by the functions called.
			CreatorCoinToTransferNanos: 0,
			DiamondPostHashIndex:       1,
			DiamondLevel:               4,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10684919520,
			m0HasPurchased:          true,
			m1CCBalance:             147230795,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           4728876532,
			m1DeSoBalance:           5999999998,
			m2DeSoBalance:           5999999998,
		},
		// m0 giving diamond level 4 to m2 should result in the same
		// CC balance for m2 as m1 has
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ReceiverPublicKeyBase58Check: m2Pub,
			ProfilePublicKeyBase58Check:  m0Pub,
			// This field is ignored when giving a diamond. It's computed
			// by the functions called.
			CreatorCoinToTransferNanos: 0,
			DiamondPostHashIndex:       2,
			DiamondLevel:               4,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10537688724,
			m0HasPurchased:          true,
			m1CCBalance:             147230795,
			m1HasPurchased:          false,
			m2CCBalance:             147230796,
			m2HasPurchased:          false,
			m0DeSoBalance:           4728876529,
			m1DeSoBalance:           5999999998,
			m2DeSoBalance:           5999999998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinWithDiamondsFailureCases(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	// Create a paramUpdater for this test
	params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// Give paramUpdater some mony
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, paramUpdaterPub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Send money to people from moneyPk
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m0Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m1Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m2Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Create a post for m0
	_, postTxn, _, err := _doSubmitPostTxn(
		t, chain, db, params, feeRateNanosPerKB,
		m0Pub, m0Priv,
		nil,
		nil,
		"a post from m0",
		make(map[string][]byte),
		false)
	require.NoError(err)

	// Create a profile for m0
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB /*feerate*/, m0Pub,
			m0Priv, nil, "m0",
			"m0 profile", "",
			2500, /*CreatorBasisPoints*/
			12500 /*stakeMultipleBasisPoints*/, false /*isHidden*/)
		require.NoError(err)
	}
	// Create a profile for m1
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB /*feerate*/, m1Pub,
			m1Priv, nil, "m1",
			"m1 profile", "",
			2500, /*CreatorBasisPoints*/
			12500 /*stakeMultipleBasisPoints*/, false /*isHidden*/)
		require.NoError(err)
	}

	// Have m0 buy some of their own coin
	{
		_, _, _, err = _creatorCoinTxn(
			t, chain, db, params, feeRateNanosPerKB,
			m0Pub, m0Priv, /*updater*/
			m0Pub,                       /*profile*/
			CreatorCoinOperationTypeBuy, /*buy/sell*/
			1000000000,                  /*DeSoToSellNanos*/
			0,                           /*CreatorCoinToSellNanos*/
			0,                           /*DeSoToAddNanos*/
			0,                           /*MinDeSoExpectedNanos*/
			0 /*MinCreatorCoinExpectedNanos*/)
		require.NoError(err)
	}
	// Have m0 buy some m1 as well
	{
		_, _, _, err = _creatorCoinTxn(
			t, chain, db, params, feeRateNanosPerKB,
			m0Pub, m0Priv, /*updater*/
			m1Pub,                       /*profile*/
			CreatorCoinOperationTypeBuy, /*buy/sell*/
			1000000000,                  /*DeSoToSellNanos*/
			0,                           /*CreatorCoinToSellNanos*/
			0,                           /*DeSoToAddNanos*/
			0,                           /*MinDeSoExpectedNanos*/
			0 /*MinCreatorCoinExpectedNanos*/)
		require.NoError(err)
	}

	// Missing a DiamondLevel should fail
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		delete(txn.ExtraData, DiamondLevelKey)

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreatorCoinTransferHasDiamondPostHashWithoutDiamondLevel)
	}

	// An invalid DiamondLevel should fail
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		txn.ExtraData[DiamondLevelKey] = IntToBuf(15)

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), "level 15 not allowed")
	}
	// A DiamondLevel of zero should fail
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		txn.ExtraData[DiamondLevelKey] = IntToBuf(0)

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), "level 0 not allowed")
	}
	// You cannot give diamonds for profiles that are not your own.
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		txn.TxnMeta.(*CreatorCoinTransferMetadataa).ProfilePublicKey = receiverPkBytes

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreatorCoinTransferCantSendDiamondsForOtherProfiles)
	}
	// You can't Diamond yourself
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		txn.TxnMeta.(*CreatorCoinTransferMetadataa).ReceiverPublicKey = senderPkBytes

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCoinTransferCannotTransferToSelf)
	}
	// You can't Diamond off a post that doesn't exist
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		emptyHash := &BlockHash{}
		txn.ExtraData[DiamondPostHashKey] = emptyHash[:]

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreatorCoinTransferDiamondPostEntryDoesNotExist)
	}
	// If you don't have enough creator coins, you can't Diamond
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			receiverPkBytes,
			senderPkBytes,
			postTxn.Hash(),
			1,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		txn.ExtraData[DiamondLevelKey] = IntToBuf(7)

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m1Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreatorCoinTransferInsufficientCreatorCoinsForDiamondLevel)
	}
	// You can't apply the same number of Diamonds to a post twice
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		// Let's have a successful transaction
		{
			senderPkBytes, _, err := Base58CheckDecode(m0Pub)
			require.NoError(err)

			receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
			require.NoError(err)

			txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
				senderPkBytes,
				receiverPkBytes,
				postTxn.Hash(),
				3,
				feeRateNanosPerKB, nil, []*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m0Priv)

			txHash := txn.Hash()
			// Always use height+1 for validation since it's assumed the transaction will
			// get mined into the next block.
			blockHeight := chain.blockTip().Height + 1
			_, _, _, _, err =
				utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)
			_, err = mempool.processTransaction(txn, false, false, 0, false)
			require.NoError(err)
		}
		// Now do a transaction with the same number of Diamonds
		{
			senderPkBytes, _, err := Base58CheckDecode(m0Pub)
			require.NoError(err)

			receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
			require.NoError(err)

			txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
				senderPkBytes,
				receiverPkBytes,
				postTxn.Hash(),
				5,
				feeRateNanosPerKB, mempool, []*DeSoOutput{})
			require.NoError(err)

			txn.ExtraData[DiamondLevelKey] = IntToBuf(3)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m0Priv)

			txHash := txn.Hash()
			// Always use height+1 for validation since it's assumed the transaction will
			// get mined into the next block.
			blockHeight := chain.blockTip().Height + 1
			_, _, _, _, err =
				utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorCreatorCoinTransferPostAlreadyHasSufficientDiamonds)
		}
	}
}

func TestCreatorCoinDiamondAfterDeSoDiamondsBlockHeight(t *testing.T) {
	// Set up a blockchain.
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	// Create a paramUpdater for this test.
	params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// Set the DeSoDiamondsBlockHeight so that it is immediately hit.
	params.ForkHeights.DeSoDiamondsBlockHeight = uint32(0)

	// Give paramUpdater some mony.
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, paramUpdaterPub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Send money to people from moneyPk.
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m0Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m1Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m2Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Create a post for m0.
	_, postTxn, _, err := _doSubmitPostTxn(
		t, chain, db, params, feeRateNanosPerKB,
		m0Pub, m0Priv,
		nil,
		nil,
		"a post from m0",
		make(map[string][]byte),
		false)
	require.NoError(err)

	// Create a profile for m0.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB /*feerate*/, m0Pub,
			m0Priv, nil, "m0",
			"m0 profile", "",
			2500, /*CreatorBasisPoints*/
			12500 /*stakeMultipleBasisPoints*/, false /*isHidden*/)
		require.NoError(err)
	}
	// Create a profile for m1.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB /*feerate*/, m1Pub,
			m1Priv, nil, "m1",
			"m1 profile", "",
			2500, /*CreatorBasisPoints*/
			12500 /*stakeMultipleBasisPoints*/, false /*isHidden*/)
		require.NoError(err)
	}

	// Have m0 buy some of their own coin.
	{
		_, _, _, err = _creatorCoinTxn(
			t, chain, db, params, feeRateNanosPerKB,
			m0Pub, m0Priv, /*updater*/
			m0Pub,                       /*profile*/
			CreatorCoinOperationTypeBuy, /*buy/sell*/
			1000000000,                  /*DeSoToSellNanos*/
			0,                           /*CreatorCoinToSellNanos*/
			0,                           /*DeSoToAddNanos*/
			0,                           /*MinDeSoExpectedNanos*/
			0 /*MinCreatorCoinExpectedNanos*/)
		require.NoError(err)
	}
	// Have m0 buy some m1 as well.
	{
		_, _, _, err = _creatorCoinTxn(
			t, chain, db, params, feeRateNanosPerKB,
			m0Pub, m0Priv, /*updater*/
			m1Pub,                       /*profile*/
			CreatorCoinOperationTypeBuy, /*buy/sell*/
			1000000000,                  /*DeSoToSellNanos*/
			0,                           /*CreatorCoinToSellNanos*/
			0,                           /*DeSoToAddNanos*/
			0,                           /*MinDeSoExpectedNanos*/
			0 /*MinCreatorCoinExpectedNanos*/)
		require.NoError(err)
	}

	// Adding diamonds after the DeSo Diamonds block height should fail.
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		// Attempt to give two diamonds.
		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			2,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreatorCoinTransferHasDiamondsAfterDeSoBlockHeight)
	}
}

func TestCreatorCoinTransferSimple_CreatorCoinFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer some creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   1000000,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8123112737,
			m1HasPurchased:          true,
			m2CCBalance:             1000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer some more creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   20000000,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8103112737,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876538,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer some more creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   8000000000,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10708037578,
			m0HasPurchased:          false,
			m1CCBalance:             103112737,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876536,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer the rest of her creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   103112737,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10811150315,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 transfer all coins back to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   10811150315,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             10832150315,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999996,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 transfer all coins back to m1. Weeeeee!!!
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   10832150315,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             10832150315,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999996,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           5999999998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false /*desoFounderReward*/)
}

func TestCreatorCoinTransferSimple_DeSoFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// [0] Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// [1] Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0, // Founder reward is given in DeSo here.
			m0HasPurchased:          false,
			m1CCBalance:             9841661798,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// [2] Have m1 transfer some creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   1000000,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9840661798,
			m1HasPurchased:          true,
			m2CCBalance:             1000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// [3] Have m1 transfer some more creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   20000000,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9820661798,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876538,
			m2DeSoBalance:           6000000000,
		},
		// [4] Have m1 transfer some more creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   8000000000,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             8000000000,
			m0HasPurchased:          false,
			m1CCBalance:             1820661798,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876536,
			m2DeSoBalance:           6000000000,
		},
		// [5] Have m1 transfer the rest of her creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   1820661798,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             9820661798,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// [6] Have m0 transfer all coins back to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   9820661798,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             9841661798,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749081,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// [7] Have m2 transfer all coins back to m1. Weeeeee!!!
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   9841661798,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9841661798,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749081,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           5999999998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, true /*desoFounderReward*/)
}

func TestCreatorCoinTransferWithSwapIdentity(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           4827626815,
		},
		// Have m1 transfer 1e9 creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   1000000000,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             7124112737,
			m1HasPurchased:          true,
			m2CCBalance:             2977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           4827626815,
		},
		// Swap m0 and m3
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m0PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m3Pub,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             7124112737,
			m1HasPurchased:          true,
			m2CCBalance:             2977342329,
			m2HasPurchased:          true,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           4827626815,
		},
		// Have m2 transfer 2e9 creator coins (now attached to m3Pub's profile) to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   2000000000,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             2000000000,
			m0HasPurchased:          false,
			m1CCBalance:             7124112737,
			m1HasPurchased:          true,
			m2CCBalance:             977342329,
			m2HasPurchased:          true,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           4827626813,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinTransferWithSmallBalancesLeftOver(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 all but one nano of their creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   8124112736,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             8124112737,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 transfer all but the min threshold back to m1 (threshold assumed to be 10 nanos).
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   8124112727,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112727,
			m1HasPurchased:          false,
			m2CCBalance:             10,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           5999999998,
		},
		// Have m2 transfer their remaining 10 nanos back to m1.
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   10,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           5999999996,
		},
		// Have m1 transfer all but 5 nanos back to m0.
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   8124112732,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10832150315,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876538,
			m2DeSoBalance:           5999999996,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinTransferWithMaxTransfers(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 send all of their creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   8124112737,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             8124112737,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 buy some more of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13647653882,
			DeSoLockedNanos:         2541992686,
			CoinWatermarkNanos:      13647653882,
			m0CCBalance:             3411913469,
			m0HasPurchased:          false,
			m1CCBalance:             2111627676,
			m1HasPurchased:          true,
			m2CCBalance:             8124112737,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           3457753082,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer all their m0 coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   2111627676,

			// These are the expectations
			CoinsInCirculationNanos: 13647653882,
			DeSoLockedNanos:         2541992686,
			CoinWatermarkNanos:      13647653882,
			m0CCBalance:             3411913469,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             10235740413,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           3457753080,
			m2DeSoBalance:           5999999998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinTransferBelowMinThreshold(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	// Set up a blockchain
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	// Send money to people from moneyPk
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m0Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m1Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m2Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m3Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m4Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m5Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m6Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	_, _, _, err := _updateProfile(
		t, chain, db, params,
		feeRateNanosPerKB /*feerate*/, m0Pub, m0Priv, m0PkBytes, "m0",
		"i am m0", "m0 profile pic", 2500, /*CreatorBasisPoints*/
		12500 /*stakeMultipleBasisPoints*/, false /*isHidden*/)
	require.NoError(err)

	// m1 buys some m0 creator coin.
	_, _, _, err = _creatorCoinTxn(
		t, chain, db, params, feeRateNanosPerKB,
		m1Pub, m1Priv,
		m0Pub,                       /*profile*/
		CreatorCoinOperationTypeBuy, /*buy/sell*/
		1000000000,                  /*DeSoToSellNanos*/
		0,                           /*CreatorCoinToSellNanos*/
		0,                           /*DeSoToAddNanos*/
		0,                           /*MinDeSoExpectedNanos*/
		0 /*MinCreatorCoinExpectedNanos*/)
	require.NoError(err)

	_, _, _, err = _doCreatorCoinTransferTxn(
		t, chain, db, params, feeRateNanosPerKB,
		m1Pub, m1Priv, m0Pub, m2Pub,
		mempool.bc.params.CreatorCoinAutoSellThresholdNanos-1)
	require.Contains(err.Error(), RuleErrorCreatorCoinTransferMustBeGreaterThanMinThreshold)
}

func TestCreatorCoinBuySellSimple_CreatorCoinFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           4827626815,
		},
		// Have m1 sell half of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4123456789,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
		},
		// Have m2 sell all of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       1977342329,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 7367807635,
			DeSoLockedNanos:         399958612,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           5243756077,
		},
		// Have m1 buy more
		// Following SalomonFixBlockHeight, this should continue
		// to mint creator coins for the creator. Read about SalomonFixBlockHeight
		// in constants.go for a more indepth explanation.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13613944261,
			DeSoLockedNanos:         2523203055,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             4928685843,
			m0HasPurchased:          false,
			m1CCBalance:             8685258418,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4232379830,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 sell the rest of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       8685258418,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4928685843,
			DeSoLockedNanos:         119727407,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             4928685843,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		{
			// Have m0 sell all of their remaining stake except for 1 CreatorCoin nano
			// This will trigger an autosell due to CreatorCoinAutoSellThresholdNanos.
			// Nobody should be left with creator coins, and the deso locked should be zero.
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4928685842,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715430,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 buy a little more, again m0 should receive some more as a founders reward
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 12852863707,
			DeSoLockedNanos:         2123244443,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             3213215926,
			m0HasPurchased:          false,
			m1CCBalance:             9639647781,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715430,
			m1DeSoBalance:           4512158337,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 sell their creator coins.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       9639647781,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 3213215926,
			DeSoLockedNanos:         33175681,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             3213215926,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715430,
			m1DeSoBalance:           6602018090,
			m2DeSoBalance:           5243756077,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinBuySellSimple_DeSoFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// [0] Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// [1] Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9841661798,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// [2] Have m2 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 12237041464,
			DeSoLockedNanos:         1832439217,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9841661798,
			m1HasPurchased:          true,
			m2CCBalance:             2395379666,
			m2HasPurchased:          true,
			m0DeSoBalance:           6610813069,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           4827626815,
		},
		// [3] Have m1 sell a large chunk of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4123456789,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 8113584675,
			DeSoLockedNanos:         534119641,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             5718205009,
			m1HasPurchased:          true,
			m2CCBalance:             2395379666,
			m2HasPurchased:          true,
			m0DeSoBalance:           6610813069,
			m1DeSoBalance:           6027066284,
			m2DeSoBalance:           4827626815,
		},
		// [4] Have m2 sell all of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       2395379666,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 5718205009,
			DeSoLockedNanos:         186973195,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             5718205009,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6610813069,
			m1DeSoBalance:           6027066284,
			m2DeSoBalance:           5174738544,
		},
		// [5] Have m1 buy more
		// Following SalomonFixBlockHeight, this should continue
		// to mint creator coins / deso for the creator. Read about SalomonFixBlockHeight
		// in constants.go for a more indepth explanation.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 12117833075,
			DeSoLockedNanos:         1779406528,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             12117833075,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7141624179,
			m1DeSoBalance:           3903609493,
			m2DeSoBalance:           5174738544,
		},

		// [6] Have m1 sell the rest of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       12117833075,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7141624179,
			m1DeSoBalance:           5682838078,
			m2DeSoBalance:           5174738544,
		},

		// [7] Have m0 buy some of their own coins.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1e6,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 999966698,
			DeSoLockedNanos:         999900,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             999966698,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7140624177,
			m1DeSoBalance:           5682838078,
			m2DeSoBalance:           5174738544,
		},

		{
			// [8] Have m0 sell all of their remaining stake except for 1 CreatorCoin nano
			// This will trigger an autosell due to CreatorCoinAutoSellThresholdNanos.
			// Nobody should be left with creator coins, and the deso locked should be zero.
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       999966697,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7141623975,
			m1DeSoBalance:           5682838078,
			m2DeSoBalance:           5174738544,
		},

		// [9] Have m1 buy a little more, again m0 should receive some deso as a founders reward
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 11677601773,
			DeSoLockedNanos:         1592433333,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             11677601773,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7672435085,
			m1DeSoBalance:           3559381287,
			m2DeSoBalance:           5174738544,
		},

		// [10] Have m1 sell their creator coins.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       11677601773,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7672435085,
			m1DeSoBalance:           5151655374,
			m2DeSoBalance:           5174738544,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, true)
}

// This test exercises some logic whereby a creator buys and
// sells their own coin before anybody else.
func TestCreatorCoinSelfBuying_DeSoAndCreatorCoinFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m0 buy his own coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10832150315,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           4728876540,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 buy his own coins *again*
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             13468606753,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           3556503355,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 sell half of his own coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       1556503355,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 11912103398,
			DeSoLockedNanos:         1690307207,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             11912103398,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           4309373139,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 sell the rest of his own coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       11912103398,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999511313,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
	}

	// Buying one's own coin should always result in a creator coin founder reward,
	// even after the deso founder reward block height.
	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false /*desoFounderReward*/)
	_helpTestCreatorCoinBuySell(t, creatorCoinTests, true /*desoFounderReward*/)
}

func TestCreatorCoinTinyFounderRewardBuySellAmounts_CreatorCoinFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    1,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy a large amount of m0 to push up the watermark
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              100000000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641433551,
			DeSoLockedNanos:         99990000,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             464143,
			m0HasPurchased:          false,
			m1CCBalance:             4640969408,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 sell all their coins such that they're below the autosell threshold
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       464143,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4640969408,
			DeSoLockedNanos:         99960007,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             4640969408,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6000029986,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 buy more just up till CoinsInCirculationNanos is almost CoinWatermarkNanos
		// m0 should continue to receieve 1 basis point founders reward irrelevant of the CoinWatermarkNanos.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641124148,
			DeSoLockedNanos:         99970006,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             15, // Notice how this is just barely above the autosell threshold.
			// If this was any smaller, this transaction would fail.
			m0HasPurchased: false,
			m1CCBalance:    4641124133,
			m1HasPurchased: true,
			m2CCBalance:    0,
			m2HasPurchased: false,
			m0DeSoBalance:  6000029986,
			m1DeSoBalance:  5899989996,
			m2DeSoBalance:  6000000000,
		},
		// Now we have m2 buy a tiny amount of m0
		// This should also mint m0 a tiny founders reward, but because m0's balance
		// is above the autosell threshold, any amount will suffice.
		{
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641139607,
			DeSoLockedNanos:         99971005,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             16,
			m0HasPurchased:          false,
			m1CCBalance:             4641124133,
			m1HasPurchased:          true,
			m2CCBalance:             15458,
			m2HasPurchased:          true,
			m0DeSoBalance:           6000029986,
			m1DeSoBalance:           5899989996,
			m2DeSoBalance:           5999998998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinTinyFounderRewardBuySellAmounts_DeSoFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    1,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy a large amount of m0 to push up the watermark
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              100000000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641278831,
			DeSoLockedNanos:         99980001,
			CoinWatermarkNanos:      4641278831,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             4641278831,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6000009997,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 buy more just up till CoinsInCirculationNanos is almost CoinWatermarkNanos
		// m0 should continue to receieve 1 basis point founders reward irrelevant of the CoinWatermarkNanos.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641433550,
			DeSoLockedNanos:         99990000,
			CoinWatermarkNanos:      4641433550,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             4641433550,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6000009997,
			m1DeSoBalance:           5899989996,
			m2DeSoBalance:           6000000000,
		},
		// Now we have m2 buy a tiny amount of m0
		// This should also mint m0 a tiny founders reward, but because m0's balance
		// is above the autosell threshold, any amount will suffice.
		{
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641449007,
			DeSoLockedNanos:         99990999,
			CoinWatermarkNanos:      4641449007,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             4641433550,
			m1HasPurchased:          true,
			m2CCBalance:             15457,
			m2HasPurchased:          true,
			m0DeSoBalance:           6000009997,
			m1DeSoBalance:           5899989996,
			m2DeSoBalance:           5999998998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, true /*desoFounderReward*/)
}

func TestCreatorCoinFullFounderRewardBuySellAmounts_CreatorCoinFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    10000,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy a large amount of m0. It should all go to m0.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              100000000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641433551,
			DeSoLockedNanos:         99990000,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             4641433551,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          true, // Even though m1 does not received any creator coins, we set HasPurchased to true.
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 sell. The DeSo should've effectively
		// been transferred from m1 to m0.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4641433551,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          true, // Even though m1 does not received any creator coins, we set HasPurchased to true.
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6099979997,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinLargeFounderRewardBuySellAmounts(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    9999,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy a huge amount of m0. This will move CoinWatermarkNanos up.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              100000000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641433551,
			DeSoLockedNanos:         99990000,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             4640969407,
			m0HasPurchased:          false,
			m1CCBalance:             464144,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 try and buy a small amount of m0. If you set the amount
		// to 64000 DeSo nanos to sell, the amount to mint for m2 would
		// be 99 nano creator coins. This is below the autosell threshold,
		// so the buy (should) fail. It should respond with a rule error stating:
		// RuleErrorCreatorCoinBuyMustSatisfyAutoSellThresholdNanosForBuyer
		// Here it's set to 66000, minting just enough to push m2 above the threshold (103 nanos).
		{
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              66000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4642454435,
			DeSoLockedNanos:         100055993,
			CoinWatermarkNanos:      4642454435,
			m0CCBalance:             4641990188,
			m0HasPurchased:          false,
			m1CCBalance:             464144,
			m1HasPurchased:          true,
			m2CCBalance:             103,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           5999933998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinAroundThresholdBuySellAmounts(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    0,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m0 buy his a teeny amount of his own coins
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              7,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 18171213,
			DeSoLockedNanos:         6,
			CoinWatermarkNanos:      18171213,
			m0CCBalance:             18171213,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999989,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// m0 sells just enough creator coins to reach the CreatorCoinAutoSellThresholdNanos.
		// This should not completely sell the remaining holdings.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       18171213 - DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      18171213,
			m0CCBalance:             DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999992,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// m1 buys m0 increasing the total number of holders to 2.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 99966681,
			DeSoLockedNanos:         999,
			CoinWatermarkNanos:      99966681,
			m0CCBalance:             DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos,
			m0HasPurchased:          true,
			m1CCBalance:             99966671,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999992,
			m1DeSoBalance:           5999998998,
			m2DeSoBalance:           6000000000,
		},
		// m0 sells a single nano of their own creator coin. This triggers the
		// CreatorCoinAutoSellThresholdNanos. This reduces the number of holders to 1.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       1,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 99966671,
			DeSoLockedNanos:         999,
			CoinWatermarkNanos:      99966681,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             99966671,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999990,
			m1DeSoBalance:           5999998998,
			m2DeSoBalance:           6000000000,
		},
		// m2 now purchases m0's creator coins
		{
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1000000000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9999666925,
			DeSoLockedNanos:         999900999,
			CoinWatermarkNanos:      9999666925,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             99966671,
			m1HasPurchased:          true,
			m2CCBalance:             9899700254,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999990,
			m1DeSoBalance:           5999998998,
			m2DeSoBalance:           4999999998,
		},
		// m1 sells to just past the threshold, should trigger an autosell
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       99966671 - DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos + 1,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9899700254,
			DeSoLockedNanos:         970211757,
			CoinWatermarkNanos:      9999666925,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             9899700254,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999990,
			m1DeSoBalance:           6029685269,
			m2DeSoBalance:           4999999998,
		},
		// m2 sells to just past the threshold, should trigger an autosell and clear the profile
		{
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       9899700254 - DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos + 1,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      9999666925,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999990,
			m1DeSoBalance:           6029685269,
			m2DeSoBalance:           5970114731,
		},
	}

	// These tests shoudl behave the same since there is no founder reward.
	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
	_helpTestCreatorCoinBuySell(t, creatorCoinTests, true /*desoFounderReward*/)
}

// The salomon sequence is a sequence of transactions known to
// cause Bancor curve errors in the earlier days of the chain.
// The sequence is named after @salomon, the finder of the sequence.
func TestSalomonSequence(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0. m0 represents salomon.
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    0,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// m0 buys a specific amount of salomon
		// In the UI this would represent selling 323138431 nanos.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              323106117 + 6,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 6861733544,
			DeSoLockedNanos:         323073812,
			CoinWatermarkNanos:      6861733544,
			m0CCBalance:             6861733544,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5676893873,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// m0 follows up with another specific purchase.
		// In the UI this represented selling 191807888 nanos.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              191807888 + 6,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 8014879883,
			DeSoLockedNanos:         514862525,
			CoinWatermarkNanos:      8014879883,
			m0CCBalance:             8014879883,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5485085977,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Now is where things got interesting. In the original salomon sequence,
		// the user (m0) attempted a max sell of all their creator coins. However,
		// due to some rounding error bugs this caused an abnormal reserve ratio
		// and the price quickly approached billions of USD / creator coins. Very
		// few creator coins were in circulation, and it would not have returned
		// to a normal price. Here we check that the amount is reset upon sale.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       8014879883,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      8014879883,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999897012,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

// This test stress-tests our Bancor equation by doing the smallest
// possible buy one can do, which utilizes the polynomial equation
// to bootstrap, and then doing a normal-sized buy
func TestCreatorCoinBigBuyAfterSmallBuy(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m0 buy his a teeny amount of his own coins
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10000004, // Something small
			DeSoLockedNanos:         1,
			CoinWatermarkNanos:      10000004, // Something small
			m0CCBalance:             10000004, // Something small
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999994,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 do a normal-sized buy of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832149301,
			DeSoLockedNanos:         1270996344,
			CoinWatermarkNanos:      10832149301,
			m0CCBalance:             2715537328,
			m0HasPurchased:          true,
			m1CCBalance:             8116611973,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999994,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 sell their amount.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       2715537328,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832149301 - 2715537328,
			DeSoLockedNanos:         534717879,
			CoinWatermarkNanos:      10832149301,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             8116611973,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6736204829,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 sell their amount.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       8116611973,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      10832149301,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6736204829,
			m1DeSoBalance:           5263540947,
			m2DeSoBalance:           6000000000,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinBigBigBuyBigSell(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	desoToSellNanos := uint64(30000000000000000)
	{
		// Buy 30M DeSo worth of CC using polynomial model.
		polyMintedCCNanos := CalculateCreatorCoinToMintPolynomial(
			desoToSellNanos, 0, &DeSoMainnetParams)

		// Sell half of the CC
		desoReturnedNanos := CalculateDeSoToReturn(
			polyMintedCCNanos/2, polyMintedCCNanos,
			desoToSellNanos, &DeSoMainnetParams)

		// Sell the other half of the CC
		desoReturned2Nanos := CalculateDeSoToReturn(
			polyMintedCCNanos-polyMintedCCNanos/2, polyMintedCCNanos-polyMintedCCNanos/2,
			desoToSellNanos-desoReturnedNanos, &DeSoMainnetParams)

		// Should get back the amount of DeSo we put in.
		require.Equal(desoToSellNanos, desoReturnedNanos+desoReturned2Nanos)
	}

	{
		// Buy 30M worth of DeSo using the Bancor model at the very
		// beginning of the curve.
		// Sell the CC from the previous step down to zero.
		initialCCNanos := uint64(10000004)
		bancorMintedCCNanos := CalculateCreatorCoinToMintBancor(
			desoToSellNanos, initialCCNanos, 1, &DeSoMainnetParams)

		// Sell half of the CC
		desoReturnedNanos := CalculateDeSoToReturn(
			bancorMintedCCNanos/2, bancorMintedCCNanos+initialCCNanos,
			desoToSellNanos+1, &DeSoMainnetParams)

		// Sell the other half of the CC
		desoReturned2Nanos := CalculateDeSoToReturn(
			bancorMintedCCNanos-bancorMintedCCNanos/2,
			bancorMintedCCNanos-bancorMintedCCNanos/2+initialCCNanos,
			desoToSellNanos-desoReturnedNanos+1, &DeSoMainnetParams)

		// Should get back the amount of DeSo we put in.
		require.Equal(int64(desoToSellNanos), int64(desoReturnedNanos+desoReturned2Nanos))
	}
}

func _creatorCoinTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	UpdaterPublicKeyBase58Check string,
	UpdaterPrivateKeyBase58Check string,
	// See CreatorCoinMetadataa for an explanation of these fields.
	ProfilePublicKeyBase58Check string,
	OperationType CreatorCoinOperationType,
	DeSoToSellNanos uint64,
	CreatorCoinToSellNanos uint64,
	DeSoToAddNanos uint64,
	MinDeSoExpectedNanos uint64,
	MinCreatorCoinExpectedNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(UpdaterPublicKeyBase58Check)
	require.NoError(err)

	profilePkBytes, _, err := Base58CheckDecode(ProfilePublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateCreatorCoinTxn(
		updaterPkBytes,
		profilePkBytes,
		OperationType,
		DeSoToSellNanos,
		CreatorCoinToSellNanos,
		DeSoToAddNanos,
		MinDeSoExpectedNanos,
		MinCreatorCoinExpectedNanos,
		feeRateNanosPerKB,
		nil, /*mempool*/
		[]*DeSoOutput{})

	if err != nil {
		return nil, nil, 0, err
	}

	if OperationType == CreatorCoinOperationTypeBuy {
		require.Equal(int64(totalInputMake), int64(changeAmountMake+feesMake+DeSoToSellNanos))
	} else {
		require.Equal(int64(totalInputMake), int64(changeAmountMake+feesMake))
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, UpdaterPrivateKeyBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.GreaterOrEqual(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeCreatorCoin operation at the end.
	numInputs := len(txn.TxInputs)
	numOps := len(utxoOps)
	for ii := 0; ii < numInputs; ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	for ii := numInputs; ii < numOps-1; ii++ {
		require.Equal(OperationTypeAddUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeCreatorCoin, utxoOps[numOps-1].Type)

	require.NoError(utxoView.FlushToDb(0))

	return utxoOps, txn, blockHeight, nil
}

func _creatorCoinTxnWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	UpdaterPublicKeyBase58Check string,
	UpdaterPrivateKeyBase58Check string,
	// See CreatorCoinMetadataa for an explanation of these fields.
	ProfilePublicKeyBase58Check string,
	OperationType CreatorCoinOperationType,
	DeSoToSellNanos uint64,
	CreatorCoinToSellNanos uint64,
	DeSoToAddNanos uint64,
	MinDeSoExpectedNanos uint64,
	MinCreatorCoinExpectedNanos uint64) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, UpdaterPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _creatorCoinTxn(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB, UpdaterPublicKeyBase58Check,
		UpdaterPrivateKeyBase58Check, ProfilePublicKeyBase58Check, OperationType,
		DeSoToSellNanos, CreatorCoinToSellNanos, DeSoToAddNanos,
		MinDeSoExpectedNanos, MinCreatorCoinExpectedNanos)

	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _doCreatorCoinTransferTxnWithDiamonds(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	SenderPublicKeyBase58Check string,
	SenderPrivBase58Check string,
	ReceiverPublicKeyBase58Check string,
	DiamondPostHash *BlockHash,
	DiamondLevel int64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(SenderPublicKeyBase58Check)
	require.NoError(err)

	receiverPkBytes, _, err := Base58CheckDecode(ReceiverPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)

	txn, totalInputMake, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
		senderPkBytes,
		receiverPkBytes,
		DiamondPostHash,
		DiamondLevel,
		feeRateNanosPerKB, nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, SenderPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.GreaterOrEqual(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeCreatorCoinTransfer operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeCreatorCoinTransfer, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb(0))

	return utxoOps, txn, blockHeight, nil
}

func _doCreatorCoinTransferTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	UpdaterPublicKeyBase58Check string, UpdaterPrivateKeyBase58Check string,
	// See CreatorCoinTransferMetadataa for an explanation of these fields.
	ProfilePublicKeyBase58Check string,
	ReceiverPublicKeyBase58Check string,
	CreatorCoinToTransferNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(UpdaterPublicKeyBase58Check)
	require.NoError(err)

	profilePkBytes, _, err := Base58CheckDecode(ProfilePublicKeyBase58Check)
	require.NoError(err)

	receiverPkBytes, _, err := Base58CheckDecode(ReceiverPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)

	txn, totalInputMake, _, _, err := chain.CreateCreatorCoinTransferTxn(
		updaterPkBytes,
		profilePkBytes,
		CreatorCoinToTransferNanos,
		receiverPkBytes,
		feeRateNanosPerKB,
		nil, /*mempool*/
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, UpdaterPrivateKeyBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeCreatorCoinTransfer operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeCreatorCoinTransfer, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb(0))

	return utxoOps, txn, blockHeight, nil
}
