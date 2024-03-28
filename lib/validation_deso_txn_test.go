package lib

import (
	"encoding/hex"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

var testTransaction1HexString = "00000583010000727b22426f6479223a2249206d6973732074686f736520646179733b206d6179626520746865792077696c6c20636f6d6520616761696e2e5c6e405768616c65536861726b4554482040496e657669746162696c69747920406469616d6f6e6468616e647320404469616d6f6e64564320227de807d461dcfd9d89be90e2b917002103eed65faac1cb3e8790ab268ebde15da0f207e95ddd88bdfc2b25be0b30e2173a040d456d626564566964656f55524c000f497351756f7465645265636c6f75740101044e6f64650134115265636c6f75746564506f7374486173682080cb73b4308808cb7bf9e4657cc906742ee8fb31312fcf867214ad8c0817138e473145022100ceb6c9d2f16cc06cdd48130ecc8de1a18efc2759df4cc3ddccbc8aeb836309db0220458055db0c8c42ed3468e9d6204352907fe64b149c601b2267c8c4dbfacfc8360194238fae0f9dbd9c9e86f7f0bc34"
var testTransaction2HexString = "000102a7d230b752ae31861d6e405fba00260c6c9b6222642705549e5e96ad7e08cd70d00f0548203c449682b1ab2f16cc9c91c95b2f022449983588c8903fd4a7a07407d01491aa00177b22426f6479223a226578706563746174696f6e73227de807d461e1e7e8cda9fedfb917012103ee83d9a6e3f18c443fdc2e3c1d900fd97839fc118a929ed219282da9ce460b1f020f497351756f7465645265636c6f75740101115265636c6f75746564506f73744861736820f030c92536a92545a2ae5d1f2028a881d5989d7ef338053384621c7ad5255991463044022061974a8b6ce1eb337a9e3eeb149073384d4f8762e8eb22d1d2719eed7fd91c9a02207166fdc39b91d99d934edfb865634925dd744fdd7ddd8431d4517a330f6d2df101b902dead0fc6e28aa8e8d7b3e4d701"
var testTransaction3HexString = "000005c0022028b53cc989e26e7762c71042aec7de4b5f8c52f10a5dd6c72e0894ae6dac3f60008e027b22426f6479223a224973206974206a757374206d65206f7220616e796f6e6520656c73652067657474696e672074686973206c61796f757420746f6f3f5c6e4d79206c65667468616e64207461627320617265206d6f76696e672061726f756e6420616e6420626c6f636b2065616368206f746865722e5c6e49747320737570657220616e6e6f79696e6720406469616d6f6e6420407a6f72646f6e20222c22496d61676555524c73223a5b2268747470733a2f2f696d616765732e6465736f2e6f72672f363430396133613065663264666237393831373162643061373530376634643031373933643036336230336165346161616562616136303763393166353230362e77656270225d7de807d461abb7e6a99bffc3b9170021034584aab2cd71d14ec4709015244ed62d58bca0bdb511631838566567b1bef733020d456d626564566964656f55524c00044e6f64650134473045022100a4380b72c94f016781e9fbe87071c83038f8f007da874ec7bc5f9bd075e0047002202e52facbd641f182c7b3a2627e213260f2f8803a2a9f427b6266f6e218add31f01e003b6aa0fa487d6a3f3ab86a4ff01"

func decodeTestTxns(t *testing.T) []*MsgDeSoTxn {
	require := require.New(t)

	tx1Bytes, err := hex.DecodeString(testTransaction1HexString)
	require.NoError(err)
	tx2Bytes, err := hex.DecodeString(testTransaction2HexString)
	require.NoError(err)
	tx3Bytes, err := hex.DecodeString(testTransaction3HexString)
	require.NoError(err)

	tx1 := &MsgDeSoTxn{}
	require.NoError(tx1.FromBytes(tx1Bytes))
	tx2 := &MsgDeSoTxn{}
	require.NoError(tx2.FromBytes(tx2Bytes))
	tx3 := &MsgDeSoTxn{}
	require.NoError(tx3.FromBytes(tx3Bytes))

	return []*MsgDeSoTxn{tx1, tx2, tx3}
}

func TestValidateDeSoTxnEncoding(t *testing.T) {
	require := require.New(t)

	params := DeSoTestnetParams
	mergedGlobalParams := MergeGlobalParamEntryDefaults(&GlobalParamsEntry{}, &params)
	txns := decodeTestTxns(t)

	for _, txn := range txns {
		require.NoError(
			ValidateDeSoTxnEncoding(txn, 1, mergedGlobalParams, &params), &params)
	}

	params.MaxBlockSizeBytesPoW = 0
	for _, txn := range txns {
		require.Contains(ValidateDeSoTxnEncoding(txn, 1, mergedGlobalParams, &params).Error(), RuleErrorTxnTooBig)
	}
}

func TestValidateDeSoTxnMetadata(t *testing.T) {
	require := require.New(t)

	txns := decodeTestTxns(t)

	for _, txn := range txns {
		require.NoError(ValidateDeSoTxnMetadata(txn))
	}
}

func TestValidateDeSoTxnHash(t *testing.T) {
	require := require.New(t)

	txns := decodeTestTxns(t)

	for _, txn := range txns {
		require.NoError(ValidateDeSoTxnHash(txn))
	}
}

func TestValidateDeSoTxnPublicKey(t *testing.T) {
	require := require.New(t)

	txns := decodeTestTxns(t)

	for _, txn := range txns {
		require.NoError(ValidateDeSoTxnPublicKey(txn))
	}
}

func TestValidateDeSoTxnFormatBalanceModel(t *testing.T) {
	require := require.New(t)

	// txns have expiration block heights equal to:
	//	251663, 251614, 251190
	txns := decodeTestTxns(t)
	blockHeight := uint64(251000)
	globalParams := InitialGlobalParamsEntry
	globalParams.MaxNonceExpirationBlockHeightOffset = 1000

	for _, txn := range txns {
		require.NoError(ValidateDeSoTxnFormatBalanceModel(txn, blockHeight, &globalParams))
	}

	globalParams.MaxNonceExpirationBlockHeightOffset = 1
	for _, txn := range txns {
		require.Contains(ValidateDeSoTxnFormatBalanceModel(txn, blockHeight, &globalParams).Error(), TxErrorNonceExpirationBlockHeightOffsetExceeded)
	}
}

func TestValidateDeSoTxnMinimalNetworkFee(t *testing.T) {
	require := require.New(t)

	txns := decodeTestTxns(t)
	globalParams := InitialGlobalParamsEntry

	for _, txn := range txns {
		require.NoError(ValidateDeSoTxnMinimalNetworkFee(txn, &globalParams))
	}

	globalParams.MinimumNetworkFeeNanosPerKB = math.MaxUint64
	for _, txn := range txns {
		require.Contains(ValidateDeSoTxnMinimalNetworkFee(txn, &globalParams).Error(), RuleErrorTxnFeeBelowNetworkMinimum)
	}

	txn1 := txns[0]
	txn1.TxnFeeNanos = math.MaxUint64 / 999
	require.Contains(ValidateDeSoTxnMinimalNetworkFee(txn1, &globalParams).Error(), RuleErrorOverflowDetectedInFeeRateCalculation)

	txn2 := txns[1]
	txn2.Signature.Sign = nil
	require.Error(ValidateDeSoTxnMinimalNetworkFee(txn2, &globalParams))
}

func TestValidateDeSoTxnSanityBalanceModel(t *testing.T) {
	require := require.New(t)

	txns := decodeTestTxns(t)
	blockHeight := uint64(251000)
	params := DeSoTestnetParams
	globalParams := InitialGlobalParamsEntry

	for _, txn := range txns {
		require.NoError(ValidateDeSoTxnSanityBalanceModel(txn, blockHeight, &params, &globalParams))
	}
}
