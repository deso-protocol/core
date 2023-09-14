package lib

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"math"
	"math/big"
)

// block_view_lockups.go introduces 4 new transaction types:
//
//  (1) DAOCoinLockup - Enables "locking up" DeSo or DAO coins for a specified amount of time.
//                      Can be used for creating tokens on a vested schedule or, with the addition of an optional
//                      lockup yield, for earning a reward in return for locking up DeSo / DAO coins.
//  (2) DAOCoinUnlock - Once the locked tokens have matured, they can be unlocked via the DAOCoinUnlock transaction.
//  (3) DAOCoinLockupTransfer - Depending on how the creator has configured their DAO, locked tokens can be transferred
//                              between users via the DAOCoinLockupTransfer operation.
//  (4) UpdateDAOCoinLockupParams - Used for configuring the lockup / yield curve of the underlying DAO coin as well
//                                  as transfer restrictions. We make this a separate transaction to prevent
//                                  adding addition sub-ops to the already existing DAO coin operation.
//
// Below we define the structs, connect/disconnect logic, and flush operations associated with these new transactions.

//
// TYPES: LockedBalanceEntry
//

type LockedByType = uint8

const (
	LockedByCreator LockedByType = 0
	LockedByHODLer  LockedByType = 1
	LockedByOther   LockedByType = 2
)

type LockedBalanceEntry struct {
	HODLerPKID                      *PKID
	ProfilePKID                     *PKID
	ExpirationTimestampUnixNanoSecs int64
	AmountBaseUnits                 uint256.Int
	LockedBy                        LockedByType
	isDeleted                       bool
}

type LockedBalanceEntryMapKey struct {
	HODLerPKID                      PKID
	ProfilePKID                     PKID
	ExpirationTimestampUnixNanoSecs int64

	// Including LockedBy in the LockedBalanceEntryMapKey is a design choice
	// to prevent future ambiguous merge conflicts among several LockedBalanceEntry
	// structs. Consider two LockedBalanceEntry structs for the same HODLer and
	// profile expiring at the same time. If one is LockedByCreator and the other
	// is LockedByOther, merging these together into one LockedBalanceEntry leads
	// to ambiguous resolution. By keeping them separate and including LockedBy
	// in the LockedBalanceEntryMapKey struct we eliminate this distinction.
	LockedBy LockedByType
}

func MakeLockedBalanceEntryMapKey(
	hodlerPKID *PKID, creatorPKID *PKID, timestamp int64, lockedByType LockedByType) LockedBalanceEntryMapKey {
	return LockedBalanceEntryMapKey{
		HODLerPKID:                      *hodlerPKID,
		CreatorPKID:                     *creatorPKID,
		ExpirationTimestampUnixNanoSecs: timestamp,
		LockedBy:                        lockedByType,
	}
}

func (lockedBalanceEntry *LockedBalanceEntry) Copy() *LockedBalanceEntry {
	return &LockedBalanceEntry{
		HODLerPKID:                      lockedBalanceEntry.HODLerPKID.NewPKID(),
		ProfilePKID:                     lockedBalanceEntry.ProfilePKID.NewPKID(),
		ExpirationTimestampUnixNanoSecs: lockedBalanceEntry.ExpirationTimestampUnixNanoSecs,
		AmountBaseUnits:                 lockedBalanceEntry.AmountBaseUnits,
		LockedBy:                        lockedBalanceEntry.LockedBy,
		isDeleted:                       lockedBalanceEntry.isDeleted,
	}
}

func (lockedBalanceEntry *LockedBalanceEntry) Eq(other *LockedBalanceEntry) bool {
	return lockedBalanceEntry.ToMapKey() == other.ToMapKey()
}

func (lockedBalanceEntry *LockedBalanceEntry) ToMapKey() LockedBalanceEntryMapKey {
	return LockedBalanceEntryMapKey{
		HODLerPKID:                      *lockedBalanceEntry.HODLerPKID,
		ProfilePKID:                     *lockedBalanceEntry.ProfilePKID,
		ExpirationTimestampUnixNanoSecs: lockedBalanceEntry.ExpirationTimestampUnixNanoSecs,
		LockedBy:                        lockedBalanceEntry.LockedBy,
	}
}

// DeSoEncoder Interface Implementation for LockedBalanceEntry

func (lockedBalanceEntry *LockedBalanceEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, lockedBalanceEntry.HODLerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, lockedBalanceEntry.ProfilePKID, skipMetadata...)...)
	data = append(data, UintToBuf(uint64(lockedBalanceEntry.ExpirationTimestampUnixNanoSecs))...)
	data = append(data, VariableEncodeUint256(&lockedBalanceEntry.AmountBaseUnits)...)
	data = append(data, lockedBalanceEntry.LockedBy)
	return data
}

func (lockedBalanceEntry *LockedBalanceEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// HODLerPKID
	lockedBalanceEntry.HODLerPKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading HODLerPKID")
	}

	// ProfilePKID
	lockedBalanceEntry.ProfilePKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading ProfilePKID")
	}

	// ExpirationTimestampUnixNanoSecs
	uint64ExpirationTimestampUnixNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading ExpirationTimestampUnixNanoSecs")
	}
	lockedBalanceEntry.ExpirationTimestampUnixNanoSecs = int64(uint64ExpirationTimestampUnixNanoSecs)

	// AmountBaseUnits
	amountBaseUnits, err := VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading AmountBaseUnits")
	}
	lockedBalanceEntry.AmountBaseUnits = *amountBaseUnits

	// LockedBy
	lockedBalanceEntry.LockedBy, err = rr.ReadByte()
	if err != nil {
		return errors.Wrap(err, "LockedBalanceEntry.Decode: Problem reading LockedBy")
	}

	return err
}

func (lockedBalanceEntry *LockedBalanceEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (lockedBalanceEntry *LockedBalanceEntry) GetEncoderType() EncoderType {
	return EncoderTypeLockedBalanceEntry
}

func (bav *UtxoView) GetLockedBalanceEntryForHODLerPKIDCreatorPKIDTimestampLockedByType(
	hodlerPKID *PKID, creatorPKID *PKID, expirationTimestamp int64,
	lockedByType LockedByType) (_lockedBalanceEntry *LockedBalanceEntry) {
	// Check if we have the LockedBalanceEntry in the view.
	lockedBalanceEntryMapKey := MakeLockedBalanceEntryMapKey(hodlerPKID, creatorPKID, expirationTimestamp, lockedByType)
	if viewEntry, viewEntryExists := bav.LockedBalanceEntryMapKeyToLockedBalanceEntry[lockedBalanceEntryMapKey]; viewEntryExists {
		return viewEntry
	}

	// No mapping exists in the view, check for an entry in the DB.
	// NOTE: Postgres support is deprecated by the time we support Lockups (i.e. 1st PoS fork).
	lockedBalanceEntry := DBGetLockedBalanceEntryForHODLerPKIDCreatorPKIDTimestampType(
		bav.Handle, bav.Snapshot, hodlerPKID, creatorPKID, expirationTimestamp, lockedByType)

	// Cache the DB entry in the in-memory map.
	if lockedBalanceEntry != nil {
		bav._setLockedBalanceEntryMappingsWithPKIDsTimestampType(lockedBalanceEntry,
			hodlerPKID, creatorPKID, expirationTimestamp, lockedByType)
	}
	return lockedBalanceEntry
}

// block_view_locked_balance_entry.go
func (bav *UtxoView) _setLockedBalanceEntryMappingsWithPKIDsTimestampType(
	lockedBalanceEntry *LockedBalanceEntry, hodlerPKID *PKID, creatorPKID *PKID,
	expirationTimestamp int64, lockedByType LockedByType) {

	// This function shouldn't be called with nil.
	if lockedBalanceEntry == nil {
		glog.Errorf("_setLockedBalanceEntryMappingsWithPKIDsTimestampType: Called with nil LockedBalanceEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the LockedBalanceEntry
	lockedBalanceEntryMapKey := MakeLockedBalanceEntryMapKey(hodlerPKID, creatorPKID, expirationTimestamp, lockedByType)
	bav.LockedBalanceEntryMapKeyToLockedBalanceEntry[lockedBalanceEntryMapKey] = lockedBalanceEntry
}

func (bav *UtxoView) _setLockedBalanceEntry(lockedBalanceEntry *LockedBalanceEntry) {
	bav._setLockedBalanceEntryMappingsWithPKIDsTimestampType(lockedBalanceEntry,
		lockedBalanceEntry.HODLerPKID, lockedBalanceEntry.CreatorPKID,
		lockedBalanceEntry.ExpirationTimestampUnixNanoSecs, lockedBalanceEntry.LockedBy)
}

//
// TYPES: LockupYieldCurvePoint
//

type LockupYieldCurvePoint struct {
	CreatorPKID               *PKID
	LockupDurationNanoSecs    int64
	LockupYieldAPYBasisPoints uint64
}

type LockupYieldCurvePointMapKey struct {
	CreatorPKID            *PKID
	LockupDurationNanoSecs int64
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) Copy() *LockupYieldCurvePoint {
	return &LockupYieldCurvePoint{
		CreatorPKID:               lockupYieldCurvePoint.CreatorPKID.NewPKID(),
		LockupDurationNanoSecs:    lockupYieldCurvePoint.LockupDurationNanoSecs,
		LockupYieldAPYBasisPoints: lockupYieldCurvePoint.LockupYieldAPYBasisPoints,
	}
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) Eq(other *LockupYieldCurvePoint) bool {
	return lockupYieldCurvePoint.ToMapKey() == other.ToMapKey()
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) ToMapKey() LockupYieldCurvePointMapKey {
	return LockupYieldCurvePointMapKey{
		CreatorPKID:            lockupYieldCurvePoint.CreatorPKID,
		LockupDurationNanoSecs: lockupYieldCurvePoint.LockupDurationNanoSecs,
	}
}

//
// TYPES: CoinLockupMetadata
//

type CoinLockupMetadata struct {
	ProfilePublicKey       *PublicKey
	LockupDurationNanoSecs int64
	LockupAmountBaseUnits  *uint256.Int
}

func (txnData *CoinLockupMetadata) GetTxnType() TxnType {
	return TxnTypeCoinLockup
}

func (txnData *CoinLockupMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, UintToBuf(uint64(txnData.LockupDurationNanoSecs))...)
	data = append(data, VariableEncodeUint256(txnData.LockupAmountBaseUnits)...)
	return data, nil
}

func (txnData *CoinLockupMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinLockupMetadata.FromBytes: Problem reading ProfilePublicKey")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// ExpirationTimestampUnixNanoSecs
	uint64LockupDurationNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinLockupMetadata.FromBytes: Problem reading LockupDurationNanoSecs")
	}
	txnData.LockupDurationNanoSecs = int64(uint64LockupDurationNanoSecs)

	// LockupAmountBaseUnits
	txnData.LockupAmountBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinLockupMetadata.FromBytes: Problem reading LockupAmountBaseUnits")
	}

	return nil
}

func (txnData *CoinLockupMetadata) New() DeSoTxnMetadata {
	return &CoinLockupMetadata{}
}

//
// TYPES: UpdateDAOCoinLockupParamsMetadata
//

type UpdateDAOCoinLockupParamsMetadata struct {
	// LockupYieldDurationNanoSecs and LockupYieldAPYBasisPoints describe a coordinate pair
	// of (duration, APY yield) on a yield curve.
	//
	// A yield curve consists of a series of (duration, APY yield) points. For example,
	// the following points describe a simple yield curve:
	//              {(6mo, 3%), (12mo, 3.5%), (18mo, 4%), (24mo, 4.5%)}
	//
	// Assuming RemoveYieldCurvePoint is false:
	//    The point (LockupYieldDurationNanoSecs, LockupYieldAPYBasisPoints)
	//    is added to the profile's yield curve. If a point with the same duration already exists
	//    on the profile's yield curve, it will be updated with the new yield.
	// Assuming RemoveYieldCurvePoint is true:
	//    The point (LockupYieldDurationNanoSecs, XXX) is removed from the profile's yield curve.
	//    Note that LockupYieldAPYBasisPoints is ignored in this transaction.
	//
	// By setting LockupYieldDurationNanoSecs to zero, the yield curve attached to the profile
	// is left unmodified. In any UpdateDAOCoinLockupParams transaction looking to modify only
	// LockupTransferRestrictions, LockupYieldDurationNanoSecs would be set to zero.
	LockupYieldDurationNanoSecs int64
	LockupYieldAPYBasisPoints   uint64
	RemoveYieldCurvePoint       bool

	// When NewLockupTransferRestrictions is set true, the TransferRestrictionStatus specified
	// in the transaction is updated in the transactor's profile for locked coins.
	// Any subsequent transfers utilizing the transactor's locked coins are validated against
	// the updated locked transfer restriction status.
	NewLockupTransferRestrictions   bool
	LockupTransferRestrictionStatus TransferRestrictionStatus
}

func (txnData *UpdateDAOCoinLockupParamsMetadata) GetTxnType() TxnType {
	return TxnTypeUpdateDAOCoinLockupParams
}

func (txnData *UpdateDAOCoinLockupParamsMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, UintToBuf(uint64(txnData.LockupYieldDurationNanoSecs))...)
	data = append(data, UintToBuf(txnData.LockupYieldAPYBasisPoints)...)
	data = append(data, BoolToByte(txnData.RemoveYieldCurvePoint))
	data = append(data, BoolToByte(txnData.NewLockupTransferRestrictions))
	data = append(data, byte(txnData.LockupTransferRestrictionStatus))
	return data, nil
}

func (txnData *UpdateDAOCoinLockupParamsMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	lockupYieldDurationNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading LockupYieldDurationNanoSecs")
	}
	txnData.LockupYieldDurationNanoSecs = int64(lockupYieldDurationNanoSecs)

	txnData.LockupYieldAPYBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading LockupYieldAPYBasisPoints")
	}

	txnData.RemoveYieldCurvePoint, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading RemoveYieldCurvePoint")
	}

	txnData.NewLockupTransferRestrictions, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading NewLockupTransferRestrictions")
	}

	lockedStatusByte, err := rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading LockupTransferRestrictionStatus")
	}
	txnData.LockupTransferRestrictionStatus = TransferRestrictionStatus(lockedStatusByte)

	return nil
}

func (txnData *UpdateDAOCoinLockupParamsMetadata) New() DeSoTxnMetadata {
	return &UpdateDAOCoinLockupParamsMetadata{}
}

//
// TYPES: DAOCoinLockupTransferMetadata
//

type DAOCoinLockupTransferMetadata struct {
	RecipientPublicKey               *PublicKey
	ProfilePublicKey                 *PublicKey
	ExpirationTimestampUnixNanoSecs  int64
	LockedDAOCoinToTransferBaseUnits *uint256.Int
}

func (txnData *DAOCoinLockupTransferMetadata) GetTxnType() TxnType {
	return TxnTypeDAOCoinLockupTransfer
}

func (txnData *DAOCoinLockupTransferMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.RecipientPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, UintToBuf(uint64(txnData.ExpirationTimestampUnixNanoSecs))...)
	data = append(data, VariableEncodeUint256(txnData.LockedDAOCoinToTransferBaseUnits)...)
	return data, nil
}

func (txnData *DAOCoinLockupTransferMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// RecipientPublicKey
	recipientPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading RecipientPublicKey")
	}
	txnData.RecipientPublicKey = NewPublicKey(recipientPublicKeyBytes)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading ProfilePublicKey")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// ExpirationTimestampUnixNanoSecs
	uint64ExpirationTimestampUnixNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading ExpirationTimestampUnixNanoSecs")
	}
	txnData.ExpirationTimestampUnixNanoSecs = int64(uint64ExpirationTimestampUnixNanoSecs)

	// LockedDAOCoinToTransferBaseUnits
	txnData.LockedDAOCoinToTransferBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading LockedDAOCoinToTransferBaseUnits")
	}

	return nil
}

func (txnData *DAOCoinLockupTransferMetadata) New() DeSoTxnMetadata {
	return &DAOCoinLockupTransferMetadata{}
}

//
// TYPES: DAOCoinUnlockMetadata
//

type DAOCoinUnlockMetadata struct {
	ProfilePublicKey         *PublicKey
	DAOCoinToUnlockBaseUnits *uint256.Int
}

func (txnData *DAOCoinUnlockMetadata) GetTxnType() TxnType {
	return TxnTypeDAOCoinUnlock
}

func (txnData *DAOCoinUnlockMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, VariableEncodeUint256(txnData.DAOCoinToUnlockBaseUnits)...)
	return data, nil
}

func (txnData *DAOCoinUnlockMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinUnlockMetadata.FromBytes: Problem reading ProfilePublicKey")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// LockedDAOCoinToTransferBaseUnits
	txnData.DAOCoinToUnlockBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinUnlockMetadata.FromBytes: Problem reading DAOCoinToUnlockBaseUnits")
	}

	return nil
}

func (txnData *DAOCoinUnlockMetadata) New() DeSoTxnMetadata {
	return &DAOCoinUnlockMetadata{}
}

//
// CoinLockup Transaction Logic
//

func (bav *UtxoView) _connectCoinLockup(
	txn *MsgDeSoTxn,
	txHash *BlockHash,
	blockHeight uint32,
	verifySignatures bool,
) (
	_totalInput uint64,
	_totalOutput uint64,
	_utxoOps []*UtxoOperation,
	_err error,
) {
	var utxoOpsForTxn []*UtxoOperation

	// Validate the starting block height.
	// We require the ProofOfStake1StateSetupBlockHeight fork to time the release of lockups
	// with the 1st Proof-Of-Stake lockup height.
	// We require the BalanceModelBlockHeight fork to ensure consensus is utilizing balance model.
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return 0, 0, nil, errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_connectCoinLockup")
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCoinLockup {
		return 0, 0, nil, fmt.Errorf(
			"_connectDAOCoinLockup: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Try connecting the basic transfer without considering transaction metadata.
	//
	// NOTE: Because we require balance model, this basic transfer will deduct txn fees from the transactor's
	// DeSo balance. In the event the transactor is locking up DeSo, this allows us to easily check that
	// the transactor has sufficient DeSo remaining for the lockup.
	_, _, utxoOpsForBasicTransfer, err := bav._connectBasicTransfer(txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectCoinLockup")
	}
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpsForBasicTransfer...)

	// Normally here we check for non-zero input to prevent replay attacks.
	// In this transaction, we're requiring balance model to be present where the txn nonce prevents replay.

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*CoinLockupMetadata)

	// Check that the target profile public key is valid and that a profile corresponding to that public key exists.
	//
	// NOTE: Here we make an exception to this rule is made for the zero public key.
	//       The zero public key symbolically represents raw DeSo for lockup.
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupInvalidProfilePubKey, "_connectCoinLockup")
	}
	if !txMeta.ProfilePublicKey.IsZeroPublicKey() {
		creatorProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey.ToBytes())
		if creatorProfileEntry == nil || creatorProfileEntry.isDeleted {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinLockupOnNonExistentProfile, "_connectCoinLockup")
		}
	}

	// Validate the lockup amount as non-zero. This is meant to prevent wasteful "no-op" transactions.
	if txMeta.LockupAmountBaseUnits.IsZero() {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupOfAmountZero, "_connectCoinLockup")
	}

	// If this is a DeSo lockup, ensure the amount is less than 2**64 (maximum DeSo balance).
	if txMeta.ProfilePublicKey.IsZeroPublicKey() {
		maxUint64, _ := uint256.FromBig(big.NewInt(0).SetUint64(math.MaxUint64))
		if txMeta.LockupAmountBaseUnits.Gt(maxUint64) {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinLockupExcessiveDeSoLockup, "_connectCoinLockup")
		}
	}

	// Validate the lockup duration as non-negative and non-zero. This ensures the lockup will expire in the future.
	if txMeta.LockupDurationNanoSecs <= 0 {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupInvalidLockupDuration, "_connectCoinLockup")
	}

	// Validate the transactor as having sufficient DAO Coin or DESO balance for the transaction.
	var transactorBalanceNanos256 *uint256.Int
	var prevTransactorBalanceEntry *BalanceEntry
	if txMeta.ProfilePublicKey.IsZeroPublicKey() {
		// Check the DeSo balance of the user.
		transactorBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(txn.PublicKey)
		if err != nil {
			return 0, 0, nil, errors.Wrap(err, "_connectCoinLockup")
		}

		// Validate the DeSo balance as having sufficient funds.
		transactorBalanceNanos256, _ = uint256.FromBig(big.NewInt(0).SetUint64(transactorBalanceNanos))
		if txMeta.LockupAmountBaseUnits.Gt(transactorBalanceNanos256) {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinLockupInsufficientDeSo, "_connectCoinLockup")
		}

		// Spend the transactor's DeSo balance.
		lockupAmount64 := txMeta.LockupAmountBaseUnits.Uint64()
		newUtxoOp, err := bav._spendBalance(lockupAmount64, txn.PublicKey, blockHeight)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectCoinLockup")
		}
		utxoOpsForTxn = append(utxoOpsForTxn, newUtxoOp)
	} else {
		// Check the BalanceEntry of the user.
		transactorBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			txn.PublicKey,
			txMeta.ProfilePublicKey.ToBytes(),
			true)
		if transactorBalanceEntry == nil || transactorBalanceEntry.isDeleted {
			return 0, 0, nil,
				errors.Wrapf(RuleErrorCoinLockupBalanceEntryDoesNotExist, "_connectCoinLockup")
		}

		// Validate the balance entry as having sufficient funds.
		transactorBalanceNanos256 = transactorBalanceEntry.BalanceNanos.Clone()
		if txMeta.LockupAmountBaseUnits.Gt(transactorBalanceNanos256) {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinLockupInsufficientCoins, "_connectCoinLockup")
		}

		// We store the previous transactor balance entry in the event we need to revert the transaction.
		prevTransactorBalanceEntry = transactorBalanceEntry

		// Spend the transactor's DAO coin balance.
		transactorBalanceEntry.BalanceNanos = *uint256.NewInt().Sub(&transactorBalanceEntry.BalanceNanos, txMeta.LockupAmountBaseUnits)
		bav._setDAOCoinBalanceEntryMappings(transactorBalanceEntry)
	}

	// Determine which PKID to use.
	var creatorPKID *PKID
	if txMeta.ProfilePublicKey.IsZeroPublicKey() {
		creatorPKID = ZeroPKID.NewPKID()
	} else {
		creatorPKIDEntry := bav.GetPKIDForPublicKey(txMeta.ProfilePublicKey.ToBytes())
		if creatorPKIDEntry == nil || creatorPKIDEntry.isDeleted {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinLockupNonExistentProfile, "_connectCoinLockup")
		}
		creatorPKID = creatorPKIDEntry.PKID.NewPKID()
	}

	// By now we know the transaction to be valid. We now source yield information from either
	// the profile's yield curve or the DeSo yield curve. Because there's some choice in how
	// to determine the yield when the lockup duration falls between two creator specified yield curve
	// points, we return here the two local points and choose/interpolate between them below.
	leftYieldCurvePoint, rightYieldCurvePoint, err := bav.GetLocalYieldCurvePoints(creatorPKID, txMeta.LockupDurationNanoSecs)
	if err != nil {
		return 0, 0, nil, errors.Wrap(err, "_connectCoinLockup")
	}

	// Here we interpolate/choose between the two local yield curve points.
	//
	// If we fall between two points, we choose the left yield curve point (i.e. the one with lesser lockup duration).
	// The transactor earns yield only for the lockup duration specified by the left yield curve point but will
	// be unable to unlock the coins until the transaction specified lockup duration expires.
	txnYieldBasisPoints := uint64(0)
	txnYieldEarningDurationNanoSecs := int64(0)
	if leftYieldCurvePoint.LockupDurationNanoSecs < txMeta.LockupDurationNanoSecs {
		txnYieldBasisPoints = leftYieldCurvePoint.LockupYieldAPYBasisPoints
		txnYieldEarningDurationNanoSecs = leftYieldCurvePoint.LockupDurationNanoSecs
	}
	if rightYieldCurvePoint.LockupDurationNanoSecs == txMeta.LockupDurationNanoSecs {
		txnYieldBasisPoints = rightYieldCurvePoint.LockupYieldAPYBasisPoints
		txnYieldEarningDurationNanoSecs = rightYieldCurvePoint.LockupDurationNanoSecs
	}

	// Convert variables to a consistent uint256 representation. This is to use them in SafeUint256 math.
	txnYieldBasisPoints256 := uint256.NewInt().SetUint64(txnYieldBasisPoints)
	txnYieldEarningDurationNanoSecs256 := uint256.NewInt().SetUint64(uint64(txnYieldEarningDurationNanoSecs))

	// Compute the yield associated with this operation, checking to ensure there's no overflow.
	yieldFromTxn, err :=
		CalculateLockupYield(txMeta.LockupAmountBaseUnits, txnYieldBasisPoints256, txnYieldEarningDurationNanoSecs256)
	if err != nil {
		return 0, 0, nil, errors.Wrap(err, "_connectCoinLockup")
	}

	// We check that the minted yield does not cause an overflow in the transactor's balance.
	// In the case of DeSo being locked up, we must check that the resulting amount is less than 2**64.
	if uint256.NewInt().Sub(MaxUint256, yieldFromTxn).Lt(transactorBalanceNanos256) {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupYieldCausesOverflow, "_connectCoinLockup")
	}
	if creatorPKID.IsZeroPKID() {
		// Check if DeSo minted would overflow 2**64 in the transactor balance.
		if uint256.NewInt().Sub(uint256.NewInt().SetUint64(math.MaxUint64), yieldFromTxn).Lt(transactorBalanceNanos256) {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinLockupYieldCausesOverflow, "_connectCoinLockup")
		}
	}

	// Compute the amount to be added to the locked balance entry.
	lockupValue := *uint256.NewInt().Add(transactorBalanceNanos256, yieldFromTxn)

	// NOTE: While we could check for "global" overflow here, we let this occur on the unlock transaction instead.
	//       Global overflow is where the yield causes fields like CoinEntry.CoinsInCirculationNanos to overflow.
	//       Performing the check here would be redundant and may lead to worse UX in the case of coins being
	//       burned in the future making current lockups no longer an overflow.

	// Determine who performed the lockup.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	transactorPKID := transactorPKIDEntry.PKID
	var lockedByType LockedByType
	if transactorPKID.Eq(creatorPKID) {
		lockedByType = LockedByCreator
	} else {
		lockedByType = LockedByHODLer
	}

	// Check that the unlock time won't overflow UNIX nanosecond timestamps.
	// TODO: Discuss this because getting the block timestamp is a bit wonk.
	//       Feeding it in from ConnectBlock through _connectTransaction would require modifying
	//       all uses of _connectTransaction in tests.
	blockTimestampNanoSecs := int64(0)
	if int64(math.MaxInt64)-blockTimestampNanoSecs < txMeta.LockupDurationNanoSecs {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupUnlockTimestampOverflow, "_connectCoinLockup")
	}
	unlockTimestamp := blockTimestampNanoSecs + txMeta.LockupDurationNanoSecs

	// For consolidation, we fetch equivalent LockedBalanceEntries.
	lockedBalanceEntry := bav.GetLockedBalanceEntryForHODLerPKIDCreatorPKIDTimestampLockedByType(
		transactorPKID, creatorPKID, unlockTimestamp, lockedByType)
	if lockedBalanceEntry == nil || lockedBalanceEntry.isDeleted {
		lockedBalanceEntry = &LockedBalanceEntry{
			HODLerPKID:                      transactorPKID,
			CreatorPKID:                     creatorPKID,
			ExpirationTimestampUnixNanoSecs: unlockTimestamp,
			AmountBaseUnits:                 *uint256.NewInt(),
			LockedBy:                        lockedByType,
		}
	}
	previousLockedBalanceEntry := *lockedBalanceEntry

	// Check for overflow within the locked balance entry itself.
	if uint256.NewInt().Sub(MaxUint256, yieldFromTxn).Lt(transactorBalanceNanos256) {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupYieldCausesOverflow, "_connectCoinLockup")
	}
	if creatorPKID.IsZeroPKID() {
		// Check if DeSo minted would overflow 2**64 in the transactor balance.
		if uint256.NewInt().Sub(uint256.NewInt().SetUint64(math.MaxUint64), yieldFromTxn).Lt(transactorBalanceNanos256) {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinLockupYieldCausesOverflow, "_connectCoinLockup")
		}
	}

	// Increment the lockedBalanceEntry and update the view.
	lockedBalanceEntry.AmountBaseUnits = *uint256.NewInt().Add(&lockedBalanceEntry.AmountBaseUnits, &lockupValue)
	bav._setLockedBalanceEntry(lockedBalanceEntry)

	// Add a UtxoOperation for easy reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                       OperationTypeCoinLockup,
		PrevTransactorBalanceEntry: prevTransactorBalanceEntry,
		PrevLockedBalanceEntry:     &previousLockedBalanceEntry,
	})

	// Construct UtxoOps in the event this transaction is reverted.
	return 0, 0, utxoOpsForTxn, nil
}

func CalculateLockupYield(
	principal *uint256.Int,
	apyYieldBasisPoints *uint256.Int,
	durationNanoSecs *uint256.Int,
) (*uint256.Int, error) {
	// Note: We could compute either simple of compounding interest. While compounding interest is ideal from an
	//       application perspective, it becomes incredibly difficult to implement from a numerical perspective.
	//       This is because compound interest requires fractional exponents rather for computing the yield.
	//       Determining overflow and preventing excessive money-printers becomes tricky in the compound interest case.
	//       For this reason, we opt to use simple interest.
	//
	// Simple interest formula:
	//       yield = principal * apy_yield * time_in_years
	//
	// Notice this formula makes detecting computational overflow trivial by utilizing the DeSo SafeUint256 library.

	// Compute the denominators from the nanosecond to year conversion and the basis point computation.
	denominators, err := SafeUint256().Mul(
		uint256.NewInt().SetUint64(_nanoSecsPerYear),
		uint256.NewInt().SetUint64(10000))
	if err != nil {
		return nil,
			errors.Wrap(RuleErrorCoinLockupCoinYieldOverflow, "CalculateLockupYield (nanoSecsPerYear * 10000)")
	}

	// Compute the numerators from the principal, apy yield, and time in nanoseconds.
	numerators, err := SafeUint256().Mul(principal, apyYieldBasisPoints)
	if err != nil {
		return nil,
			errors.Wrap(RuleErrorCoinLockupCoinYieldOverflow, "CalculateLockupYield (principal * yield)")
	}
	numerators, err = SafeUint256().Mul(numerators, durationNanoSecs)
	if err != nil {
		return nil,
			errors.Wrap(RuleErrorCoinLockupCoinYieldOverflow, "CalculateLockupYield ((principal * yield) * duration)")
	}

	// Compute the yield for the transaction.
	yield, err := SafeUint256().Div(numerators, denominators)
	if err != nil {
		return nil,
			errors.Wrap(err, "CalculateLockupYield (numerator / denominator)")
	}

	return yield, nil
}

func (bav *UtxoView) GetLocalYieldCurvePoints(creatorPKID *PKID, lockupDuration int64) (
	leftLockupPoint *LockupYieldCurvePoint, rightLockupPoint *LockupYieldCurvePoint, err error) {
	// Setup "default" local points.
	leftLockupPoint = &LockupYieldCurvePoint{
		CreatorPKID:               creatorPKID,
		LockupDurationNanoSecs:    0,
		LockupYieldAPYBasisPoints: 0,
	}
	rightLockupPoint = &LockupYieldCurvePoint{
		CreatorPKID:               creatorPKID,
		LockupDurationNanoSecs:    int64(math.MaxInt64),
		LockupYieldAPYBasisPoints: 0,
	}

	// Check the UtxoView for local points tied to the creatorPKID.
	//
	// NOTE: While we could use a binary search here, it's unlikely for there to be a large number
	//       of yield curve points held in the UtxoView.
	// NOTE: We take special care to "Copy()" the yield curve points in the view to prevent
	//       accidental modifications of the points before writing to the db.
	for _, lockupYieldCurvePoint := range bav.PKIDToLockupYieldCurvePoints[*creatorPKID] {
		// Check if the point is "more left" than the current left point.
		if lockupYieldCurvePoint.LockupDurationNanoSecs < lockupDuration &&
			lockupYieldCurvePoint.LockupDurationNanoSecs > leftLockupPoint.LockupDurationNanoSecs {
			leftLockupPoint = lockupYieldCurvePoint.Copy()
		}

		// Check if the point is "more right" than the current right point.
		if lockupYieldCurvePoint.LockupDurationNanoSecs >= lockupDuration &&
			lockupYieldCurvePoint.LockupDurationNanoSecs < leftLockupPoint.LockupDurationNanoSecs {
			rightLockupPoint = lockupYieldCurvePoint.Copy()
		}
	}

	// Now we fetch local curve points from the DB using careful seek operations.
	key := _dbKeyForLockupYieldCurvePoint(LockupYieldCurvePoint{
		CreatorPKID:               creatorPKID,
		LockupDurationNanoSecs:    lockupDuration,
		LockupYieldAPYBasisPoints: 0,
	})

	// Seek badgerDB for the closest left point in the DB.
	err = bav.GetDbAdapter().badgerDb.View(func(txn *badger.Txn) error {
		iterLeftOpts := badger.DefaultIteratorOptions
		iterLeftOpts.Reverse = true
		iterLeft := txn.NewIterator(iterLeftOpts)
		iterLeft.Seek(key)
		iterLeftKey := iterLeft.Item().Key()

		// There's a chance our seek yield a key in a different prefix (i.e. not a yield curve point).
		// In this case, we know _dbKeyToLockupYieldCurvePoint will fail in parsing the key.
		// We can return early in this case as there's no relevant yield points in the DB.
		if len(iterLeftKey) < len(Prefixes.PrefixLockedDAOCoinYieldByCreatorAndDuration) {
			return nil
		}
		if !bytes.Equal(iterLeftKey[:len(Prefixes.PrefixLockedDAOCoinYieldByCreatorAndDuration)],
			Prefixes.PrefixLockedDAOCoinYieldByCreatorAndDuration) {
			return nil
		}

		// Parse the db key returned by seek.
		leftDbLockupPoint, err := _dbKeyToLockupYieldCurvePoint(iterLeftKey)
		if err != nil {
			return err
		}

		// Check for an updated left point.
		if leftDbLockupPoint.CreatorPKID.Eq(creatorPKID) {
			if leftDbLockupPoint.LockupDurationNanoSecs < lockupDuration &&
				leftDbLockupPoint.LockupDurationNanoSecs > leftLockupPoint.LockupDurationNanoSecs {
				leftLockupPoint = leftDbLockupPoint
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "_getLocalYieldCurvePoints")
	}

	// Seek badgerDB for the closest right point in the DB.
	err = bav.GetDbAdapter().badgerDb.View(func(txn *badger.Txn) error {
		iterRightOpts := badger.DefaultIteratorOptions
		iterRight := txn.NewIterator(iterRightOpts)
		iterRight.Seek(key)
		iterRightKey := iterRight.Item().Key()

		// There's a chance our seek yield a key in a different prefix (i.e. not a yield curve point).
		// In this case, we know _dbKeyToLockupYieldCurvePoint will fail in parsing the key.
		// We can return early in this case as there's no relevant yield points in the DB.
		if len(iterRightKey) < len(Prefixes.PrefixLockedDAOCoinYieldByCreatorAndDuration) {
			return nil
		}
		if !bytes.Equal(iterRightKey[:len(Prefixes.PrefixLockedDAOCoinYieldByCreatorAndDuration)],
			Prefixes.PrefixLockedDAOCoinYieldByCreatorAndDuration) {
			return nil
		}

		// Parse the db key returned by seek.
		rightDbLockupPoint, err := _dbKeyToLockupYieldCurvePoint(iterRightKey)
		if err != nil {
			return err
		}

		// Check for an updated right point.
		if rightDbLockupPoint.CreatorPKID.Eq(creatorPKID) {
			if rightDbLockupPoint.LockupDurationNanoSecs >= lockupDuration &&
				rightDbLockupPoint.LockupDurationNanoSecs < rightLockupPoint.LockupDurationNanoSecs {
				rightLockupPoint = rightDbLockupPoint
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "_getLocalYieldCurvePoints")
	}

	return leftLockupPoint, rightLockupPoint, nil
}

func (bav *UtxoView) _disconnectDAOCoinLockup(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32) error {

	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectDAOCoinLockup: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1

	// Verify the last operation as being a DAOCoinLockup operation.
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCoinLockup {
		return fmt.Errorf("_disconnectDAOCoinLockup: Trying to revert "+
			"OperationTypeDAOCoinLockup but found type %v", utxoOpsForTxn[operationIndex].Type)
	}

	// Sanity check the DAOCoinLockup operation exists.
	operationData := utxoOpsForTxn[operationIndex]
	if operationData.PrevLockedBalanceEntry == nil || operationData.PrevLockedBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectDAOCoinLockup: Trying to revert OperationTypeDAOCoinLockup " +
			"but found nil or deleted previous locked balance entry")
	}
	operationIndex--
	if operationIndex < 0 {
		return fmt.Errorf("_disconnectDAOCoinLockup: Trying to revert OperationTypeDAOCoinLockup " +
			"but malformed utxoOpsForTxn")
	}

	// Sanity check the data within the DAOCoinLockup. Reverting a lockup should not result in more coins.
	lockedBalanceEntry := bav.GetLockedBalanceEntryForHODLerPKIDCreatorPKIDTimestampLockedByType(
		operationData.PrevLockedBalanceEntry.HODLerPKID, operationData.PrevLockedBalanceEntry.CreatorPKID,
		operationData.PrevLockedBalanceEntry.ExpirationTimestampUnixNanoSecs, operationData.PrevLockedBalanceEntry.LockedBy)
	if lockedBalanceEntry.AmountBaseUnits.Lt(&operationData.PrevLockedBalanceEntry.AmountBaseUnits) {
		return fmt.Errorf("_disconnectDAOCoinLockup: Reversion of coin lockup would result in " +
			"more coins in the lockup")
	}

	// Reset the transactor's LockedBalanceEntry to what it was previously.
	bav._setLockedBalanceEntry(operationData.PrevLockedBalanceEntry)

	// Depending on whether the lockup dealt with DeSo, we should have either a UtxoOp or a PrevTransactorBalanceEntry.
	isDeSoLockup := operationData.PrevLockedBalanceEntry.CreatorPKID.IsZeroPKID()
	if isDeSoLockup {
		// Revert the spent DeSo.
		operationData = utxoOpsForTxn[operationIndex]
		if operationData.Type != OperationTypeSpendBalance {
			return fmt.Errorf("_disconnectDAOCoinLockup: Trying to revert OperationTypeSpendBalance "+
				"but found type %v", operationData.Type)
		}
		if !bytes.Equal(operationData.BalancePublicKey, currentTxn.PublicKey) {
			return fmt.Errorf("_disconnectDAOCoinLockup: Trying to revert OperationTypeSpendBalance but found " +
				"mismatched public keys")
		}
		err := bav._unSpendBalance(operationData.BalanceAmountNanos, currentTxn.PublicKey)
		if err != nil {
			return errors.Wrapf(err, "_disconnectDAOCoinLockup: Problem unSpending balance of %v for the transactor", operationData.BalanceAmountNanos)
		}
		operationIndex--
		if operationIndex < 0 {
			return fmt.Errorf("_disconnectDAOCoinLockup: Trying to revert OperationTypeDAOCoinLockup " +
				"but malformed utxoOpsForTxn")
		}
	} else {
		// Revert the transactor's DAO coin balance.
		bav._setBalanceEntryMappings(operationData.PrevTransactorBalanceEntry, true)
	}

	// By here we only need to disconnect the basic transfer associated with the transaction.
	basicTransferOps := utxoOpsForTxn[:operationIndex]
	err := bav._disconnectBasicTransfer(currentTxn, txnHash, basicTransferOps, blockHeight)
	if err != nil {
		return errors.Wrapf(err, "_disconnectDAOCoinLockup")
	}
	return nil
}

func (bav *UtxoView) _connectUpdateDAOCoinLockupParams(
	txn *MsgDeSoTxn,
	txHash *BlockHash,
	blockHeight uint32,
	verifySignatures bool,
) (_totalInput uint64,
	_totalOutput uint64,
	_utxoOps []*UtxoOperation,
	_err error) {
	return 0, 0, nil, nil
}

func (bav *UtxoView) _disconnectUpdateDAOCoinLockupParams(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32) error {
	return nil
}

func (bav *UtxoView) _connectDAOCoinLockupTransfer(
	txn *MsgDeSoTxn,
	txHash *BlockHash,
	blockHeight uint32,
	verifySignatures bool,
) (_totalInput uint64,
	_totalOutput uint64,
	_utxoOps []*UtxoOperation,
	_err error) {
	return 0, 0, nil, nil
}

func (bav *UtxoView) _disconnectDAOCoinLockupTransfer(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32) error {
	return nil
}

func (bav *UtxoView) _connectDAOCoinUnlock(
	txn *MsgDeSoTxn,
	txHash *BlockHash,
	blockHeight uint32,
	verifySignatures bool,
) (_totalInput uint64,
	_totalOutput uint64,
	_utxoOps []*UtxoOperation,
	_err error) {
	return 0, 0, nil, nil
}

func (bav *UtxoView) _disconnectDAOCoinUnlock(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32) error {
	return nil
}

//
// DB FLUSHES
//

func (bav *UtxoView) _flushLockedBalanceEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	return nil
}

func (bav *UtxoView) _flushYieldCurveEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	return nil
}

//
// Mempool Operations (TBD)
//
