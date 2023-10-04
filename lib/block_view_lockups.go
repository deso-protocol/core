package lib

import (
	"bytes"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

//
// TYPES: LockedBalanceEntry
//

type LockedBalanceEntry struct {
	HODLerPKID                  *PKID
	ProfilePKID                 *PKID
	ExpirationTimestampNanoSecs int64
	BalanceBaseUnits            uint256.Int
	isDeleted                   bool
}

type LockedBalanceEntryKey struct {
	HODLerPKID                      PKID
	ProfilePKID                     PKID
	ExpirationTimestampUnixNanoSecs int64
}

func (lockedBalanceEntry *LockedBalanceEntry) Copy() *LockedBalanceEntry {
	return &LockedBalanceEntry{
		HODLerPKID:                  lockedBalanceEntry.HODLerPKID.NewPKID(),
		ProfilePKID:                 lockedBalanceEntry.ProfilePKID.NewPKID(),
		ExpirationTimestampNanoSecs: lockedBalanceEntry.ExpirationTimestampNanoSecs,
		BalanceBaseUnits:            lockedBalanceEntry.BalanceBaseUnits,
		isDeleted:                   lockedBalanceEntry.isDeleted,
	}
}

func (lockedBalanceEntry *LockedBalanceEntry) Eq(other *LockedBalanceEntry) bool {
	return lockedBalanceEntry.ToMapKey() == other.ToMapKey()
}

func (lockedBalanceEntry *LockedBalanceEntry) ToMapKey() LockedBalanceEntryKey {
	return LockedBalanceEntryKey{
		HODLerPKID:                      *lockedBalanceEntry.HODLerPKID,
		ProfilePKID:                     *lockedBalanceEntry.ProfilePKID,
		ExpirationTimestampUnixNanoSecs: lockedBalanceEntry.ExpirationTimestampNanoSecs,
	}
}

// DeSoEncoder Interface Implementation for LockedBalanceEntry

func (lockedBalanceEntry *LockedBalanceEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, lockedBalanceEntry.HODLerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, lockedBalanceEntry.ProfilePKID, skipMetadata...)...)
	data = append(data, UintToBuf(uint64(lockedBalanceEntry.ExpirationTimestampNanoSecs))...)
	data = append(data, VariableEncodeUint256(&lockedBalanceEntry.BalanceBaseUnits)...)
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

	// ExpirationTimestampNanoSecs
	uint64ExpirationTimestampUnixNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading ExpirationTimestampNanoSecs")
	}
	lockedBalanceEntry.ExpirationTimestampNanoSecs = int64(uint64ExpirationTimestampUnixNanoSecs)

	// BalanceBaseUnits
	balanceBaseUnits, err := VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading BalanceBaseUnits")
	}
	lockedBalanceEntry.BalanceBaseUnits = *balanceBaseUnits

	return err
}

func (lockedBalanceEntry *LockedBalanceEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (lockedBalanceEntry *LockedBalanceEntry) GetEncoderType() EncoderType {
	return EncoderTypeLockedBalanceEntry
}

// Set and Delete Functions for LockedBalanceEntry

func (bav *UtxoView) _setLockedBalanceEntry(lockedBalanceEntry *LockedBalanceEntry) {
	// This function shouldn't be called with nil.
	if lockedBalanceEntry == nil {
		glog.Errorf("_setLockedBalanceEntryMappingsWithPKIDsTimestampType: Called with nil LockedBalanceEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the LockedBalanceEntry in the view.
	bav.LockedBalanceEntryKeyToLockedBalanceEntry[lockedBalanceEntry.ToMapKey()] = lockedBalanceEntry
}

func (bav *UtxoView) _deleteLockedBalanceEntry(lockedBalanceEntry *LockedBalanceEntry) {
	// Create a tombstone entry.
	tombstoneLockedBalanceEntry := *lockedBalanceEntry
	tombstoneLockedBalanceEntry.isDeleted = true

	// Set the LockupYieldCurvePoint as deleted in the view.
	bav._setLockedBalanceEntry(&tombstoneLockedBalanceEntry)
}

// TODO: Get Helper Functions for LockedBalanceEntry

//
// TYPES: LockupYieldCurvePoint
//

type LockupYieldCurvePoint struct {
	ProfilePKID               *PKID
	LockupDurationNanoSecs    int64
	LockupYieldAPYBasisPoints uint64
	isDeleted                 bool
}

type LockupYieldCurvePointKey struct {
	ProfilePKID            *PKID
	LockupDurationNanoSecs int64
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) Copy() *LockupYieldCurvePoint {
	return &LockupYieldCurvePoint{
		ProfilePKID:               lockupYieldCurvePoint.ProfilePKID.NewPKID(),
		LockupDurationNanoSecs:    lockupYieldCurvePoint.LockupDurationNanoSecs,
		LockupYieldAPYBasisPoints: lockupYieldCurvePoint.LockupYieldAPYBasisPoints,
	}
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) Eq(other *LockupYieldCurvePoint) bool {
	return lockupYieldCurvePoint.ToMapKey() == other.ToMapKey()
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) ToMapKey() LockupYieldCurvePointKey {
	return LockupYieldCurvePointKey{
		ProfilePKID:            lockupYieldCurvePoint.ProfilePKID,
		LockupDurationNanoSecs: lockupYieldCurvePoint.LockupDurationNanoSecs,
	}
}

// DeSoEncoder Interface Implementation for LockupYieldCurvePoint

func (lockupYieldCurvePoint *LockupYieldCurvePoint) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, lockupYieldCurvePoint.ProfilePKID, skipMetadata...)...)
	data = append(data, UintToBuf(uint64(lockupYieldCurvePoint.LockupDurationNanoSecs))...)
	data = append(data, UintToBuf(lockupYieldCurvePoint.LockupYieldAPYBasisPoints)...)
	return data
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// ProfilePKID
	lockupYieldCurvePoint.ProfilePKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "LockupYieldCurvePoint.Decode: Problem reading ProfilePKID")
	}

	// LockupDurationNanoSecs
	uint64LockupDurationNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "LockupYieldCurvePoint.Decode: Problem reading LockupDurationNanoSecs")
	}
	lockupYieldCurvePoint.LockupDurationNanoSecs = int64(uint64LockupDurationNanoSecs)

	// LockupYieldAPYBasisPoints
	lockupYieldAPYBasisPoints, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "LockupYieldCurvePoint.Decode: Problem reading LockupYieldAPYBasisPoints")
	}
	lockupYieldCurvePoint.LockupYieldAPYBasisPoints = lockupYieldAPYBasisPoints

	return err
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) GetEncoderType() EncoderType {
	return EncoderTypeLockupYieldCurvePoint
}

// Set and Delete Functions for LockupYieldCurvePoints

func (bav *UtxoView) _setLockupYieldCurvePoint(point *LockupYieldCurvePoint) {
	// This function shouldn't be called with nil.
	if point == nil {
		glog.Errorf("_setLockupYieldCurvePoint: Called with nil LockupYieldCurvePoint; " +
			"this should never happen.")
		return
	}

	// Check if the PKID needs a map added to the view.
	if _, mapExists := bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*point.ProfilePKID]; !mapExists {
		bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*point.ProfilePKID] =
			make(map[LockupYieldCurvePointKey]*LockupYieldCurvePoint)
	}

	// Set the LockupYieldCurvePoint in the view.
	bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*point.ProfilePKID][point.ToMapKey()] = point
}

func (bav *UtxoView) _deleteLockupYieldCurvePoint(point *LockupYieldCurvePoint) {
	// Create a tombstone entry.
	tombstoneLockupYieldCurvePoint := *point
	tombstoneLockupYieldCurvePoint.isDeleted = true

	// Set the LockupYieldCurvePoint as deleted in the view.
	bav._setLockupYieldCurvePoint(&tombstoneLockupYieldCurvePoint)
}

// TODO: Get Helper Functions for LockupYieldCurvePoint

//
// TYPES: CoinLockupMetadata
//

type CoinLockupMetadata struct {
	ProfilePublicKey        *PublicKey
	UnlockTimestampNanoSecs int64
	LockupAmountBaseUnits   *uint256.Int
}

func (txnData *CoinLockupMetadata) GetTxnType() TxnType {
	return TxnTypeCoinLockup
}

func (txnData *CoinLockupMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, UintToBuf(uint64(txnData.UnlockTimestampNanoSecs))...)
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

	// UnlockTimestampNanoSecs
	uint64UnlockTimestampNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinLockupMetadata.FromBytes: Problem reading UnlockTimestampNanoSecs")
	}
	txnData.UnlockTimestampNanoSecs = int64(uint64UnlockTimestampNanoSecs)

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

type UpdateCoinLockupParamsMetadata struct {
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
	//    Note if LockupYieldDurationNanoSecs=0, nothing is modified or added at t=0.
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

func (txnData *UpdateCoinLockupParamsMetadata) GetTxnType() TxnType {
	return TxnTypeUpdateCoinLockupParams
}

func (txnData *UpdateCoinLockupParamsMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, UintToBuf(uint64(txnData.LockupYieldDurationNanoSecs))...)
	data = append(data, UintToBuf(txnData.LockupYieldAPYBasisPoints)...)
	data = append(data, BoolToByte(txnData.RemoveYieldCurvePoint))
	data = append(data, BoolToByte(txnData.NewLockupTransferRestrictions))
	data = append(data, byte(txnData.LockupTransferRestrictionStatus))
	return data, nil
}

func (txnData *UpdateCoinLockupParamsMetadata) FromBytes(data []byte) error {
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

func (txnData *UpdateCoinLockupParamsMetadata) New() DeSoTxnMetadata {
	return &UpdateCoinLockupParamsMetadata{}
}

//
// TYPES: DAOCoinLockupTransferMetadata
//

type CoinLockupTransferMetadata struct {
	RecipientPublicKey              *PublicKey
	ProfilePublicKey                *PublicKey
	ExpirationTimestampUnixNanoSecs int64
	LockedCoinsToTransferBaseUnits  *uint256.Int
}

func (txnData *CoinLockupTransferMetadata) GetTxnType() TxnType {
	return TxnTypeCoinLockupTransfer
}

func (txnData *CoinLockupTransferMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.RecipientPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, UintToBuf(uint64(txnData.ExpirationTimestampUnixNanoSecs))...)
	data = append(data, VariableEncodeUint256(txnData.LockedCoinsToTransferBaseUnits)...)
	return data, nil
}

func (txnData *CoinLockupTransferMetadata) FromBytes(data []byte) error {
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

	// ExpirationTimestampNanoSecs
	uint64ExpirationTimestampUnixNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading ExpirationTimestampNanoSecs")
	}
	txnData.ExpirationTimestampUnixNanoSecs = int64(uint64ExpirationTimestampUnixNanoSecs)

	// LockedDAOCoinToTransferBaseUnits
	txnData.LockedCoinsToTransferBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading LockedDAOCoinToTransferBaseUnits")
	}

	return nil
}

func (txnData *CoinLockupTransferMetadata) New() DeSoTxnMetadata {
	return &CoinLockupTransferMetadata{}
}

//
// TYPES: CoinUnlockMetadata
//

type CoinUnlockMetadata struct {
	ProfilePublicKey       *PublicKey
	CoinsToUnlockBaseUnits *uint256.Int
}

func (txnData *CoinUnlockMetadata) GetTxnType() TxnType {
	return TxnTypeCoinUnlock
}

func (txnData *CoinUnlockMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, VariableEncodeUint256(txnData.CoinsToUnlockBaseUnits)...)
	return data, nil
}

func (txnData *CoinUnlockMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinUnlockMetadata.FromBytes: Problem reading ProfilePublicKey")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// CoinToUnlockBaseUnits
	txnData.CoinsToUnlockBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinUnlockMetadata.FromBytes: Problem reading DAOCoinToUnlockBaseUnits")
	}

	return nil
}

func (txnData *CoinUnlockMetadata) New() DeSoTxnMetadata {
	return &CoinUnlockMetadata{}
}
