package lib

import (
	"bytes"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

// Lockups:
// TODO: Add detailed description of what lockups are used for.

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
	CreatorPKID                     *PKID
	ExpirationTimestampUnixNanoSecs int64
	AmountBaseUnits                 *uint256.Int
	LockedBy                        LockedByType
	isDeleted                       bool
}

type LockedBalanceEntryMapKey struct {
	HODLerPKID                      PKID
	CreatorPKID                     PKID
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

func (lockedBalanceEntry *LockedBalanceEntry) Copy() *LockedBalanceEntry {
	return &LockedBalanceEntry{
		HODLerPKID:                      lockedBalanceEntry.HODLerPKID.NewPKID(),
		CreatorPKID:                     lockedBalanceEntry.CreatorPKID.NewPKID(),
		ExpirationTimestampUnixNanoSecs: lockedBalanceEntry.ExpirationTimestampUnixNanoSecs,
		AmountBaseUnits:                 lockedBalanceEntry.AmountBaseUnits.Clone(),
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
		CreatorPKID:                     *lockedBalanceEntry.CreatorPKID,
		ExpirationTimestampUnixNanoSecs: lockedBalanceEntry.ExpirationTimestampUnixNanoSecs,
		LockedBy:                        lockedBalanceEntry.LockedBy,
	}
}

//
// DeSoEncoder Interface Implementation for LockedBalanceEntry
//

func (lockedBalanceEntry *LockedBalanceEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, lockedBalanceEntry.HODLerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, lockedBalanceEntry.CreatorPKID, skipMetadata...)...)
	data = append(data, UintToBuf(uint64(lockedBalanceEntry.ExpirationTimestampUnixNanoSecs))...)
	data = append(data, VariableEncodeUint256(lockedBalanceEntry.AmountBaseUnits)...)
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

	// CreatorPKID
	lockedBalanceEntry.CreatorPKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading CreatorPKID")
	}

	// ExpirationTimestampUnixNanoSecs
	uint64ExpirationTimestampUnixNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading ExpirationTimestampUnixNanoSecs")
	}
	lockedBalanceEntry.ExpirationTimestampUnixNanoSecs = int64(uint64ExpirationTimestampUnixNanoSecs)

	// AmountBaseUnits
	lockedBalanceEntry.AmountBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading AmountBaseUnits")
	}

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

//
// TYPES: DAOCoinLockupMetadata
//

type DAOCoinLockupMetadata struct {
	ProfilePublicKey       *PublicKey
	LockupDurationNanoSecs int64
	LockupAmountBaseUnits  *uint256.Int
}

func (txnData *DAOCoinLockupMetadata) GetTxnType() TxnType {
	return TxnTypeDAOCoinLockup
}

func (txnData *DAOCoinLockupMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, UintToBuf(uint64(txnData.LockupDurationNanoSecs))...)
	data = append(data, VariableEncodeUint256(txnData.LockupAmountBaseUnits)...)
	return data, nil
}

func (txnData *DAOCoinLockupMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupMetadata.FromBytes: Problem reading ProfilePublicKey")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// ExpirationTimestampUnixNanoSecs
	uint64LockupDurationNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupMetadata.FromBytes: Problem reading LockupDurationNanoSecs")
	}
	txnData.LockupDurationNanoSecs = int64(uint64LockupDurationNanoSecs)

	// LockupAmountBaseUnits
	txnData.LockupAmountBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupMetadata.FromBytes: Problem reading LockupAmountBaseUnits")
	}

	return nil
}

func (txnData *DAOCoinLockupMetadata) New() DeSoTxnMetadata {
	return &DAOCoinLockupMetadata{}
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
