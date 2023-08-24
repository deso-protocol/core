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
	LockedByCreator LockedByType = iota
	LockedByHODLer
	LockedByOther
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
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading HODLerPKID: ")
	}

	// CreatorPKID
	lockedBalanceEntry.CreatorPKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading CreatorPKID: ")
	}

	// ExpirationTimestampUnixNanoSecs
	uint64ExpirationTimestampUnixNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading ExpirationTimestampUnixNanoSecs: ")
	}
	lockedBalanceEntry.ExpirationTimestampUnixNanoSecs = int64(uint64ExpirationTimestampUnixNanoSecs)

	// AmountBaseUnits
	lockedBalanceEntry.AmountBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading AmountBaseUnits: ")
	}

	// LockedBy
	lockedBalanceEntry.LockedBy, err = rr.ReadByte()
	if err != nil {
		return errors.Wrap(err, "LockedBalanceEntry.Decode: Problem reading LockedBy: ")
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
	ProfilePublicKey                *PublicKey
	ExpirationTimestampUnixNanoSecs int64
	LockupAmountBaseUnits           *uint256.Int
}

func (txnData *DAOCoinLockupMetadata) GetTxnType() TxnType {
	return TxnTypeDAOCoinLockup
}

func (txnData *DAOCoinLockupMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, UintToBuf(uint64(txnData.ExpirationTimestampUnixNanoSecs))...)
	data = append(data, VariableEncodeUint256(txnData.LockupAmountBaseUnits)...)
	return data, nil
}

func (txnData *DAOCoinLockupMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupMetadata.FromBytes: Problem reading ProfilePublicKey: ")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// ExpirationTimestampUnixNanoSecs
	uint64ExpirationTimestampUnixNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupMetadata.FromBytes: Problem reading ExpirationTimestampUnixNanoSecs: ")
	}
	txnData.ExpirationTimestampUnixNanoSecs = int64(uint64ExpirationTimestampUnixNanoSecs)

	// LockupAmountBaseUnits
	txnData.LockupAmountBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupMetadata.FromBytes: Problem reading LockupAmountBaseUnits: ")
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
	DAOCoinLockupYieldAPYBasisPoints uint64
	LockupTransferRestrictionStatus  TransferRestrictionStatus
	MinimumLockupDurationNanoseconds int64
}

func (txnData *UpdateDAOCoinLockupParamsMetadata) GetTxnType() TxnType {
	return TxnTypeUpdateDAOCoinLockupParams
}

func (txnData *UpdateDAOCoinLockupParamsMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, UintToBuf(txnData.DAOCoinLockupYieldAPYBasisPoints)...)
	data = append(data, byte(txnData.LockupTransferRestrictionStatus))
	data = append(data, UintToBuf(uint64(txnData.MinimumLockupDurationNanoseconds))...)
	return data, nil
}

func (txnData *UpdateDAOCoinLockupParamsMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	daoCoinLockupYieldAPYBasisPoints, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading DAOCoinLockupYieldAPYBasisPoints")
	}
	txnData.DAOCoinLockupYieldAPYBasisPoints = daoCoinLockupYieldAPYBasisPoints

	lockedStatusByte, err := rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading LockupTransferRestrictionStatus")
	}
	txnData.LockupTransferRestrictionStatus = TransferRestrictionStatus(lockedStatusByte)

	uint64MinimumLockupDurationNanoseconds, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading MinimumLockupDurationNanoseconds")
	}
	txnData.MinimumLockupDurationNanoseconds = int64(uint64MinimumLockupDurationNanoseconds)

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
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading RecipientPublicKey: ")
	}
	txnData.RecipientPublicKey = NewPublicKey(recipientPublicKeyBytes)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading ProfilePublicKey: ")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// ExpirationTimestampUnixNanoSecs
	uint64ExpirationTimestampUnixNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading ExpirationTimestampUnixNanoSecs: ")
	}
	txnData.ExpirationTimestampUnixNanoSecs = int64(uint64ExpirationTimestampUnixNanoSecs)

	// LockedDAOCoinToTransferBaseUnits
	txnData.LockedDAOCoinToTransferBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading LockedDAOCoinToTransferBaseUnits: ")
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
		return errors.Wrapf(err, "DAOCoinUnlockMetadata.FromBytes: Problem reading ProfilePublicKey: ")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// LockedDAOCoinToTransferBaseUnits
	txnData.DAOCoinToUnlockBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinUnlockMetadata.FromBytes: Problem reading DAOCoinToUnlockBaseUnits: ")
	}

	return nil
}

func (txnData *DAOCoinUnlockMetadata) New() DeSoTxnMetadata {
	return &DAOCoinUnlockMetadata{}
}
