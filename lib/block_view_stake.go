package lib

import (
	"bytes"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

//
// TYPES: StakeEntry
//

type StakeEntry struct {
	StakeID          *BlockHash
	StakerPKID       *PKID
	ValidatorPKID    *PKID
	StakeAmountNanos *uint256.Int
	ExtraData        map[string][]byte
}

type StakeMapKey struct {
	StakerPKID    PKID
	ValidatorPKID PKID
}

func (stakeEntry *StakeEntry) Copy() *StakeEntry {
	// Copy ExtraData.
	extraDataCopy := make(map[string][]byte)
	for key, value := range stakeEntry.ExtraData {
		extraDataCopy[key] = value
	}

	return &StakeEntry{
		StakeID:          stakeEntry.StakeID.NewBlockHash(),
		StakerPKID:       stakeEntry.StakerPKID.NewPKID(),
		ValidatorPKID:    stakeEntry.ValidatorPKID.NewPKID(),
		StakeAmountNanos: stakeEntry.StakeAmountNanos.Clone(),
		ExtraData:        extraDataCopy,
	}
}

func (stakeEntry *StakeEntry) ToMapKey() StakeMapKey {
	return StakeMapKey{
		StakerPKID:    *stakeEntry.StakerPKID,
		ValidatorPKID: *stakeEntry.ValidatorPKID,
	}
}

func (stakeEntry *StakeEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, stakeEntry.StakeID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, stakeEntry.StakerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, stakeEntry.ValidatorPKID, skipMetadata...)...)
	data = append(data, EncodeUint256(stakeEntry.StakeAmountNanos)...)
	data = append(data, EncodeExtraData(stakeEntry.ExtraData)...)
	return data
}

func (stakeEntry *StakeEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// StakeID
	stakeID := &BlockHash{}
	if exist, err := DecodeFromBytes(stakeID, rr); exist && err == nil {
		stakeEntry.StakeID = stakeID
	} else if err != nil {
		return errors.Wrapf(err, "StakeEntry.Decode: Problem reading StakeID: ")
	}

	// StakerPKID
	stakerPKID := &PKID{}
	if exist, err := DecodeFromBytes(stakerPKID, rr); exist && err == nil {
		stakeEntry.StakerPKID = stakerPKID
	} else if err != nil {
		return errors.Wrapf(err, "StakeEntry.Decode: Problem reading StakerPKID: ")
	}

	// ValidatorPKID
	validatorPKID := &PKID{}
	if exist, err := DecodeFromBytes(validatorPKID, rr); exist && err == nil {
		stakeEntry.ValidatorPKID = validatorPKID
	} else if err != nil {
		return errors.Wrapf(err, "StakeEntry.Decode: Problem reading ValidatorPKID: ")
	}

	// StakeAmountNanos
	stakeEntry.StakeAmountNanos, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "StakeEntry.Decode: Problem reading StakeAmountNanos: ")
	}

	// ExtraData
	stakeEntry.ExtraData, err = DecodeExtraData(rr)
	if err != nil {
		return errors.Wrapf(err, "StakeEntry.Decode: Problem reading ExtraData: ")
	}

	return err
}

func (stakeEntry *StakeEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (stakeEntry *StakeEntry) GetEncoderType() EncoderType {
	return EncoderTypeStakeEntry
}

//
// TYPES: LockedStakeEntry
//

type LockedStakeEntry struct {
	LockedStakeID       *BlockHash
	StakerPKID          *PKID
	ValidatorPKID       *PKID
	LockedAmountNanos   *uint256.Int
	LockedAtEpochNumber uint64
	ExtraData           map[string][]byte
}

type LockedStakeEntryMapKey struct {
	StakerPKID          PKID
	ValidatorPKID       PKID
	LockedAtEpochNumber uint64
}

func (lockedStakeEntry *LockedStakeEntry) Copy() *LockedStakeEntry {
	// Copy ExtraData.
	extraDataCopy := make(map[string][]byte)
	for key, value := range lockedStakeEntry.ExtraData {
		extraDataCopy[key] = value
	}

	return &LockedStakeEntry{
		LockedStakeID:       lockedStakeEntry.LockedStakeID.NewBlockHash(),
		StakerPKID:          lockedStakeEntry.StakerPKID.NewPKID(),
		ValidatorPKID:       lockedStakeEntry.ValidatorPKID.NewPKID(),
		LockedAmountNanos:   lockedStakeEntry.LockedAmountNanos.Clone(),
		LockedAtEpochNumber: lockedStakeEntry.LockedAtEpochNumber,
		ExtraData:           extraDataCopy,
	}
}

func (lockedStakeEntry *LockedStakeEntry) ToMapKey() LockedStakeEntryMapKey {
	return LockedStakeEntryMapKey{
		StakerPKID:          *lockedStakeEntry.StakerPKID,
		ValidatorPKID:       *lockedStakeEntry.ValidatorPKID,
		LockedAtEpochNumber: lockedStakeEntry.LockedAtEpochNumber,
	}
}

func (lockedStakeEntry *LockedStakeEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, lockedStakeEntry.LockedStakeID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, lockedStakeEntry.StakerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, lockedStakeEntry.ValidatorPKID, skipMetadata...)...)
	data = append(data, EncodeUint256(lockedStakeEntry.LockedAmountNanos)...)
	data = append(data, UintToBuf(lockedStakeEntry.LockedAtEpochNumber)...)
	data = append(data, EncodeExtraData(lockedStakeEntry.ExtraData)...)
	return data
}

func (lockedStakeEntry *LockedStakeEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// LockedStakeID
	lockedStakeID := &BlockHash{}
	if exist, err := DecodeFromBytes(lockedStakeID, rr); exist && err == nil {
		lockedStakeEntry.LockedStakeID = lockedStakeID
	} else if err != nil {
		return errors.Wrapf(err, "LockedStakeEntry.Decode: Problem reading LockedStakeID: ")
	}

	// StakerPKID
	stakerPKID := &PKID{}
	if exist, err := DecodeFromBytes(stakerPKID, rr); exist && err == nil {
		lockedStakeEntry.StakerPKID = stakerPKID
	} else if err != nil {
		return errors.Wrapf(err, "LockedStakeEntry.Decode: Problem reading StakerPKID: ")
	}

	// ValidatorPKID
	validatorPKID := &PKID{}
	if exist, err := DecodeFromBytes(validatorPKID, rr); exist && err == nil {
		lockedStakeEntry.ValidatorPKID = validatorPKID
	} else if err != nil {
		return errors.Wrapf(err, "LockedStakeEntry.Decode: Problem reading ValidatorPKID: ")
	}

	// LockedAmountNanos
	lockedStakeEntry.LockedAmountNanos, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedStakeEntry.Decode: Problem reading LockedAmountNanos: ")
	}

	// LockedAtEpochNumber
	lockedStakeEntry.LockedAtEpochNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedStakeEntry.Decode: Problem reading LockedAtEpochNumber: ")
	}

	// ExtraData
	lockedStakeEntry.ExtraData, err = DecodeExtraData(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedStakeEntry.Decode: Problem reading ExtraData: ")
	}

	return err
}

func (lockedStakeEntry *LockedStakeEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (lockedStakeEntry *LockedStakeEntry) GetEncoderType() EncoderType {
	return EncoderTypeLockedStakeEntry
}

//
// TYPES: StakeMetadata
//

type StakeMetadata struct {
	ValidatorPublicKey *PublicKey
	StakeAmountNanos   *uint256.Int
}

func (txnData *StakeMetadata) GetTxnType() TxnType {
	return TxnTypeStake
}

func (txnData *StakeMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ValidatorPublicKey.ToBytes())...)
	data = append(data, EncodeUint256(txnData.StakeAmountNanos)...)
	return data, nil
}

func (txnData *StakeMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ValidatorPublicKey
	validatorPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "StakeMetadata.FromBytes: Problem reading ValidatorPublicKey: ")
	}
	txnData.ValidatorPublicKey = NewPublicKey(validatorPublicKeyBytes)

	// StakeAmountNanos
	txnData.StakeAmountNanos, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "StakeMetadata.FromBytes: Problem reading StakeAmountNanos: ")
	}

	return nil
}

func (txnData *StakeMetadata) New() DeSoTxnMetadata {
	return &StakeMetadata{}
}

//
// TYPES: UnstakeMetadata
//

type UnstakeMetadata struct {
	ValidatorPublicKey *PublicKey
	UnstakeAmountNanos *uint256.Int
}

func (txnData *UnstakeMetadata) GetTxnType() TxnType {
	return TxnTypeUnstake
}

func (txnData *UnstakeMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ValidatorPublicKey.ToBytes())...)
	data = append(data, EncodeUint256(txnData.UnstakeAmountNanos)...)
	return data, nil
}

func (txnData *UnstakeMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ValidatorPublicKey
	validatorPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UnstakeMetadata.FromBytes: Problem reading ValidatorPublicKey: ")
	}
	txnData.ValidatorPublicKey = NewPublicKey(validatorPublicKeyBytes)

	// UnstakeAmountNanos
	txnData.UnstakeAmountNanos, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "UnstakeMetadata.FromBytes: Problem reading UnstakeAmountNanos: ")
	}

	return nil
}

func (txnData *UnstakeMetadata) New() DeSoTxnMetadata {
	return &UnstakeMetadata{}
}

//
// TYPES: UnlockStakeMetadata
//

type UnlockStakeMetadata struct {
	ValidatorPublicKey *PublicKey
	StartEpochNumber   uint64
	EndEpochNumber     uint64
}

func (txnData *UnlockStakeMetadata) GetTxnType() TxnType {
	return TxnTypeUnlockStake
}

func (txnData *UnlockStakeMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ValidatorPublicKey.ToBytes())...)
	data = append(data, UintToBuf(txnData.StartEpochNumber)...)
	data = append(data, UintToBuf(txnData.EndEpochNumber)...)
	return data, nil
}

func (txnData *UnlockStakeMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ValidatorPublicKey
	validatorPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UnlockStakeMetadata.FromBytes: Problem reading ValidatorPublicKey: ")
	}
	txnData.ValidatorPublicKey = NewPublicKey(validatorPublicKeyBytes)

	// StartEpochNumber
	txnData.StartEpochNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UnlockStakeMetadata.FromBytes: Problem reading StartEpochNumber: ")
	}

	// EndEpochNumber
	txnData.EndEpochNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UnlockStakeMetadata.FromBytes: Problem reading EndEpochNumber: ")
	}

	return nil
}

func (txnData *UnlockStakeMetadata) New() DeSoTxnMetadata {
	return &UnlockStakeMetadata{}
}

//
// TYPES: StakeTxindexMetadata
//

type StakeTxindexMetadata struct {
	StakerPublicKeyBase58Check    string
	ValidatorPublicKeyBase58Check string
	StakeAmountNanos              *uint256.Int
}

func (txindexMetadata *StakeTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(txindexMetadata.StakerPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(txindexMetadata.ValidatorPublicKeyBase58Check))...)
	data = append(data, EncodeUint256(txindexMetadata.StakeAmountNanos)...)
	return data
}

func (txindexMetadata *StakeTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// StakerPublicKeyBase58Check
	stakerPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "StakeTxindexMetadata.Decode: Problem reading StakerPublicKeyBase58Check: ")
	}
	txindexMetadata.StakerPublicKeyBase58Check = string(stakerPublicKeyBase58CheckBytes)

	// ValidatorPublicKeyBase58Check
	validatorPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "StakeTxindexMetadata.Decode: Problem reading ValidatorPublicKeyBase58Check: ")
	}
	txindexMetadata.ValidatorPublicKeyBase58Check = string(validatorPublicKeyBase58CheckBytes)

	// StakeAmountNanos
	txindexMetadata.StakeAmountNanos, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "StakeTxindexMetadata.Decode: Problem reading StakeAmountNanos: ")
	}

	return nil
}

func (txindexMetadata *StakeTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txindexMetadata *StakeTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeStakeTxindexMetadata
}

//
// TYPES: UnstakeTxindexMetadata
//

type UnstakeTxindexMetadata struct {
	StakerPublicKeyBase58Check    string
	ValidatorPublicKeyBase58Check string
	UnstakeAmountNanos            *uint256.Int
}

func (txindexMetadata *UnstakeTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(txindexMetadata.StakerPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(txindexMetadata.ValidatorPublicKeyBase58Check))...)
	data = append(data, EncodeUint256(txindexMetadata.UnstakeAmountNanos)...)
	return data
}

func (txindexMetadata *UnstakeTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// StakerPublicKeyBase58Check
	stakerPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UnstakeTxindexMetadata.Decode: Problem reading StakerPublicKeyBase58Check: ")
	}
	txindexMetadata.StakerPublicKeyBase58Check = string(stakerPublicKeyBase58CheckBytes)

	// ValidatorPublicKeyBase58Check
	validatorPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UnstakeTxindexMetadata.Decode: Problem reading ValidatorPublicKeyBase58Check: ")
	}
	txindexMetadata.ValidatorPublicKeyBase58Check = string(validatorPublicKeyBase58CheckBytes)

	// UnstakeAmountNanos
	txindexMetadata.UnstakeAmountNanos, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "UnstakeTxindexMetadata.Decode: Problem reading UnstakeAmountNanos: ")
	}

	return nil
}

func (txindexMetadata *UnstakeTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txindexMetadata *UnstakeTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeUnstakeTxindexMetadata
}

//
// TYPES: UnlockStakeTxindexMetadata
//

type UnlockStakeTxindexMetadata struct {
	StakerPublicKeyBase58Check    string
	ValidatorPublicKeyBase58Check string
	StartEpochNumber              uint64
	EndEpochNumber                uint64
	TotalUnlockedAmountNanos      *uint256.Int
}

func (txindexMetadata *UnlockStakeTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(txindexMetadata.StakerPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(txindexMetadata.ValidatorPublicKeyBase58Check))...)
	data = append(data, UintToBuf(txindexMetadata.StartEpochNumber)...)
	data = append(data, UintToBuf(txindexMetadata.EndEpochNumber)...)
	data = append(data, EncodeUint256(txindexMetadata.TotalUnlockedAmountNanos)...)
	return data
}

func (txindexMetadata *UnlockStakeTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// StakerPublicKeyBase58Check
	stakerPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UnlockStakeTxindexMetadata.Decode: Problem reading StakerPublicKeyBase58Check: ")
	}
	txindexMetadata.StakerPublicKeyBase58Check = string(stakerPublicKeyBase58CheckBytes)

	// ValidatorPublicKeyBase58Check
	validatorPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UnlockStakeTxindexMetadata.Decode: Problem reading ValidatorPublicKeyBase58Check: ")
	}
	txindexMetadata.ValidatorPublicKeyBase58Check = string(validatorPublicKeyBase58CheckBytes)

	// StartEpochNumber
	txindexMetadata.StartEpochNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UnlockStakeTxindexMetadata.Decode: Problem reading StartEpochNumber: ")
	}

	// EndEpochNumber
	txindexMetadata.EndEpochNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UnlockStakeTxindexMetadata.Decode: Problem reading EndEpochNumber: ")
	}

	// TotalUnlockedAmountNanos
	txindexMetadata.TotalUnlockedAmountNanos, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "UnlockStakeTxindexMetadata.Decode: Problem reading TotalUnlockedAmountNanos: ")
	}

	return nil
}

func (txindexMetadata *UnlockStakeTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txindexMetadata *UnlockStakeTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeUnlockStakeTxindexMetadata
}
