package lib

import (
	"bytes"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"sort"
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
	isDeleted        bool
}

type StakeMapKey struct {
	ValidatorPKID PKID
	StakerPKID    PKID
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
		isDeleted:        stakeEntry.isDeleted,
	}
}

func (stakeEntry *StakeEntry) Eq(other *StakeEntry) bool {
	return stakeEntry.StakeID.IsEqual(other.StakeID)
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
	isDeleted           bool
}

type LockedStakeMapKey struct {
	ValidatorPKID       PKID
	StakerPKID          PKID
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
		isDeleted:           lockedStakeEntry.isDeleted,
	}
}

func (lockedStakeEntry *LockedStakeEntry) Eq(other *LockedStakeEntry) bool {
	return lockedStakeEntry.LockedStakeID.IsEqual(other.LockedStakeID)
}

func (lockedStakeEntry *LockedStakeEntry) ToMapKey() LockedStakeMapKey {
	return LockedStakeMapKey{
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

//
// DB UTILS
//

func DBKeyForStakeByValidatorByStaker(stakeEntry *StakeEntry) []byte {
	var data []byte
	data = append(data, Prefixes.PrefixStakeByValidatorByStaker...)
	data = append(data, stakeEntry.ValidatorPKID.ToBytes()...)
	data = append(data, stakeEntry.StakerPKID.ToBytes()...)
	return data
}

func DBKeyForLockedStakeByValidatorByStakerByLockedAt(lockedStakeEntry *LockedStakeEntry) []byte {
	var data []byte
	data = append(data, Prefixes.PrefixLockedStakeByValidatorByStakerByLockedAt...)
	data = append(data, lockedStakeEntry.ValidatorPKID.ToBytes()...)
	data = append(data, lockedStakeEntry.StakerPKID.ToBytes()...)
	data = append(data, UintToBuf(lockedStakeEntry.LockedAtEpochNumber)...)
	return data
}

func DBGetStakeEntry(
	handle *badger.DB,
	snap *Snapshot,
	validatorPKID *PKID,
	stakerPKID *PKID,
) (*StakeEntry, error) {
	var ret *StakeEntry
	var err error
	handle.View(func(txn *badger.Txn) error {
		ret, err = DBGetStakeEntryWithTxn(txn, snap, validatorPKID, stakerPKID)
		return nil
	})
	return ret, err
}

func DBGetStakeEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorPKID *PKID,
	stakerPKID *PKID,
) (*StakeEntry, error) {
	// Retrieve StakeEntry from db.
	key := DBKeyForStakeByValidatorByStaker(&StakeEntry{ValidatorPKID: validatorPKID, StakerPKID: stakerPKID})
	stakeEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetStakeByValidatorByStaker: problem retrieving StakeEntry")
	}

	// Decode StakeEntry from bytes.
	stakeEntry := &StakeEntry{}
	rr := bytes.NewReader(stakeEntryBytes)
	if exist, err := DecodeFromBytes(stakeEntry, rr); !exist || err != nil {
		return nil, errors.Wrapf(err, "DBGetStakeByValidatorByStaker: problem decoding StakeEntry")
	}
	return stakeEntry, nil
}

func DBGetLockedStakeEntry(
	handle *badger.DB,
	snap *Snapshot,
	validatorPKID *PKID,
	stakerPKID *PKID,
	lockedAtEpochNumber uint64,
) (*LockedStakeEntry, error) {
	var ret *LockedStakeEntry
	var err error
	handle.View(func(txn *badger.Txn) error {
		ret, err = DBGetLockedStakeEntryWithTxn(
			txn, snap, validatorPKID, stakerPKID, lockedAtEpochNumber,
		)
		return nil
	})
	return ret, err
}

func DBGetLockedStakeEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorPKID *PKID,
	stakerPKID *PKID,
	lockedAtEpochNumber uint64,
) (*LockedStakeEntry, error) {
	// Retrieve LockedStakeEntry from db.
	key := DBKeyForLockedStakeByValidatorByStakerByLockedAt(&LockedStakeEntry{
		ValidatorPKID:       validatorPKID,
		StakerPKID:          stakerPKID,
		LockedAtEpochNumber: lockedAtEpochNumber,
	})
	lockedStakeEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(
			err, "DBGetLockedStakeByValidatorByStakerByLockedAt: problem retrieving LockedStakeEntry",
		)
	}

	// Decode LockedStakeEntry from bytes.
	lockedStakeEntry := &LockedStakeEntry{}
	rr := bytes.NewReader(lockedStakeEntryBytes)
	if exist, err := DecodeFromBytes(lockedStakeEntry, rr); !exist || err != nil {
		return nil, errors.Wrapf(
			err, "DBGetLockedStakeByValidatorByStakerByLockedAt: problem retrieving LockedStakeEntry",
		)
	}
	return lockedStakeEntry, nil
}

func DBGetLockedStakeEntriesInRange(
	handle *badger.DB,
	snap *Snapshot,
	validatorPKID *PKID,
	stakerPKID *PKID,
	startEpochNumber uint64,
	endEpochNumber uint64,
) ([]*LockedStakeEntry, error) {
	var ret []*LockedStakeEntry
	var err error
	handle.View(func(txn *badger.Txn) error {
		ret, err = DBGetLockedStakeEntriesInRangeWithTxn(
			txn, snap, validatorPKID, stakerPKID, startEpochNumber, endEpochNumber,
		)
		return nil
	})
	return ret, err
}

func DBGetLockedStakeEntriesInRangeWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorPKID *PKID,
	stakerPKID *PKID,
	startEpochNumber uint64,
	endEpochNumber uint64,
) ([]*LockedStakeEntry, error) {
	// Retrieve LockedStakeEntries from db matching ValidatorPKID, StakerPKID, and
	// StartEpochNumber <= LockedAtEpochNumber <= EndEpochNumber.
	// TODO
	return nil, nil
}

func DBPutStakeEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	stakeEntry *StakeEntry,
	blockHeight uint64,
) error {
	if stakeEntry == nil {
		return nil
	}

	// Set StakeEntry in PrefixStakeByValidatorByStaker.
	key := DBKeyForStakeByValidatorByStaker(stakeEntry)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, stakeEntry)); err != nil {
		return errors.Wrapf(
			err, "DBPutStakeWithTxn: problem storing StakeEntry in index PrefixStakeByValidatorByStaker",
		)
	}

	return nil
}

func DBPutLockedStakeEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	lockedStakeEntry *LockedStakeEntry,
	blockHeight uint64,
) error {
	if lockedStakeEntry == nil {
		return nil
	}

	// Set LockedStakeEntry in PrefixLockedStakeByValidatorByStakerByLockedAt.
	key := DBKeyForLockedStakeByValidatorByStakerByLockedAt(lockedStakeEntry)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, lockedStakeEntry)); err != nil {
		return errors.Wrapf(
			err, "DBPutLockedStakeWithTxn: problem storing LockedStakeEntry in index PrefixLockedStakeByValidatorByStakerByLockedAt",
		)
	}

	return nil
}

func DBDeleteStakeEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	stakeEntry *StakeEntry,
	blockHeight uint64,
) error {
	if stakeEntry == nil {
		return nil
	}

	// Delete StakeEntry from PrefixStakeByValidatorByStaker.
	key := DBKeyForStakeByValidatorByStaker(stakeEntry)
	if err := DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(
			err, "DBDeleteStakeWithTxn: problem deleting StakeEntry from index PrefixStakeByValidatorByStaker",
		)
	}

	return nil
}

func DBDeleteLockedStakeEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	lockedStakeEntry *LockedStakeEntry,
	blockHeight uint64,
) error {
	if lockedStakeEntry == nil {
		return nil
	}

	// Delete LockedStakeEntry from PrefixLockedStakeByValidatorByStakerByLockedAt.
	key := DBKeyForLockedStakeByValidatorByStakerByLockedAt(lockedStakeEntry)
	if err := DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(
			err, "DBDeleteLockedStakeWithTxn: problem deleting StakeEntry from index PrefixLockedStakeByValidatorByStakerByLockedAt",
		)
	}

	return nil
}

//
// BLOCKCHAIN UTILS
//

func (bc *Blockchain) CreateStakeTxn(
	transactorPublicKey []byte,
	metadata *StakeMetadata,
	extraData map[string][]byte,
	minFeeRateNanosPerKB uint64,
	mempool *DeSoMempool,
	additionalOutputs []*DeSoOutput,
) (
	_txn *MsgDeSoTxn,
	_totalInput uint64,
	_changeAmount uint64,
	_fees uint64,
	_err error,
) {
	return nil, 0, 0, 0, nil
}

func (bc *Blockchain) CreateUnstakeTxn(
	transactorPublicKey []byte,
	metadata *UnstakeMetadata,
	extraData map[string][]byte,
	minFeeRateNanosPerKB uint64,
	mempool *DeSoMempool,
	additionalOutputs []*DeSoOutput,
) (
	_txn *MsgDeSoTxn,
	_totalInput uint64,
	_changeAmount uint64,
	_fees uint64,
	_err error,
) {
	// Create a txn containing the metadata fields.
	txn := &MsgDeSoTxn{
		PublicKey: transactorPublicKey,
		TxnMeta:   metadata,
		TxOutputs: additionalOutputs,
		ExtraData: extraData,
		// We wait to compute the signature until
		// we've added all the inputs and change.
	}

	// Create a new UtxoView. If we have access to a mempool object, use
	// it to get an augmented view that factors in pending transactions.
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres, bc.snapshot)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrap(
			err, "Blockchain.CreateUnstakeTxn: problem creating new utxo view: ",
		)
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(
				err, "Blockchain.CreateUnstakeTxn: problem getting augmented utxo view from mempool: ",
			)
		}
	}

	// Validate txn metadata.
	if err = utxoView.IsValidUnstakeMetadata(transactorPublicKey, metadata); err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateUnstakeTxn: invalid txn metadata: ",
		)
	}

	// We don't need to make any tweaks to the amount because
	// it's basically a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err := bc.AddInputsAndChangeToTransaction(
		txn, minFeeRateNanosPerKB, mempool,
	)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateUnstakeTxn: problem adding inputs: ",
		)
	}

	// Validate that the transaction has at least one input, even if it all goes
	// to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, errors.New(
			"Blockchain.CreateUnstakeTxn: txn has zero inputs, try increasing the fee rate",
		)
	}

	// Sanity-check that the spendAmount is zero.
	if spendAmount != 0 {
		return nil, 0, 0, 0, fmt.Errorf(
			"Blockchain.CreateUnstakeTxn: spend amount is non-zero: %d", spendAmount,
		)
	}
	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateUnlockStakeTxn(
	transactorPublicKey []byte,
	metadata *UnlockStakeMetadata,
	extraData map[string][]byte,
	minFeeRateNanosPerKB uint64,
	mempool *DeSoMempool,
	additionalOutputs []*DeSoOutput,
) (
	_txn *MsgDeSoTxn,
	_totalInput uint64,
	_changeAmount uint64,
	_fees uint64,
	_err error,
) {
	return nil, 0, 0, 0, nil
}

//
// UTXO VIEW UTILS
//

func (bav *UtxoView) _connectStake(
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
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight {
		return 0, 0, nil, RuleErrorProofofStakeTxnBeforeBlockHeight
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeStake {
		return 0, 0, nil, fmt.Errorf(
			"_connectStake: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Connect a basic transfer to get the total input and the
	// total output without considering the txn metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: ")
	}
	if verifySignatures {
		// _connectBasicTransfer has already checked that the txn is signed
		// by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*StakeMetadata)

	// Validate the txn metadata.
	if err = bav.IsValidStakeMetadata(txn.PublicKey, txMeta, blockHeight); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: ")
	}

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return 0, 0, nil, RuleErrorInvalidStakerPKID
	}

	// Convert ValidatorPublicKey to ValidatorPKID.
	validatorPKIDEntry := bav.GetPKIDForPublicKey(txMeta.ValidatorPublicKey.ToBytes())
	if validatorPKIDEntry == nil || validatorPKIDEntry.isDeleted {
		return 0, 0, nil, RuleErrorInvalidValidatorPKID
	}
	prevValidatorEntry, err := bav.GetValidatorByPKID(validatorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: ")
	}
	if prevValidatorEntry == nil || prevValidatorEntry.isDeleted || prevValidatorEntry.DisableDelegatedStake {
		return 0, 0, nil, RuleErrorInvalidValidatorPKID
	}
	// Delete the existing ValidatorEntry.
	bav._deleteValidatorEntryMappings(prevValidatorEntry)

	// TODO: decrease staker's DESO balance.

	// Check if there is an existing StakeEntry that will be updated.
	// The existing StakeEntry will be restored if we disconnect this transaction.
	prevStakeEntry, err := bav.GetStakeEntry(validatorPKIDEntry.PKID, transactorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: ")
	}
	// Delete the existing StakeEntry, if exists.
	if prevStakeEntry != nil {
		bav._deleteStakeEntryMappings(prevStakeEntry)
	}

	// Set StakeID only if this is a new StakeEntry.
	stakeID := txHash
	if prevStakeEntry != nil {
		stakeID = prevStakeEntry.StakeID
	}

	// Calculate StakeAmountNanos.
	stakeAmountNanos := txMeta.StakeAmountNanos
	if prevStakeEntry != nil {
		stakeAmountNanos, err = SafeUint256().Add(stakeAmountNanos, prevStakeEntry.StakeAmountNanos)
		if err != nil {
			return 0, 0, nil, fmt.Errorf(
				"_connectStake: %v: %v", RuleErrorInvalidStakeAmountNanos, err,
			)
		}
	}

	// Retrieve existing ExtraData to merge with any new ExtraData.
	var prevExtraData map[string][]byte
	if prevStakeEntry != nil {
		prevExtraData = prevStakeEntry.ExtraData
	}

	// Construct new StakeEntry from metadata.
	currentStakeEntry := &StakeEntry{
		StakeID:          stakeID,
		StakerPKID:       transactorPKIDEntry.PKID,
		ValidatorPKID:    validatorPKIDEntry.PKID,
		StakeAmountNanos: stakeAmountNanos,
		ExtraData:        mergeExtraData(prevExtraData, txn.ExtraData),
	}
	// Set the new StakeEntry.
	bav._setStakeEntryMappings(currentStakeEntry)

	// Construct a new ValidatorEntry.
	currentValidatorEntry := prevValidatorEntry.Copy()
	currentValidatorEntry.TotalStakeAmountNanos, err = SafeUint256().Add(
		currentValidatorEntry.TotalStakeAmountNanos, txMeta.StakeAmountNanos,
	)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectStake: %v: %v", RuleErrorInvalidStakeAmountNanos, err,
		)
	}
	// Set the new ValidatorEntry.
	bav._setValidatorEntryMappings(currentValidatorEntry)

	// Increase the GlobalStakeAmountNanos.
	prevGlobalStakeAmountNanos, err := bav.GetGlobalStakeAmountNanos()
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: error retrieving GlobalStakeAmountNanos: ")
	}
	globalStakeAmountNanos, err := SafeUint256().Add(prevGlobalStakeAmountNanos, txMeta.StakeAmountNanos)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: error calculating updated GlobalStakeAmountNanos: ")
	}
	// Set the new GlobalStakeAmountNanos.
	bav._setGlobalStakeAmountNanos(globalStakeAmountNanos)

	// Add a UTXO operation
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                       OperationTypeRegisterAsValidator,
		PrevValidatorEntry:         prevValidatorEntry,
		PrevStakeEntries:           []*StakeEntry{prevStakeEntry},
		PrevGlobalStakeAmountNanos: prevGlobalStakeAmountNanos,
	})
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectStake(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// Validate the last operation is a Stake operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectStake: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	operationData := utxoOpsForTxn[operationIndex]
	if operationData.Type != OperationTypeStake {
		return fmt.Errorf(
			"_disconnectStake: trying to revert %v but found %v",
			OperationTypeStake,
			operationData.Type,
		)
	}

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorInvalidStakerPKID
	}

	// Delete the CurrentValidatorEntry.
	currentValidatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "_disconnectStake: ")
	}
	if currentValidatorEntry == nil {
		return fmt.Errorf(
			"_disconnectStake: no current ValidatorEntry found for %v", transactorPKIDEntry.PKID,
		)
	}
	bav._deleteValidatorEntryMappings(currentValidatorEntry)

	// Restore the PrevValidatorEntry.
	prevValidatorEntry := operationData.PrevValidatorEntry
	if prevValidatorEntry == nil {
		return fmt.Errorf(
			"_disconnectStake: no prev ValidatorEntry found for %v", transactorPKIDEntry.PKID,
		)
	}
	bav._setValidatorEntryMappings(prevValidatorEntry)

	// Restore the PrevValidatorEntry.
	if operationData.PrevValidatorEntry == nil {

	}

	// Restore the PrevStakeEntry, if exists. If not, delete the CurrentStakeEntry.
	// Restore the PrevGlobalStakeAmountNanos.
	// TODO: Increase DESO balance of transactor.
	return nil
}

func (bav *UtxoView) _connectUnstake(
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
	return 0, 0, nil, nil
}

func (bav *UtxoView) _disconnectUnstake(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	return nil
}

func (bav *UtxoView) _connectUnlockStake(
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
	return 0, 0, nil, nil
}

func (bav *UtxoView) _disconnectUnlockStake(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	return nil
}

func (bav *UtxoView) IsValidStakeMetadata(transactorPkBytes []byte, metadata *StakeMetadata, blockHeight uint32) error {
	// Validate TransactorPublicKey.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPkBytes)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorInvalidStakerPKID
	}

	// Validate ValidatorPublicKey.
	validatorPKIDEntry := bav.GetPKIDForPublicKey(metadata.ValidatorPublicKey.ToBytes())
	if validatorPKIDEntry == nil || validatorPKIDEntry.isDeleted {
		return RuleErrorInvalidValidatorPKID
	}
	validatorEntry, err := bav.GetValidatorByPKID(validatorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "IsValidStakeMetadata: ")
	}
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true.
	if validatorEntry == nil || validatorEntry.isDeleted || validatorEntry.DisableDelegatedStake {
		return RuleErrorInvalidValidatorPKID
	}

	// Validate StakeAmountNanos.
	// TODO: should we include fees in this check?
	transactorDeSoBalanceNanos, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(transactorPkBytes, blockHeight-1)
	if err != nil {
		return errors.Wrapf(err, "IsValidStakeMetadata: ")
	}
	if uint256.NewInt().SetUint64(transactorDeSoBalanceNanos).Cmp(metadata.StakeAmountNanos) < 0 {
		return RuleErrorInvalidStakeInsufficientBalance
	}

	return nil
}

func (bav *UtxoView) IsValidUnstakeMetadata(transactorPkBytes []byte, metadata *UnstakeMetadata) error {
	// Validate TransactorPublicKey.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPkBytes)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorInvalidStakerPKID
	}

	// Validate ValidatorPublicKey.
	validatorPKIDEntry := bav.GetPKIDForPublicKey(metadata.ValidatorPublicKey.ToBytes())
	if validatorPKIDEntry == nil || validatorPKIDEntry.isDeleted {
		return RuleErrorInvalidValidatorPKID
	}
	validatorEntry, err := bav.GetValidatorByPKID(validatorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "IsValidUnstakeMetadata: ")
	}
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true.
	if validatorEntry == nil || validatorEntry.isDeleted {
		return RuleErrorInvalidValidatorPKID
	}

	// Validate StakeEntry exists.
	stakeEntry, err := bav.GetStakeEntry(validatorPKIDEntry.PKID, transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "IsValidUnstakeMetadata: ")
	}
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true.
	if stakeEntry == nil || stakeEntry.isDeleted {
		return RuleErrorInvalidUnstakeNoStakeFound
	}

	// Validate StakeEntry.StakeAmountNanos >= UnstakeAmountNanos.
	if stakeEntry.StakeAmountNanos.Cmp(metadata.UnstakeAmountNanos) < 0 {
		return RuleErrorInvalidUnstakeInsufficientStakeFound
	}

	return nil
}

func (bav *UtxoView) IsValidUnlockStakeMetadata(transactorPkBytes []byte, metadata *UnlockStakeMetadata) error {
	// Validate TransactorPublicKey.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPkBytes)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorInvalidStakerPKID
	}

	// Validate ValidatorPublicKey.
	validatorPKIDEntry := bav.GetPKIDForPublicKey(metadata.ValidatorPublicKey.ToBytes())
	if validatorPKIDEntry == nil || validatorPKIDEntry.isDeleted {
		return RuleErrorInvalidValidatorPKID
	}
	validatorEntry, err := bav.GetValidatorByPKID(validatorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "IsValidUnlockStakeMetadata: ")
	}
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true.
	if validatorEntry == nil || validatorEntry.isDeleted {
		return RuleErrorInvalidValidatorPKID
	}

	// Validate StartEpochNumber and EndEpochNumber.
	if metadata.StartEpochNumber > metadata.EndEpochNumber {
		return RuleErrorInvalidUnlockStakeEpochRange
	}
	// TODO: validate EndEpochNumber is <= CurrentEpochNumber - 2

	// Validate LockedStakeEntries exist.
	lockedStakeEntries, err := bav.GetLockedStakeEntriesInRange(
		validatorPKIDEntry.PKID, transactorPKIDEntry.PKID, metadata.StartEpochNumber, metadata.EndEpochNumber,
	)
	lockedStakeEntryCount := uint64(0)
	for _, lockedStakeEntry := range lockedStakeEntries {
		// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true.
		if lockedStakeEntry != nil && lockedStakeEntry.isDeleted {
			lockedStakeEntryCount += 1
		}
	}
	if lockedStakeEntryCount == 0 {
		return RuleErrorInvalidUnlockStakeNoUnlockableStakeFound
	}

	return nil
}

func (bav *UtxoView) AddStake(validatorPKID *PKID, stakerPKID *PKID, amountNanos *uint256.Int) (
	_prevValidatorEntry *ValidatorEntry,
	_prevStakeEntry *StakeEntry,
	_prevGlobalStakeAmountNanos *uint256.Int,
	_currentValidatorEntry *ValidatorEntry,
	_currentStakeEntry *StakeEntry,
	_currentGlobalStakeAmountNanos *uint256.Int,
	_err error,
) {
	prevValidatorEntry, prevStakeEntry, prevGlobalStakeAmountNanos, err := bav._getPrevValidatorAndStake(validatorPKID, stakerPKID)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, errors.Wrapf(err, "UtxoView.AddStake: ")
	}

	// PrevValidatorEntry has to exist in order to receive stake.
	if prevValidatorEntry == nil || prevValidatorEntry.isDeleted || prevValidatorEntry.DisableDelegatedStake {
		return nil, nil, nil, nil, nil, nil, errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView.AddStake: ")
	}

	// Update CurrentValidatorEntry.TotalStakeAmountNanos.
	currentValidatorEntry := prevValidatorEntry.Copy()
	currentValidatorEntry.TotalStakeAmountNanos, err = SafeUint256().Add(currentValidatorEntry.TotalStakeAmountNanos, amountNanos)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, errors.Wrapf(err, "UtxoView.AddStake: error computing ValidatorEntry.TotalStakeAmountNanos: ")
	}

	currentStakeEntry := prevStakeEntry.Copy()
	currentStakeEntry
}

func (bav *UtxoView) RemoveStake(validatorPKID *PKID, stakerPKID *PKID, amountNanos *uint256.Int) error {

}

func (bav *UtxoView) _getPrevValidatorAndStake(validatorPKID *PKID, stakerPKID *PKID) (
	_prevValidatorEntry *ValidatorEntry,
	_prevStakeEntry *StakeEntry,
	_prevGlobalStakeAmountNanos *uint256.Int,
	_err error,
) {
	// Retrieve PrevValidatorEntry.
	prevValidatorEntry, err := bav.GetValidatorByPKID(validatorPKID)
	if err != nil {
		return nil, nil, nil, err
	}

	// Retrieve PrevStakeEntry.
	prevStakeEntry, err := bav.GetStakeEntry(validatorPKID, stakerPKID)
	if err != nil {
		return nil, nil, nil, err
	}

	// Retrieve PrevGlobalStakeAmountNanos.
	prevGlobalStakeAmountNanos, err := bav.GetGlobalStakeAmountNanos()
	if err != nil {
		return nil, nil, nil, err
	}

	return prevValidatorEntry, prevStakeEntry, prevGlobalStakeAmountNanos, nil
}

func (bav *UtxoView) GetStakeEntry(validatorPKID *PKID, stakerPKID *PKID) (*StakeEntry, error) {
	// First, check the UtxoView.
	stakeMapKey := StakeMapKey{ValidatorPKID: *validatorPKID, StakerPKID: *stakerPKID}
	if stakeEntry, exists := bav.StakeMapKeyToStakeEntry[stakeMapKey]; exists {
		// If StakeEntry.isDeleted, return nil.
		if stakeEntry.isDeleted {
			return nil, nil
		}
		return stakeEntry, nil
	}
	// Then, check the database.
	return DBGetStakeEntry(bav.Handle, bav.Snapshot, validatorPKID, stakerPKID)
}

func (bav *UtxoView) GetLockedStakeEntry(
	validatorPKID *PKID,
	stakerPKID *PKID,
	lockedAtEpochNumber uint64,
) (*LockedStakeEntry, error) {
	// First, check the UtxoView.
	lockedStakeMapKey := LockedStakeMapKey{
		ValidatorPKID:       *validatorPKID,
		StakerPKID:          *stakerPKID,
		LockedAtEpochNumber: lockedAtEpochNumber,
	}
	if lockedStakeEntry, exists := bav.LockedStakeMapKeyToLockedStakeEntry[lockedStakeMapKey]; exists {
		// If LockedStakeEntry.isDeleted, return nil.
		if lockedStakeEntry.isDeleted {
			return nil, nil
		}
		return lockedStakeEntry, nil
	}
	// Then, check the database.
	return DBGetLockedStakeEntry(bav.Handle, bav.Snapshot, validatorPKID, stakerPKID, lockedAtEpochNumber)
}

func (bav *UtxoView) GetLockedStakeEntriesInRange(
	validatorPKID *PKID,
	stakerPKID *PKID,
	startEpochNumber uint64,
	endEpochNumber uint64,
) ([]*LockedStakeEntry, error) {
	// Store matching LockedStakeEntries in a set to prevent
	// returning duplicates between the db and UtxoView.
	lockedStakeEntriesSet := NewSet([]*LockedStakeEntry{})

	// First, pull matching LockedStakeEntries from the db.
	dbLockedStakeEntries, err := DBGetLockedStakeEntriesInRange(
		bav.Handle, bav.Snapshot, validatorPKID, stakerPKID, startEpochNumber, endEpochNumber,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetLockedStakeEntriesInRange: ")
	}
	for _, lockedStakeEntry := range dbLockedStakeEntries {
		lockedStakeEntriesSet.Add(lockedStakeEntry)
	}

	// Then, pull matching LockedStakeEntries from the UtxoView.
	// Loop through all LockedStakeEntries in the UtxoView.
	for _, lockedStakeEntry := range bav.LockedStakeMapKeyToLockedStakeEntry {
		// Filter to matching LockedStakeEntries.
		if !lockedStakeEntry.ValidatorPKID.Eq(validatorPKID) ||
			!lockedStakeEntry.StakerPKID.Eq(stakerPKID) ||
			lockedStakeEntry.LockedAtEpochNumber < startEpochNumber ||
			lockedStakeEntry.LockedAtEpochNumber > endEpochNumber {
			continue
		}

		if lockedStakeEntry.isDeleted {
			// Remove from set if isDeleted.
			lockedStakeEntriesSet.Remove(lockedStakeEntry)
		} else {
			// Otherwise, add to set.
			lockedStakeEntriesSet.Add(lockedStakeEntry)
		}
	}

	// Convert LockedStakeEntries set to slice, sorted by LockedAtEpochNumber ASC.
	lockedStakeEntries := lockedStakeEntriesSet.ToSlice()
	sort.Slice(lockedStakeEntries, func(ii, jj int) bool {
		return lockedStakeEntries[ii].LockedAtEpochNumber < lockedStakeEntries[jj].LockedAtEpochNumber
	})
	return lockedStakeEntries, nil
}

func (bav *UtxoView) _setStakeEntryMappings(stakeEntry *StakeEntry) {
	// This function shouldn't be called with nil.
	if stakeEntry == nil {
		glog.Errorf("_setStakeEntryMappings: called with nil entry, this should never happen")
		return
	}
	bav.StakeMapKeyToStakeEntry[stakeEntry.ToMapKey()] = stakeEntry
}

func (bav *UtxoView) _setLockedStakeEntryMappings(lockedStakeEntry *LockedStakeEntry) {
	// This function shouldn't be called with nil.
	if lockedStakeEntry == nil {
		glog.Errorf("_setLockedStakeEntryMappings: called with nil entry, this should never happen")
		return
	}
	bav.LockedStakeMapKeyToLockedStakeEntry[lockedStakeEntry.ToMapKey()] = lockedStakeEntry
}

func (bav *UtxoView) _deleteStakeEntryMappings(stakeEntry *StakeEntry) {
	// This function shouldn't be called with nil.
	if stakeEntry == nil {
		glog.Errorf("_deleteStakeEntryMappings: called with nil entry, this should never happen")
		return
	}
	// Create a tombstone entry.
	tombstoneEntry := *stakeEntry
	tombstoneEntry.isDeleted = true
	// Set the mappings to the point to the tombstone entry.
	bav._setStakeEntryMappings(&tombstoneEntry)
}

func (bav *UtxoView) _deleteLockedStakeEntryMappings(lockedStakeEntry *LockedStakeEntry) {
	// This function shouldn't be called with nil.
	if lockedStakeEntry == nil {
		glog.Errorf("_deleteLockedStakeEntryMappings: called with nil entry, this should never happen")
		return
	}
	// Create a tombstone entry.
	tombstoneEntry := *lockedStakeEntry
	tombstoneEntry.isDeleted = true
	// Set the mappings to the point to the tombstone entry.
	bav._setLockedStakeEntryMappings(&tombstoneEntry)
}

func (bav *UtxoView) _flushStakeEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Delete all entries in the UtxoView map.
	for mapKeyIter, entryIter := range bav.StakeMapKeyToStakeEntry {
		// Make a copy of the iterators since we make references to them below.
		mapKey := mapKeyIter
		entry := *entryIter

		// Sanity-check that the entry matches the map key.
		mapKeyInEntry := entry.ToMapKey()
		if mapKeyInEntry != mapKey {
			return fmt.Errorf(
				"_flushStakeEntriesToDbWithTxn: StakeEntry key %v doesn't match MapKey %v",
				&mapKeyInEntry,
				&mapKey,
			)
		}

		// Delete the existing mappings in the db for this MapKey. They will be
		// re-added if the corresponding entry in-memory has isDeleted=false.
		if err := DBDeleteStakeEntryWithTxn(txn, bav.Snapshot, &entry, blockHeight); err != nil {
			return errors.Wrapf(err, "_flushStakeEntriesToDbWithTxn: ")
		}
	}

	// Set any !isDeleted entries in the UtxoView map.
	for _, entryIter := range bav.StakeMapKeyToStakeEntry {
		entry := *entryIter
		if entry.isDeleted {
			// If isDeleted then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If !isDeleted then we put the corresponding
			// mappings for it into the db.
			if err := DBPutStakeEntryWithTxn(txn, bav.Snapshot, &entry, blockHeight); err != nil {
				return errors.Wrapf(err, "_flushStakeEntriesToDbWithTxn: ")
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushLockedStakeEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Delete all entries in the UtxoView map.
	for mapKeyIter, entryIter := range bav.LockedStakeMapKeyToLockedStakeEntry {
		// Make a copy of the iterators since we make references to them below.
		mapKey := mapKeyIter
		entry := *entryIter

		// Sanity-check that the entry matches the map key.
		mapKeyInEntry := entry.ToMapKey()
		if mapKeyInEntry != mapKey {
			return fmt.Errorf(
				"_flushLockedStakeEntriesToDbWithTxn: StakeEntry key %v doesn't match MapKey %v",
				&mapKeyInEntry,
				&mapKey,
			)
		}

		// Delete the existing mappings in the db for this MapKey. They will be
		// re-added if the corresponding entry in-memory has isDeleted=false.
		if err := DBDeleteLockedStakeEntryWithTxn(txn, bav.Snapshot, &entry, blockHeight); err != nil {
			return errors.Wrapf(err, "_flushLockedStakeEntriesToDbWithTxn: ")
		}
	}

	// Set any !isDeleted entries in the UtxoView map.
	for _, entryIter := range bav.LockedStakeMapKeyToLockedStakeEntry {
		entry := *entryIter
		if entry.isDeleted {
			// If isDeleted then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If !isDeleted then we put the corresponding
			// mappings for it into the db.
			if err := DBPutLockedStakeEntryWithTxn(txn, bav.Snapshot, &entry, blockHeight); err != nil {
				return errors.Wrapf(err, "_flushLockedStakeEntriesToDbWithTxn: ")
			}
		}
	}

	return nil
}

//
// MEMPOOL UTILS
//

func (bav *UtxoView) CreateStakeTxindexMetadata(utxoOp *UtxoOperation, txn *MsgDeSoTxn) (*StakeTxindexMetadata, []*AffectedPublicKey) {
	metadata := txn.TxnMeta.(*StakeMetadata)

	// Cast TransactorPublicKeyBytes to StakerPublicKeyBase58Check.
	stakerPublicKeyBase58Check := PkToString(txn.PublicKey, bav.Params)

	// Cast ValidatorPublicKey to ValidatorPublicKeyBase58Check.
	validatorPublicKeyBase58Check := PkToString(metadata.ValidatorPublicKey.ToBytes(), bav.Params)

	// Construct TxindexMetadata.
	txindexMetadata := &StakeTxindexMetadata{
		StakerPublicKeyBase58Check:    stakerPublicKeyBase58Check,
		ValidatorPublicKeyBase58Check: validatorPublicKeyBase58Check,
		StakeAmountNanos:              metadata.StakeAmountNanos,
	}

	// Construct AffectedPublicKeys.
	affectedPublicKeys := []*AffectedPublicKey{
		{
			PublicKeyBase58Check: stakerPublicKeyBase58Check,
			Metadata:             "StakerPublicKeyBase58Check",
		},
		{
			PublicKeyBase58Check: validatorPublicKeyBase58Check,
			Metadata:             "ValidatorStakedToPublicKeyBase58Check",
		},
	}

	return txindexMetadata, affectedPublicKeys
}

func (bav *UtxoView) CreateUnstakeTxindexMetadata(utxoOp *UtxoOperation, txn *MsgDeSoTxn) (*UnstakeTxindexMetadata, []*AffectedPublicKey) {
	metadata := txn.TxnMeta.(*UnstakeMetadata)

	// Cast TransactorPublicKeyBytes to StakerPublicKeyBase58Check.
	stakerPublicKeyBase58Check := PkToString(txn.PublicKey, bav.Params)

	// Cast ValidatorPublicKey to ValidatorPublicKeyBase58Check.
	validatorPublicKeyBase58Check := PkToString(metadata.ValidatorPublicKey.ToBytes(), bav.Params)

	// Construct TxindexMetadata.
	txindexMetadata := &UnstakeTxindexMetadata{
		StakerPublicKeyBase58Check:    stakerPublicKeyBase58Check,
		ValidatorPublicKeyBase58Check: validatorPublicKeyBase58Check,
		UnstakeAmountNanos:            metadata.UnstakeAmountNanos,
	}

	// Construct AffectedPublicKeys.
	affectedPublicKeys := []*AffectedPublicKey{
		{
			PublicKeyBase58Check: stakerPublicKeyBase58Check,
			Metadata:             "UnstakerPublicKeyBase58Check",
		},
		{
			PublicKeyBase58Check: validatorPublicKeyBase58Check,
			Metadata:             "ValidatorUnstakedFromPublicKeyBase58Check",
		},
	}

	return txindexMetadata, affectedPublicKeys
}

func (bav *UtxoView) CreateUnlockStakeTxindexMetadata(utxoOp *UtxoOperation, txn *MsgDeSoTxn) (*UnlockStakeTxindexMetadata, []*AffectedPublicKey) {
	metadata := txn.TxnMeta.(*UnlockStakeMetadata)

	// Cast TransactorPublicKeyBytes to StakerPublicKeyBase58Check.
	stakerPublicKeyBase58Check := PkToString(txn.PublicKey, bav.Params)

	// Cast ValidatorPublicKey to ValidatorPublicKeyBase58Check.
	validatorPublicKeyBase58Check := PkToString(metadata.ValidatorPublicKey.ToBytes(), bav.Params)

	// TODO: Calculate TotalUnlockedAmountNanos.
	totalUnlockedAmountNanos := uint256.NewInt()

	// Construct TxindexMetadata.
	txindexMetadata := &UnlockStakeTxindexMetadata{
		StakerPublicKeyBase58Check:    stakerPublicKeyBase58Check,
		ValidatorPublicKeyBase58Check: validatorPublicKeyBase58Check,
		StartEpochNumber:              metadata.StartEpochNumber,
		EndEpochNumber:                metadata.EndEpochNumber,
		TotalUnlockedAmountNanos:      totalUnlockedAmountNanos,
	}

	// Construct AffectedPublicKeys.
	affectedPublicKeys := []*AffectedPublicKey{
		{
			PublicKeyBase58Check: stakerPublicKeyBase58Check,
			Metadata:             "UnlockedStakerPublicKeyBase58Check",
		},
	}

	return txindexMetadata, affectedPublicKeys
}

//
// CONSTANTS
//

const RuleErrorInvalidStakerPKID RuleError = "RuleErrorInvalidStakerPKID"
const RuleErrorInvalidStakeAmountNanos RuleError = "RuleErrorInvalidStakeAmountNanos"
const RuleErrorInvalidStakeInsufficientBalance RuleError = "RuleErrorInvalidStakeInsufficientBalance"
const RuleErrorInvalidUnstakeNoStakeFound RuleError = "RuleErrorInvalidUnstakeNoStakeFound"
const RuleErrorInvalidUnstakeInsufficientStakeFound RuleError = "RuleErrorInvalidUnstakeInsufficientStakeFound"
const RuleErrorInvalidUnlockStakeEpochRange RuleError = "RuleErrorInvalidUnlockStakeEpochRange"
const RuleErrorInvalidUnlockStakeNoUnlockableStakeFound RuleError = "RuleErrorInvalidUnlockStakeNoUnlockableStakeFound"
