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
	data := DBPrefixKeyForLockedStakeByValidatorByStaker(lockedStakeEntry)
	data = append(data, UintToBuf(lockedStakeEntry.LockedAtEpochNumber)...)
	return data
}

func DBPrefixKeyForLockedStakeByValidatorByStaker(lockedStakeEntry *LockedStakeEntry) []byte {
	var data []byte
	data = append(data, Prefixes.PrefixLockedStakeByValidatorByStakerByLockedAt...)
	data = append(data, lockedStakeEntry.ValidatorPKID.ToBytes()...)
	data = append(data, lockedStakeEntry.StakerPKID.ToBytes()...)
	return data
}

func DBGetStakeEntry(
	handle *badger.DB,
	snap *Snapshot,
	validatorPKID *PKID,
	stakerPKID *PKID,
) (*StakeEntry, error) {
	var ret *StakeEntry
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetStakeEntryWithTxn(txn, snap, validatorPKID, stakerPKID)
		return innerErr
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
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetLockedStakeEntryWithTxn(
			txn, snap, validatorPKID, stakerPKID, lockedAtEpochNumber,
		)
		return innerErr
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

	// Start at the StartEpochNumber.
	startKey := DBKeyForLockedStakeByValidatorByStakerByLockedAt(&LockedStakeEntry{
		ValidatorPKID:       validatorPKID,
		StakerPKID:          stakerPKID,
		LockedAtEpochNumber: startEpochNumber,
	})

	// Consider only LockedStakeEntries for this ValidatorPKID, StakerPKID.
	prefixKey := DBPrefixKeyForLockedStakeByValidatorByStaker(&LockedStakeEntry{
		ValidatorPKID: validatorPKID,
		StakerPKID:    stakerPKID,
	})

	// Create an iterator.
	iterator := txn.NewIterator(badger.DefaultIteratorOptions)
	defer iterator.Close()

	// Store matching LockedStakeEntries to return.
	var lockedStakeEntries []*LockedStakeEntry

	// Loop.
	for iterator.Seek(startKey); iterator.ValidForPrefix(prefixKey); iterator.Next() {
		// Retrieve the LockedStakeEntryBytes.
		lockedStakeEntryBytes, err := iterator.Item().ValueCopy(nil)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetLockedStakeEntriesInRange: error retrieving LockedStakeEntry: ")
		}

		// Convert LockedStakeEntryBytes to LockedStakeEntry.
		lockedStakeEntry := &LockedStakeEntry{}
		rr := bytes.NewReader(lockedStakeEntryBytes)
		if exist, err := DecodeFromBytes(lockedStakeEntry, rr); !exist || err != nil {
			return nil, errors.Wrapf(err, "DBGetLockedStakeEntriesInRange: error decoding LockedStakeEntry: ")
		}

		// Break if LockedStakeEntry.LockedAtEpochNumber > EndEpochNumber.
		if lockedStakeEntry.LockedAtEpochNumber > endEpochNumber {
			break
		}

		// Add LockedStakeEntry to return slice.
		lockedStakeEntries = append(lockedStakeEntries, lockedStakeEntry)
	}

	return lockedStakeEntries, nil
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
	// TODO: incorporate DESO being spent by transactor + balance model
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
			err, "Blockchain.CreateStakeTxn: problem creating new utxo view: ",
		)
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(
				err, "Blockchain.CreateStakeTxn: problem getting augmented utxo view from mempool: ",
			)
		}
	}

	// Validate txn metadata.
	blockHeight := bc.blockTip().Height + 1
	if err = utxoView.IsValidStakeMetadata(transactorPublicKey, metadata, blockHeight); err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateStakeTxn: invalid txn metadata: ",
		)
	}

	// We don't need to make any tweaks to the amount because
	// it's basically a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err := bc.AddInputsAndChangeToTransaction(
		txn, minFeeRateNanosPerKB, mempool,
	)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateStakeTxn: problem adding inputs: ",
		)
	}

	// Validate that the transaction has at least one input, even if it all goes
	// to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 && bc.blockTip().Height+1 < bc.params.ForkHeights.BalanceModelBlockHeight {
		return nil, 0, 0, 0, errors.New(
			"Blockchain.CreateStakeTxn: txn has zero inputs, try increasing the fee rate",
		)
	}

	// Sanity-check that the spendAmount is zero.
	if spendAmount != 0 {
		return nil, 0, 0, 0, fmt.Errorf(
			"Blockchain.CreateStakeTxn: spend amount is non-zero: %d", spendAmount,
		)
	}
	return txn, totalInput, changeAmount, fees, nil
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
	if len(txn.TxInputs) == 0 && bc.blockTip().Height+1 < bc.params.ForkHeights.BalanceModelBlockHeight {
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
	// TODO: incorporate DESO being returned to transactor + balance model
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
			err, "Blockchain.CreateUnlockStakeTxn: problem creating new utxo view: ",
		)
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(
				err, "Blockchain.CreateUnlockStakeTxn: problem getting augmented utxo view from mempool: ",
			)
		}
	}

	// Validate txn metadata.
	if err = utxoView.IsValidUnlockStakeMetadata(transactorPublicKey, metadata); err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateUnlockStakeTxn: invalid txn metadata: ",
		)
	}

	// We don't need to make any tweaks to the amount because
	// it's basically a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err := bc.AddInputsAndChangeToTransaction(
		txn, minFeeRateNanosPerKB, mempool,
	)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateUnlockStakeTxn: problem adding inputs: ",
		)
	}

	// Validate that the transaction has at least one input, even if it all goes
	// to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 && bc.blockTip().Height+1 < bc.params.ForkHeights.BalanceModelBlockHeight {
		return nil, 0, 0, 0, errors.New(
			"Blockchain.CreateUnlockStakeTxn: txn has zero inputs, try increasing the fee rate",
		)
	}

	// Sanity-check that the spendAmount is zero.
	if spendAmount != 0 {
		return nil, 0, 0, 0, fmt.Errorf(
			"Blockchain.CreateUnlockStakeTxn: spend amount is non-zero: %d", spendAmount,
		)
	}
	return txn, totalInput, changeAmount, fees, nil
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
	if blockHeight < bav.Params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return 0, 0, nil, RuleErrorProofofStakeTxnBeforeBlockHeight
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeStake {
		return 0, 0, nil, fmt.Errorf(
			"_connectStake: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*StakeMetadata)

	// Validate the txn metadata.
	if err := bav.IsValidStakeMetadata(txn.PublicKey, txMeta, blockHeight); err != nil {
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
	// Retrieve the existing ValidatorEntry. It must exist.
	// The PrevValidatorEntry will be restored if we disconnect this transaction.
	prevValidatorEntry, err := bav.GetValidatorByPKID(validatorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: ")
	}
	if prevValidatorEntry == nil || prevValidatorEntry.isDeleted || prevValidatorEntry.DisableDelegatedStake {
		return 0, 0, nil, RuleErrorInvalidValidatorPKID
	}

	// Convert StakeAmountNanos *uint256.Int to StakeAmountNanosUint64 uint64.
	if txMeta.StakeAmountNanos == nil || !txMeta.StakeAmountNanos.IsUint64() {
		return 0, 0, nil, RuleErrorInvalidStakeAmountNanos
	}
	stakeAmountNanosUint64 := txMeta.StakeAmountNanos.Uint64()

	// Connect a BasicTransfer to get the total input and the
	// total output without considering the txn metadata. This
	// BasicTransfer also includes the extra spend associated
	// with the amount the transactor is staking.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransferWithExtraSpend(
		txn, txHash, blockHeight, stakeAmountNanosUint64, verifySignatures,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: ")
	}
	if verifySignatures {
		// _connectBasicTransfer has already checked that the txn is signed
		// by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

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
			return 0, 0, nil, errors.Wrapf(err, "_connectStake: invalid StakeAmountNanos: ")
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

	// Update the ValidatorEntry.TotalStakeAmountNanos.
	// 1. Delete the existing ValidatorEntry.
	bav._deleteValidatorEntryMappings(prevValidatorEntry)
	// 2. Create a new ValidatorEntry with the updated TotalStakeAmountNanos.
	currentValidatorEntry := prevValidatorEntry.Copy()
	currentValidatorEntry.TotalStakeAmountNanos, err = SafeUint256().Add(
		currentValidatorEntry.TotalStakeAmountNanos, txMeta.StakeAmountNanos,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: invalid StakeAmountNanos: ")
	}
	// 3. Set the new ValidatorEntry.
	bav._setValidatorEntryMappings(currentValidatorEntry)

	// Increase the GlobalStakeAmountNanos.
	// Retrieve the existing GlobalStakeAmountNanos.
	// The PrevGlobalStakeAmountNanos will be restored if we disconnect this transaction.
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
		Type:                       OperationTypeStake,
		PrevValidatorEntry:         prevValidatorEntry,
		PrevGlobalStakeAmountNanos: prevGlobalStakeAmountNanos,
		PrevStakeEntries:           []*StakeEntry{prevStakeEntry},
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
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_disconnectStake: ")
	}

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
	txMeta := currentTxn.TxnMeta.(*StakeMetadata)

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorInvalidStakerPKID
	}

	// Restore the PrevValidatorEntry.
	prevValidatorEntry := operationData.PrevValidatorEntry
	if prevValidatorEntry == nil {
		return fmt.Errorf(
			"_disconnectStake: no prev ValidatorEntry found for %v", txMeta.ValidatorPublicKey,
		)
	}
	// 1. Delete the CurrentValidatorEntry.
	currentValidatorEntry, err := bav.GetValidatorByPKID(prevValidatorEntry.ValidatorPKID)
	if err != nil {
		return errors.Wrapf(err, "_disconnectStake: ")
	}
	if currentValidatorEntry == nil {
		return fmt.Errorf(
			"_disconnectStake: no current ValidatorEntry found for %v", txMeta.ValidatorPublicKey,
		)
	}
	bav._deleteValidatorEntryMappings(currentValidatorEntry)
	// 2. Set the PrevValidatorEntry.
	bav._setValidatorEntryMappings(prevValidatorEntry)

	// Restore the PrevStakeEntry.
	// 1. Delete the CurrentStakeEntry.
	currentStakeEntry, err := bav.GetStakeEntry(prevValidatorEntry.ValidatorPKID, transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "_disconnectStake: ")
	}
	if currentStakeEntry == nil {
		return fmt.Errorf("_disconnectStake: no current StakeEntry found for %v", currentTxn.PublicKey)
	}
	bav._deleteStakeEntryMappings(currentStakeEntry)
	// 2. Set the PrevStakeEntry, if exists. The PrevStakeEntry will exist if the transactor
	//    was adding stake to an existing StakeEntry. It will not exist if this is the first
	//    stake the transactor has staked with this validator.
	if len(operationData.PrevStakeEntries) > 1 {
		return fmt.Errorf("_disconnectStake: more than one prev StakeEntry found for %v", currentTxn.PublicKey)
	} else if len(operationData.PrevStakeEntries) == 1 {
		bav._setStakeEntryMappings(operationData.PrevStakeEntries[0])
	}

	// Restore the PrevGlobalStakeAmountNanos.
	bav._setGlobalStakeAmountNanos(operationData.PrevGlobalStakeAmountNanos)

	// Disconnect the BasicTransfer. Disconnecting the BasicTransfer also returns
	// the extra spend associated with the amount the transactor staked.
	return bav._disconnectBasicTransfer(
		currentTxn, txHash, utxoOpsForTxn[:operationIndex], blockHeight,
	)
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
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return 0, 0, nil, RuleErrorProofofStakeTxnBeforeBlockHeight
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeUnstake {
		return 0, 0, nil, fmt.Errorf(
			"_connectUnstake: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Connect a basic transfer to get the total input and the
	// total output without considering the txn metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: ")
	}
	if verifySignatures {
		// _connectBasicTransfer has already checked that the txn is signed
		// by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*UnstakeMetadata)

	// Validate the txn metadata.
	if err = bav.IsValidUnstakeMetadata(txn.PublicKey, txMeta); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: ")
	}

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return 0, 0, nil, RuleErrorInvalidStakerPKID
	}

	// Retrieve PrevValidatorEntry. This will be restored if we disconnect the txn.
	prevValidatorEntry, err := bav.GetValidatorByPublicKey(txMeta.ValidatorPublicKey)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: ")
	}
	if prevValidatorEntry == nil || prevValidatorEntry.isDeleted || prevValidatorEntry.DisableDelegatedStake {
		return 0, 0, nil, RuleErrorInvalidValidatorPKID
	}

	// Retrieve PrevStakeEntry. This will be restored if we disconnect the txn.
	prevStakeEntry, err := bav.GetStakeEntry(prevValidatorEntry.ValidatorPKID, transactorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: ")
	}
	if prevStakeEntry == nil || prevStakeEntry.isDeleted {
		return 0, 0, nil, RuleErrorInvalidUnstakeNoStakeFound
	}
	if prevStakeEntry.StakeAmountNanos.Cmp(txMeta.UnstakeAmountNanos) < 0 {
		return 0, 0, nil, RuleErrorInvalidUnstakeInsufficientStakeFound
	}

	// Update the StakeEntry, decreasing the StakeAmountNanos.
	// 1. Calculate the updated StakeAmountNanos.
	stakeAmountNanos, err := SafeUint256().Sub(prevStakeEntry.StakeAmountNanos, txMeta.UnstakeAmountNanos)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: invalid UnstakeAmountNanos: ")
	}
	// 2. Create a CurrentStakeEntry, if updated StakeAmountNanos > 0.
	var currentStakeEntry *StakeEntry
	if stakeAmountNanos.Cmp(uint256.NewInt()) > 0 {
		currentStakeEntry = prevStakeEntry.Copy()
		currentStakeEntry.StakeAmountNanos = stakeAmountNanos
	}
	// 3. Delete the PrevStakeEntry.
	bav._deleteStakeEntryMappings(prevStakeEntry)
	// 4. Set the CurrentStakeEntry, if exists. The CurrentStakeEntry will not exist
	//    if the transactor has unstaked all stake assigned to this validator.
	if currentStakeEntry != nil {
		bav._setStakeEntryMappings(currentStakeEntry)
	}

	// Update the ValidatorEntry.TotalStakeAmountNanos.
	// 1. Delete the existing ValidatorEntry.
	bav._deleteValidatorEntryMappings(prevValidatorEntry)
	// 2. Create a new ValidatorEntry with the updated TotalStakeAmountNanos.
	currentValidatorEntry := prevValidatorEntry.Copy()
	currentValidatorEntry.TotalStakeAmountNanos, err = SafeUint256().Sub(
		currentValidatorEntry.TotalStakeAmountNanos, txMeta.UnstakeAmountNanos,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: invalid UnstakeAmountNanos: ")
	}
	// 3. Set the new ValidatorEntry.
	bav._setValidatorEntryMappings(currentValidatorEntry)

	// Decrease the GlobalStakeAmountNanos.
	// 1. Retrieve the existing GlobalStakeAmountNanos. This will be restored if we disconnect this txn.
	prevGlobalStakeAmountNanos, err := bav.GetGlobalStakeAmountNanos()
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: error retrieving GlobalStakeAmountNanos: ")
	}
	globalStakeAmountNanos, err := SafeUint256().Sub(prevGlobalStakeAmountNanos, txMeta.UnstakeAmountNanos)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: error calculating updated GlobalStakeAmountNanos: ")
	}
	// 2. Set the new GlobalStakeAmountNanos.
	bav._setGlobalStakeAmountNanos(globalStakeAmountNanos)

	// Update the LockedStakeEntry, if exists. Create if not.
	currentEpochNumber := uint64(0) // TODO: set this
	// 1. Retrieve the PrevLockedStakeEntry. This will be restored if we disconnect this txn.
	prevLockedStakeEntry, err := bav.GetLockedStakeEntry(
		prevValidatorEntry.ValidatorPKID, transactorPKIDEntry.PKID, currentEpochNumber,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: ")
	}
	// 2. Create a CurrrentLockedStakeEntry.
	var currentLockedStakeEntry *LockedStakeEntry
	if prevLockedStakeEntry != nil {
		// Update the existing LockedStakeEntry.
		currentLockedStakeEntry = prevLockedStakeEntry.Copy()
		currentLockedStakeEntry.LockedAmountNanos, err = SafeUint256().Add(
			prevLockedStakeEntry.LockedAmountNanos, txMeta.UnstakeAmountNanos,
		)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: invalid LockedAmountNanos")
		}
		currentLockedStakeEntry.ExtraData = mergeExtraData(prevLockedStakeEntry.ExtraData, txn.ExtraData)
	} else {
		// Create a new LockedStakeEntry.
		currentLockedStakeEntry = &LockedStakeEntry{
			LockedStakeID:       txn.Hash(),
			StakerPKID:          transactorPKIDEntry.PKID,
			ValidatorPKID:       prevValidatorEntry.ValidatorPKID,
			LockedAmountNanos:   txMeta.UnstakeAmountNanos,
			LockedAtEpochNumber: currentEpochNumber,
			ExtraData:           txn.ExtraData,
		}
	}
	// 3. Delete the PrevLockedStakeEntry, if exists.
	if prevLockedStakeEntry != nil {
		bav._deleteLockedStakeEntryMappings(prevLockedStakeEntry)
	}
	// 4. Set the CurrentLockedStakeEntry.
	bav._setLockedStakeEntryMappings(currentLockedStakeEntry)

	// Add a UTXO operation
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                       OperationTypeUnstake,
		PrevValidatorEntry:         prevValidatorEntry,
		PrevGlobalStakeAmountNanos: prevGlobalStakeAmountNanos,
		PrevStakeEntries:           []*StakeEntry{prevStakeEntry},
		PrevLockedStakeEntries:     []*LockedStakeEntry{prevLockedStakeEntry},
	})
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectUnstake(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_disconnectUnstake: ")
	}

	// Validate the last operation is an Unstake operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUnstake: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	operationData := utxoOpsForTxn[operationIndex]
	if operationData.Type != OperationTypeUnstake {
		return fmt.Errorf(
			"_disconnectUnstake: trying to revert %v but found %v",
			OperationTypeUnstake,
			operationData.Type,
		)
	}
	txMeta := currentTxn.TxnMeta.(*UnstakeMetadata)

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorInvalidStakerPKID
	}

	// Restore the PrevValidatorEntry.
	prevValidatorEntry := operationData.PrevValidatorEntry
	if prevValidatorEntry == nil {
		return fmt.Errorf(
			"_disconnectUnstake: no prev ValidatorEntry found for %v", txMeta.ValidatorPublicKey,
		)
	}
	// 1. Delete the CurrentValidatorEntry.
	currentValidatorEntry, err := bav.GetValidatorByPKID(prevValidatorEntry.ValidatorPKID)
	if err != nil {
		return errors.Wrapf(err, "_disconnectUnstake: ")
	}
	if currentValidatorEntry == nil {
		return fmt.Errorf(
			"_disconnectUnstake: no current ValidatorEntry found for %v", txMeta.ValidatorPublicKey,
		)
	}
	bav._deleteValidatorEntryMappings(currentValidatorEntry)
	// 2. Set the PrevValidatorEntry.
	bav._setValidatorEntryMappings(prevValidatorEntry)

	// Restore the PrevStakeEntry.
	// 1. Delete the CurrentStakeEntry, if exists. The CurrentStakeEntry will exist if the transactor
	//    still has stake assigned to this validator. The CurrentStakeEntry will not exist if the
	//    transactor unstaked all stake.
	currentStakeEntry, err := bav.GetStakeEntry(prevValidatorEntry.ValidatorPKID, transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "_disconnectUnstake: ")
	}
	if currentStakeEntry != nil {
		bav._deleteStakeEntryMappings(currentStakeEntry)
	}
	// 2. Set the PrevStakeEntry.
	if len(operationData.PrevStakeEntries) < 1 {
		return fmt.Errorf("_disconnectUnstake: no prev StakeEntry found for %v", currentTxn.PublicKey)
	}
	if len(operationData.PrevStakeEntries) > 1 {
		return fmt.Errorf("_disconnectUnstake: more than one prev StakeEntry found for %v", currentTxn.PublicKey)
	}
	bav._setStakeEntryMappings(operationData.PrevStakeEntries[0])

	// Restore the PrevGlobalStakeAmountNanos.
	bav._setGlobalStakeAmountNanos(operationData.PrevGlobalStakeAmountNanos)

	// Restore the PrevLockedStakeEntry, if exists. The PrevLockedStakeEntry will exist if the
	// transactor has previously unstaked stake assigned to this validator within the same epoch.
	// The PrevLockedStakeEntry will not exist otherwise.
	currentEpochNumber := uint64(0) // TODO: set this
	// 1. Retrieve the CurrentLockedStakeEntry.
	currentLockedStakeEntry, err := bav.GetLockedStakeEntry(
		prevValidatorEntry.ValidatorPKID, transactorPKIDEntry.PKID, currentEpochNumber,
	)
	if err != nil {
		return errors.Wrapf(err, "_disconnectUnstake: ")
	}
	// 2. Delete the CurrentLockedStakeEntry.
	bav._deleteLockedStakeEntryMappings(currentLockedStakeEntry)
	// 3. Set the PrevLockedStakeEntry, if exists.
	if len(operationData.PrevLockedStakeEntries) > 1 {
		return fmt.Errorf("_disconnectUnstake: more than one prev LockedStakeEntry found for %v", currentTxn.PublicKey)
	}
	if len(operationData.PrevLockedStakeEntries) == 1 {
		bav._setLockedStakeEntryMappings(operationData.PrevLockedStakeEntries[0])
	}

	// Disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txHash, utxoOpsForTxn[:operationIndex], blockHeight,
	)
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
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return 0, 0, nil, RuleErrorProofofStakeTxnBeforeBlockHeight
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeUnlockStake {
		return 0, 0, nil, fmt.Errorf(
			"_connectUnlockStake: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*UnlockStakeMetadata)

	// Validate the txn metadata.
	if err := bav.IsValidUnlockStakeMetadata(txn.PublicKey, txMeta); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnlockStake: ")
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

	// Retrieve the PrevLockedStakeEntries. These will be restored if we disconnect this txn.
	prevLockedStakeEntries, err := bav.GetLockedStakeEntriesInRange(
		validatorPKIDEntry.PKID, transactorPKIDEntry.PKID, txMeta.StartEpochNumber, txMeta.EndEpochNumber,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnlockStake: ")
	}
	if len(prevLockedStakeEntries) == 0 {
		return 0, 0, nil, RuleErrorInvalidUnlockStakeNoUnlockableStakeFound
	}

	// Connect a basic transfer to get the total input and the
	// total output without considering the txn metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnlockStake: ")
	}
	if verifySignatures {
		// _connectBasicTransfer has already checked that the txn is signed
		// by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// Calculate the TotalUnlockedAmountNanos and delete the PrevLockedStakeEntries.
	totalUnlockedAmountNanos := uint256.NewInt()
	for _, prevLockedStakeEntry := range prevLockedStakeEntries {
		totalUnlockedAmountNanos, err = SafeUint256().Add(
			totalUnlockedAmountNanos, prevLockedStakeEntry.LockedAmountNanos,
		)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectUnlockStake: ")
		}
		bav._deleteLockedStakeEntryMappings(prevLockedStakeEntry)
	}
	if !totalUnlockedAmountNanos.IsUint64() {
		return 0, 0, nil, RuleErrorInvalidUnlockStakeUnlockableStakeOverflowsUint64
	}
	totalUnlockedAmountNanosUint64 := totalUnlockedAmountNanos.Uint64()

	// Return TotalUnlockedAmountNanos back to the transactor.
	outputKey := UtxoKey{
		TxID:  *txn.Hash(),
		Index: uint32(len(txn.TxOutputs)),
	}
	utxoEntry := UtxoEntry{
		AmountNanos: totalUnlockedAmountNanosUint64,
		PublicKey:   txn.PublicKey,
		BlockHeight: blockHeight,
		UtxoType:    UtxoTypeUnlockedStake,
		UtxoKey:     &outputKey,
	}
	utxoOp, err := bav._addDESO(totalUnlockedAmountNanosUint64, txn.PublicKey, &utxoEntry, blockHeight)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnlockStake: ")
	}
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)

	// Add a UTXO operation
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                   OperationTypeUnlockStake,
		PrevLockedStakeEntries: prevLockedStakeEntries,
	})
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectUnlockStake(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_disconnectUnlockStake: ")
	}

	// Validate the last operation is an UnlockStake operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUnlockStake: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	operationData := utxoOpsForTxn[operationIndex]
	if operationData.Type != OperationTypeUnlockStake {
		return fmt.Errorf(
			"_disconnectUnlockStake: trying to revert %v but found %v",
			OperationTypeUnlockStake,
			operationData.Type,
		)
	}

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorInvalidStakerPKID
	}

	// Calculate the TotalUnlockedAmountNanos.
	totalUnlockedAmountNanos := uint256.NewInt()
	var err error
	for _, prevLockedStakeEntry := range operationData.PrevLockedStakeEntries {
		totalUnlockedAmountNanos, err = SafeUint256().Add(
			totalUnlockedAmountNanos, prevLockedStakeEntry.LockedAmountNanos,
		)
		if err != nil {
			return errors.Wrapf(err, "_disconnectUnlockStake: ")
		}
	}
	if !totalUnlockedAmountNanos.IsUint64() {
		return RuleErrorInvalidUnlockStakeUnlockableStakeOverflowsUint64
	}

	// Restore the PrevLockedStakeEntries.
	for _, prevLockedStakeEntry := range operationData.PrevLockedStakeEntries {
		bav._setLockedStakeEntryMappings(prevLockedStakeEntry)
	}

	// Unadd TotalUnlockedAmountNanos from the transactor.
	err = bav._unAddBalance(totalUnlockedAmountNanos.Uint64(), currentTxn.PublicKey)
	if err != nil {
		return errors.Wrapf(err, "_disconnectUnlockStake: ")
	}

	// Disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txHash, utxoOpsForTxn[:operationIndex], blockHeight,
	)
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
	if validatorEntry == nil || validatorEntry.isDeleted || validatorEntry.DisableDelegatedStake {
		return RuleErrorInvalidValidatorPKID
	}

	// Validate 0 < StakeAmountNanos <= transactor's DESO Balance. We ignore
	// the txn fees in this check. The StakeAmountNanos will be validated to
	// be less than the transactor's DESO balance net of txn fees in the call
	// to connectBasicTransferWithExtraSpend.
	if metadata.StakeAmountNanos == nil ||
		metadata.StakeAmountNanos.IsZero() ||
		!metadata.StakeAmountNanos.IsUint64() {
		return RuleErrorInvalidStakeAmountNanos
	}
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
	if validatorEntry == nil || validatorEntry.isDeleted {
		return RuleErrorInvalidValidatorPKID
	}

	// Validate StakeEntry exists.
	stakeEntry, err := bav.GetStakeEntry(validatorPKIDEntry.PKID, transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "IsValidUnstakeMetadata: ")
	}
	if stakeEntry == nil || stakeEntry.isDeleted {
		return RuleErrorInvalidUnstakeNoStakeFound
	}

	// Validate 0 < UnstakeAmountNanos <= StakeEntry.StakeAmountNanos.
	if metadata.UnstakeAmountNanos == nil || metadata.UnstakeAmountNanos.IsZero() {
		return RuleErrorInvalidUnstakeAmountNanos
	}
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
	existsLockedStakeEntries := false
	for _, lockedStakeEntry := range lockedStakeEntries {
		if lockedStakeEntry != nil && !lockedStakeEntry.isDeleted {
			existsLockedStakeEntries = true
			break
		}
	}
	if !existsLockedStakeEntries {
		return RuleErrorInvalidUnlockStakeNoUnlockableStakeFound
	}

	return nil
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
				"_flushLockedStakeEntriesToDbWithTxn: LockedStakeEntry key %v doesn't match MapKey %v",
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

	// Convert TransactorPublicKeyBytes to StakerPublicKeyBase58Check.
	stakerPublicKeyBase58Check := PkToString(txn.PublicKey, bav.Params)

	// Convert ValidatorPublicKey to ValidatorPublicKeyBase58Check.
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

	// Convert TransactorPublicKeyBytes to StakerPublicKeyBase58Check.
	stakerPublicKeyBase58Check := PkToString(txn.PublicKey, bav.Params)

	// Convert ValidatorPublicKey to ValidatorPublicKeyBase58Check.
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

	// Convert TransactorPublicKeyBytes to StakerPublicKeyBase58Check.
	stakerPublicKeyBase58Check := PkToString(txn.PublicKey, bav.Params)

	// Convert ValidatorPublicKey to ValidatorPublicKeyBase58Check.
	validatorPublicKeyBase58Check := PkToString(metadata.ValidatorPublicKey.ToBytes(), bav.Params)

	// Calculate TotalUnlockedAmountNanos.
	totalUnlockedAmountNanos := uint256.NewInt()
	var err error
	for _, prevLockedStakeEntry := range utxoOp.PrevLockedStakeEntries {
		totalUnlockedAmountNanos, err = SafeUint256().Add(
			totalUnlockedAmountNanos, prevLockedStakeEntry.LockedAmountNanos,
		)
		if err != nil {
			glog.Errorf("CreateUnlockStakeTxindexMetadata: error calculating TotalUnlockedAmountNanos: %v", err)
			totalUnlockedAmountNanos = uint256.NewInt()
			break
		}
	}

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
// TRANSACTION SPENDING LIMITS
//

type StakeLimitKey struct {
	ValidatorPKID PKID
	StakerPKID    PKID
}

func MakeStakeLimitKey(validatorPKID *PKID, stakerPKID *PKID) StakeLimitKey {
	return StakeLimitKey{
		ValidatorPKID: *validatorPKID,
		StakerPKID:    *stakerPKID,
	}
}

func (stakeLimitKey *StakeLimitKey) Encode() []byte {
	var data []byte
	data = append(data, stakeLimitKey.ValidatorPKID.ToBytes()...)
	data = append(data, stakeLimitKey.StakerPKID.ToBytes()...)
	return data
}

func (stakeLimitKey *StakeLimitKey) Decode(rr *bytes.Reader) error {
	var err error

	// ValidatorPKID
	validatorPKID := &PKID{}
	if err = validatorPKID.FromBytes(rr); err != nil {
		return errors.Wrap(err, "StakeLimitKey.Decode: Problem reading ValidatorPKID: ")
	}
	stakeLimitKey.ValidatorPKID = *validatorPKID

	// StakerPKID
	stakerPKID := &PKID{}
	if err = stakerPKID.FromBytes(rr); err != nil {
		return errors.Wrap(err, "StakeLimitKey.Decode: Problem reading StakerPKID: ")
	}
	stakeLimitKey.StakerPKID = *stakerPKID

	return nil
}

func (bav *UtxoView) _checkStakeTxnSpendingLimitAndUpdateDerivedKey(
	derivedKeyEntry DerivedKeyEntry,
	transactorPublicKeyBytes []byte,
	txMeta *StakeMetadata,
) (DerivedKeyEntry, error) {
	// The DerivedKeyEntry.TransactionSpendingLimit for staking maps
	// ValidatorPKID || StakerPKID to the amount of stake-able DESO
	// nanos allowed for this derived key.

	// Convert TransactorPublicKeyBytes to StakerPKID.
	stakerPKIDEntry := bav.GetPKIDForPublicKey(transactorPublicKeyBytes)
	if stakerPKIDEntry == nil || stakerPKIDEntry.isDeleted {
		return derivedKeyEntry, RuleErrorInvalidStakerPKID
	}

	// Convert ValidatorPublicKey to ValidatorPKID.
	validatorEntry, err := bav.GetValidatorByPublicKey(txMeta.ValidatorPublicKey)
	if err != nil {
		return derivedKeyEntry, errors.Wrapf(err, "_checkStakeTxnSpendingLimitAndUpdateDerivedKey: ")
	}
	if validatorEntry == nil || validatorEntry.isDeleted {
		return derivedKeyEntry, RuleErrorInvalidValidatorPKID
	}

	// Check spending limit for this validator.
	// If not found, check spending limit for any validator.
	for _, validatorPKID := range []*PKID{validatorEntry.ValidatorPKID, &ZeroPKID} {
		// Retrieve DerivedKeyEntry.TransactionSpendingLimit.
		stakeLimitKey := MakeStakeLimitKey(validatorPKID, stakerPKIDEntry.PKID)
		spendingLimit, exists := derivedKeyEntry.TransactionSpendingLimitTracker.StakeLimitMap[stakeLimitKey]
		if !exists {
			continue
		}
		spendingLimitUint256 := uint256.NewInt().SetUint64(spendingLimit)

		// If the amount being staked exceeds the spending limit, error.
		if spendingLimitUint256.Cmp(txMeta.StakeAmountNanos) < 0 {
			return derivedKeyEntry, RuleErrorStakeTransactionSpendingLimitExceeded
		}

		// If the spending limit exceeds the amount being staked, update the spending limit.
		if spendingLimitUint256.Cmp(txMeta.StakeAmountNanos) > 0 {
			updatedSpendingLimit, err := SafeUint256().Sub(spendingLimitUint256, txMeta.StakeAmountNanos)
			if err != nil {
				return derivedKeyEntry, errors.Wrapf(err, "_checkStakeTxnSpendingLimitAndUpdateDerivedKey: ")
			}
			if !updatedSpendingLimit.IsUint64() {
				// This should never happen, but good to double-check.
				return derivedKeyEntry, errors.New(
					"_checkStakeTxnSpendingLimitAndUpdateDerivedKey: updated spending limit exceeds uint64",
				)
			}
			derivedKeyEntry.TransactionSpendingLimitTracker.StakeLimitMap[stakeLimitKey] = updatedSpendingLimit.Uint64()
			return derivedKeyEntry, nil
		}

		// If we get to this point, the spending limit exactly equals
		// the amount being staked. Delete the spending limit.
		delete(derivedKeyEntry.TransactionSpendingLimitTracker.StakeLimitMap, stakeLimitKey)
		return derivedKeyEntry, nil
	}

	// If we get to this point, we didn't find a matching spending limit.
	return derivedKeyEntry, RuleErrorStakeTransactionSpendingLimitNotFound
}

func (bav *UtxoView) _checkUnstakeTxnSpendingLimitAndUpdateDerivedKey(
	derivedKeyEntry DerivedKeyEntry,
	transactorPublicKeyBytes []byte,
	txMeta *UnstakeMetadata,
) (DerivedKeyEntry, error) {
	// The DerivedKeyEntry.TransactionSpendingLimit for unstaking maps
	// ValidatorPKID || StakerPKID to the amount of unstake-able DESO
	// nanos allowed for this derived key.

	// Convert TransactorPublicKeyBytes to StakerPKID.
	stakerPKIDEntry := bav.GetPKIDForPublicKey(transactorPublicKeyBytes)
	if stakerPKIDEntry == nil || stakerPKIDEntry.isDeleted {
		return derivedKeyEntry, RuleErrorInvalidStakerPKID
	}

	// Convert ValidatorPublicKey to ValidatorPKID.
	validatorEntry, err := bav.GetValidatorByPublicKey(txMeta.ValidatorPublicKey)
	if err != nil {
		return derivedKeyEntry, errors.Wrapf(err, "_checkUnstakeTxnSpendingLimitAndUpdateDerivedKey: ")
	}
	if validatorEntry == nil || validatorEntry.isDeleted {
		return derivedKeyEntry, RuleErrorInvalidValidatorPKID
	}

	// Check spending limit for this validator.
	// If not found, check spending limit for any validator.
	for _, validatorPKID := range []*PKID{validatorEntry.ValidatorPKID, &ZeroPKID} {
		// Retrieve DerivedKeyEntry.TransactionSpendingLimit.
		stakeLimitKey := MakeStakeLimitKey(validatorPKID, stakerPKIDEntry.PKID)
		spendingLimit, exists := derivedKeyEntry.TransactionSpendingLimitTracker.UnstakeLimitMap[stakeLimitKey]
		if !exists {
			continue
		}
		spendingLimitUint256 := uint256.NewInt().SetUint64(spendingLimit)

		// If the amount being unstaked exceeds the spending limit, error.
		if spendingLimitUint256.Cmp(txMeta.UnstakeAmountNanos) < 0 {
			return derivedKeyEntry, RuleErrorUnstakeTransactionSpendingLimitExceeded
		}

		// If the spending limit exceeds the amount being unstaked, update the spending limit.
		if spendingLimitUint256.Cmp(txMeta.UnstakeAmountNanos) > 0 {
			updatedSpendingLimit, err := SafeUint256().Sub(spendingLimitUint256, txMeta.UnstakeAmountNanos)
			if err != nil {
				return derivedKeyEntry, errors.Wrapf(err, "_checkUnstakeTxnSpendingLimitAndUpdateDerivedKey: ")
			}
			if !updatedSpendingLimit.IsUint64() {
				// This should never happen, but good to double-check.
				return derivedKeyEntry, errors.New(
					"_checkUnstakeTxnSpendingLimitAndUpdateDerivedKey: updated spending limit exceeds uint64",
				)
			}
			derivedKeyEntry.TransactionSpendingLimitTracker.UnstakeLimitMap[stakeLimitKey] = updatedSpendingLimit.Uint64()
			return derivedKeyEntry, nil
		}

		// If we get to this point, the spending limit exactly equals
		// the amount being unstaked. Delete the spending limit.
		delete(derivedKeyEntry.TransactionSpendingLimitTracker.UnstakeLimitMap, stakeLimitKey)
		return derivedKeyEntry, nil
	}

	// If we get to this point, we didn't find a matching spending limit.
	return derivedKeyEntry, RuleErrorUnstakeTransactionSpendingLimitNotFound
}

func (bav *UtxoView) _checkUnlockStakeTxnSpendingLimitAndUpdateDerivedKey(
	derivedKeyEntry DerivedKeyEntry,
	transactorPublicKeyBytes []byte,
	txMeta *UnlockStakeMetadata,
) (DerivedKeyEntry, error) {
	// The DerivedKeyEntry.TransactionSpendingLimit for unlocking stake maps
	// ValidatorPKID || StakerPKID to the number of UnlockStake transactions
	// this derived key is allowed to perform.

	// Convert TransactorPublicKeyBytes to StakerPKID.
	stakerPKIDEntry := bav.GetPKIDForPublicKey(transactorPublicKeyBytes)
	if stakerPKIDEntry == nil || stakerPKIDEntry.isDeleted {
		return derivedKeyEntry, RuleErrorInvalidStakerPKID
	}

	// Convert ValidatorPublicKey to ValidatorPKID.
	validatorEntry, err := bav.GetValidatorByPublicKey(txMeta.ValidatorPublicKey)
	if err != nil {
		return derivedKeyEntry, errors.Wrapf(err, "_checkUnlockStakeTxnSpendingLimitAndUpdateDerivedKey: ")
	}
	if validatorEntry == nil || validatorEntry.isDeleted {
		return derivedKeyEntry, RuleErrorInvalidValidatorPKID
	}

	// Check spending limit for this validator.
	// If not found, check spending limit for any validator.
	for _, validatorPKID := range []*PKID{validatorEntry.ValidatorPKID, &ZeroPKID} {
		// Retrieve DerivedKeyEntry.TransactionSpendingLimit.
		stakeLimitKey := MakeStakeLimitKey(validatorPKID, stakerPKIDEntry.PKID)
		spendingLimit, exists := derivedKeyEntry.TransactionSpendingLimitTracker.UnlockStakeLimitMap[stakeLimitKey]
		if !exists || spendingLimit <= 0 {
			continue
		}

		// Delete the spending limit if we've exhausted the spending limit for this key.
		if spendingLimit == 1 {
			delete(derivedKeyEntry.TransactionSpendingLimitTracker.UnlockStakeLimitMap, stakeLimitKey)
		} else {
			// Otherwise decrement it by 1.
			derivedKeyEntry.TransactionSpendingLimitTracker.UnlockStakeLimitMap[stakeLimitKey]--
		}

		// If we get to this point, we found a matching spending limit which we either deleted or decremented.
		return derivedKeyEntry, nil
	}

	// If we get to this point, we didn't find a matching spending limit.
	return derivedKeyEntry, RuleErrorUnlockStakeTransactionSpendingLimitNotFound
}

func (bav *UtxoView) IsValidStakeLimitKey(transactorPublicKeyBytes []byte, stakeLimitKey StakeLimitKey) error {
	// Convert TransactorPublicKeyBytes to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPublicKeyBytes)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorTransactionSpendingLimitInvalidStaker
	}

	// Verify TransactorPKID == StakerPKID.
	if !transactorPKIDEntry.PKID.Eq(&stakeLimitKey.StakerPKID) {
		return RuleErrorTransactionSpendingLimitInvalidStaker
	}

	// Verify ValidatorEntry.
	if stakeLimitKey.ValidatorPKID.Eq(&ZeroPKID) {
		// The ZeroPKID is a special case that indicates that the spending limit
		// applies to any validator. In this case, we don't need to check that the
		// validator exists, as there is no validator registered for the ZeroPKID.
		return nil
	}
	validatorEntry, err := bav.GetValidatorByPKID(&stakeLimitKey.ValidatorPKID)
	if err != nil {
		return errors.Wrapf(err, "IsValidStakeLimitKey: ")
	}
	if validatorEntry == nil || validatorEntry.isDeleted || validatorEntry.DisableDelegatedStake {
		return RuleErrorTransactionSpendingLimitInvalidValidator
	}

	return nil
}

//
// CONSTANTS
//

const RuleErrorInvalidStakerPKID RuleError = "RuleErrorInvalidStakerPKID"
const RuleErrorInvalidStakeAmountNanos RuleError = "RuleErrorInvalidStakeAmountNanos"
const RuleErrorInvalidStakeInsufficientBalance RuleError = "RuleErrorInvalidStakeInsufficientBalance"
const RuleErrorInvalidUnstakeNoStakeFound RuleError = "RuleErrorInvalidUnstakeNoStakeFound"
const RuleErrorInvalidUnstakeAmountNanos RuleError = "RuleErrorInvalidUnstakeAmountNanos"
const RuleErrorInvalidUnstakeInsufficientStakeFound RuleError = "RuleErrorInvalidUnstakeInsufficientStakeFound"
const RuleErrorInvalidUnlockStakeEpochRange RuleError = "RuleErrorInvalidUnlockStakeEpochRange"
const RuleErrorInvalidUnlockStakeNoUnlockableStakeFound RuleError = "RuleErrorInvalidUnlockStakeNoUnlockableStakeFound"
const RuleErrorInvalidUnlockStakeUnlockableStakeOverflowsUint64 RuleError = "RuleErrorInvalidUnlockStakeUnlockableStakeOverflowsUint64"
const RuleErrorStakeTransactionSpendingLimitNotFound RuleError = "RuleErrorStakeTransactionSpendingLimitNotFound"
const RuleErrorStakeTransactionSpendingLimitExceeded RuleError = "RuleErrorStakeTransactionSpendingLimitExceeded"
const RuleErrorUnstakeTransactionSpendingLimitNotFound RuleError = "RuleErrorUnstakeTransactionSpendingLimitNotFound"
const RuleErrorUnstakeTransactionSpendingLimitExceeded RuleError = "RuleErrorUnstakeTransactionSpendingLimitExceeded"
const RuleErrorUnlockStakeTransactionSpendingLimitNotFound RuleError = "RuleErrorUnlockStakeTransactionSpendingLimitNotFound"
const RuleErrorTransactionSpendingLimitInvalidStaker RuleError = "RuleErrorTransactionSpendingLimitInvalidStaker"
const RuleErrorTransactionSpendingLimitInvalidValidator RuleError = "RuleErrorTransactionSpendingLimitInvalidValidator"
