package lib

import (
	"bytes"
	"fmt"
	"github.com/google/uuid"
	"sort"

	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

// Stake: Any user can assign stake to a registered validator who allows delegated stake.
// When a user stakes with a validator, they lock up $DESO from their account balance
// into a StakeEntry. As reward for staking, a user is eligible to receive a percentage
// of the block rewards attributed to the validator. Any staked $DESO is unspendable
// until the user unstakes and unlocks their stake. See below.
//
// Unstake: If a user wants to retrieve their funds from being staked with a validator,
// they must submit an Unstake transaction. This deletes or updates their existing
// StakeEntry and creates or updates a LockedStakeEntry. Unstaked stake is not immediately
// withdrawalable and usable. It is locked for a period of time as determined by a consensus
// parameter. This is to prevent byzantine users from trying to game block rewards or
// leader schedules.
//
// UnlockStake: Once sufficient time has elapsed since unstaking their funds, a user can
// submit an UnlockStake transaction to retrieve their funds. Any eligible funds are
// unlocked and returned to the user's account balance.

//
// TYPES: StakeEntry
//

type StakingRewardMethod = uint8

const (
	StakingRewardMethodPayToBalance StakingRewardMethod = 0
	StakingRewardMethodRestake      StakingRewardMethod = 1
	StakingRewardMethodUnknown      StakingRewardMethod = 2
)

type StakeEntry struct {
	StakerPKID       *PKID
	ValidatorPKID    *PKID
	RewardMethod     StakingRewardMethod
	StakeAmountNanos *uint256.Int
	ExtraData        map[string][]byte
	isDeleted        bool
}

type StakeMapKey struct {
	ValidatorPKID PKID
	StakerPKID    PKID
}

func (stakeEntry *StakeEntry) Copy() *StakeEntry {
	return &StakeEntry{
		StakerPKID:       stakeEntry.StakerPKID.NewPKID(),
		ValidatorPKID:    stakeEntry.ValidatorPKID.NewPKID(),
		RewardMethod:     stakeEntry.RewardMethod,
		StakeAmountNanos: stakeEntry.StakeAmountNanos.Clone(),
		ExtraData:        copyExtraData(stakeEntry.ExtraData),
		isDeleted:        stakeEntry.isDeleted,
	}
}

func (stakeEntry *StakeEntry) Eq(other *StakeEntry) bool {
	return stakeEntry.ToMapKey() == other.ToMapKey()
}

func (stakeEntry *StakeEntry) ToMapKey() StakeMapKey {
	return StakeMapKey{
		StakerPKID:    *stakeEntry.StakerPKID,
		ValidatorPKID: *stakeEntry.ValidatorPKID,
	}
}

func (stakeEntry *StakeEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, stakeEntry.StakerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, stakeEntry.ValidatorPKID, skipMetadata...)...)
	data = append(data, stakeEntry.RewardMethod)
	data = append(data, VariableEncodeUint256(stakeEntry.StakeAmountNanos)...)
	data = append(data, EncodeExtraData(stakeEntry.ExtraData)...)
	return data
}

func (stakeEntry *StakeEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// StakerPKID
	stakeEntry.StakerPKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "StakeEntry.Decode: Problem reading StakerPKID: ")
	}

	// ValidatorPKID
	stakeEntry.ValidatorPKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "StakeEntry.Decode: Problem reading ValidatorPKID: ")
	}

	// RewardMethod
	stakeEntry.RewardMethod, err = rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "StakeEntry.Decode: Problem reading RewardMethod")
	}

	// StakeAmountNanos
	stakeEntry.StakeAmountNanos, err = VariableDecodeUint256(rr)
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
	return &LockedStakeEntry{
		StakerPKID:          lockedStakeEntry.StakerPKID.NewPKID(),
		ValidatorPKID:       lockedStakeEntry.ValidatorPKID.NewPKID(),
		LockedAmountNanos:   lockedStakeEntry.LockedAmountNanos.Clone(),
		LockedAtEpochNumber: lockedStakeEntry.LockedAtEpochNumber,
		ExtraData:           copyExtraData(lockedStakeEntry.ExtraData),
		isDeleted:           lockedStakeEntry.isDeleted,
	}
}

func (lockedStakeEntry *LockedStakeEntry) Eq(other *LockedStakeEntry) bool {
	return lockedStakeEntry.ToMapKey() == other.ToMapKey()
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
	data = append(data, EncodeToBytes(blockHeight, lockedStakeEntry.StakerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, lockedStakeEntry.ValidatorPKID, skipMetadata...)...)
	data = append(data, VariableEncodeUint256(lockedStakeEntry.LockedAmountNanos)...)
	data = append(data, UintToBuf(lockedStakeEntry.LockedAtEpochNumber)...)
	data = append(data, EncodeExtraData(lockedStakeEntry.ExtraData)...)
	return data
}

func (lockedStakeEntry *LockedStakeEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// StakerPKID
	lockedStakeEntry.StakerPKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "LockedStakeEntry.Decode: Problem reading StakerPKID: ")
	}

	// ValidatorPKID
	lockedStakeEntry.ValidatorPKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "LockedStakeEntry.Decode: Problem reading ValidatorPKID: ")
	}

	// LockedAmountNanos
	lockedStakeEntry.LockedAmountNanos, err = VariableDecodeUint256(rr)
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

func (lockedStakeEntry *LockedStakeEntry) IsDeleted() bool {
	return lockedStakeEntry.isDeleted
}

//
// TYPES: StakeMetadata
//

type StakeMetadata struct {
	ValidatorPublicKey *PublicKey
	RewardMethod       StakingRewardMethod
	StakeAmountNanos   *uint256.Int
}

func (txnData *StakeMetadata) GetTxnType() TxnType {
	return TxnTypeStake
}

func (txnData *StakeMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ValidatorPublicKey.ToBytes())...)
	data = append(data, txnData.RewardMethod)
	data = append(data, VariableEncodeUint256(txnData.StakeAmountNanos)...)
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

	// RewardMethod
	txnData.RewardMethod, err = rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "StakeMetadata.FromBytes: Problem reading RewardMethod: ")
	}

	// StakeAmountNanos
	txnData.StakeAmountNanos, err = VariableDecodeUint256(rr)
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
	data = append(data, VariableEncodeUint256(txnData.UnstakeAmountNanos)...)
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
	txnData.UnstakeAmountNanos, err = VariableDecodeUint256(rr)
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
	RewardMethod                  StakingRewardMethod
	StakeAmountNanos              *uint256.Int
}

func (txindexMetadata *StakeTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(txindexMetadata.StakerPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(txindexMetadata.ValidatorPublicKeyBase58Check))...)
	data = append(data, txindexMetadata.RewardMethod)
	data = append(data, VariableEncodeUint256(txindexMetadata.StakeAmountNanos)...)
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

	// RewardMethod
	txindexMetadata.RewardMethod, err = rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "StakeTxindexMetadata.Decode: Problem reading RewardMethod: ")
	}

	// StakeAmountNanos
	txindexMetadata.StakeAmountNanos, err = VariableDecodeUint256(rr)
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
	data = append(data, VariableEncodeUint256(txindexMetadata.UnstakeAmountNanos)...)
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
	txindexMetadata.UnstakeAmountNanos, err = VariableDecodeUint256(rr)
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
	data = append(data, VariableEncodeUint256(txindexMetadata.TotalUnlockedAmountNanos)...)
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
	txindexMetadata.TotalUnlockedAmountNanos, err = VariableDecodeUint256(rr)
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

func DBKeyForStakeByValidatorAndStaker(validatorPKID *PKID, stakerPKID *PKID) []byte {
	data := DBKeyForStakeByValidator(validatorPKID)
	data = append(data, stakerPKID.ToBytes()...)
	return data
}

func DBKeyForStakeByValidator(validatorPKID *PKID) []byte {
	data := append([]byte{}, Prefixes.PrefixStakeByValidatorAndStaker...)
	data = append(data, validatorPKID.ToBytes()...)
	return data
}

func DBKeyForStakeByStakeAmount(stakeEntry *StakeEntry) []byte {
	data := append([]byte{}, Prefixes.PrefixStakeByStakeAmount...)
	data = append(data, FixedWidthEncodeUint256(stakeEntry.StakeAmountNanos)...)
	data = append(data, stakeEntry.ValidatorPKID.ToBytes()...)
	data = append(data, stakeEntry.StakerPKID.ToBytes()...)
	return data
}

func GetValidatorPKIDFromDBKeyForStakeByStakeAmount(key []byte) (*PKID, error) {
	validatorPKIDBytes := key[len(key)-(PublicKeyLenCompressed*2) : len(key)-PublicKeyLenCompressed]
	if len(validatorPKIDBytes) != PublicKeyLenCompressed {
		return nil, fmt.Errorf("GetValidatorPKIDFromDBKeyForStakeByStakeAmount: invalid key length")
	}
	return NewPKID(validatorPKIDBytes), nil
}

func GetStakerPKIDFromDBKeyForStakeByStakeAmount(key []byte) (*PKID, error) {
	stakerPKIDBytes := key[len(key)-(PublicKeyLenCompressed):]
	if len(stakerPKIDBytes) != PublicKeyLenCompressed {
		return nil, fmt.Errorf("GetStakerPKIDFromDBKeyForStakeByStakeAmount: invalid key length")
	}
	return NewPKID(stakerPKIDBytes), nil
}

func DBKeyForLockedStakeByValidatorAndStakerAndLockedAt(lockedStakeEntry *LockedStakeEntry) []byte {
	data := DBPrefixKeyForLockedStakeByValidatorAndStaker(lockedStakeEntry)
	data = append(data, EncodeUint64(lockedStakeEntry.LockedAtEpochNumber)...)
	return data
}

func DBPrefixKeyForLockedStakeByValidatorAndStaker(lockedStakeEntry *LockedStakeEntry) []byte {
	data := append([]byte{}, Prefixes.PrefixLockedStakeByValidatorAndStakerAndLockedAt...)
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
	key := DBKeyForStakeByValidatorAndStaker(validatorPKID, stakerPKID)
	stakeEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetStakeEntry: problem retrieving StakeEntry: ")
	}

	// Decode StakeEntry from bytes.
	rr := bytes.NewReader(stakeEntryBytes)
	stakeEntry, err := DecodeDeSoEncoder(&StakeEntry{}, rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetStakeEntry: problem decoding StakeEntry: ")
	}
	return stakeEntry, nil
}

func DBGetStakeEntriesForValidatorPKID(handle *badger.DB, snap *Snapshot, validatorPKID *PKID) ([]*StakeEntry, error) {
	// Retrieve StakeEntries from db.
	prefix := DBKeyForStakeByValidator(validatorPKID)
	_, valsFound, err := EnumerateKeysForPrefixWithLimitOffsetOrder(
		handle, prefix, 0, nil, false, NewSet([]string{}),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetStakeEntriesForValidatorPKID: problem retrieving StakeEntries: ")
	}

	// Decode StakeEntries from bytes.
	var stakeEntries []*StakeEntry
	for _, stakeEntryBytes := range valsFound {
		rr := bytes.NewReader(stakeEntryBytes)
		stakeEntry, err := DecodeDeSoEncoder(&StakeEntry{}, rr)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetStakeEntriesForValidatorPKID: problem decoding StakeEntry: ")
		}
		stakeEntries = append(stakeEntries, stakeEntry)
	}
	return stakeEntries, nil
}

func DBGetTopStakesForValidatorsByStakeAmount(
	handle *badger.DB,
	snap *Snapshot,
	limit uint64,
	validatorPKIDsToInclude *Set[PKID],
	stakeEntriesToSkip []*StakeEntry,
) ([]*StakeEntry, error) {
	var stakeEntries []*StakeEntry

	// Convert StakeEntriesToSkip to StakeMapKey we need to skip. We use StakeMapKey
	// here because we need to skip each StakeEntry based on both its ValidatorPKID and
	// StakerPKID.
	stakeMapKeysToSkip := NewSet([]StakeMapKey{})
	for _, stakeEntryToSkip := range stakeEntriesToSkip {
		stakeMapKeysToSkip.Add(stakeEntryToSkip.ToMapKey())
	}

	// Define a function to filter out ValidatorPKID-StakerPKID pairs that we want to skip while
	// seeking through the DB. We can't simply pass in the exact keys from the UtxoView that we
	// need to skip through because it's possible that the stake entries (and their stake amounts)
	// have changed in the UtxoView, and no longer match the stake amounts in the DB used to index them.
	canSkipValidatorPKIDAndStakerPKIDInBadgerSeek := func(badgerKey []byte) bool {
		// Parse both the validator PKID and staker PKID from the key. Just to be safe, we return false if
		// we fail to parse them. Once the seek has completed, we attempt to parse all of the same keys a
		// second time below. Any failures there will result in an error that we can propagate to the caller.
		validatorPKID, err := GetValidatorPKIDFromDBKeyForStakeByStakeAmount(badgerKey)
		if err != nil {
			return false
		}

		if !validatorPKIDsToInclude.Includes(*validatorPKID) {
			return true
		}

		stakerPKID, err := GetStakerPKIDFromDBKeyForStakeByStakeAmount(badgerKey)
		if err != nil {
			return false
		}

		return stakeMapKeysToSkip.Includes(StakeMapKey{
			ValidatorPKID: *validatorPKID,
			StakerPKID:    *stakerPKID,
		})
	}

	// Retrieve top N StakeEntry keys by stake amount.
	key := append([]byte{}, Prefixes.PrefixStakeByStakeAmount...)
	keysFound, err := EnumerateKeysOnlyForPrefixWithLimitOffsetOrderAndSkipFunc(
		handle, key, int(limit), nil, true, canSkipValidatorPKIDAndStakerPKIDInBadgerSeek,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetTopStakesForValidatorsByStakeAmount: problem retrieving top stakes: ")
	}

	// For each key found, parse the staker PKID and validator PKID from the key, then retrieve the StakeEntry.:len(keyFound)-PublicKeyLenCompressed
	for _, keyFound := range keysFound {
		// Extract the validator PKID from the key.
		validatorPKID, err := GetValidatorPKIDFromDBKeyForStakeByStakeAmount(keyFound)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetTopStakesForValidatorsByStakeAmount: problem reading ValidatorPKID: ")
		}

		// Extract the staker PKID from the key.
		stakerPKID, err := GetStakerPKIDFromDBKeyForStakeByStakeAmount(keyFound)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetTopStakesForValidatorsByStakeAmount: problem reading StakerPKID: ")
		}

		// Retrieve StakeEntry from db.
		stakeEntry, err := DBGetStakeEntry(handle, snap, validatorPKID, stakerPKID)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetTopStakesForValidatorsByStakeAmount: problem retrieving stake entry: ")
		}
		stakeEntries = append(stakeEntries, stakeEntry)
	}

	return stakeEntries, nil
}

func DBValidatorHasDelegatedStake(
	handle *badger.DB,
	snap *Snapshot,
	validatorPKID *PKID,
	utxoDeletedStakeEntries []*StakeEntry,
) (bool, error) {
	// Skip any stake the validator has assigned to himself (if exists).
	skipKeys := NewSet([]string{
		string(DBKeyForStakeByValidatorAndStaker(validatorPKID, validatorPKID)),
	})

	// Skip any StakeEntries deleted in the UtxoView.
	for _, utxoDeletedStakeEntry := range utxoDeletedStakeEntries {
		skipKeys.Add(string(DBKeyForStakeByValidatorAndStaker(utxoDeletedStakeEntry.ValidatorPKID, utxoDeletedStakeEntry.StakerPKID)))
	}

	// Scan for any delegated StakeEntries (limiting to at most one row).
	prefix := DBKeyForStakeByValidator(validatorPKID)
	keysFound, _, err := EnumerateKeysForPrefixWithLimitOffsetOrder(
		handle, prefix, 1, nil, false, skipKeys,
	)
	if err != nil {
		return false, errors.Wrapf(err, "DBValidatorHasDelegatedStake: problem retrieving StakeEntries: ")
	}

	// Return true if any delegated StakeEntries were found.
	return len(keysFound) > 0, nil
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
	key := DBKeyForLockedStakeByValidatorAndStakerAndLockedAt(&LockedStakeEntry{
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
			err, "DBGetLockedStakeEntry: problem retrieving LockedStakeEntry: ",
		)
	}

	// Decode LockedStakeEntry from bytes.
	rr := bytes.NewReader(lockedStakeEntryBytes)
	lockedStakeEntry, err := DecodeDeSoEncoder(&LockedStakeEntry{}, rr)
	if err != nil {
		return nil, errors.Wrapf(
			err, "DBGetLockedStakeEntry: problem decoding LockedStakeEntry: ",
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
	startKey := DBKeyForLockedStakeByValidatorAndStakerAndLockedAt(&LockedStakeEntry{
		ValidatorPKID:       validatorPKID,
		StakerPKID:          stakerPKID,
		LockedAtEpochNumber: startEpochNumber,
	})

	// Consider only LockedStakeEntries for this ValidatorPKID, StakerPKID.
	prefixKey := DBPrefixKeyForLockedStakeByValidatorAndStaker(&LockedStakeEntry{
		ValidatorPKID: validatorPKID,
		StakerPKID:    stakerPKID,
	})

	// Create an iterator.
	opts := badger.DefaultIteratorOptions
	opts.Prefix = prefixKey
	iterator := txn.NewIterator(opts)
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
		rr := bytes.NewReader(lockedStakeEntryBytes)
		lockedStakeEntry, err := DecodeDeSoEncoder(&LockedStakeEntry{}, rr)
		if err != nil {
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

// In order to optimize the flush, we want to only write entries to the db that have changed.
// On top of that, we add a further optimization to only update the
// PrefixStakeByStakeAmount index if the stake amount has changed. Not doing this results
// in a lot of writes to badger every epoch that eventually slow block processing to a crawl.
// This is essentially a bug in badger when you repeatedly write to the same key, and we're
// papering over it here in response to encountering the issue. In an ideal world, badger
// would work as intended and this extra optimization wouldn't be necessary.
func DBUpdateStakeEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	stakeEntry *StakeEntry,
	blockHeight uint64,
	eventManager *EventManager,
) error {
	if stakeEntry == nil {
		return nil
	}

	// Fetch the existing entry from the db so we can potentially avoid an update
	dbEntry, err := DBGetStakeEntryWithTxn(
		txn, snap, stakeEntry.ValidatorPKID, stakeEntry.StakerPKID)
	if err != nil {
		return errors.Wrapf(err, "_flushStakeEntriesToDbWithTxn: ")
	}
	dbEntryBytes := EncodeToBytes(blockHeight, dbEntry)
	// Serialize the entry to bytes
	entryToWriteBytes := EncodeToBytes(blockHeight, stakeEntry)
	// If the entry we're about to write is the exact same as what's already in the db then
	// don't write it.
	if bytes.Equal(dbEntryBytes, entryToWriteBytes) {
		if eventManager != nil {
			// We explicitly emit an upsert operation here for state syncer
			// for the case where the entry is the same.
			eventManager.stateSyncerOperation(&StateSyncerOperationEvent{
				StateChangeEntry: &StateChangeEntry{
					OperationType:        DbOperationTypeUpsert,
					KeyBytes:             DBKeyForStakeByValidatorAndStaker(stakeEntry.ValidatorPKID, stakeEntry.StakerPKID),
					EncoderBytes:         entryToWriteBytes,
					AncestralRecordBytes: dbEntryBytes,
					IsReverted:           false,
				},
				FlushId:      uuid.Nil,
				IsMempoolTxn: eventManager.isMempoolManager,
			})
		}
		return nil
	}

	// Set StakeEntry in PrefixStakeByValidatorByStaker. This should gracefully overwrite an existing entry
	// if one exists so no need to delete before adding it.
	stakeByValidatorAndStakerKey := DBKeyForStakeByValidatorAndStaker(stakeEntry.ValidatorPKID, stakeEntry.StakerPKID)
	if err := DBSetWithTxn(txn, snap, stakeByValidatorAndStakerKey, EncodeToBytes(blockHeight, stakeEntry), eventManager); err != nil {
		return errors.Wrapf(
			err, "DBUpdateStakeEntryWithTxn: problem storing StakeEntry in index PrefixStakeByValidatorByStaker: ",
		)
	}

	// Set StakeEntry in PrefixStakeByStakeAmount but only if the amount has changed.
	if dbEntry == nil || dbEntry.StakeAmountNanos.Cmp(stakeEntry.StakeAmountNanos) != 0 {
		// Delete the existing entry in the db index if one exists
		if dbEntry != nil {
			dbStakeByStakeAmountKey := DBKeyForStakeByStakeAmount(dbEntry)
			// Note we set isDeleted=false as a hint to the state syncer that we're about to
			// update this value immediately after.
			if err := DBDeleteWithTxn(txn, snap, dbStakeByStakeAmountKey, eventManager, false); err != nil {
				return errors.Wrapf(
					err, "DBDeleteStakeEntryWithTxn: problem deleting StakeEntry from index PrefixStakeByStakeAmount: ",
				)
			}
		}

		stakeByStakeAmountKey := DBKeyForStakeByStakeAmount(stakeEntry)
		if err := DBSetWithTxn(txn, snap, stakeByStakeAmountKey, nil, eventManager); err != nil {
			return errors.Wrapf(
				err, "DBUpdateStakeEntryWithTxn: problem storing StakeEntry in index PrefixStakeByStakeAmount: ",
			)
		}
	}

	return nil
}

func DBPutLockedStakeEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	lockedStakeEntry *LockedStakeEntry,
	blockHeight uint64,
	eventManager *EventManager,
) error {
	if lockedStakeEntry == nil {
		return nil
	}

	// Set LockedStakeEntry in PrefixLockedStakeByValidatorByStakerByLockedAt.
	key := DBKeyForLockedStakeByValidatorAndStakerAndLockedAt(lockedStakeEntry)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, lockedStakeEntry), eventManager); err != nil {
		return errors.Wrapf(
			err, "DBPutLockedStakeEntryWithTxn: problem storing LockedStakeEntry in index PrefixLockedStakeByValidatorByStakerByLockedAt: ",
		)
	}

	return nil
}

func DBDeleteStakeEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorPKID *PKID,
	stakerPKID *PKID,
	blockHeight uint64,
	eventManager *EventManager,
	isDeleted bool,
) error {
	if validatorPKID == nil || stakerPKID == nil {
		return nil
	}

	// Look up the existing StakeEntry in the db using the validator and staker PKIDs.
	// We need to use the stakeEntry's current values from the DB to delete it from all
	// indexes that store it.
	stakeEntry, err := DBGetStakeEntryWithTxn(txn, snap, validatorPKID, stakerPKID)
	if err != nil {
		return errors.Wrapf(err, "DBDeleteStakeEntryWithTxn: problem retrieving "+
			"StakeEntry for ValidatorPKID %v and StakerPKID %v: ", validatorPKID, stakerPKID)
	}

	// If the StakeEntry doesn't exist in the DB, then there's nothing to delete. Exit early.
	if stakeEntry == nil {
		return nil
	}

	// Delete StakeEntry from PrefixStakeByValidatorByStaker.
	stakeByValidatorAndStakerKey := DBKeyForStakeByValidatorAndStaker(validatorPKID, stakerPKID)
	if err := DBDeleteWithTxn(txn, snap, stakeByValidatorAndStakerKey, eventManager, isDeleted); err != nil {
		return errors.Wrapf(
			err, "DBDeleteStakeEntryWithTxn: problem deleting StakeEntry from index PrefixStakeByValidatorByStaker: ",
		)
	}

	// Delete the StakeEntry from PrefixStakeByStakeAmount.
	stakeByStakeAmountKey := DBKeyForStakeByStakeAmount(stakeEntry)
	if err := DBDeleteWithTxn(txn, snap, stakeByStakeAmountKey, eventManager, isDeleted); err != nil {
		return errors.Wrapf(
			err, "DBDeleteStakeEntryWithTxn: problem deleting StakeEntry from index PrefixStakeByStakeAmount: ",
		)
	}

	return nil
}

func DBDeleteLockedStakeEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	lockedStakeEntry *LockedStakeEntry,
	blockHeight uint64,
	eventManager *EventManager,
	isDeleted bool,
) error {
	if lockedStakeEntry == nil {
		return nil
	}

	// Delete LockedStakeEntry from PrefixLockedStakeByValidatorByStakerByLockedAt.
	key := DBKeyForLockedStakeByValidatorAndStakerAndLockedAt(lockedStakeEntry)
	if err := DBDeleteWithTxn(txn, snap, key, eventManager, isDeleted); err != nil {
		return errors.Wrapf(
			err, "DBDeleteLockedStakeEntryWithTxn: problem deleting StakeEntry from index PrefixLockedStakeByValidatorByStakerByLockedAt: ",
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
	mempool Mempool,
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
	utxoView := NewUtxoView(bc.db, bc.params, bc.postgres, bc.snapshot, bc.eventManager)
	if !isInterfaceValueNil(mempool) {
		var err error
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(
				err, "Blockchain.CreateStakeTxn: problem getting augmented utxo view from mempool: ",
			)
		}
	}

	// Validate txn metadata.
	blockHeight := bc.blockTip().Height + 1
	if err := utxoView.IsValidStakeMetadata(transactorPublicKey, metadata, blockHeight); err != nil {
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
	mempool Mempool,
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
	utxoView := NewUtxoView(bc.db, bc.params, bc.postgres, bc.snapshot, bc.eventManager)
	if !isInterfaceValueNil(mempool) {
		var err error
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(
				err, "Blockchain.CreateUnstakeTxn: problem getting augmented utxo view from mempool: ",
			)
		}
	}

	// Validate txn metadata.
	if err := utxoView.IsValidUnstakeMetadata(transactorPublicKey, metadata); err != nil {
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
	mempool Mempool,
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
	utxoView := NewUtxoView(bc.db, bc.params, bc.postgres, bc.snapshot, bc.eventManager)
	if !isInterfaceValueNil(mempool) {
		var err error
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(
				err, "Blockchain.CreateUnlockStakeTxn: problem getting augmented utxo view from mempool: ",
			)
		}
	}

	// Validate txn metadata.
	if err := utxoView.IsValidUnlockStakeMetadata(transactorPublicKey, metadata); err != nil {
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
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return 0, 0, nil, errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_connectStake: ")
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
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidStakerPKID, "_connectStake: ")
	}

	// Retrieve the existing ValidatorEntry. It must exist. The PrevValidatorEntry
	// will be restored if we disconnect this transaction.
	prevValidatorEntry, err := bav.GetValidatorByPublicKey(txMeta.ValidatorPublicKey)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: ")
	}
	if prevValidatorEntry == nil || prevValidatorEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidValidatorPKID, "_connectStake: ")
	}

	// Convert StakeAmountNanos *uint256.Int to StakeAmountNanosUint64 uint64.
	if txMeta.StakeAmountNanos == nil || !txMeta.StakeAmountNanos.IsUint64() {
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidStakeAmountNanos, "_connectStake: ")
	}
	stakeAmountNanosUint64 := txMeta.StakeAmountNanos.Uint64()

	// Retrieve the transactor's current balance to validate later.
	prevBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(txn.PublicKey)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: error retrieving PrevBalanceNanos: ")
	}

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
	var prevStakeEntries []*StakeEntry
	prevStakeEntry, err := bav.GetStakeEntry(prevValidatorEntry.ValidatorPKID, transactorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: ")
	}
	// Delete the existing StakeEntry, if exists.
	//
	// Note that we don't really need to do this, as setting a new StakeEntry will naturally cause
	// the old entry to be deleted in the database. However, we do this here for clarity.
	if prevStakeEntry != nil {
		prevStakeEntries = append(prevStakeEntries, prevStakeEntry)
		bav._deleteStakeEntryMappings(prevStakeEntry)
	}

	// Calculate StakeAmountNanos.
	stakeAmountNanos := txMeta.StakeAmountNanos.Clone()
	if prevStakeEntry != nil {
		stakeAmountNanos, err = SafeUint256().Add(stakeAmountNanos, prevStakeEntry.StakeAmountNanos)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectStake: error adding StakeAmountNanos to existing StakeAmountNanos: ")
		}
	}

	// Retrieve existing ExtraData to merge with any new ExtraData.
	var prevExtraData map[string][]byte
	if prevStakeEntry != nil {
		prevExtraData = prevStakeEntry.ExtraData
	}

	// Construct new StakeEntry from metadata.
	currentStakeEntry := &StakeEntry{
		StakerPKID:       transactorPKIDEntry.PKID,
		ValidatorPKID:    prevValidatorEntry.ValidatorPKID,
		RewardMethod:     txMeta.RewardMethod,
		StakeAmountNanos: stakeAmountNanos,
		ExtraData:        mergeExtraData(prevExtraData, txn.ExtraData),
	}
	// Set the new StakeEntry.
	bav._setStakeEntryMappings(currentStakeEntry)

	// Update the ValidatorEntry.TotalStakeAmountNanos.
	// 1. Copy the existing ValidatorEntry.
	currentValidatorEntry := prevValidatorEntry.Copy()
	// 2. Delete the existing ValidatorEntry.
	//
	// Note that we don't really need to do this, as setting a new ValidatorEntry will naturally cause
	// the old entry to be deleted in the database. However, we do this here for clarity.
	bav._deleteValidatorEntryMappings(prevValidatorEntry)
	// 3. Update the new ValidatorEntry's TotalStakeAmountNanos.
	currentValidatorEntry.TotalStakeAmountNanos, err = SafeUint256().Add(
		currentValidatorEntry.TotalStakeAmountNanos, txMeta.StakeAmountNanos,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: error adding StakeAmountNanos to TotalStakeAmountNanos: ")
	}
	// 4. Set the new ValidatorEntry.
	bav._setValidatorEntryMappings(currentValidatorEntry)

	// Add the StakeAmountNanos to TotalOutput. The coins being staked are already
	// part of the TotalInput. But they are not burned, so they are an implicit
	// output even though they do not go to a specific public key's balance.
	totalOutput, err = SafeUint64().Add(totalOutput, stakeAmountNanosUint64)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: error adding StakeAmountNanos to TotalOutput: ")
	}

	// Create a UTXO operation
	utxoOpForTxn := &UtxoOperation{
		Type:               OperationTypeStake,
		PrevValidatorEntry: prevValidatorEntry,
		PrevStakeEntries:   prevStakeEntries,
	}
	if err = bav.SanityCheckStakeTxn(
		transactorPKIDEntry.PKID, utxoOpForTxn, txMeta.StakeAmountNanos, txn.TxnFeeNanos, prevBalanceNanos,
	); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectStake: ")
	}
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpForTxn)
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
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight ||
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
		return errors.Wrapf(RuleErrorInvalidStakerPKID, "_disconnectStake: ")
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
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return 0, 0, nil, errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_connectUnstake: ")
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
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidStakerPKID, "_connectUnstake: ")
	}

	// Retrieve PrevValidatorEntry. This will be restored if we disconnect the txn.
	prevValidatorEntry, err := bav.GetValidatorByPublicKey(txMeta.ValidatorPublicKey)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: ")
	}
	if prevValidatorEntry == nil || prevValidatorEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidValidatorPKID, "_connectUnstake: ")
	}

	// Retrieve prevStakeEntry. This will be restored if we disconnect the txn.
	prevStakeEntry, err := bav.GetStakeEntry(prevValidatorEntry.ValidatorPKID, transactorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: ")
	}
	if prevStakeEntry == nil || prevStakeEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidUnstakeNoStakeFound, "_connectUnstake: ")
	}
	if prevStakeEntry.StakeAmountNanos.Cmp(txMeta.UnstakeAmountNanos) < 0 {
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidUnstakeInsufficientStakeFound, "_connectUnstake: ")
	}
	prevStakeEntries := []*StakeEntry{prevStakeEntry}

	// Update the StakeEntry, decreasing the StakeAmountNanos.
	// 1. Calculate the updated StakeAmountNanos.
	stakeAmountNanos, err := SafeUint256().Sub(prevStakeEntry.StakeAmountNanos, txMeta.UnstakeAmountNanos)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: error subtracting UnstakeAmountNanos from StakeAmountNanos: ")
	}
	// 2. Create a currentStakeEntry, if updated StakeAmountNanos > 0.
	var currentStakeEntry *StakeEntry
	if stakeAmountNanos.Cmp(uint256.NewInt()) > 0 {
		currentStakeEntry = prevStakeEntry.Copy()
		currentStakeEntry.StakeAmountNanos = stakeAmountNanos.Clone()
	}
	// 3. Delete the prevStakeEntry.
	bav._deleteStakeEntryMappings(prevStakeEntry)
	// 4. Set the currentStakeEntry, if exists. The currentStakeEntry will not exist
	//    if the transactor has unstaked all stake assigned to this validator.
	if currentStakeEntry != nil {
		bav._setStakeEntryMappings(currentStakeEntry)
	}

	// Update the ValidatorEntry.TotalStakeAmountNanos.
	// 1. Copy the existing ValidatorEntry.
	currentValidatorEntry := prevValidatorEntry.Copy()
	// 2. Delete the existing ValidatorEntry.
	//
	// Note that we don't technically need to delete the ValidatorEntry here since
	// the old ValidatorEntry will automatically be deleted in favor of the new one,
	// but we do this here for clarity.
	bav._deleteValidatorEntryMappings(prevValidatorEntry)
	// 3. Update the new ValidatorEntry's TotalStakeAmountNanos.
	currentValidatorEntry.TotalStakeAmountNanos, err = SafeUint256().Sub(
		currentValidatorEntry.TotalStakeAmountNanos, txMeta.UnstakeAmountNanos,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: error subtracting UnstakeAmountNanos from TotalStakeAmountNanos: ")
	}
	// 4. Set the new ValidatorEntry.
	bav._setValidatorEntryMappings(currentValidatorEntry)

	// Retrieve the CurrentEpochNumber.
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: error retrieving CurrentEpochNumber: ")
	}

	// Update the LockedStakeEntry, if exists. Create if not.
	// 1. Retrieve the PrevLockedStakeEntry. This will be restored if we disconnect this txn.
	prevLockedStakeEntry, err := bav.GetLockedStakeEntry(
		prevValidatorEntry.ValidatorPKID, transactorPKIDEntry.PKID, currentEpochNumber,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: ")
	}
	// 2. Create a CurrrentLockedStakeEntry.
	var prevLockedStakeEntries []*LockedStakeEntry
	var currentLockedStakeEntry *LockedStakeEntry
	if prevLockedStakeEntry != nil {
		// Update the existing LockedStakeEntry.
		currentLockedStakeEntry = prevLockedStakeEntry.Copy()
		currentLockedStakeEntry.LockedAmountNanos, err = SafeUint256().Add(
			prevLockedStakeEntry.LockedAmountNanos, txMeta.UnstakeAmountNanos,
		)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: error adding UnstakeAmountNanos to LockedAmountNanos")
		}
		currentLockedStakeEntry.ExtraData = mergeExtraData(prevLockedStakeEntry.ExtraData, txn.ExtraData)
	} else {
		// Create a new LockedStakeEntry.
		currentLockedStakeEntry = &LockedStakeEntry{
			StakerPKID:          transactorPKIDEntry.PKID,
			ValidatorPKID:       prevValidatorEntry.ValidatorPKID,
			LockedAmountNanos:   txMeta.UnstakeAmountNanos,
			LockedAtEpochNumber: currentEpochNumber,
			ExtraData:           txn.ExtraData,
		}
	}
	// 3. Delete the PrevLockedStakeEntry, if exists.
	//
	// Note that we don't technically need to do this since the flush will naturally delete
	// the old value from the db before setting the new one, but we do it here for clarity.
	if prevLockedStakeEntry != nil {
		prevLockedStakeEntries = append(prevLockedStakeEntries, prevLockedStakeEntry)
		bav._deleteLockedStakeEntryMappings(prevLockedStakeEntry)
	}
	// 4. Set the CurrentLockedStakeEntry.
	bav._setLockedStakeEntryMappings(currentLockedStakeEntry)

	// Create a UTXO operation.
	utxoOpForTxn := &UtxoOperation{
		Type:                   OperationTypeUnstake,
		PrevValidatorEntry:     prevValidatorEntry,
		PrevStakeEntries:       prevStakeEntries,
		PrevLockedStakeEntries: prevLockedStakeEntries,
		LockedAtEpochNumber:    currentEpochNumber,
	}
	if err = bav.SanityCheckUnstakeTxn(transactorPKIDEntry.PKID, utxoOpForTxn, txMeta.UnstakeAmountNanos); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnstake: ")
	}
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpForTxn)
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
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight ||
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
		return errors.Wrapf(RuleErrorInvalidStakerPKID, "_disconnectUnstake: ")
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

	// Retrieve the CurrentEpochNumber.
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return errors.Wrapf(err, "_disconnectUnstake: error retrieving CurrentEpochNumber: ")
	}

	// Restore the PrevLockedStakeEntry, if exists. The PrevLockedStakeEntry will exist if the
	// transactor has previously unstaked stake assigned to this validator within the same epoch.
	// The PrevLockedStakeEntry will not exist otherwise.
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
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return 0, 0, nil, errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_connectUnlockStake: ")
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
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidStakerPKID, "_connectUnlockStake: ")
	}

	// Convert ValidatorPublicKey to ValidatorPKID.
	validatorPKIDEntry := bav.GetPKIDForPublicKey(txMeta.ValidatorPublicKey.ToBytes())
	if validatorPKIDEntry == nil || validatorPKIDEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidValidatorPKID, "_connectUnlockStake: ")
	}

	// Retrieve the PrevLockedStakeEntries. These will be restored if we disconnect this txn.
	prevLockedStakeEntries, err := bav.GetLockedStakeEntriesInRange(
		validatorPKIDEntry.PKID, transactorPKIDEntry.PKID, txMeta.StartEpochNumber, txMeta.EndEpochNumber,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnlockStake: ")
	}
	if len(prevLockedStakeEntries) == 0 {
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidUnlockStakeNoUnlockableStakeFound, "_connectUnlockStake: ")
	}

	// Retrieve the transactor's current balance to validate later.
	prevBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(txn.PublicKey)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnlockStake: error retrieving PrevBalanceNanos: ")
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
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidUnlockStakeUnlockableStakeOverflowsUint64, "_connectUnlockStake: ")
	}
	totalUnlockedAmountNanosUint64 := totalUnlockedAmountNanos.Uint64()

	// Add TotalUnlockedAmountNanos to TotalInput. The unlocked coins are an
	// implicit input even though they do not come from a specific public key.
	totalInput, err = SafeUint64().Add(totalInput, totalUnlockedAmountNanosUint64)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnlockStake: error adding TotalUnlockedAmountNanos to TotalInput: ")
	}

	// Add TotalUnlockedAmountNanos to TotalOutput. The unlocked
	// coins being sent to the transactor are an implicit output.
	totalOutput, err = SafeUint64().Add(totalOutput, totalUnlockedAmountNanosUint64)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnlockStake: error adding TotalUnlockedAmountNanos to TotalOutput: ")
	}

	// Return TotalUnlockedAmountNanos back to the transactor. We can use
	// _addBalance here since we validate that connectUnlockStake can only
	// occur after the BalanceModelBlockHeight.
	utxoOp, err := bav._addBalance(totalUnlockedAmountNanosUint64, txn.PublicKey)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(
			err, "_connectUnlockStake: error adding TotalUnlockedAmountNanos to the transactor balance: ",
		)
	}
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)

	// Create a UTXO operation.
	utxoOpForTxn := &UtxoOperation{
		Type:                   OperationTypeUnlockStake,
		PrevLockedStakeEntries: prevLockedStakeEntries,
	}
	if err = bav.SanityCheckUnlockStakeTxn(
		transactorPKIDEntry.PKID, utxoOpForTxn, totalUnlockedAmountNanos, txn.TxnFeeNanos, prevBalanceNanos,
	); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnlockStake: ")
	}
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpForTxn)
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
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight ||
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
		return errors.Wrapf(RuleErrorInvalidStakerPKID, "_disconnectUnlockStake: ")
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
		return errors.Wrapf(RuleErrorInvalidUnlockStakeUnlockableStakeOverflowsUint64, "_disconnectUnlockStake: ")
	}

	// Unadd TotalUnlockedAmountNanos from the transactor.
	err = bav._unAddBalance(totalUnlockedAmountNanos.Uint64(), currentTxn.PublicKey)
	if err != nil {
		return errors.Wrapf(err, "_disconnectUnlockStake: error unadding TotalUnlockedAmountNanos from the transactor balance: ")
	}

	// Restore the PrevLockedStakeEntries.
	for _, prevLockedStakeEntry := range operationData.PrevLockedStakeEntries {
		bav._setLockedStakeEntryMappings(prevLockedStakeEntry)
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
		return errors.Wrapf(RuleErrorInvalidStakerPKID, "UtxoView.IsValidStakeMetadata: ")
	}

	// Validate ValidatorPublicKey.
	validatorEntry, err := bav.GetValidatorByPublicKey(metadata.ValidatorPublicKey)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidStakeMetadata: ")
	}
	if validatorEntry == nil || validatorEntry.isDeleted {
		return errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView.IsValidStakeMetadata: ")
	}
	if !transactorPKIDEntry.PKID.Eq(validatorEntry.ValidatorPKID) && validatorEntry.DisableDelegatedStake {
		return errors.Wrapf(RuleErrorInvalidStakeValidatorDisabledDelegatedStake, "UtxoView.IsValidStakeMetadata: ")
	}

	// Validate RewardMethod.
	if metadata.RewardMethod != StakingRewardMethodPayToBalance && metadata.RewardMethod != StakingRewardMethodRestake {
		return errors.Wrapf(RuleErrorInvalidStakingRewardMethod, "UtxoView.IsValidStakeMetadata: ")
	}

	// Validate 0 <= StakeAmountNanos <= transactor's DESO Balance. We ignore
	// the txn fees in this check. The StakeAmountNanos will be validated to
	// be less than the transactor's DESO balance net of txn fees in the call
	// to connectBasicTransferWithExtraSpend.
	if metadata.StakeAmountNanos == nil || !metadata.StakeAmountNanos.IsUint64() {
		return errors.Wrapf(RuleErrorInvalidStakeAmountNanos, "UtxoView.IsValidStakeMetadata: ")
	}
	transactorDeSoBalanceNanos, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(transactorPkBytes, blockHeight-1)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidStakeMetadata: ")
	}
	if uint256.NewInt().SetUint64(transactorDeSoBalanceNanos).Cmp(metadata.StakeAmountNanos) < 0 {
		return errors.Wrapf(RuleErrorInvalidStakeInsufficientBalance, "UtxoView.IsValidStakeMetadata: ")
	}

	// Validate StakeAmountNanos > 0 when this is the first stake operation where the transactor is staking
	// to the validator. It should not be possible for a validator to stake 0 DESO to a validator.
	stakeEntry, err := bav.GetStakeEntry(validatorEntry.ValidatorPKID, transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidStakeMetadata: ")
	}
	if stakeEntry == nil && metadata.StakeAmountNanos.IsZero() {
		return errors.Wrapf(RuleErrorInvalidStakeAmountNanos, "UtxoView.IsValidStakeMetadata: ")
	}

	return nil
}

func (bav *UtxoView) IsValidUnstakeMetadata(transactorPkBytes []byte, metadata *UnstakeMetadata) error {
	// Validate TransactorPublicKey.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPkBytes)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return errors.Wrapf(RuleErrorInvalidStakerPKID, "UtxoView.IsValidUnstakeMetadata: ")
	}

	// Validate ValidatorPublicKey.
	validatorEntry, err := bav.GetValidatorByPublicKey(metadata.ValidatorPublicKey)
	if err != nil {
		return errors.Wrapf(err, "IsValidUnstakeMetadata: ")
	}
	if validatorEntry == nil || validatorEntry.isDeleted {
		return errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView.IsValidUnstakeMetadata: ")
	}

	// Validate StakeEntry exists.
	stakeEntry, err := bav.GetStakeEntry(validatorEntry.ValidatorPKID, transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidUnstakeMetadata: ")
	}
	if stakeEntry == nil || stakeEntry.isDeleted {
		return errors.Wrapf(RuleErrorInvalidUnstakeNoStakeFound, "UtxoView.IsValidUnstakeMetadata: ")
	}

	// Validate 0 < UnstakeAmountNanos <= StakeEntry.StakeAmountNanos.
	if metadata.UnstakeAmountNanos == nil || metadata.UnstakeAmountNanos.IsZero() {
		return errors.Wrapf(RuleErrorInvalidUnstakeAmountNanos, "UtxoView.IsValidUnstakeMetadata: ")
	}
	if stakeEntry.StakeAmountNanos.Cmp(metadata.UnstakeAmountNanos) < 0 {
		return errors.Wrapf(RuleErrorInvalidUnstakeInsufficientStakeFound, "UtxoView.IsValidUnstakeMetadata: ")
	}

	return nil
}

func (bav *UtxoView) IsValidUnlockStakeMetadata(transactorPkBytes []byte, metadata *UnlockStakeMetadata) error {
	// Validate TransactorPublicKey.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPkBytes)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return errors.Wrapf(RuleErrorInvalidStakerPKID, "UtxoView.IsValidUnlockStakeMetadata: ")
	}

	// Validate ValidatorPublicKey.
	validatorPKIDEntry := bav.GetPKIDForPublicKey(metadata.ValidatorPublicKey.ToBytes())
	if validatorPKIDEntry == nil || validatorPKIDEntry.isDeleted {
		return errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView.IsValidUnlockStakeMetadata: ")
	}

	// Validate StartEpochNumber and EndEpochNumber.
	if metadata.StartEpochNumber > metadata.EndEpochNumber {
		return errors.Wrapf(RuleErrorInvalidUnlockStakeEpochRange, "UtxoView.IsValidUnlockStakeMetadata: ")
	}

	// Retrieve CurrentEpochNumber.
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidUnlockStakeMetadata: error retrieving CurrentEpochNumber: ")
	}

	// Retrieve the StakeLockupEpochDuration from the current global params. It's safe to use the current global
	// params here because the changes made to locked stake do not affect the PoS consensus until they are
	// snapshotted.
	currentGlobalParamsEntry := bav.GetCurrentGlobalParamsEntry()

	// Calculate UnlockableAtEpochNumber.
	unlockableAtEpochNumber, err := SafeUint64().Add(
		metadata.EndEpochNumber, currentGlobalParamsEntry.StakeLockupEpochDuration,
	)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidUnlockStakeMetadata: error calculating UnlockableAtEpochNumber: ")
	}

	// Validate EndEpochNumber + StakeLockupEpochDuration <= CurrentEpochNumber.
	if unlockableAtEpochNumber > currentEpochNumber {
		return errors.Wrapf(RuleErrorInvalidUnlockStakeMustWaitLockupDuration, "UtxoView.IsValidUnlockStakeMetadata: ")
	}

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
		return errors.Wrapf(RuleErrorInvalidUnlockStakeNoUnlockableStakeFound, "UtxoView.IsValidUnlockStakeMetadata: ")
	}

	return nil
}

// IsCorrectValidatorTotalStakeAmountNanos returns true if the total stake amount for the validator
// matches the total stake amount calculated from the StakeEntries in the UtxoView + DB and false otherwise.
func (bav *UtxoView) IsCorrectValidatorTotalStakeAmountNanos(validatorEntry *ValidatorEntry) (bool, error) {
	// Map of all the stake entries for this validator.
	stakeEntryMap := make(map[StakeMapKey]*StakeEntry)

	dbStakeEntries, err := DBGetStakeEntriesForValidatorPKID(bav.Handle, bav.Snapshot, validatorEntry.ValidatorPKID)
	if err != nil {
		return false, errors.Wrapf(err, "IsCorrectValidatorTotalStakeAmountNanos: error retrieving StakeEntries: ")
	}
	// Fill the DB entries into the map first.
	for _, dbStakeEntry := range dbStakeEntries {
		stakeEntryMap[dbStakeEntry.ToMapKey()] = dbStakeEntry
	}

	// Merge in results from the view, overwriting results from the DB.
	for stakeMapKey, stakeEntry := range bav.StakeMapKeyToStakeEntry {
		// Only add entries for this validator.
		if stakeEntry.ValidatorPKID.Eq(validatorEntry.ValidatorPKID) {
			stakeEntryMap[stakeMapKey] = stakeEntry.Copy()
		}
	}
	// Calculate the total stake amount for the validator.
	totalStakeAmountNanos := uint256.NewInt()
	for _, stakeEntry := range stakeEntryMap {
		// If an entry is deleted, we don't count it towards the total.
		if stakeEntry.isDeleted {
			continue
		}
		totalStakeAmountNanos.Add(totalStakeAmountNanos, stakeEntry.StakeAmountNanos)
	}
	return totalStakeAmountNanos.Eq(validatorEntry.TotalStakeAmountNanos), nil
}

func (bav *UtxoView) SanityCheckStakeTxn(
	transactorPKID *PKID,
	utxoOp *UtxoOperation,
	amountNanos *uint256.Int,
	feeNanos uint64,
	prevBalanceNanos uint64,
) error {
	if utxoOp.Type != OperationTypeStake {
		return fmt.Errorf("SanityCheckStakeTxn: called with %v", utxoOp.Type)
	}

	// Sanity check ValidatorEntry.TotalStakeAmountNanos increase.
	if utxoOp.PrevValidatorEntry == nil {
		return errors.New("SanityCheckStakeTxn: nil PrevValidatorEntry provided")
	}
	currentValidatorEntry, err := bav.GetValidatorByPKID(utxoOp.PrevValidatorEntry.ValidatorPKID)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckStakeTxn: error retrieving ValidatorEntry: ")
	}
	if currentValidatorEntry == nil {
		return errors.New("SanityCheckStakeTxn: no CurrentValidatorEntry found")
	}
	validatorEntryTotalStakeAmountNanosIncrease, err := SafeUint256().Sub(
		currentValidatorEntry.TotalStakeAmountNanos, utxoOp.PrevValidatorEntry.TotalStakeAmountNanos,
	)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckStakeTxn: error calculating TotalStakeAmountNanos increase: ")
	}
	if !validatorEntryTotalStakeAmountNanosIncrease.Eq(amountNanos) {
		return errors.New("SanityCheckStakeTxn: TotalStakeAmountNanos increase does not match")
	}

	// Validate StakeEntry.StakeAmountNanos increase.
	prevStakeEntry := &StakeEntry{StakeAmountNanos: uint256.NewInt()}
	if len(utxoOp.PrevStakeEntries) == 1 {
		prevStakeEntry = utxoOp.PrevStakeEntries[0]
	}
	currentStakeEntry, err := bav.GetStakeEntry(currentValidatorEntry.ValidatorPKID, transactorPKID)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckStakeTxn: error retrieving StakeEntry: ")
	}
	if currentStakeEntry == nil {
		return errors.New("SanityCheckStakeTxn: no CurrentStakeEntry found")
	}
	stakeEntryStakeAmountNanosIncrease, err := SafeUint256().Sub(
		currentStakeEntry.StakeAmountNanos, prevStakeEntry.StakeAmountNanos,
	)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckStakeTxn: error calculating StakeAmountNanos increase: ")
	}
	if !stakeEntryStakeAmountNanosIncrease.Eq(amountNanos) {
		return errors.New("SanityCheckStakeTxn: StakeAmountNanos increase does not match")
	}

	// Validate TransactorBalance decrease.
	// PrevTransactorBalanceNanos = CurrentTransactorBalanceNanos + AmountNanos + FeeNanos
	// PrevTransactorBalanceNanos - CurrentTransactorBalanceNanos - FeeNanos = AmountNanos
	currentBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(bav.GetPublicKeyForPKID(transactorPKID))
	if err != nil {
		return errors.Wrapf(err, "SanityCheckStakeTxn: error retrieving TransactorBalance: ")
	}
	transactorBalanceNanosDecrease, err := SafeUint64().Sub(prevBalanceNanos, currentBalanceNanos)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckStakeTxn: error calculating TransactorBalance decrease: ")
	}
	transactorBalanceNanosDecrease, err = SafeUint64().Sub(transactorBalanceNanosDecrease, feeNanos)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckStakeTxn: error including fees in TransactorBalance decrease: ")
	}
	if !uint256.NewInt().SetUint64(transactorBalanceNanosDecrease).Eq(amountNanos) {
		return errors.New("SanityCheckStakeTxn: TransactorBalance decrease does not match")
	}

	isCorrectTotalStakeAmountNanos, err := bav.IsCorrectValidatorTotalStakeAmountNanos(currentValidatorEntry)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckStakeTxn: error validating ValidatorEntry.TotalStakeAmountNanos: ")
	}
	if !isCorrectTotalStakeAmountNanos {
		return errors.New("SanityCheckStakeTxn: incorrect TotalStakeAmountNanos for validator after " +
			"connecting transaction")
	}

	return nil
}

func (bav *UtxoView) SanityCheckUnstakeTxn(transactorPKID *PKID, utxoOp *UtxoOperation, amountNanos *uint256.Int) error {
	if utxoOp.Type != OperationTypeUnstake {
		return fmt.Errorf("SanityCheckUnstakeTxn: called with %v", utxoOp.Type)
	}

	// Validate ValidatorEntry.TotalStakeAmountNanos decrease.
	if utxoOp.PrevValidatorEntry == nil {
		return errors.New("SanityCheckUnstakeTxn: nil PrevValidatorEntry provided")
	}
	currentValidatorEntry, err := bav.GetValidatorByPKID(utxoOp.PrevValidatorEntry.ValidatorPKID)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnstakeTxn: error retrieving ValidatorEntry: ")
	}
	if currentValidatorEntry == nil {
		return errors.New("SanityCheckUnstakeTxn: no CurrentValidatorEntry found")
	}
	validatorEntryTotalStakeAmountNanosDecrease, err := SafeUint256().Sub(
		utxoOp.PrevValidatorEntry.TotalStakeAmountNanos, currentValidatorEntry.TotalStakeAmountNanos,
	)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnstakeTxn: error calculating TotalStakeAmountNanos decrease: ")
	}
	if !validatorEntryTotalStakeAmountNanosDecrease.Eq(amountNanos) {
		return errors.New("SanityCheckUnstakeTxn: TotalStakeAmountNanos decrease does not match")
	}

	// Validate PrevStakeEntry.StakeAmountNanos decrease.
	if len(utxoOp.PrevStakeEntries) != 1 {
		return errors.New("SanityCheckUnstakeTxn: PrevStakeEntries should have exactly one entry")
	}
	prevStakeEntry := utxoOp.PrevStakeEntries[0]
	currentStakeEntry, err := bav.GetStakeEntry(prevStakeEntry.ValidatorPKID, transactorPKID)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnstakeTxn: error retrieving StakeEntry: ")
	}
	if currentStakeEntry == nil {
		currentStakeEntry = &StakeEntry{StakeAmountNanos: uint256.NewInt()}
	}
	stakeEntryStakeAmountNanosDecrease, err := SafeUint256().Sub(
		prevStakeEntry.StakeAmountNanos, currentStakeEntry.StakeAmountNanos,
	)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnstakeTxn: error calculating StakeAmountNanos decrease: ")
	}
	if !stakeEntryStakeAmountNanosDecrease.Eq(amountNanos) {
		return errors.New("SanityCheckUnstakeTxn: StakeAmountNanos decrease does not match")
	}

	// Validate LockedStakeEntry.LockedAmountNanos increase.
	prevLockedStakeEntry := &LockedStakeEntry{LockedAmountNanos: uint256.NewInt()}
	if len(utxoOp.PrevLockedStakeEntries) == 1 {
		prevLockedStakeEntry = utxoOp.PrevLockedStakeEntries[0]
	}
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnstakeTxn: error retrieving CurrentEpochNumber: ")
	}
	currentLockedStakeEntry, err := bav.GetLockedStakeEntry(
		currentValidatorEntry.ValidatorPKID, transactorPKID, currentEpochNumber,
	)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnstakeTxn: error retrieving LockedStakeEntry: ")
	}
	lockedStakeEntryLockedAmountNanosIncrease, err := SafeUint256().Sub(
		currentLockedStakeEntry.LockedAmountNanos, prevLockedStakeEntry.LockedAmountNanos,
	)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnstakeTxn: error calculating LockedAmountNanos increase: ")
	}
	if !lockedStakeEntryLockedAmountNanosIncrease.Eq(amountNanos) {
		return errors.New("SanityCheckUnstakeTxn: LockedAmountNanos increase does not match")
	}

	isCorrectTotalStakeAmountNanos, err := bav.IsCorrectValidatorTotalStakeAmountNanos(currentValidatorEntry)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnstakeTxn: error validating ValidatorEntry.TotalStakeAmountNanos: ")
	}
	if !isCorrectTotalStakeAmountNanos {
		return errors.New("SanityCheckUnstakeTxn: incorrect TotalStakeAmountNanos for validator after " +
			"connecting transaction")
	}

	return nil
}

func (bav *UtxoView) SanityCheckUnlockStakeTxn(
	transactorPKID *PKID,
	utxoOp *UtxoOperation,
	amountNanos *uint256.Int,
	feeNanos uint64,
	prevBalanceNanos uint64,
) error {
	if utxoOp.Type != OperationTypeUnlockStake {
		return fmt.Errorf("SanityCheckUnlockStakeTxn: called with %v", utxoOp.Type)
	}

	// Validate PrevLockedStakeEntry.LockedAmountNanos.
	if utxoOp.PrevLockedStakeEntries == nil || len(utxoOp.PrevLockedStakeEntries) == 0 {
		return errors.New("SanityCheckUnlockStakeTxn: PrevLockedStakeEntries is empty")
	}
	totalUnlockedAmountNanos := uint256.NewInt()
	var err error
	for _, prevLockedStakeEntry := range utxoOp.PrevLockedStakeEntries {
		totalUnlockedAmountNanos, err = SafeUint256().Add(totalUnlockedAmountNanos, prevLockedStakeEntry.LockedAmountNanos)
		if err != nil {
			return errors.Wrapf(err, "SanityCheckUnlockStakeTxn: error calculating TotalUnlockedAmountNanos: ")
		}
	}
	if !totalUnlockedAmountNanos.Eq(amountNanos) {
		return errors.New("SanityCheckUnlockStakeTxn: TotalUnlockedAmountNanos does not match")
	}

	// Validate TransactorBalanceNanos increase.
	// CurrentTransactorBalanceNanos = PrevTransactorBalanceNanos + AmountNanos - FeeNanos
	// CurrentTransactorBalanceNanos - PrevTransactorBalanceNanos + FeeNanos = AmountNanos
	currentBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(bav.GetPublicKeyForPKID(transactorPKID))
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnlockStakeTxn: error retrieving TransactorBalance: ")
	}
	transactorBalanceNanosIncrease, err := SafeUint64().Sub(currentBalanceNanos, prevBalanceNanos)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnlockStakeTxn: error calculating TransactorBalance increase: ")
	}
	transactorBalanceNanosIncrease, err = SafeUint64().Add(transactorBalanceNanosIncrease, feeNanos)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckStakeTxn: error including fees in TransactorBalance decrease: ")
	}
	if !uint256.NewInt().SetUint64(transactorBalanceNanosIncrease).Eq(amountNanos) {
		return errors.New("SanityCheckUnlockStakeTxn: TransactorBalance increase does not match")
	}

	return nil
}

func (bav *UtxoView) GetStakeEntry(validatorPKID *PKID, stakerPKID *PKID) (*StakeEntry, error) {
	// Error if either input is nil.
	if validatorPKID == nil {
		return nil, errors.New("UtxoView.GetStakeEntry: nil ValidatorPKID provided as input")
	}
	if stakerPKID == nil {
		return nil, errors.New("UtxoView.GetStakeEntry: nil StakerPKID provided as input")
	}
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
	stakeEntry, err := DBGetStakeEntry(bav.Handle, bav.Snapshot, validatorPKID, stakerPKID)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetStakeEntry: ")
	}
	if stakeEntry != nil {
		// Cache the StakeEntry in the UtxoView if exists.
		bav._setStakeEntryMappings(stakeEntry)
	}
	return stakeEntry, nil
}

func (bav *UtxoView) GetStakeEntriesForValidatorPKID(validatorPKID *PKID) ([]*StakeEntry, error) {
	// Validate inputs.
	if validatorPKID == nil {
		return nil, errors.New("UtxoView.GetStakeEntriesForValidatorPKID: nil ValidatorPKID provided as input")
	}

	// First, pull matching StakeEntries from the database and cache them in the UtxoView.
	dbStakeEntries, err := DBGetStakeEntriesForValidatorPKID(bav.Handle, bav.Snapshot, validatorPKID)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetStakeEntriesForValidatorPKID: error retrieving StakeEntries from the db: ")
	}
	for _, stakeEntry := range dbStakeEntries {
		// Cache results in the UtxoView.
		if _, exists := bav.StakeMapKeyToStakeEntry[stakeEntry.ToMapKey()]; !exists {
			bav._setStakeEntryMappings(stakeEntry)
		}
	}

	// Then, pull matching StakeEntries from the UtxoView.
	var stakeEntries []*StakeEntry
	for _, stakeEntry := range bav.StakeMapKeyToStakeEntry {
		if !stakeEntry.ValidatorPKID.Eq(validatorPKID) || stakeEntry.isDeleted {
			continue
		}
		stakeEntries = append(stakeEntries, stakeEntry)
	}

	// Sort by StakerPKID so that the ordering is deterministic.
	sort.Slice(stakeEntries, func(ii, jj int) bool {
		return bytes.Compare(
			stakeEntries[ii].StakerPKID.ToBytes(),
			stakeEntries[jj].StakerPKID.ToBytes(),
		) < 0
	})
	return stakeEntries, nil
}

// GetTopStakesForValidatorsByStakeAmount fetches the top n StakeEntries sorted by stake amount for
// the given validators. The validatorPKIDs and limit parameters are strictly respected. If either has
// 0 size, then no StakeEntries are returned.
func (bav *UtxoView) GetTopStakesForValidatorsByStakeAmount(
	validatorPKIDs []*PKID,
	limit uint64,
) ([]*StakeEntry, error) {
	// Validate validator PKIDs and limit params.
	if len(validatorPKIDs) == 0 || limit == uint64(0) {
		return []*StakeEntry{}, nil
	}

	// Create a slice of UtxoViewStakeEntries. We want to skip pulling these from the database for two
	// reasons:
	// 1. It's possible that they have been updated in the UtxoView and the changes have not yet flushed
	// to the database.
	// 2. By skipping these entries from the DB seek, we ensure that the DB seek always returns the top n
	// entries not found in the UtxoView. When we merge the entries from the UtxoView and the DB, this
	// guarantee that the top n entries will exist in the merged set of entries.
	var utxoViewStakeEntries []*StakeEntry
	for _, stakeEntry := range bav.StakeMapKeyToStakeEntry {
		utxoViewStakeEntries = append(utxoViewStakeEntries, stakeEntry)
	}

	// Convert the validatorPKIDs to a set for easy lookup.
	validatorPKIDsToInclude := NewSet([]PKID{})
	for _, validatorPKID := range validatorPKIDs {
		validatorPKIDsToInclude.Add(*validatorPKID)
	}

	// Pull top N StakeEntries from the database (not present in the UtxoView).
	// Note that we will skip stakers that are present in the view because we pass
	// utxoViewStakeEntries to the function.
	dbStakeEntries, err := DBGetTopStakesForValidatorsByStakeAmount(
		bav.Handle,
		bav.Snapshot,
		limit,
		validatorPKIDsToInclude,
		utxoViewStakeEntries,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetTopStakesForValidatorsByStakeAmount: error retrieving stake entries from db: ")
	}

	// Cache StakeEntries from the db in the UtxoView.
	for _, stakeEntry := range dbStakeEntries {
		stakeMapKey := stakeEntry.ToMapKey()
		// If the utxoViewStakeEntries have been properly skipped when doing the DB seek, then there
		// should be no duplicates here. We perform a sanity check to ensure that is the case. If we
		// find duplicates here, then something is wrong. It would unsafe to continue as it may result
		// in an invalid ordering of stakes.
		if _, exists := bav.StakeMapKeyToStakeEntry[stakeMapKey]; exists {
			return nil, fmt.Errorf("UtxoView.GetTopStakesForValidatorsByStakeAmount: duplicate StakeEntry returned from the DB: %v", stakeEntry)
		}

		bav._setStakeEntryMappings(stakeEntry)
	}

	// Pull !isDeleted StakeEntries that have staked to the desired validators and have non-zero stake.
	var stakeEntries []*StakeEntry
	for _, stakeEntry := range bav.StakeMapKeyToStakeEntry {
		if stakeEntry.isDeleted || stakeEntry.StakeAmountNanos.IsZero() {
			continue
		}
		if !validatorPKIDsToInclude.Includes(*stakeEntry.ValidatorPKID) {
			continue
		}
		stakeEntries = append(stakeEntries, stakeEntry)
	}

	// Sort the StakeEntries by StakeAmountNanos DESC.
	sort.Slice(stakeEntries, func(ii, jj int) bool {
		stakeCmp := stakeEntries[ii].StakeAmountNanos.Cmp(stakeEntries[jj].StakeAmountNanos)
		if stakeCmp != 0 {
			return stakeCmp > 0
		}

		// Use ValidatorPKID as a tie-breaker if equal StakeAmountNanos.
		validatorPKIDCmp := bytes.Compare(
			stakeEntries[ii].ValidatorPKID.ToBytes(),
			stakeEntries[jj].ValidatorPKID.ToBytes(),
		)
		if validatorPKIDCmp != 0 {
			return validatorPKIDCmp > 0
		}

		// Use StakerPKID as a tie-breaker if equal ValidatorPKID.
		return bytes.Compare(
			stakeEntries[ii].StakerPKID.ToBytes(),
			stakeEntries[jj].StakerPKID.ToBytes(),
		) > 0
	})

	// Return top N.
	upperBound := limit
	if uint64(len(stakeEntries)) < upperBound {
		upperBound = uint64(len(stakeEntries))
	}
	return stakeEntries[0:upperBound], nil
}

func (bav *UtxoView) ValidatorHasDelegatedStake(validatorPKID *PKID) (bool, error) {
	// True if the validator has any delegated stake assigned to them.

	// First check the UtxoView.
	var utxoDeletedStakeEntries []*StakeEntry
	for _, stakeEntry := range bav.StakeMapKeyToStakeEntry {
		if !stakeEntry.ValidatorPKID.Eq(validatorPKID) {
			// Skip any stake assigned to other validators.
			continue
		}
		if stakeEntry.StakerPKID.Eq(validatorPKID) {
			// Skip any stake the validator assigned to themselves.
			continue
		}
		if !stakeEntry.isDeleted {
			// A non-deleted delegated StakeEntry for this validator was found in the UtxoView.
			return true, nil
		}
		// A deleted delegated StakeEntry for this validator was found in the UtxoView.
		utxoDeletedStakeEntries = append(utxoDeletedStakeEntries, stakeEntry)
	}

	// Next, check the database skipping any deleted StakeEntries for this validator.
	return DBValidatorHasDelegatedStake(bav.Handle, bav.Snapshot, validatorPKID, utxoDeletedStakeEntries)
}

func (bav *UtxoView) GetLockedStakeEntry(
	validatorPKID *PKID,
	stakerPKID *PKID,
	lockedAtEpochNumber uint64,
) (*LockedStakeEntry, error) {
	// Error if either input is nil.
	if validatorPKID == nil {
		return nil, errors.New("UtxoView.GetLockedStakeEntry: nil ValidatorPKID provided as input")
	}
	if stakerPKID == nil {
		return nil, errors.New("UtxoView.GetLockedStakeEntry: nil StakerPKID provided as input")
	}
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
	lockedStakeEntry, err := DBGetLockedStakeEntry(bav.Handle, bav.Snapshot, validatorPKID, stakerPKID, lockedAtEpochNumber)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetLockedStakeEntry: ")
	}
	if lockedStakeEntry != nil {
		// Cache the LockedStakeEntry in the UtxoView if exists.
		bav._setLockedStakeEntryMappings(lockedStakeEntry)
	}
	return lockedStakeEntry, nil
}

func (bav *UtxoView) GetLockedStakeEntriesInRange(
	validatorPKID *PKID,
	stakerPKID *PKID,
	startEpochNumber uint64,
	endEpochNumber uint64,
) ([]*LockedStakeEntry, error) {
	// Validate inputs.
	if validatorPKID == nil {
		return nil, errors.New("UtxoView.GetLockedStakeEntriesInRange: nil ValidatorPKID provided as input")
	}
	if stakerPKID == nil {
		return nil, errors.New("UtxoView.GetLockedStakeEntriesInRange: nil StakerPKID provided as input")
	}
	if startEpochNumber > endEpochNumber {
		return nil, errors.New("UtxoView.GetLockedStakeEntriesInRange: invalid LockedAtEpochNumber range provided as input")
	}

	// First, pull matching LockedStakeEntries from the db and cache them in the UtxoView.
	dbLockedStakeEntries, err := DBGetLockedStakeEntriesInRange(
		bav.Handle, bav.Snapshot, validatorPKID, stakerPKID, startEpochNumber, endEpochNumber,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetLockedStakeEntriesInRange: ")
	}
	for _, lockedStakeEntry := range dbLockedStakeEntries {
		// Cache results in the UtxoView.
		if _, exists := bav.LockedStakeMapKeyToLockedStakeEntry[lockedStakeEntry.ToMapKey()]; !exists {
			bav._setLockedStakeEntryMappings(lockedStakeEntry)
		}
	}

	// Then, pull matching LockedStakeEntries from the UtxoView.
	var lockedStakeEntries []*LockedStakeEntry
	for _, lockedStakeEntry := range bav.LockedStakeMapKeyToLockedStakeEntry {
		// Filter to matching LockedStakeEntries.
		if !lockedStakeEntry.ValidatorPKID.Eq(validatorPKID) ||
			!lockedStakeEntry.StakerPKID.Eq(stakerPKID) ||
			lockedStakeEntry.LockedAtEpochNumber < startEpochNumber ||
			lockedStakeEntry.LockedAtEpochNumber > endEpochNumber ||
			lockedStakeEntry.isDeleted {
			continue
		}
		lockedStakeEntries = append(lockedStakeEntries, lockedStakeEntry)
	}

	// Sort LockedStakeEntries by LockedAtEpochNumber ASC.
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
	// Iterate through all the entries in the view. Delete the entries that have isDeleted=true
	// and update the entries that don't.
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
		if entry.isDeleted {
			if err := DBDeleteStakeEntryWithTxn(txn, bav.Snapshot, entry.ValidatorPKID, entry.StakerPKID, blockHeight, bav.EventManager, entry.isDeleted); err != nil {
				return errors.Wrapf(err, "_flushStakeEntriesToDbWithTxn: ")
			}
		} else {
			if err := DBUpdateStakeEntryWithTxn(txn, bav.Snapshot, &entry, blockHeight, bav.EventManager); err != nil {
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
		if err := DBDeleteLockedStakeEntryWithTxn(txn, bav.Snapshot, &entry, blockHeight, bav.EventManager, entry.isDeleted); err != nil {
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
			if err := DBPutLockedStakeEntryWithTxn(txn, bav.Snapshot, &entry, blockHeight, bav.EventManager); err != nil {
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
}

func MakeStakeLimitKey(validatorPKID *PKID) StakeLimitKey {
	return StakeLimitKey{
		ValidatorPKID: *validatorPKID,
	}
}

func (stakeLimitKey *StakeLimitKey) Encode() []byte {
	var data []byte
	data = append(data, stakeLimitKey.ValidatorPKID.ToBytes()...)
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

	return nil
}

func (bav *UtxoView) _checkStakeTxnSpendingLimitAndUpdateDerivedKey(
	derivedKeyEntry DerivedKeyEntry,
	transactorPublicKeyBytes []byte,
	txMeta *StakeMetadata,
) (DerivedKeyEntry, error) {
	// The DerivedKeyEntry.TransactionSpendingLimit for staking maps
	// ValidatorPKID to the amount of stake-able DESO
	// nanos allowed for this derived key.

	// Convert ValidatorPublicKey to ValidatorPKID.
	validatorEntry, err := bav.GetValidatorByPublicKey(txMeta.ValidatorPublicKey)
	if err != nil {
		return derivedKeyEntry, errors.Wrapf(err, "_checkStakeTxnSpendingLimitAndUpdateDerivedKey: ")
	}
	if validatorEntry == nil || validatorEntry.isDeleted {
		return derivedKeyEntry, errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView._checkStakeTxnSpendingLimitAndUpdateDerivedKey: ")
	}

	// Check spending limit for this validator.
	// If not found, check spending limit for any validator.
	isSpendingLimitExceeded := false

	for _, validatorPKID := range []*PKID{validatorEntry.ValidatorPKID, &ZeroPKID} {
		// Retrieve DerivedKeyEntry.TransactionSpendingLimit.
		stakeLimitKey := MakeStakeLimitKey(validatorPKID)
		spendingLimit, exists := derivedKeyEntry.TransactionSpendingLimitTracker.StakeLimitMap[stakeLimitKey]
		if !exists {
			continue
		}
		spendingLimitCmp := spendingLimit.Cmp(txMeta.StakeAmountNanos)

		// If the amount being staked exceeds the spending limit, note it, and skip this spending limit.
		// This solves for the case where the amount being staked is greater than the spending limit
		// scoped to a specific validator but may be within the limit scoped to any validator.
		if spendingLimitCmp < 0 {
			isSpendingLimitExceeded = true
			continue
		}

		// If the spending limit exceeds the amount being staked, update the spending limit.
		if spendingLimitCmp > 0 {
			updatedSpendingLimit, err := SafeUint256().Sub(spendingLimit, txMeta.StakeAmountNanos)
			if err != nil {
				return derivedKeyEntry, errors.Wrapf(err, "_checkStakeTxnSpendingLimitAndUpdateDerivedKey: ")
			}
			if !updatedSpendingLimit.IsUint64() {
				// This should never happen, but good to double-check.
				return derivedKeyEntry, errors.New(
					"_checkStakeTxnSpendingLimitAndUpdateDerivedKey: updated spending limit exceeds uint64",
				)
			}
			derivedKeyEntry.TransactionSpendingLimitTracker.StakeLimitMap[stakeLimitKey] = updatedSpendingLimit
			return derivedKeyEntry, nil
		}

		// If we get to this point, the spending limit exactly equals
		// the amount being staked. Delete the spending limit.
		delete(derivedKeyEntry.TransactionSpendingLimitTracker.StakeLimitMap, stakeLimitKey)
		return derivedKeyEntry, nil
	}
	// If we get here, it means that we did not find a valid spendingLimit with enough stake
	// to cover the transaction's required stake amount.

	// Error if the spending limit was found but the staking limit was exceeded.
	if isSpendingLimitExceeded {
		return derivedKeyEntry, errors.Wrapf(RuleErrorStakeTransactionSpendingLimitExceeded, "UtxoView._checkStakeTxnSpendingLimitAndUpdateDerivedKey: ")
	}

	// If we get to this point, we didn't find a matching spending limit.
	return derivedKeyEntry, errors.Wrapf(RuleErrorStakeTransactionSpendingLimitNotFound, "UtxoView._checkStakeTxnSpendingLimitAndUpdateDerivedKey: ")
}

// TODO: This function is highly-redundant with the previous function. Probably makes sense
// to consolidate in the future.
func (bav *UtxoView) _checkUnstakeTxnSpendingLimitAndUpdateDerivedKey(
	derivedKeyEntry DerivedKeyEntry,
	txMeta *UnstakeMetadata,
) (DerivedKeyEntry, error) {
	// The DerivedKeyEntry.TransactionSpendingLimit for unstaking maps
	// ValidatorPKID to the amount of unstake-able DESO
	// nanos allowed for this derived key.

	// Convert ValidatorPublicKey to ValidatorPKID.
	validatorEntry, err := bav.GetValidatorByPublicKey(txMeta.ValidatorPublicKey)
	if err != nil {
		return derivedKeyEntry, errors.Wrapf(err, "_checkUnstakeTxnSpendingLimitAndUpdateDerivedKey: ")
	}
	if validatorEntry == nil || validatorEntry.isDeleted {
		return derivedKeyEntry, errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView._checkUnstakeTxnSpendingLimitAndUpdateDerivedKey: ")
	}

	// Check spending limit for this validator.
	// If not found, check spending limit for any validator.
	isSpendingLimitExceeded := false

	for _, validatorPKID := range []*PKID{validatorEntry.ValidatorPKID, &ZeroPKID} {
		// Retrieve DerivedKeyEntry.TransactionSpendingLimit.
		stakeLimitKey := MakeStakeLimitKey(validatorPKID)
		spendingLimit, exists := derivedKeyEntry.TransactionSpendingLimitTracker.UnstakeLimitMap[stakeLimitKey]
		if !exists {
			continue
		}
		spendingLimitCmp := spendingLimit.Cmp(txMeta.UnstakeAmountNanos)

		// If the amount being unstaked exceeds the spending limit, note it, and skip this spending limit.
		// This solves for the case where the amount being unstaked is greater than the spending limit
		// scoped to a specific validator but may be within the limit scoped to any validator.
		if spendingLimitCmp < 0 {
			isSpendingLimitExceeded = true
			continue
		}

		// If the spending limit exceeds the amount being unstaked, update the spending limit.
		if spendingLimitCmp > 0 {
			updatedSpendingLimit, err := SafeUint256().Sub(spendingLimit, txMeta.UnstakeAmountNanos)
			if err != nil {
				return derivedKeyEntry, errors.Wrapf(err, "_checkUnstakeTxnSpendingLimitAndUpdateDerivedKey: ")
			}
			if !updatedSpendingLimit.IsUint64() {
				// This should never happen, but good to double-check.
				return derivedKeyEntry, errors.New(
					"_checkUnstakeTxnSpendingLimitAndUpdateDerivedKey: updated spending limit exceeds uint64",
				)
			}
			derivedKeyEntry.TransactionSpendingLimitTracker.UnstakeLimitMap[stakeLimitKey] = updatedSpendingLimit
			return derivedKeyEntry, nil
		}

		// If we get to this point, the spending limit exactly equals
		// the amount being unstaked. Delete the spending limit.
		delete(derivedKeyEntry.TransactionSpendingLimitTracker.UnstakeLimitMap, stakeLimitKey)
		return derivedKeyEntry, nil
	}

	// Error if the spending limit was found but the unstaking limit was exceeded.
	if isSpendingLimitExceeded {
		return derivedKeyEntry, errors.Wrapf(RuleErrorUnstakeTransactionSpendingLimitExceeded, "UtxoView._checkUnstakeTxnSpendingLimitAndUpdateDerivedKey: ")
	}

	// If we get to this point, we didn't find a matching spending limit.
	return derivedKeyEntry, errors.Wrapf(RuleErrorUnstakeTransactionSpendingLimitNotFound, "UtxoView._checkUnstakeTxnSpendingLimitAndUpdateDerivedKey: ")
}

func (bav *UtxoView) _checkUnlockStakeTxnSpendingLimitAndUpdateDerivedKey(
	derivedKeyEntry DerivedKeyEntry,
	txMeta *UnlockStakeMetadata,
) (DerivedKeyEntry, error) {
	// The DerivedKeyEntry.TransactionSpendingLimit for unlocking stake maps
	// ValidatorPKID to the number of UnlockStake transactions
	// this derived key is allowed to perform.

	// Convert ValidatorPublicKey to ValidatorPKID.
	validatorPKIDEntry := bav.GetPKIDForPublicKey(txMeta.ValidatorPublicKey.ToBytes())
	if validatorPKIDEntry == nil || validatorPKIDEntry.isDeleted {
		return derivedKeyEntry, errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView._checkUnlockStakeTxnSpendingLimitAndUpdateDerivedKey: ")
	}

	// Check spending limit for this validator.
	// If not found, check spending limit for any validator.
	for _, validatorPKID := range []*PKID{validatorPKIDEntry.PKID, &ZeroPKID} {
		// Retrieve DerivedKeyEntry.TransactionSpendingLimit.
		stakeLimitKey := MakeStakeLimitKey(validatorPKID)
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
	return derivedKeyEntry, errors.Wrapf(RuleErrorUnlockStakeTransactionSpendingLimitNotFound, "UtxoView._checkUnlockStakeTxnSpendingLimitAndUpdateDerivedKey: ")
}

func (bav *UtxoView) IsValidStakeLimitKey(transactorPublicKeyBytes []byte) error {
	// Convert TransactorPublicKeyBytes to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPublicKeyBytes)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return errors.Wrapf(RuleErrorTransactionSpendingLimitInvalidStaker, "UtxoView.IsValidStakeLimitKey: ")
	}

	return nil
}

//
// CONSTANTS
//

const RuleErrorInvalidStakerPKID RuleError = "RuleErrorInvalidStakerPKID"
const RuleErrorInvalidStakingRewardMethod RuleError = "RuleErrorInvalidStakingRewardMethod"
const RuleErrorInvalidStakeAmountNanos RuleError = "RuleErrorInvalidStakeAmountNanos"
const RuleErrorInvalidStakeInsufficientBalance RuleError = "RuleErrorInvalidStakeInsufficientBalance"
const RuleErrorInvalidStakeValidatorDisabledDelegatedStake RuleError = "RuleErrorInvalidStakeValidatorDisabledDelegatedStake"
const RuleErrorInvalidUnstakeNoStakeFound RuleError = "RuleErrorInvalidUnstakeNoStakeFound"
const RuleErrorInvalidUnstakeAmountNanos RuleError = "RuleErrorInvalidUnstakeAmountNanos"
const RuleErrorInvalidUnstakeInsufficientStakeFound RuleError = "RuleErrorInvalidUnstakeInsufficientStakeFound"
const RuleErrorInvalidUnlockStakeEpochRange RuleError = "RuleErrorInvalidUnlockStakeEpochRange"
const RuleErrorInvalidUnlockStakeMustWaitLockupDuration RuleError = "RuleErrorInvalidUnlockStakeMustWaitLockupDuration"
const RuleErrorInvalidUnlockStakeNoUnlockableStakeFound RuleError = "RuleErrorInvalidUnlockStakeNoUnlockableStakeFound"
const RuleErrorInvalidUnlockStakeUnlockableStakeOverflowsUint64 RuleError = "RuleErrorInvalidUnlockStakeUnlockableStakeOverflowsUint64"
const RuleErrorStakeTransactionSpendingLimitNotFound RuleError = "RuleErrorStakeTransactionSpendingLimitNotFound"
const RuleErrorStakeTransactionSpendingLimitExceeded RuleError = "RuleErrorStakeTransactionSpendingLimitExceeded"
const RuleErrorUnstakeTransactionSpendingLimitNotFound RuleError = "RuleErrorUnstakeTransactionSpendingLimitNotFound"
const RuleErrorUnstakeTransactionSpendingLimitExceeded RuleError = "RuleErrorUnstakeTransactionSpendingLimitExceeded"
const RuleErrorUnlockStakeTransactionSpendingLimitNotFound RuleError = "RuleErrorUnlockStakeTransactionSpendingLimitNotFound"
const RuleErrorTransactionSpendingLimitInvalidStaker RuleError = "RuleErrorTransactionSpendingLimitInvalidStaker"
const RuleErrorTransactionSpendingLimitInvalidValidator RuleError = "RuleErrorTransactionSpendingLimitInvalidValidator"
const RuleErrorTransactionSpendingLimitValidatorDisabledDelegatedStake RuleError = "RuleErrorTransactionSpendingLimitValidatorDisabledDelegatedStake"
