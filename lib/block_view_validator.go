package lib

import (
	"bytes"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"math"
	"net/url"
	"sort"
)

//
// TYPES: ValidatorEntry
//

type ValidatorEntry struct {
	ValidatorID                *BlockHash
	ValidatorPKID              *PKID
	Domains                    [][]byte
	DisableDelegatedStake      bool
	VotingPublicKey            []byte
	VotingPublicKeySignature   []byte
	VotingSignatureBlockHeight uint64
	TotalStakeAmountNanos      *uint256.Int
	RegisteredAtBlockHeight    uint64
	ExtraData                  map[string][]byte
	isDeleted                  bool
}

type ValidatorMapKey struct {
	ValidatorPKID PKID
}

func (validatorEntry *ValidatorEntry) Copy() *ValidatorEntry {
	// Copy domains.
	var domainsCopy [][]byte
	for _, domain := range validatorEntry.Domains {
		domainsCopy = append(domainsCopy, append([]byte{}, domain...)) // Makes a copy.
	}

	// Copy ExtraData.
	extraDataCopy := make(map[string][]byte)
	for key, value := range validatorEntry.ExtraData {
		extraDataCopy[key] = value
	}

	// Return new ValidatorEntry.
	return &ValidatorEntry{
		ValidatorID:                validatorEntry.ValidatorID.NewBlockHash(),
		ValidatorPKID:              validatorEntry.ValidatorPKID.NewPKID(),
		Domains:                    domainsCopy,
		DisableDelegatedStake:      validatorEntry.DisableDelegatedStake,
		VotingPublicKey:            append([]byte{}, validatorEntry.VotingPublicKey...),
		VotingPublicKeySignature:   append([]byte{}, validatorEntry.VotingPublicKeySignature...),
		VotingSignatureBlockHeight: validatorEntry.VotingSignatureBlockHeight,
		TotalStakeAmountNanos:      validatorEntry.TotalStakeAmountNanos.Clone(),
		RegisteredAtBlockHeight:    validatorEntry.RegisteredAtBlockHeight,
		ExtraData:                  extraDataCopy,
		isDeleted:                  validatorEntry.isDeleted,
	}
}

func (validatorEntry *ValidatorEntry) ToMapKey() ValidatorMapKey {
	return ValidatorMapKey{ValidatorPKID: *validatorEntry.ValidatorPKID}
}

func (validatorEntry *ValidatorEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, validatorEntry.ValidatorID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, validatorEntry.ValidatorPKID, skipMetadata...)...)

	// Domains
	data = append(data, UintToBuf(uint64(len(validatorEntry.Domains)))...)
	for _, domain := range validatorEntry.Domains {
		data = append(data, EncodeByteArray(domain)...)
	}

	data = append(data, BoolToByte(validatorEntry.DisableDelegatedStake))
	data = append(data, EncodeByteArray(validatorEntry.VotingPublicKey)...)
	data = append(data, EncodeByteArray(validatorEntry.VotingPublicKeySignature)...)
	data = append(data, UintToBuf(validatorEntry.VotingSignatureBlockHeight)...)
	data = append(data, EncodeUint256(validatorEntry.TotalStakeAmountNanos)...)
	data = append(data, UintToBuf(validatorEntry.RegisteredAtBlockHeight)...)
	data = append(data, EncodeExtraData(validatorEntry.ExtraData)...)
	return data
}

func (validatorEntry *ValidatorEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// ValidatorID
	validatorID := &BlockHash{}
	if exist, err := DecodeFromBytes(validatorID, rr); exist && err == nil {
		validatorEntry.ValidatorID = validatorID
	} else if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading ValidatorID: ")
	}

	// ValidatorPKID
	validatorPKID := &PKID{}
	if exist, err := DecodeFromBytes(validatorPKID, rr); exist && err == nil {
		validatorEntry.ValidatorPKID = validatorPKID
	} else if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading ValidatorPKID: ")
	}

	// Domains
	numDomains, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading Domains: ")
	}
	for ii := 0; ii < int(numDomains); ii++ {
		domain, err := DecodeByteArray(rr)
		if err != nil {
			return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading Domains: ")
		}
		validatorEntry.Domains = append(validatorEntry.Domains, domain)
	}

	// DisableDelegatedStake
	validatorEntry.DisableDelegatedStake, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading DisableDelegatedStake: ")
	}

	// VotingPublicKey
	validatorEntry.VotingPublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading VotingPublicKey: ")
	}

	// VotingPublicKeySignature
	validatorEntry.VotingPublicKeySignature, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading VotingPublicKeySignature: ")
	}

	// VotingSignatureBlockHeight
	validatorEntry.VotingSignatureBlockHeight, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading VotingSignatureBlockHeight: ")
	}

	// TotalStakeAmountNanos
	validatorEntry.TotalStakeAmountNanos, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading TotalStakeAmountNanos: ")
	}

	// RegisteredAtBlockHeight
	validatorEntry.RegisteredAtBlockHeight, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading RegisteredAtBlockHeight: ")
	}

	// ExtraData
	validatorEntry.ExtraData, err = DecodeExtraData(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading ExtraData: ")
	}

	return nil
}

func (validatorEntry *ValidatorEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (validatorEntry *ValidatorEntry) GetEncoderType() EncoderType {
	return EncoderTypeValidatorEntry
}

//
// TYPES: RegisterAsValidatorMetadata
//

type RegisterAsValidatorMetadata struct {
	Domains                    [][]byte
	DisableDelegatedStake      bool
	VotingPublicKey            []byte
	VotingPublicKeySignature   []byte
	VotingSignatureBlockHeight uint64
}

func (txnData *RegisterAsValidatorMetadata) GetTxnType() TxnType {
	return TxnTypeRegisterAsValidator
}

func (txnData *RegisterAsValidatorMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte

	// Domains
	data = append(data, UintToBuf(uint64(len(txnData.Domains)))...)
	for _, domain := range txnData.Domains {
		data = append(data, EncodeByteArray(domain)...)
	}

	data = append(data, BoolToByte(txnData.DisableDelegatedStake))
	data = append(data, EncodeByteArray(txnData.VotingPublicKey)...)
	data = append(data, EncodeByteArray(txnData.VotingPublicKeySignature)...)
	data = append(data, UintToBuf(txnData.VotingSignatureBlockHeight)...)
	return data, nil
}

func (txnData *RegisterAsValidatorMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// Domains
	numDomains, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorMetadata.FromBytes: Problem reading Domains: ")
	}
	for ii := 0; ii < int(numDomains); ii++ {
		domain, err := DecodeByteArray(rr)
		if err != nil {
			return errors.Wrapf(err, "RegisterAsValidatorMetadata.FromBytes: Problem reading Domains: ")
		}
		txnData.Domains = append(txnData.Domains, domain)
	}

	// DisableDelegatedStake
	txnData.DisableDelegatedStake, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorMetadata.FromBytes: Problem reading DisableDelegatedStake: ")
	}

	// VotingPublicKey
	txnData.VotingPublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorMetadata.FromBytes: Problem reading VotingPublicKey: ")
	}

	// VotingPublicKeySignature
	txnData.VotingPublicKeySignature, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorMetadata.FromBytes: Problem reading VotingPublicKeySignature: ")
	}

	// VotingSignatureBlockHeight
	txnData.VotingSignatureBlockHeight, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorMetadata.FromBytes: Problem reading VotingSignatureBlockHeight: ")
	}

	return nil
}

func (txnData *RegisterAsValidatorMetadata) New() DeSoTxnMetadata {
	return &RegisterAsValidatorMetadata{}
}

//
// TYPES: UnregisterAsValidatorMetadata
//

type UnregisterAsValidatorMetadata struct{}

func (txnData *UnregisterAsValidatorMetadata) GetTxnType() TxnType {
	return TxnTypeUnregisterAsValidator
}

func (txnData *UnregisterAsValidatorMetadata) ToBytes(preSignature bool) ([]byte, error) {
	return []byte{}, nil
}

func (txnData *UnregisterAsValidatorMetadata) FromBytes(data []byte) error {
	return nil
}

func (txnData *UnregisterAsValidatorMetadata) New() DeSoTxnMetadata {
	return &UnregisterAsValidatorMetadata{}
}

//
// TYPES: RegisterAsValidatorTxindexMetadata
//

type RegisterAsValidatorTxindexMetadata struct {
	ValidatorPublicKeyBase58Check string
	Domains                       []string
	DisableDelegatedStake         bool
	VotingPublicKey               string
	VotingPublicKeySignature      string
	VotingSignatureBlockHeight    uint64
	UnstakedStakers               []*UnstakedStakerTxindexMetadata
}

func (txindexMetadata *RegisterAsValidatorTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(txindexMetadata.ValidatorPublicKeyBase58Check))...)

	// Domains
	data = append(data, UintToBuf(uint64(len(txindexMetadata.Domains)))...)
	for _, domain := range txindexMetadata.Domains {
		data = append(data, EncodeByteArray([]byte(domain))...)
	}

	data = append(data, BoolToByte(txindexMetadata.DisableDelegatedStake))
	data = append(data, EncodeByteArray([]byte(txindexMetadata.VotingPublicKey))...)
	data = append(data, EncodeByteArray([]byte(txindexMetadata.VotingPublicKeySignature))...)
	data = append(data, UintToBuf(txindexMetadata.VotingSignatureBlockHeight)...)

	// UnstakedStakers
	data = append(data, UintToBuf(uint64(len(txindexMetadata.UnstakedStakers)))...)
	for _, unstakedStaker := range txindexMetadata.UnstakedStakers {
		data = append(data, unstakedStaker.RawEncodeWithoutMetadata(blockHeight, skipMetadata...)...)
	}

	return data
}

func (txindexMetadata *RegisterAsValidatorTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// ValidatorPublicKeyBase58Check
	validatorPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorTxindexMetadata.Decode: Problem reading ValidatorPublicKeyBase58Check: ")
	}
	txindexMetadata.ValidatorPublicKeyBase58Check = string(validatorPublicKeyBase58CheckBytes)

	// Domains
	numDomains, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorTxindexMetadata.Decode: Problem reading Domains: ")
	}
	for ii := 0; ii < int(numDomains); ii++ {
		domain, err := DecodeByteArray(rr)
		if err != nil {
			return errors.Wrapf(err, "RegisterAsValidatorTxindexMetadata.Decode: Problem reading Domains: ")
		}
		txindexMetadata.Domains = append(txindexMetadata.Domains, string(domain))
	}

	// DisableDelegatedStake
	txindexMetadata.DisableDelegatedStake, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorTxindexMetadata.Decode: Problem reading DisableDelegatedStake: ")
	}

	// VotingPublicKey
	votingPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorTxindexMetadata.Decode: Problem reading VotingPublicKey: ")
	}
	txindexMetadata.VotingPublicKey = string(votingPublicKeyBytes)

	// VotingPublicKeySignature
	votingPublicKeySignatureBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorTxindexMetadata.Decode: Problem reading VotingPublicKeySignature: ")
	}
	txindexMetadata.VotingPublicKeySignature = string(votingPublicKeySignatureBytes)

	// VotingSignatureBlockHeight
	txindexMetadata.VotingSignatureBlockHeight, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorTxindexMetadata.Decode: Problem reading VotingSignatureBlockHeight: ")
	}

	// UnstakedStakers
	numUnstakedStakers, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorTxindexMetadata.Decode: Problem reading UnstakedStakers: ")
	}
	for ii := 0; ii < int(numUnstakedStakers); ii++ {
		unstakedStaker := &UnstakedStakerTxindexMetadata{}
		err = unstakedStaker.RawDecodeWithoutMetadata(blockHeight, rr)
		if err != nil {
			return errors.Wrapf(err, "RegisterAsValidatorTxindexMetadata.Decode: Problem reading UnstakedStakers: ")
		}
		txindexMetadata.UnstakedStakers = append(txindexMetadata.UnstakedStakers, unstakedStaker)
	}

	return nil
}

func (txindexMetadata *RegisterAsValidatorTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txindexMetadata *RegisterAsValidatorTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeRegisterAsValidatorTxindexMetadata
}

//
// TYPES: UnstakedStakerTxindexMetadata
//

type UnstakedStakerTxindexMetadata struct {
	StakerPublicKeyBase58Check string
	UnstakeAmountNanos         *uint256.Int
}

func (txindexMetadata *UnstakedStakerTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(txindexMetadata.StakerPublicKeyBase58Check))...)
	data = append(data, EncodeUint256(txindexMetadata.UnstakeAmountNanos)...)
	return data
}

func (txindexMetadata *UnstakedStakerTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// StakerPublicKeyBase58Check
	stakerPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UnstakedStakerTxindexMetadata.Decode: Problem reading StakerPublicKeyBase58Check: ")
	}
	txindexMetadata.StakerPublicKeyBase58Check = string(stakerPublicKeyBase58CheckBytes)

	// UnstakeAmountNanos
	txindexMetadata.UnstakeAmountNanos, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "UnstakedStakerTxindexMetadata.Decode: Problem reading UnstakeAmountNanos: ")
	}

	return nil
}

//
// TYPES: UnregisterAsValidatorTxindexMetadata
//

type UnregisterAsValidatorTxindexMetadata struct {
	ValidatorPublicKeyBase58Check string
	UnstakedStakers               []*UnstakedStakerTxindexMetadata
}

func (txindexMetadata *UnregisterAsValidatorTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(txindexMetadata.ValidatorPublicKeyBase58Check))...)

	// UnstakedStakers
	data = append(data, UintToBuf(uint64(len(txindexMetadata.UnstakedStakers)))...)
	for _, unstakedStaker := range txindexMetadata.UnstakedStakers {
		data = append(data, unstakedStaker.RawEncodeWithoutMetadata(blockHeight, skipMetadata...)...)
	}

	return data
}

func (txindexMetadata *UnregisterAsValidatorTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// ValidatorPublicKeyBase58Check
	validatorPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UnregisterAsValidatorTxindexMetadata.Decode: Problem reading ValidatorPublicKeyBase58Check: ")
	}
	txindexMetadata.ValidatorPublicKeyBase58Check = string(validatorPublicKeyBase58CheckBytes)

	// UnstakedStakers
	numUnstakedStakers, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UnregisterAsValidatorTxindexMetadata.Decode: Problem reading UnstakedStakers: ")
	}
	for ii := 0; ii < int(numUnstakedStakers); ii++ {
		unstakedStaker := &UnstakedStakerTxindexMetadata{}
		err = unstakedStaker.RawDecodeWithoutMetadata(blockHeight, rr)
		if err != nil {
			return errors.Wrapf(err, "UnregisterAsValidatorTxindexMetadata.Decode: Problem reading UnstakedStakers: ")
		}
		txindexMetadata.UnstakedStakers = append(txindexMetadata.UnstakedStakers, unstakedStaker)
	}

	return nil
}

func (txindexMetadata *UnregisterAsValidatorTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txindexMetadata *UnregisterAsValidatorTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeUnregisterAsValidatorTxindexMetadata
}

//
// DB UTILS
//

func DBKeyForValidatorByPKID(validatorEntry *ValidatorEntry) []byte {
	var key []byte
	key = append(key, Prefixes.PrefixValidatorByPKID...)
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBKeyForValidatorByStake(validatorEntry *ValidatorEntry) []byte {
	var key []byte
	key = append(key, Prefixes.PrefixValidatorByStake...)
	// FIXME: ensure that this left-pads the uint256 to be equal width
	key = append(key, EncodeUint256(validatorEntry.TotalStakeAmountNanos)...)                 // Highest stake first
	key = append(key, EncodeUint64(math.MaxUint64-validatorEntry.RegisteredAtBlockHeight)...) // Oldest first
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBKeyForGlobalStakeAmountNanos() []byte {
	var key []byte
	key = append(key, Prefixes.PrefixGlobalStakeAmountNanos...)
	return key
}

func DBGetValidatorByPKID(handle *badger.DB, snap *Snapshot, pkid *PKID) (*ValidatorEntry, error) {
	var ret *ValidatorEntry
	var err error
	handle.View(func(txn *badger.Txn) error {
		ret, err = DBGetValidatorByPKIDWithTxn(txn, snap, pkid)
		return nil
	})
	return ret, err
}

func DBGetValidatorByPKIDWithTxn(txn *badger.Txn, snap *Snapshot, pkid *PKID) (*ValidatorEntry, error) {
	// Retrieve ValidatorEntry from db.
	key := DBKeyForValidatorByPKID(&ValidatorEntry{ValidatorPKID: pkid})
	validatorBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetValidatorByPKID: problem retrieving ValidatorEntry")
	}

	// Decode ValidatorEntry from bytes.
	validatorEntry := &ValidatorEntry{}
	rr := bytes.NewReader(validatorBytes)
	if exist, err := DecodeFromBytes(validatorEntry, rr); !exist || err != nil {
		return nil, errors.Wrapf(err, "DBGetValidatorByPKID: problem decoding ValidatorEntry")
	}
	return validatorEntry, nil
}

func DBGetTopValidatorsByStake(
	handle *badger.DB,
	snap *Snapshot,
	limit int,
	validatorEntriesToSkip []*ValidatorEntry,
) ([]*ValidatorEntry, error) {
	var validatorEntries []*ValidatorEntry

	// Convert ValidatorEntriesToSkip to ValidatorEntryKeysToSkip.
	validatorKeysToSkip := NewSet([]string{})
	for _, validatorEntryToSkip := range validatorEntriesToSkip {
		validatorKeysToSkip.Add(string(DBKeyForValidatorByStake(validatorEntryToSkip)))
	}

	// Retrieve top N ValidatorEntry PKIDs by stake.
	var key []byte
	key = append(key, Prefixes.PrefixValidatorByStake...)
	_, validatorPKIDsBytes, err := EnumerateKeysForPrefixWithLimitOffsetOrder(
		handle, key, limit, nil, true, validatorKeysToSkip,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetTopValidatorsByStake: problem retrieving top validators: ")
	}

	// For each PKID, retrieve the ValidatorEntry by PKID.
	for _, validatorPKIDBytes := range validatorPKIDsBytes {
		// Convert PKIDBytes to PKID.
		validatorPKID := &PKID{}
		exists, err := DecodeFromBytes(validatorPKID, bytes.NewReader(validatorPKIDBytes))
		if !exists || err != nil {
			return nil, errors.Wrapf(err, "DBGetTopValidatorsByStake: problem reading ValidatorPKID: ")
		}
		// Retrieve ValidatorEntry by PKID.
		validatorEntry, err := DBGetValidatorByPKID(handle, snap, validatorPKID)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetTopValidatorsByStake: problem retrieving validator by PKID: ")
		}
		validatorEntries = append(validatorEntries, validatorEntry)
	}

	return validatorEntries, nil
}

func DBGetGlobalStakeAmountNanos(handle *badger.DB, snap *Snapshot) (*uint256.Int, error) {
	var ret *uint256.Int
	var err error
	handle.View(func(txn *badger.Txn) error {
		ret, err = DBGetGlobalStakeAmountNanosWithTxn(txn, snap)
		return nil
	})
	return ret, err
}

func DBGetGlobalStakeAmountNanosWithTxn(txn *badger.Txn, snap *Snapshot) (*uint256.Int, error) {
	// Retrieve from db.
	key := DBKeyForGlobalStakeAmountNanos()
	globalStakeAmountNanosBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return 0.
		if err == badger.ErrKeyNotFound {
			return uint256.NewInt(), nil
		}
		return nil, errors.Wrapf(err, "DBGetGlobalStakeAmountNanosWithTxn: problem retrieving value")
	}

	// Decode from bytes.
	var globalStakeAmountNanos *uint256.Int
	rr := bytes.NewReader(globalStakeAmountNanosBytes)
	globalStakeAmountNanos, err = DecodeUint256(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetGlobalStakeAmountNanosWithTxn: problem decoding value")
	}
	return globalStakeAmountNanos, nil
}

func DBPutValidatorWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorEntry *ValidatorEntry,
	blockHeight uint64,
) error {
	if validatorEntry == nil {
		return nil
	}

	// Set ValidatorEntry in PrefixValidatorByPKID.
	key := DBKeyForValidatorByPKID(validatorEntry)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorEntry)); err != nil {
		return errors.Wrapf(
			err, "DBPutValidatorWithTxn: problem storing ValidatorEntry in index PrefixValidatorByPKID",
		)
	}

	// Set ValidatorEntry.PKID in PrefixValidatorByStake.
	key = DBKeyForValidatorByStake(validatorEntry)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorEntry.ValidatorPKID)); err != nil {
		return errors.Wrapf(
			err, "DBPutValidatorWithTxn: problem storing ValidatorEntry in index PrefixValidatorByPKID",
		)
	}

	return nil
}

func DBDeleteValidatorWithTxn(txn *badger.Txn, snap *Snapshot, validatorEntry *ValidatorEntry) error {
	if validatorEntry == nil {
		return nil
	}

	// Delete ValidatorEntry from PrefixValidatorByPKID.
	key := DBKeyForValidatorByPKID(validatorEntry)
	if err := DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(
			err, "DBDeleteValidatorWithTxn: problem deleting ValidatorEntry from index PrefixValidatorByPKID",
		)
	}

	// Delete ValidatorEntry.PKID from PrefixValidatorByStake.
	key = DBKeyForValidatorByStake(validatorEntry)
	if err := DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(
			err, "DBDeleteValidatorWithTxn: problem deleting ValidatorEntry from index PrefixValidatorByPKID",
		)
	}

	return nil
}

func DBPutGlobalStakeAmountNanosWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	globalStakeAmountNanos *uint256.Int,
	blockHeight uint64,
) error {
	key := DBKeyForGlobalStakeAmountNanos()
	return DBSetWithTxn(txn, snap, key, EncodeUint256(globalStakeAmountNanos))
}

//
// BLOCKCHAIN UTILS
//

func (bc *Blockchain) CreateRegisterAsValidatorTxn(
	transactorPublicKey []byte,
	metadata *RegisterAsValidatorMetadata,
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
	// Create a txn containing the RegisterAsValidator fields.
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
			err, "Blockchain.CreateRegisterAsValidatorTxn: problem creating new utxo view: ",
		)
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(
				err, "Blockchain.CreateRegisterAsValidatorTxn: problem getting augmented utxo view from mempool: ",
			)
		}
	}

	// Validate txn metadata.
	if err = utxoView.IsValidRegisterAsValidatorMetadata(transactorPublicKey, metadata); err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateRegisterAsValidatorTxn: invalid txn metadata: ",
		)
	}

	// We don't need to make any tweaks to the amount because
	// it's basically a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err := bc.AddInputsAndChangeToTransaction(
		txn, minFeeRateNanosPerKB, mempool,
	)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateRegisterAsValidatorTxn: problem adding inputs: ",
		)
	}

	// Validate that the transaction has at least one input, even if it all goes
	// to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, errors.New(
			"Blockchain.CreateRegisterAsValidatorTxn: txn has zero inputs, try increasing the fee rate",
		)
	}

	// Sanity-check that the spendAmount is zero.
	if spendAmount != 0 {
		return nil, 0, 0, 0, fmt.Errorf(
			"Blockchain.CreateRegisterAsValidatorTxn: spend amount is non-zero: %d", spendAmount,
		)
	}
	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateUnregisterAsValidatorTxn(
	transactorPublicKey []byte,
	metadata *UnregisterAsValidatorMetadata,
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
	// Create a txn containing the UnregisterAsValidator fields.
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
			err, "Blockchain.CreateRegisterAsValidatorTxn: problem creating new utxo view: ",
		)
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(
				err, "Blockchain.CreateRegisterAsValidatorTxn: problem getting augmented utxo view from mempool: ",
			)
		}
	}

	// Validate txn metadata.
	if err = utxoView.IsValidUnregisterAsValidatorMetadata(transactorPublicKey, metadata); err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateUnregisterAsValidatorTxn: invalid txn metadata: ",
		)
	}

	// We don't need to make any tweaks to the amount because
	// it's basically a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err := bc.AddInputsAndChangeToTransaction(
		txn, minFeeRateNanosPerKB, mempool,
	)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateUnregisterAsValidatorTxn: problem adding inputs: ",
		)
	}

	// Validate that the transaction has at least one input, even if it all goes
	// to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, errors.New(
			"Blockchain.CreateUnregisterAsValidatorTxn: txn has zero inputs, try increasing the fee rate",
		)
	}

	// Sanity-check that the spendAmount is zero.
	if spendAmount != 0 {
		return nil, 0, 0, 0, fmt.Errorf(
			"Blockchain.CreateUnregisterAsValidatorTxn: spend amount is non-zero: %d", spendAmount,
		)
	}
	return txn, totalInput, changeAmount, fees, nil
}

//
// UTXO VIEW UTILS
//

func (bav *UtxoView) _connectRegisterAsValidator(
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
	if txn.TxnMeta.GetTxnType() != TxnTypeRegisterAsValidator {
		return 0, 0, nil, fmt.Errorf(
			"_connectRegisterAsValidator: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Connect a basic transfer to get the total input and the
	// total output without considering the txn metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectRegisterAsValidator: ")
	}
	if verifySignatures {
		// _connectBasicTransfer has already checked that the txn is signed
		// by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*RegisterAsValidatorMetadata)

	// Validate the txn metadata.
	if err = bav.IsValidRegisterAsValidatorMetadata(txn.PublicKey, txMeta); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectRegisterAsValidator: ")
	}

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return 0, 0, nil, RuleErrorInvalidValidatorPKID
	}

	// Check if there is an existing ValidatorEntry that will be overwritten.
	// The existing ValidatorEntry will be restored if we disconnect this transaction.
	prevValidatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectRegisterAsValidator: ")
	}
	// Delete the existing ValidatorEntry, if exists.
	if prevValidatorEntry != nil {
		bav._deleteValidatorEntryMappings(prevValidatorEntry)
	}

	// Set ValidatorID only if this is a new ValidatorEntry.
	validatorID := txHash
	if prevValidatorEntry != nil {
		validatorID = prevValidatorEntry.ValidatorID
	}

	// TODO: In subsequent PR, unstake delegated stakers if updating DisableDelegatedStake=true.
	// This should also update GlobalStakeAmountNanos.
	if prevValidatorEntry != nil &&
		!prevValidatorEntry.DisableDelegatedStake && // Validator previously allowed delegated stake.
		txMeta.DisableDelegatedStake { // Validator no longer allows delegated stake.
	}

	// TODO: In subsequent PR, calculate TotalStakeAmountNanos.
	totalStakeAmountNanos := uint256.NewInt()

	// Set RegisteredAtBlockHeight only if this is a new ValidatorEntry.
	registeredAtBlockHeight := uint64(blockHeight)
	if prevValidatorEntry != nil {
		registeredAtBlockHeight = prevValidatorEntry.RegisteredAtBlockHeight
	}

	// Retrieve existing ExtraData to merge with any new ExtraData.
	var prevExtraData map[string][]byte
	if prevValidatorEntry != nil {
		prevExtraData = prevValidatorEntry.ExtraData
	}

	// Construct new ValidatorEntry from metadata.
	currentValidatorEntry := &ValidatorEntry{
		ValidatorID:                validatorID,
		ValidatorPKID:              transactorPKIDEntry.PKID,
		Domains:                    txMeta.Domains,
		DisableDelegatedStake:      txMeta.DisableDelegatedStake,
		VotingPublicKey:            txMeta.VotingPublicKey,
		VotingPublicKeySignature:   txMeta.VotingPublicKeySignature,
		VotingSignatureBlockHeight: txMeta.VotingSignatureBlockHeight,
		TotalStakeAmountNanos:      totalStakeAmountNanos,
		RegisteredAtBlockHeight:    registeredAtBlockHeight,
		ExtraData:                  mergeExtraData(prevExtraData, txn.ExtraData),
	}
	// Set the ValidatorEntry.
	bav._setValidatorEntryMappings(currentValidatorEntry)

	// Add a UTXO operation
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:               OperationTypeRegisterAsValidator,
		PrevValidatorEntry: prevValidatorEntry,
		// PrevStakeEntries: prevStakeEntries, // TODO: in subsequent PR
	})
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectRegisterAsValidator(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// Validate the last operation is a RegisterAsValidator operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectRegisterAsValidator: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	operationData := utxoOpsForTxn[operationIndex]
	if operationData.Type != OperationTypeRegisterAsValidator {
		return fmt.Errorf(
			"_disconnectRegisterAsValidator: trying to revert %v but found %v",
			OperationTypeRegisterAsValidator,
			operationData.Type,
		)
	}

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorInvalidValidatorPKID
	}

	// Delete the current ValidatorEntry.
	currentValidatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "_disconnectRegisterAsValidator: ")
	}
	if currentValidatorEntry == nil {
		return fmt.Errorf(
			"_disconnectRegisterAsValidator: no ValidatorEntry found for %v", transactorPKIDEntry.PKID,
		)
	}
	bav._deleteValidatorEntryMappings(currentValidatorEntry)

	// Restore the PrevValidatorEntry, if exists. The PrevValidatorEntry won't exist if this was
	// the first time this ValidatorEntry was created. The PrevValidatorEntry will exist if this
	// was an update operation on an existing ValidatorEntry.
	prevValidatorEntry := operationData.PrevValidatorEntry
	if prevValidatorEntry != nil {
		bav._setValidatorEntryMappings(prevValidatorEntry)
	}

	// TODO: In subsequent PR, if PrevStakeEntries, delete the
	// current StakeEntries and restore the prev StakeEntries.
	// This should also update GlobalStakeAmountNanos.

	// Disconnect the BasicTransfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txHash, utxoOpsForTxn[:operationIndex], blockHeight,
	)
}

func (bav *UtxoView) _connectUnregisterAsValidator(
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
	if txn.TxnMeta.GetTxnType() != TxnTypeUnregisterAsValidator {
		return 0, 0, nil, fmt.Errorf(
			"_connectUnregisterAsValidator: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Connect a basic transfer to get the total input and the
	// total output without considering the txn metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnregisterAsValidator: ")
	}
	if verifySignatures {
		// _connectBasicTransfer has already checked that the txn is signed
		// by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*UnregisterAsValidatorMetadata)

	// Validate the txn metadata.
	if err = bav.IsValidUnregisterAsValidatorMetadata(txn.PublicKey, txMeta); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnregisterAsValidator: ")
	}

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return 0, 0, nil, RuleErrorInvalidValidatorPKID
	}

	// TODO: In subsequent PR, unstake all StakeEntries for this validator.
	// This should also update GlobalStakeAmountNanos.

	// Delete the existing ValidatorEntry.
	prevValidatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnregisterAsValidator: ")
	}
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true.
	if prevValidatorEntry == nil {
		return 0, 0, nil, RuleErrorValidatorNotFound
	}
	bav._deleteValidatorEntryMappings(prevValidatorEntry)

	// Add a UTXO operation.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:               OperationTypeUnregisterAsValidator,
		PrevValidatorEntry: prevValidatorEntry,
		// PrevStakeEntries: prevStakeEntries, // TODO: in subsequent PR
	})
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectUnregisterAsValidator(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// Validate the last operation is an UnregisterAsValidator operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUnregisterAsValidator: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	operationData := utxoOpsForTxn[operationIndex]
	if operationData.Type != OperationTypeUnregisterAsValidator {
		return fmt.Errorf(
			"_disconnectUnregisterAsValidator: trying to revert %v but found %v",
			OperationTypeUnregisterAsValidator,
			operationData.Type,
		)
	}

	// Restore the PrevValidatorEntry.
	prevValidatorEntry := operationData.PrevValidatorEntry
	if prevValidatorEntry == nil {
		// This should never happen as you can only unregister an existing ValidatorEntry
		// when connecting. So disconnecting should always have a PrevValidatorEntry.
		return fmt.Errorf(
			"_disconnectUnregisterAsValidator: no deleted ValidatorEntry found for %v", currentTxn.PublicKey,
		)
	}
	bav._setValidatorEntryMappings(prevValidatorEntry)

	// TODO: In subsequent PR, restore the prev StakeEntries, if any.

	// Disconnect the BasicTransfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txHash, utxoOpsForTxn[:operationIndex], blockHeight,
	)
}

func (bav *UtxoView) IsValidRegisterAsValidatorMetadata(transactorPublicKey []byte, metadata *RegisterAsValidatorMetadata) error {
	// Validate ValidatorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorInvalidValidatorPKID
	}

	// Validate Domains.
	if len(metadata.Domains) < 1 {
		return RuleErrorValidatorNoDomains
	}
	if len(metadata.Domains) > MaxValidatorNumDomains {
		return RuleErrorValidatorTooManyDomains
	}
	var domainStrings []string
	for _, domain := range metadata.Domains {
		_, err := url.ParseRequestURI(string(domain))
		if err != nil {
			return fmt.Errorf("%s: %v", RuleErrorValidatorInvalidDomain, domain)
		}
		domainStrings = append(domainStrings, string(domain))
	}
	if len(NewSet(domainStrings).ToSlice()) != len(domainStrings) {
		return RuleErrorValidatorDuplicateDomains
	}

	// TODO: In subsequent PR, validate VotingPublicKey, VotingPublicKeySignature, and VotingSignatureBlockHeight.
	return nil
}

func (bav *UtxoView) IsValidUnregisterAsValidatorMetadata(transactorPublicKey []byte, metadata *UnregisterAsValidatorMetadata) error {
	// Validate ValidatorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorInvalidValidatorPKID
	}

	// Validate ValidatorEntry exists.
	validatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "IsValidUnregisterAsValidatorMetadata: ")
	}
	if validatorEntry == nil {
		return RuleErrorValidatorNotFound
	}

	return nil
}

func (bav *UtxoView) GetValidatorByPKID(pkid *PKID) (*ValidatorEntry, error) {
	// First check UtxoView.
	validatorEntry, exists := bav.ValidatorMapKeyToValidatorEntry[ValidatorMapKey{ValidatorPKID: *pkid}]
	if exists && validatorEntry != nil {
		// Return not found if ValidatorEntry isDeleted.
		if validatorEntry.isDeleted {
			return nil, nil
		}
		return validatorEntry, nil
	}
	// If not found, check database.
	return DBGetValidatorByPKID(bav.Handle, bav.Snapshot, pkid)
}

func (bav *UtxoView) GetTopValidatorsByStake(limit int) ([]*ValidatorEntry, error) {
	// Validate limit param.
	if limit <= 0 {
		return []*ValidatorEntry{}, nil
	}
	// Create a slice of UtxoViewValidatorEntries. We want to skip pulling these from the database in
	// case they have been updated in the UtxoView and the changes have not yet flushed to the database.
	// Updates to a ValidatorEntry could include adding/removing stake or being deleted which would
	// impact our ordering. We pull N ValidatorEntries not present in the UtxoView from the database
	// then sort the UtxoViewValidatorEntries and DatabaseValidatorEntries together to find the top N
	// ValidatorEntries by stake across both the UtxoView and database.
	var utxoViewValidatorEntries []*ValidatorEntry
	for _, validatorEntry := range bav.ValidatorMapKeyToValidatorEntry {
		utxoViewValidatorEntries = append(utxoViewValidatorEntries, validatorEntry)
	}
	// Pull top N ValidatorEntries from the database (not present in the UtxoView).
	validatorEntries, err := DBGetTopValidatorsByStake(bav.Handle, bav.Snapshot, limit, utxoViewValidatorEntries)
	if err != nil {
		return nil, errors.Wrapf(err, "GetTopValidatorsByStake: error retrieving entries from db: ")
	}
	// Add !isDeleted ValidatorEntries from the UtxoView to the ValidatorEntries from the db.
	for _, validatorEntry := range utxoViewValidatorEntries {
		if !validatorEntry.isDeleted {
			validatorEntries = append(validatorEntries, validatorEntry)
		}
	}
	// Sort the ValidatorEntries DESC by TotalStakeAmountNanos.
	sort.Slice(validatorEntries, func(ii, jj int) bool {
		return validatorEntries[ii].TotalStakeAmountNanos.Cmp(validatorEntries[jj].TotalStakeAmountNanos) > 0
	})
	// Return top N.
	upperBound := int(math.Min(float64(limit), float64(len(validatorEntries))))
	return validatorEntries[0:upperBound], nil
}

func (bav *UtxoView) GetGlobalStakeAmountNanos() (*uint256.Int, error) {
	var globalStakeAmountNanos *uint256.Int
	var err error
	// Read the GlobalStakeAmountNanos from the UtxoView.
	globalStakeAmountNanos = bav.GlobalStakeAmountNanos
	// If not set, read the GlobalStakeAmountNanos from the db.
	if globalStakeAmountNanos == nil || globalStakeAmountNanos.IsZero() {
		globalStakeAmountNanos, err = DBGetGlobalStakeAmountNanos(bav.Handle, bav.Snapshot)
		if err != nil {
			return nil, err
		}
		bav.GlobalStakeAmountNanos = globalStakeAmountNanos
	}
	return globalStakeAmountNanos, nil
}

func (bav *UtxoView) _setValidatorEntryMappings(validatorEntry *ValidatorEntry) {
	// This function shouldn't be called with nil.
	if validatorEntry == nil {
		glog.Errorf("_setValidatorEntryMappings: called with nil entry, this should never happen")
		return
	}
	bav.ValidatorMapKeyToValidatorEntry[validatorEntry.ToMapKey()] = validatorEntry
}

func (bav *UtxoView) _deleteValidatorEntryMappings(validatorEntry *ValidatorEntry) {
	// This function shouldn't be called with nil.
	if validatorEntry == nil {
		glog.Errorf("_deleteValidatorEntryMappings: called with nil entry, this should never happen")
		return
	}
	// Create a tombstone entry.
	tombstoneEntry := *validatorEntry
	tombstoneEntry.isDeleted = true
	// Set the mappings to the point to the tombstone entry.
	bav._setValidatorEntryMappings(&tombstoneEntry)
}

func (bav *UtxoView) _setGlobalStakeAmountNanos(globalStakeAmountNanos *uint256.Int) {
	// This function shouldn't be called with nil.
	if globalStakeAmountNanos == nil {
		glog.Errorf("_setGlobalStakeAmountNanos: called with nil entry, this should never happen")
		return
	}
	bav.GlobalStakeAmountNanos = globalStakeAmountNanos
}

func (bav *UtxoView) _flushValidatorEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Delete all entries in the ValidatorMapKeyToValidatorEntry UtxoView map.
	for validatorMapKeyIter, validatorEntryIter := range bav.ValidatorMapKeyToValidatorEntry {
		// Make a copy of the iterators since we make references to them below.
		validatorMapKey := validatorMapKeyIter
		validatorEntry := *validatorEntryIter

		// Sanity-check that the entry matches the map key.
		validatorMapKeyInEntry := validatorEntry.ToMapKey()
		if validatorMapKeyInEntry != validatorMapKey {
			return fmt.Errorf(
				"_flushValidatorEntriesToDbWithTxn: ValidatorEnry key %v doesn't match MapKey %v",
				&validatorMapKeyInEntry,
				&validatorMapKey,
			)
		}

		// Delete the existing mappings in the db for this ValidatorMapKey. They
		// will be re-added if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteValidatorWithTxn(txn, bav.Snapshot, &validatorEntry); err != nil {
			return errors.Wrapf(err, "_flushValidatorEntriesToDbWithTxn: ")
		}
	}

	// Set any !isDeleted ValidatorEntries in the ValidatorMapKeyToValidatorEntry UtxoView map.
	for _, validatorEntryIter := range bav.ValidatorMapKeyToValidatorEntry {
		validatorEntry := *validatorEntryIter
		if validatorEntry.isDeleted {
			// If ValidatorEntry.isDeleted then there's nothing to
			// do because we already deleted the entry above.
		} else {
			// If !ValidatorEntry.isDeleted then we put the
			// corresponding mappings for it into the db.
			if err := DBPutValidatorWithTxn(txn, bav.Snapshot, &validatorEntry, blockHeight); err != nil {
				return errors.Wrapf(err, "_flushValidatorEntriesToDbWithTxn: ")
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushGlobalStakeAmountNanosToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	return DBPutGlobalStakeAmountNanosWithTxn(txn, bav.Snapshot, bav.GlobalStakeAmountNanos, blockHeight)
}

//
// MEMPOOL UTILS
//

func (bav *UtxoView) CreateRegisterAsValidatorTxindexMetadata(
	utxoOp *UtxoOperation,
	txn *MsgDeSoTxn,
) (
	*RegisterAsValidatorTxindexMetadata,
	[]*AffectedPublicKey,
) {
	metadata := txn.TxnMeta.(*RegisterAsValidatorMetadata)

	// Cast ValidatorPublicKey to ValidatorPublicKeyBase58Check.
	validatorPublicKeyBase58Check := PkToString(txn.PublicKey, bav.Params)

	// Cast domains from []byte to string.
	var domains []string
	for _, domain := range metadata.Domains {
		domains = append(domains, string(domain))
	}

	// TODO: In subsequent PR, pull UnstakedStakers from PrevStakeEntries on UtxoOperation.
	var unstakedStakers []*UnstakedStakerTxindexMetadata

	// Construct TxindexMetadata.
	txindexMetadata := &RegisterAsValidatorTxindexMetadata{
		ValidatorPublicKeyBase58Check: validatorPublicKeyBase58Check,
		Domains:                       domains,
		DisableDelegatedStake:         metadata.DisableDelegatedStake,
		VotingPublicKey:               string(metadata.VotingPublicKey),
		VotingPublicKeySignature:      string(metadata.VotingPublicKeySignature),
		VotingSignatureBlockHeight:    metadata.VotingSignatureBlockHeight,
		UnstakedStakers:               unstakedStakers,
	}

	// Construct AffectedPublicKeys.
	affectedPublicKeys := []*AffectedPublicKey{
		{
			PublicKeyBase58Check: validatorPublicKeyBase58Check,
			Metadata:             "RegisteredValidatorPublicKeyBase58Check",
		},
	}
	for _, unstakedStaker := range unstakedStakers {
		affectedPublicKeys = append(affectedPublicKeys, &AffectedPublicKey{
			PublicKeyBase58Check: unstakedStaker.StakerPublicKeyBase58Check,
			Metadata:             "UnstakedStakerPublicKeyBase58Check",
		})
	}

	return txindexMetadata, affectedPublicKeys
}

func (bav *UtxoView) CreateUnregisterAsValidatorTxindexMetadata(
	utxoOp *UtxoOperation,
	txn *MsgDeSoTxn,
) (
	*UnregisterAsValidatorTxindexMetadata,
	[]*AffectedPublicKey,
) {
	// Cast ValidatorPublicKey to ValidatorPublicKeyBase58Check.
	validatorPublicKeyBase58Check := PkToString(txn.PublicKey, bav.Params)

	// TODO: In subsequent PR, pull UnstakedStakers from PrevStakeEntries on UtxoOperation.
	var unstakedStakers []*UnstakedStakerTxindexMetadata

	// Construct TxindexMetadata.
	txindexMetadata := &UnregisterAsValidatorTxindexMetadata{
		ValidatorPublicKeyBase58Check: validatorPublicKeyBase58Check,
		UnstakedStakers:               unstakedStakers,
	}

	// Construct AffectedPublicKeys.
	affectedPublicKeys := []*AffectedPublicKey{
		{
			PublicKeyBase58Check: validatorPublicKeyBase58Check,
			Metadata:             "UnregisteredValidatorPublicKeyBase58Check",
		},
	}
	for _, unstakedStaker := range unstakedStakers {
		affectedPublicKeys = append(affectedPublicKeys, &AffectedPublicKey{
			PublicKeyBase58Check: unstakedStaker.StakerPublicKeyBase58Check,
			Metadata:             "UnstakedStakerPublicKeyBase58Check",
		})
	}

	return txindexMetadata, affectedPublicKeys
}

//
// CONSTANTS
//

const RuleErrorProofofStakeTxnBeforeBlockHeight RuleError = "RuleErrorProofOfStakeTxnBeforeBlockHeight"
const RuleErrorInvalidValidatorPKID RuleError = "RuleErrorInvalidValidatorPKID"
const RuleErrorValidatorNoDomains RuleError = "RuleErrorValidatorNoDomains"
const RuleErrorValidatorTooManyDomains RuleError = "RuleErrorValidatorTooManyDomains"
const RuleErrorValidatorInvalidDomain RuleError = "RuleErrorValidatorInvalidDomain"
const RuleErrorValidatorDuplicateDomains RuleError = "RuleErrorValidatorDuplicateDomains"
const RuleErrorValidatorNotFound RuleError = "RuleErrorValidatorNotFound"

const MaxValidatorNumDomains int = 12
