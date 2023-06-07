package lib

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"net/url"
	"sort"

	"github.com/deso-protocol/core/bls"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

// RegisterAsValidator: Registers a new validator. This transaction can be called multiple times
// if a validator needs to update any of their registration info such as their domains. Once
// a validator is registered, stake can be assigned to that validator, the validator is eligible
// to participate in consensus by voting, and may be selected as leader to propose new blocks.
//
// UnregisterAsValidator: Unregisters an existing validator. This unstakes all stake assigned to this
// validator and removes this validator from the set of eligible validators. A user would have to
// re-register by submitting a subsequent RegisterAsValidator transaction to be re-included.
//
// UnjailValidator: Unjails a jailed validator if sufficient time (epochs) have elapsed since the
// validator was first jailed. A validator is jailed if they fail to participate in consensus by
// either voting or proposing blocks for too long. A jailed validator is ineligible to receive
// any block rewards and ineligible to elected leader.

//
// TYPES: ValidatorEntry
//

type ValidatorEntry struct {
	// The ValidatorPKID is the primary key for a ValidatorEntry. It is the PKID
	// for the transactor who registered the validator. A user's PKID can only
	// be associated with one validator.
	ValidatorPKID *PKID
	// Domains is a slice of web domains where the validator can be reached.
	// Note: if someone is updating their ValidatorEntry, they need to include
	// all domains. The Domains field is not appended to. It is overwritten.
	Domains [][]byte
	// DisableDelegatedStake is a boolean that indicates whether the validator
	// disallows delegated / 3rd party stake being assigned to themselves. If
	// a validator sets DisableDelegatedStake to true, then they can still
	// stake with themselves, but all other users will receive an error if they
	// try to stake with this validator.
	DisableDelegatedStake bool
	// The VotingPublicKey is a BLS PublicKey that is used in consensus messages.
	// A validator signs consensus messages with their VotingPrivateKey and then
	// other validators can reliably prove the message came from this validator
	// by verifying against their VotingPublicKey.
	VotingPublicKey *bls.PublicKey
	// The VotingPublicKeySignature is the signature of the SHA256(TransactorPublicKey)
	// by the VotingPrivateKey.
	// This proves that this validator is indeed the proper owner of the corresponding
	// VotingPrivateKey. See comment on CreateValidatorVotingSignaturePayload for more details.
	VotingPublicKeySignature *bls.Signature
	// TotalStakeAmountNanos is a cached value of this validator's total stake, calculated
	// by summing all the corresponding StakeEntries assigned to this validator. We cache
	// the value here to avoid the O(N) operation of recomputing when determining a
	// validator's total stake. This way it is an O(1) operation instead.
	TotalStakeAmountNanos *uint256.Int
	// LastActiveAtEpochNumber is the last epoch in which this validator either 1) participated in
	// consensus by voting or proposing blocks, or 2) unjailed themselves. If a validator is
	// inactive for too long, then they are jailed.
	LastActiveAtEpochNumber uint64
	// JailedAtEpochNumber tracks when a validator was first jailed. This helps to verify
	// that enough time (epochs) have passed before the validator is able to unjail themselves.
	JailedAtEpochNumber uint64

	ExtraData map[string][]byte
	isDeleted bool
}

func (validatorEntry *ValidatorEntry) Status() ValidatorStatus {
	// ValidatorEntry.Status() is a virtual/derived field that is not stored in
	// the database, but instead constructed from other ValidatorEntry fields.
	// No sense in storing duplicative data twice. This saves memory and ensures
	// that e.g. the ValidatorEntry.JailedAtEpochNumber field and the
	// ValidatorEntry.Status() return value will never get out of sync.
	//
	// Make sure that any fields referenced here are included in the ValidatorMapKey
	// since the ValidatorEntry.Status() value is used as a field in a Badger index.
	if validatorEntry.JailedAtEpochNumber > uint64(0) {
		return ValidatorStatusJailed
	}
	return ValidatorStatusActive
}

type ValidatorStatus uint8

const (
	ValidatorStatusInvalid ValidatorStatus = 0
	ValidatorStatusActive  ValidatorStatus = 1
	ValidatorStatusJailed  ValidatorStatus = 2
)

func (validatorEntry *ValidatorEntry) Copy() *ValidatorEntry {
	// Copy domains.
	var domainsCopy [][]byte
	for _, domain := range validatorEntry.Domains {
		domainsCopy = append(domainsCopy, append([]byte{}, domain...)) // Makes a copy.
	}

	// Return new ValidatorEntry.
	return &ValidatorEntry{
		ValidatorPKID:            validatorEntry.ValidatorPKID.NewPKID(),
		Domains:                  domainsCopy,
		DisableDelegatedStake:    validatorEntry.DisableDelegatedStake,
		VotingPublicKey:          validatorEntry.VotingPublicKey.Copy(),
		VotingPublicKeySignature: validatorEntry.VotingPublicKeySignature.Copy(),
		TotalStakeAmountNanos:    validatorEntry.TotalStakeAmountNanos.Clone(),
		LastActiveAtEpochNumber:  validatorEntry.LastActiveAtEpochNumber,
		JailedAtEpochNumber:      validatorEntry.JailedAtEpochNumber,
		ExtraData:                copyExtraData(validatorEntry.ExtraData),
		isDeleted:                validatorEntry.isDeleted,
	}
}

func (validatorEntry *ValidatorEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, validatorEntry.ValidatorPKID, skipMetadata...)...)

	// Domains
	data = append(data, UintToBuf(uint64(len(validatorEntry.Domains)))...)
	for _, domain := range validatorEntry.Domains {
		data = append(data, EncodeByteArray(domain)...)
	}

	data = append(data, BoolToByte(validatorEntry.DisableDelegatedStake))
	data = append(data, EncodeBLSPublicKey(validatorEntry.VotingPublicKey)...)
	data = append(data, EncodeBLSSignature(validatorEntry.VotingPublicKeySignature)...)
	data = append(data, VariableEncodeUint256(validatorEntry.TotalStakeAmountNanos)...)
	data = append(data, UintToBuf(validatorEntry.LastActiveAtEpochNumber)...)
	data = append(data, UintToBuf(validatorEntry.JailedAtEpochNumber)...)
	data = append(data, EncodeExtraData(validatorEntry.ExtraData)...)
	return data
}

func (validatorEntry *ValidatorEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// ValidatorPKID
	validatorEntry.ValidatorPKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
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
	validatorEntry.VotingPublicKey, err = DecodeBLSPublicKey(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading VotingPublicKey: ")
	}

	// VotingPublicKeySignature
	validatorEntry.VotingPublicKeySignature, err = DecodeBLSSignature(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading VotingPublicKeySignature: ")
	}

	// TotalStakeAmountNanos
	validatorEntry.TotalStakeAmountNanos, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading TotalStakeAmountNanos: ")
	}

	// LastActiveAtEpochNumber
	validatorEntry.LastActiveAtEpochNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading LastActiveAtEpochNumber: ")
	}

	// JailedAtEpochNumber
	validatorEntry.JailedAtEpochNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading JailedAtEpochNumber: ")
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
	Domains                  [][]byte
	DisableDelegatedStake    bool
	VotingPublicKey          *bls.PublicKey
	VotingPublicKeySignature *bls.Signature
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
	data = append(data, EncodeBLSPublicKey(txnData.VotingPublicKey)...)
	data = append(data, EncodeBLSSignature(txnData.VotingPublicKeySignature)...)
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
	txnData.VotingPublicKey, err = DecodeBLSPublicKey(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorMetadata.FromBytes: Problem reading VotingPublicKey: ")
	}

	// VotingPublicKeySignature
	txnData.VotingPublicKeySignature, err = DecodeBLSSignature(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterAsValidatorMetadata.FromBytes: Problem reading VotingPublicKeySignature: ")
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
// TYPES: UnjailValidatorMetadata
//

type UnjailValidatorMetadata struct{}

func (txnData *UnjailValidatorMetadata) GetTxnType() TxnType {
	return TxnTypeUnjailValidator
}

func (txnData *UnjailValidatorMetadata) ToBytes(preSignature bool) ([]byte, error) {
	return []byte{}, nil
}

func (txnData *UnjailValidatorMetadata) FromBytes(data []byte) error {
	return nil
}

func (txnData *UnjailValidatorMetadata) New() DeSoTxnMetadata {
	return &UnjailValidatorMetadata{}
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
	data = append(data, VariableEncodeUint256(txindexMetadata.UnstakeAmountNanos)...)
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
	txindexMetadata.UnstakeAmountNanos, err = VariableDecodeUint256(rr)
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
// TYPES: UnjailValidatorTxindexMetadata
//

type UnjailValidatorTxindexMetadata struct {
}

func (txindexMetadata *UnjailValidatorTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	return []byte{}
}

func (txindexMetadata *UnjailValidatorTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	return nil
}

func (txindexMetadata *UnjailValidatorTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txindexMetadata *UnjailValidatorTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeUnjailValidatorTxindexMetadata
}

//
// DB UTILS
//

func DBKeyForValidatorByPKID(validatorEntry *ValidatorEntry) []byte {
	key := append([]byte{}, Prefixes.PrefixValidatorByPKID...)
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBKeyForValidatorByStake(validatorEntry *ValidatorEntry) []byte {
	key := append([]byte{}, Prefixes.PrefixValidatorByStatusAndStake...)
	key = append(key, EncodeUint8(uint8(validatorEntry.Status()))...)
	key = append(key, FixedWidthEncodeUint256(validatorEntry.TotalStakeAmountNanos)...)
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBKeyForGlobalActiveStakeAmountNanos() []byte {
	return append([]byte{}, Prefixes.PrefixGlobalActiveStakeAmountNanos...)
}

func DBGetValidatorByPKID(handle *badger.DB, snap *Snapshot, pkid *PKID) (*ValidatorEntry, error) {
	var ret *ValidatorEntry
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetValidatorByPKIDWithTxn(txn, snap, pkid)
		return innerErr
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

func DBGetTopActiveValidatorsByStake(
	handle *badger.DB,
	snap *Snapshot,
	limit uint64,
	validatorEntriesToSkip []*ValidatorEntry,
) ([]*ValidatorEntry, error) {
	var validatorEntries []*ValidatorEntry

	// Convert ValidatorEntriesToSkip to ValidatorEntryKeysToSkip.
	validatorKeysToSkip := NewSet([]string{})
	for _, validatorEntryToSkip := range validatorEntriesToSkip {
		validatorKeysToSkip.Add(string(DBKeyForValidatorByStake(validatorEntryToSkip)))
	}

	// Retrieve top N active ValidatorEntry keys by stake.
	key := append([]byte{}, Prefixes.PrefixValidatorByStatusAndStake...)
	key = append(key, EncodeUint8(uint8(ValidatorStatusActive))...)
	keysFound, _, err := EnumerateKeysForPrefixWithLimitOffsetOrder(
		handle, key, int(limit), nil, true, validatorKeysToSkip,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetTopActiveValidatorsByStake: problem retrieving top validators: ")
	}

	// For each key found, parse the ValidatorPKID from the key,
	// then retrieve the ValidatorEntry by the ValidatorPKID.
	for _, keyFound := range keysFound {
		// Parse the PKIDBytes from the key. The ValidatorPKID is the last component of the key.
		validatorPKIDBytes := keyFound[len(keyFound)-PublicKeyLenCompressed:]
		// Convert PKIDBytes to PKID.
		validatorPKID := &PKID{}
		if err = validatorPKID.FromBytes(bytes.NewReader(validatorPKIDBytes)); err != nil {
			return nil, errors.Wrapf(err, "DBGetTopActiveValidatorsByStake: problem reading ValidatorPKID: ")
		}
		// Retrieve ValidatorEntry by PKID.
		validatorEntry, err := DBGetValidatorByPKID(handle, snap, validatorPKID)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetTopActiveValidatorsByStake: problem retrieving validator by PKID: ")
		}
		validatorEntries = append(validatorEntries, validatorEntry)
	}

	return validatorEntries, nil
}

func DBGetGlobalActiveStakeAmountNanos(handle *badger.DB, snap *Snapshot) (*uint256.Int, error) {
	var ret *uint256.Int
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetGlobalActiveStakeAmountNanosWithTxn(txn, snap)
		return innerErr
	})
	return ret, err
}

func DBGetGlobalActiveStakeAmountNanosWithTxn(txn *badger.Txn, snap *Snapshot) (*uint256.Int, error) {
	// Retrieve from db.
	key := DBKeyForGlobalActiveStakeAmountNanos()
	globalActiveStakeAmountNanosBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetGlobalActiveStakeAmountNanosWithTxn: problem retrieving value")
	}

	// Decode from bytes.
	var globalActiveStakeAmountNanos *uint256.Int
	rr := bytes.NewReader(globalActiveStakeAmountNanosBytes)
	globalActiveStakeAmountNanos, err = VariableDecodeUint256(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetGlobalActiveStakeAmountNanosWithTxn: problem decoding value")
	}
	return globalActiveStakeAmountNanos, nil
}

func DBPutValidatorWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorEntry *ValidatorEntry,
	blockHeight uint64,
) error {
	if validatorEntry == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutValidatorWithTxn: called with nil ValidatorEntry")
		return nil
	}

	// Set ValidatorEntry in PrefixValidatorByPKID.
	key := DBKeyForValidatorByPKID(validatorEntry)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorEntry)); err != nil {
		return errors.Wrapf(
			err, "DBPutValidatorWithTxn: problem storing ValidatorEntry in index PrefixValidatorByPKID",
		)
	}

	// Set ValidatorEntry key in PrefixValidatorByStatusAndStake. The value should be nil.
	// We parse the ValidatorPKID from the key for this index.
	key = DBKeyForValidatorByStake(validatorEntry)
	if err := DBSetWithTxn(txn, snap, key, nil); err != nil {
		return errors.Wrapf(
			err, "DBPutValidatorWithTxn: problem storing ValidatorEntry in index PrefixValidatorByStatusAndStake",
		)
	}

	return nil
}

func DBDeleteValidatorWithTxn(txn *badger.Txn, snap *Snapshot, validatorPKID *PKID) error {
	if validatorPKID == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBDeleteValidatorWithTxn: called with nil ValidatorPKID")
		return nil
	}

	// Look up the existing ValidatorEntry in the db using the PKID. We need to use this
	// validator's values to delete the corresponding indexes.
	validatorEntry, err := DBGetValidatorByPKIDWithTxn(txn, snap, validatorPKID)
	if err != nil {
		return errors.Wrapf(err, "DBDeleteValidatorWithTxn: problem retrieving "+
			"ValidatorEntry for PKID %v: ", validatorPKID)
	}

	// If there is no ValidatorEntry in the DB for this PKID, then there is nothing to
	// delete.
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

	// Delete ValidatorEntry.PKID from PrefixValidatorByStatusAndStake.
	key = DBKeyForValidatorByStake(validatorEntry)
	if err := DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(
			err, "DBDeleteValidatorWithTxn: problem deleting ValidatorEntry from index PrefixValidatorByStatusAndStake",
		)
	}

	return nil
}

func DBPutGlobalActiveStakeAmountNanosWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	globalActiveStakeAmountNanos *uint256.Int,
	blockHeight uint64,
) error {
	if globalActiveStakeAmountNanos == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutGlobalActiveStakeAmountNanosWithTxn: called with nil GlobalActiveStakeAmountNanos")
		return nil
	}
	key := DBKeyForGlobalActiveStakeAmountNanos()
	return DBSetWithTxn(txn, snap, key, VariableEncodeUint256(globalActiveStakeAmountNanos))
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
	blockHeight := uint64(bc.blockTip().Height) + 1
	if err = utxoView.IsValidRegisterAsValidatorMetadata(transactorPublicKey, metadata, blockHeight); err != nil {
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
	if len(txn.TxInputs) == 0 && bc.blockTip().Height+1 < bc.params.ForkHeights.BalanceModelBlockHeight {
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
			err, "Blockchain.CreateUnregisterAsValidatorTxn: problem creating new utxo view: ",
		)
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(
				err, "Blockchain.CreateUnregisterAsValidatorTxn: problem getting augmented utxo view from mempool: ",
			)
		}
	}

	// Validate txn metadata.
	if err = utxoView.IsValidUnregisterAsValidatorMetadata(transactorPublicKey); err != nil {
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
	if len(txn.TxInputs) == 0 && bc.blockTip().Height+1 < bc.params.ForkHeights.BalanceModelBlockHeight {
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

func (bc *Blockchain) CreateUnjailValidatorTxn(
	transactorPublicKey []byte,
	metadata *UnjailValidatorMetadata,
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
	// Create a txn containing the UnjailValidator fields.
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
			err, "Blockchain.CreateUnjailValidatorTxn: problem creating new utxo view: ",
		)
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(
				err, "Blockchain.CreateUnjailValidatorTxn: problem getting augmented utxo view from mempool: ",
			)
		}
	}

	// Validate txn metadata.
	if err = utxoView.IsValidUnjailValidatorMetadata(transactorPublicKey); err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateUnjailValidatorTxn: invalid txn metadata: ",
		)
	}

	// We don't need to make any tweaks to the amount because
	// it's basically a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err := bc.AddInputsAndChangeToTransaction(
		txn, minFeeRateNanosPerKB, mempool,
	)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateUnjailValidatorTxn: problem adding inputs: ",
		)
	}

	// Validate that the transaction has at least one input, even if it all goes
	// to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 && bc.blockTip().Height+1 < bc.params.ForkHeights.BalanceModelBlockHeight {
		return nil, 0, 0, 0, errors.New(
			"Blockchain.CreateUnjailValidatorTxn: txn has zero inputs, try increasing the fee rate",
		)
	}

	// Sanity-check that the spendAmount is zero.
	if spendAmount != 0 {
		return nil, 0, 0, 0, fmt.Errorf(
			"Blockchain.CreateUnjailValidatorTxn: spend amount is non-zero: %d", spendAmount,
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
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight {
		return 0, 0, nil, errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_connectRegisterAsValidator: ")
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
	if err = bav.IsValidRegisterAsValidatorMetadata(txn.PublicKey, txMeta, uint64(blockHeight)); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectRegisterAsValidator: ")
	}

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidValidatorPKID, "_connectRegisterAsValidator: ")
	}

	// Check if there is an existing ValidatorEntry that will be overwritten.
	// The existing ValidatorEntry will be restored if we disconnect this transaction.
	prevValidatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectRegisterAsValidator: ")
	}
	// Delete the existing ValidatorEntry, if exists. There will be an existing ValidatorEntry
	// if the transactor is updating their ValidatorEntry. There will not be one if the transactor
	// is registering a ValidatorEntry for the first time (or it was previously unregistered).
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true.
	if prevValidatorEntry != nil {
		bav._deleteValidatorEntryMappings(prevValidatorEntry)
	}

	// Calculate TotalStakeAmountNanos.
	totalStakeAmountNanos := uint256.NewInt()
	if prevValidatorEntry != nil {
		totalStakeAmountNanos = prevValidatorEntry.TotalStakeAmountNanos.Clone()
	}

	// Set LastActiveAtEpochNumber to CurrentEpochNumber if this is a new ValidatorEntry.
	// Otherwise, retain the existing LastActiveAtEpochNumber.
	var lastActiveAtEpochNumber uint64
	if prevValidatorEntry != nil {
		// Retain the existing LastActiveAtEpochNumber.
		lastActiveAtEpochNumber = prevValidatorEntry.LastActiveAtEpochNumber
	} else {
		// Retrieve the CurrentEpochNumber.
		currentEpochNumber, err := bav.GetCurrentEpochNumber()
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectRegisterAsValidator: error retrieving CurrentEpochNumber: ")
		}
		// Set LastActiveAtEpochNumber to CurrentEpochNumber.
		lastActiveAtEpochNumber = currentEpochNumber
	}

	// Set JailedAtEpochNumber to zero if this is a new ValidatorEntry.
	// Otherwise, retain the existing JailedAtEpochNumber.
	jailedAtEpochNumber := uint64(0)
	if prevValidatorEntry != nil {
		jailedAtEpochNumber = prevValidatorEntry.JailedAtEpochNumber
	}

	// Retrieve existing ExtraData to merge with any new ExtraData.
	var prevExtraData map[string][]byte
	if prevValidatorEntry != nil {
		prevExtraData = prevValidatorEntry.ExtraData
	}

	// Construct new ValidatorEntry from metadata.
	currentValidatorEntry := &ValidatorEntry{
		ValidatorPKID: transactorPKIDEntry.PKID,
		// Note: if someone is updating their ValidatorEntry, they need to include
		// all domains. The Domains field is not appended to. It is overwritten.
		Domains:                  txMeta.Domains,
		DisableDelegatedStake:    txMeta.DisableDelegatedStake,
		VotingPublicKey:          txMeta.VotingPublicKey,
		VotingPublicKeySignature: txMeta.VotingPublicKeySignature,
		TotalStakeAmountNanos:    totalStakeAmountNanos,
		LastActiveAtEpochNumber:  lastActiveAtEpochNumber,
		JailedAtEpochNumber:      jailedAtEpochNumber,
		ExtraData:                mergeExtraData(prevExtraData, txn.ExtraData),
	}
	// Set the ValidatorEntry.
	bav._setValidatorEntryMappings(currentValidatorEntry)

	// Add a UTXO operation
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:               OperationTypeRegisterAsValidator,
		PrevValidatorEntry: prevValidatorEntry,
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
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight {
		return errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_disconnectRegisterAsValidator: ")
	}

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
		return errors.Wrapf(RuleErrorInvalidValidatorPKID, "_disconnectRegisterAsValidator: ")
	}

	// Delete the current ValidatorEntry.
	currentValidatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "_disconnectRegisterAsValidator: ")
	}
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true.
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
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight {
		return 0, 0, nil, errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_connectUnregisterAsValidator: ")
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

	// Validate the transactor.
	if err = bav.IsValidUnregisterAsValidatorMetadata(txn.PublicKey); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnregisterAsValidator: ")
	}

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidValidatorPKID, "_connectUnregisterAsValidator: ")
	}

	// Retrieve PrevStakeEntries for this ValidatorPKID.
	prevStakeEntries, err := bav.GetStakeEntriesForValidatorPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnregisterAsValidator: error retrieving StakeEntries: ")
	}

	// Retrieve the CurrentEpochNumber.
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnregisterAsValidator: error retrieving CurrentEpochNumber: ")
	}

	// Delete each StakeEntry and create or update the corresponding LockedStakeEntry.
	// Track TotalUnstakedAmountNanos and PrevLockedStakeEntries.
	totalUnstakedAmountNanos := uint256.NewInt()
	var prevLockedStakeEntries []*LockedStakeEntry

	for _, prevStakeEntry := range prevStakeEntries {
		// Add the UnstakedAmountNanos to the TotalUnstakedAmountNanos.
		totalUnstakedAmountNanos, err = SafeUint256().Add(
			totalUnstakedAmountNanos, prevStakeEntry.StakeAmountNanos,
		)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(
				err, "_connectUnregisterAsValidator: error adding UnstakedAmountNanos to TotalUnstakedAmountNanos: ",
			)
		}

		// Retrieve the existing LockedStakeEntry, if exists.
		prevLockedStakeEntry, err := bav.GetLockedStakeEntry(
			prevStakeEntry.ValidatorPKID, prevStakeEntry.StakerPKID, currentEpochNumber,
		)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(
				err, "_connectUnregisterAsValidator: error retrieving LockedStakeEntry: ",
			)
		}

		// Copy the existing LockedStakeEntry and update the LockedAmountNanos, if exists.
		// Create a new LockedStakeEntry with the unstaked LockedAmountNanos, otherwise.
		var lockedStakeEntry *LockedStakeEntry

		if prevLockedStakeEntry != nil {
			prevLockedStakeEntries = append(prevLockedStakeEntries, prevLockedStakeEntry)
			lockedStakeEntry = prevLockedStakeEntry.Copy()
			lockedStakeEntry.LockedAmountNanos, err = SafeUint256().Add(
				lockedStakeEntry.LockedAmountNanos, prevStakeEntry.StakeAmountNanos,
			)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(
					err, "_connectUnregisterAsValidator: error adding LockedStakeEntry.LockedAmountNanos: ",
				)
			}
		} else {
			lockedStakeEntry = &LockedStakeEntry{
				StakerPKID:          prevStakeEntry.StakerPKID.NewPKID(),
				ValidatorPKID:       prevStakeEntry.ValidatorPKID.NewPKID(),
				LockedAmountNanos:   prevStakeEntry.StakeAmountNanos.Clone(),
				LockedAtEpochNumber: currentEpochNumber,
			}
		}

		// Delete the PrevStakeEntry.
		bav._deleteStakeEntryMappings(prevStakeEntry)

		// Delete the PrevLockedStakeEntry, if exists.
		if prevLockedStakeEntry != nil {
			bav._deleteLockedStakeEntryMappings(prevLockedStakeEntry)
		}

		// Set the new LockedStakeEntry.
		bav._setLockedStakeEntryMappings(lockedStakeEntry)
	}

	// Delete the existing ValidatorEntry.
	prevValidatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnregisterAsValidator: ")
	}
	if prevValidatorEntry == nil || prevValidatorEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(RuleErrorValidatorNotFound, "_connectUnregisterAsValidator: ")
	}
	bav._deleteValidatorEntryMappings(prevValidatorEntry)

	// Sanity check that TotalUnstakedAmountNanos == PrevValidatorEntry.TotalStakedAmountNanos.
	if !totalUnstakedAmountNanos.Eq(prevValidatorEntry.TotalStakeAmountNanos) {
		return 0, 0, nil, errors.New(
			"_connectUnregisterAsValidator: TotalUnstakedAmountNanos does not match ValidatorEntry.TotalStakedAmountNanos: ",
		)
	}

	// If the validator was active, decrease the GlobalActiveStakeAmountNanos
	// by the amount that was unstaked. Do nothing if the validator was jailed.
	var prevGlobalActiveStakeAmountNanos *uint256.Int
	if prevValidatorEntry.Status() == ValidatorStatusActive {
		// Fetch the existing GlobalActiveStakeAmountNanos.
		prevGlobalActiveStakeAmountNanos, err = bav.GetGlobalActiveStakeAmountNanos()
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectUnregisterAsValidator: error fetching GlobalActiveStakeAmountNanos: ")
		}
		// Subtract the amount that was unstaked.
		globalActiveStakeAmountNanos, err := SafeUint256().Sub(
			prevGlobalActiveStakeAmountNanos, totalUnstakedAmountNanos,
		)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(
				err, "_connectUnregisterAsValidator: error subtracting TotalUnstakedAmountNanos from GlobalActiveStakeAmountNanos: ",
			)
		}
		// Set the new GlobalActiveStakeAmountNanos.
		bav._setGlobalActiveStakeAmountNanos(globalActiveStakeAmountNanos)
	}

	// Create a UTXO operation.
	utxoOpForTxn := &UtxoOperation{
		Type:                             OperationTypeUnregisterAsValidator,
		PrevValidatorEntry:               prevValidatorEntry,
		PrevGlobalActiveStakeAmountNanos: prevGlobalActiveStakeAmountNanos,
		PrevStakeEntries:                 prevStakeEntries,
		PrevLockedStakeEntries:           prevLockedStakeEntries,
	}
	if err = bav.SanityCheckUnregisterAsValidatorTxn(transactorPKIDEntry.PKID, utxoOpForTxn, totalUnstakedAmountNanos); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnregisterAsValidator: ")
	}
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpForTxn)
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectUnregisterAsValidator(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight {
		return errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_disconnectUnregisterAsValidator: ")
	}

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

	// Restore the PrevValidatorEntry. This must always exist.
	prevValidatorEntry := operationData.PrevValidatorEntry
	if prevValidatorEntry == nil {
		// This should never happen as you can only unregister an existing ValidatorEntry
		// when connecting. So disconnecting should always have a PrevValidatorEntry.
		return fmt.Errorf(
			"_disconnectUnregisterAsValidator: no deleted ValidatorEntry found for %v", currentTxn.PublicKey,
		)
	}
	bav._setValidatorEntryMappings(prevValidatorEntry)

	// Restore the PrevStakeEntries, if any.
	for _, prevStakeEntry := range operationData.PrevStakeEntries {
		// Delete the CurrentStakeEntry.
		currentStakeEntry, err := bav.GetStakeEntry(prevStakeEntry.ValidatorPKID, prevStakeEntry.StakerPKID)
		if err != nil {
			return errors.Wrapf(err, "_disconnectUnregisterAsValidator: error retrieving CurrentStakeEntry: ")
		}
		bav._deleteStakeEntryMappings(currentStakeEntry)

		// Set the PrevStakeEntry.
		bav._setStakeEntryMappings(prevStakeEntry)
	}

	// Retrieve the CurrentEpochNumber.
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return errors.Wrapf(err, "_disconnectUnregisterAsValidator: error retrieving CurrentEpochNumber: ")
	}

	// Restore the PrevLockedStakeEntries, if any.
	for _, prevLockedStakeEntry := range operationData.PrevLockedStakeEntries {
		// Delete the CurrentLockedStakeEntry.
		currentLockedStakeEntry, err := bav.GetLockedStakeEntry(
			prevLockedStakeEntry.ValidatorPKID, prevLockedStakeEntry.StakerPKID, currentEpochNumber,
		)
		if err != nil {
			return errors.Wrapf(err, "_disconnectUnregisterAsValidator: error retrieving CurrentLockedStakeEntry: ")
		}
		bav._deleteLockedStakeEntryMappings(currentLockedStakeEntry)

		// Set the PrevLockedStakeEntry.
		bav._setLockedStakeEntryMappings(prevLockedStakeEntry)
	}

	// Restore the PrevGlobalActiveStakeAmountNanos, if exists.
	if operationData.PrevGlobalActiveStakeAmountNanos != nil {
		bav._setGlobalActiveStakeAmountNanos(operationData.PrevGlobalActiveStakeAmountNanos)
	}

	// Disconnect the BasicTransfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txHash, utxoOpsForTxn[:operationIndex], blockHeight,
	)
}

func (bav *UtxoView) _connectUnjailValidator(
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
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight {
		return 0, 0, nil, errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_connectUnjailValidator: ")
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeUnjailValidator {
		return 0, 0, nil, fmt.Errorf(
			"_connectUnjailValidator: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Connect a basic transfer to get the total input and the
	// total output without considering the txn metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnjailValidator: ")
	}
	if verifySignatures {
		// _connectBasicTransfer has already checked that the txn is signed
		// by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// Validate the transactor.
	if err = bav.IsValidUnjailValidatorMetadata(txn.PublicKey); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnjailValidator: ")
	}

	// At this point, we have validated in IsValidUnjailValidatorMetadata()
	// that the ValidatorEntry exists, belongs to the transactor, is jailed,
	// and a sufficient number of epochs have elapsed for this validator to
	// be unjailed.

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidValidatorPKID, "_connectUnjailValidator: ")
	}

	// Retrieve the existing ValidatorEntry that will be overwritten.
	// This ValidatorEntry will be restored if we disconnect this txn.
	prevValidatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnjailValidator: ")
	}
	if prevValidatorEntry == nil || prevValidatorEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(RuleErrorValidatorNotFound, "_connectUnjailValidator: ")
	}

	// Copy the existing ValidatorEntry.
	currentValidatorEntry := prevValidatorEntry.Copy()

	// Retrieve the CurrentEpochNumber.
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnjailValidator: error retrieving CurrentEpochNumber: ")
	}

	// Update LastActiveAtEpochNumber to CurrentEpochNumber.
	currentValidatorEntry.LastActiveAtEpochNumber = currentEpochNumber

	// Reset JailedAtEpochNumber to zero.
	currentValidatorEntry.JailedAtEpochNumber = 0

	// Merge ExtraData with existing ExtraData.
	currentValidatorEntry.ExtraData = mergeExtraData(prevValidatorEntry.ExtraData, txn.ExtraData)

	// Delete the PrevValidatorEntry.
	bav._deleteValidatorEntryMappings(prevValidatorEntry)

	// Set the CurrentValidatorEntry.
	bav._setValidatorEntryMappings(currentValidatorEntry)

	// Increase the GlobalActiveStakeAmountNanos.
	prevGlobalActiveStakeAmountNanos, err := bav.GetGlobalActiveStakeAmountNanos()
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnjailValidator: error retrieving existing GlobalActiveStakeAmountNanos: ")
	}
	currentGlobalActiveStakeAmountNanos, err := SafeUint256().Add(
		prevGlobalActiveStakeAmountNanos, currentValidatorEntry.TotalStakeAmountNanos,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnjailValidator: error calculating updated GlobalActiveStakeAmountNanos ")
	}
	bav._setGlobalActiveStakeAmountNanos(currentGlobalActiveStakeAmountNanos)

	// Add a UTXO operation
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                             OperationTypeUnjailValidator,
		PrevValidatorEntry:               prevValidatorEntry,
		PrevGlobalActiveStakeAmountNanos: prevGlobalActiveStakeAmountNanos,
	})
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectUnjailValidator(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight {
		return errors.Wrapf(RuleErrorProofofStakeTxnBeforeBlockHeight, "_disconnectUnjailValidator: ")
	}

	// Validate the last operation is an UnjailValidator operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUnjailValidator: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	operationData := utxoOpsForTxn[operationIndex]
	if operationData.Type != OperationTypeUnjailValidator {
		return fmt.Errorf(
			"_disconnectUnjailValidator: trying to revert %v but found %v",
			OperationTypeUnjailValidator,
			operationData.Type,
		)
	}

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return errors.Wrapf(RuleErrorInvalidValidatorPKID, "_disconnectUnjailValidator: ")
	}

	// Delete the current ValidatorEntry.
	currentValidatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "_disconnectUnjailValidator: ")
	}
	if currentValidatorEntry == nil || currentValidatorEntry.isDeleted {
		return errors.Wrapf(RuleErrorValidatorNotFound, "_disconnectUnjailValidator: ")
	}
	bav._deleteValidatorEntryMappings(currentValidatorEntry)

	// Restore the PrevValidatorEntry.
	prevValidatorEntry := operationData.PrevValidatorEntry
	if prevValidatorEntry == nil {
		return errors.New("_disconnectUnjailValidator: PrevValidatorEntry is nil")
	}
	bav._setValidatorEntryMappings(prevValidatorEntry)

	// Restore the PrevGlobalActiveStakeAmountNanos.
	prevGlobalActiveStakeAmountNanos := operationData.PrevGlobalActiveStakeAmountNanos
	if prevGlobalActiveStakeAmountNanos == nil {
		return errors.New("_disconnectUnjailValidator: PrevGlobalActiveStakeAmountNanos is nil, this should never happen")
	}
	bav._setGlobalActiveStakeAmountNanos(prevGlobalActiveStakeAmountNanos)

	// Disconnect the BasicTransfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txHash, utxoOpsForTxn[:operationIndex], blockHeight,
	)
}

func (bav *UtxoView) IsValidRegisterAsValidatorMetadata(
	transactorPublicKey []byte,
	metadata *RegisterAsValidatorMetadata,
	blockHeight uint64,
) error {
	// Validate ValidatorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView.IsValidRegisterAsValidatorMetadata: ")
	}

	// Validate Domains.
	if len(metadata.Domains) < 1 {
		return errors.Wrapf(RuleErrorValidatorNoDomains, "UtxoView.IsValidRegisterAsValidatorMetadata: ")
	}
	if len(metadata.Domains) > MaxValidatorNumDomains {
		return errors.Wrapf(RuleErrorValidatorTooManyDomains, "UtxoView.IsValidRegisterAsValidatorMetadata: ")
	}
	var domainStrings []string
	for _, domain := range metadata.Domains {
		_, err := url.ParseRequestURI(string(domain))
		if err != nil {
			return fmt.Errorf("UtxoView.IsValidRegisterAsValidatorMetadata: %s: %v", RuleErrorValidatorInvalidDomain, domain)
		}
		domainStrings = append(domainStrings, string(domain))
	}
	if len(NewSet(domainStrings).ToSlice()) != len(domainStrings) {
		return errors.Wrapf(RuleErrorValidatorDuplicateDomains, "UtxoView.IsValidRegisterAsValidatorMetadata: ")
	}

	// Validate VotingPublicKey.
	if metadata.VotingPublicKey == nil {
		return errors.Wrapf(RuleErrorValidatorMissingVotingPublicKey, "UtxoView.IsValidRegisterAsValidatorMetadata: ")
	}

	// Validate VotingPublicKeySignature.
	if metadata.VotingPublicKeySignature == nil {
		return errors.Wrapf(RuleErrorValidatorMissingVotingPublicKeySignature, "UtxoView.IsValidRegisterAsValidatorMetadata: ")
	}
	votingSignaturePayload := CreateValidatorVotingSignaturePayload(transactorPublicKey)
	isValidBLSSignature, err := metadata.VotingPublicKey.Verify(metadata.VotingPublicKeySignature, votingSignaturePayload)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidRegisterAsValidatorMetadata: error verifying VotingPublicKeySignature: ")
	}
	if !isValidBLSSignature {
		return errors.Wrapf(RuleErrorValidatorInvalidVotingPublicKeySignature, "UtxoView.IsValidRegisterAsValidatorMetadata: ")
	}

	// Error if updating DisableDelegatedStake from false to
	// true and there are existing delegated StakeEntries.
	validatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidRegisterAsValidatorMetadata: error retrieving existing ValidatorEntry: ")
	}
	if validatorEntry != nil && // ValidatorEntry exists
		!validatorEntry.DisableDelegatedStake && // Existing ValidatorEntry.DisableDelegatedStake = false
		metadata.DisableDelegatedStake { // Updating DisableDelegatedStake = true

		hasDelegatedStake, err := bav.ValidatorHasDelegatedStake(transactorPKIDEntry.PKID)
		if err != nil {
			return errors.Wrapf(err, "UtxoView.IsValidRegisterAsValidatorMetadata: error checking for existing delegated StakeEntries: ")
		}
		if hasDelegatedStake {
			return errors.Wrapf(
				RuleErrorValidatorDisablingExistingDelegatedStakers, "UtxoView.IsValidRegisterAsValidatorMetadata: ",
			)
		}
	}

	return nil
}

func (bav *UtxoView) IsValidUnregisterAsValidatorMetadata(transactorPublicKey []byte) error {
	// Validate ValidatorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView.IsValidUnregisterAsValidatorMetadata: ")
	}

	// Validate ValidatorEntry exists.
	validatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidUnregisterAsValidatorMetadata: ")
	}
	if validatorEntry == nil || validatorEntry.isDeleted {
		return errors.Wrapf(RuleErrorValidatorNotFound, "UtxoView.IsValidUnregisterAsValidatorMetadata: ")
	}

	return nil
}

func (bav *UtxoView) IsValidUnjailValidatorMetadata(transactorPublicKey []byte) error {
	// Validate ValidatorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView.IsValidUnjailValidatorMetadata: ")
	}

	// Validate ValidatorEntry exists.
	validatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidUnjailValidatorMetadata: ")
	}
	if validatorEntry == nil || validatorEntry.isDeleted {
		return errors.Wrapf(RuleErrorValidatorNotFound, "UtxoView.IsValidUnjailValidatorMetadata: ")
	}

	// Validate ValidatorEntry is jailed.
	if validatorEntry.Status() != ValidatorStatusJailed {
		return errors.Wrapf(RuleErrorUnjailingNonjailedValidator, "UtxoView.IsValidUnjailValidatorMetadata: ")
	}

	// Retrieve CurrentEpochNumber.
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidUnjailValidatorMetadata: error retrieving CurrentEpochNumber: ")
	}

	// Retrieve the SnapshotGlobalParam: ValidatorJailEpochDuration.
	validatorJailEpochDuration, err := bav.GetSnapshotGlobalParam(ValidatorJailEpochDuration)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidUnjailValidatorMetadata: error retrieving snapshot ValidatorJailEpochDuration: ")
	}

	// Calculate UnjailableAtEpochNumber.
	unjailableAtEpochNumber, err := SafeUint64().Add(validatorEntry.JailedAtEpochNumber, validatorJailEpochDuration)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.IsValidUnjailValidatorMetadata: error calculating UnjailableAtEpochNumber: ")
	}

	// Validate sufficient epochs have elapsed for validator to be unjailed.
	if unjailableAtEpochNumber > currentEpochNumber {
		return errors.Wrapf(RuleErrorUnjailingValidatorTooEarly, "UtxoView.IsValidUnjailValidatorMetadata: ")
	}

	return nil
}

func (bav *UtxoView) SanityCheckUnregisterAsValidatorTxn(
	transactorPKID *PKID,
	utxoOp *UtxoOperation,
	amountNanos *uint256.Int,
) error {
	if utxoOp.Type != OperationTypeUnregisterAsValidator {
		return fmt.Errorf("SanityCheckUnregisterAsValidatorTxn: called with %v", utxoOp.Type)
	}

	// Sanity check the deleted ValidatorEntry.
	if utxoOp.PrevValidatorEntry == nil {
		return errors.New("SanityCheckUnregisterAsValidatorTxn: nil PrevValidatorEntry provided")
	}
	if !utxoOp.PrevValidatorEntry.ValidatorPKID.Eq(transactorPKID) {
		return errors.New("SanityCheckUnregisterAsValidatorTxn: ValidatorPKID doesn't match TransactorPKID")
	}
	if !utxoOp.PrevValidatorEntry.TotalStakeAmountNanos.Eq(amountNanos) {
		return errors.New("SanityCheckUnregisterAsValidatorTxn: TotalStakeAmountNanos doesn't match")
	}
	currentValidatorEntry, err := bav.GetValidatorByPKID(utxoOp.PrevValidatorEntry.ValidatorPKID)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnregisterAsValidatorTxn: error retrieving ValidatorEntry: ")
	}
	if currentValidatorEntry != nil {
		return errors.New("SanityCheckUnregisterAsValidatorTxn: ValidatorEntry was not deleted")
	}

	// Sanity check that there are no existing StakeEntries for the validator.
	stakeEntries, err := bav.GetStakeEntriesForValidatorPKID(utxoOp.PrevValidatorEntry.ValidatorPKID)
	if err != nil {
		return errors.Wrapf(err, "SanityCheckUnregisterAsValidatorTxn: error retrieving StakeEntries: ")
	}
	if len(stakeEntries) != 0 {
		return errors.New("SanityCheckUnregisterAsValidatorTxn: StakeEntries for ValidatorEntry still exist")
	}

	// Sanity check the deleted StakeEntries.
	totalUnstakedAmountNanos := uint256.NewInt()
	for _, stakeEntry := range utxoOp.PrevStakeEntries {
		totalUnstakedAmountNanos, err = SafeUint256().Add(totalUnstakedAmountNanos, stakeEntry.StakeAmountNanos)
		if err != nil {
			return errors.Wrapf(err, "SanityCheckUnregisterAsValidatorTxn: error calculating TotalUnstakedAmountNanos: ")
		}
	}
	if !totalUnstakedAmountNanos.Eq(amountNanos) {
		return errors.New("SanityCheckUnregisterAsValidatorTxn: TotalUnstakedAmountNanos doesn't match")
	}

	// Sanity check that the GlobalActiveStakeAmountNanos was decreased
	// by amountNanos if the PrevValidatorEntry was active.
	if utxoOp.PrevValidatorEntry.Status() == ValidatorStatusActive {
		if utxoOp.PrevGlobalActiveStakeAmountNanos == nil {
			return errors.New("SanityCheckUnregisterAsValidatorTxn: nil PrevGlobalActiveStakeAmountNanos provided")
		}
		currentGlobalActiveStakeAmountNanos, err := bav.GetGlobalActiveStakeAmountNanos()
		if err != nil {
			return errors.Wrapf(err, "SanityCheckUnregisterAsValidatorTxn: error retrieving GlobalActiveStakeAmountNanos: ")
		}
		globalActiveStakeAmountNanosDecrease, err := SafeUint256().Sub(utxoOp.PrevGlobalActiveStakeAmountNanos, currentGlobalActiveStakeAmountNanos)
		if err != nil {
			return errors.Wrapf(err, "SanityCheckUnregisterAsValidatorTxn: error calculating GlobalActiveStakeAmountNanos decrease: ")
		}
		if !globalActiveStakeAmountNanosDecrease.Eq(amountNanos) {
			return errors.New("SanityCheckUnregisterAsValidatorTxn: GlobalActiveStakeAmountNanos decrease doesn't match")
		}
	} else if utxoOp.PrevGlobalActiveStakeAmountNanos != nil {
		return errors.New("SanityCheckUnregisterAsValidatorTxn: non-nil PrevGlobalActiveStakeAmountNanos provided for inactive validator")
	}

	return nil
}

func (bav *UtxoView) GetValidatorByPKID(pkid *PKID) (*ValidatorEntry, error) {
	// First check the UtxoView.
	validatorEntry, exists := bav.ValidatorPKIDToValidatorEntry[*pkid]
	if exists {
		if validatorEntry.isDeleted {
			// If we get to this point, we found a ValidatorEntry for the given PKID
			// but it was marked as isDeleted. In this case, we do not want to check
			// the database but instead just return nil, no ValidatorEntry found.
			return nil, nil
		}
		// If we get to this point, we found a matching
		// !isDeleted ValidatorEntry for the given PKID.
		return validatorEntry, nil
	}
	// At this point, we know there was no matching ValidatorEntry in the view.

	// If no ValidatorEntry (either isDeleted or !isDeleted) was found
	// in the UtxoView for the given PKID, check the database.
	dbValidatorEntry, err := DBGetValidatorByPKID(bav.Handle, bav.Snapshot, pkid)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetValidatorByPKID: ")
	}
	if dbValidatorEntry != nil {
		// Cache the ValidatorEntry from the db in the UtxoView.
		bav._setValidatorEntryMappings(dbValidatorEntry)
	}
	return dbValidatorEntry, nil
}

func (bav *UtxoView) GetValidatorByPublicKey(validatorPublicKey *PublicKey) (*ValidatorEntry, error) {
	validatorPKIDEntry := bav.GetPKIDForPublicKey(validatorPublicKey.ToBytes())
	if validatorPKIDEntry == nil || validatorPKIDEntry.isDeleted {
		return nil, errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView.GetValidatorByPublicKey: ")
	}
	validatorEntry, err := bav.GetValidatorByPKID(validatorPKIDEntry.PKID)
	if err != nil {
		return nil, err
	}
	if validatorEntry == nil || validatorEntry.isDeleted {
		return nil, errors.Wrapf(RuleErrorInvalidValidatorPKID, "UtxoView.GetValidatorByPublicKey: ")
	}
	return validatorEntry, nil
}

func (bav *UtxoView) GetTopActiveValidatorsByStake(limit uint64) ([]*ValidatorEntry, error) {
	// Validate limit param.
	if limit == uint64(0) {
		return []*ValidatorEntry{}, nil
	}
	// Create a slice of UtxoViewValidatorEntries. We want to skip pulling these from the database in
	// case they have been updated in the UtxoView and the changes have not yet flushed to the database.
	// Updates to a ValidatorEntry could include adding/removing stake or being deleted which would
	// impact our ordering. We pull N ValidatorEntries not present in the UtxoView from the database
	// then sort the UtxoViewValidatorEntries and DatabaseValidatorEntries together to find the top N
	// ValidatorEntries by stake across both the UtxoView and database.
	var utxoViewValidatorEntries []*ValidatorEntry
	for _, validatorEntry := range bav.ValidatorPKIDToValidatorEntry {
		utxoViewValidatorEntries = append(utxoViewValidatorEntries, validatorEntry)
	}
	// Pull top N active ValidatorEntries from the database (not present in the UtxoView).
	// Note that we will skip validators that are present in the view because we pass
	// utxoViewValidatorEntries to the function.
	dbValidatorEntries, err := DBGetTopActiveValidatorsByStake(bav.Handle, bav.Snapshot, limit, utxoViewValidatorEntries)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetTopActiveValidatorsByStake: error retrieving entries from db: ")
	}
	// Cache top N active ValidatorEntries from the db in the UtxoView.
	for _, validatorEntry := range dbValidatorEntries {
		// We only pull ValidatorEntries from the db that are not present in the
		// UtxoView. As a sanity check, we double-check that the ValidatorEntry
		// is not already in the UtxoView here.
		if _, exists := bav.ValidatorPKIDToValidatorEntry[*validatorEntry.ValidatorPKID]; !exists {
			bav._setValidatorEntryMappings(validatorEntry)
		}
	}
	// Pull !isDeleted, active ValidatorEntries from the UtxoView with stake > 0.
	var validatorEntries []*ValidatorEntry
	for _, validatorEntry := range bav.ValidatorPKIDToValidatorEntry {
		if !validatorEntry.isDeleted &&
			validatorEntry.Status() == ValidatorStatusActive &&
			!validatorEntry.TotalStakeAmountNanos.IsZero() {
			validatorEntries = append(validatorEntries, validatorEntry)
		}
	}
	// Sort the ValidatorEntries DESC by TotalStakeAmountNanos.
	sort.SliceStable(validatorEntries, func(ii, jj int) bool {
		stakeCmp := validatorEntries[ii].TotalStakeAmountNanos.Cmp(validatorEntries[jj].TotalStakeAmountNanos)
		if stakeCmp == 0 {
			// Use ValidatorPKID as a tie-breaker if equal TotalStakeAmountNanos.
			return bytes.Compare(
				validatorEntries[ii].ValidatorPKID.ToBytes(),
				validatorEntries[jj].ValidatorPKID.ToBytes(),
			) > 0
		}
		return stakeCmp > 0
	})
	// Return top N.
	upperBound := int(math.Min(float64(limit), float64(len(validatorEntries))))
	return validatorEntries[0:upperBound], nil
}

func (bav *UtxoView) GetGlobalActiveStakeAmountNanos() (*uint256.Int, error) {
	// Read the GlobalActiveStakeAmountNanos from the UtxoView.
	if bav.GlobalActiveStakeAmountNanos != nil {
		return bav.GlobalActiveStakeAmountNanos.Clone(), nil
	}
	// If not set, read the GlobalActiveStakeAmountNanos from the db.
	globalActiveStakeAmountNanos, err := DBGetGlobalActiveStakeAmountNanos(bav.Handle, bav.Snapshot)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetGlobalActiveStakeAmountNanos: ")
	}
	if globalActiveStakeAmountNanos == nil {
		globalActiveStakeAmountNanos = uint256.NewInt()
	}
	// Cache the GlobalActiveStakeAmountNanos from the db in the UtxoView.
	bav._setGlobalActiveStakeAmountNanos(globalActiveStakeAmountNanos)
	return globalActiveStakeAmountNanos, nil
}

func (bav *UtxoView) ShouldJailValidator(validatorEntry *ValidatorEntry) (bool, error) {
	// Return false if the validator is already jailed. We do not want to jail
	// them again. And we want to retain their original JailedAtEpochNumber so
	// that they can eventually unjail themselves.
	if validatorEntry.Status() == ValidatorStatusJailed {
		return false, nil
	}

	// Retrieve the CurrentEpochNumber.
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return false, errors.Wrapf(err, "UtxoView.ShouldJailValidator: error retrieving CurrentEpochNumber: ")
	}

	// Retrieve the SnapshotGlobalParam: JailInactiveValidatorEpochThreshold.
	jailInactiveValidatorEpochThreshold, err := bav.GetSnapshotGlobalParam(JailInactiveValidatorEpochThreshold)
	if err != nil {
		return false, errors.Wrapf(err, "UtxoView.ShouldJailValidator: error retrieving JailInactiveValidatorEpochThreshold: ")
	}

	// Calculate JailAtEpochNumber.
	jailAtEpochNumber, err := SafeUint64().Add(validatorEntry.LastActiveAtEpochNumber, jailInactiveValidatorEpochThreshold)
	if err != nil {
		return false, errors.Wrapf(err, "UtxoView.ShouldJailValidator: error calculating JailAtEpochNumber: ")
	}

	// Return true if LastActiveAtEpochNumber + JailInactiveValidatorEpochThreshold <= CurrentEpochNumber.
	return jailAtEpochNumber <= currentEpochNumber, nil
}

func (bav *UtxoView) JailValidator(validatorEntry *ValidatorEntry) error {
	// Retrieve the CurrentEpochNumber.
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return errors.Wrapf(err, "UtxoView.JailValidator: error retrieving CurrentEpochNumber: ")
	}

	// Set ValidatorEntry.JailedAtEpochNumber to the CurrentEpochNumber.
	validatorEntry.JailedAtEpochNumber = currentEpochNumber

	// Remove the validator's stake from the GlobalActiveStakeAmountNanos.
	prevGlobalActiveStakeAmountNanos, err := bav.GetGlobalActiveStakeAmountNanos()
	if err != nil {
		return errors.Wrapf(err, "UtxoView.JailValidator: error retrieving GlobalActiveStakeAmountNanos: ")
	}
	currentGlobalActiveStakeAmountNanos, err := SafeUint256().Sub(
		prevGlobalActiveStakeAmountNanos, validatorEntry.TotalStakeAmountNanos,
	)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.JailValidator: error calculating updated GlobalActiveStakeAmountNanos: ")
	}

	// Store the updated ValidatorEntry.
	bav._setValidatorEntryMappings(validatorEntry)

	// Store the updated GlobalActiveStakeAmountNanos.
	bav._setGlobalActiveStakeAmountNanos(currentGlobalActiveStakeAmountNanos)

	return nil
}

func (bav *UtxoView) _setValidatorEntryMappings(validatorEntry *ValidatorEntry) {
	// This function shouldn't be called with nil.
	if validatorEntry == nil {
		glog.Errorf("_setValidatorEntryMappings: called with nil entry, this should never happen")
		return
	}
	bav.ValidatorPKIDToValidatorEntry[*validatorEntry.ValidatorPKID] = validatorEntry
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

func (bav *UtxoView) _setGlobalActiveStakeAmountNanos(globalActiveStakeAmountNanos *uint256.Int) {
	// This function shouldn't be called with nil.
	if globalActiveStakeAmountNanos == nil {
		glog.Errorf("_setGlobalActiveStakeAmountNanos: called with nil entry, this should never happen")
		return
	}
	bav.GlobalActiveStakeAmountNanos = globalActiveStakeAmountNanos.Clone()
}

func (bav *UtxoView) _flushValidatorEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Delete all entries in the ValidatorMapKeyToValidatorEntry UtxoView map.
	for validatorMapKeyIter, validatorEntryIter := range bav.ValidatorPKIDToValidatorEntry {
		// Make a copy of the iterators since we make references to them below.
		validatorMapKey := validatorMapKeyIter
		validatorEntry := *validatorEntryIter

		// Sanity-check that the entry matches the map key.
		validatorMapKeyInEntry := *validatorEntry.ValidatorPKID
		if !validatorMapKeyInEntry.Eq(&validatorMapKey) {
			return fmt.Errorf(
				"_flushValidatorEntriesToDbWithTxn: ValidatorEnry key %v doesn't match MapKey %v",
				&validatorMapKeyInEntry,
				&validatorMapKey,
			)
		}

		// Delete the existing mappings in the db for this ValidatorMapKey. They
		// will be re-added if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteValidatorWithTxn(txn, bav.Snapshot, &validatorMapKey); err != nil {
			return errors.Wrapf(err, "_flushValidatorEntriesToDbWithTxn: ")
		}
	}

	// Set any !isDeleted ValidatorEntries in the ValidatorMapKeyToValidatorEntry UtxoView map.
	for _, validatorEntryIter := range bav.ValidatorPKIDToValidatorEntry {
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

func (bav *UtxoView) _flushGlobalActiveStakeAmountNanosToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// If GlobalActiveStakeAmountNanos is nil, then it was never
	// set and shouldn't overwrite the value in the db.
	if bav.GlobalActiveStakeAmountNanos == nil {
		return nil
	}

	return DBPutGlobalActiveStakeAmountNanosWithTxn(txn, bav.Snapshot, bav.GlobalActiveStakeAmountNanos, blockHeight)
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

	// Construct TxindexMetadata.
	txindexMetadata := &RegisterAsValidatorTxindexMetadata{
		ValidatorPublicKeyBase58Check: validatorPublicKeyBase58Check,
		Domains:                       domains,
		DisableDelegatedStake:         metadata.DisableDelegatedStake,
		VotingPublicKey:               metadata.VotingPublicKey.ToString(),
		VotingPublicKeySignature:      metadata.VotingPublicKeySignature.ToString(),
	}

	// Construct AffectedPublicKeys.
	affectedPublicKeys := []*AffectedPublicKey{
		{
			PublicKeyBase58Check: validatorPublicKeyBase58Check,
			Metadata:             "RegisteredValidatorPublicKeyBase58Check",
		},
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

	// Pull UnstakedStakers from PrevStakeEntries on UtxoOperation.
	var unstakedStakers []*UnstakedStakerTxindexMetadata

	for _, stakeEntry := range utxoOp.PrevStakeEntries {
		stakerPublicKeyBytes := bav.GetPublicKeyForPKID(stakeEntry.StakerPKID)
		stakerPublicKeyBase58Check := PkToString(stakerPublicKeyBytes, bav.Params)

		unstakedStakers = append(unstakedStakers, &UnstakedStakerTxindexMetadata{
			StakerPublicKeyBase58Check: stakerPublicKeyBase58Check,
			UnstakeAmountNanos:         stakeEntry.StakeAmountNanos,
		})
	}

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

func (bav *UtxoView) CreateUnjailValidatorTxindexMetadata(
	utxoOp *UtxoOperation,
	txn *MsgDeSoTxn,
) (
	*UnjailValidatorTxindexMetadata,
	[]*AffectedPublicKey,
) {
	// Cast ValidatorPublicKey to ValidatorPublicKeyBase58Check.
	validatorPublicKeyBase58Check := PkToString(txn.PublicKey, bav.Params)

	// Construct AffectedPublicKeys.
	affectedPublicKeys := []*AffectedPublicKey{
		{
			PublicKeyBase58Check: validatorPublicKeyBase58Check,
			Metadata:             "UnjailedValidatorPublicKeyBase58Check",
		},
	}

	return &UnjailValidatorTxindexMetadata{}, affectedPublicKeys
}

//
// BLS UTILS
//

func EncodeBLSPublicKey(blsPublicKey *bls.PublicKey) []byte {
	var blsPublicKeyBytes []byte
	if blsPublicKey != nil {
		blsPublicKeyBytes = blsPublicKey.ToBytes()
	}
	return EncodeByteArray(blsPublicKeyBytes)
}

func DecodeBLSPublicKey(rr io.Reader) (*bls.PublicKey, error) {
	publicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return nil, err
	}
	return (&bls.PublicKey{}).FromBytes(publicKeyBytes)
}

func EncodeBLSSignature(blsSignature *bls.Signature) []byte {
	var blsSignatureBytes []byte
	if blsSignature != nil {
		blsSignatureBytes = blsSignature.ToBytes()
	}
	return EncodeByteArray(blsSignatureBytes)
}

func DecodeBLSSignature(rr io.Reader) (*bls.Signature, error) {
	signatureBytes, err := DecodeByteArray(rr)
	if err != nil {
		return nil, err
	}
	return (&bls.Signature{}).FromBytes(signatureBytes)
}

// When registering as a validator, there are two keys that are involved:
//
//   - transactorPublicKey: This is the key that is used to sign transactions on the
//     network.
//
//   - votingPublicKey: This is the key that is used as a part of consensus to sign
//     vote and timeout messages. It is distinct from the transactorPublicKey because
//     it is a BLS key rather than a standard ECDSA key, which means we can *aggregate*
//     signatures generated by these keys, which is needed for our Fast-HotStuff
//     consensus to be efficient. It is also useful from an operational standpoint
//     to separate the key used to perform transactions on the network from the key
//     used to vote on blocks (the former can remail "cold" while the latter needs
//     to remain "hot").
//
// Given that there are two keys involved, the validation of a RegisterAsValidator
// transaction needs to check a few things:
//
//  1. That the user owns the transactorPublicKey. This is proven by checking the signature
//     at the transaction level.
//
//  2. That the user owns the votingPublicKey. This is proven by checking a *second*
//     signature embedded in the RegisterAsValidatorMetadata, which we define below.
//
// To prove #2, it is sufficient to have the votingPublicKey sign the
// transactorPublicKey. Doing this makes it so that the signature can only ever be
// used to associate this specific votingPublicKey with this specific transactorPublicKey.
// In addition, the fact that the transactorPublicKey is required to sign the
// *entire transaction payload*, including this votingPublicKey signature,
// ensures that no *other* transactor can ever associate
// this votingPublicKey with another key. Finally, replay attacks are prevented by
// the fact that the transaction includes a nonce in its payload, signed by the
// transactorPublicKey, that only allows the transaction as a whole to be run once.
// This means that nobody can construct a transaction to re-register this validator
// without constructing a new transaction with a fresh nonce, thus requiring a new
// signature from the same transactorPublicKey, which they wouldn't have access to.
func CreateValidatorVotingSignaturePayload(
	transactorPublicKeyBytes []byte,
) []byte {
	// HASH(TransactorPublicKey)
	hashedTransactorPublicKey := sha256.Sum256(transactorPublicKeyBytes)
	return hashedTransactorPublicKey[:]
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
const RuleErrorValidatorMissingVotingPublicKey RuleError = "RuleErrorValidatorMissingVotingPublicKey"
const RuleErrorValidatorMissingVotingPublicKeySignature RuleError = "RuleErrorValidatorMissingVotingPublicKeySignature"
const RuleErrorValidatorInvalidVotingPublicKeySignature RuleError = "RuleErrorValidatorInvalidVotingPublicKeySignature"
const RuleErrorValidatorDisablingExistingDelegatedStakers RuleError = "RuleErrorValidatorDisablingExistingDelegatedStakers"
const RuleErrorUnjailingNonjailedValidator RuleError = "RuleErrorUnjailingNonjailedValidator"
const RuleErrorUnjailingValidatorTooEarly RuleError = "RuleErrorUnjailingValidatorTooEarly"

const MaxValidatorNumDomains int = 100
