package lib

import (
	"bytes"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"math"
	"sort"
)

//
// TYPES: ValidatorEntry
//

type ValidatorEntry struct {
	ValidatorID           *BlockHash
	ValidatorPKID         *PKID
	Domains               [][]byte
	DisableDelegatedStake bool
	TotalStakeAmountNanos *uint256.Int
	CreatedAtBlockHeight  uint32
	ExtraData             map[string][]byte
	isDeleted             bool
}

type ValidatorMapKey struct {
	ValidatorID BlockHash
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
		ValidatorID:           validatorEntry.ValidatorID.NewBlockHash(),
		ValidatorPKID:         validatorEntry.ValidatorPKID.NewPKID(),
		Domains:               domainsCopy,
		DisableDelegatedStake: validatorEntry.DisableDelegatedStake,
		CreatedAtBlockHeight:  validatorEntry.CreatedAtBlockHeight,
		ExtraData:             extraDataCopy,
		isDeleted:             validatorEntry.isDeleted,
	}
}

func (validatorEntry *ValidatorEntry) Eq(other *ValidatorEntry, blockHeight uint64) bool {
	return bytes.Equal(EncodeToBytes(blockHeight, validatorEntry), EncodeToBytes(blockHeight, other))
}

func (validatorEntry *ValidatorEntry) ToMapKey() ValidatorMapKey {
	return ValidatorMapKey{ValidatorID: *validatorEntry.ValidatorID}
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
	data = append(data, UintToBuf(uint64(validatorEntry.CreatedAtBlockHeight))...)
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

	// CreatedAtBlockHeight
	createdAtBlockHeight, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading CreatedAtBlockHeight: ")
	}
	if blockHeight > uint64(math.MaxUint32) {
		return fmt.Errorf(
			"ValidatorEntry.Decode: CreatedAtBlockHeight %d greater than max uint32",
			createdAtBlockHeight,
		)
	}
	validatorEntry.CreatedAtBlockHeight = uint32(createdAtBlockHeight)

	// ExtraData
	extraData, err := DecodeExtraData(rr)
	if err != nil {
		return errors.Wrapf(err, "ValidatorEntry.Decode: Problem reading ExtraData: ")
	}
	validatorEntry.ExtraData = extraData

	return nil
}

func (validatorEntry *ValidatorEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (validatorEntry *ValidatorEntry) GetEncoderType() EncoderType {
	return 0 // TODO
}

//
// TYPES: RegisterAsValidatorMetadata
//

type RegisterAsValidatorMetadata struct {
	Domains               [][]byte
	DisableDelegatedStake bool
}

func (txnData *RegisterAsValidatorMetadata) GetTxnType() TxnType {
	return 0 // TODO
}

func (txnData *RegisterAsValidatorMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte

	// Domains
	data = append(data, UintToBuf(uint64(len(txnData.Domains)))...)
	for _, domain := range txnData.Domains {
		data = append(data, EncodeByteArray(domain)...)
	}

	data = append(data, BoolToByte(txnData.DisableDelegatedStake))
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
	return 0 // TODO
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
	return 0 // TODO
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
	return 0 // TODO
}

//
// DB UTILS
//

func DBKeyForValidatorByPKID(validatorEntry *ValidatorEntry) []byte {
	var key []byte
	// key = append(key, Prefixes.PrefixValidatorByPKID...) // TODO
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBKeyForValidatorByStake(validatorEntry *ValidatorEntry) []byte {
	var key []byte
	// key = append(key, Prefixes.PrefixValidatorByStake...) // TODO
	key = append(key, EncodeUint256(validatorEntry.TotalStakeAmountNanos)...)               // Highest stake first
	key = append(key, _EncodeUint32(math.MaxUint32-validatorEntry.CreatedAtBlockHeight)...) // Oldest first
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
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

func DBGetTopValidatorsByStake(handle *badger.DB, snap *Snapshot, limit uint64) ([]*ValidatorEntry, error) {
	var validatorEntries []*ValidatorEntry

	// Retrieve top N ValidatorEntry PKIDs by stake.
	var key []byte
	// key := Prefixes.PrefixValidatorByStake // TODO
	key = append(key)
	_, validatorPKIDsBytes, err := EnumerateKeysForPrefixWithLimitOffsetOrder(
		handle, key, int(limit), nil, true, NewSet([]string{}),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetTopValidatorsByStake: problem retrieving top validators: ")
	}

	// For each PKID, retrieve the ValidatorEntry by PKID.
	for _, validatorPKIDBytes := range validatorPKIDsBytes {
		validatorEntry, err := DBGetValidatorByPKID(handle, snap, NewPKID(validatorPKIDBytes))
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
	var key []byte
	// key := Prefixes.PrefixGlobalStakeAmountNanos // TODO
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
	validatorEntryBytes := EncodeToBytes(blockHeight, validatorEntry)

	// Retrieve existing ValidatorEntry.
	prevValidatorEntry, err := DBGetValidatorByPKIDWithTxn(txn, snap, validatorEntry.ValidatorPKID)
	if err != nil {
		return errors.Wrapf(err, "DBPutValidatorWithTxn: problem retrieving validator by PKID: ")
	}
	if validatorEntry.Eq(prevValidatorEntry, blockHeight) {
		return nil
	}

	// Set ValidatorEntry in PrefixValidatorByPKID.
	key := DBKeyForValidatorByPKID(validatorEntry)
	if err = DBSetWithTxn(txn, snap, key, validatorEntryBytes); err != nil {
		return errors.Wrapf(
			err, "DBPutValidatorWithTxn: problem storing ValidatorEntry in index PrefixValidatorByPKID",
		)
	}

	if !validatorEntry.TotalStakeAmountNanos.Eq(prevValidatorEntry.TotalStakeAmountNanos) {
		// Delete existing entry in PrefixValidatorByStake.
		key = DBKeyForValidatorByStake(prevValidatorEntry)
		if err = DBDeleteWithTxn(txn, snap, key); err != nil {
			return errors.Wrapf(
				err, "DBPutValidatorWithTxn: problem deleting ValidatorEntry from index PrefixValidatorByStake",
			)
		}

		// Set new entry in PrefixValidatorByStake.
		key = DBKeyForValidatorByStake(validatorEntry)
		if err = DBSetWithTxn(txn, snap, key, validatorEntry.ValidatorPKID.ToBytes()); err != nil {
			return errors.Wrapf(
				err, "DBPutValidatorWithTxn: problem storing ValidatorEntry in index PrefixValidatorByPKID",
			)
		}

		// Update PrefixGlobalStakeAmountNanos.
		// Retrieve existing GlobalStakeAmountNanos.
		var globalStakeAmountNanos *uint256.Int
		globalStakeAmountNanos, err = DBGetGlobalStakeAmountNanosWithTxn(txn, snap)
		if err != nil {
			return errors.Wrapf(
				err, "DBPutValidatorWithTxn: problem retrieving value from index PrefixGlobalStakeAmountNanos",
			)
		}

		// Calculate change in GlobalStakeAmountNanos.
		var deltaStakeAmountNanos *uint256.Int
		if validatorEntry.TotalStakeAmountNanos.Lt(prevValidatorEntry.TotalStakeAmountNanos) {
			// Validator stake has been decreased.
			deltaStakeAmountNanos, err = SafeUint256().Sub(
				prevValidatorEntry.TotalStakeAmountNanos, validatorEntry.TotalStakeAmountNanos,
			)
			if err != nil {
				return errors.Wrapf(
					err, "DBPutValidatorWithTxn: problem calculating decrease in validator's stake",
				)
			}
			globalStakeAmountNanos, err = SafeUint256().Sub(globalStakeAmountNanos, deltaStakeAmountNanos)
			if err != nil {
				return errors.Wrapf(
					err, "DBPutValidatorWithTxn: problem calculating decrease in global stake",
				)
			}
		} else {
			// Validator stake has been increased.
			deltaStakeAmountNanos, err = SafeUint256().Sub(
				validatorEntry.TotalStakeAmountNanos, prevValidatorEntry.TotalStakeAmountNanos,
			)
			if err != nil {
				return errors.Wrapf(
					err, "DBPutValidatorWithTxn: problem calculating increase in validator's stake",
				)
			}
			globalStakeAmountNanos, err = SafeUint256().Add(globalStakeAmountNanos, deltaStakeAmountNanos)
			if err != nil {
				return errors.Wrapf(
					err, "DBPutValidatorWithTxn: problem calculating increase in global stake",
				)
			}
		}

		// Set updated GlobalStakeAmountNanos.
		// key = Prefixes.PrefixGlobalStakeAmountNanos // TODO
		if err = DBSetWithTxn(txn, snap, key, EncodeUint256(globalStakeAmountNanos)); err != nil {
			return errors.Wrapf(
				err, "DBPutValidatorWithTxn: problem storing value in index PrefixGlobalStakeAmountNanos",
			)
		}
	}

	return nil
}

func DBDeleteValidatorWithTxn(txn *badger.Txn, snap *Snapshot, validatorEntry *ValidatorEntry) error {
	if validatorEntry == nil {
		return nil
	}
	var key []byte
	var err error

	// Delete ValidatorEntry from PrefixValidatorByPKID.
	key = DBKeyForValidatorByPKID(validatorEntry)
	if err = DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(
			err, "DBDeleteValidatorWithTxn: problem deleting ValidatorEntry from index PrefixValidatorByPKID",
		)
	}

	// Delete ValidatorEntry from PrefixValidatorByStake.
	key = DBKeyForValidatorByStake(validatorEntry)
	if err = DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(
			err, "DBDeleteValidatorWithTxn: problem deleting ValidatorEntry from index PrefixValidatorByPKID",
		)
	}

	// Update PrefixGlobalStakeAmountNanos.
	// Retrieve existing GlobalStakeAmountNanos.
	var globalStakeAmountNanos *uint256.Int
	globalStakeAmountNanos, err = DBGetGlobalStakeAmountNanosWithTxn(txn, snap)
	if err != nil {
		return errors.Wrapf(
			err, "DBDeleteValidatorWithTxn: problem retrieving value from index PrefixGlobalStakeAmountNanos",
		)
	}

	// Calculate change in GlobalStakeAmountNanos.
	globalStakeAmountNanos, err = SafeUint256().Sub(globalStakeAmountNanos, validatorEntry.TotalStakeAmountNanos)
	if err != nil {
		return errors.Wrapf(
			err, "DBDeleteValidatorWithTxn: problem calculating decrease in global stake",
		)
	}

	// Set updated GlobalStakeAmountNanos.
	// key = Prefixes.PrefixGlobalStakeAmountNanos // TODO
	if err = DBSetWithTxn(txn, snap, key, EncodeUint256(globalStakeAmountNanos)); err != nil {
		return errors.Wrapf(
			err, "DBDeleteValidatorWithTxn: problem storing value in index PrefixGlobalStakeAmountNanos",
		)
	}

	return nil
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

	// TODO: what else do we need here with balance model

	return txn, 0, 0, 0, nil
}

//
// UTXO VIEW UTILS
//

func (bav *UtxoView) IsValidRegisterAsValidatorMetadata(transactorPublicKey []byte, metadata *RegisterAsValidatorMetadata) error {
	// TODO
	return nil
}

func (bav *UtxoView) GetValidatorByPKID(pkid *PKID) (*ValidatorEntry, error) {
	// First check UtxoView.
	var validatorMapKeyToValidatorEntry map[ValidatorMapKey]*ValidatorEntry // TODO: store this on the UtxoView
	for _, validatorEntry := range validatorMapKeyToValidatorEntry {
		if validatorEntry != nil && validatorEntry.ValidatorPKID.Eq(pkid) {
			if validatorEntry.isDeleted {
				return nil, nil
			}
			return validatorEntry, nil
		}
	}
	// If not found, check database.
	return DBGetValidatorByPKID(bav.Handle, bav.Snapshot, pkid)
}

func (bav *UtxoView) GetTopValidatorsByStake(limit uint64) ([]*ValidatorEntry, error) {
	// Pull top ValidatorEntries from the database.
	dbValidatorEntries, err := DBGetTopValidatorsByStake(bav.Handle, bav.Snapshot, limit)
	if err != nil {
		return nil, errors.Wrapf(err, "GetTopValidatorsByStake: error retrieving entries from db: ")
	}
	// Add ValidatorEntries from the UtxoView.
	// Convert from slice to set to prevent duplicates.
	validatorSet := NewSet(dbValidatorEntries)
	var validatorMapKeyToValidatorEntry map[ValidatorMapKey]*ValidatorEntry // TODO: store this on the UtxoView
	for _, validatorEntry := range validatorMapKeyToValidatorEntry {
		validatorSet.Add(validatorEntry)
	}
	// Convert from set to slice to sort DESC by TotalStakeAmountNanos.
	validatorEntries := validatorSet.ToSlice()
	sort.Slice(validatorEntries, func(ii, jj int) bool {
		return validatorEntries[ii].TotalStakeAmountNanos.Cmp(validatorEntries[jj].TotalStakeAmountNanos) > 0
	})
	// Return top N.
	return validatorEntries[0:limit], nil
}

func (bav *UtxoView) _flushValidatorEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Iterate through all entries in the UtxoView map.
	var validatorMapKeyToValidatorEntry map[ValidatorMapKey]*ValidatorEntry // TODO: store this on the UtxoView
	for validatorMapKeyIter, validatorEntryIter := range validatorMapKeyToValidatorEntry {
		// Make a copy of the iterators since we make references to them below.
		validatorMapKey := validatorMapKeyIter
		validatorEntry := *validatorEntryIter

		// Sanity-check that the entry matches the map key.
		validatorMapKeyInEntry := validatorEntry.ToMapKey()
		if validatorMapKeyInEntry != validatorMapKey {
			return fmt.Errorf(
				"_flushValidatorEntriesToDbWithTxn: validator entry key %v doesn't match map key %v",
				&validatorMapKeyInEntry,
				&validatorMapKey,
			)
		}

		// We can't first delete all then set all !isDeleted entries since we have
		// an index that relies on the previous TotalStakeAmountNanos value. The
		// DBPutValidatorWithTxn function handles deleting the old entries from the
		// database for us and setting the new ones.
		if validatorEntry.isDeleted {
			// Delete entry if isDeleted.
			if err := DBDeleteValidatorWithTxn(txn, bav.Snapshot, &validatorEntry); err != nil {
				return errors.Wrapf(err, "_flushValidatorEntriesToDbWithTxn: error deleting entry: ")
			}
		} else {
			// Set entry if !isDeleted.
			if err := DBPutValidatorWithTxn(txn, bav.Snapshot, &validatorEntry, blockHeight); err != nil {
				return errors.Wrapf(err, "_flushValidatorEntriesToDbWithTxn: error setting entry: ")
			}
		}
	}
	return nil
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

	// TODO: Pull UnstakedStakers from UtxoOperation.
	var unstakedStakers []*UnstakedStakerTxindexMetadata

	// Construct TxindexMetadata.
	txindexMetadata := &RegisterAsValidatorTxindexMetadata{
		ValidatorPublicKeyBase58Check: validatorPublicKeyBase58Check,
		Domains:                       domains,
		DisableDelegatedStake:         metadata.DisableDelegatedStake,
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
