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
	return EncoderTypeValidatorEntry
}

//
// TYPES: RegisterAsValidatorMetadata
//

type RegisterAsValidatorMetadata struct {
	Domains               [][]byte
	DisableDelegatedStake bool
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
	key = append(key, EncodeUint256(validatorEntry.TotalStakeAmountNanos)...)               // Highest stake first
	key = append(key, _EncodeUint32(math.MaxUint32-validatorEntry.CreatedAtBlockHeight)...) // Oldest first
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

func DBGetTopValidatorsByStake(handle *badger.DB, snap *Snapshot, limit uint64) ([]*ValidatorEntry, error) {
	var validatorEntries []*ValidatorEntry

	// Retrieve top N ValidatorEntry PKIDs by stake.
	var key []byte
	key = append(key, Prefixes.PrefixValidatorByStake...)
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
	validatorEntryBytes := EncodeToBytes(blockHeight, validatorEntry)
	var key []byte
	var err error

	// Set ValidatorEntry in PrefixValidatorByPKID.
	key = DBKeyForValidatorByPKID(validatorEntry)
	if err = DBSetWithTxn(txn, snap, key, validatorEntryBytes); err != nil {
		return errors.Wrapf(
			err, "DBPutValidatorWithTxn: problem storing ValidatorEntry in index PrefixValidatorByPKID",
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
	// Calculate increase in GlobalStakeAmountNanos.
	globalStakeAmountNanos, err = SafeUint256().Add(globalStakeAmountNanos, validatorEntry.TotalStakeAmountNanos)
	if err != nil {
		return errors.Wrapf(
			err, "DBPutValidatorWithTxn: problem calculating increase in GlobalStakeAmountNanos",
		)
	}
	// Set updated GlobalStakeAmountNanos.
	key = DBKeyForGlobalStakeAmountNanos()
	if err = DBSetWithTxn(txn, snap, key, EncodeUint256(globalStakeAmountNanos)); err != nil {
		return errors.Wrapf(
			err, "DBPutValidatorWithTxn: problem storing value in index PrefixGlobalStakeAmountNanos",
		)
	}

	return nil
}

func DBDeleteValidatorWithTxn(txn *badger.Txn, snap *Snapshot, validatorEntry *ValidatorEntry) error {
	if validatorEntry == nil {
		return nil
	}
	var key []byte
	var err error

	// Check if the ValidatorEntry exists in the db. If there isn't an existing
	// ValidatorEntry in the db, just return. This is an important check since
	// we do not want to decrease the GlobalStakeAmountNanos for a validator
	// that does not exist.
	key = DBKeyForValidatorByPKID(validatorEntry)
	prevValidatorEntry, err := DBGetValidatorByPKIDWithTxn(txn, snap, validatorEntry.ValidatorPKID)
	if err != nil {
		return errors.Wrapf(err, "DBDeleteValidatorWithTxn: problem retrieving ValidatorEntry from index PrefixValidatorByPKID")
	}
	if prevValidatorEntry == nil {
		return nil
	}

	// Delete ValidatorEntry from PrefixValidatorByPKID.
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
	// Calculate decrease in GlobalStakeAmountNanos.
	globalStakeAmountNanos, err = SafeUint256().Sub(globalStakeAmountNanos, validatorEntry.TotalStakeAmountNanos)
	if err != nil {
		return errors.Wrapf(
			err, "DBDeleteValidatorWithTxn: problem calculating decrease in global stake",
		)
	}
	// Set updated GlobalStakeAmountNanos.
	key = DBKeyForGlobalStakeAmountNanos()
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
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true.
	if prevValidatorEntry != nil {
		bav._deleteValidatorEntryMappings(prevValidatorEntry)
	}

	// Set ValidatorID only if this is a new ValidatorEntry.
	validatorID := txHash
	if prevValidatorEntry != nil {
		validatorID = prevValidatorEntry.ValidatorID
	}

	// TODO: Unstake delegated stakers if updating DisableDelegatedStake=true.
	if prevValidatorEntry != nil &&
		!prevValidatorEntry.DisableDelegatedStake && // Validator previously allowed delegated stake.
		txMeta.DisableDelegatedStake { // Validator no longer allows delegated stake.
	}

	// TODO: Calculate TotalStakeAmountNanos.
	totalStakeAmountNanos := uint256.NewInt()

	// Set CreatedAtBlockHeight only if this is a new ValidatorEntry.
	createdAtBlockHeight := blockHeight
	if prevValidatorEntry != nil {
		createdAtBlockHeight = prevValidatorEntry.CreatedAtBlockHeight
	}

	// Retrieve existing ExtraData to merge with any new ExtraData.
	var prevExtraData map[string][]byte
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true.
	if prevValidatorEntry != nil {
		prevExtraData = prevValidatorEntry.ExtraData
	}

	// Construct new ValidatorEntry from metadata.
	currentValidatorEntry := &ValidatorEntry{
		ValidatorID:           validatorID,
		ValidatorPKID:         transactorPKIDEntry.PKID,
		Domains:               txMeta.Domains,
		DisableDelegatedStake: txMeta.DisableDelegatedStake,
		TotalStakeAmountNanos: totalStakeAmountNanos,
		CreatedAtBlockHeight:  createdAtBlockHeight,
		ExtraData:             mergeExtraData(prevExtraData, txn.ExtraData),
	}
	// Set the ValidatorEntry.
	bav._setValidatorEntryMappings(currentValidatorEntry)

	// Add a UTXO operation
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:               OperationTypeRegisterAsValidator,
		PrevValidatorEntry: prevValidatorEntry,
		// PrevStakeEntries: prevStakeEntries, // TODO
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

	// Restore the prev ValidatorEntry, if exists.
	prevValidatorEntry := operationData.PrevValidatorEntry
	if prevValidatorEntry != nil {
		bav._setValidatorEntryMappings(prevValidatorEntry)
	}

	// TODO: If PrevStakeEntries, delete the current StakeEntries and restore the prev StakeEntries.

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

	// Convert TransactorPublicKey to TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return 0, 0, nil, RuleErrorInvalidValidatorPKID
	}

	// TODO: Unstake all StakeEntries for this validator.

	// Delete the existing ValidatorEntry.
	prevValidatorEntry, err := bav.GetValidatorByPKID(transactorPKIDEntry.PKID)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUnregisterAsValidator: ")
	}
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true.
	if prevValidatorEntry != nil {
		bav._deleteValidatorEntryMappings(prevValidatorEntry)
	} else {
		return 0, 0, nil, RuleErrorValidatorNotFound
	}

	// Add a UTXO operation.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:               OperationTypeUnregisterAsValidator,
		PrevValidatorEntry: prevValidatorEntry,
		// PrevStakeEntries: prevStakeEntries, // TODO
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
			"_disconnectUnegisterAsValidator: trying to revert %v but found %v",
			OperationTypeUnregisterAsValidator,
			operationData.Type,
		)
	}

	// Restore the prev ValidatorEntry.
	prevValidatorEntry := operationData.PrevValidatorEntry
	if prevValidatorEntry == nil {
		// This should never happen.
		return fmt.Errorf(
			"_disconnectUnregisterAsValidator: no deleted ValidatorEntry found for %v", currentTxn.PublicKey,
		)
	}
	bav._setValidatorEntryMappings(prevValidatorEntry)

	// TODO: Restore the prev StakeEntries, if any.

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

	return nil
}

func (bav *UtxoView) GetValidatorByPKID(pkid *PKID) (*ValidatorEntry, error) {
	// First check UtxoView.
	for _, validatorEntry := range bav.ValidatorMapKeyToValidatorEntry {
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
	for _, validatorEntry := range bav.ValidatorMapKeyToValidatorEntry {
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
	tombstoneEntry := validatorEntry
	tombstoneEntry.isDeleted = true
	// Set the mappings to the point to the tombstone entry.
	bav._setValidatorEntryMappings(tombstoneEntry)
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
				"_flushValidatorEntriesToDbWithTxn: validator entry key %v doesn't match map key %v",
				&validatorMapKeyInEntry,
				&validatorMapKey,
			)
		}

		// Delete the existing mappings in the db for this ValidatorMapKey. They
		// will be re-added if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteValidatorWithTxn(txn, bav.Snapshot, &validatorEntry); err != nil {
			return fmt.Errorf(
				"_flushValidatorEntriesToDbWithTxn: problem deleting association mappings for map key %v: %v",
				&validatorMapKey,
				err,
			)
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
				return fmt.Errorf("_flushValidatorEntriesToDbWithTxn: %v", err)
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

	// TODO: Pull UnstakedStakers from PrevStakeEntries on UtxoOperation.
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

func (bav *UtxoView) CreateUnregisterAsValidatorTxindexMetadata(
	utxoOp *UtxoOperation,
	txn *MsgDeSoTxn,
) (
	*UnregisterAsValidatorTxindexMetadata,
	[]*AffectedPublicKey,
) {
	// Cast ValidatorPublicKey to ValidatorPublicKeyBase58Check.
	validatorPublicKeyBase58Check := PkToString(txn.PublicKey, bav.Params)

	// TODO: Pull UnstakedStakers from PrevStakeEntries on UtxoOperation.
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
