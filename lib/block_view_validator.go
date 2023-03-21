package lib

import (
	"bytes"
	"fmt"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"math"
)

//
// ValidatorEntry
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

func (validatorEntry *ValidatorEntry) GetVersionByte(_ uint64) byte {
	return 0
}

func (validatorEntry *ValidatorEntry) GetEncoderType() EncoderType {
	return 0 // TODO
}

//
// RegisterAsValidatorMetadata
//

type RegisterAsValidatorMetadata struct {
	Domains               [][]byte
	DisableDelegatedStake bool
}

func (txnData *RegisterAsValidatorMetadata) GetTxnType() TxnType {
	return 0 // TODO
}

func (txnData *RegisterAsValidatorMetadata) ToBytes(_ bool) ([]byte, error) {
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
// UnregisterAsValidatorMetadata
//

type UnregisterAsValidatorMetadata struct{}

func (txnData *UnregisterAsValidatorMetadata) GetTxnType() TxnType {
	return 0 // TODO
}

func (txnData *UnregisterAsValidatorMetadata) ToBytes(_ bool) ([]byte, error) {
	return []byte{}, nil
}

func (txnData *UnregisterAsValidatorMetadata) FromBytes(data []byte) error {
	return nil
}

func (txnData *UnregisterAsValidatorMetadata) New() DeSoTxnMetadata {
	return &UnregisterAsValidatorMetadata{}
}

//
// RegisterAsValidatorTxindexMetadata
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

func (txindexMetadata *RegisterAsValidatorTxindexMetadata) GetVersionByte(_ uint64) byte {
	return 0
}

func (txindexMetadata *RegisterAsValidatorTxindexMetadata) GetEncoderType() EncoderType {
	return 0 // TODO
}

//
// UnstakedStakerTxindexMetadata
//

type UnstakedStakerTxindexMetadata struct {
	StakerPublicKeyBase58Check string
	UnstakeAmountNanos         *uint256.Int
}

func (txindexMetadata *UnstakedStakerTxindexMetadata) RawEncodeWithoutMetadata(_ uint64, _ ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(txindexMetadata.StakerPublicKeyBase58Check))...)
	data = append(data, EncodeUint256(txindexMetadata.UnstakeAmountNanos)...)
	return data
}

func (txindexMetadata *UnstakedStakerTxindexMetadata) RawDecodeWithoutMetadata(_ uint64, rr *bytes.Reader) error {
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
// UnregisterAsValidatorTxindexMetadata
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

func (txindexMetadata *UnregisterAsValidatorTxindexMetadata) GetVersionByte(_ uint64) byte {
	return 0
}

func (txindexMetadata *UnregisterAsValidatorTxindexMetadata) GetEncoderType() EncoderType {
	return 0 // TODO
}
