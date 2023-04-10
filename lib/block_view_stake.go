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
	// TODO: EncoderTypeStakeEntry
	return EncoderTypeValidatorEntry
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
	// TODO: EncoderTypeLockedStakeEntry
	return EncoderTypeValidatorEntry
}
