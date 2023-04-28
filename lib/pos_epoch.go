package lib

import (
	"bytes"
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
)

//
// TYPE
//

type EpochEntry struct {
	EpochNumber      uint64
	FinalBlockHeight uint64
}

func (epochEntry *EpochEntry) Copy() *EpochEntry {
	return &EpochEntry{
		EpochNumber:      epochEntry.EpochNumber,
		FinalBlockHeight: epochEntry.FinalBlockHeight,
	}
}

func (epochEntry *EpochEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, UintToBuf(epochEntry.EpochNumber)...)
	data = append(data, UintToBuf(epochEntry.FinalBlockHeight)...)
	return data
}

func (epochEntry *EpochEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// EpochNumber
	epochEntry.EpochNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "EpochEntry.Decode: Problem reading EpochNumber: ")
	}

	// FinalBlockHeight
	epochEntry.FinalBlockHeight, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "EpochEntry.Decode: Problem reading FinalBlockHeight: ")
	}

	return err
}

func (epochEntry *EpochEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (epochEntry *EpochEntry) GetEncoderType() EncoderType {
	return EncoderTypeEpochEntry
}

//
// UTXO VIEW UTILS
//

func (bav *UtxoView) GetCurrentEpochEntry() (*EpochEntry, error) {
	var epochEntry *EpochEntry
	var err error

	// First, check the UtxoView.
	epochEntry = bav.CurrentEpochEntry
	if epochEntry != nil {
		return epochEntry.Copy(), nil
	}

	// If not found, check the database.
	epochEntry, err = DBGetCurrentEpochEntry(bav.Handle, bav.Snapshot)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetCurrentEpoch: problem retrieving EpochEntry from db: ")
	}
	if epochEntry != nil {
		// Cache in the UtxoView.
		bav.CurrentEpochEntry = epochEntry.Copy()
	}
	return epochEntry, nil
}

func (bav *UtxoView) GetCurrentEpochNumber() (uint64, error) {
	epochEntry, err := bav.GetCurrentEpochEntry()
	if err != nil {
		return 0, errors.Wrapf(err, "UtxoView.GetCurrentEpochNumber: ")
	}
	if epochEntry == nil {
		return 0, errors.New("UtxoView.GetCurrentEpochNumber: no CurrentEpochEntry found")
	}
	return epochEntry.EpochNumber, nil
}

func (bav *UtxoView) SetCurrentEpochEntry(epochEntry *EpochEntry, blockHeight uint64) error {
	// This function should only ever be called from the OnEpochEnd hook.
	if epochEntry == nil {
		return errors.New("UtxoView.SetCurrentEpochEntry: called with nil EpochEntry")
	}

	// Set the current EpochEntry in the db.
	if err := DBPutCurrentEpochEntry(bav.Handle, bav.Snapshot, epochEntry, blockHeight); err != nil {
		return errors.Wrapf(err, "UtxoView.SetCurrentEpochEntry: problem setting EpochEntry in db: ")
	}

	// Set the current EpochEntry in the UtxoView.
	bav.CurrentEpochEntry = epochEntry.Copy()
	return nil
}

func (bav *UtxoView) DeleteCurrentEpochEntry() {
	// This function should only ever be called from the OnEpochEnd hook.
	bav.CurrentEpochEntry = nil
}

//
// DB UTILS
//

func DBKeyForCurrentEpoch() []byte {
	return append([]byte{}, Prefixes.PrefixCurrentEpoch...)
}

func DBGetCurrentEpochEntry(handle *badger.DB, snap *Snapshot) (*EpochEntry, error) {
	var ret *EpochEntry
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetCurrentEpochEntryWithTxn(txn, snap)
		return innerErr
	})
	return ret, err
}

func DBGetCurrentEpochEntryWithTxn(txn *badger.Txn, snap *Snapshot) (*EpochEntry, error) {
	// Retrieve StakeEntry from db.
	key := DBKeyForCurrentEpoch()
	epochEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetCurrentEpochEntry: problem retrieving EpochEntry: ")
	}

	// Decode EpochEntry from bytes.
	rr := bytes.NewReader(epochEntryBytes)
	epochEntry, err := DecodeDeSoEncoder(&EpochEntry{}, rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetCurrentEpochEntry: problem decoding EpochEntry: ")
	}
	return epochEntry, nil
}

func DBPutCurrentEpochEntry(handle *badger.DB, snap *Snapshot, epochEntry *EpochEntry, blockHeight uint64) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DBPutCurrentEpochEntryWithTxn(txn, snap, epochEntry, blockHeight)
	})
}

func DBPutCurrentEpochEntryWithTxn(txn *badger.Txn, snap *Snapshot, epochEntry *EpochEntry, blockHeight uint64) error {
	// Set EpochEntry in PrefixCurrentEpoch.
	key := DBKeyForCurrentEpoch()
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, epochEntry)); err != nil {
		return errors.Wrapf(
			err, "DBPutCurrentEpochEntry: problem storing EpochEntry in index PrefixCurrentEpoch: ",
		)
	}
	return nil
}
