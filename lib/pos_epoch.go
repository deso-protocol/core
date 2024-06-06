package lib

import (
	"bytes"

	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

//
// TYPE
//

type EpochEntry struct {
	EpochNumber        uint64
	InitialBlockHeight uint64
	InitialView        uint64
	FinalBlockHeight   uint64

	// This captures an offset used to index into the leader schedule at the start of the
	// epoch.
	// - This value is set to 0 if there were no timeouts at the epoch transition during
	//   the final two block heights of the previous epoch
	// - This value is non-zero if there was at least one timeout at the epoch transition
	//   during the final two block heights of the previous epoch
	InitialLeaderIndexOffset uint64

	// This captures the on-chain timestamp when this epoch entry was created. This does not
	// represent the timestamp for first block of the epoch, but rather when this epoch entry
	// was created during that epoch transition at the end of the previous epoch.
	CreatedAtBlockTimestampNanoSecs int64
}

func (epochEntry *EpochEntry) Copy() *EpochEntry {
	return &EpochEntry{
		EpochNumber:                     epochEntry.EpochNumber,
		InitialBlockHeight:              epochEntry.InitialBlockHeight,
		InitialView:                     epochEntry.InitialView,
		FinalBlockHeight:                epochEntry.FinalBlockHeight,
		InitialLeaderIndexOffset:        epochEntry.InitialLeaderIndexOffset,
		CreatedAtBlockTimestampNanoSecs: epochEntry.CreatedAtBlockTimestampNanoSecs,
	}
}

func (epochEntry *EpochEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, UintToBuf(epochEntry.EpochNumber)...)
	data = append(data, UintToBuf(epochEntry.InitialBlockHeight)...)
	data = append(data, UintToBuf(epochEntry.InitialView)...)
	data = append(data, UintToBuf(epochEntry.FinalBlockHeight)...)
	data = append(data, UintToBuf(epochEntry.InitialLeaderIndexOffset)...)
	data = append(data, IntToBuf(epochEntry.CreatedAtBlockTimestampNanoSecs)...)
	return data
}

func (epochEntry *EpochEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// EpochNumber
	epochEntry.EpochNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "EpochEntry.Decode: Problem reading EpochNumber: ")
	}

	// InitialBlockHeight
	epochEntry.InitialBlockHeight, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "EpochEntry.Decode: Problem reading InitialBlockHeight: ")
	}

	// InitialView
	epochEntry.InitialView, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "EpochEntry.Decode: Problem reading InitialView: ")
	}

	// FinalBlockHeight
	epochEntry.FinalBlockHeight, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "EpochEntry.Decode: Problem reading FinalBlockHeight: ")
	}

	// InitialLeaderIndexOffset
	epochEntry.InitialLeaderIndexOffset, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "EpochEntry.Decode: Problem reading InitialLeaderIndexOffset: ")
	}

	// CreatedAtBlockTimestampNanoSecs
	epochEntry.CreatedAtBlockTimestampNanoSecs, err = ReadVarint(rr)
	if err != nil {
		return errors.Wrapf(err, "EpochEntry.Decode: Problem reading CreatedAtBlockTimestampNanoSecs: ")
	}

	return err
}

func (epochEntry *EpochEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (epochEntry *EpochEntry) GetEncoderType() EncoderType {
	return EncoderTypeEpochEntry
}

func (epochEntry *EpochEntry) ContainsBlockHeight(blockHeight uint64) bool {
	return blockHeight >= epochEntry.InitialBlockHeight && blockHeight <= epochEntry.FinalBlockHeight
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
		return epochEntry, nil
	}

	// If not found, check the database.
	epochEntry, err = DBGetCurrentEpochEntry(bav.Handle, bav.Snapshot)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetCurrentEpoch: problem retrieving EpochEntry from db: ")
	}
	if epochEntry != nil {
		// Cache in the UtxoView.
		bav._setCurrentEpochEntry(epochEntry)
		return epochEntry, nil
	}

	// If still not found, return the GenesisEpochEntry. This will be the
	// case prior to the first execution of the OnEpochCompleteHook.
	genesisEpochEntry := &EpochEntry{
		EpochNumber:                     0,
		InitialBlockHeight:              0,
		InitialView:                     0,
		FinalBlockHeight:                uint64(bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight),
		InitialLeaderIndexOffset:        0,
		CreatedAtBlockTimestampNanoSecs: 0,
	}
	return genesisEpochEntry, nil
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

func (bav *UtxoView) _setCurrentEpochEntry(epochEntry *EpochEntry) {
	if epochEntry == nil {
		glog.Errorf("UtxoView._setCurrentEpochEntry: called with nil EpochEntry")
		return
	}
	bav.CurrentEpochEntry = epochEntry.Copy()
}

func (bav *UtxoView) _flushCurrentEpochEntryToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	if bav.CurrentEpochEntry == nil {
		// It is possible that the current UtxoView never interacted with the CurrentEpochEntry
		// in which case the CurrentEpochEntry in the UtxoView will be nil. In that case, we
		// don't want to overwrite what is in the database. Just no-op.
		return nil
	}
	if err := DBPutCurrentEpochEntryWithTxn(txn, bav.Snapshot, bav.CurrentEpochEntry, blockHeight, bav.EventManager); err != nil {
		return errors.Wrapf(err, "_flushCurrentEpochEntryToDbWithTxn: ")
	}
	return nil
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

func DBPutCurrentEpochEntryWithTxn(txn *badger.Txn, snap *Snapshot, epochEntry *EpochEntry, blockHeight uint64, eventManager *EventManager) error {
	// Set EpochEntry in PrefixCurrentEpoch.
	if epochEntry == nil {
		// This is just a safety check that we are not accidentally overwriting an
		// existing EpochEntry with a nil EpochEntry. This should never happen.
		return errors.New("DBPutCurrentEpochEntryWithTxn: called with nil EpochEntry")
	}
	key := DBKeyForCurrentEpoch()
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, epochEntry), eventManager); err != nil {
		return errors.Wrapf(
			err, "DBPutCurrentEpochEntryWithTxn: problem storing EpochEntry in index PrefixCurrentEpoch: ",
		)
	}
	return nil
}
