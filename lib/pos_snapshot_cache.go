package lib

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
	"sync"
)

// SnapshotCache is a struct that holds cached versions of the end-of-epoch
// snapshot data. This data is used to speed up the process of fetching the
// snapshot data from the database when processing blocks. We only
// ever update the cache with data from the database and never the view.
type SnapshotCache struct {
	sync.RWMutex

	// snapshot validator cache
	cachedValidatorsBySnapshotAtEpoch map[uint64][]*ValidatorEntry

	// snapshot leader schedule cache
	cachedLeaderScheduleBySnapshotAtEpoch map[uint64][]*PKID

	// snapshot global params cache
	cachedGlobalParamsBySnapshotAtEpoch map[uint64]*GlobalParamsEntry

	snapshotsCached map[uint64]bool
}

func NewSnapshotCache() *SnapshotCache {
	return &SnapshotCache{
		cachedValidatorsBySnapshotAtEpoch:     make(map[uint64][]*ValidatorEntry),
		cachedLeaderScheduleBySnapshotAtEpoch: make(map[uint64][]*PKID),
		cachedGlobalParamsBySnapshotAtEpoch:   make(map[uint64]*GlobalParamsEntry),
		snapshotsCached:                       make(map[uint64]bool),
	}
}

// LoadCacheAtSnapshotAtEpochNumber loads the cache with the snapshot data at the
// given snapshot epoch number and the previous two snapshot at epochs. It should
// only ever be called when committing a block.
func (sc *SnapshotCache) LoadCacheAtSnapshotAtEpochNumber(
	snapshotAtEpochNumber uint64,
	currentEpochNumber uint64,
	handle *badger.DB,
	snapshot *Snapshot,
	params *DeSoParams,
) {
	var snapshotsToLoad []uint64
	for ii := snapshotAtEpochNumber; ii < currentEpochNumber; ii++ {
		snapshotsToLoad = append(snapshotsToLoad, ii)
	}
	for _, epochNumber := range snapshotsToLoad {
		_, err1 := sc.GetSnapshotValidatorSetEntriesByStakeAtEpochNumber(snapshotAtEpochNumber, handle, snapshot, params)
		_, err2 := sc.GetSnapshotLeaderSchedule(snapshotAtEpochNumber, handle, snapshot, params)
		_, err3 := sc.GetSnapshotGlobalParams(snapshotAtEpochNumber, handle, snapshot, params)
		if err1 == nil && err2 == nil && err3 == nil {
			sc.snapshotsCached[epochNumber] = true
		}
	}
	for epochNumber := range sc.snapshotsCached {
		if epochNumber < snapshotAtEpochNumber {
			delete(sc.cachedValidatorsBySnapshotAtEpoch, epochNumber)
			delete(sc.cachedLeaderScheduleBySnapshotAtEpoch, epochNumber)
			delete(sc.cachedGlobalParamsBySnapshotAtEpoch, epochNumber)
			delete(sc.snapshotsCached, epochNumber)
		}
	}
}

// GetAllCachedSnapshotValidatorSetEntries returns all cached validator entries.
func (sc *SnapshotCache) GetAllCachedSnapshotValidatorSetEntries() map[uint64][]*ValidatorEntry {
	sc.RLock()
	defer sc.RUnlock()
	return sc.cachedValidatorsBySnapshotAtEpoch
}

// GetSnapshotValidatorSetEntriesByStakeAtEpochNumber returns the top N validators by stake at the given snapshot
// epoch number.
func (sc *SnapshotCache) GetSnapshotValidatorSetEntriesByStakeAtEpochNumber(
	snapshotAtEpochNumber uint64,
	handle *badger.DB,
	snapshot *Snapshot,
	params *DeSoParams,
) ([]*ValidatorEntry, error) {
	// First check the cache to see if we have the validator entries for the snapshot epoch number.
	sc.RLock()
	validatorEntries, exists := sc.cachedValidatorsBySnapshotAtEpoch[snapshotAtEpochNumber]
	sc.RUnlock()
	if exists {
		return validatorEntries, nil
	}
	// If not found in the cache, create a new view and use it to fetch the validator entries.
	tempView, err := NewUtxoView(handle, params, nil, snapshot, nil)
	if err != nil {
		return nil, errors.Wrap(err, "sc.GetSnapshotLeaderSchedule: Error creating new UtxoView: ")
	}
	// Get the snapshot global params so we know how many validators to fetch.
	snapshotGlobalParams, err := sc.GetSnapshotGlobalParams(snapshotAtEpochNumber, handle, snapshot, params)
	if err != nil {
		return nil, errors.Wrap(
			err, "sc.GetSnapshotValidatorSetEntriesByStakeAtEpochNumber: Error fetching global params: ")
	}
	// Fetch the validator entries for the snapshot epoch number.
	finalValidatorEntries, err := tempView.GetSnapshotValidatorSetByStakeAmountAtEpochNumber(
		snapshotAtEpochNumber, snapshotGlobalParams.ValidatorSetMaxNumValidators)
	if err != nil {
		return nil, errors.Wrap(
			err, "sc.GetSnapshotValidatorSetEntriesByStakeAtEpochNumber: Error fetching validator set: ")
	}
	// Cache the ValidatorEntries.
	sc.Lock()
	sc.cachedValidatorsBySnapshotAtEpoch[snapshotAtEpochNumber] = finalValidatorEntries
	sc.Unlock()
	return finalValidatorEntries, nil
}

// GetAllCachedSnapshotGlobalParams returns all cached global params.
func (sc *SnapshotCache) GetAllCachedSnapshotGlobalParams() map[uint64]*GlobalParamsEntry {
	sc.RLock()
	defer sc.RUnlock()
	return sc.cachedGlobalParamsBySnapshotAtEpoch
}

// GetSnapshotGlobalParams returns the global params for the snapshot at the given epoch number.
// If it is not in the cache, it fetches it from the database and caches it.
func (sc *SnapshotCache) GetSnapshotGlobalParams(
	snapshotAtEpoch uint64,
	handle *badger.DB,
	snapshot *Snapshot,
	params *DeSoParams,
) (*GlobalParamsEntry, error) {
	// First check the cache to see if we have the global params for the snapshot epoch number.
	sc.RLock()
	globalParams, exists := sc.cachedGlobalParamsBySnapshotAtEpoch[snapshotAtEpoch]
	sc.RUnlock()
	if exists {
		return globalParams, nil
	}
	// If not found in the cache, create a new view and use it to fetch the global params.
	tempView, err := NewUtxoView(handle, params, nil, snapshot, nil)
	if err != nil {
		return nil, errors.Wrap(err, "sc.GetSnapshotLeaderSchedule: Error creating new UtxoView: ")
	}
	globalParams, err = tempView.GetSnapshotGlobalParamsEntryByEpochNumber(snapshotAtEpoch)
	if err != nil {
		return nil, errors.Wrap(err, "sc.GetSnapshotGlobalParams: Error fetching global params: ")
	}
	// Cache the global params for the snapshot epoch number
	sc.Lock()
	sc.cachedGlobalParamsBySnapshotAtEpoch[snapshotAtEpoch] = globalParams
	sc.Unlock()
	return globalParams, nil
}

// GetAllCachedLeaderSchedules returns all cached leader schedules.
func (sc *SnapshotCache) GetAllCachedLeaderSchedules() map[uint64][]*PKID {
	sc.RLock()
	defer sc.RUnlock()
	return sc.cachedLeaderScheduleBySnapshotAtEpoch
}

// GetSnapshotLeaderSchedule returns the leader schedule for the snapshot at the given epoch number.
// If it is not in the cache, it fetches it from the database and caches it.
func (sc *SnapshotCache) GetSnapshotLeaderSchedule(
	snapshotAtEpoch uint64,
	handle *badger.DB,
	snapshot *Snapshot,
	params *DeSoParams,
) ([]*PKID, error) {
	// First check the cache to see if we have the leader schedule for the snapshot epoch number.
	sc.RLock()
	leaderSchedule, exists := sc.cachedLeaderScheduleBySnapshotAtEpoch[snapshotAtEpoch]
	sc.RUnlock()
	if exists {
		return leaderSchedule, nil
	}

	// Fetch the leader schedule for the snapshot epoch number
	tempView, err := NewUtxoView(handle, params, nil, snapshot, nil)
	if err != nil {
		return nil, errors.Wrap(err, "sc.GetSnapshotLeaderSchedule: Error creating new UtxoView: ")
	}
	leaderPKIDs, err := tempView.GetSnapshotLeaderScheduleAtEpochNumber(snapshotAtEpoch)
	if err != nil {
		return nil, errors.Wrap(err, "sc.GetSnapshotLeaderSchedule: Error fetching leader schedule: ")
	}
	// Cache the leader schedule for the snapshot epoch number
	sc.Lock()
	sc.cachedLeaderScheduleBySnapshotAtEpoch[snapshotAtEpoch] = leaderPKIDs
	sc.Unlock()
	return leaderPKIDs, nil
}
