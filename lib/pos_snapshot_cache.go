package lib

import (
	"bytes"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
	"math"
	"sort"
	"strconv"
	"sync"
)

// SnapshotCache is a struct that holds cached versions of the end-of-epoch
// snapshot data. This data is used to speed up the process of fetching the
// snapshot data from the database when processing blocks. We only
// ever update the cache with data from the database and never the view.
type SnapshotCache struct {
	// snapshot validator cache
	cachedValidatorsBySnapshotAtEpoch map[uint64][]*ValidatorEntry
	validatorRWLock                   sync.RWMutex

	// snapshot leader schedule cache
	cachedLeaderScheduleBySnapshotAtEpoch map[uint64][]*PKID
	leaderScheduleRWLock                  sync.RWMutex

	// snapshot global params cache
	cachedGlobalParamsBySnapshotAtEpoch map[uint64]*GlobalParamsEntry
	globalParamsRWLock                  sync.RWMutex

	snapshotsCached map[uint64]bool

	// snapshot leader schedule validator. Key is string(snapshotAtEpochNumber)+"L"+string(leaderIndex)
	cachedLeaderScheduleValidatorBySnapshotAtEpoch map[string]*ValidatorEntry

	// TODO: rename this to cachedValidatorBLSPublicKeyPKIDPairBySnapshotAtEpoch
	// snapshot bls public key pkid pair entry by bls public key. Key is string(snapshotAtEpochNumber)+"V"+string(validatorPKID)
	cachedValidatorEntryByBLSPublicKeyBySnapshotAtEpoch map[string]*BLSPublicKeyPKIDPairEntry

	// snapshot validator entry by pkid
	cachedValidatorEntryByPKIDBySnapshotAtEpoch map[string]*ValidatorEntry
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

	snapshotsToLoad := []uint64{}
	for ii := snapshotAtEpochNumber; ii < currentEpochNumber; ii++ {
		snapshotsToLoad = append(snapshotsToLoad, ii)
	}
	for _, epochNumber := range snapshotsToLoad {
		_, err1 := sc.GetSnapshotValidatorSetEntriesByStakeAtEpochNumber(snapshotAtEpochNumber, handle, snapshot, params)
		_, err2 := sc.GetSnapshotLeaderSchedule(snapshotAtEpochNumber, handle)
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
func (sc *SnapshotCache) GetAllCachedSnapshotValidatorSetEntries() (map[uint64][]*ValidatorEntry, bool) {
	if sc == nil {
		return nil, false
	}
	sc.validatorRWLock.RLock()
	defer sc.validatorRWLock.RUnlock()
	return sc.cachedValidatorsBySnapshotAtEpoch, true
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
	if sc != nil {
		sc.validatorRWLock.RLock()
		validatorEntries, exists := sc.cachedValidatorsBySnapshotAtEpoch[snapshotAtEpochNumber]
		sc.validatorRWLock.RUnlock()
		if exists {
			return validatorEntries, nil
		}
	}
	// Pull the global params from the cache/db.
	snapshotGlobalParams, err := sc.GetSnapshotGlobalParams(snapshotAtEpochNumber, handle, snapshot, params)
	if err != nil {
		return nil, errors.Errorf(
			"sc.DBGetSnapshotValidatorSetByStakeAmount: Error fetching snapshot global params: %v", err)
	}
	// Pull all ValidatorEntries from the database.
	dbValidatorEntries, err := DBGetSnapshotValidatorSetByStakeAmount(
		handle, snapshot, snapshotGlobalParams.ValidatorSetMaxNumValidators, snapshotAtEpochNumber, nil,
	)
	if err != nil {
		return nil, errors.Errorf("sc.DBGetSnapshotValidatorSetByStakeAmount: Error fetching validator list: %v", err)
	}

	// Filter the ValidatorEntries.
	filteredValidatorEntries := collections.Filter(dbValidatorEntries, func(validatorEntry *ValidatorEntry) bool {
		return validatorEntry.Status() == ValidatorStatusActive && !validatorEntry.TotalStakeAmountNanos.IsZero()
	})
	// Sort the ValidatorEntries DESC by TotalStakeAmountNanos.
	sort.SliceStable(filteredValidatorEntries, func(ii, jj int) bool {
		stakeCmp := filteredValidatorEntries[ii].TotalStakeAmountNanos.Cmp(filteredValidatorEntries[jj].TotalStakeAmountNanos)
		if stakeCmp == 0 {
			// Use ValidatorPKID as a tie-breaker if equal TotalStakeAmountNanos.
			return bytes.Compare(
				filteredValidatorEntries[ii].ValidatorPKID.ToBytes(),
				filteredValidatorEntries[jj].ValidatorPKID.ToBytes(),
			) > 0
		}
		return stakeCmp > 0
	})
	// Return top N.
	upperBound := int(math.Min(float64(snapshotGlobalParams.ValidatorSetMaxNumValidators),
		float64(len(filteredValidatorEntries))))
	finalValidatorEntries := filteredValidatorEntries[:upperBound]
	if sc != nil {
		// Cache the ValidatorEntries.
		sc.validatorRWLock.Lock()
		sc.cachedValidatorsBySnapshotAtEpoch[snapshotAtEpochNumber] = finalValidatorEntries
		sc.validatorRWLock.Unlock()
	}
	return finalValidatorEntries, nil
}

// GetAllCachedSnapshotGlobalParams returns all cached global params.
func (sc *SnapshotCache) GetAllCachedSnapshotGlobalParams() (map[uint64]*GlobalParamsEntry, bool) {
	if sc == nil {
		return nil, false
	}
	sc.globalParamsRWLock.RLock()
	defer sc.globalParamsRWLock.RUnlock()
	return sc.cachedGlobalParamsBySnapshotAtEpoch, true
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
	if sc != nil {
		sc.globalParamsRWLock.RLock()
		globalParams, exists := sc.cachedGlobalParamsBySnapshotAtEpoch[snapshotAtEpoch]
		sc.globalParamsRWLock.RUnlock()
		if exists {
			return globalParams, nil
		}
	}

	// Fetch the global params for the snapshot epoch number
	dbGlobalParams, err := DBGetSnapshotGlobalParamsEntry(handle, snapshot, snapshotAtEpoch)
	if err != nil {
		return nil, errors.Errorf("sc.GetSnapshotGlobalParams: Error fetching global params: %v", err)
	}
	mergedGlobalParams := MergeGlobalParamEntryDefaults(dbGlobalParams, params)
	if sc != nil {
		// Cache the global params for the snapshot epoch number
		sc.globalParamsRWLock.Lock()
		sc.cachedGlobalParamsBySnapshotAtEpoch[snapshotAtEpoch] = mergedGlobalParams
		sc.globalParamsRWLock.Unlock()
	}
	return mergedGlobalParams, nil
}

// GetAllCachedLeaderSchedules returns all cached leader schedules.
func (sc *SnapshotCache) GetAllCachedLeaderSchedules() (map[uint64][]*PKID, bool) {
	if sc == nil {
		return nil, false
	}
	sc.leaderScheduleRWLock.RLock()
	defer sc.leaderScheduleRWLock.RUnlock()
	return sc.cachedLeaderScheduleBySnapshotAtEpoch, true
}

// GetSnapshotLeaderSchedule returns the leader schedule for the snapshot at the given epoch number.
// If it is not in the cache, it fetches it from the database and caches it.
func (sc *SnapshotCache) GetSnapshotLeaderSchedule(
	snapshotAtEpoch uint64,
	handle *badger.DB,
) ([]*PKID, error) {
	// First check the cache to see if we have the leader schedule for the snapshot epoch number.
	if sc != nil {
		sc.leaderScheduleRWLock.RLock()
		leaderSchedule, exists := sc.cachedLeaderScheduleBySnapshotAtEpoch[snapshotAtEpoch]
		sc.leaderScheduleRWLock.RUnlock()
		if exists {
			return leaderSchedule, nil
		}
	}

	// Fetch the leader schedule for the snapshot epoch number
	dbLeaderSchedule, err := DBSeekSnapshotLeaderSchedule(handle, snapshotAtEpoch)
	if err != nil {
		return nil, errors.Errorf("sc.GetSnapshotLeaderSchedule: Error fetching leader schedule: %v", err)
	}
	var leaderPKIDAndIndexSlice []LeaderPKIDAndIndex
	for mapKey, validatorPKID := range dbLeaderSchedule {
		leaderPKIDAndIndexSlice = append(leaderPKIDAndIndexSlice, LeaderPKIDAndIndex{
			leaderIdx:  mapKey,
			leaderPKID: validatorPKID,
		})
	}
	// Sort the leader schedule by leader index.
	sort.Slice(leaderPKIDAndIndexSlice, func(ii, jj int) bool {
		return leaderPKIDAndIndexSlice[ii].leaderIdx < leaderPKIDAndIndexSlice[jj].leaderIdx
	})
	leaderPKIDs := collections.Transform(leaderPKIDAndIndexSlice, func(index LeaderPKIDAndIndex) *PKID {
		return index.leaderPKID
	})
	if sc != nil {
		// Cache the leader schedule for the snapshot epoch number
		sc.leaderScheduleRWLock.Lock()
		sc.cachedLeaderScheduleBySnapshotAtEpoch[snapshotAtEpoch] = leaderPKIDs
		sc.leaderScheduleRWLock.Unlock()
	}
	return leaderPKIDs, nil
}

func keyForSnapshotLeaderScheduleValidator(snapshotAtEpoch uint64, leaderIndex uint16) string {
	return strconv.FormatUint(snapshotAtEpoch, 10) + "L" + strconv.FormatUint(uint64(leaderIndex), 10)
}

func (sc *SnapshotCache) GetSnapshotLeaderScheduleValidator(
	snapshotAtEpoch uint64,
	leaderIndex uint16,
	handle *badger.DB,
	snapshot *Snapshot,
) (*ValidatorEntry, error) {
	if sc != nil {
		leaderScheduleValidator, exists := sc.cachedLeaderScheduleValidatorBySnapshotAtEpoch[keyForSnapshotLeaderScheduleValidator(snapshotAtEpoch, leaderIndex)]
		if exists {
			return leaderScheduleValidator, nil
		}
	}

	// Fetch the leader schedule for the snapshot epoch number
	validatorEntry, err := DBGetSnapshotLeaderScheduleValidator(handle, snapshot, leaderIndex, snapshotAtEpoch)
	if err != nil {
		return nil, errors.Errorf(
			"sc.GetSnapshotLeaderScheduleValidator: Error fetching leader schedule validator entry: %v", err)
	}
	if sc != nil {
		// Cache the leader schedule for the snapshot epoch number
		sc.cachedLeaderScheduleValidatorBySnapshotAtEpoch[keyForSnapshotLeaderScheduleValidator(snapshotAtEpoch, leaderIndex)] = validatorEntry
	}
	return validatorEntry, nil
}

func keyForSnapshotValidatorEntryByBLSPublicKey(snapshotAtEpoch uint64, blsPublicKey *bls.PublicKey) string {
	return strconv.FormatUint(snapshotAtEpoch, 10) + "V" + blsPublicKey.ToString()
}

func (sc *SnapshotCache) GetSnapshotValidatorEntryByBLSPublicKey(
	snapshotAtEpoch uint64,
	blsPublicKey *bls.PublicKey,
	handle *badger.DB,
	snapshot *Snapshot,
) (*BLSPublicKeyPKIDPairEntry, error) {
	if sc != nil {
		blsPublicKeyPKIDPairEntry, exists := sc.cachedValidatorEntryByBLSPublicKeyBySnapshotAtEpoch[keyForSnapshotValidatorEntryByBLSPublicKey(snapshotAtEpoch, blsPublicKey)]
		if exists {
			return blsPublicKeyPKIDPairEntry, nil
		}
	}

	// Fetch the leader schedule for the snapshot epoch number
	blsPublicKeyPKIDPairEntry, err := DBGetSnapshotValidatorBLSPublicKeyPKIDPairEntry(
		handle, snapshot, blsPublicKey, snapshotAtEpoch)
	if err != nil {
		return nil, errors.Errorf(
			"sc.GetSnapshotValidatorEntryByBLSPublicKey: Error fetching validator entry by BLS public key: %v", err)
	}
	if sc != nil {
		// Cache the leader schedule for the snapshot epoch number
		sc.cachedValidatorEntryByBLSPublicKeyBySnapshotAtEpoch[keyForSnapshotValidatorEntryByBLSPublicKey(snapshotAtEpoch, blsPublicKey)] = blsPublicKeyPKIDPairEntry
	}
	return blsPublicKeyPKIDPairEntry, nil
}

func keyForSnapshotValidatorEntryByPKID(snapshotAtEpoch uint64, pkid *PKID) string {
	return strconv.FormatUint(snapshotAtEpoch, 10) + "P" + pkid.ToString()
}

func (sc *SnapshotCache) GetSnapshotValidatorEntryByPKID(
	snapshotAtEpoch uint64,
	pkid *PKID,
	handle *badger.DB,
	snapshot *Snapshot,
) (*ValidatorEntry, error) {
	if sc != nil {
		validatorEntry, exists := sc.cachedValidatorEntryByPKIDBySnapshotAtEpoch[keyForSnapshotValidatorEntryByPKID(snapshotAtEpoch, pkid)]
		if exists {
			return validatorEntry, nil
		}
	}

	// Fetch the leader schedule for the snapshot epoch number
	validatorEntry, err := DBGetSnapshotValidatorSetEntryByPKID(handle, snapshot, pkid, snapshotAtEpoch)
	if err != nil {
		return nil, errors.Errorf(
			"sc.GetSnapshotValidatorEntryByPKID: Error fetching validator entry by PKID: %v", err)
	}
	if sc != nil {
		// Cache the leader schedule for the snapshot epoch number
		sc.cachedValidatorEntryByPKIDBySnapshotAtEpoch[keyForSnapshotValidatorEntryByPKID(snapshotAtEpoch, pkid)] = validatorEntry
	}
	return validatorEntry, nil
}
