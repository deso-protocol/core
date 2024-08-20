package lib

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/dgraph-io/badger/v4"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

//
// TYPES: LockedBalanceEntry
//

// LockedBalanceEntry is a simple struct with different disjoint states:
//
//		(1) UnlockTimestampNanoSecs == VestingEndTimestampNanoSecs
//			This is the unvested case. It represents a lump sum unlock at a given time.
//			The user can unlock the full BalanceBaseUnits AFTER UnlockTimestampNanoSecs.
//			When written to disk, we add a special 'byte' to the database entry key such
//			that we can quickly find all unvested LockedBalanceEntries.
//		(2) UnlockTimestampNanoSecs < VestingEndTimestampNanoSecs
//			This is the vested case. It represents a vest schedule for locked DeSo tokens.
//			The user can unlock a portion of BalanceBaseUnits proportional to
//			how much of the time between (UnlockTimestampNanoSecs, VestingEndTimestampNanoSecs)
//			has passed by the time the balance is unlocked. When writing this LockedBalanceEntry
//	        to disk, we add a special 'byte' to the database entry key such that
//	        we can quickly find all vested LockedBalanceEntries.
//		(3) UnlockTimestampNanoSecs > VestingEndTimestampNanoSecs
//			This shouldn't be possible. Any LockedBalanceEntries where this is the case
//		    are degenerate and should not exist.
//
// These states delineate between vested and unvested LockedBalanceEntries. It's important to note that
// by only specifying the remaining BalanceBaseUnits, UnlockTimestampNanoSecs, and VestingEndTimestampNanoSecs
// this vesting schedule implementation is linear.
type LockedBalanceEntry struct {
	HODLerPKID                  *PKID
	ProfilePKID                 *PKID
	UnlockTimestampNanoSecs     int64
	VestingEndTimestampNanoSecs int64
	BalanceBaseUnits            uint256.Int
	isDeleted                   bool
}

// LockedBalanceEntryKey is a very crucial struct in the design of lockup
//
// Consider a naive utilization of LockedBalanceEntryMapKey in the context of two subsequent vested unlocks
// WITHOUT flushing to db in-between. Assume that there exists a vested locked balance entry in the db
// and that the view is empty at the start. We will step through how the code would read from disk and the
// UtxoView when performing these two unlocks:
//
//		(1st Unlock, blockTimestampNanoSecs=x+100)
//			(1) We read from disk the LockedBalanceEntry with UnlockTimestampNanoSecs=x
//	     	(2) We cache the entry found in-memory (i.e. in the UtxoView)
//	     	(3) We read from the in-memory cache the LockedBalanceEntry with UnlockTimestampNanoSecs=x
//			(4) We update the in-memory entry to have UnlockTimestampNanoSecs=x+100.
//				NOTE: At this step, there is no entry in the UtxoView view with an UnlockTimestampNanoSecs=x.
//					  This is an issue as we will see in the next unlock as we will read duplicate entries from the db.
//		(2nd Unlock, blockTimestampNanoSecs=x+150)
//			(1) We read from disk the LockedBalanceEntry with UnlockTimestampNanoSecs=x
//	       	(2) Because no other entry in-memory has UnlockTimestampNanoSecs=x, we cache a duplicate entry in-memory
//			(3) We read from the in-memory cache the two LockedBalanceEntries with UnlockTimestampNanoSecs={x,x+100}
//	       	(4) We update the in-memory entries to both {x+150,x+150}
//	       	(5) <buggy behavior to follow>
//
// NOTE: While it may seem that there's an error on the 1st unlock step #4 as we do not check to see if there's
// a conflicting on-disk LockedBalanceEntry with UnlockTimestampNanoSecs=x+100 that must be consolidated,
// we're assuming that consolidation happens on the lockup transaction rather than the unlock transaction.
// This means that it's impossible there's two vested LockedBalanceEntries who have ANY overlap in their
// (UnlockTimestampNanoSecs, VestingEndTimestampNanoSecs) pairs. That is to say, this would not cause
// a bug in this specific implementation.
//
// At the heart, this problem exists because what is semantically the same LockedBalanceEntry did not have a
// way of deduplicating the on-disk and in-memory versions given the updated UnlockTimestampNanoSecs.
// This is not ideal, and would likely be the root of more complicated problems if not dealt with.
//
// To solve this problem, we opt to deduplicate the in-memory and on-disk entries via a careful utilization of
// the isDeleted field in the various transaction connects related to lockups. For instance, in the case
// where we deal with two subsequent unlocks we must both mark the previous in-memory entry with isDeleted=true and
// store a semantically duplicate entry with the updatedUnlockTimestampNanoSecs with isDeleted=false. To show how
// this would work on the previous example:
//
//		(1st Unlock, blockTimestampNanoSecs=x+100)
//			(1) We read from disk the LockedBalanceEntry with UnlockTimestampNanoSecs=x
//		    (2) We cache the entry found in-memory (i.e. in the UtxoView)
//		    (3) We read from the in-memory cache the LockedBalanceEntry with UnlockTimestampNanoSecs=x
//			(4) We update the entry to have UnlockTimestampNanoSecs=x+100
//	        (5) We delete the original LockedBalanceEntry with UnlockTimestampNanoSecs from the view
//	        (6) We set the updated LockedBalanceEntry in-memory
//		(2nd Unlock, blockTimestampNanoSecs=x+150)
//			(1) We read from disk the LockedBalanceEntry with UnlockTimestampNanoSecs=x
//			(2) We see an equivalent entry in the view with isDeleted=true,
//				meaning we do NOT cache this entry in-memory.
//			(3) We read from the in-memory cache the LockedBalanceEntry with UnlockTimestampNanoSecs=x+100
//		    (4) We update the entry to have UnlockTimestampNanoSecs=x+100
//		    (5) We set the updated LockedBalanceEntry in-memory
//
// The difference here is the LockedBalanceEntry is not duplicated in-memory on repetitive reads between flushes.
// This is a crucial difference to prevent odd and dangerous caching bugs from happening. It's important
// to note we could instead utilize a UUID on the LockedBalanceEntry that persists across transactions,
// but this creates difficulties around consolidations and (possible) future transfers. While ideally we would
// opt to avoid consolidations, consolidations are inevitable either on lockup or on unlock to ensure on-disk
// entries do not get inadvertently overwritten.
//
// In summary, whenever changing logic that touches in-memory (i.e. in the UtxoView) LockedBalanceEntries,
// make sure of the following:
// IF modifying a LockedBalanceEntry in the UtxoView, THEN ensure to delete the original
// LockedBalanceEntry under the original LockedBalanceEntryKey AND set the new LockedBalanceEntry
// under the new and different LockedBalanceEntryKey in the view.
type LockedBalanceEntryKey struct {
	HODLerPKID                  PKID
	ProfilePKID                 PKID
	UnlockTimestampNanoSecs     int64
	VestingEndTimestampNanoSecs int64
}

func (lockedBalanceEntry *LockedBalanceEntry) Copy() *LockedBalanceEntry {
	return &LockedBalanceEntry{
		HODLerPKID:                  lockedBalanceEntry.HODLerPKID.NewPKID(),
		ProfilePKID:                 lockedBalanceEntry.ProfilePKID.NewPKID(),
		UnlockTimestampNanoSecs:     lockedBalanceEntry.UnlockTimestampNanoSecs,
		VestingEndTimestampNanoSecs: lockedBalanceEntry.VestingEndTimestampNanoSecs,
		BalanceBaseUnits:            *lockedBalanceEntry.BalanceBaseUnits.Clone(),
		isDeleted:                   lockedBalanceEntry.isDeleted,
	}
}

func (lockedBalanceEntry *LockedBalanceEntry) ToMapKey() LockedBalanceEntryKey {
	return LockedBalanceEntryKey{
		HODLerPKID:                  *lockedBalanceEntry.HODLerPKID,
		ProfilePKID:                 *lockedBalanceEntry.ProfilePKID,
		UnlockTimestampNanoSecs:     lockedBalanceEntry.UnlockTimestampNanoSecs,
		VestingEndTimestampNanoSecs: lockedBalanceEntry.VestingEndTimestampNanoSecs,
	}
}

func (lockedBalanceEntry *LockedBalanceEntry) IsDeleted() bool {
	return lockedBalanceEntry.isDeleted
}

// DeSoEncoder Interface Implementation for LockedBalanceEntry

func (lockedBalanceEntry *LockedBalanceEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, lockedBalanceEntry.HODLerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, lockedBalanceEntry.ProfilePKID, skipMetadata...)...)
	data = append(data, IntToBuf(lockedBalanceEntry.UnlockTimestampNanoSecs)...)
	data = append(data, IntToBuf(lockedBalanceEntry.VestingEndTimestampNanoSecs)...)
	data = append(data, EncodeByteArray(lockedBalanceEntry.BalanceBaseUnits.Bytes())...)
	return data
}

func (lockedBalanceEntry *LockedBalanceEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// HODLerPKID
	lockedBalanceEntry.HODLerPKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrap(err, "LockedBalanceEntry.Decode: Problem reading HODLerPKID")
	}

	// ProfilePKID
	lockedBalanceEntry.ProfilePKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrap(err, "LockedBalanceEntry.Decode: Problem reading ProfilePKID")
	}

	// UnlockTimestampNanoSecs
	lockedBalanceEntry.UnlockTimestampNanoSecs, err = ReadVarint(rr)
	if err != nil {
		return errors.Wrap(err, "LockedBalanceEntry.Decode: Problem reading UnlockTimestampNanoSecs")
	}

	// VestingEndTimestampNanoSecs
	lockedBalanceEntry.VestingEndTimestampNanoSecs, err = ReadVarint(rr)
	if err != nil {
		return errors.Wrap(err, "LockedBalanceEntry.Decode: Problem reading VestingEndTimestampNanoSecs")
	}

	// BalanceBaseUnits
	balanceBaseUnitsBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrap(err, "LockedBalanceEntry.Decode: Problem reading BalanceBaseUnits")
	}
	lockedBalanceEntry.BalanceBaseUnits = *uint256.NewInt(0).SetBytes(balanceBaseUnitsBytes)

	return nil
}

func (lockedBalanceEntry *LockedBalanceEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (lockedBalanceEntry *LockedBalanceEntry) GetEncoderType() EncoderType {
	return EncoderTypeLockedBalanceEntry
}

// Set and Delete Functions for LockedBalanceEntry

func (bav *UtxoView) _setLockedBalanceEntry(lockedBalanceEntry *LockedBalanceEntry) {
	// This function shouldn't be called with nil.
	if lockedBalanceEntry == nil {
		glog.Errorf("_setLockedBalanceEntry: Called with nil LockedBalanceEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the LockedBalanceEntry in the view.
	bav.LockedBalanceEntryKeyToLockedBalanceEntry[lockedBalanceEntry.ToMapKey()] = lockedBalanceEntry
}

func (bav *UtxoView) _deleteLockedBalanceEntry(lockedBalanceEntry *LockedBalanceEntry) {
	// This function shouldn't be called with nil.
	if lockedBalanceEntry == nil {
		glog.Errorf("_deleteLockedBalanceEntry: Called with nil LockedBalanceEntry; " +
			"this should never happen.")
		return
	}

	// Create a tombstone entry.
	tombstoneLockedBalanceEntry := lockedBalanceEntry.Copy()
	tombstoneLockedBalanceEntry.isDeleted = true

	// Set the LockedBalanceEntry as deleted in the view.
	bav._setLockedBalanceEntry(tombstoneLockedBalanceEntry)
}

// Get Helper Functions for LockedBalanceEntry

func (bav *UtxoView) GetAllLockedBalanceEntriesForHodlerPKID(
	hodlerPKID *PKID,
) (
	_lockedBalanceEntries []*LockedBalanceEntry,
	_err error,
) {
	// Pull entries from db.
	dbLockedBalanceEntries, err := DBGetAllLockedBalanceEntriesForHodlerPKID(bav.Handle, hodlerPKID)
	if err != nil {
		return nil,
			errors.Wrap(err, "GetLockedBalanceEntryForLockedBalanceEntryKey")
	}

	// Cache entries found in the db.
	for _, lockedBalanceEntry := range dbLockedBalanceEntries {
		if _, exists := bav.LockedBalanceEntryKeyToLockedBalanceEntry[lockedBalanceEntry.ToMapKey()]; !exists {
			bav._setLockedBalanceEntry(lockedBalanceEntry)
		}
	}

	// Pull relevant entries from the view and return.
	var lockedBalanceEntries []*LockedBalanceEntry
	for _, lockedBalanceEntry := range bav.LockedBalanceEntryKeyToLockedBalanceEntry {
		if lockedBalanceEntry.HODLerPKID.Eq(hodlerPKID) && !lockedBalanceEntry.isDeleted {
			lockedBalanceEntries = append(lockedBalanceEntries, lockedBalanceEntry)
		}
	}

	// Sort by unlock time for convenience.
	sort.Slice(lockedBalanceEntries, func(ii, jj int) bool {
		return lockedBalanceEntries[ii].UnlockTimestampNanoSecs <
			lockedBalanceEntries[jj].UnlockTimestampNanoSecs
	})

	return lockedBalanceEntries, nil
}

func (bav *UtxoView) GetLockedBalanceEntryForLockedBalanceEntryKey(
	lockedBalanceEntryKey LockedBalanceEntryKey,
) (
	_lockedBalanceEntry *LockedBalanceEntry,
	_err error,
) {
	// Check if the key exists in the view.
	if viewEntry, viewEntryExists :=
		bav.LockedBalanceEntryKeyToLockedBalanceEntry[lockedBalanceEntryKey]; viewEntryExists {
		if viewEntry == nil || viewEntry.isDeleted {
			return nil, nil
		}
		return viewEntry, nil
	}

	// No mapping exists in the view, check for an entry in the db.
	lockedBalanceEntry, err := DBGetLockedBalanceEntryForLockedBalanceEntryKey(
		bav.Handle, bav.Snapshot, lockedBalanceEntryKey)
	if err != nil {
		return nil,
			errors.Wrap(err, "GetLockedBalanceEntryForLockedBalanceEntryKey")
	}

	// Cache the DB entry in the in-memory map.
	if lockedBalanceEntry != nil {
		bav._setLockedBalanceEntry(lockedBalanceEntry)
	}

	return lockedBalanceEntry, nil
}

func (bav *UtxoView) GetLimitedVestedLockedBalanceEntriesOverTimeInterval(
	hodlerPKID *PKID,
	profilePKID *PKID,
	unlockTimestampNanoSecs int64,
	vestingEndTimestampNanoSecs int64,
	limitToFetch int,
) (
	_lockedBalanceEntries []*LockedBalanceEntry,
	_err error,
) {
	// Step 1: Fetch a limited number of vested locked balance entries from the view.
	// 		   Any modified/deleted locked balance entries should have .isDeleted=true
	//         preventing them from being re-read into the view. The fact that modified
	//         locked balance entries have .isDeleted=True is a unique feature that
	//		   occurs because keys on locked balance entries can change with time for the same
	//         semantically equivalent value.
	//		   Also note, we read a limited number of entries based on the passed limitToFetch
	//         to prevent excessive reads to the db. We explicitly check if the error occurs
	//		   as a result of over-reading the db or from other db errors.
	vestedLockedBalanceEntries, err := DBGetLimitedVestedLockedBalanceEntries(
		bav.Handle,
		hodlerPKID,
		profilePKID,
		unlockTimestampNanoSecs,
		vestingEndTimestampNanoSecs,
		limitToFetch)
	if err != nil {
		return nil,
			errors.Wrap(err, "GetLimitedVestedLockedBalanceEntriesOverTimeInterval")
	}

	// Step 2: Cache the fetched locked balance entries from the view into the db.
	//		   Again, any existing modified/deleted vested locked balance entries should result in no insert.
	for _, lockedBalanceEntry := range vestedLockedBalanceEntries {
		if _, exists := bav.LockedBalanceEntryKeyToLockedBalanceEntry[lockedBalanceEntry.ToMapKey()]; !exists {
			bav._setLockedBalanceEntry(lockedBalanceEntry)
		}
	}

	// Step 3: Read from the view the relevant vested locked balance entries.
	//		   Note that if we over-read the view, meaning we find more than limitToFetch relevant entries,
	// 		   we will throw a rule error.
	//		   Also note, this operation is currently quite inefficient as it iterates through all locked
	//		   balance entries in the view. In the future, it may be necessary to replace the
	//		   LockedBalanceEntryKeyToLockedBalanceEntry field of UtxoView with an optimized B-tree implementation.
	//		   We could opt to use an ordered map, but the Go implementation would sort on insertion time.
	var lockedBalanceEntries []*LockedBalanceEntry
	for _, lockedBalanceEntry := range bav.LockedBalanceEntryKeyToLockedBalanceEntry {
		// A relevant vested locked balance entry satisfies all the following conditions:
		//	(1) Matching profile PKID
		//  (2) Matching hodler PKID
		//  (3) An unlock OR end timestamp within the specified (unlock, end) bounds OR
		//		the lockedBalanceEntry interval is a superset of the specified (unlock, end) bounds
		//	(4) A mismatched unlock and vesting end timestamp (vesting condition)
		//  (5) Not deleted
		if lockedBalanceEntry.ProfilePKID.Eq(profilePKID) &&
			lockedBalanceEntry.HODLerPKID.Eq(hodlerPKID) &&
			((lockedBalanceEntry.UnlockTimestampNanoSecs >= unlockTimestampNanoSecs &&
				lockedBalanceEntry.UnlockTimestampNanoSecs <= vestingEndTimestampNanoSecs) ||
				(lockedBalanceEntry.VestingEndTimestampNanoSecs >= unlockTimestampNanoSecs &&
					lockedBalanceEntry.VestingEndTimestampNanoSecs <= vestingEndTimestampNanoSecs) ||
				(lockedBalanceEntry.UnlockTimestampNanoSecs < unlockTimestampNanoSecs &&
					lockedBalanceEntry.VestingEndTimestampNanoSecs > vestingEndTimestampNanoSecs)) &&
			lockedBalanceEntry.UnlockTimestampNanoSecs != lockedBalanceEntry.VestingEndTimestampNanoSecs &&
			!lockedBalanceEntry.isDeleted {
			lockedBalanceEntries = append(lockedBalanceEntries, lockedBalanceEntry)
		}

		// If we've fetched more than we're permitted, we throw an error.
		if len(lockedBalanceEntries) > limitToFetch {
			return nil, errors.Wrap(RuleErrorCoinLockupViolatesVestingIntersectionLimit,
				"GetLimitedVestedLockedBalanceEntriesOverTimeInterval")
		}
	}

	// Step 4: Sort by unlock time.
	sort.Slice(lockedBalanceEntries, func(ii, jj int) bool {
		return lockedBalanceEntries[ii].UnlockTimestampNanoSecs <
			lockedBalanceEntries[jj].UnlockTimestampNanoSecs
	})

	return lockedBalanceEntries, nil
}

func (bav *UtxoView) GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
	hodlerPKID *PKID,
	profilePKID *PKID,
	unlockTimestampNanoSecs int64,
	vestingEndTimestampNanoSecs int64,
) (
	_lockedBalanceEntry *LockedBalanceEntry,
	_err error,
) {
	// Create a key associated with the LockedBalanceEntry.
	lockedBalanceEntryKey := (&LockedBalanceEntry{
		HODLerPKID:                  hodlerPKID,
		ProfilePKID:                 profilePKID,
		UnlockTimestampNanoSecs:     unlockTimestampNanoSecs,
		VestingEndTimestampNanoSecs: vestingEndTimestampNanoSecs,
	}).ToMapKey()

	// Check if the key exists in the view.
	if viewEntry, viewEntryExists :=
		bav.LockedBalanceEntryKeyToLockedBalanceEntry[lockedBalanceEntryKey]; viewEntryExists {
		if viewEntry == nil || viewEntry.isDeleted {
			return nil, nil
		}
		return viewEntry, nil
	}

	// No mapping exists in the view, check for an entry in the DB.
	lockedBalanceEntry, err :=
		DBGetLockedBalanceEntryForLockedBalanceEntryKey(bav.Handle, bav.Snapshot, lockedBalanceEntryKey)
	if err != nil {
		return nil,
			errors.Wrap(err,
				"GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs")
	}

	// Cache the DB entry in the in-memory map.
	if lockedBalanceEntry != nil {
		bav._setLockedBalanceEntry(lockedBalanceEntry)
	}

	return lockedBalanceEntry, nil
}

func (bav *UtxoView) GetUnlockableLockedBalanceEntries(
	hodlerPKID *PKID,
	profilePKID *PKID,
	currentTimestampNanoSecs int64,
) (
	_unvestedUnlockabeLockedBalanceEntries []*LockedBalanceEntry,
	_vestedUnlockableLockedEntries []*LockedBalanceEntry,
	_err error,
) {
	// Validate inputs.
	if hodlerPKID == nil {
		return nil, nil,
			errors.New("UtxoView.GetUnlockableLockedBalanceEntries: nil hodlerPKID provided as input")
	}
	if profilePKID == nil {
		return nil, nil,
			errors.New("UtxoView.GetUnlockableLockedBalanceEntries: nil profilePKID provided as input")
	}

	// First, pull unlockable LockedBalanceEntries from the db and cache them in the UtxoView.
	dbUnvestedUnlockableLockedBalanceEntries, dbVestedUnlockableLockedBalanceEntries, err :=
		DBGetUnlockableLockedBalanceEntries(bav.Handle, hodlerPKID, profilePKID, currentTimestampNanoSecs)
	if err != nil {
		return nil, nil,
			errors.Wrap(err, "UtxoView.GetUnlockableLockedBalanceEntries")
	}
	for _, lockedBalanceEntry := range dbUnvestedUnlockableLockedBalanceEntries {
		// Cache results in the UtxoView.
		if _, exists := bav.LockedBalanceEntryKeyToLockedBalanceEntry[lockedBalanceEntry.ToMapKey()]; !exists {
			bav._setLockedBalanceEntry(lockedBalanceEntry)
		}
	}
	for _, lockedBalanceEntry := range dbVestedUnlockableLockedBalanceEntries {
		// Cache results in the UtxoView.
		if _, exists := bav.LockedBalanceEntryKeyToLockedBalanceEntry[lockedBalanceEntry.ToMapKey()]; !exists {
			bav._setLockedBalanceEntry(lockedBalanceEntry)
		}
	}

	// Then, pull unlockable LockedBalanceEntries from the UtxoView.
	var unlockableUnvestedLockedBalanceEntries []*LockedBalanceEntry
	var unlockableVestedLockedBalanceEntries []*LockedBalanceEntry
	for _, lockedBalanceEntry := range bav.LockedBalanceEntryKeyToLockedBalanceEntry {
		// Filter to matching LockedBalanceEntries.
		if !lockedBalanceEntry.HODLerPKID.Eq(hodlerPKID) ||
			!lockedBalanceEntry.ProfilePKID.Eq(profilePKID) ||
			lockedBalanceEntry.UnlockTimestampNanoSecs >= currentTimestampNanoSecs ||
			lockedBalanceEntry.BalanceBaseUnits.IsZero() ||
			lockedBalanceEntry.isDeleted {
			continue
		}
		if lockedBalanceEntry.UnlockTimestampNanoSecs == lockedBalanceEntry.VestingEndTimestampNanoSecs {
			unlockableUnvestedLockedBalanceEntries = append(unlockableUnvestedLockedBalanceEntries, lockedBalanceEntry)
		} else {
			unlockableVestedLockedBalanceEntries = append(unlockableVestedLockedBalanceEntries, lockedBalanceEntry)
		}
	}

	// Sort UnlockableLockedBalanceEntries by timestamp ASC.
	sort.Slice(unlockableUnvestedLockedBalanceEntries, func(ii, jj int) bool {
		return unlockableUnvestedLockedBalanceEntries[ii].UnlockTimestampNanoSecs <
			unlockableUnvestedLockedBalanceEntries[jj].UnlockTimestampNanoSecs
	})
	sort.Slice(unlockableVestedLockedBalanceEntries, func(ii, jj int) bool {
		return unlockableVestedLockedBalanceEntries[ii].UnlockTimestampNanoSecs <
			unlockableVestedLockedBalanceEntries[jj].UnlockTimestampNanoSecs
	})
	return unlockableUnvestedLockedBalanceEntries, unlockableVestedLockedBalanceEntries, nil
}

//
// TYPES: LockupYieldCurvePoint
//

type LockupYieldCurvePoint struct {
	ProfilePKID               *PKID
	LockupDurationNanoSecs    int64
	LockupYieldAPYBasisPoints uint64
	isDeleted                 bool
}

type LockupYieldCurvePointKey struct {
	ProfilePKID            PKID
	LockupDurationNanoSecs int64
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) Copy() *LockupYieldCurvePoint {
	return &LockupYieldCurvePoint{
		ProfilePKID:               lockupYieldCurvePoint.ProfilePKID.NewPKID(),
		LockupDurationNanoSecs:    lockupYieldCurvePoint.LockupDurationNanoSecs,
		LockupYieldAPYBasisPoints: lockupYieldCurvePoint.LockupYieldAPYBasisPoints,
		isDeleted:                 lockupYieldCurvePoint.isDeleted,
	}
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) Eq(other *LockupYieldCurvePoint) bool {
	return lockupYieldCurvePoint.ToMapKey() == other.ToMapKey()
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) ToMapKey() LockupYieldCurvePointKey {
	return LockupYieldCurvePointKey{
		ProfilePKID:            *lockupYieldCurvePoint.ProfilePKID,
		LockupDurationNanoSecs: lockupYieldCurvePoint.LockupDurationNanoSecs,
	}
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) IsDeleted() bool {
	return lockupYieldCurvePoint.isDeleted
}

// DeSoEncoder Interface Implementation for LockupYieldCurvePoint

func (lockupYieldCurvePoint *LockupYieldCurvePoint) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, lockupYieldCurvePoint.ProfilePKID, skipMetadata...)...)
	data = append(data, IntToBuf(lockupYieldCurvePoint.LockupDurationNanoSecs)...)
	data = append(data, UintToBuf(lockupYieldCurvePoint.LockupYieldAPYBasisPoints)...)
	return data
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// ProfilePKID
	lockupYieldCurvePoint.ProfilePKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrap(err, "LockupYieldCurvePoint.Decode: Problem reading ProfilePKID")
	}

	// LockupDurationNanoSecs
	lockupYieldCurvePoint.LockupDurationNanoSecs, err = ReadVarint(rr)
	if err != nil {
		return errors.Wrap(err, "LockupYieldCurvePoint.Decode: Problem reading LockupDurationNanoSecs")
	}

	// LockupYieldAPYBasisPoints
	lockupYieldCurvePoint.LockupYieldAPYBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrap(err, "LockupYieldCurvePoint.Decode: Problem reading LockupYieldAPYBasisPoints")
	}

	return nil
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) GetEncoderType() EncoderType {
	return EncoderTypeLockupYieldCurvePoint
}

// Set and Delete Functions for LockupYieldCurvePoints

func (bav *UtxoView) _setLockupYieldCurvePoint(point *LockupYieldCurvePoint) {
	// This function shouldn't be called with nil.
	if point == nil {
		glog.Errorf("_setLockupYieldCurvePoint: Called with nil LockupYieldCurvePoint; " +
			"this should never happen.")
		return
	}

	// Check if the PKID needs a map added to the view.
	if _, mapExists := bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*point.ProfilePKID]; !mapExists {
		bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*point.ProfilePKID] =
			make(map[LockupYieldCurvePointKey]*LockupYieldCurvePoint)
	}

	// Set the LockupYieldCurvePoint in the view.
	bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*point.ProfilePKID][point.ToMapKey()] = point
}

func (bav *UtxoView) _deleteLockupYieldCurvePoint(point *LockupYieldCurvePoint) {
	// This function shouldn't be called with nil.
	if point == nil {
		glog.Errorf("_deleteLockupYieldCurvePoint: Called with nil LockupYieldCurvePoint; " +
			"this should never happen.")
		return
	}

	// Create a tombstone entry.
	tombstoneLockupYieldCurvePoint := point.Copy()
	tombstoneLockupYieldCurvePoint.isDeleted = true

	// Set the LockupYieldCurvePoint as deleted in the view.
	bav._setLockupYieldCurvePoint(tombstoneLockupYieldCurvePoint)
}

// Get Helper Functions for LockupYieldCurvePoint

func (bav *UtxoView) GetYieldCurvePointByProfilePKIDAndDurationNanoSecs(profilePKID *PKID,
	lockupDurationNanoSecs int64) (_lockupYieldCurvePoint *LockupYieldCurvePoint, _err error) {
	var lockupYieldCurvePoint *LockupYieldCurvePoint
	var err error

	// Check the view for a yield curve point.
	if _, pointsInView := bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID]; pointsInView {
		lockupYieldCurvePointKey := (&LockupYieldCurvePoint{
			ProfilePKID:            profilePKID,
			LockupDurationNanoSecs: lockupDurationNanoSecs,
		}).ToMapKey()
		if inMemoryYieldCurvePoint, pointExists :=
			bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID][lockupYieldCurvePointKey]; pointExists {
			if inMemoryYieldCurvePoint == nil || inMemoryYieldCurvePoint.isDeleted {
				return nil, nil
			}
			return inMemoryYieldCurvePoint, nil
		}
	}

	// No mapping exists in the view, check for an entry in the DB.
	lockupYieldCurvePoint, err = DBGetYieldCurvePointsByProfilePKIDAndDurationNanoSecs(bav.GetDbAdapter().badgerDb,
		bav.Snapshot, profilePKID, lockupDurationNanoSecs)
	if err != nil {
		return nil, errors.Wrap(err, "GetYieldCurvePointByProfilePKIDAndDurationNanoSecs")
	}

	// Cache the DB entry in the in-memory map.
	if lockupYieldCurvePoint != nil {
		bav._setLockupYieldCurvePoint(lockupYieldCurvePoint)
	}

	return lockupYieldCurvePoint, nil
}

// GetLocalYieldCurvePoints is used when trying to figure out what yield to award a user for a coin lockup
// transaction. Consider a profile who has generated the following yield curve: {0.5 years: 5%, 2 years: 10%}
// While this yield curve is simple, what should happen in the event where a lockup of length 1 year occurs?
// In this case it's convenient to provide the "local" points meaning those points on the yield curve closest
// to the one year lockup duration. If GetLocalYieldCurvePoints was called in this case, it would return
// 0.5 years @ 5% as the leftLockupPoint and 2 years @ 10% as the rightLockupPoint.
//
// To be more specific, the leftLockupPoint returned will always be greatest yield curve point with a
// LockupDurationNanoSecs less than the lockupDuration provided. The rightLockupPoint returned will
// always be the least yield curve point with a LockupDurationNanoSecs greater than or equal to the lockupDuration
// provided.
func (bav *UtxoView) GetLocalYieldCurvePoints(profilePKID *PKID, lockupDuration int64) (
	_leftLockupPoint *LockupYieldCurvePoint, _rightLockupPoint *LockupYieldCurvePoint, _err error) {
	var leftLockupPoint *LockupYieldCurvePoint
	var rightLockupPoint *LockupYieldCurvePoint

	// Fetch all yield curve points in the db.
	dbYieldCurvePoints, err := DBGetAllYieldCurvePointsByProfilePKID(
		bav.GetDbAdapter().badgerDb, bav.Snapshot, profilePKID)
	if err != nil {
		return nil, nil, errors.Wrap(err, "GetLocalYieldCurvePoints")
	}

	// Cache the db points in the view.
	// While there's more efficient ways to do this with specialized badger seek operations, this is sufficient for now.
	if len(dbYieldCurvePoints) > 0 {
		// Check if there's a yield curve in the view for the associated profile.
		if _, mapInView := bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID]; !mapInView {
			bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID] =
				make(map[LockupYieldCurvePointKey]*LockupYieldCurvePoint)
		}

		// Check if any of the points needs to be cached in the view.
		for _, yieldCurvePoint := range dbYieldCurvePoints {
			_, pointInView :=
				bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID][yieldCurvePoint.ToMapKey()]
			if !pointInView {
				bav._setLockupYieldCurvePoint(yieldCurvePoint)
			}
		}
	}

	// Check the view for yield curve points.
	if _, pointsInView := bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID]; pointsInView {
		for _, lockupYieldCurvePoint := range bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID] {
			// Ensure the point is not deleted.
			if lockupYieldCurvePoint.isDeleted {
				continue
			}

			// Check for nil pointer cases.
			if lockupYieldCurvePoint.LockupDurationNanoSecs < lockupDuration && leftLockupPoint == nil {
				leftLockupPoint = lockupYieldCurvePoint.Copy()
			}
			if lockupYieldCurvePoint.LockupDurationNanoSecs >= lockupDuration && rightLockupPoint == nil {
				rightLockupPoint = lockupYieldCurvePoint.Copy()
			}

			// Check if the point is "more left" than the current left point.
			if lockupYieldCurvePoint.LockupDurationNanoSecs < lockupDuration &&
				lockupYieldCurvePoint.LockupDurationNanoSecs > leftLockupPoint.LockupDurationNanoSecs {
				leftLockupPoint = lockupYieldCurvePoint.Copy()
			}

			// Check if the point is "more right" than the current right point.
			if lockupYieldCurvePoint.LockupDurationNanoSecs >= lockupDuration &&
				lockupYieldCurvePoint.LockupDurationNanoSecs < rightLockupPoint.LockupDurationNanoSecs {
				rightLockupPoint = lockupYieldCurvePoint.Copy()
			}
		}
	}

	return leftLockupPoint, rightLockupPoint, nil
}

func (bav *UtxoView) GetAllYieldCurvePoints(
	profilePKID *PKID,
) (
	map[LockupYieldCurvePointKey]*LockupYieldCurvePoint,
	error,
) {
	// Fetch all yield curve points in the db.
	dbYieldCurvePoints, err := DBGetAllYieldCurvePointsByProfilePKID(
		bav.GetDbAdapter().badgerDb, bav.Snapshot, profilePKID)
	if err != nil {
		return nil, errors.Wrap(err, "GetLocalYieldCurvePoints")
	}

	// Cache the db points in the view.
	// While there's more efficient ways to do this with specialized badger seek operations, this is sufficient for now.
	if len(dbYieldCurvePoints) > 0 {
		// Check if there's a yield curve in the view for the associated profile.
		if _, mapInView := bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID]; !mapInView {
			bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID] =
				make(map[LockupYieldCurvePointKey]*LockupYieldCurvePoint)
		}

		// Check if any of the points needs to be cached in the view.
		for _, yieldCurvePoint := range dbYieldCurvePoints {
			_, pointInView :=
				bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID][yieldCurvePoint.ToMapKey()]
			if !pointInView {
				bav._setLockupYieldCurvePoint(yieldCurvePoint)
			}
		}
	}

	return bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID], nil
}

//
// TYPES: CoinLockupMetadata
//

type CoinLockupMetadata struct {
	// The profile public key is the profile who's associated DAO coins we wish to lockup.
	ProfilePublicKey *PublicKey

	// The recipient of the locked DAO coins following execution of the transaction.
	RecipientPublicKey *PublicKey

	// The UnlockTimestampNanoSecs specifies when the recipient should begin to be able to unlock
	// their locked DAO coins.
	UnlockTimestampNanoSecs int64

	// If VestingEndTimestampNanoSecs is equal to UnlockTimestampNanoSecs, the user will be able to unlock
	// all locked DAO coins associated with this transaction once a block whose header timestamp is
	// greater to or equal to UnlockTimestampNanoSecs. This is the "unvested" or "point" case.
	//
	// If not equal to UnlockTimestampNanoSecs, the user can unlock the associated DAO coins once
	// a block with header timestamp greater to or equal to UnlockTimestampNanoSecs, but will only
	// receive tokens in proportion to the amount of time that has passed between UnlockTimestampNanoSecs
	// and VestingEndTimestampNanoSecs. This is the "vested" case.
	VestingEndTimestampNanoSecs int64

	// LockupAmountBaseUnits specifies The amount of locked ProfilePublicKey DAO coins to be
	// placed in a LockedBalanceEntry and given to RecipientPublicKey.
	LockupAmountBaseUnits *uint256.Int
}

func (txnData *CoinLockupMetadata) GetTxnType() TxnType {
	return TxnTypeCoinLockup
}

func (txnData *CoinLockupMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.RecipientPublicKey.ToBytes())...)
	data = append(data, IntToBuf(txnData.UnlockTimestampNanoSecs)...)
	data = append(data, IntToBuf(txnData.VestingEndTimestampNanoSecs)...)
	data = append(data, VariableEncodeUint256(txnData.LockupAmountBaseUnits)...)
	return data, nil
}

func (txnData *CoinLockupMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrap(err, "CoinLockupMetadata.FromBytes: Problem reading ProfilePublicKey")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// RecipientPublicKey
	recipientPublicKey, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrap(err, "CoinLockupMetadata.FromBytes: Problem reading RecipientPublicKey")
	}
	txnData.RecipientPublicKey = NewPublicKey(recipientPublicKey)

	// UnlockTimestampNanoSecs
	txnData.UnlockTimestampNanoSecs, err = ReadVarint(rr)
	if err != nil {
		return errors.Wrap(err, "CoinLockupMetadata.FromBytes: Problem reading UnlockTimestampNanoSecs")
	}

	// VestingEndTimestampNanoSecs
	txnData.VestingEndTimestampNanoSecs, err = ReadVarint(rr)
	if err != nil {
		return errors.Wrap(err,
			"CoinLockupMetadata.FromBytes: Problem reading VestingEndTimestampNanoSecs")
	}

	// LockupAmountBaseUnits
	txnData.LockupAmountBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrap(err, "CoinLockupMetadata.FromBytes: Problem reading LockupAmountBaseUnits")
	}

	return nil
}

func (txnData *CoinLockupMetadata) New() DeSoTxnMetadata {
	return &CoinLockupMetadata{}
}

//
// TYPES: UpdateDAOCoinLockupParamsMetadata
//

type UpdateCoinLockupParamsMetadata struct {
	// LockupYieldDurationNanoSecs and LockupYieldAPYBasisPoints describe a coordinate pair
	// of (duration, APY yield) on a yield curve.
	//
	// A yield curve consists of a series of (duration, APY yield) points. For example,
	// the following points describe a simple yield curve:
	//              {(6mo, 3%), (12mo, 3.5%), (18mo, 4%), (24mo, 4.5%)}
	//
	// Assuming RemoveYieldCurvePoint is false:
	//    The point (LockupYieldDurationNanoSecs, LockupYieldAPYBasisPoints)
	//    is added to the profile's yield curve. If a point with the same duration already exists
	//    on the profile's yield curve, it will be updated with the new yield.
	//    Note if LockupYieldDurationNanoSecs=0, nothing is modified or added at t=0.
	// Assuming RemoveYieldCurvePoint is true:
	//    The point (LockupYieldDurationNanoSecs, XXX) is removed from the profile's yield curve.
	//    Note that LockupYieldAPYBasisPoints is ignored in this transaction.
	//
	// By setting LockupYieldDurationNanoSecs to zero, the yield curve attached to the profile
	// is left unmodified. In any UpdateCoinLockupParams transaction looking to modify only
	// LockupTransferRestrictions, LockupYieldDurationNanoSecs would be set to zero.
	LockupYieldDurationNanoSecs int64
	LockupYieldAPYBasisPoints   uint64
	RemoveYieldCurvePoint       bool

	// When NewLockupTransferRestrictions is set true, the TransferRestrictionStatus specified
	// in the transaction is updated in the transactor's profile for locked coins.
	// Any subsequent transfers utilizing the transactor's locked coins are validated against
	// the updated locked transfer restriction status.
	NewLockupTransferRestrictions   bool
	LockupTransferRestrictionStatus TransferRestrictionStatus
}

func (txnData *UpdateCoinLockupParamsMetadata) GetTxnType() TxnType {
	return TxnTypeUpdateCoinLockupParams
}

func (txnData *UpdateCoinLockupParamsMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, IntToBuf(txnData.LockupYieldDurationNanoSecs)...)
	data = append(data, UintToBuf(txnData.LockupYieldAPYBasisPoints)...)
	data = append(data, BoolToByte(txnData.RemoveYieldCurvePoint))
	data = append(data, BoolToByte(txnData.NewLockupTransferRestrictions))
	data = append(data, byte(txnData.LockupTransferRestrictionStatus))
	return data, nil
}

func (txnData *UpdateCoinLockupParamsMetadata) FromBytes(data []byte) error {
	var err error
	rr := bytes.NewReader(data)

	txnData.LockupYieldDurationNanoSecs, err = ReadVarint(rr)
	if err != nil {
		return errors.Wrap(err, "UpdateCoinLockupParams.FromBytes: Problem reading LockupYieldDurationNanoSecs")
	}

	txnData.LockupYieldAPYBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrap(err, "UpdateCoinLockupParams.FromBytes: Problem reading LockupYieldAPYBasisPoints")
	}

	txnData.RemoveYieldCurvePoint, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrap(err, "UpdateCoinLockupParams.FromBytes: Problem reading RemoveYieldCurvePoint")
	}

	txnData.NewLockupTransferRestrictions, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrap(err, "UpdateCoinLockupParams.FromBytes: Problem reading NewLockupTransferRestrictions")
	}

	lockedStatusByte, err := rr.ReadByte()
	if err != nil {
		return errors.Wrap(err, "UpdateCoinLockupParams.FromBytes: Problem reading LockupTransferRestrictionStatus")
	}
	txnData.LockupTransferRestrictionStatus = TransferRestrictionStatus(lockedStatusByte)

	return nil
}

func (txnData *UpdateCoinLockupParamsMetadata) New() DeSoTxnMetadata {
	return &UpdateCoinLockupParamsMetadata{}
}

//
// TYPES: CoinLockupTransferMetadata
//

type CoinLockupTransferMetadata struct {
	// The recipient of the locked coins.
	RecipientPublicKey *PublicKey

	// The profile whose locked coins are being transferred.
	ProfilePublicKey *PublicKey

	// The UnlockTimestampNanoSecs to source the locked coins from.
	UnlockTimestampNanoSecs int64

	// The amount of locked coins to transfer.
	LockedCoinsToTransferBaseUnits *uint256.Int
}

func (txnData *CoinLockupTransferMetadata) GetTxnType() TxnType {
	return TxnTypeCoinLockupTransfer
}

func (txnData *CoinLockupTransferMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.RecipientPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, IntToBuf(txnData.UnlockTimestampNanoSecs)...)
	data = append(data, VariableEncodeUint256(txnData.LockedCoinsToTransferBaseUnits)...)
	return data, nil
}

func (txnData *CoinLockupTransferMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// RecipientPublicKey
	recipientPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrap(err, "CoinLockupTransferMetadata.FromBytes: Problem reading RecipientPublicKey")
	}
	txnData.RecipientPublicKey = NewPublicKey(recipientPublicKeyBytes)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrap(err, "CoinLockupTransferMetadata.FromBytes: Problem reading ProfilePublicKey")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// UnlockTimestampNanoSecs
	txnData.UnlockTimestampNanoSecs, err = ReadVarint(rr)
	if err != nil {
		return errors.Wrap(err, "CoinLockupTransferMetadata.FromBytes: Problem reading UnlockTimestampNanoSecs")
	}

	// LockedDAOCoinToTransferBaseUnits
	txnData.LockedCoinsToTransferBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrap(err, "CoinLockupTransferMetadata.FromBytes: Problem reading LockedDAOCoinToTransferBaseUnits")
	}

	return nil
}

func (txnData *CoinLockupTransferMetadata) New() DeSoTxnMetadata {
	return &CoinLockupTransferMetadata{}
}

//
// TYPES: CoinUnlockMetadata
//

type CoinUnlockMetadata struct {
	// The public key whose associated locked coins should be unlocked.
	ProfilePublicKey *PublicKey
}

func (txnData *CoinUnlockMetadata) GetTxnType() TxnType {
	return TxnTypeCoinUnlock
}

func (txnData *CoinUnlockMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	return data, nil
}

func (txnData *CoinUnlockMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrap(err, "CoinUnlockMetadata.FromBytes: Problem reading ProfilePublicKey")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	return nil
}

func (txnData *CoinUnlockMetadata) New() DeSoTxnMetadata {
	return &CoinUnlockMetadata{}
}

//
// CoinLockup Transaction Logic
//

func (bav *UtxoView) _connectCoinLockup(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32,
	blockTimestampNanoSecs int64, verifySignatures bool) (_totalInput uint64,
	_totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	var utxoOpsForTxn []*UtxoOperation

	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.LockupsBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return 0, 0, nil,
			errors.Wrap(RuleErrorLockupTxnBeforeBlockHeight, "_connectCoinLockup")
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCoinLockup {
		return 0, 0, nil, fmt.Errorf(
			"_connectCoinLockup: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Try connecting the basic transfer without considering transaction metadata.
	// NOTE: Even in the balance model era, we require totalInput and totalOutput
	//       to test that fees are being paid accurately.
	totalInput, totalOutput, utxoOpsForBasicTransfer, err :=
		bav._connectBasicTransfer(txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrap(err, "_connectCoinLockup")
	}
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpsForBasicTransfer...)

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*CoinLockupMetadata)

	// Check that the target profile public key is valid and that a profile corresponding to that public key exists.
	// We also go ahead and fetch the profile PKID as we will use it later.
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupInvalidProfilePubKey, "_connectCoinLockup")
	}

	// NOTE: The zero key could be used to enable locking up DESO.
	// If this feature is desired, it can be restored with the following PR:
	// https://github.com/deso-protocol/core/pull/991
	if txMeta.ProfilePublicKey.IsZeroPublicKey() {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupCannotLockupZeroKey, "_connectCoinLockup")

	}

	// Check that the profile specified exists.
	profileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey.ToBytes())
	if profileEntry == nil || profileEntry.isDeleted {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupOnNonExistentProfile, "_connectCoinLockup")
	}
	profilePKIDEntry := bav.GetPKIDForPublicKey(txMeta.ProfilePublicKey.ToBytes())
	if profilePKIDEntry == nil || profilePKIDEntry.isDeleted {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupNonExistentProfile, "_connectCoinLockup")
	}
	profilePKID := profilePKIDEntry.PKID.NewPKID()

	// Validate the lockup amount as non-zero. This is meant to prevent wasteful "no-op" transactions.
	if txMeta.LockupAmountBaseUnits.IsZero() {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupOfAmountZero, "_connectCoinLockup")
	}

	// Validate the lockup expires in the future.
	if txMeta.UnlockTimestampNanoSecs <= blockTimestampNanoSecs {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupInvalidLockupDuration, "_connectCoinLockup")
	}

	// Validate the vesting end timestamp as expiring at a logically valid time.
	if txMeta.VestingEndTimestampNanoSecs < txMeta.UnlockTimestampNanoSecs {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupInvalidVestingEndTimestamp, "_connectCoinLockup")
	}

	// In the vested case, validate that the underlying profile is the transactor.
	// NOTE: This check exists because there's several attack vectors that exist in letting
	//		 any user perform vested lockups and send them to other users. For example, in the
	// 		 current implementation we rely on consolidation in the lockup transaction to provide
	//		 quick unlock transactions by users. A malicious user could knowingly send vested
	// 		 lockups with small durations in the attempt to fragment the targeted users locked balance
	//	  	 entries. This would result in the user being unable to easily receive future vested lockups.
	//		 Attack vectors exist in various vested lockup designs and as a result it was decided
	//		 best to only allow the transacting public key to perform vested lockups.
	if txMeta.VestingEndTimestampNanoSecs > txMeta.UnlockTimestampNanoSecs &&
		!reflect.DeepEqual(txn.PublicKey, txMeta.ProfilePublicKey.ToBytes()) {
		return 0, 0, nil,
			errors.Wrapf(RuleErrorCoinLockupInvalidVestedTransactor, "_connectCoinLockup: Profile "+
				"pub key: %v, signer public key: %v", PkToString(txn.PublicKey, bav.Params),
				PkToString(txn.PublicKey, bav.Params))
	}

	// Determine the recipient PKID to use.
	if len(txMeta.RecipientPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupInvalidRecipientPubKey, "_connectCoinLockup")
	}
	if txMeta.RecipientPublicKey.IsZeroPublicKey() {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupZeroPublicKeyAsRecipient, "_connectCoinLockup")
	}
	recipientPKIDEntry := bav.GetPKIDForPublicKey(txMeta.RecipientPublicKey.ToBytes())
	if recipientPKIDEntry == nil || recipientPKIDEntry.isDeleted {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupInvalidRecipientPKID, "_connectCoinLockup")
	}
	hodlerPKID := recipientPKIDEntry.PKID

	// Check the BalanceEntry of the user.
	transactorBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txn.PublicKey,
		txMeta.ProfilePublicKey.ToBytes(),
		true)
	if transactorBalanceEntry == nil || transactorBalanceEntry.isDeleted {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupBalanceEntryDoesNotExist, "_connectCoinLockup")
	}

	// Validate the balance entry as having sufficient funds.
	transactorBalanceNanos256 := transactorBalanceEntry.BalanceNanos.Clone()
	if txMeta.LockupAmountBaseUnits.Gt(transactorBalanceNanos256) {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupInsufficientCoins, "_connectCoinLockup")
	}

	// We store the previous transactor balance entry in the event we need to revert the transaction.
	prevTransactorBalanceEntry := transactorBalanceEntry.Copy()

	// Spend the transactor's DAO coin balance.
	transactorBalanceEntry.BalanceNanos =
		*uint256.NewInt(0).Sub(&transactorBalanceEntry.BalanceNanos, txMeta.LockupAmountBaseUnits)
	bav._setDAOCoinBalanceEntryMappings(transactorBalanceEntry)

	// Create a copy of the associated CoinEntry in the event we must roll back the transaction.
	prevCoinEntry := profileEntry.DAOCoinEntry.Copy()

	// Update CoinsInCirculation and NumberOfHolders associated with the DAO coin balance.
	profileEntry.DAOCoinEntry.CoinsInCirculationNanos = *uint256.NewInt(0).Sub(
		&profileEntry.DAOCoinEntry.CoinsInCirculationNanos,
		txMeta.LockupAmountBaseUnits)
	if transactorBalanceEntry.BalanceNanos.IsZero() && !prevTransactorBalanceEntry.BalanceNanos.IsZero() {
		profileEntry.DAOCoinEntry.NumberOfHolders--
	}
	bav._setProfileEntryMappings(profileEntry)

	// SAFEGUARD: We perform a redundant check if the profile has ANY yield curve points.
	// This could be removed for added performance, but it adds an extra sanity check before we compute
	// any associated yield. Specifically this helps protect against unforeseen issues with GetLocalYieldCurvePoints
	// which is meant to be an optimized DB implementation capable of quickly fetching the yield
	profileEnablesYield := false
	if txMeta.UnlockTimestampNanoSecs == txMeta.VestingEndTimestampNanoSecs {
		// Fetch ALL yield curve points associated with the profilePKID.
		yieldCurvePointsMap, err := bav.GetAllYieldCurvePoints(profilePKID)
		if err != nil {
			return 0, 0, nil,
				errors.Wrap(err, "_connectCoinLockup failed to perform yield curve safeguard check")
		}

		// Check if any yield curve points exist, updating profileEnablesYield if so.
		for _, yieldCurvePoint := range yieldCurvePointsMap {
			if !yieldCurvePoint.isDeleted {
				profileEnablesYield = true
			}
		}
	}

	// If this is an unvested lockup, compute any accrued yield.
	// In the vested lockup case, the yield earned is always zero.
	yieldFromTxn := uint256.NewInt(0)
	if profileEnablesYield && txMeta.UnlockTimestampNanoSecs == txMeta.VestingEndTimestampNanoSecs {
		// Compute the lockup duration in nanoseconds.
		lockupDurationNanoSeconds := txMeta.UnlockTimestampNanoSecs - blockTimestampNanoSecs

		// By now we know the transaction to be valid. We now source yield information from either
		// the profile's yield curve or the raw DeSo yield curve. Because there's some choice in how
		// to determine the yield when the lockup duration falls between two profile-specified yield curve
		// points, we return here the two local points and choose/interpolate between them below.
		leftYieldCurvePoint, rightYieldCurvePoint, err :=
			bav.GetLocalYieldCurvePoints(profilePKID, lockupDurationNanoSeconds)
		if err != nil {
			return 0, 0, nil,
				errors.Wrap(err, "_connectCoinLockup failed to fetch yield curve points")
		}

		// Here we interpolate (choose) the yield between the two returned local yield curve points.
		//
		// If we fall between two points, we choose the left yield curve point (i.e. the one with lesser lockup duration).
		// The transactor earns yield only for the lockup duration specified by the left yield curve point but will
		// be unable to unlock the coins until the transaction specified lockup duration expires.
		txnYieldBasisPoints := uint64(0)
		txnYieldEarningDurationNanoSecs := int64(0)
		if leftYieldCurvePoint != nil &&
			leftYieldCurvePoint.LockupDurationNanoSecs < lockupDurationNanoSeconds {
			txnYieldBasisPoints = leftYieldCurvePoint.LockupYieldAPYBasisPoints
			txnYieldEarningDurationNanoSecs = leftYieldCurvePoint.LockupDurationNanoSecs
		}
		if rightYieldCurvePoint != nil &&
			rightYieldCurvePoint.LockupDurationNanoSecs == lockupDurationNanoSeconds {
			txnYieldBasisPoints = rightYieldCurvePoint.LockupYieldAPYBasisPoints
			txnYieldEarningDurationNanoSecs = rightYieldCurvePoint.LockupDurationNanoSecs
		}

		// Convert variables to a consistent uint256 representation. This is to use them in SafeUint256 math.
		txnYieldBasisPoints256 := uint256.NewInt(0).SetUint64(txnYieldBasisPoints)
		txnYieldEarningDurationNanoSecs256 := uint256.NewInt(0).SetUint64(uint64(txnYieldEarningDurationNanoSecs))

		// Compute the yield associated with this operation, checking to ensure there's no overflow.
		yieldFromTxn, err =
			CalculateLockupYield(
				txMeta.LockupAmountBaseUnits, txnYieldBasisPoints256, txnYieldEarningDurationNanoSecs256)
		if err != nil {
			return 0, 0, nil, errors.Wrap(err, "_connectCoinLockup")
		}
	}

	// Compute the total amount to be locked up in this transaction.
	lockupValue, err := SafeUint256().Add(txMeta.LockupAmountBaseUnits, yieldFromTxn)
	if err != nil {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupYieldCausesOverflow, "_connectCoinLockup: lockupValue")
	}

	// Now we must consolidate the locked balance entry along with those already present
	// in the UtxoView and the DB.
	// In the unvested case this is simple as we only look for an existing locked balance entry
	// with the same unlock time, store the previous locked balance entry, and set the new locked balance entry
	// in the view. An equivalent LockedBalanceEntry has the same unlock timestamp and the same profile PKID.
	// In the vested case we must make careful modifications to the existing locked balance entry/entries.
	var previousLockedBalanceEntry *LockedBalanceEntry
	var previousLockedBalanceEntries []*LockedBalanceEntry
	var setLockedBalanceEntries []*LockedBalanceEntry
	if txMeta.UnlockTimestampNanoSecs == txMeta.VestingEndTimestampNanoSecs {
		// Unvested consolidation case:

		// (1) Check for a locked balance entry with the same unlock time
		lockedBalanceEntry, err := bav.GetLockedBalanceEntryForLockedBalanceEntryKey(
			LockedBalanceEntryKey{
				HODLerPKID:                  *hodlerPKID,
				ProfilePKID:                 *profilePKID,
				UnlockTimestampNanoSecs:     txMeta.UnlockTimestampNanoSecs,
				VestingEndTimestampNanoSecs: txMeta.VestingEndTimestampNanoSecs,
			})
		if err != nil {
			return 0, 0, nil,
				errors.Wrap(err, "_connectCoinLockup failed to fetch unvested lockedBalanceEntry")
		}
		if lockedBalanceEntry == nil || lockedBalanceEntry.isDeleted {
			lockedBalanceEntry = &LockedBalanceEntry{
				HODLerPKID:                  hodlerPKID,
				ProfilePKID:                 profilePKID,
				UnlockTimestampNanoSecs:     txMeta.UnlockTimestampNanoSecs,
				VestingEndTimestampNanoSecs: txMeta.VestingEndTimestampNanoSecs,
				BalanceBaseUnits:            *uint256.NewInt(0),
			}
		}

		// (1.5) Verify  transfer restriction statuses as being respected

		// Fetch the transfer restrictions attached to the transfer.
		transferRestrictionStatus := profileEntry.DAOCoinEntry.LockupTransferRestrictionStatus

		// Fetch the "sender" (transactor's) PKID entry.
		senderPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
		if senderPKIDEntry == nil || senderPKIDEntry.isDeleted {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinLockupInvalidSenderPKID, "_connectCoinLockup")
		}
		senderPKID := senderPKIDEntry.PKID

		// Validate transfer restriction rules.
		err = bav.CheckLockupTransferRestrictions(
			transferRestrictionStatus,
			profilePKID,
			senderPKID,
			hodlerPKID,
			lockedBalanceEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrap(err, "_connectCoinLockup")
		}

		// (2) Store the previous locked balance entry
		previousLockedBalanceEntry = lockedBalanceEntry.Copy()

		// (3) Check for consolidation overflow
		newLockedBalanceEntryBalance, err := SafeUint256().Add(&lockedBalanceEntry.BalanceBaseUnits, lockupValue)
		if err != nil {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinLockupYieldCausesOverflowInLockedBalanceEntry,
					"_connectCoinLockup: New Locked Balance Entry Balance")
		}

		// (4) Set the new locked balance entry in the view
		// NOTE: An astute reader may have noticed the comment on the LockedBalanceEntryKey definition
		// and be confused why we are not deleting then setting the lockedBalanceEntry below. This is because
		// we do not modify the key in this case, making it safe to just set the lockedBalanceEntry.
		lockedBalanceEntry.BalanceBaseUnits = *newLockedBalanceEntryBalance
		bav._setLockedBalanceEntry(lockedBalanceEntry)

		// NOTE: While we could check for "global" overflow here, we let this occur on the unlock transaction instead.
		//       Global overflow is where the yield causes fields like CoinEntry.CoinsInCirculationNanos to overflow.
		//       Performing the check here would be redundant and may lead to worse UX in the case of coins being
		//       burned in the future making current lockups no longer an overflow. Checking here would also
		//       create a DoS attack vector where a malicious entity takes out an extremely long-dated lockup
		//       with the sole intent of saturating the CoinsInCirculationNanos field preventing others from locking up.
	} else {
		// Vested consolidation case:

		// (1) Check for overlapping locked balance entries
		lockedBalanceEntries, err := bav.GetLimitedVestedLockedBalanceEntriesOverTimeInterval(
			hodlerPKID, profilePKID, txMeta.UnlockTimestampNanoSecs, txMeta.VestingEndTimestampNanoSecs,
			bav.GetCurrentGlobalParamsEntry().MaximumVestedIntersectionsPerLockupTransaction)
		if err != nil && errors.Is(err, RuleErrorCoinLockupViolatesVestingIntersectionLimit) {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinLockupViolatesVestingIntersectionLimit, "_connectCoinLockup")
		}
		if err != nil {
			return 0, 0, nil,
				errors.Wrap(err, "_connectCoinLockup failed to fetch vested locked balance entries")
		}

		// (2a) Store the previous locked balance entries in the event of disconnect
		for _, lockedBalanceEntry := range lockedBalanceEntries {
			previousLockedBalanceEntries = append(previousLockedBalanceEntries, lockedBalanceEntry.Copy())
		}

		// (2b) Delete the previous locked balance entries in the view
		//      See the comment on LockedBalanceEntryKey to understand why.
		for _, lockedBalanceEntry := range lockedBalanceEntries {
			bav._deleteLockedBalanceEntry(lockedBalanceEntry)
		}

		// (3) Consolidate vested locked balance entries

		// (3a) First check if there's no existing vested locked balance entries, this is the no-consolidation case
		if len(lockedBalanceEntries) == 0 {
			newLockedBalanceEntry := &LockedBalanceEntry{
				HODLerPKID:                  hodlerPKID,
				ProfilePKID:                 profilePKID,
				UnlockTimestampNanoSecs:     txMeta.UnlockTimestampNanoSecs,
				VestingEndTimestampNanoSecs: txMeta.VestingEndTimestampNanoSecs,
				BalanceBaseUnits:            *lockupValue,
			}
			bav._setLockedBalanceEntry(newLockedBalanceEntry)
			setLockedBalanceEntries = append(setLockedBalanceEntries, newLockedBalanceEntry.Copy())
		} else if len(lockedBalanceEntries) > 0 {
			// (3b) Go through each existing locked balance entry and consolidate

			// Construct a "proposed" locked balance entry from the transaction's metadata.
			proposedLockedBalanceEntry := &LockedBalanceEntry{
				HODLerPKID:                  hodlerPKID,
				ProfilePKID:                 profilePKID,
				UnlockTimestampNanoSecs:     txMeta.UnlockTimestampNanoSecs,
				VestingEndTimestampNanoSecs: txMeta.VestingEndTimestampNanoSecs,
				BalanceBaseUnits:            *lockupValue,
			}

			for ii, existingLockedBalanceEntry := range lockedBalanceEntries {
				// (3b-i) Determine if there is left overhang by either the existing or the proposed locked balance entry
				// e.g.           UnlockTimestampNanoSecs --------------------- VestingEndTimestampNanoSecs
				//            UnlockTimestampNanoSecs --------------------- VestingEndTimestampNanoSecs
				//            ^  ^
				//         left overhang
				// We will break any overhang off into its own separate locked balance entry.

				// Check for left overhang by the existing locked balance entry
				if existingLockedBalanceEntry.UnlockTimestampNanoSecs <
					proposedLockedBalanceEntry.UnlockTimestampNanoSecs {
					// Split the overhanging portion off the existing locked balance entry.
					// Following the split, the existing and the remaining should have the same start time.
					splitLockedBalanceEntry, remainingLockedBalanceEntry, err := SplitVestedLockedBalanceEntry(
						existingLockedBalanceEntry,
						existingLockedBalanceEntry.UnlockTimestampNanoSecs,
						proposedLockedBalanceEntry.UnlockTimestampNanoSecs-1)
					if err != nil {
						return 0, 0, nil,
							errors.Wrap(err, "_connectCoinLockup failed to compute vested split")
					}

					// Set the splitLockedBalanceEntry into the view.
					// NOTE: While it may seem as though we need to check for a conflicting vested
					//       locked balance entry here, by design we only ever have one vested locked
					//       balance entry across any given time interval thus by splitting the locked
					//       balance entry in half it's impossible to intersect an existing
					//       vested locked balance entry.
					bav._setLockedBalanceEntry(splitLockedBalanceEntry)
					setLockedBalanceEntries = append(setLockedBalanceEntries, splitLockedBalanceEntry.Copy())

					// We update the existingLockedBalanceEntry as broke the left overhanging portion off.
					existingLockedBalanceEntry = remainingLockedBalanceEntry
				}

				// Check for left overhang by the proposed locked balance entry
				if proposedLockedBalanceEntry.UnlockTimestampNanoSecs <
					existingLockedBalanceEntry.UnlockTimestampNanoSecs {
					splitLockedBalanceEntry, remainingLockedBalanceEntry, err := SplitVestedLockedBalanceEntry(
						proposedLockedBalanceEntry,
						proposedLockedBalanceEntry.UnlockTimestampNanoSecs,
						existingLockedBalanceEntry.UnlockTimestampNanoSecs-1)
					if err != nil {
						return 0, 0, nil,
							errors.Wrap(err, "_connectCoinLockup failed to compute vested split")
					}

					// Set the splitLockedBalanceEntry into the view.
					bav._setLockedBalanceEntry(splitLockedBalanceEntry)
					setLockedBalanceEntries = append(setLockedBalanceEntries, splitLockedBalanceEntry.Copy())

					// We update the proposedLockedBalanceEntry as the left overhanging portion was broken off.
					proposedLockedBalanceEntry = remainingLockedBalanceEntry
				}

				// (3b-ii) Determine if there is right overhang by either the existing or proposed locked balance entry
				// e.g.      UnlockTimestampNanoSecs --------------------- VestingEndTimestampNanoSecs
				//               UnlockTimestampNanoSecs --------------------- VestingEndTimestampNanoSecs
				//                                                                                    ^  ^
				//                                                                               right overhang
				// We will break any overhang off into its own separate locked balance entry.
				//
				// NOTE: Because in the previous portion of the code we trim any locked balance entries that
				// have "left overhang" we know the UnlockTimestampNanoSecs to be lined up between
				// both the existing and proposed LockedBalanceEntry. This is important as it means after
				// we remove any existing right overhang the two locked balance entries will be perfectly lined up.

				// Check for right overhang by the existing locked balance entry
				if existingLockedBalanceEntry.VestingEndTimestampNanoSecs >
					proposedLockedBalanceEntry.VestingEndTimestampNanoSecs {
					splitLockedBalanceEntry, remainingLockedBalanceEntry, err := SplitVestedLockedBalanceEntry(
						existingLockedBalanceEntry,
						proposedLockedBalanceEntry.VestingEndTimestampNanoSecs+1,
						existingLockedBalanceEntry.VestingEndTimestampNanoSecs)
					if err != nil {
						return 0, 0, nil,
							errors.Wrap(err, "_connectCoinLockup failed to compute vested split")
					}

					// Set the splitLockedBalanceEntry into the view.
					bav._setLockedBalanceEntry(splitLockedBalanceEntry)
					setLockedBalanceEntries = append(setLockedBalanceEntries, splitLockedBalanceEntry.Copy())

					// We update the existingLockedBalanceEntry as broke the right overhanging portion off.
					existingLockedBalanceEntry = remainingLockedBalanceEntry
				}

				// Check for right overhang by the proposed locked balance entry
				if proposedLockedBalanceEntry.VestingEndTimestampNanoSecs >
					existingLockedBalanceEntry.VestingEndTimestampNanoSecs {
					// NOTE: This case is particularly interesting as there's two situations in
					// which we might find ourselves.
					//
					// First case:
					// proposed:   <----------------------------------------->
					// existing:   <------------------>
					//                                 ^                     ^ Overhang
					// Second case:
					// proposed:   <----------------------------------------->
					// existing:   <------------------>            <--------->
					//                                 ^          ^ Overhang
					// In the second case there exists another conflicting LockedBalanceEntry
					// sometime in the future that we must be aware of. Also note that
					// the first case is only possible in the very last iteration.
					//
					// To account for this, we split from the proposed LockedBalanceEntry
					// and combine the left overlapping portion. This leaves us with two
					// remaining cases:
					// First case:
					// proposed:                       <--------------------->
					// existing:
					//
					// Second case:
					// proposed:                       <--------------------->
					// existing:                                   <--------->
					//
					// The second case is fine to leave as it will be taken care of in the
					// subsequent iteration. However, we make a special note to capture the
					// remaining LockedBalanceEntry present in the first case.

					// We check if there's another locked balance entry sometime in the future.
					splitLockedBalanceEntry, remainingLockedBalanceEntry, err := SplitVestedLockedBalanceEntry(
						proposedLockedBalanceEntry,
						existingLockedBalanceEntry.UnlockTimestampNanoSecs,
						existingLockedBalanceEntry.VestingEndTimestampNanoSecs)
					if err != nil {
						return 0, 0, nil,
							errors.Wrap(err, "_connectCoinLockup failed to compute vested split")
					}

					// Consolidate the split and existing locked balance entry.
					combinedBalanceBaseUnits, err := SafeUint256().Add(
						&splitLockedBalanceEntry.BalanceBaseUnits,
						&existingLockedBalanceEntry.BalanceBaseUnits)
					if err != nil {
						return 0, 0, nil,
							errors.Wrap(RuleErrorCoinLockupYieldCausesOverflowInLockedBalanceEntry,
								"_connectCoinLockup")
					}
					splitLockedBalanceEntry.BalanceBaseUnits = *combinedBalanceBaseUnits

					// Set the now combined splitLockedBalanceEntry into the view.
					bav._setLockedBalanceEntry(splitLockedBalanceEntry)
					setLockedBalanceEntries = append(setLockedBalanceEntries, splitLockedBalanceEntry.Copy())

					// Update the proposed locked balance entry with the remaining portion.
					proposedLockedBalanceEntry = remainingLockedBalanceEntry

					// (3b-iii) On the final iteration, the remaining proposedLockedBalanceEntry
					//          is the only vesting schedule left.
					if ii == len(lockedBalanceEntries)-1 {
						bav._setLockedBalanceEntry(proposedLockedBalanceEntry)
						setLockedBalanceEntries = append(setLockedBalanceEntries, proposedLockedBalanceEntry.Copy())
					}
				}

				// (3b-iv) By now, we know the edges to be trimmed as best possible.
				// We check if the existing and proposed now overlap perfectly in time and combine if so.
				if (existingLockedBalanceEntry.UnlockTimestampNanoSecs ==
					proposedLockedBalanceEntry.UnlockTimestampNanoSecs) &&
					(existingLockedBalanceEntry.VestingEndTimestampNanoSecs ==
						proposedLockedBalanceEntry.VestingEndTimestampNanoSecs) {
					// Combine the remaining balance.
					combinedBalanceBaseUnits, err := SafeUint256().Add(
						&existingLockedBalanceEntry.BalanceBaseUnits,
						&proposedLockedBalanceEntry.BalanceBaseUnits)
					if err != nil {
						return 0, 0, nil,
							errors.Wrap(RuleErrorCoinLockupYieldCausesOverflowInLockedBalanceEntry,
								"_connectCoinLockup")
					}

					// Update the remaining entry.
					proposedLockedBalanceEntry.BalanceBaseUnits = *combinedBalanceBaseUnits
					bav._setLockedBalanceEntry(proposedLockedBalanceEntry)
					setLockedBalanceEntries = append(setLockedBalanceEntries, proposedLockedBalanceEntry.Copy())
				}
			}
		}
	}

	// Add a UtxoOperation for easy reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                       OperationTypeCoinLockup,
		PrevTransactorBalanceEntry: prevTransactorBalanceEntry,
		PrevLockedBalanceEntry:     previousLockedBalanceEntry,
		PrevLockedBalanceEntries:   previousLockedBalanceEntries,
		SetLockedBalanceEntries:    setLockedBalanceEntries,
		PrevCoinEntry:              prevCoinEntry,
	})

	// Construct UtxoOps in the event this transaction is reverted.
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

// CheckLockupTransferRestrictions is a helper function meant to consolidate the transfer
// checks present in both _connectCoinLockup and _connectCoinLockupTransfer in one place.
// The check takes several expected arguments including the transfer restriction status
// in question (transferRestrictionStatus), the profile being transferred (profilePKID),
// who's initiating the transfer (senderPKID), and who's receiving the transfer (receiverPKID).
//
// In addition, there's a receiverLockedBalanceEntry as there's a context dependent
// check we do where we enable a "DAO" member to be someone who already possesses a
// non-zero unvested locked balance entry with the associated timestamp.
func (bav *UtxoView) CheckLockupTransferRestrictions(
	transferRestrictionStatus TransferRestrictionStatus,
	profilePKID *PKID,
	senderPKID *PKID,
	receiverPKID *PKID,
	receiverLockedBalanceEntry *LockedBalanceEntry,
) (
	_ruleError error,
) {
	// Check if profile owner only transfer restrictions are respected.
	if transferRestrictionStatus == TransferRestrictionStatusProfileOwnerOnly && !profilePKID.Eq(senderPKID) {
		return RuleErrorCoinLockupTransferRestrictedToProfileOwner
	}

	// Check if the DAO member only restrictions are respected.
	// Here, a "DAO member" is anyone who holds either unlocked or locked DAO coins associated with the profile.
	if transferRestrictionStatus == TransferRestrictionStatusDAOMembersOnly {
		// NOTE: It's not possible for the receiverBalanceEntry below to be nil as
		// the function will return an empty balance entry with the specified (hodler, profile)
		// pair instead of returning nil if there's no entries in the db.
		receiverBalanceEntry :=
			bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(receiverPKID, profilePKID, true)
		if receiverBalanceEntry.BalanceNanos.IsZero() && receiverLockedBalanceEntry.BalanceBaseUnits.IsZero() {
			return RuleErrorCoinLockupTransferRestrictedToDAOMembers
		}
	}

	// If we reach here, the lockup transfer is valid.
	return nil
}

// SplitVestedLockedBalanceEntry is used for splitting a vested locked balance entry into two pieces.
// It is assumed that the startSplitTimestamp lines up with the UnlockTimestampNanoSecs of the lockedBalanceEntry
// passed or endSplitTimestampNanoSecs lines up with the VestingEndTimestampNanoSecs of
// the lockedBalanceEntry passed.
//
// On return a splitLockedBalanceEntry will be returned with UnlockTimestampNanoSecs=startSplitTimestampNanoSecs
// and VestingEndTimestampNanoSecs=endSplitTimestampNanoSecs.
// In addition, a remainingLockedBalanceEntry will be returned whose UnlockTimestampNanoSecs and
// VestingEndTimestampNanoSecs is whatever remains of the lockedBalanceEntry passed minus the splitLockedBalanceEntry.
func SplitVestedLockedBalanceEntry(
	lockedBalanceEntry *LockedBalanceEntry,
	startSplitTimestampNanoSecs int64,
	endSplitTimestampNanoSecs int64,
) (
	_splitLockedBalanceEntry *LockedBalanceEntry,
	_remainingLockedBalanceEntry *LockedBalanceEntry,
	_err error,
) {
	// SplitVestedLockedBalanceEntry performs simple split operations where
	// either startSplitTimestampNanoSecs or endSplitTimestampNanoSecs corresponds with the
	// start or end timestamp in lockedBalanceEntry.
	//
	// This means the function can take in one of the two following configurations:
	//
	// Valid Input Configuration 1:
	//             lockedBalanceEntry <start-------------------------------end>
	//    startSplitTimestampNanoSecs ^
	//      endSplitTimestampNanoSecs                 ^
	//
	// Valid Input Configuration 2:
	//             lockedBalanceEntry <start-------------------------------end>
	//    startSplitTimestampNanoSecs                      ^
	//      endSplitTimestampNanoSecs                                         ^
	//
	// NOTE: We can imagine the split operation taking a lockedBalanceEntry with interval [t1, t2] and
	// splitting it into two separate lockedBalanceEntry intervals: [t3, t4] & [t5, t6] where t4 + 1 = t5.
	// Notice however that there is a 1 nanosecond loss in this that we must account for between
	// t4 and t5. This becomes computationally tricky when trying to consistently compute the split's value.
	// To deal with this, we always let the lockedBalanceEntry using the split off interval
	// (passed as [startSplitTimestampNanoSecs, endSplitTimestampNanoSecs]) take on the extra 1 nanosecond of
	// value. This ends up being the best way to ensure numerical consistency for all caller of this function,
	// but other decisions on where to put the extra nanosecond of value can be made as well, and they will also work.
	//
	// Stated another way: While we return lockedBalanceEntries with intervals [t3, t4] & [t5, t6]
	// where t4 + 1 = t5, we compute the balance in each of those entries based on the time elapsed
	// in the intervals [t3, t5) and [t5, t6]. This ensures a computationally consistent means of computing
	// the value in the returned lockedBalanceEntries.
	//
	// You can see this implemented below where CalculateLockupValueOverElapsedDuration is called
	// with (endSplitTimestampNanoSecs - startSplitTimestampNanoSecs + 1) as the elapsed duration.

	// Sanity check to ensure the start timestamp is before the end timestamp.
	if startSplitTimestampNanoSecs >= endSplitTimestampNanoSecs {
		return nil, nil,
			errors.New("SplitVestedLockedBalanceEntry: cannot use reversed split timestamps")
	}

	// Check to ensure the start and end timestamps are within the bounds
	if startSplitTimestampNanoSecs < lockedBalanceEntry.UnlockTimestampNanoSecs ||
		endSplitTimestampNanoSecs > lockedBalanceEntry.VestingEndTimestampNanoSecs {
		return nil, nil,
			errors.New("SplitVestedLockedBalanceEntry: split timestamps must be within bounds")
	}

	// Check to ensure the split will not form three pieces.
	if startSplitTimestampNanoSecs != lockedBalanceEntry.UnlockTimestampNanoSecs &&
		endSplitTimestampNanoSecs != lockedBalanceEntry.VestingEndTimestampNanoSecs {
		return nil, nil,
			errors.New("SplitVestedLockedBalanceEntry: split would create three pieces")
	}

	// Check to ensure the split will not form one.
	if startSplitTimestampNanoSecs == lockedBalanceEntry.UnlockTimestampNanoSecs &&
		endSplitTimestampNanoSecs == lockedBalanceEntry.VestingEndTimestampNanoSecs {
		return nil, nil,
			errors.New("SplitVestedLockedBalanceEntry: split would result in no-op")
	}

	// Create a split locked balance entry.
	splitLockedBalanceEntry := &LockedBalanceEntry{
		HODLerPKID:                  lockedBalanceEntry.HODLerPKID,
		ProfilePKID:                 lockedBalanceEntry.ProfilePKID,
		UnlockTimestampNanoSecs:     startSplitTimestampNanoSecs,
		VestingEndTimestampNanoSecs: endSplitTimestampNanoSecs,
		BalanceBaseUnits:            uint256.Int{},
	}

	// Create the remaining locked balance entry.
	// NOTE: The SplitVestedLockedBalanceEntry function is designed such that
	// the portion being split off from the LockedBalanceEntry either starts
	// at the lockedBalanceEntry.UnlockTimestampNanoSecs OR ends at the
	// lockedBalanceEntry.VestingEndTimestampNanoSecs. Based on these two cases
	// we can determine the remaining LockedBalanceEntry.
	var remainingLockedBalanceEntry *LockedBalanceEntry
	if startSplitTimestampNanoSecs == lockedBalanceEntry.UnlockTimestampNanoSecs {
		remainingLockedBalanceEntry = &LockedBalanceEntry{
			HODLerPKID:                  lockedBalanceEntry.HODLerPKID,
			ProfilePKID:                 lockedBalanceEntry.ProfilePKID,
			UnlockTimestampNanoSecs:     endSplitTimestampNanoSecs + 1,
			VestingEndTimestampNanoSecs: lockedBalanceEntry.VestingEndTimestampNanoSecs,
			BalanceBaseUnits:            uint256.Int{},
		}
	}
	if endSplitTimestampNanoSecs == lockedBalanceEntry.VestingEndTimestampNanoSecs {
		remainingLockedBalanceEntry = &LockedBalanceEntry{
			HODLerPKID:                  lockedBalanceEntry.HODLerPKID,
			ProfilePKID:                 lockedBalanceEntry.ProfilePKID,
			UnlockTimestampNanoSecs:     lockedBalanceEntry.UnlockTimestampNanoSecs,
			VestingEndTimestampNanoSecs: startSplitTimestampNanoSecs - 1,
			BalanceBaseUnits:            uint256.Int{},
		}
	}

	// Compute the balance in the split locked balance entry.
	// See the note at the top of this function for why we do this.
	splitValue, err := CalculateLockupValueOverElapsedDuration(
		lockedBalanceEntry,
		endSplitTimestampNanoSecs-startSplitTimestampNanoSecs+1)
	if err != nil {
		return nil, nil,
			errors.Wrap(err, "SplitVestedLockedBalanceEntry failed to compute split value")
	}
	splitLockedBalanceEntry.BalanceBaseUnits = *splitValue

	// Compute the balance in the remaining locked balance entry.
	remainingValue, err := SafeUint256().Sub(&lockedBalanceEntry.BalanceBaseUnits, splitValue)
	if err != nil {
		return nil, nil,
			errors.Wrap(err, "SplitVestedLockedBalanceEntry failed to compute remaining value")
	}
	remainingLockedBalanceEntry.BalanceBaseUnits = *remainingValue

	// Sanity check the split does not print money.
	if uint256.NewInt(0).Add(
		&splitLockedBalanceEntry.BalanceBaseUnits, &remainingLockedBalanceEntry.BalanceBaseUnits).
		Gt(&lockedBalanceEntry.BalanceBaseUnits) {
		return nil, nil,
			errors.New("SplitVestedLockedBalanceEntry: split would print tokens/DESO")
	}

	// Sanity check the split does not result in empty locked balance entries.
	if splitLockedBalanceEntry.BalanceBaseUnits.IsZero() ||
		remainingLockedBalanceEntry.BalanceBaseUnits.IsZero() {
		return nil, nil,
			errors.New("SplitVestedLockedBalanceEntry: split would result in empty locked balance entry")
	}

	return splitLockedBalanceEntry, remainingLockedBalanceEntry, nil
}

func CalculateLockupValueOverElapsedDuration(
	lockedBalanceEntry *LockedBalanceEntry,
	elapsedDuration int64,
) (
	_splitValue *uint256.Int,
	_err error,
) {
	// Sanity check the passed values.
	if elapsedDuration <= 0 {
		return nil, errors.New("CalculateLockupSplitValue: " +
			"elapsedDuration specified is either zero or negative.")
	}

	// Convert the elapsedDuration to an uint256
	numerator := uint256.NewInt(0).SetUint64(uint64(elapsedDuration))

	// Compute the time that passes over the duration of the locked balance entry
	denominator, err := SafeUint256().Sub(
		uint256.NewInt(0).SetUint64(uint64(lockedBalanceEntry.VestingEndTimestampNanoSecs)),
		uint256.NewInt(0).SetUint64(uint64(lockedBalanceEntry.UnlockTimestampNanoSecs)))
	if err != nil {
		return nil, errors.Wrap(err, "CalculateLockupSplitValue: "+
			"(lockedBalanceEntry.UnlockTimestamp - lockedBalanceEntry.VestingEndTimestamp) underflow")
	}

	// Rather than creating a floating point for the fraction of time that passes, we keep
	// everything as uint256 by multiplying the locked balance entry value by the numerator and
	// dividing by the denominator. We know uint256 division to produce a quotient strictly less
	// than the true infinite precision quotient. This approach is an extra layer of protection against
	// money printer bugs.
	numerator, err = SafeUint256().Mul(numerator, &lockedBalanceEntry.BalanceBaseUnits)
	if err != nil {
		return nil, errors.Wrap(err, "CalculateLockupSplitValue: "+
			"((start timestamp - end timestamp) + 1) * lockedBalanceEntry.Balance overflow")
	}
	splitValue, err := SafeUint256().Div(numerator, denominator)
	if err != nil {
		return nil, errors.Wrap(err, "CalculateLockupSplitValue: "+
			"(elapsedDuration * lockedBalanceEntry.BalanceBaseUnits) / "+
			"(lockedBalanceEntry.UnlockTimestamp - lockedBalanceEntry.VestingEndTimestamp) has zero denominator")
	}

	return splitValue, nil
}

func CalculateLockupYield(
	principal *uint256.Int,
	apyYieldBasisPoints *uint256.Int,
	durationNanoSecs *uint256.Int,
) (*uint256.Int, error) {
	// Note: We could compute either simple or compounding interest. While compounding interest is ideal from an
	//       application perspective, it becomes incredibly difficult to implement from a numerical perspective.
	//       This is because compound interest requires fractional exponents rather for computing the yield.
	//       Determining overflow and preventing excessive money-printers becomes tricky in the compound interest case.
	//       For this reason, we opt to use simple interest.
	//
	// Simple interest formula:
	//       yield = principal * apy_yield * time_in_years
	//
	// Notice this formula makes detecting computational overflow trivial by utilizing the DeSo SafeUint256 library.

	// The SafeUint256 Library uses division to ensure there's no overflow. This leads to possible
	// unnecessary false overflows in the event the duration or the yield is 0. Hence, we do a separate check here.
	if apyYieldBasisPoints.IsZero() || durationNanoSecs.IsZero() {
		return uint256.NewInt(0), nil
	}

	// Compute the denominators from the nanosecond to year conversion and the basis point computation.
	denominators, err := SafeUint256().Mul(
		uint256.NewInt(0).SetUint64(NanoSecsPerYear),
		uint256.NewInt(0).SetUint64(10000))
	if err != nil {
		return nil,
			errors.Wrap(RuleErrorCoinLockupCoinYieldOverflow, "CalculateLockupYield (nanoSecsPerYear * 10000)")
	}

	// Compute the numerators from the principal, apy yield, and time in nanoseconds.
	numerators, err := SafeUint256().Mul(principal, apyYieldBasisPoints)
	if err != nil {
		return nil,
			errors.Wrap(RuleErrorCoinLockupCoinYieldOverflow, "CalculateLockupYield (principal * yield)")
	}
	numerators, err = SafeUint256().Mul(numerators, durationNanoSecs)
	if err != nil {
		return nil,
			errors.Wrap(RuleErrorCoinLockupCoinYieldOverflow, "CalculateLockupYield ((principal * yield) * duration)")
	}

	// Compute the yield for the transaction.
	yield, err := SafeUint256().Div(numerators, denominators)
	if err != nil {
		return nil,
			errors.Wrap(err, "CalculateLockupYield (numerator / denominator)")
	}

	return yield, nil
}

func (bav *UtxoView) _disconnectCoinLockup(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32) error {

	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectCoinLockup: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1

	// Verify the last operation as being a CoinLockup operation.
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCoinLockup {
		return fmt.Errorf("_disconnectCoinLockup: Trying to revert "+
			"OperationTypeCoinLockup but found type %v", utxoOpsForTxn[operationIndex].Type)
	}

	// Sanity check the CoinLockup operation exists.
	operationData := utxoOpsForTxn[operationIndex]
	if operationData.PrevLockedBalanceEntry == nil || operationData.PrevLockedBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCoinLockup: Trying to revert OperationTypeCoinLockup " +
			"but found nil or deleted previous locked balance entry")
	}

	// Depending on whether this was a vested or unvested lockup, we disconnect differently.
	if operationData.PrevLockedBalanceEntry != nil {
		// Sanity check the data within the CoinLockup. Reverting an unvested lockup should not result in more coins.
		lockedBalanceEntry, err :=
			bav.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				operationData.PrevLockedBalanceEntry.HODLerPKID,
				operationData.PrevLockedBalanceEntry.ProfilePKID,
				operationData.PrevLockedBalanceEntry.UnlockTimestampNanoSecs,
				operationData.PrevLockedBalanceEntry.VestingEndTimestampNanoSecs)
		if err != nil {
			return errors.Wrap(err, "_disconnectCoinLockup failed to fetch current lockedBalanceEntry")
		}
		if lockedBalanceEntry == nil || lockedBalanceEntry.isDeleted {
			lockedBalanceEntry = &LockedBalanceEntry{
				HODLerPKID:                  operationData.PrevLockedBalanceEntry.HODLerPKID,
				ProfilePKID:                 operationData.PrevLockedBalanceEntry.ProfilePKID,
				UnlockTimestampNanoSecs:     operationData.PrevLockedBalanceEntry.UnlockTimestampNanoSecs,
				VestingEndTimestampNanoSecs: operationData.PrevLockedBalanceEntry.VestingEndTimestampNanoSecs,
				BalanceBaseUnits:            *uint256.NewInt(0),
			}
		}
		if lockedBalanceEntry.BalanceBaseUnits.Lt(&operationData.PrevLockedBalanceEntry.BalanceBaseUnits) {
			return fmt.Errorf("_disconnectCoinLockup: Reversion of coin lockup would result in " +
				"more coins in the lockup")
		}

		// Reset the transactor's LockedBalanceEntry to what it was previously.
		bav._setLockedBalanceEntry(operationData.PrevLockedBalanceEntry)
	} else {
		// Delete any set locked balance entries.
		for _, setLockedBalanceEntry := range operationData.SetLockedBalanceEntries {
			bav._setLockedBalanceEntry(setLockedBalanceEntry)
		}

		// Set any previous locked balance entries.
		for _, prevLockedBalanceEntry := range operationData.PrevLockedBalanceEntries {
			bav._setLockedBalanceEntry(prevLockedBalanceEntry)
		}
	}

	// Revert the transactor's DAO coin balance.
	bav._setBalanceEntryMappings(operationData.PrevTransactorBalanceEntry, true)

	// Fetch the profile entry associated with the lockup.
	profileEntry := bav.GetProfileEntryForPKID(operationData.PrevLockedBalanceEntry.ProfilePKID)
	if profileEntry == nil || profileEntry.isDeleted {
		return fmt.Errorf("_disconnectCoinLockup: Trying to revert coin entry " +
			"update but found nil profile entry; this shouldn't be possible")
	}

	// Ensure the PrevCoinEntry is not nil. This shouldn't be possible.
	if operationData.PrevCoinEntry == nil {
		return fmt.Errorf("_disconnectCoinLockup: Trying to revert coin entry " +
			"update but found nil prev coin entry; this shouldn't be possible")
	}

	// Revert the coin entry.
	profileEntry.DAOCoinEntry = *operationData.PrevCoinEntry
	bav._setProfileEntryMappings(profileEntry)

	// By here we only need to disconnect the basic transfer associated with the transaction.
	basicTransferOps := utxoOpsForTxn[:operationIndex]
	err := bav._disconnectBasicTransfer(currentTxn, txnHash, basicTransferOps, blockHeight)
	if err != nil {
		return errors.Wrap(err, "_disconnectCoinLockup")
	}
	return nil
}

//
// UpdateCoinLockupParams Transaction Logic
//

func (bav *UtxoView) _connectUpdateCoinLockupParams(
	txn *MsgDeSoTxn,
	txHash *BlockHash,
	blockHeight uint32,
	verifySignatures bool,
) (_totalInput uint64,
	_totalOutput uint64,
	_utxoOps []*UtxoOperation,
	_err error) {
	var utxoOpsForTxn []*UtxoOperation

	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.LockupsBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return 0, 0, nil,
			errors.Wrap(RuleErrorLockupTxnBeforeBlockHeight, "_connectUpdateCoinLockupParams")
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeUpdateCoinLockupParams {
		return 0, 0, nil, fmt.Errorf("_connectUpdateCoinLockupParams: "+
			"called with bad TxnType %s", txn.TxnMeta.GetTxnType().String())
	}

	// Try connecting the basic transfer without considering transaction metadata.
	totalInput, totalOutput, utxoOpsForBasicTransfer, err :=
		bav._connectBasicTransfer(txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrap(err, "_connectUpdateCoinLockupParams")
	}
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpsForBasicTransfer...)

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*UpdateCoinLockupParamsMetadata)

	// Get the profilePKID from the transactor public key.
	profilePKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if profilePKIDEntry == nil || profilePKIDEntry.isDeleted {
		return 0, 0, nil, errors.Wrap(RuleErrorUpdateCoinLockupParamsOnInvalidPKID,
			"_connectUpdateCoinLockupParams")
	}
	profilePKID := profilePKIDEntry.PKID

	// Sanity check the lockup duration as valid.
	if txMeta.LockupYieldDurationNanoSecs < 0 {
		return 0, 0, nil, errors.Wrap(RuleErrorUpdateCoinLockupParamsNegativeDuration,
			"_connectUpdateCoinLockupParams")
	}

	// Check to ensure this transaction is not a no-op.
	if !txMeta.NewLockupTransferRestrictions && txMeta.LockupYieldDurationNanoSecs == 0 {
		return 0, 0, nil, errors.Wrap(RuleErrorUpdateCoinLockupParamsIsNoOp,
			"_connectUpdateCoinLockupParams")

	}

	// Fetch the previous yield curve point associated with this <profilePKID, lockupDurationNanoSecs> pair.
	prevLockupYieldCurvePoint, err :=
		bav.GetYieldCurvePointByProfilePKIDAndDurationNanoSecs(profilePKID, txMeta.LockupYieldDurationNanoSecs)
	if err != nil {
		return 0, 0, nil, errors.Wrap(err, "_connectUpdateCoinLockupParams: "+
			"failed a DB get operation on the previous yield curve point; this shouldn't happen")
	}

	// Check if a yield curve point is being added.
	if !txMeta.RemoveYieldCurvePoint && txMeta.LockupYieldDurationNanoSecs > 0 {
		// NOTE: During the view flush, any comparable LockupYieldCurvePoint with the unique
		//       <ProfilePKID, LockupDurationNanoSecs> pair will be deleted prior to this new
		//       point being added. Above we saved the previous LockupYieldCurvePoint
		//       in the even this is reverted.
		bav._setLockupYieldCurvePoint(&LockupYieldCurvePoint{
			ProfilePKID:               profilePKID,
			LockupDurationNanoSecs:    txMeta.LockupYieldDurationNanoSecs,
			LockupYieldAPYBasisPoints: txMeta.LockupYieldAPYBasisPoints,
		})
	}

	// Check if a yield curve point is being removed.
	if txMeta.RemoveYieldCurvePoint && txMeta.LockupYieldDurationNanoSecs > 0 {
		// Check that we're not deleting a point which doesn't exist. This ensures that disconnects function properly,
		// as well ensures there's no wasteful "no-ops" executed.
		if prevLockupYieldCurvePoint == nil {
			return 0, 0, nil,
				errors.Wrap(RuleErrorUpdateCoinLockupParamsDeletingNonExistentPoint, "_connectUpdateCoinLockupParams")
		}

		// NOTE: The "LockupYieldAPYBasisPoints" field is effectively irrelevant here.
		//       The DB operations will seek to the unique <ProfilePKID, LockupDurationNanoSecs>
		//       pair and delete it during the view flush. The "isDeleted" field ensures
		//       nothing else is put in its place.
		bav._deleteLockupYieldCurvePoint(&LockupYieldCurvePoint{
			ProfilePKID:            profilePKID,
			LockupDurationNanoSecs: txMeta.LockupYieldDurationNanoSecs,
		})
	}

	// Check if we're updating transfer restriction.
	var prevLockupTransferRestriction TransferRestrictionStatus
	if txMeta.NewLockupTransferRestrictions {
		// Fetch the profile entry and LockupTransferRestriction status.
		profileEntry := bav.GetProfileEntryForPKID(profilePKID)
		if profileEntry == nil || profileEntry.isDeleted {
			return 0, 0, nil,
				errors.Wrap(RuleErrorUpdateCoinLockupParamsUpdatingNonExistentProfile, "_connectUpdateCoinLockupParams")
		}

		// Store a copy of the previous LockupTransferRestrictionStatus for easy transaction disconnect.
		prevLockupTransferRestriction = profileEntry.DAOCoinEntry.LockupTransferRestrictionStatus

		// Update the transfer restrictions.
		profileEntry.DAOCoinEntry.LockupTransferRestrictionStatus = txMeta.LockupTransferRestrictionStatus
		bav._setProfileEntryMappings(profileEntry)
	}

	// Check that the new transfer restriction is valid.
	if txMeta.NewLockupTransferRestrictions {
		// Ensure we're not updating a permanent transfer restriction.
		if prevLockupTransferRestriction == TransferRestrictionStatusPermanentlyUnrestricted {
			return 0, 0, nil, errors.Wrap(
				RuleErrorUpdateCoinLockupParamsUpdatingPermanentTransferRestriction, "_connectUpdateCoinLockupParams")
		}

		// Check that the new transfer restrictions are valid.
		if !(txMeta.LockupTransferRestrictionStatus == TransferRestrictionStatusUnrestricted) &&
			!(txMeta.LockupTransferRestrictionStatus == TransferRestrictionStatusProfileOwnerOnly) &&
			!(txMeta.LockupTransferRestrictionStatus == TransferRestrictionStatusDAOMembersOnly) &&
			!(txMeta.LockupTransferRestrictionStatus == TransferRestrictionStatusPermanentlyUnrestricted) {
			return 0, 0, nil,
				errors.Wrap(RuleErrorUpdateCoinLockupParamsInvalidRestrictions, "_connectUpdateCoinLockupParams")
		}
	}

	// Add a UtxoOperation for easy reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                          OperationTypeUpdateCoinLockupParams,
		PrevLockupYieldCurvePoint:     prevLockupYieldCurvePoint,
		PrevLockupTransferRestriction: prevLockupTransferRestriction,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectUpdateCoinLockupParams(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32) error {

	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUpdateCoinLockupParams: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1

	// Verify the last operation as being a UpdateCoinLockupParams operation.
	if utxoOpsForTxn[operationIndex].Type != OperationTypeUpdateCoinLockupParams {
		return fmt.Errorf("_disconnectUpdateCoinLockupParams: Trying to revert "+
			"OperationTypeUpdateCoinLockupParams but found type %v", utxoOpsForTxn[operationIndex].Type)
	}

	// Fetch the UpdateCoinLockupParams operation.
	operationData := utxoOpsForTxn[operationIndex]

	// Grab the txn metadata.
	txMeta := currentTxn.TxnMeta.(*UpdateCoinLockupParamsMetadata)

	// Fetch the profilePKID for the transactor.
	profilePKIDEntry := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if profilePKIDEntry == nil || profilePKIDEntry.isDeleted {
		return errors.Wrap(RuleErrorUpdateCoinLockupParamsOnInvalidPKID,
			"_connectUpdateCoinLockupParams")
	}
	profilePKID := profilePKIDEntry.PKID

	// Check if the transaction added a yield curve point. If it did, we restore the previous point.
	// If the previous point is nil meaning this point didn't have a previous, then we simply delete the current point.
	if !txMeta.RemoveYieldCurvePoint && txMeta.LockupYieldDurationNanoSecs > 0 {
		if operationData.PrevLockupYieldCurvePoint == nil {
			bav._deleteLockupYieldCurvePoint(&LockupYieldCurvePoint{
				ProfilePKID:            profilePKID,
				LockupDurationNanoSecs: txMeta.LockupYieldDurationNanoSecs,
			})
		} else {
			bav._setLockupYieldCurvePoint(&LockupYieldCurvePoint{
				ProfilePKID:               profilePKID,
				LockupDurationNanoSecs:    operationData.PrevLockupYieldCurvePoint.LockupDurationNanoSecs,
				LockupYieldAPYBasisPoints: operationData.PrevLockupYieldCurvePoint.LockupYieldAPYBasisPoints,
			})
		}
	}

	// Check if the transaction deleted a yield curve point. If it did, we add back the previous point.
	// If the previous point is nil, we throw an error. This shouldn't be possible.
	if txMeta.RemoveYieldCurvePoint && txMeta.LockupYieldDurationNanoSecs > 0 {
		if operationData.PrevLockupYieldCurvePoint == nil {
			return fmt.Errorf("_disconnectUpdateCoinLockupParams: trying to revert point deletion " +
				"but found nil previous yield curve point; this shouldn't be possible")
		}
		bav._setLockupYieldCurvePoint(&LockupYieldCurvePoint{
			ProfilePKID:               profilePKID,
			LockupDurationNanoSecs:    operationData.PrevLockupYieldCurvePoint.LockupDurationNanoSecs,
			LockupYieldAPYBasisPoints: operationData.PrevLockupYieldCurvePoint.LockupYieldAPYBasisPoints,
		})
	}

	// Check if the transaction updated transfer restrictions. If it did, we reset the previous transfer restrictions.
	if txMeta.NewLockupTransferRestrictions {
		// Fetch the profile entry and LockupTransferRestriction status.
		profileEntry := bav.GetProfileEntryForPKID(profilePKID)
		if profileEntry == nil || profileEntry.isDeleted {
			return fmt.Errorf("_disconnectUpdateCoinLockupParams: Trying to revert lockup transfer restriction " +
				"update but found nil profile entry; this shouldn't be possible")
		}

		// Update the transfer restrictions.
		profileEntry.DAOCoinEntry.LockupTransferRestrictionStatus = operationData.PrevLockupTransferRestriction
		bav._setProfileEntryMappings(profileEntry)
	}

	// By here we only need to disconnect the basic transfer associated with the transaction.
	basicTransferOps := utxoOpsForTxn[:operationIndex]
	err := bav._disconnectBasicTransfer(currentTxn, txnHash, basicTransferOps, blockHeight)
	if err != nil {
		return errors.Wrap(err, "_disconnectUpdateCoinLockupParams")
	}
	return nil
}

//
// CoinLockupTransfer Transaction Logic
//

func (bav *UtxoView) _connectCoinLockupTransfer(
	txn *MsgDeSoTxn,
	txHash *BlockHash,
	blockHeight uint32,
	verifySignatures bool,
) (_totalInput uint64,
	_totalOutput uint64,
	_utxoOps []*UtxoOperation,
	_err error) {
	var utxoOpsForTxn []*UtxoOperation

	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.LockupsBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return 0, 0, nil,
			errors.Wrap(RuleErrorLockupTxnBeforeBlockHeight, "_connectCoinLockupTransfer")
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCoinLockupTransfer {
		return 0, 0, nil, fmt.Errorf(
			"_connectCoinLockupTransfer: called with bad TxnType: %s", txn.TxnMeta.GetTxnType().String())
	}

	// Try connecting the basic transfer without considering transaction metadata.
	totalInput, totalOutput, utxoOpsForBasicTransfer, err :=
		bav._connectBasicTransfer(txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrap(err, "_connectCoinLockupTransfer")
	}
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpsForBasicTransfer...)

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*CoinLockupTransferMetadata)

	// Validate the transfer amount as non-zero.
	if txMeta.LockedCoinsToTransferBaseUnits.IsZero() {
		return 0, 0, nil, errors.Wrap(RuleErrorCoinLockupTransferOfAmountZero,
			"_connectCoinLockupTransfer")
	}

	// Validate recipient and profile public keys as valid.
	var profileEntry *ProfileEntry
	if len(txMeta.RecipientPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupTransferInvalidRecipientPubKey, "_connectCoinLockupTransfer")
	}
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupTransferInvalidProfilePubKey, "_connectCoinLockupTransfer")
	}

	// Ensure the locked profile exists.
	profileEntry = bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey.ToBytes())
	if profileEntry == nil || profileEntry.isDeleted {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupTransferOnNonExistentProfile, "_connectCoinLockupTransfer")
	}

	// Fetch PKIDs for the recipient, sender, and profile.
	senderPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	senderPKID := senderPKIDEntry.PKID
	if txMeta.RecipientPublicKey.IsZeroPublicKey() {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupTransferToZeroPublicKey, "_connectCoinLockupTransfer")
	}
	receiverPKIDEntry := bav.GetPKIDForPublicKey(txMeta.RecipientPublicKey.ToBytes())
	receiverPKID := receiverPKIDEntry.PKID
	profilePKIDEntry := bav.GetPKIDForPublicKey(txMeta.ProfilePublicKey.ToBytes())
	profilePKID := profilePKIDEntry.PKID

	// Ensure the sender and receiver are different.
	if senderPKID.Eq(receiverPKID) {
		return 0, 0, nil, errors.Wrap(RuleErrorCoinLockupTransferSenderEqualsReceiver,
			"_connectCoinLockupTransfer")
	}

	// Fetch the sender's balance entries.
	senderLockedBalanceEntry, err :=
		bav.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			senderPKID, profilePKID, txMeta.UnlockTimestampNanoSecs, txMeta.UnlockTimestampNanoSecs)
	if err != nil {
		return 0, 0, nil,
			errors.Wrap(err, "connectCoinLockupTransfer failed to fetch senderLockedBalanceEntry")
	}
	if senderLockedBalanceEntry == nil || senderLockedBalanceEntry.isDeleted {
		senderLockedBalanceEntry = &LockedBalanceEntry{
			HODLerPKID:                  senderPKID,
			ProfilePKID:                 profilePKID,
			UnlockTimestampNanoSecs:     txMeta.UnlockTimestampNanoSecs,
			VestingEndTimestampNanoSecs: txMeta.UnlockTimestampNanoSecs,
			BalanceBaseUnits:            *uint256.NewInt(0),
		}
	}
	prevSenderLockedBalanceEntry := senderLockedBalanceEntry.Copy()

	// Check that the sender's balance entry has sufficient balance.
	if txMeta.LockedCoinsToTransferBaseUnits.Gt(&senderLockedBalanceEntry.BalanceBaseUnits) {
		return 0, 0, nil, errors.Wrap(RuleErrorCoinLockupTransferInsufficientBalance,
			"_connectCoinLockupTransfer")
	}

	// Debit the sender's balance entry.
	senderLockedBalanceEntry.BalanceBaseUnits = *uint256.NewInt(0).Sub(
		&senderLockedBalanceEntry.BalanceBaseUnits, txMeta.LockedCoinsToTransferBaseUnits)

	// Fetch the recipient's balance entry.
	receiverLockedBalanceEntry, err :=
		bav.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			receiverPKID,
			profilePKID,
			txMeta.UnlockTimestampNanoSecs,
			txMeta.UnlockTimestampNanoSecs)
	if err != nil {
		return 0, 0, nil,
			errors.Wrap(err, "connectCoinLockupTransfer failed to fetch receiverLockedBalanceEntry")
	}
	if receiverLockedBalanceEntry == nil || receiverLockedBalanceEntry.isDeleted {
		receiverLockedBalanceEntry = &LockedBalanceEntry{
			HODLerPKID:                  receiverPKID,
			ProfilePKID:                 profilePKID,
			UnlockTimestampNanoSecs:     txMeta.UnlockTimestampNanoSecs,
			VestingEndTimestampNanoSecs: txMeta.UnlockTimestampNanoSecs,
			BalanceBaseUnits:            *uint256.NewInt(0),
		}
	}
	prevReceiverLockedBalanceEntry := receiverLockedBalanceEntry.Copy()

	// Fetch the transfer restrictions attached to the transfer.
	transferRestrictionStatus := profileEntry.DAOCoinEntry.LockupTransferRestrictionStatus

	// Validate transfer restriction rules.
	err = bav.CheckLockupTransferRestrictions(
		transferRestrictionStatus,
		profilePKID,
		senderPKID,
		receiverPKID,
		receiverLockedBalanceEntry)
	if err != nil {
		return 0, 0, nil,
			errors.Wrap(err, "_connectCoinLockupTransfer")
	}

	// Add to the recipient's balance entry, checking for overflow.
	newRecipientBalanceBaseUnits, err := SafeUint256().Add(&receiverLockedBalanceEntry.BalanceBaseUnits,
		txMeta.LockedCoinsToTransferBaseUnits)
	if err != nil {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinLockupTransferBalanceOverflowAtReceiver, "_connectCoinLockupTransfer")
	}
	receiverLockedBalanceEntry.BalanceBaseUnits = *newRecipientBalanceBaseUnits

	// Update the balances in the view.
	bav._setLockedBalanceEntry(senderLockedBalanceEntry)
	bav._setLockedBalanceEntry(receiverLockedBalanceEntry)

	// SAFEGUARD: Ensure no locked coins were printed by accident.
	prevTotalBalance, err := SafeUint256().Add(
		&prevSenderLockedBalanceEntry.BalanceBaseUnits,
		&prevReceiverLockedBalanceEntry.BalanceBaseUnits)
	if err != nil {
		return 0, 0, nil, errors.New("_connectCoinLockupTransfer" +
			" cannot verify balance change safeguard check due to previous balance overflow")
	}
	newSenderLockedBalanceEntry, err :=
		bav.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			senderPKID,
			profilePKID,
			txMeta.UnlockTimestampNanoSecs,
			txMeta.UnlockTimestampNanoSecs)
	if err != nil {
		return 0, 0, nil, errors.New("_connectCoinLockupTransfer" +
			" cannot verify balance change safeguard check; cannot fetch new sender locked balance entry")
	}
	newReceiverLockedBalanceEntry, err :=
		bav.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			receiverPKID,
			profilePKID,
			txMeta.UnlockTimestampNanoSecs,
			txMeta.UnlockTimestampNanoSecs)
	if err != nil {
		return 0, 0, nil, errors.New("_connectCoinLockupTransfer" +
			" cannot verify balance change safeguard check; cannot fetch new receiver locked balance entry")
	}
	newTotalBalance, err := SafeUint256().Add(
		&newSenderLockedBalanceEntry.BalanceBaseUnits,
		&newReceiverLockedBalanceEntry.BalanceBaseUnits)
	if err != nil {
		return 0, 0, nil, errors.New("_connectCoinLockupTransfer" +
			" cannot verify balance change safeguard check due to new balance overflow")
	}
	if !prevTotalBalance.Eq(newTotalBalance) {
		return 0, 0, nil, errors.New("_connectCoinLockupTransfer" +
			" failed coin printing safeguard check; this should not be possible")
	}

	// Create a UtxoOperation for easily disconnecting the transaction.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                           OperationTypeCoinLockupTransfer,
		PrevSenderLockedBalanceEntry:   prevSenderLockedBalanceEntry,
		PrevReceiverLockedBalanceEntry: prevReceiverLockedBalanceEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectCoinLockupTransfer(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32) error {
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectCoinLockupTransfer: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1

	// Verify the last operation as being a CoinLockupTransfer operation.
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCoinLockupTransfer {
		return fmt.Errorf("_disconnectDAOCoinLockup: Trying to revert "+
			"OperationTypeCoinLockupTransfer but found type %v", utxoOpsForTxn[operationIndex].Type)
	}

	// Sanity check the OperationTypeCoinLockupTransfer exists.
	operationData := utxoOpsForTxn[operationIndex]
	if operationData.PrevSenderLockedBalanceEntry == nil || operationData.PrevSenderLockedBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCoinLockupTransfer: Trying to revert OperationTypeCoinLockupTransfer " +
			"but found nil or deleted PrevSenderLockedBalanceEntry")
	}
	if operationData.PrevReceiverLockedBalanceEntry == nil || operationData.PrevReceiverLockedBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCoinLockupTransfer: Trying to revert OperationTypeCoinLockupTransfer " +
			"but found nil or deleted PrevReceiverLockedBalanceEntry")
	}

	// Fetch the LockedBalanceEntries in the view.
	senderLockedBalanceEntry, err :=
		bav.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			operationData.PrevSenderLockedBalanceEntry.HODLerPKID,
			operationData.PrevSenderLockedBalanceEntry.ProfilePKID,
			operationData.PrevSenderLockedBalanceEntry.UnlockTimestampNanoSecs,
			operationData.PrevSenderLockedBalanceEntry.UnlockTimestampNanoSecs)
	if err != nil {
		return errors.Wrap(err, "_disconnectCoinLockupTransfer failed to fetch senderLockedBalanceEntry")
	}
	if senderLockedBalanceEntry == nil || senderLockedBalanceEntry.isDeleted {
		senderLockedBalanceEntry = &LockedBalanceEntry{
			HODLerPKID:                  operationData.PrevSenderLockedBalanceEntry.HODLerPKID,
			ProfilePKID:                 operationData.PrevSenderLockedBalanceEntry.ProfilePKID,
			UnlockTimestampNanoSecs:     operationData.PrevSenderLockedBalanceEntry.UnlockTimestampNanoSecs,
			VestingEndTimestampNanoSecs: operationData.PrevSenderLockedBalanceEntry.VestingEndTimestampNanoSecs,
			BalanceBaseUnits:            *uint256.NewInt(0),
		}
	}
	receiverLockedBalanceEntry, err :=
		bav.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			operationData.PrevReceiverLockedBalanceEntry.HODLerPKID,
			operationData.PrevReceiverLockedBalanceEntry.ProfilePKID,
			operationData.PrevReceiverLockedBalanceEntry.UnlockTimestampNanoSecs,
			operationData.PrevReceiverLockedBalanceEntry.UnlockTimestampNanoSecs)
	if err != nil {
		return errors.Wrap(err, "_disconnectCoinLockupTransfer failed to fetch receiverLockedBalanceEntry")
	}
	if receiverLockedBalanceEntry == nil || receiverLockedBalanceEntry.isDeleted {
		receiverLockedBalanceEntry = &LockedBalanceEntry{
			HODLerPKID:                  operationData.PrevReceiverLockedBalanceEntry.HODLerPKID,
			ProfilePKID:                 operationData.PrevReceiverLockedBalanceEntry.ProfilePKID,
			UnlockTimestampNanoSecs:     operationData.PrevReceiverLockedBalanceEntry.UnlockTimestampNanoSecs,
			VestingEndTimestampNanoSecs: operationData.PrevReceiverLockedBalanceEntry.VestingEndTimestampNanoSecs,
			BalanceBaseUnits:            *uint256.NewInt(0),
		}
	}

	// Ensure reverting the transaction won't cause the recipients balances to increase
	// or cause the senders balances to decrease.
	if operationData.PrevSenderLockedBalanceEntry.BalanceBaseUnits.Lt(&senderLockedBalanceEntry.BalanceBaseUnits) {
		return fmt.Errorf("_disconnectCoinLockupTransfer: Reversion of coin lockup transfer would " +
			"result in less coins for sender")
	}
	if operationData.PrevReceiverLockedBalanceEntry.BalanceBaseUnits.Gt(&receiverLockedBalanceEntry.BalanceBaseUnits) {
		return fmt.Errorf("_disconnectCoinLockupTransfer: Reversion of coin lockup transfer would " +
			"result in more coins for receiver")
	}

	// Set the balance entry mappings.
	bav._setLockedBalanceEntry(operationData.PrevSenderLockedBalanceEntry)
	bav._setLockedBalanceEntry(operationData.PrevReceiverLockedBalanceEntry)

	// By here we only need to disconnect the basic transfer associated with the transaction.
	basicTransferOps := utxoOpsForTxn[:operationIndex]
	err = bav._disconnectBasicTransfer(currentTxn, txnHash, basicTransferOps, blockHeight)
	if err != nil {
		return errors.Wrap(err, "_disconnectCoinLockupTransfer")
	}

	return nil
}

//
// CoinUnlock Transaction Logic
//

func (bav *UtxoView) _connectCoinUnlock(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, blockTimestampNanoSecs int64,
	verifySignatures bool) (_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	var utxoOpsForTxn []*UtxoOperation

	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.LockupsBlockHeight ||
		blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
		return 0, 0, nil,
			errors.Wrap(RuleErrorLockupTxnBeforeBlockHeight, "_connectCoinUnlock")
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCoinUnlock {
		return 0, 0, nil, fmt.Errorf(
			"_connectCoinUnlock: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Try connecting the basic transfer without considering transaction metadata.
	totalInput, totalOutput, utxoOpsForBasicTransfer, err :=
		bav._connectBasicTransfer(txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrap(err, "_connectCoinUnlock")
	}
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpsForBasicTransfer...)

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*CoinUnlockMetadata)

	// Check for a valid profile public key.
	var profileEntry *ProfileEntry
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, errors.Wrap(RuleErrorDAOCoinInvalidPubKey,
			"_connectCoinUnlock")
	}

	// Check that we're not unlocking the zero public key.
	if txMeta.ProfilePublicKey.IsZeroPublicKey() {
		return 0, 0, nil, errors.Wrap(RuleErrorCoinUnlockCannotUnlockZeroPublicKey,
			"_connectCoinUnlock")
	}

	// Check that the associated public key exists.
	profileEntry = bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey.ToBytes())
	if profileEntry == nil || profileEntry.isDeleted {
		return 0, 0, nil, errors.Wrap(RuleErrorCoinUnlockOnNonExistentProfile,
			"_connectCoinUnlock")
	}

	// Convert the TransactorPublicKey to HODLerPKID
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return 0, 0, nil, errors.Wrap(RuleErrorCoinUnlockInvalidHODLerPKID,
			"_connectCoinUnlock")
	}
	hodlerPKID := transactorPKIDEntry.PKID

	// Convert the ProfilePublicKey to ProfilePKID.
	profilePKIDEntry := bav.GetPKIDForPublicKey(txMeta.ProfilePublicKey.ToBytes())
	if profilePKIDEntry == nil || profilePKIDEntry.isDeleted {
		return 0, 0, nil, errors.Wrap(RuleErrorCoinUnlockInvalidProfilePKID,
			"_connectCoinUnlock")
	}
	profilePKID := profilePKIDEntry.PKID

	// Retrieve unlockable locked balance entries.
	unvestedUnlockableLockedBalanceEntries, vestedUnlockableLockedBalanceEntries, err :=
		bav.GetUnlockableLockedBalanceEntries(hodlerPKID, profilePKID, blockTimestampNanoSecs)
	if err != nil {
		return 0, 0, nil, errors.Wrap(err, "_connectCoinUnlock")
	}
	if len(unvestedUnlockableLockedBalanceEntries) == 0 && len(vestedUnlockableLockedBalanceEntries) == 0 {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinUnlockNoUnlockableCoinsFound, "_connectCoinUnlock")
	}

	// Create an unlockedBalance uint256 to track what will be given back to the user.
	unlockedBalance := uint256.NewInt(0)

	// Unlock all unvested unlockable locked balance entries.
	var prevLockedBalanceEntries []*LockedBalanceEntry
	for _, unlockableLockedBalanceEntry := range unvestedUnlockableLockedBalanceEntries {
		unlockedBalance, err =
			SafeUint256().Add(unlockedBalance, &unlockableLockedBalanceEntry.BalanceBaseUnits)
		if err != nil {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinUnlockUnlockableCoinsOverflow, "_connectCoinUnlock")
		}

		// Append the LockedBalanceEntry in the event we rollback the transaction.
		prevLockedBalanceEntries = append(prevLockedBalanceEntries, unlockableLockedBalanceEntry.Copy())

		// Update the LockedBalanceEntry and delete the record.
		unlockableLockedBalanceEntry.BalanceBaseUnits = *uint256.NewInt(0)
		bav._deleteLockedBalanceEntry(unlockableLockedBalanceEntry)
	}

	// Unlock all vested locked balance entries.
	// NOTE: See the comment on LockedBalanceEntryKey for how we deal with modified vested locked balance entries.
	var modifiedLockedBalanceEntry *LockedBalanceEntry
	for _, unlockableLockedBalanceEntry := range vestedUnlockableLockedBalanceEntries {
		// Depending on the time of unlock, compute how much from the balance can be unlocked.
		amountToUnlock, err := CalculateVestedEarnings(unlockableLockedBalanceEntry, blockTimestampNanoSecs)
		if err != nil {
			return 0, 0, nil,
				errors.Wrap(err, "_connectCoinUnlock: error computing vested earnings")
		}

		// Add the unlocked amount and check for overflow.
		unlockedBalance, err =
			SafeUint256().Add(unlockedBalance, amountToUnlock)
		if err != nil {
			return 0, 0, nil,
				errors.Wrap(RuleErrorCoinUnlockUnlockableCoinsOverflow, "_connectCoinUnlock")
		}

		// Append the original LockedBalanceEntry in the event we rollback the transaction.
		prevLockedBalanceEntries = append(prevLockedBalanceEntries, unlockableLockedBalanceEntry.Copy())

		// Depending on when the unlock occurs, we either DELETE or MODIFY the locked balance entry.
		if blockTimestampNanoSecs >= unlockableLockedBalanceEntry.VestingEndTimestampNanoSecs {
			bav._deleteLockedBalanceEntry(unlockableLockedBalanceEntry)
		} else {
			// DELETE the previous key.
			bav._deleteLockedBalanceEntry(unlockableLockedBalanceEntry)

			// Create and modify a copy to prevent pointer reuse.
			modifiedLockedBalanceEntry = unlockableLockedBalanceEntry.Copy()
			modifiedLockedBalanceEntry.UnlockTimestampNanoSecs = blockTimestampNanoSecs
			newBalanceBaseUnits, err := SafeUint256().Sub(
				&modifiedLockedBalanceEntry.BalanceBaseUnits,
				amountToUnlock)
			if err != nil {
				return 0, 0, nil,
					errors.New("_connectCoinUnlock: newBalanceBaseUnits underflow; " +
						"this shouldn't be possible")
			}
			modifiedLockedBalanceEntry.BalanceBaseUnits = *newBalanceBaseUnits

			// SET the modified key.
			bav._setLockedBalanceEntry(modifiedLockedBalanceEntry)
		}
	}

	// Credit the transactor with either DAO coins or DeSo for this unlock.
	prevTransactorBalanceEntry :=
		bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(hodlerPKID, profilePKID, true)
	if prevTransactorBalanceEntry == nil || prevTransactorBalanceEntry.isDeleted {
		prevTransactorBalanceEntry = &BalanceEntry{
			HODLerPKID:   hodlerPKID,
			CreatorPKID:  profilePKID,
			BalanceNanos: uint256.Int{},
			HasPurchased: false,
		}
	}

	// Credit the transactor with the unlock amount.
	newTransactorBalanceEntry := prevTransactorBalanceEntry.Copy()
	newTransactorBalanceNanos, err := SafeUint256().Add(&newTransactorBalanceEntry.BalanceNanos, unlockedBalance)
	if err != nil {
		return 0, 0, nil, errors.Wrap(RuleErrorCoinUnlockCausesBalanceOverflow,
			"_connectCoinUnlock")
	}
	newTransactorBalanceEntry.BalanceNanos = *newTransactorBalanceNanos
	bav._setBalanceEntryMappings(newTransactorBalanceEntry, true)

	// Update CoinsInCirculation and NumberOfHolders to accurately reflect the changing balance.
	prevCoinEntry := profileEntry.DAOCoinEntry.Copy()
	newCoinsInCirculationNanos, err := SafeUint256().Add(
		&profileEntry.DAOCoinEntry.CoinsInCirculationNanos,
		unlockedBalance)
	if err != nil {
		return 0, 0, nil,
			errors.Wrap(RuleErrorCoinUnlockCausesCoinsInCirculationOverflow, "_connectCoinUnlock")
	}
	profileEntry.DAOCoinEntry.CoinsInCirculationNanos = *newCoinsInCirculationNanos
	if prevTransactorBalanceEntry.BalanceNanos.IsZero() && !newTransactorBalanceEntry.BalanceNanos.IsZero() {
		profileEntry.DAOCoinEntry.NumberOfHolders++
	}
	bav._setProfileEntryMappings(profileEntry)

	// Create a UtxoOp for the operation.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                       OperationTypeCoinUnlock,
		PrevTransactorBalanceEntry: prevTransactorBalanceEntry,
		PrevLockedBalanceEntries:   prevLockedBalanceEntries,
		ModifiedLockedBalanceEntry: modifiedLockedBalanceEntry,
		PrevCoinEntry:              prevCoinEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func CalculateVestedEarnings(
	lockedBalanceEntry *LockedBalanceEntry,
	blockTimestampNanoSecs int64,
) (
	_vestedEarnings *uint256.Int,
	_err error,
) {
	// Check if this lockup should not be unlocked right now.
	if blockTimestampNanoSecs <= lockedBalanceEntry.UnlockTimestampNanoSecs {
		return uint256.NewInt(0), nil
	}

	// Check if this lockup should be fully unlocked.
	if blockTimestampNanoSecs >= lockedBalanceEntry.VestingEndTimestampNanoSecs {
		return &lockedBalanceEntry.BalanceBaseUnits, nil
	}

	// Compute the vested earnings using CalculateLockupValueOverElapsedDuration
	vestedEarnings, err := CalculateLockupValueOverElapsedDuration(
		lockedBalanceEntry,
		blockTimestampNanoSecs-lockedBalanceEntry.UnlockTimestampNanoSecs)
	if err != nil {
		return uint256.NewInt(0),
			errors.Wrap(err, "CalculateVestedEarnings failed to compute vestedEarnings")
	}

	// Sanity check that vestedEarnings < BalanceBaseUnits
	if vestedEarnings.Gt(&lockedBalanceEntry.BalanceBaseUnits) ||
		vestedEarnings.Eq(&lockedBalanceEntry.BalanceBaseUnits) {
		return uint256.NewInt(0),
			errors.New("ComputeVestedEarnings: " +
				"vested earnings >= outstanding balance; this shouldn't be possible")
	}

	return vestedEarnings, nil
}

func (bav *UtxoView) _disconnectCoinUnlock(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32) error {

	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectCoinUnlock: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1

	// Verify the last operation as being a CoinUnlock operation.
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCoinUnlock {
		return fmt.Errorf("_disconnectCoinUnlock: Trying to revert "+
			"OperationTypeCoinUnlock but found type %v", utxoOpsForTxn[operationIndex].Type)
	}

	// Sanity check the CoinUnlock operation exists.
	operationData := utxoOpsForTxn[operationIndex]
	if operationData.PrevLockedBalanceEntries == nil || len(operationData.PrevLockedBalanceEntries) == 0 {
		return fmt.Errorf("_disconnectCoinUnlock: Trying to revert OperationTypeCoinUnlock " +
			"but found nil or empty previous locked balance entries slice")
	}
	for _, prevLockedBalanceEntry := range operationData.PrevLockedBalanceEntries {
		if prevLockedBalanceEntry == nil || prevLockedBalanceEntry.isDeleted {
			return fmt.Errorf("_disconnectCoinUnlock: Trying to revert OperationTypeCoinUnlock " +
				"but found nil or deleted previous locked balance entry")
		}
	}

	// Sanity check the data within the CoinUnlock.
	// Reverting an unlock of LockedBalanceEntry for unvested lockups should not result in less coins.
	for _, prevLockedBalanceEntry := range operationData.PrevLockedBalanceEntries {
		// Skip the balance decrease check for vested lockups -- the changing map key makes this an inaccurate test.
		if prevLockedBalanceEntry.UnlockTimestampNanoSecs < prevLockedBalanceEntry.VestingEndTimestampNanoSecs {
			bav._setLockedBalanceEntry(prevLockedBalanceEntry)
			continue
		}

		lockedBalanceEntry, err :=
			bav.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				prevLockedBalanceEntry.HODLerPKID,
				prevLockedBalanceEntry.ProfilePKID,
				prevLockedBalanceEntry.UnlockTimestampNanoSecs,
				prevLockedBalanceEntry.VestingEndTimestampNanoSecs)
		if err != nil {
			return errors.Wrap(err, "_disconnectCoinUnlock failed to fetch lockedBalanceEntry")
		}
		if lockedBalanceEntry == nil || lockedBalanceEntry.isDeleted {
			lockedBalanceEntry = &LockedBalanceEntry{
				HODLerPKID:                  prevLockedBalanceEntry.HODLerPKID,
				ProfilePKID:                 prevLockedBalanceEntry.ProfilePKID,
				UnlockTimestampNanoSecs:     prevLockedBalanceEntry.UnlockTimestampNanoSecs,
				VestingEndTimestampNanoSecs: prevLockedBalanceEntry.VestingEndTimestampNanoSecs,
				BalanceBaseUnits:            *uint256.NewInt(0),
			}
		}
		if prevLockedBalanceEntry.BalanceBaseUnits.Lt(&lockedBalanceEntry.BalanceBaseUnits) {
			return fmt.Errorf("_disconnectCoinUnlock: Trying to revert OperationTypeCoinUnlock " +
				"would cause locked balance entry balance to decrease")
		}
		bav._setLockedBalanceEntry(prevLockedBalanceEntry)
	}

	// If a modified vested locked balance entry exists, we must delete this from the view to ensure proper reversion.
	// This is because the underlying key for the vested lockup may have changed, and we
	// would otherwise leave this lingering in the view.
	if operationData.ModifiedLockedBalanceEntry != nil {
		bav._deleteLockedBalanceEntry(operationData.ModifiedLockedBalanceEntry)
	}

	// Reverting the BalanceEntry should not result in more coins.
	profilePKID := operationData.PrevLockedBalanceEntries[0].ProfilePKID
	hodlerPKID := operationData.PrevLockedBalanceEntries[0].HODLerPKID
	balanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(hodlerPKID, profilePKID, true)
	if operationData.PrevTransactorBalanceEntry == nil || operationData.PrevTransactorBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCoinUnlock: Trying to revert OperationTypeCoinUnlock " +
			"but found nil or deleted previous balance entry")
	}
	if operationData.PrevTransactorBalanceEntry.BalanceNanos.Gt(&balanceEntry.BalanceNanos) {
		return fmt.Errorf("_disconnectCoinUnlock: Trying to revert OperationTypeCoinUnlock " +
			"would cause balance entry balance to increase")
	}
	if operationData.PrevTransactorBalanceEntry.BalanceNanos.IsZero() {
		bav._deleteBalanceEntryMappingsWithPKIDs(operationData.PrevTransactorBalanceEntry,
			hodlerPKID, profilePKID, true)
	} else {
		bav._setBalanceEntryMappings(operationData.PrevTransactorBalanceEntry, true)
	}

	// Reverting the CoinEntry should not result in more coins in circulation.
	profileEntry := bav.GetProfileEntryForPKID(profilePKID)
	if profileEntry == nil || profileEntry.isDeleted {
		return fmt.Errorf("_disconnectCoinUnlock: Trying to revert coin unlock " +
			"but found nil profile entry; this shouldn't be possible")
	}
	if operationData.PrevCoinEntry.CoinsInCirculationNanos.Gt(&profileEntry.DAOCoinEntry.CoinsInCirculationNanos) {
		return fmt.Errorf("_disconnectCoinUnlock: Trying to revert OperationTypeCoinUnlock " +
			"would cause profile entry coin entry balance to increase")
	}
	profileEntry.DAOCoinEntry = *operationData.PrevCoinEntry
	bav._setProfileEntryMappings(profileEntry)

	// By here we only need to disconnect the basic transfer associated with the transaction.
	basicTransferOps := utxoOpsForTxn[:operationIndex]
	err := bav._disconnectBasicTransfer(currentTxn, txnHash, basicTransferOps, blockHeight)
	if err != nil {
		return errors.Wrap(err, "_disconnectCoinUnlock")
	}
	return nil
}

//
// DB FLUSHES
//

func (bav *UtxoView) _flushLockedBalanceEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Go through all entries in the LockedBalanceEntryMapKeyToLockedBalanceEntry map.
	for lockedBalanceEntryMapKeyIter, lockedBalanceEntry := range bav.LockedBalanceEntryKeyToLockedBalanceEntry {
		lockedBalanceEntryKey := lockedBalanceEntryMapKeyIter

		// Sanity check the key computed from the lockedBalanceEntry is equal
		// to the lockedBalanceEntryKey that maps to that entry.
		lockedBalanceEntryKeyInEntry := lockedBalanceEntry.ToMapKey()
		if lockedBalanceEntryKeyInEntry != lockedBalanceEntryKey {
			return fmt.Errorf("_flushLockedBalanceEntriesToDbWithTxn: LockedBalanceEntry has "+
				"LockedBalanceEntryKey: %v, which doesn't match the LockedBalanceEntryMapKeyToLockedBalanceEntry map key %v",
				&lockedBalanceEntryKeyInEntry, &lockedBalanceEntry)
		}

		// Delete the existing mappings in the db for this LockedBalanceEntry.
		// They will be re-added if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteLockedBalanceEntryWithTxn(txn, bav.Snapshot, *lockedBalanceEntry,
			bav.EventManager, lockedBalanceEntry.isDeleted); err != nil {
			return errors.Wrapf(
				err, "_flushLockedBalanceEntriesToDbWithTxn: Problem deleting mappings "+
					"for LockedBalanceEntry: %v", &lockedBalanceEntryKey)
		}
	}
	for _, lockedBalanceEntry := range bav.LockedBalanceEntryKeyToLockedBalanceEntry {
		if lockedBalanceEntry.isDeleted || lockedBalanceEntry.BalanceBaseUnits.IsZero() {
			// We do nothing as we've already deleted the entry above or the balance is zero.
		} else {
			if err := DbPutLockedBalanceEntryMappingsWithTxn(txn, bav.Snapshot, blockHeight,
				*lockedBalanceEntry, bav.EventManager); err != nil {
				return errors.Wrap(err, "_flushLockedBalanceEntriesToDbWithTxn")
			}
		}
	}

	// By here the LockedBalanceEntry mappings in the db should be up-to-date.
	return nil
}

func (bav *UtxoView) _flushLockupYieldCurvePointEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Go through all PKIDs with changes to their yield curves.
	for _, LockupYieldCurvePointMap := range bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints {
		// Go through all LockupYieldCurvePoints in the LockupYieldCurvePoint map.
		for lockupYieldCurvePointKey, lockupYieldCurvePoint := range LockupYieldCurvePointMap {

			// Sanity check the key computed from the lockupYieldCurvePoint is equal
			// to the lockupYieldCurvePointKey that maps to that entry.
			lockupYieldCurvePointKeyInEntry := lockupYieldCurvePoint.ToMapKey()
			if lockupYieldCurvePointKeyInEntry != lockupYieldCurvePointKey {
				return fmt.Errorf("_flushYieldCurveEntriesToDbWithTxn: LockupYieldCurvePoint has "+
					"LockupYieldCurvePoint: %v, which doesn't match the LockupYieldCurvePoint map key %v",
					&lockupYieldCurvePointKeyInEntry, &lockupYieldCurvePointKey)
			}

			// Delete the existing mappings in the db for this LockupYieldCurvePoint.
			// They will be re-added if the corresponding entry in memory has isDeleted=false.
			if err := DbDeleteLockupYieldCurvePointWithTxn(
				txn, bav.Snapshot, *lockupYieldCurvePoint,
				bav.EventManager, lockupYieldCurvePoint.isDeleted); err != nil {
				return errors.Wrapf(
					err, "_flushYieldCurveEntriesToDbWithTxn: Problem deleting mappings "+
						"for LockupYieldCurvePoint: %v", &lockupYieldCurvePoint)
			}
		}
	}
	// Go through all PKIDs with changes to their yield curves.
	for _, LockupYieldCurvePointMap := range bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints {
		// Go through all LockupYieldCurvePoints in the LockupYieldCurvePoint map.
		for _, lockupYieldCurvePoint := range LockupYieldCurvePointMap {
			if lockupYieldCurvePoint.isDeleted {
				// We do nothing as we've already deleted the entry above.
			} else {
				if err := DbPutLockupYieldCurvePointMappingsWithTxn(txn, bav.Snapshot, blockHeight,
					*lockupYieldCurvePoint, bav.EventManager); err != nil {
					return errors.Wrap(err, "_flushYieldCurveEntriesToDbWithTxn")
				}
			}
		}
	}

	// By here the LockupYieldCurvePoint mappings in the db should be up-to-date.
	return nil
}

//
// Derived Key Transactional Limits
//

type LockupLimitKey struct {
	ProfilePKID PKID
	ScopeType   LockupLimitScopeType
	Operation   LockupLimitOperation
}

func MakeLockupLimitKey(profilePKID PKID, scopeType LockupLimitScopeType, operation LockupLimitOperation) LockupLimitKey {
	return LockupLimitKey{
		ProfilePKID: profilePKID,
		ScopeType:   scopeType,
		Operation:   operation,
	}
}

func (lockupLimitKey *LockupLimitKey) Encode() []byte {
	var data []byte
	data = append(data, lockupLimitKey.ProfilePKID.ToBytes()...)
	data = append(data, byte(lockupLimitKey.ScopeType))
	data = append(data, byte(lockupLimitKey.Operation))
	return data
}

func (lockupLimitKey *LockupLimitKey) Decode(rr *bytes.Reader) error {
	var err error

	// ProfilePKID
	profilePKID := &PKID{}
	if err = profilePKID.FromBytes(rr); err != nil {
		return errors.Wrap(err, "LockupLimitKey.Decode: Problem reading ProfilePKID: ")
	}
	lockupLimitKey.ProfilePKID = *profilePKID

	// ScopeType
	var scopeTypeByte byte
	if scopeTypeByte, err = rr.ReadByte(); err != nil {
		return errors.Wrap(err, "LockupLimitKey.Decode: Problem reading ScopeType: ")
	}
	lockupLimitKey.ScopeType = LockupLimitScopeType(scopeTypeByte)

	// Operation
	var operationByte byte
	if operationByte, err = rr.ReadByte(); err != nil {
		return errors.Wrap(err, "LockupLimitKey.Decode: Problem reading Operation: ")
	}
	lockupLimitKey.Operation = LockupLimitOperation(operationByte)

	return nil
}

type LockupLimitOperation uint8
type LockupLimitOperationString string

const (
	AnyLockupOperation                            LockupLimitOperation = 0
	CoinLockupOperation                           LockupLimitOperation = 1
	UpdateCoinLockupYieldCurveOperation           LockupLimitOperation = 2
	UpdateCoinLockupTransferRestrictionsOperation LockupLimitOperation = 3
	CoinLockupTransferOperation                   LockupLimitOperation = 4
	CoinLockupUnlockOperation                     LockupLimitOperation = 5
	UndefinedCoinLockupOperation                  LockupLimitOperation = 6
)

const (
	AnyLockupOperationString                            LockupLimitOperationString = "Any"
	CoinLockupOperationString                           LockupLimitOperationString = "CoinLockup"
	UpdateCoinLockupYieldCurveOperationString           LockupLimitOperationString = "UpdateCoinLockupYieldCurve"
	UpdateCoinLockupTransferRestrictionsOperationString LockupLimitOperationString = "UpdateCoinLockupTransferRestrictions"
	CoinLockupTransferOperationString                   LockupLimitOperationString = "CoinLockupTransferOperationString"
	CoinLockupUnlockOperationString                     LockupLimitOperationString = "CoinLockupUnlock"
	UndefinedCoinLockupOperationString                  LockupLimitOperationString = "Undefined"
)

func (lockupLimitOperation LockupLimitOperation) ToString() string {
	return string(lockupLimitOperation.ToOperationString())
}

func (lockupLimitOperation LockupLimitOperation) ToOperationString() LockupLimitOperationString {
	switch lockupLimitOperation {
	case AnyLockupOperation:
		return AnyLockupOperationString
	case CoinLockupOperation:
		return CoinLockupOperationString
	case UpdateCoinLockupYieldCurveOperation:
		return UpdateCoinLockupYieldCurveOperationString
	case UpdateCoinLockupTransferRestrictionsOperation:
		return UpdateCoinLockupTransferRestrictionsOperationString
	case CoinLockupTransferOperation:
		return CoinLockupTransferOperationString
	case CoinLockupUnlockOperation:
		return CoinLockupUnlockOperationString
	default:
		return UndefinedCoinLockupOperationString
	}
}

func (lockupLimitOperationString LockupLimitOperationString) ToOperationType() LockupLimitOperation {
	switch lockupLimitOperationString {
	case AnyLockupOperationString:
		return AnyLockupOperation
	case CoinLockupOperationString:
		return CoinLockupOperation
	case UpdateCoinLockupYieldCurveOperationString:
		return UpdateCoinLockupYieldCurveOperation
	case UpdateCoinLockupTransferRestrictionsOperationString:
		return UpdateCoinLockupTransferRestrictionsOperation
	case CoinLockupTransferOperationString:
		return CoinLockupTransferOperation
	case CoinLockupUnlockOperationString:
		return CoinLockupUnlockOperation
	default:
		return UndefinedCoinLockupOperation
	}
}

type LockupLimitScopeType uint8
type LockupLimitScopeTypeString string

const (
	LockupLimitScopeTypeUndefined   LockupLimitScopeType = 0
	LockupLimitScopeTypeAnyCoins    LockupLimitScopeType = 1
	LockupLimitScopeTypeScopedCoins LockupLimitScopeType = 2
)

const (
	LockupLimitScopeTypeUndefinedString   LockupLimitScopeTypeString = "Undefined"
	LockupLimitScopeTypeAnyCoinsString    LockupLimitScopeTypeString = "AnyCoins"
	LockupLimitScopeTypeScopedCoinsString LockupLimitScopeTypeString = "ScopedCoins"
)

func (lockupLimitScopeType LockupLimitScopeType) ToString() string {
	return string(lockupLimitScopeType.ToScopeString())
}

func (lockupLimitScopeType LockupLimitScopeType) ToScopeString() LockupLimitScopeTypeString {
	switch lockupLimitScopeType {
	case LockupLimitScopeTypeAnyCoins:
		return LockupLimitScopeTypeAnyCoinsString
	case LockupLimitScopeTypeScopedCoins:
		return LockupLimitScopeTypeScopedCoinsString
	default:
		return LockupLimitScopeTypeUndefinedString
	}
}

func (lockupLimitScopeType LockupLimitScopeTypeString) ToScopeType() LockupLimitScopeType {
	switch lockupLimitScopeType {
	case LockupLimitScopeTypeAnyCoinsString:
		return LockupLimitScopeTypeAnyCoins
	case LockupLimitScopeTypeScopedCoinsString:
		return LockupLimitScopeTypeScopedCoins
	default:
		return LockupLimitScopeTypeUndefined
	}
}

func (bav *UtxoView) _checkLockupTxnSpendingLimitAndUpdateDerivedKey(
	derivedKeyEntry DerivedKeyEntry,
	profilePublicKey *PublicKey,
	lockupOperation LockupLimitOperation,
) (DerivedKeyEntry, error) {
	// Convert profile public key to PKID.
	var profilePKID *PKID
	if profilePublicKey.IsZeroPublicKey() {
		profilePKID = ZeroPKID.NewPKID()
	} else {
		profilePKIDEntry := bav.GetPKIDForPublicKey(profilePublicKey.ToBytes())
		if profilePKIDEntry == nil || profilePKIDEntry.isDeleted {
			return derivedKeyEntry,
				errors.Wrap(RuleErrorDerivedKeyCoinLockupOperationInvalidProfilePKID,
					"_checkCoinLockupTxnSpendingLimitAndUpdateDerivedKey")
		}
		profilePKID = profilePKIDEntry.PKID.NewPKID()
	}

	// Start by checking (specific profile PKID || specific operation) key
	profilePKIDOperationKey := MakeLockupLimitKey(*profilePKID, LockupLimitScopeTypeScopedCoins, lockupOperation)
	if _checkLimitKeyAndUpdateDerivedKeyEntry(profilePKIDOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Next check (specific profile PKID || any operation) key
	profilePKIDAnyOperationKey := MakeLockupLimitKey(*profilePKID, LockupLimitScopeTypeScopedCoins, AnyLockupOperation)
	if _checkLimitKeyAndUpdateDerivedKeyEntry(profilePKIDAnyOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Next check (any creator PKID || specific operation) key
	anyProfilePKIDOperationKey := MakeLockupLimitKey(ZeroPKID, LockupLimitScopeTypeAnyCoins, lockupOperation)
	if _checkLimitKeyAndUpdateDerivedKeyEntry(anyProfilePKIDOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Next check (any creator PKID || any operation) key
	anyProfilePKIDAnyOperationKey := MakeLockupLimitKey(ZeroPKID, LockupLimitScopeTypeAnyCoins, AnyLockupOperation)
	if _checkLimitKeyAndUpdateDerivedKeyEntry(anyProfilePKIDAnyOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	return derivedKeyEntry, errors.Wrapf(RuleErrorDerivedKeyCoinLockupOperationNotAuthorized, ""+
		"_checkCoinLockupTxnSpendingLimitAndUpdateDerivedKey: coin lockup operation (type %s) not authorized: ",
		lockupOperation.ToString())
}

func _checkLimitKeyAndUpdateDerivedKeyEntry(key LockupLimitKey, derivedKeyEntry DerivedKeyEntry) bool {
	if derivedKeyEntry.TransactionSpendingLimitTracker == nil ||
		derivedKeyEntry.TransactionSpendingLimitTracker.LockupLimitMap == nil {
		return false
	}
	// If the key is present in the LockupLimitMap...
	lockupOperationLimit, lockupOperationLimitExists :=
		derivedKeyEntry.TransactionSpendingLimitTracker.LockupLimitMap[key]
	if !lockupOperationLimitExists || lockupOperationLimit <= 0 {
		return false
	}
	// If this is the last operation allowed for this key, we delete the key from the map.
	if lockupOperationLimit == 1 {
		delete(derivedKeyEntry.TransactionSpendingLimitTracker.LockupLimitMap, key)
	} else {
		// Otherwise we decrement the number of operations remaining for this key
		derivedKeyEntry.TransactionSpendingLimitTracker.LockupLimitMap[key]--
	}
	// Return true because we found the key and decremented the remaining operations
	return true
}

// TXINDEX STUBS

// TYPES: CoinLockupTxindexMetadata
type CoinLockupTxindexMetadata struct {
}

func (txindexMetadata *CoinLockupTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	return []byte{}
}

func (txindexMetadata *CoinLockupTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	return nil
}

func (txindexMetadata *CoinLockupTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txindexMetadata *CoinLockupTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCoinLockupTxindexMetadata
}

// TYPES: UpdateCoinLockupParamsTxindexMetadata
type UpdateCoinLockupParamsTxindexMetadata struct {
}

func (txindexMetadata *UpdateCoinLockupParamsTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	return []byte{}
}

func (txindexMetadata *UpdateCoinLockupParamsTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	return nil
}

func (txindexMetadata *UpdateCoinLockupParamsTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txindexMetadata *UpdateCoinLockupParamsTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeUpdateCoinLockupParamsTxindexMetadata
}

// TYPES: CoinLockupTransferTxindexMetadata
type CoinLockupTransferTxindexMetadata struct {
}

func (txindexMetadata *CoinLockupTransferTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	return []byte{}
}

func (txindexMetadata *CoinLockupTransferTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	return nil
}

func (txindexMetadata *CoinLockupTransferTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txindexMetadata *CoinLockupTransferTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCoinLockupTransferTxindexMetadata
}

// TYPES: CoinUnlockTxindexMetadata
type CoinUnlockTxindexMetadata struct {
}

func (txindexMetadata *CoinUnlockTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	return []byte{}
}

func (txindexMetadata *CoinUnlockTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	return nil
}

func (txindexMetadata *CoinUnlockTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txindexMetadata *CoinUnlockTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCoinUnlockTxindexMetadata
}
