package lib

import (
	"bytes"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"sort"
)

//
// TYPES: LockedBalanceEntry
//

type LockedBalanceEntry struct {
	HODLerPKID                  *PKID
	ProfilePKID                 *PKID
	ExpirationTimestampNanoSecs int64
	BalanceBaseUnits            uint256.Int
	isDeleted                   bool
}

type LockedBalanceEntryKey struct {
	HODLerPKID                      PKID
	ProfilePKID                     PKID
	ExpirationTimestampUnixNanoSecs int64
}

func (lockedBalanceEntry *LockedBalanceEntry) Copy() *LockedBalanceEntry {
	return &LockedBalanceEntry{
		HODLerPKID:                  lockedBalanceEntry.HODLerPKID.NewPKID(),
		ProfilePKID:                 lockedBalanceEntry.ProfilePKID.NewPKID(),
		ExpirationTimestampNanoSecs: lockedBalanceEntry.ExpirationTimestampNanoSecs,
		BalanceBaseUnits:            lockedBalanceEntry.BalanceBaseUnits,
		isDeleted:                   lockedBalanceEntry.isDeleted,
	}
}

func (lockedBalanceEntry *LockedBalanceEntry) Eq(other *LockedBalanceEntry) bool {
	return lockedBalanceEntry.ToMapKey() == other.ToMapKey()
}

func (lockedBalanceEntry *LockedBalanceEntry) ToMapKey() LockedBalanceEntryKey {
	return LockedBalanceEntryKey{
		HODLerPKID:                      *lockedBalanceEntry.HODLerPKID,
		ProfilePKID:                     *lockedBalanceEntry.ProfilePKID,
		ExpirationTimestampUnixNanoSecs: lockedBalanceEntry.ExpirationTimestampNanoSecs,
	}
}

// DeSoEncoder Interface Implementation for LockedBalanceEntry

func (lockedBalanceEntry *LockedBalanceEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, lockedBalanceEntry.HODLerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, lockedBalanceEntry.ProfilePKID, skipMetadata...)...)
	data = append(data, UintToBuf(uint64(lockedBalanceEntry.ExpirationTimestampNanoSecs))...)
	data = append(data, VariableEncodeUint256(&lockedBalanceEntry.BalanceBaseUnits)...)
	return data
}

func (lockedBalanceEntry *LockedBalanceEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// HODLerPKID
	lockedBalanceEntry.HODLerPKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading HODLerPKID")
	}

	// ProfilePKID
	lockedBalanceEntry.ProfilePKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading ProfilePKID")
	}

	// ExpirationTimestampNanoSecs
	uint64ExpirationTimestampUnixNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading ExpirationTimestampNanoSecs")
	}
	lockedBalanceEntry.ExpirationTimestampNanoSecs = int64(uint64ExpirationTimestampUnixNanoSecs)

	// BalanceBaseUnits
	balanceBaseUnits, err := VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "LockedBalanceEntry.Decode: Problem reading BalanceBaseUnits")
	}
	lockedBalanceEntry.BalanceBaseUnits = *balanceBaseUnits

	return err
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
		glog.Errorf("_setLockedBalanceEntryMappingsWithPKIDsTimestampType: Called with nil LockedBalanceEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the LockedBalanceEntry in the view.
	bav.LockedBalanceEntryKeyToLockedBalanceEntry[lockedBalanceEntry.ToMapKey()] = lockedBalanceEntry
}

func (bav *UtxoView) _deleteLockedBalanceEntry(lockedBalanceEntry *LockedBalanceEntry) {
	// Create a tombstone entry.
	tombstoneLockedBalanceEntry := *lockedBalanceEntry
	tombstoneLockedBalanceEntry.isDeleted = true

	// Set the LockupYieldCurvePoint as deleted in the view.
	bav._setLockedBalanceEntry(&tombstoneLockedBalanceEntry)
}

// Get Helper Functions for LockedBalanceEntry

func (bav *UtxoView) GetLockedBalanceEntryForHODLerPKIDProfilePKIDExpirationTimestampNanoSecs(
	hodlerPKID *PKID, profilePKID *PKID, expirationTimestampNanoSecs int64) (_lockedBalanceEntry *LockedBalanceEntry) {
	// Create a key associated with the LockedBalanceEntry.
	lockedBalanceEntryKey := (&LockedBalanceEntry{
		HODLerPKID:                  hodlerPKID,
		ProfilePKID:                 profilePKID,
		ExpirationTimestampNanoSecs: expirationTimestampNanoSecs,
	}).ToMapKey()

	// Check if the key exists in the view.
	if viewEntry, viewEntryExists :=
		bav.LockedBalanceEntryKeyToLockedBalanceEntry[lockedBalanceEntryKey]; viewEntryExists {
		return viewEntry
	}

	// No mapping exists in the view, check for an entry in the DB.
	lockedBalanceEntry := DBGetLockedBalanceEntryForHODLerPKIDProfilePKIDExpirationTimestampNanoSecs(
		bav.Handle, bav.Snapshot, hodlerPKID, profilePKID, expirationTimestampNanoSecs)

	// Cache the DB entry in the in-memory map.
	if lockedBalanceEntry != nil {
		bav._setLockedBalanceEntry(lockedBalanceEntry)
	}

	return lockedBalanceEntry
}

func (bav *UtxoView) GetUnlockableLockedBalanceEntries(
	hodlerPKID *PKID,
	profilePKID *PKID,
	currentTimestampNanoSecs int64,
) ([]*LockedBalanceEntry, error) {
	// Validate inputs.
	if hodlerPKID == nil {
		return nil, errors.New("UtxoView.GetUnlockableLockedBalanceEntries: nil hodlerPKID provided as input")
	}
	if profilePKID == nil {
		return nil, errors.New("UtxoView.GetUnlockableLockedBalanceEntries: nil profilePKID provided as input")
	}

	// First, pull unlockable LockedBalanceEntries from the db and cache them in the UtxoView.
	dbUnlockableLockedBalanceEntries, err := DBGetUnlockableLockedBalanceEntries(
		bav.Handle, bav.Snapshot, hodlerPKID, profilePKID, currentTimestampNanoSecs)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetUnlockableLockedBalanceEntries")
	}
	for _, lockedBalanceEntry := range dbUnlockableLockedBalanceEntries {
		// Cache results in the UtxoView.
		if _, exists := bav.LockedBalanceEntryKeyToLockedBalanceEntry[lockedBalanceEntry.ToMapKey()]; !exists {
			bav._setLockedBalanceEntry(lockedBalanceEntry)
		}
	}

	// Then, pull unlockable LockedBalanceEntries from the UtxoView.
	var unlockableLockedBalanceEntries []*LockedBalanceEntry
	for _, lockedBalanceEntry := range bav.LockedBalanceEntryKeyToLockedBalanceEntry {
		// Filter to matching LockedBalanceEntries.
		if !lockedBalanceEntry.HODLerPKID.Eq(hodlerPKID) ||
			!lockedBalanceEntry.ProfilePKID.Eq(profilePKID) ||
			lockedBalanceEntry.ExpirationTimestampNanoSecs > currentTimestampNanoSecs ||
			lockedBalanceEntry.BalanceBaseUnits.IsZero() ||
			lockedBalanceEntry.isDeleted {
			continue
		}
		unlockableLockedBalanceEntries = append(unlockableLockedBalanceEntries, lockedBalanceEntry)
	}

	// Sort UnlockableLockedBalanceEntries by timestamp ASC.
	sort.Slice(unlockableLockedBalanceEntries, func(ii, jj int) bool {
		return unlockableLockedBalanceEntries[ii].ExpirationTimestampNanoSecs <
			unlockableLockedBalanceEntries[jj].ExpirationTimestampNanoSecs
	})
	return unlockableLockedBalanceEntries, nil
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
	ProfilePKID            *PKID
	LockupDurationNanoSecs int64
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) Copy() *LockupYieldCurvePoint {
	return &LockupYieldCurvePoint{
		ProfilePKID:               lockupYieldCurvePoint.ProfilePKID.NewPKID(),
		LockupDurationNanoSecs:    lockupYieldCurvePoint.LockupDurationNanoSecs,
		LockupYieldAPYBasisPoints: lockupYieldCurvePoint.LockupYieldAPYBasisPoints,
	}
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) Eq(other *LockupYieldCurvePoint) bool {
	return lockupYieldCurvePoint.ToMapKey() == other.ToMapKey()
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) ToMapKey() LockupYieldCurvePointKey {
	return LockupYieldCurvePointKey{
		ProfilePKID:            lockupYieldCurvePoint.ProfilePKID,
		LockupDurationNanoSecs: lockupYieldCurvePoint.LockupDurationNanoSecs,
	}
}

// DeSoEncoder Interface Implementation for LockupYieldCurvePoint

func (lockupYieldCurvePoint *LockupYieldCurvePoint) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, lockupYieldCurvePoint.ProfilePKID, skipMetadata...)...)
	data = append(data, UintToBuf(uint64(lockupYieldCurvePoint.LockupDurationNanoSecs))...)
	data = append(data, UintToBuf(lockupYieldCurvePoint.LockupYieldAPYBasisPoints)...)
	return data
}

func (lockupYieldCurvePoint *LockupYieldCurvePoint) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// ProfilePKID
	lockupYieldCurvePoint.ProfilePKID, err = DecodeDeSoEncoder(&PKID{}, rr)
	if err != nil {
		return errors.Wrapf(err, "LockupYieldCurvePoint.Decode: Problem reading ProfilePKID")
	}

	// LockupDurationNanoSecs
	uint64LockupDurationNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "LockupYieldCurvePoint.Decode: Problem reading LockupDurationNanoSecs")
	}
	lockupYieldCurvePoint.LockupDurationNanoSecs = int64(uint64LockupDurationNanoSecs)

	// LockupYieldAPYBasisPoints
	lockupYieldAPYBasisPoints, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "LockupYieldCurvePoint.Decode: Problem reading LockupYieldAPYBasisPoints")
	}
	lockupYieldCurvePoint.LockupYieldAPYBasisPoints = lockupYieldAPYBasisPoints

	return err
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
	// Create a tombstone entry.
	tombstoneLockupYieldCurvePoint := *point
	tombstoneLockupYieldCurvePoint.isDeleted = true

	// Set the LockupYieldCurvePoint as deleted in the view.
	bav._setLockupYieldCurvePoint(&tombstoneLockupYieldCurvePoint)
}

// Get Helper Functions for LockupYieldCurvePoint

func (bav *UtxoView) GetYieldCurvePointByProfilePKIDAndDurationNanoSecs(profilePKID *PKID,
	lockupDurationNanoSecs int64) (_lockupYieldCurvePoint *LockupYieldCurvePoint) {
	var lockupYieldCurvePoint *LockupYieldCurvePoint

	// Check the view for a yield curve point.
	if _, pointsInView := bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID]; pointsInView {
		lockupYieldCurvePointKey := (&LockupYieldCurvePoint{
			ProfilePKID:            profilePKID,
			LockupDurationNanoSecs: lockupDurationNanoSecs,
		}).ToMapKey()
		if inMemoryYieldCurvePoint, pointExists :=
			bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID][lockupYieldCurvePointKey]; pointExists {
			return inMemoryYieldCurvePoint
		}
	}

	// No mapping exists in the view, check for an entry in the DB.
	lockupYieldCurvePoint = DBGetYieldCurvePointsByProfilePKIDAndDurationNanoSecs(bav.GetDbAdapter().badgerDb,
		bav.Snapshot, profilePKID, lockupDurationNanoSecs)

	// Cache the DB entry in the in-memory map.
	if lockupYieldCurvePoint != nil {
		bav._setLockupYieldCurvePoint(lockupYieldCurvePoint)
	}

	return lockupYieldCurvePoint
}

func (bav *UtxoView) GetLocalYieldCurvePoints(profilePKID *PKID, lockupDuration int64) (
	_leftLockupPoint *LockupYieldCurvePoint, _rightLockupPoint *LockupYieldCurvePoint) {
	var leftLockupPoint *LockupYieldCurvePoint
	var rightLockupPoint *LockupYieldCurvePoint

	// Check the view for yield curve points.
	if _, pointsInView := bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID]; pointsInView {
		for _, lockupYieldCurvePoint := range bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[*profilePKID] {
			// Check for nil pointer cases.
			if lockupYieldCurvePoint.LockupDurationNanoSecs < lockupDuration && leftLockupPoint == nil {
				leftLockupPoint = lockupYieldCurvePoint
			}
			if lockupYieldCurvePoint.LockupDurationNanoSecs >= lockupDuration && rightLockupPoint == nil {
				rightLockupPoint = lockupYieldCurvePoint
			}

			// Check if the point is "more left" than the current left point.
			if lockupYieldCurvePoint.LockupDurationNanoSecs < lockupDuration &&
				lockupYieldCurvePoint.LockupDurationNanoSecs > leftLockupPoint.LockupDurationNanoSecs {
				leftLockupPoint = lockupYieldCurvePoint.Copy()
			}

			// Check if the point is "more right" than the current right point.
			if lockupYieldCurvePoint.LockupDurationNanoSecs >= lockupDuration &&
				lockupYieldCurvePoint.LockupDurationNanoSecs < leftLockupPoint.LockupDurationNanoSecs {
				rightLockupPoint = lockupYieldCurvePoint.Copy()
			}
		}
	}

	// Now we quickly fetch left and right local yield curve points from the DB using careful seek operations.
	leftDBLockupPoint, rightDBLockupPoint := DBGetLocalYieldCurvePoints(
		bav.GetDbAdapter().badgerDb, bav.Snapshot, profilePKID, lockupDuration)

	// Check for nil pointer cases.
	if leftDBLockupPoint != nil &&
		leftDBLockupPoint.LockupDurationNanoSecs < lockupDuration {
		leftLockupPoint = leftDBLockupPoint
	}
	if rightDBLockupPoint != nil &&
		rightDBLockupPoint.LockupDurationNanoSecs >= lockupDuration {
		rightLockupPoint = rightDBLockupPoint
	}

	// Check for an updated left and right yield curve point from the DB.
	if leftDBLockupPoint != nil &&
		leftDBLockupPoint.ProfilePKID.Eq(profilePKID) &&
		leftDBLockupPoint.LockupDurationNanoSecs < lockupDuration &&
		leftDBLockupPoint.LockupDurationNanoSecs > leftLockupPoint.LockupDurationNanoSecs {
		leftLockupPoint = leftDBLockupPoint
	}
	if rightDBLockupPoint != nil &&
		rightDBLockupPoint.ProfilePKID.Eq(profilePKID) &&
		rightDBLockupPoint.LockupDurationNanoSecs >= lockupDuration &&
		rightDBLockupPoint.LockupDurationNanoSecs < rightLockupPoint.LockupDurationNanoSecs {
		rightLockupPoint = rightDBLockupPoint
	}

	return leftLockupPoint, rightLockupPoint
}

//
// TYPES: CoinLockupMetadata
//

type CoinLockupMetadata struct {
	ProfilePublicKey        *PublicKey
	UnlockTimestampNanoSecs int64
	LockupAmountBaseUnits   *uint256.Int
}

func (txnData *CoinLockupMetadata) GetTxnType() TxnType {
	return TxnTypeCoinLockup
}

func (txnData *CoinLockupMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, UintToBuf(uint64(txnData.UnlockTimestampNanoSecs))...)
	data = append(data, VariableEncodeUint256(txnData.LockupAmountBaseUnits)...)
	return data, nil
}

func (txnData *CoinLockupMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinLockupMetadata.FromBytes: Problem reading ProfilePublicKey")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// UnlockTimestampNanoSecs
	uint64UnlockTimestampNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinLockupMetadata.FromBytes: Problem reading UnlockTimestampNanoSecs")
	}
	txnData.UnlockTimestampNanoSecs = int64(uint64UnlockTimestampNanoSecs)

	// LockupAmountBaseUnits
	txnData.LockupAmountBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinLockupMetadata.FromBytes: Problem reading LockupAmountBaseUnits")
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
	// is left unmodified. In any UpdateDAOCoinLockupParams transaction looking to modify only
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
	data = append(data, UintToBuf(uint64(txnData.LockupYieldDurationNanoSecs))...)
	data = append(data, UintToBuf(txnData.LockupYieldAPYBasisPoints)...)
	data = append(data, BoolToByte(txnData.RemoveYieldCurvePoint))
	data = append(data, BoolToByte(txnData.NewLockupTransferRestrictions))
	data = append(data, byte(txnData.LockupTransferRestrictionStatus))
	return data, nil
}

func (txnData *UpdateCoinLockupParamsMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	lockupYieldDurationNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading LockupYieldDurationNanoSecs")
	}
	txnData.LockupYieldDurationNanoSecs = int64(lockupYieldDurationNanoSecs)

	txnData.LockupYieldAPYBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading LockupYieldAPYBasisPoints")
	}

	txnData.RemoveYieldCurvePoint, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading RemoveYieldCurvePoint")
	}

	txnData.NewLockupTransferRestrictions, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading NewLockupTransferRestrictions")
	}

	lockedStatusByte, err := rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "UpdateDAOCoinLockupParams.FromBytes: Problem reading LockupTransferRestrictionStatus")
	}
	txnData.LockupTransferRestrictionStatus = TransferRestrictionStatus(lockedStatusByte)

	return nil
}

func (txnData *UpdateCoinLockupParamsMetadata) New() DeSoTxnMetadata {
	return &UpdateCoinLockupParamsMetadata{}
}

//
// TYPES: DAOCoinLockupTransferMetadata
//

type CoinLockupTransferMetadata struct {
	RecipientPublicKey              *PublicKey
	ProfilePublicKey                *PublicKey
	ExpirationTimestampUnixNanoSecs int64
	LockedCoinsToTransferBaseUnits  *uint256.Int
}

func (txnData *CoinLockupTransferMetadata) GetTxnType() TxnType {
	return TxnTypeCoinLockupTransfer
}

func (txnData *CoinLockupTransferMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.RecipientPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, UintToBuf(uint64(txnData.ExpirationTimestampUnixNanoSecs))...)
	data = append(data, VariableEncodeUint256(txnData.LockedCoinsToTransferBaseUnits)...)
	return data, nil
}

func (txnData *CoinLockupTransferMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// RecipientPublicKey
	recipientPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading RecipientPublicKey")
	}
	txnData.RecipientPublicKey = NewPublicKey(recipientPublicKeyBytes)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading ProfilePublicKey")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// ExpirationTimestampNanoSecs
	uint64ExpirationTimestampUnixNanoSecs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading ExpirationTimestampNanoSecs")
	}
	txnData.ExpirationTimestampUnixNanoSecs = int64(uint64ExpirationTimestampUnixNanoSecs)

	// LockedDAOCoinToTransferBaseUnits
	txnData.LockedCoinsToTransferBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLockupTransferMetadata.FromBytes: Problem reading LockedDAOCoinToTransferBaseUnits")
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
	ProfilePublicKey       *PublicKey
	CoinsToUnlockBaseUnits *uint256.Int
}

func (txnData *CoinUnlockMetadata) GetTxnType() TxnType {
	return TxnTypeCoinUnlock
}

func (txnData *CoinUnlockMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.ProfilePublicKey.ToBytes())...)
	data = append(data, VariableEncodeUint256(txnData.CoinsToUnlockBaseUnits)...)
	return data, nil
}

func (txnData *CoinUnlockMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	profilePublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinUnlockMetadata.FromBytes: Problem reading ProfilePublicKey")
	}
	txnData.ProfilePublicKey = NewPublicKey(profilePublicKeyBytes)

	// CoinToUnlockBaseUnits
	txnData.CoinsToUnlockBaseUnits, err = VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinUnlockMetadata.FromBytes: Problem reading DAOCoinToUnlockBaseUnits")
	}

	return nil
}

func (txnData *CoinUnlockMetadata) New() DeSoTxnMetadata {
	return &CoinUnlockMetadata{}
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
		if err := DbDeleteLockedBalanceEntryWithTxn(txn, bav.Snapshot, *lockedBalanceEntry); err != nil {
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
				*lockedBalanceEntry); err != nil {
				return errors.Wrapf(err, "_flushLockedBalanceEntriesToDbWithTxn")
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
			if err := DbDeleteLockupYieldCurvePointWithTxn(txn, bav.Snapshot, *lockupYieldCurvePoint); err != nil {
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
					*lockupYieldCurvePoint); err != nil {
					return errors.Wrapf(err, "_flushYieldCurveEntriesToDbWithTxn")
				}
			}
		}
	}

	// By here the LockupYieldCurvePoint mappings in the db should be up-to-date.
	return nil
}
