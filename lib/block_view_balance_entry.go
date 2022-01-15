package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"reflect"
)

func (bav *UtxoView) _getBalanceEntryForHODLerPKIDAndCreatorPKID(
	hodlerPKID *PKID, creatorPKID *PKID, isDAOCoin bool) *BalanceEntry {

	// If an entry exists in the in-memory map, return the value of that mapping.
	balanceEntryKey := MakeBalanceEntryKey(hodlerPKID, creatorPKID)
	if mapValue, existsMapValue := bav.GetHODLerPKIDCreatorPKIDToBalanceEntryMap(isDAOCoin)[balanceEntryKey]; existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	var balanceEntry *BalanceEntry
	if bav.Postgres != nil {
		balanceEntry = bav.GetBalanceEntry(hodlerPKID, creatorPKID, isDAOCoin)
	} else {
		balanceEntry = DBGetBalanceEntryForHODLerAndCreatorPKIDs(bav.Handle, hodlerPKID, creatorPKID, isDAOCoin)
	}
	if balanceEntry != nil {
		bav._setBalanceEntryMappingsWithPKIDs(balanceEntry, hodlerPKID, creatorPKID, isDAOCoin)
	}
	return balanceEntry
}

func (bav *UtxoView) GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
	hodlerPubKey []byte, creatorPubKey []byte, isDAOCoin bool) (
	_balanceEntry *BalanceEntry, _hodlerPKID *PKID, _creatorPKID *PKID) {

	// These are guaranteed to be non-nil as long as the public keys are valid.
	hodlerPKID := bav.GetPKIDForPublicKey(hodlerPubKey)
	creatorPKID := bav.GetPKIDForPublicKey(creatorPubKey)

	return bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(hodlerPKID.PKID, creatorPKID.PKID, isDAOCoin), hodlerPKID.PKID, creatorPKID.PKID
}

func (bav *UtxoView) _setBalanceEntryMappingsWithPKIDs(
	balanceEntry *BalanceEntry, hodlerPKID *PKID, creatorPKID *PKID, isDAOCoin bool) {

	// This function shouldn't be called with nil.
	if balanceEntry == nil {
		glog.Errorf("_setBalanceEntryMappingsWithPKIDs: Called with nil BalanceEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the BalanceEntry.
	balanceEntryKey := MakeBalanceEntryKey(hodlerPKID, creatorPKID)
	if isDAOCoin {
		bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry[balanceEntryKey] = balanceEntry
	} else {
		bav.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryKey] = balanceEntry
	}
}

func (bav *UtxoView) _setBalanceEntryMappings(balanceEntry *BalanceEntry, isDAOCoin bool) {
	bav._setBalanceEntryMappingsWithPKIDs(balanceEntry, balanceEntry.HODLerPKID, balanceEntry.CreatorPKID, isDAOCoin)
}

func (bav *UtxoView) _deleteBalanceEntryMappingsWithPKIDs(
	balanceEntry *BalanceEntry, hodlerPKID *PKID, creatorPKID *PKID, isDAOCoin bool) {

	// Create a tombstone entry.
	tombstoneBalanceEntry := *balanceEntry
	tombstoneBalanceEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setBalanceEntryMappingsWithPKIDs(&tombstoneBalanceEntry, hodlerPKID, creatorPKID, isDAOCoin)
}

func (bav *UtxoView) _deleteBalanceEntryMappings(
	balanceEntry *BalanceEntry, hodlerPublicKey []byte, creatorPublicKey []byte, isDAOCoin bool) {

	// These are guaranteed to be non-nil as long as the public keys are valid.
	hodlerPKID := bav.GetPKIDForPublicKey(hodlerPublicKey)
	creatorPKID := bav.GetPKIDForPublicKey(creatorPublicKey)

	// Set the mappings to point to the tombstone entry.
	bav._deleteBalanceEntryMappingsWithPKIDs(balanceEntry, hodlerPKID.PKID, creatorPKID.PKID, isDAOCoin)
}

func (bav *UtxoView) GetHoldings(pkid *PKID, fetchProfiles bool, isDAOCoin bool) (
	[]*BalanceEntry, []*ProfileEntry, error) {
	var entriesYouHold []*BalanceEntry
	if bav.Postgres != nil {
		entriesYouHold = bav.GetBalanceEntryHoldings(pkid, isDAOCoin)
	} else {
		holdings, err := DbGetBalanceEntriesYouHold(bav.Handle, pkid, true, isDAOCoin)
		if err != nil {
			return nil, nil, err
		}
		entriesYouHold = holdings
	}

	holdingsMap := make(map[PKID]*BalanceEntry)
	for _, balanceEntry := range entriesYouHold {
		holdingsMap[*balanceEntry.CreatorPKID] = balanceEntry
	}

	for _, balanceEntry := range bav.GetHODLerPKIDCreatorPKIDToBalanceEntryMap(isDAOCoin) {
		if reflect.DeepEqual(balanceEntry.HODLerPKID, pkid) {
			if _, ok := holdingsMap[*balanceEntry.CreatorPKID]; ok {
				// We found both an utxoView and a db balanceEntry. Update the BalanceEntry using utxoView data.
				holdingsMap[*balanceEntry.CreatorPKID].BalanceNanos = balanceEntry.BalanceNanos
				holdingsMap[*balanceEntry.CreatorPKID].HasPurchased = balanceEntry.HasPurchased
			} else {
				// Add new entries to the list
				entriesYouHold = append(entriesYouHold, balanceEntry)
			}
		}
	}

	// Optionally fetch all the profile entries as well.
	var profilesYouHold []*ProfileEntry
	if fetchProfiles {
		for _, balanceEntry := range entriesYouHold {
			// In this case you're the hodler so the creator is the one whose profile we need to fetch.
			currentProfileEntry := bav.GetProfileEntryForPKID(balanceEntry.CreatorPKID)
			profilesYouHold = append(profilesYouHold, currentProfileEntry)
		}
	}

	return entriesYouHold, profilesYouHold, nil
}

func (bav *UtxoView) GetHolders(pkid *PKID, fetchProfiles bool, isDAOCoin bool) (
	[]*BalanceEntry, []*ProfileEntry, error) {
	var holderEntries []*BalanceEntry
	if bav.Postgres != nil {
		holderEntries = bav.GetBalanceEntryHolders(pkid, isDAOCoin)
	} else {
		holders, err := DbGetBalanceEntriesHodlingYou(bav.Handle, pkid, true, isDAOCoin)
		if err != nil {
			return nil, nil, err
		}
		holderEntries = holders
	}

	holdersMap := make(map[PKID]*BalanceEntry)
	for _, balanceEntry := range holderEntries {
		holdersMap[*balanceEntry.HODLerPKID] = balanceEntry
	}

	for _, balanceEntry := range bav.GetHODLerPKIDCreatorPKIDToBalanceEntryMap(isDAOCoin) {
		if reflect.DeepEqual(balanceEntry.CreatorPKID, pkid) {
			if _, ok := holdersMap[*balanceEntry.HODLerPKID]; ok {
				// We found both an utxoView and a db balanceEntry. Update the BalanceEntry using utxoView data.
				holdersMap[*balanceEntry.HODLerPKID].BalanceNanos = balanceEntry.BalanceNanos
				holdersMap[*balanceEntry.HODLerPKID].HasPurchased = balanceEntry.HasPurchased
			} else {
				// Add new entries to the list
				holderEntries = append(holderEntries, balanceEntry)
			}
		}
	}

	// Optionally fetch all the profile entries as well.
	var profilesYouHold []*ProfileEntry
	if fetchProfiles {
		for _, balanceEntry := range holderEntries {
			// In this case you're the hodler so the creator is the one whose profile we need to fetch.
			currentProfileEntry := bav.GetProfileEntryForPKID(balanceEntry.CreatorPKID)
			profilesYouHold = append(profilesYouHold, currentProfileEntry)
		}
	}

	return holderEntries, profilesYouHold, nil
}

func (bav *UtxoView) GetHODLerPKIDCreatorPKIDToBalanceEntryMap(isDAOCoin bool) map[BalanceEntryMapKey]*BalanceEntry {
	if isDAOCoin {
		return bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry
	} else {
		return bav.HODLerPKIDCreatorPKIDToBalanceEntry
	}
}

//
// BalanceEntry Postgres
//

func (bav *UtxoView) GetBalanceEntry(holderPkid *PKID, creatorPkid *PKID, isDAOCoin bool) *BalanceEntry {
	if bav.Postgres == nil {
		return nil
	}
	var balanceEntry *BalanceEntry
	if isDAOCoin {
		balance := bav.Postgres.GetDAOCoinBalance(holderPkid, creatorPkid)
		if balance != nil {
			balanceEntry = balance.NewBalanceEntry()
		}
	} else {
		balance := bav.Postgres.GetCreatorCoinBalance(holderPkid, creatorPkid)
		if balance != nil {
			balanceEntry = balance.NewBalanceEntry()
		}
	}
	return balanceEntry
}

func (bav *UtxoView) GetBalanceEntryHoldings(pkid *PKID, isDAOCoin bool) []*BalanceEntry {
	if bav.Postgres == nil {
		return nil
	}
	var balanceEntries []*BalanceEntry
	if isDAOCoin {
		balances := bav.Postgres.GetDAOCoinHoldings(pkid)
		for _, balance := range balances {
			balanceEntries = append(balanceEntries, balance.NewBalanceEntry())
		}
	} else {
		balances := bav.Postgres.GetCreatorCoinHoldings(pkid)
		for _, balance := range balances {
			balanceEntries = append(balanceEntries, balance.NewBalanceEntry())
		}
	}
	return balanceEntries
}

func (bav *UtxoView) GetBalanceEntryHolders(pkid *PKID, isDAOCoin bool) []*BalanceEntry {
	if bav.Postgres == nil {
		return nil
	}
	var balanceEntries []*BalanceEntry
	if isDAOCoin {
		balances := bav.Postgres.GetDAOCoinHolders(pkid)
		for _, balance := range balances {
			balanceEntries = append(balanceEntries, balance.NewBalanceEntry())
		}
	} else {
		balances := bav.Postgres.GetCreatorCoinHolders(pkid)
		for _, balance := range balances {
			balanceEntries = append(balanceEntries, balance.NewBalanceEntry())
		}
	}
	return balanceEntries
}

// This function is the workhorse for both _connectCreatorCoinTransfer and
// _connectDAOCoinTransfer. We consolidated the code because they're very similar.
func (bav *UtxoView) HelpConnectCoinTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool, isDAOCoin bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// This code block is a bit ugly because Go doesn't support generics. In an ideal world,
	// we wouldn't have to repeat all of the assignments twice.
	var receiverPublicKey []byte
	var profilePublicKey []byte
	var coinToTransferNanos *uint256.Int
	if isDAOCoin {
		// In this case, we're dealing with a DAOCoin transfer
		txMeta := txn.TxnMeta.(*DAOCoinTransferMetadata)
		receiverPublicKey = txMeta.ReceiverPublicKey
		profilePublicKey = txMeta.ProfilePublicKey
		coinToTransferNanos = &txMeta.DAOCoinToTransferNanos
	} else {
		// In this case, we're dealing with a CreatorCoin transfer
		txMeta := txn.TxnMeta.(*CreatorCoinTransferMetadataa)
		receiverPublicKey = txMeta.ReceiverPublicKey
		profilePublicKey = txMeta.ProfilePublicKey
		coinToTransferNanos = uint256.NewInt().SetUint64(txMeta.CreatorCoinToTransferNanos)
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_helpConnectCoinTransfer: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorCoinTransferRequiresNonZeroInput
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Check that the specified receiver public key is valid.
	if len(receiverPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorCoinTransferInvalidReceiverPubKeySize
	}
	if _, err = btcec.ParsePubKey(receiverPublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(
			RuleErrorCoinTransferInvalidReceiverPubKey, err.Error())
	}

	// Check that the sender and receiver public keys are different.
	if reflect.DeepEqual(txn.PublicKey, receiverPublicKey) {
		return 0, 0, nil, RuleErrorCoinTransferCannotTransferToSelf
	}

	// Check that the specified profile public key is valid and that a profile
	// corresponding to that public key exists.
	if len(profilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorCoinTransferInvalidProfilePubKeySize
	}
	if _, err = btcec.ParsePubKey(profilePublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(
			RuleErrorCoinTransferInvalidProfilePubKey, err.Error())
	}

	// Dig up the profile. It must exist for the user to be able to transfer its coin.
	creatorProfileEntry := bav.GetProfileEntryForPublicKey(profilePublicKey)
	if creatorProfileEntry == nil || creatorProfileEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorCoinTransferOnNonexistentProfile,
			"_helpConnectCoinTransfer: Profile pub key: %v %v",
			PkToStringMainnet(profilePublicKey), PkToStringTestnet(profilePublicKey))
	}

	// At this point we are confident that we have a profile that
	// exists that corresponds to the profile public key the user provided.

	// Look up a BalanceEntry for the sender. If it doesn't exist then the sender implicitly
	// has a balance of zero coins, and so the transfer shouldn't be allowed.
	senderBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txn.PublicKey, creatorProfileEntry.PublicKey, isDAOCoin)
	if senderBalanceEntry == nil || senderBalanceEntry.isDeleted {
		return 0, 0, nil, RuleErrorCoinTransferBalanceEntryDoesNotExist
	}

	// For CreatorCoins, we must check that the amount of creator coin being
	// transferred is not less than the min threshold. For DAO coins, this constraint
	// doesn't matter because there is no bonding curve.
	if !isDAOCoin {
		// CreatorCoins can't exceed a uint64
		if coinToTransferNanos.Uint64() < bav.Params.CreatorCoinAutoSellThresholdNanos {
			return 0, 0, nil, RuleErrorCreatorCoinTransferMustBeGreaterThanMinThreshold
		}
	}

	// Check that the amount of coin being transferred does not exceed the user's
	// balance of this particular coin.
	if coinToTransferNanos.Gt(&senderBalanceEntry.BalanceNanos) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorCoinTransferInsufficientCoins,
			"_helpConnectCoinTransfer: Coin nanos being transferred %v exceeds "+
				"user's coin balance %v",
			coinToTransferNanos, senderBalanceEntry.BalanceNanos)
	}

	// If this is a coin, we need to make sure we're not violating any
	// transfer restrictions.
	if isDAOCoin {
		if err := bav.IsValidDAOCoinTransfer(creatorProfileEntry, txn.PublicKey, receiverPublicKey); err != nil {
			return 0, 0, nil, err
		}
	}

	// Now that we have validated this transaction, let's build the new BalanceEntry state.

	// Look up a BalanceEntry for the receiver.
	receiverBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		receiverPublicKey, profilePublicKey, isDAOCoin)

	// Save the receiver's balance if it is non-nil.
	var prevReceiverBalanceEntry *BalanceEntry
	if receiverBalanceEntry != nil && !receiverBalanceEntry.isDeleted {
		prevReceiverBalanceEntry = &BalanceEntry{}
		*prevReceiverBalanceEntry = *receiverBalanceEntry
	}

	// If the receiver's balance entry is nil, we need to make one.
	if receiverBalanceEntry == nil || receiverBalanceEntry.isDeleted {
		receiverPKID := bav.GetPKIDForPublicKey(receiverPublicKey)
		creatorPKID := bav.GetPKIDForPublicKey(creatorProfileEntry.PublicKey)
		// Sanity check that we found a PKID entry for these pub keys (should never fail).
		if receiverPKID == nil || receiverPKID.isDeleted || creatorPKID == nil || creatorPKID.isDeleted {
			return 0, 0, nil, fmt.Errorf(
				"_helpConnectCoinTransfer: Found nil or deleted PKID for receiver or creator, this should never "+
					"happen. Receiver pubkey: %v, creator pubkey: %v",
				PkToStringMainnet(receiverPublicKey),
				PkToStringMainnet(creatorProfileEntry.PublicKey))
		}
		receiverBalanceEntry = &BalanceEntry{
			HODLerPKID:   receiverPKID.PKID,
			CreatorPKID:  creatorPKID.PKID,
			BalanceNanos: *uint256.NewInt(),
		}
	}

	// Save the sender's balance before we modify it.
	prevSenderBalanceEntry := *senderBalanceEntry

	// Subtract the number of coins being given from the sender and add them to the receiver.
	senderBalanceEntry.BalanceNanos = *uint256.NewInt().Sub(
		&senderBalanceEntry.BalanceNanos,
		coinToTransferNanos)
	receiverBalanceEntry.BalanceNanos = *uint256.NewInt().Add(
		&receiverBalanceEntry.BalanceNanos,
		coinToTransferNanos)

	// If we're dealing with a CreatorCoin transfer, we need to ensure that the balance
	// gets zeroed out if it gets too small. This is not needed for DAO coins.
	if !isDAOCoin {
		// We do not allow accounts to maintain tiny creator coin balances in order to avoid
		// Bancor curve price anomalies as famously demonstrated by @salomon.  Thus, if the
		// sender tries to make a transfer that will leave them below the threshold we give
		// their remaining balance to the receiver in order to zero them out.
		//
		// CreatorCoins can't exceed a uint64
		if senderBalanceEntry.BalanceNanos.Uint64() < bav.Params.CreatorCoinAutoSellThresholdNanos {
			receiverBalanceEntry.BalanceNanos = *uint256.NewInt().Add(
				&receiverBalanceEntry.BalanceNanos,
				&senderBalanceEntry.BalanceNanos)
			senderBalanceEntry.BalanceNanos = *uint256.NewInt()
			senderBalanceEntry.HasPurchased = false
		}
	}

	// Delete the sender's balance entry under the assumption that the sender gave away all
	// of their coins. We add it back later, if this is not the case.
	bav._deleteBalanceEntryMappings(senderBalanceEntry, txn.PublicKey, profilePublicKey, isDAOCoin)
	// Delete the receiver's balance entry just to be safe. Added back immediately after.
	bav._deleteBalanceEntryMappings(receiverBalanceEntry, receiverPublicKey, profilePublicKey, isDAOCoin)

	bav._setBalanceEntryMappings(receiverBalanceEntry, isDAOCoin)
	if senderBalanceEntry.BalanceNanos.Gt(uint256.NewInt()) {
		bav._setBalanceEntryMappings(senderBalanceEntry, isDAOCoin)
	}

	// Save all the old values from the CreatorCoinEntry before we potentially update them. Note
	// that CreatorCoinEntry doesn't contain any pointers and so a direct copy is OK.
	// We copy a different entry depending on whether we're dealing with a CreatorCoin or
	// a coin
	var prevCoinEntry CoinEntry
	if isDAOCoin {
		prevCoinEntry = creatorProfileEntry.DAOCoinEntry
	} else {
		prevCoinEntry = creatorProfileEntry.CreatorCoinEntry
	}

	if prevReceiverBalanceEntry == nil || prevReceiverBalanceEntry.BalanceNanos.IsZero() ||
		prevReceiverBalanceEntry.isDeleted {
		// The receiver did not have a BalanceEntry before. Increment num holders.
		if isDAOCoin {
			creatorProfileEntry.DAOCoinEntry.NumberOfHolders++
		} else {
			creatorProfileEntry.CreatorCoinEntry.NumberOfHolders++
		}
	}

	if senderBalanceEntry.BalanceNanos.IsZero() {
		// The sender no longer holds any of this creator's coin, so we decrement num holders.
		if isDAOCoin {
			creatorProfileEntry.DAOCoinEntry.NumberOfHolders--
		} else {
			creatorProfileEntry.CreatorCoinEntry.NumberOfHolders--
		}
	}

	// Update and set the new profile entry.
	bav._setProfileEntryMappings(creatorProfileEntry)

	// Diamonds used to be associated with CreatorCoin transfers. We maintain that logic
	// for legacy blocks here.
	//
	// TODO(DELETEME): Get rid of this once HyperSync is here.
	var previousDiamondPostEntry *PostEntry
	var previousDiamondEntry *DiamondEntry
	if !isDAOCoin {
		// If this creator coin transfer has diamonds, validate them and do the connection.
		diamondPostHashBytes, hasDiamondPostHash := txn.ExtraData[DiamondPostHashKey]
		diamondPostHash := &BlockHash{}
		diamondLevelBytes, hasDiamondLevel := txn.ExtraData[DiamondLevelKey]
		// After the DeSoDiamondsBlockHeight, we no longer accept creator coin diamonds.
		if hasDiamondPostHash && blockHeight > bav.Params.ForkHeights.DeSoDiamondsBlockHeight {
			return 0, 0, nil, RuleErrorCreatorCoinTransferHasDiamondsAfterDeSoBlockHeight
		} else if hasDiamondPostHash {
			if !hasDiamondLevel {
				return 0, 0, nil, RuleErrorCreatorCoinTransferHasDiamondPostHashWithoutDiamondLevel
			}
			diamondLevel, bytesRead := Varint(diamondLevelBytes)
			// NOTE: Despite being an int, diamondLevel is required to be non-negative. This
			// is useful for sorting our dbkeys by diamondLevel.
			if bytesRead < 0 || diamondLevel < 0 {
				return 0, 0, nil, RuleErrorCreatorCoinTransferHasInvalidDiamondLevel
			}

			if !reflect.DeepEqual(txn.PublicKey, creatorProfileEntry.PublicKey) {
				return 0, 0, nil, RuleErrorCreatorCoinTransferCantSendDiamondsForOtherProfiles
			}
			if reflect.DeepEqual(receiverPublicKey, creatorProfileEntry.PublicKey) {
				return 0, 0, nil, RuleErrorCreatorCoinTransferCantDiamondYourself
			}

			if len(diamondPostHashBytes) != HashSizeBytes {
				return 0, 0, nil, errors.Wrapf(
					RuleErrorCreatorCoinTransferInvalidLengthForPostHashBytes,
					"_helpConnectCoinTransfer: DiamondPostHashBytes length: %d", len(diamondPostHashBytes))
			}
			copy(diamondPostHash[:], diamondPostHashBytes[:])

			previousDiamondPostEntry = bav.GetPostEntryForPostHash(diamondPostHash)
			if previousDiamondPostEntry == nil || previousDiamondPostEntry.isDeleted {
				return 0, 0, nil, RuleErrorCreatorCoinTransferDiamondPostEntryDoesNotExist
			}

			expectedCreatorCoinNanosToTransfer, netNewDiamonds, err := bav.ValidateDiamondsAndGetNumCreatorCoinNanos(
				txn.PublicKey, receiverPublicKey, diamondPostHash, diamondLevel, blockHeight)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_helpConnectCoinTransfer: ")
			}

			// CreatorCoins can't exceed a uint64
			if coinToTransferNanos.Uint64() < expectedCreatorCoinNanosToTransfer {
				return 0, 0, nil, RuleErrorCreatorCoinTransferInsufficientCreatorCoinsForDiamondLevel
			}

			// The diamondPostEntry needs to be updated with the number of new diamonds.
			// We make a copy to avoid issues with disconnecting.
			newDiamondPostEntry := &PostEntry{}
			*newDiamondPostEntry = *previousDiamondPostEntry
			newDiamondPostEntry.DiamondCount += uint64(netNewDiamonds)
			bav._setPostEntryMappings(newDiamondPostEntry)

			// Convert pub keys into PKIDs so we can make the DiamondEntry.
			senderPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
			receiverPKID := bav.GetPKIDForPublicKey(receiverPublicKey)

			// Create a new DiamondEntry
			newDiamondEntry := &DiamondEntry{
				SenderPKID:      senderPKID.PKID,
				ReceiverPKID:    receiverPKID.PKID,
				DiamondPostHash: diamondPostHash,
				DiamondLevel:    diamondLevel,
			}

			// Save the old DiamondEntry
			diamondKey := MakeDiamondKey(senderPKID.PKID, receiverPKID.PKID, diamondPostHash)
			existingDiamondEntry := bav.GetDiamondEntryForDiamondKey(&diamondKey)
			// Save the existing DiamondEntry, if it exists, so we can disconnect
			if existingDiamondEntry != nil {
				dd := &DiamondEntry{}
				*dd = *existingDiamondEntry
				previousDiamondEntry = dd
			}

			// Now set the diamond entry mappings on the view so they are flushed to the DB.
			bav._setDiamondEntryMappings(newDiamondEntry)
		}
	}

	// Add an operation to the list at the end indicating we've executed a
	// coin transfer txn. Save the previous state of the CreatorCoinEntry for easy
	// reversion during disconnect.
	var opType OperationType
	if isDAOCoin {
		opType = OperationTypeDAOCoinTransfer
	} else {
		opType = OperationTypeCreatorCoinTransfer
	}
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                     opType,
		PrevSenderBalanceEntry:   &prevSenderBalanceEntry,
		PrevReceiverBalanceEntry: prevReceiverBalanceEntry,
		PrevCoinEntry:            &prevCoinEntry,

		// Legacy CreatorCoin fields from when diamonds were associated with
		// CreatorCoin transfers.
		PrevPostEntry:    previousDiamondPostEntry,
		PrevDiamondEntry: previousDiamondEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}
