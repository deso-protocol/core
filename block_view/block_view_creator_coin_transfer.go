package block_view

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/lib"
	"github.com/deso-protocol/core/network"
	"github.com/deso-protocol/core/types"
	"github.com/pkg/errors"
	"reflect"
)

func (bav *UtxoView) _connectCreatorCoinTransfer(
	txn *network.MsgDeSoTxn, txHash *types.BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != network.TxnTypeCreatorCoinTransfer {
		return 0, 0, nil, fmt.Errorf("_connectCreatorCoinTransfer: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*network.CreatorCoinTransferMetadataa)

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectCreatorCoin: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks. If
	// we didn't do this then someone could replay your transfer over and over again
	// to force-convert all your creator coin into DeSo. Think about it.
	if totalInput == 0 {
		return 0, 0, nil, types.RuleErrorCreatorCoinTransferRequiresNonZeroInput
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Check that the specified receiver public key is valid.
	if len(txMeta.ReceiverPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, types.RuleErrorCreatorCoinTransferInvalidReceiverPubKeySize
	}

	// Check that the sender and receiver public keys are different.
	if reflect.DeepEqual(txn.PublicKey, txMeta.ReceiverPublicKey) {
		return 0, 0, nil, types.RuleErrorCreatorCoinTransferCannotTransferToSelf
	}

	// Check that the specified profile public key is valid and that a profile
	// corresponding to that public key exists.
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, types.RuleErrorCreatorCoinTransferInvalidProfilePubKeySize
	}

	// Dig up the profile. It must exist for the user to be able to transfer its coin.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(
			types.RuleErrorCreatorCoinTransferOnNonexistentProfile,
			"_connectCreatorCoin: Profile pub key: %v %v",
			types.PkToStringMainnet(txMeta.ProfilePublicKey), types.PkToStringTestnet(txMeta.ProfilePublicKey))
	}

	// At this point we are confident that we have a profile that
	// exists that corresponds to the profile public key the user provided.

	// Look up a BalanceEntry for the sender. If it doesn't exist then the sender implicitly
	// has a balance of zero coins, and so the transfer shouldn't be allowed.
	senderBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txn.PublicKey, existingProfileEntry.PublicKey)
	if senderBalanceEntry == nil || senderBalanceEntry.isDeleted {
		return 0, 0, nil, types.RuleErrorCreatorCoinTransferBalanceEntryDoesNotExist
	}

	// Check that the amount of creator coin being transferred is not less than the min threshold.
	if txMeta.CreatorCoinToTransferNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
		return 0, 0, nil, types.RuleErrorCreatorCoinTransferMustBeGreaterThanMinThreshold
	}

	// Check that the amount of creator coin being transferred does not exceed the user's
	// balance of this particular creator coin.
	if txMeta.CreatorCoinToTransferNanos > senderBalanceEntry.BalanceNanos {
		return 0, 0, nil, errors.Wrapf(
			types.RuleErrorCreatorCoinTransferInsufficientCoins,
			"_connectCreatorCoin: CreatorCoin nanos being transferred %v exceeds "+
				"user's creator coin balance %v",
			txMeta.CreatorCoinToTransferNanos, senderBalanceEntry.BalanceNanos)
	}

	// Now that we have validated this transaction, let's build the new BalanceEntry state.

	// Look up a BalanceEntry for the receiver.
	receiverBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)

	// Save the receiver's balance if it is non-nil.
	var prevReceiverBalanceEntry *BalanceEntry
	if receiverBalanceEntry != nil {
		prevReceiverBalanceEntry = &BalanceEntry{}
		*prevReceiverBalanceEntry = *receiverBalanceEntry
	}

	// If the receiver's balance entry is nil, we need to make one.
	if receiverBalanceEntry == nil || receiverBalanceEntry.isDeleted {
		receiverPKID := bav.GetPKIDForPublicKey(txMeta.ReceiverPublicKey)
		creatorPKID := bav.GetPKIDForPublicKey(existingProfileEntry.PublicKey)
		// Sanity check that we found a PKID entry for these pub keys (should never fail).
		if receiverPKID == nil || receiverPKID.isDeleted || creatorPKID == nil || creatorPKID.isDeleted {
			return 0, 0, nil, fmt.Errorf(
				"_connectCreatorCoin: Found nil or deleted PKID for receiver or creator, this should never "+
					"happen. Receiver pubkey: %v, creator pubkey: %v",
				types.PkToStringMainnet(txMeta.ReceiverPublicKey),
				types.PkToStringMainnet(existingProfileEntry.PublicKey))
		}
		receiverBalanceEntry = &BalanceEntry{
			HODLerPKID:   receiverPKID.PKID,
			CreatorPKID:  creatorPKID.PKID,
			BalanceNanos: uint64(0),
		}
	}

	// Save the sender's balance before we modify it.
	prevSenderBalanceEntry := *senderBalanceEntry

	// Subtract the number of coins being given from the sender and add them to the receiver.
	// TODO: We should avoid editing the pointer returned by "bav._getX" directly before
	// deleting / setting. Since the pointer returned is the one held by the view, it
	// makes setting redundant.  An alternative would be to not call _set after modification.
	senderBalanceEntry.BalanceNanos -= txMeta.CreatorCoinToTransferNanos
	receiverBalanceEntry.BalanceNanos += txMeta.CreatorCoinToTransferNanos

	// We do not allow accounts to maintain tiny creator coin balances in order to avoid
	// Bancor curve price anomalies as famously demonstrated by @salomon.  Thus, if the
	// sender tries to make a transfer that will leave them below the threshold we give
	// their remaining balance to the receiver in order to zero them out.
	if senderBalanceEntry.BalanceNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
		receiverBalanceEntry.BalanceNanos += senderBalanceEntry.BalanceNanos
		senderBalanceEntry.BalanceNanos = 0
		senderBalanceEntry.HasPurchased = false
	}

	// Delete the sender's balance entry under the assumption that the sender gave away all
	// of their coins. We add it back later, if this is not the case.
	bav._deleteBalanceEntryMappings(senderBalanceEntry, txn.PublicKey, txMeta.ProfilePublicKey)
	// Delete the receiver's balance entry just to be safe. Added back immediately after.
	bav._deleteBalanceEntryMappings(
		receiverBalanceEntry, txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)

	bav._setBalanceEntryMappings(receiverBalanceEntry)
	if senderBalanceEntry.BalanceNanos > 0 {
		bav._setBalanceEntryMappings(senderBalanceEntry)
	}

	// Save all the old values from the CoinEntry before we potentially update them. Note
	// that CoinEntry doesn't contain any pointers and so a direct copy is OK.
	prevCoinEntry := existingProfileEntry.CoinEntry

	if prevReceiverBalanceEntry == nil || prevReceiverBalanceEntry.BalanceNanos == 0 {
		// The receiver did not have a BalanceEntry before. Increment num holders.
		existingProfileEntry.CoinEntry.NumberOfHolders++
	}

	if senderBalanceEntry.BalanceNanos == 0 {
		// The sender no longer holds any of this creator's coin, so we decrement num holders.
		existingProfileEntry.CoinEntry.NumberOfHolders--
	}

	// Update and set the new profile entry.
	bav._setProfileEntryMappings(existingProfileEntry)

	// If this creator coin transfer has diamonds, validate them and do the connection.
	diamondPostHashBytes, hasDiamondPostHash := txn.ExtraData[types.DiamondPostHashKey]
	diamondPostHash := &types.BlockHash{}
	diamondLevelBytes, hasDiamondLevel := txn.ExtraData[types.DiamondLevelKey]
	var previousDiamondPostEntry *PostEntry
	var previousDiamondEntry *DiamondEntry
	// After the DeSoDiamondsBlockHeight, we no longer accept creator coin diamonds.
	if hasDiamondPostHash && blockHeight > types.DeSoDiamondsBlockHeight {
		return 0, 0, nil, types.RuleErrorCreatorCoinTransferHasDiamondsAfterDeSoBlockHeight
	} else if hasDiamondPostHash {
		if !hasDiamondLevel {
			return 0, 0, nil, types.RuleErrorCreatorCoinTransferHasDiamondPostHashWithoutDiamondLevel
		}
		diamondLevel, bytesRead := network.Varint(diamondLevelBytes)
		// NOTE: Despite being an int, diamondLevel is required to be non-negative. This
		// is useful for sorting our dbkeys by diamondLevel.
		if bytesRead < 0 || diamondLevel < 0 {
			return 0, 0, nil, types.RuleErrorCreatorCoinTransferHasInvalidDiamondLevel
		}

		if !reflect.DeepEqual(txn.PublicKey, existingProfileEntry.PublicKey) {
			return 0, 0, nil, types.RuleErrorCreatorCoinTransferCantSendDiamondsForOtherProfiles
		}
		if reflect.DeepEqual(txMeta.ReceiverPublicKey, existingProfileEntry.PublicKey) {
			return 0, 0, nil, types.RuleErrorCreatorCoinTransferCantDiamondYourself
		}

		if len(diamondPostHashBytes) != types.HashSizeBytes {
			return 0, 0, nil, errors.Wrapf(
				types.RuleErrorCreatorCoinTransferInvalidLengthForPostHashBytes,
				"_connectCreatorCoin: DiamondPostHashBytes length: %d", len(diamondPostHashBytes))
		}
		copy(diamondPostHash[:], diamondPostHashBytes[:])

		previousDiamondPostEntry = bav.GetPostEntryForPostHash(diamondPostHash)
		if previousDiamondPostEntry == nil || previousDiamondPostEntry.isDeleted {
			return 0, 0, nil, types.RuleErrorCreatorCoinTransferDiamondPostEntryDoesNotExist
		}

		expectedCreatorCoinNanosToTransfer, netNewDiamonds, err := bav.ValidateDiamondsAndGetNumCreatorCoinNanos(
			txn.PublicKey, txMeta.ReceiverPublicKey, diamondPostHash, diamondLevel, blockHeight)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectCreatorCoin: ")
		}

		if txMeta.CreatorCoinToTransferNanos < expectedCreatorCoinNanosToTransfer {
			return 0, 0, nil, types.RuleErrorCreatorCoinTransferInsufficientCreatorCoinsForDiamondLevel
		}

		// The diamondPostEntry needs to be updated with the number of new diamonds.
		// We make a copy to avoid issues with disconnecting.
		newDiamondPostEntry := &PostEntry{}
		*newDiamondPostEntry = *previousDiamondPostEntry
		newDiamondPostEntry.DiamondCount += uint64(netNewDiamonds)
		bav._setPostEntryMappings(newDiamondPostEntry)

		// Convert pub keys into PKIDs so we can make the DiamondEntry.
		senderPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
		receiverPKID := bav.GetPKIDForPublicKey(txMeta.ReceiverPublicKey)

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

	// Add an operation to the list at the end indicating we've executed a
	// CreatorCoin txn. Save the previous state of the CoinEntry for easy
	// reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                     OperationTypeCreatorCoinTransfer,
		PrevSenderBalanceEntry:   &prevSenderBalanceEntry,
		PrevReceiverBalanceEntry: prevReceiverBalanceEntry,
		PrevCoinEntry:            &prevCoinEntry,
		PrevPostEntry:            previousDiamondPostEntry,
		PrevDiamondEntry:         previousDiamondEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) ValidateDiamondsAndGetNumCreatorCoinNanos(
	senderPublicKey []byte,
	receiverPublicKey []byte,
	diamondPostHash *types.BlockHash,
	diamondLevel int64,
	blockHeight uint32,
) (_numCreatorCoinNanos uint64, _netNewDiamonds int64, _err error) {

	// Check that the diamond level is reasonable
	diamondLevelMap := lib.GetDeSoNanosDiamondLevelMapAtBlockHeight(int64(blockHeight))
	if _, isAllowedLevel := diamondLevelMap[diamondLevel]; !isAllowedLevel {
		return 0, 0, fmt.Errorf(
			"ValidateDiamondsAndGetNumCreatorCoinNanos: Diamond level %v not allowed",
			diamondLevel)
	}

	// Convert pub keys into PKIDs.
	senderPKID := bav.GetPKIDForPublicKey(senderPublicKey)
	receiverPKID := bav.GetPKIDForPublicKey(receiverPublicKey)

	// Look up if there is an existing diamond entry.
	diamondKey := MakeDiamondKey(senderPKID.PKID, receiverPKID.PKID, diamondPostHash)
	diamondEntry := bav.GetDiamondEntryForDiamondKey(&diamondKey)

	// Look up if there's an existing profile entry for the sender. There needs
	// to be in order to be able to give one's creator coin as a diamond.
	existingProfileEntry := bav.GetProfileEntryForPKID(senderPKID.PKID)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, fmt.Errorf(
			"ValidateDiamondsAndGetNumCreatorCoinNanos: Cannot send CreatorCoin "+
				"with diamond because ProfileEntry for public key %v does not exist",
			senderPublicKey)
	}
	// If we get here, then we're sure the ProfileEntry for this user exists.

	currDiamondLevel := int64(0)
	if diamondEntry != nil {
		currDiamondLevel = diamondEntry.DiamondLevel
	}

	if currDiamondLevel >= diamondLevel {
		return 0, 0, types.RuleErrorCreatorCoinTransferPostAlreadyHasSufficientDiamonds
	}

	// Calculate the number of creator coin nanos needed vs. already added for previous diamonds.
	currCreatorCoinNanos := lib.GetCreatorCoinNanosForDiamondLevelAtBlockHeight(
		existingProfileEntry.CoinsInCirculationNanos, existingProfileEntry.DeSoLockedNanos,
		currDiamondLevel, int64(blockHeight), bav.Params)
	neededCreatorCoinNanos := lib.GetCreatorCoinNanosForDiamondLevelAtBlockHeight(
		existingProfileEntry.CoinsInCirculationNanos, existingProfileEntry.DeSoLockedNanos,
		diamondLevel, int64(blockHeight), bav.Params)

	// There is an edge case where, if the person's creator coin value goes down
	// by a large enough amount, then they can get a "free" diamond upgrade. This
	// seems fine for now.
	creatorCoinToTransferNanos := uint64(0)
	if neededCreatorCoinNanos > currCreatorCoinNanos {
		creatorCoinToTransferNanos = neededCreatorCoinNanos - currCreatorCoinNanos
	}

	netNewDiamonds := diamondLevel - currDiamondLevel

	return creatorCoinToTransferNanos, netNewDiamonds, nil
}

func (bav *UtxoView) _disconnectCreatorCoinTransfer(
	operationType OperationType, currentTxn *network.MsgDeSoTxn, txnHash *types.BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a CreatorCoinTransfer operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCreatorCoinTransfer {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Trying to revert "+
			"OperationTypeCreatorCoinTransfer but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*network.CreatorCoinTransferMetadataa)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Get the profile corresponding to the creator coin txn.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	// Sanity-check that it exists.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: CreatorCoinTransfer profile for "+
			"public key %v doesn't exist; this should never happen",
			types.PkToStringBoth(txMeta.ProfilePublicKey))
	}

	// Get the current / previous balance for the sender for sanity checking.
	senderBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		currentTxn.PublicKey, txMeta.ProfilePublicKey)
	// Sanity-check that the sender had a previous BalanceEntry, it should always exist.
	if operationData.PrevSenderBalanceEntry == nil || operationData.PrevSenderBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Previous sender BalanceEntry "+
			"pubkey %v and creator pubkey %v does not exist; this should "+
			"never happen",
			types.PkToStringBoth(currentTxn.PublicKey), types.PkToStringBoth(txMeta.ProfilePublicKey))
	}
	senderPrevBalanceNanos := operationData.PrevSenderBalanceEntry.BalanceNanos
	var senderCurrBalanceNanos uint64
	// Since the sender may have given away their whole balance, their BalanceEntry can be nil.
	if senderBalanceEntry != nil && !senderBalanceEntry.isDeleted {
		senderCurrBalanceNanos = senderBalanceEntry.BalanceNanos
	}

	// Get the current / previous balance for the receiver for sanity checking.
	receiverBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)
	// Sanity-check that the receiver BalanceEntry exists, it should always exist here.
	if receiverBalanceEntry == nil || receiverBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Receiver BalanceEntry "+
			"pubkey %v and creator pubkey %v does not exist; this should "+
			"never happen",
			types.PkToStringBoth(currentTxn.PublicKey), types.PkToStringBoth(txMeta.ProfilePublicKey))
	}
	receiverCurrBalanceNanos := receiverBalanceEntry.BalanceNanos
	var receiverPrevBalanceNanos uint64
	if operationData.PrevReceiverBalanceEntry != nil {
		receiverPrevBalanceNanos = operationData.PrevReceiverBalanceEntry.BalanceNanos
	}

	// Sanity check that the sender's current balance is less than their previous balance.
	if senderCurrBalanceNanos > senderPrevBalanceNanos {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Sender's current balance %d is "+
			"greater than their previous balance %d.",
			senderCurrBalanceNanos, senderPrevBalanceNanos)
	}

	// Sanity check that the receiver's previous balance is less than their current balance.
	if receiverPrevBalanceNanos > receiverCurrBalanceNanos {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Receiver's previous balance %d is "+
			"greater than their current balance %d.",
			receiverPrevBalanceNanos, receiverCurrBalanceNanos)
	}

	// Sanity check the sender's increase equals the receiver's decrease after disconnect.
	senderBalanceIncrease := senderPrevBalanceNanos - senderCurrBalanceNanos
	receiverBalanceDecrease := receiverCurrBalanceNanos - receiverPrevBalanceNanos
	if senderBalanceIncrease != receiverBalanceDecrease {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Sender's balance increase "+
			"of %d will not equal the receiver's balance decrease of  %v after disconnect.",
			senderBalanceIncrease, receiverBalanceDecrease)
	}

	// At this point we have sanity checked the current and previous state. Now we just
	// need to revert the mappings.

	// Delete the sender/receiver balance entries (they will be added back later if needed).
	bav._deleteBalanceEntryMappings(
		receiverBalanceEntry, txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)
	if senderBalanceEntry != nil {
		bav._deleteBalanceEntryMappings(
			senderBalanceEntry, currentTxn.PublicKey, txMeta.ProfilePublicKey)
	}

	// Set the balance entries appropriately.
	bav._setBalanceEntryMappings(operationData.PrevSenderBalanceEntry)
	if operationData.PrevReceiverBalanceEntry != nil && operationData.PrevReceiverBalanceEntry.BalanceNanos != 0 {
		bav._setBalanceEntryMappings(operationData.PrevReceiverBalanceEntry)
	}

	// Reset the CoinEntry on the profile to what it was previously now that we
	// have reverted the individual users' balances.
	existingProfileEntry.CoinEntry = *operationData.PrevCoinEntry
	bav._setProfileEntryMappings(existingProfileEntry)

	// If the transaction had diamonds, let's revert those too.
	diamondPostHashBytes, hasDiamondPostHash := currentTxn.ExtraData[types.DiamondPostHashKey]
	if hasDiamondPostHash {
		// Sanity check the post hash bytes before creating the post hash.
		diamondPostHash := &types.BlockHash{}
		if len(diamondPostHashBytes) != types.HashSizeBytes {
			return fmt.Errorf(
				"_disconnectCreatorCoin: DiamondPostHashBytes has incorrect length: %d",
				len(diamondPostHashBytes))
		}
		copy(diamondPostHash[:], diamondPostHashBytes[:])

		// Get the existing diamondEntry so we can delete it.
		senderPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
		receiverPKID := bav.GetPKIDForPublicKey(txMeta.ReceiverPublicKey)
		diamondKey := MakeDiamondKey(senderPKID.PKID, receiverPKID.PKID, diamondPostHash)
		diamondEntry := bav.GetDiamondEntryForDiamondKey(&diamondKey)

		// Sanity check that the diamondEntry is not nil.
		if diamondEntry == nil {
			return fmt.Errorf(
				"_disconnectCreatorCoin: Found nil diamond entry for diamondKey: %v", &diamondKey)
		}

		// Delete the diamond entry mapping and re-add it if the previous mapping is not nil.
		bav._deleteDiamondEntryMappings(diamondEntry)
		if operationData.PrevDiamondEntry != nil {
			bav._setDiamondEntryMappings(operationData.PrevDiamondEntry)
		}

		// Finally, revert the post entry mapping since we likely updated the DiamondCount.
		bav._setPostEntryMappings(operationData.PrevPostEntry)
	}

	// Now revert the basic transfer with the remaining operations. Cut off
	// the CreatorCoin operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}
