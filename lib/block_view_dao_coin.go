package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"reflect"
)

func (bav *UtxoView) GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(
	hodlerPubKey []byte, creatorPubKey []byte) (
	_balanceEntry *BalanceEntry, _hodlerPKID *PKID, _creatorPKID *PKID) {
	return bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(hodlerPubKey, creatorPubKey, true)
}

func (bav *UtxoView) GetDAOCoinHoldings(pkid *PKID, fetchProfiles bool) (
	[]*BalanceEntry, []*ProfileEntry, error) {
	return bav.GetHoldings(pkid, fetchProfiles, true)
}

func (bav *UtxoView) GetDAOCoinHolders(pkid *PKID, fetchProfiles bool) (
	[]*BalanceEntry, []*ProfileEntry, error) {
	return bav.GetHolders(pkid, fetchProfiles, true)
}

func (bav *UtxoView) _setDAOCoinBalanceEntryMappings(balanceEntry *BalanceEntry) {
	bav._setBalanceEntryMappings(balanceEntry, true)
}

func (bav *UtxoView) _deleteDAOCoinBalanceEntryMappings(
	balanceEntry *BalanceEntry, hodlerPublicKey []byte, creatorPublicKey []byte) {
	bav._deleteBalanceEntryMappings(balanceEntry, hodlerPublicKey, creatorPublicKey, true)
}

func (bav *UtxoView) _disconnectDAOCoin(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	if blockHeight < bav.Params.ForkHeights.DAOCoinBlockHeight {
		return fmt.Errorf("_disconnectDAOCoin: DAOCoin transaction before block height")
	}
	// Verify that the last operation is a DAO Coin operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectDAOCoin: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeDAOCoin {
		return fmt.Errorf("_disconnectDAOCoin: Trying to revert "+
			"OperationTypeDAOCoin but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*DAOCoinMetadata)
	operationData := utxoOpsForTxn[operationIndex]

	// Get the profile corresponding to the DAO coin txn.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	// Sanity-check that it exists.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return fmt.Errorf("_disconnectDAOCoin: DAOCoin profile for "+
			"public key %v doesn't exist; this should never happen",
			PkToStringBoth(txMeta.ProfilePublicKey))
	}
	// Get the BalanceEntry of the transactor
	transactorBalanceEntry, hodlerPKID, creatorPKID := bav.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		currentTxn.PublicKey, txMeta.ProfilePublicKey)
	if transactorBalanceEntry == nil || transactorBalanceEntry.isDeleted {
		transactorBalanceEntry = &BalanceEntry{
			CreatorPKID:  creatorPKID,
			HODLerPKID:   hodlerPKID,
			BalanceNanos: *uint256.NewInt(),
		}
	}

	if txMeta.OperationType == DAOCoinOperationTypeMint {
		// Sanity checks
		// transactor and profile match
		if !reflect.DeepEqual(txMeta.ProfilePublicKey, currentTxn.PublicKey) {
			return fmt.Errorf("_disconnectDAOCoin: Minting by transactor public key that does not match "+
				"ProfilePublicKey: %v, %v; this should never happen", currentTxn.PublicKey, txMeta.ProfilePublicKey)
		}
		// coins to mint is non-zero
		if txMeta.CoinsToMintNanos.IsZero() {
			return fmt.Errorf("_disconnectDAOCoin: Must mint more than zero coins; this should never happen")
		}
		// Coins minted + prev coin entry's coins in circulation matches new coin entry's coins in circulation
		CoinsInCirculationPlusCoinsToMintNanos := uint256.NewInt().Add(
			&operationData.PrevCoinEntry.CoinsInCirculationNanos,
			&txMeta.CoinsToMintNanos)
		if !existingProfileEntry.DAOCoinEntry.CoinsInCirculationNanos.Eq(
			CoinsInCirculationPlusCoinsToMintNanos) {
			return fmt.Errorf("_disconnectDAOCoin: existingProfileEntry's Coins in circulation does not "+
				"equal previous coins in circulation + txMeta.CoinsToMintNanos: %v, %v, %v",
				existingProfileEntry.DAOCoinEntry.CoinsInCirculationNanos,
				operationData.PrevCoinEntry.CoinsInCirculationNanos,
				txMeta.CoinsToMintNanos)
		}
		// Check that creator's current balance is equal to previous balance plus coins to mint. Note: the creator is
		// the transactor in this case
		PrevBalanceNanosPlusCoinsToMintNanos := uint256.NewInt().Add(
			&operationData.PrevCreatorBalanceEntry.BalanceNanos,
			&txMeta.CoinsToMintNanos)
		if !transactorBalanceEntry.BalanceNanos.Eq(PrevBalanceNanosPlusCoinsToMintNanos) {
			return fmt.Errorf("_disconnectDAOCoin: creator DAO coin balance is not equal to previous balance "+
				"plus txMeta.CoinsToMintNanos: %v, %v, %v",
				transactorBalanceEntry.BalanceNanos,
				operationData.PrevCreatorBalanceEntry.BalanceNanos,
				txMeta.CoinsToMintNanos)
		}

		// Revert the balance entry
		*transactorBalanceEntry = *operationData.PrevCreatorBalanceEntry
		bav._setDAOCoinBalanceEntryMappings(transactorBalanceEntry)
	} else if txMeta.OperationType == DAOCoinOperationTypeBurn {
		// Sanity checks
		// coins to burn is non-zero
		if txMeta.CoinsToBurnNanos.IsZero() {
			return fmt.Errorf("_disconnctDAOCoin: Must burn more than zero coins; this should never happen")
		}
		// prev coin entry's coins in circulation minus coins burned matches new coin entry's coins in circulation
		PrevCoinsInCirculationMinusCoinsToBurnNanos := uint256.NewInt().Sub(
			&operationData.PrevCoinEntry.CoinsInCirculationNanos,
			&txMeta.CoinsToBurnNanos)
		if !existingProfileEntry.DAOCoinEntry.CoinsInCirculationNanos.Eq(
			PrevCoinsInCirculationMinusCoinsToBurnNanos) {

			return fmt.Errorf("_disconnectDAOCoin: existingProfileEntry's Coins in circulation does not "+
				"equal previous coins in circulation + txMeta.CoinsToBurnNanos: %v, %v, %v",
				existingProfileEntry.DAOCoinEntry.CoinsInCirculationNanos,
				operationData.PrevCoinEntry.CoinsInCirculationNanos,
				txMeta.CoinsToBurnNanos)
		}
		// prev balance entry - coins burned matches the new balance entry's balance
		// Check that transactor's current balance is equal to previous balance minus coins to mint. Note: the creator is
		// the transactor in this case
		PrevBalanceNanosMinusCoinsToBurnNanos := uint256.NewInt().Sub(
			&operationData.PrevTransactorBalanceEntry.BalanceNanos,
			&txMeta.CoinsToBurnNanos)
		if !transactorBalanceEntry.BalanceNanos.Eq(PrevBalanceNanosMinusCoinsToBurnNanos) {
			return fmt.Errorf("_disconnectDAOCoin: creator DAO coin balance is not equal to previous balance "+
				"plus txMeta.CoinsToBurnNanos: %v, %v, %v",
				transactorBalanceEntry.BalanceNanos,
				operationData.PrevTransactorBalanceEntry.BalanceNanos,
				txMeta.CoinsToBurnNanos)
		}
		// Revert the balance entries
		*transactorBalanceEntry = *operationData.PrevTransactorBalanceEntry
		bav._setDAOCoinBalanceEntryMappings(transactorBalanceEntry)
	} else if txMeta.OperationType == DAOCoinOperationTypeDisableMinting {
		// Sanity checks
		// transactor and profile match
		if !reflect.DeepEqual(txMeta.ProfilePublicKey, currentTxn.PublicKey) {
			return fmt.Errorf("_disconnectDAOCoin: Disabling minting by transactor public key that does not match "+
				"ProfilePublicKey: %v, %v; this should never happen", currentTxn.PublicKey, txMeta.ProfilePublicKey)
		}
		// Previous coin entry should not have minting disabled.
		if operationData.PrevCoinEntry.MintingDisabled {
			return fmt.Errorf("_disconnectDAOCoin: Disabling minting on a CreatorCoinEntry that already has minting " +
				"disabled; this should never happen")
		}
	} else if txMeta.OperationType == DAOCoinOperationTypeUpdateTransferRestrictionStatus {
		// Sanity checks
		// transactor and profile match
		if !reflect.DeepEqual(txMeta.ProfilePublicKey, currentTxn.PublicKey) {
			return fmt.Errorf("_disconnectDAOCoin: Updating Transfer Restriction status by transactor public key "+
				"that does not match ProfilePublicKey: %v, %v; this should never happen",
				currentTxn.PublicKey, txMeta.ProfilePublicKey)
		}
		// Transfer Restriction update is a valid one
		if existingProfileEntry.DAOCoinEntry.TransferRestrictionStatus == operationData.PrevCoinEntry.TransferRestrictionStatus {
			return fmt.Errorf("_disconnectDAOCoin: Previous TransferRestrictionStatus %v is the same as "+
				"current TransferRestrictionStatus %v; this should never happen",
				operationData.PrevCoinEntry.TransferRestrictionStatus,
				existingProfileEntry.DAOCoinEntry.TransferRestrictionStatus)
		}
		if operationData.PrevCoinEntry.TransferRestrictionStatus == TransferRestrictionStatusPermanentlyUnrestricted {
			return fmt.Errorf("_disconnectDAOCoin: Previous TransferRestrictionStatus is permananetly " +
				"unrestricted; this should never happen")
		}
	}
	// Revert the coin entry
	existingProfileEntry.DAOCoinEntry = *operationData.PrevCoinEntry
	bav._setProfileEntryMappings(existingProfileEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the DAO Coin operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

// TODO: Not going to bother merging this function with _disconnectCreatorCoinTransfer
// because we're going to delete all disconnect logic when we move to PoS anyway.
func (bav *UtxoView) _disconnectDAOCoinTransfer(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a DAOCoinTransfer operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectDAOCoinTransfer: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeDAOCoinTransfer {
		return fmt.Errorf("_disconnectDAOCoinTransfer: Trying to revert "+
			"OperationTypeCreatorCoinTransfer but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*DAOCoinTransferMetadata)
	operationData := utxoOpsForTxn[operationIndex]

	// Get the profile corresponding to the DAO coin transfer txn.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	// Sanity-check that it exists.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return fmt.Errorf("_disconnectDAOCoinTransfer: DAOCoinTransfer profile for "+
			"public key %v doesn't exist; this should never happen",
			PkToStringBoth(txMeta.ProfilePublicKey))
	}

	// Get the current / previous balance for the sender for sanity checking.
	senderBalanceEntry, _, _ := bav.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		currentTxn.PublicKey, txMeta.ProfilePublicKey)
	// Sanity-check that the sender had a previous BalanceEntry, it should always exist.
	if operationData.PrevSenderBalanceEntry == nil || operationData.PrevSenderBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectDAOCoinTransfer: Previous sender BalanceEntry "+
			"pubkey %v and creator pubkey %v does not exist; this should "+
			"never happen",
			PkToStringBoth(currentTxn.PublicKey), PkToStringBoth(txMeta.ProfilePublicKey))
	}
	senderPrevBalanceNanos := operationData.PrevSenderBalanceEntry.BalanceNanos
	senderCurrBalanceNanos := *uint256.NewInt()
	// Since the sender may have given away their whole balance, their BalanceEntry can be nil.
	if senderBalanceEntry != nil && !senderBalanceEntry.isDeleted {
		// This assignment is OK because we never modify values in-place
		senderCurrBalanceNanos = senderBalanceEntry.BalanceNanos
	}

	// Get the current / previous balance for the receiver for sanity checking.
	receiverBalanceEntry, _, _ := bav.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)
	// Sanity-check that the receiver BalanceEntry exists, it should always exist here.
	if receiverBalanceEntry == nil || receiverBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectDAOCoinTransfer: Receiver BalanceEntry "+
			"pubkey %v and creator pubkey %v does not exist; this should "+
			"never happen",
			PkToStringBoth(currentTxn.PublicKey), PkToStringBoth(txMeta.ProfilePublicKey))
	}
	receiverCurrBalanceNanos := receiverBalanceEntry.BalanceNanos
	receiverPrevBalanceNanos := *uint256.NewInt()
	if operationData.PrevReceiverBalanceEntry != nil {
		// This assignment is OK because we never modify values in-place
		receiverPrevBalanceNanos = operationData.PrevReceiverBalanceEntry.BalanceNanos
	}

	// Sanity check that the sender's current balance is less than their previous balance.
	if senderCurrBalanceNanos.Gt(&senderPrevBalanceNanos) {
		return fmt.Errorf("_disconnectDAOCoinTransfer: Sender's current balance %d is "+
			"greater than their previous balance %d",
			senderCurrBalanceNanos, senderPrevBalanceNanos)
	}

	// Sanity check that the receiver's previous balance is less than their current balance.
	if receiverPrevBalanceNanos.Gt(&receiverCurrBalanceNanos) {
		return fmt.Errorf("_disconnectDAOCoinTransfer: Receiver's previous balance %d is "+
			"greater than their current balance %d",
			receiverPrevBalanceNanos, receiverCurrBalanceNanos)
	}

	// Sanity check the sender's increase equals the receiver's decrease after disconnect.
	senderBalanceIncrease := uint256.NewInt().Sub(&senderPrevBalanceNanos, &senderCurrBalanceNanos)
	receiverBalanceDecrease := uint256.NewInt().Sub(&receiverCurrBalanceNanos, &receiverPrevBalanceNanos)
	if !senderBalanceIncrease.Eq(receiverBalanceDecrease) {
		return fmt.Errorf("_disconnectDAOCoinTransfer: Sender's balance increase "+
			"of %d will not equal the receiver's balance decrease of  %v after disconnect.",
			senderBalanceIncrease, receiverBalanceDecrease)
	}

	// At this point we have sanity checked the current and previous state. Now we just
	// need to revert the mappings.

	// Delete the sender/receiver balance entries (they will be added back later if needed).
	bav._deleteDAOCoinBalanceEntryMappings(
		receiverBalanceEntry, txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)
	if senderBalanceEntry != nil {
		bav._deleteDAOCoinBalanceEntryMappings(
			senderBalanceEntry, currentTxn.PublicKey, txMeta.ProfilePublicKey)
	}

	// Set the balance entries appropriately.
	bav._setDAOCoinBalanceEntryMappings(operationData.PrevSenderBalanceEntry)
	if operationData.PrevReceiverBalanceEntry != nil && !operationData.PrevReceiverBalanceEntry.BalanceNanos.IsZero() {
		bav._setDAOCoinBalanceEntryMappings(operationData.PrevReceiverBalanceEntry)
	}

	// Reset the CreatorCoinEntry on the profile to what it was previously now that we
	// have reverted the individual users' balances.
	existingProfileEntry.DAOCoinEntry = *operationData.PrevCoinEntry
	bav._setProfileEntryMappings(existingProfileEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the DAOCoinTransfer operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) HelpConnectDAOCoinInitialization(txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32,
	verifySignatures bool) (_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation,
	_creatorProfileEntry *ProfileEntry, _err error) {

	if blockHeight < bav.Params.ForkHeights.DAOCoinBlockHeight {
		return 0, 0, nil, nil, RuleErrorDAOCoinBeforeDAOCoinBlockHeight
	}
	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, nil, errors.Wrapf(err, "_connectDAOCoin: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, nil, RuleErrorDAOCoinRequiresNonZeroInput
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.
	txMeta := txn.TxnMeta.(*DAOCoinMetadata)

	// Check that the specified profile public key is valid and that a profile
	// corresponding to that public key exists.
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, nil, RuleErrorDAOCoinInvalidPubKeySize
	}

	if _, err = btcec.ParsePubKey(txMeta.ProfilePublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, nil, errors.Wrap(RuleErrorDAOCoinInvalidPubKey, err.Error())
	}

	// Dig up the profile. It must exist for the user to be able to
	// operate on its DAO coin.
	creatorProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	if creatorProfileEntry == nil || creatorProfileEntry.isDeleted {
		return 0, 0, nil, nil, errors.Wrapf(
			RuleErrorDAOCoinOperationOnNonexistentProfile,
			"_connectDAOCoin: Profile pub key: %v %v",
			PkToStringMainnet(txMeta.ProfilePublicKey), PkToStringTestnet(txMeta.ProfilePublicKey))
	}
	return totalInput, totalOutput, utxoOpsForTxn, creatorProfileEntry, err
}

func (bav *UtxoView) HelpConnectDAOCoinMint(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	totalInput, totalOutput, utxoOpsForTxn, creatorProfileEntry, err := bav.HelpConnectDAOCoinInitialization(
		txn, txHash, blockHeight, verifySignatures)

	if err != nil {
		return 0, 0, nil, err
	}

	if creatorProfileEntry.DAOCoinEntry.MintingDisabled {
		return 0, 0, nil, RuleErrorDAOCoinCannotMintIfMintingIsDisabled
	}

	txMeta := txn.TxnMeta.(*DAOCoinMetadata)

	// First, only the profile associated with the DAO coin can mint
	if !reflect.DeepEqual(txMeta.ProfilePublicKey, txn.PublicKey) {
		return 0, 0, nil, RuleErrorOnlyProfileOwnerCanMintDAOCoin
	}

	// Must mint non-zero amount of DAO coins
	if txMeta.CoinsToMintNanos.IsZero() {
		return 0, 0, nil, RuleErrorDAOCoinMustMintNonZeroDAOCoin
	}

	// At this point we are confident that we have the profile owner minting DAO coins for themselves.
	prevDAOCoinEntry := creatorProfileEntry.DAOCoinEntry

	// Increase coins in circulation. Do not exceed the value of a uint256...
	//
	// if CoinsInCirculationNanos > MaxUint256 - CoinsToMintNanos
	if creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos.Gt(
		uint256.NewInt().Sub(MaxUint256, &txMeta.CoinsToMintNanos)) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorOverflowWhileMintingDAOCoins, fmt.Sprintf(
				"_connectDAOCoin: Overflow while summing CoinsInCirculationNanos and CoinsToMinNanos: %v, %v",
				creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos, txMeta.CoinsToMintNanos))
	}
	// CoinsInCirculationNanos = CoinsInCirculationNanos + CoinsToMintNanos
	creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos = *uint256.NewInt().Add(
		&creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos, &txMeta.CoinsToMintNanos)

	// Increase Balance entry for owner
	profileOwnerBalanceEntry, hodlerPKID, creatorPKID := bav.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txn.PublicKey, txMeta.ProfilePublicKey)
	if profileOwnerBalanceEntry == nil || profileOwnerBalanceEntry.isDeleted {
		profileOwnerBalanceEntry = &BalanceEntry{
			HODLerPKID:   hodlerPKID,
			CreatorPKID:  creatorPKID,
			BalanceNanos: *uint256.NewInt(),
		}
	}

	// Save a copy of the balance entry
	prevProfileOwnerBalanceEntry := *profileOwnerBalanceEntry

	// Check for overflow of the uint256
	// if profileOwnerBalanceEntry.BalanceNanos > MaxUint256-txMeta.CoinsToMintNanos
	if profileOwnerBalanceEntry.BalanceNanos.Gt(uint256.NewInt().Sub(
		MaxUint256, &txMeta.CoinsToMintNanos)) {
		return 0, 0, nil, fmt.Errorf(
			"_connectDAOCoin: Overflow while summing profileOwnerBalanceEntry.BalanceNanos and CoinsToMintNanos: %v, %v",
			profileOwnerBalanceEntry.BalanceNanos, txMeta.CoinsToMintNanos)
	}

	profileOwnerBalanceEntry.BalanceNanos = *uint256.NewInt().Add(
		&profileOwnerBalanceEntry.BalanceNanos,
		&txMeta.CoinsToMintNanos)
	bav._setDAOCoinBalanceEntryMappings(profileOwnerBalanceEntry)

	// Increment the number of holders if necessary
	if prevProfileOwnerBalanceEntry.BalanceNanos.IsZero() {
		creatorProfileEntry.DAOCoinEntry.NumberOfHolders++

		bav._setProfileEntryMappings(creatorProfileEntry)
	}

	// Add an operation to the list at the end indicating we've executed a
	// DAOCoin txn. Save the previous state of the CreatorCoinEntry for easy
	// reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                    OperationTypeDAOCoin,
		PrevCoinEntry:           &prevDAOCoinEntry,
		PrevCreatorBalanceEntry: &prevProfileOwnerBalanceEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) HelpConnectDAOCoinBurn(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	totalInput, totalOutput, utxoOpsForTxn, creatorProfileEntry, err := bav.HelpConnectDAOCoinInitialization(
		txn, txHash, blockHeight, verifySignatures)

	if err != nil {
		return 0, 0, nil, err
	}

	txMeta := txn.TxnMeta.(*DAOCoinMetadata)
	// At this point we are confident that we have a profile that
	// exists that corresponds to the profile public key the user
	// provided.

	// Look up a BalanceEntry for the burner. If it doesn't exist then the burner
	// implicitly has a balance of zero coins, and so the burn transaction shouldn't be
	// allowed.
	burnerBalanceEntry, _, _ := bav.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txn.PublicKey, creatorProfileEntry.PublicKey)
	if burnerBalanceEntry == nil || burnerBalanceEntry.isDeleted {
		return 0, 0, nil, RuleErrorDAOCoinBurnerBalanceEntryDoesNotExist
	}

	daoCoinToBurn := txMeta.CoinsToBurnNanos
	// Check that the burner is burning a non-zero amount of DAO coin
	if daoCoinToBurn.IsZero() {
		return 0, 0, nil, RuleErrorDAOCoinBurnMustBurnNonZeroDAOCoin
	}

	// Check that the amount of DAO coin being burned does not exceed the user's balance
	// if daoCoinToBurn > burnerBalanceEntry.BalanceNanos {
	if daoCoinToBurn.Gt(&burnerBalanceEntry.BalanceNanos) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorDAOCoinBurnInsufficientCoins,
			"_connectDAOCoin: DAO Coin nanos being burned %v exceeds user's DAO coin balance %v",
			daoCoinToBurn,
			burnerBalanceEntry.BalanceNanos)
	}

	// Sanity check that the amount being burned is less than the total circulation
	// if daoCoinToBurn > creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos {
	if daoCoinToBurn.Gt(&creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorDAOCoinBurnAmountExceedsCoinsInCirculation,
			"_connectDAOCoin: DAO Coin nanos being burned %v exceeds coins in circulation %v; this should never happen.",
			daoCoinToBurn, creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos)
	}

	// Now we're safe to burn the coins
	// Reduce the total number of coins in circulation
	prevCoinEntry := creatorProfileEntry.DAOCoinEntry
	creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos = *uint256.NewInt().Sub(
		&creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos,
		&daoCoinToBurn)

	// Burn them from the burner's balance entry
	prevTransactorBalanceEntry := *burnerBalanceEntry
	burnerBalanceEntry.BalanceNanos = *uint256.NewInt().Sub(
		&burnerBalanceEntry.BalanceNanos,
		&daoCoinToBurn)

	// Reduce number of holders if necessary
	if burnerBalanceEntry.BalanceNanos.IsZero() {
		creatorProfileEntry.DAOCoinEntry.NumberOfHolders--
	}

	// Delete the burner's balance entry under the assumption that the burner burned all of their coins.
	// We add it back later, if this is not the case.
	bav._deleteDAOCoinBalanceEntryMappings(burnerBalanceEntry, txn.PublicKey, txMeta.ProfilePublicKey)

	// Set the new BalanceEntry in our mappings for the burner and set the
	// ProfileEntry mappings as well since everything is up to date.
	if burnerBalanceEntry.BalanceNanos.Gt(uint256.NewInt()) {
		bav._setDAOCoinBalanceEntryMappings(burnerBalanceEntry)
	}
	bav._setProfileEntryMappings(creatorProfileEntry)

	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                       OperationTypeDAOCoin,
		PrevCoinEntry:              &prevCoinEntry,
		PrevTransactorBalanceEntry: &prevTransactorBalanceEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) HelpConnectDAOCoinDisableMinting(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	totalInput, totalOutput, utxoOpsForTxn, creatorProfileEntry, err := bav.HelpConnectDAOCoinInitialization(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, err
	}

	txMeta := txn.TxnMeta.(*DAOCoinMetadata)

	// First, only the profile associated with the DAO coin can disable minting
	if !reflect.DeepEqual(txMeta.ProfilePublicKey, txn.PublicKey) {
		return 0, 0, nil, RuleErrorOnlyProfileOwnerCanDisableMintingDAOCoin
	}

	// Make sure that minting has not been disabled yet.
	if creatorProfileEntry.DAOCoinEntry.MintingDisabled {
		return 0, 0, nil, RuleErrorDAOCoinCannotDisableMintingIfAlreadyDisabled
	}

	// Save the previous coin entry and then set minting disabled on the existing profile
	prevCoinEntry := creatorProfileEntry.DAOCoinEntry
	creatorProfileEntry.DAOCoinEntry.MintingDisabled = true

	bav._setProfileEntryMappings(creatorProfileEntry)

	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:          OperationTypeDAOCoin,
		PrevCoinEntry: &prevCoinEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) HelpConnectUpdateTransferRestrictionStatus(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	totalInput, totalOutput, utxoOpsForTxn, creatorProfileEntry, err := bav.HelpConnectDAOCoinInitialization(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, err
	}

	txMeta := txn.TxnMeta.(*DAOCoinMetadata)

	// First, only the profile associated with the DAO coin can Update Transfer Restriction Status
	if !reflect.DeepEqual(txMeta.ProfilePublicKey, txn.PublicKey) {
		return 0, 0, nil, RuleErrorOnlyProfileOwnerCanUpdateTransferRestrictionStatus
	}

	// Verify that we're setting TransferRestrictionStatus to a valid value
	currentRestrictionStatus := creatorProfileEntry.DAOCoinEntry.TransferRestrictionStatus

	if currentRestrictionStatus == TransferRestrictionStatusPermanentlyUnrestricted {
		return 0, 0, nil, RuleErrorDAOCoinCannotUpdateRestrictionStatusIfStatusIsPermanentlyUnrestricted
	}

	// We can't update to the same restriction status.
	if currentRestrictionStatus == txMeta.TransferRestrictionStatus {
		return 0, 0, nil, RuleErrorDAOCoinCannotUpdateTransferRestrictionStatusToCurrentStatus
	}

	prevCoinEntry := creatorProfileEntry.DAOCoinEntry
	creatorProfileEntry.DAOCoinEntry.TransferRestrictionStatus = txMeta.TransferRestrictionStatus

	bav._setProfileEntryMappings(creatorProfileEntry)

	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:          OperationTypeDAOCoin,
		PrevCoinEntry: &prevCoinEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, err
}

func (bav *UtxoView) _connectDAOCoin(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeDAOCoin {
		return 0, 0, nil, fmt.Errorf("_connectDAOCoin: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*DAOCoinMetadata)

	switch txMeta.OperationType {
	case DAOCoinOperationTypeMint:
		return bav.HelpConnectDAOCoinMint(txn, txHash, blockHeight, verifySignatures)

	case DAOCoinOperationTypeBurn:
		return bav.HelpConnectDAOCoinBurn(txn, txHash, blockHeight, verifySignatures)

	case DAOCoinOperationTypeDisableMinting:
		return bav.HelpConnectDAOCoinDisableMinting(txn, txHash, blockHeight, verifySignatures)

	case DAOCoinOperationTypeUpdateTransferRestrictionStatus:
		return bav.HelpConnectUpdateTransferRestrictionStatus(txn, txHash, blockHeight, verifySignatures)
	}

	return 0, 0, nil, fmt.Errorf("_connectDAOCoin: Unrecognized DAOCoin "+
		"OperationType: %v", txMeta.OperationType)
}

func (bav *UtxoView) _connectDAOCoinTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < bav.Params.ForkHeights.DAOCoinBlockHeight {
		return 0, 0, nil, errors.Wrapf(RuleErrorDAOCoinBeforeDAOCoinBlockHeight,
			"_connectDAOCoinTransfer: ")
	}
	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeDAOCoinTransfer {
		return 0, 0, nil, fmt.Errorf("_connectDAOCoinTransfer: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}

	return bav.HelpConnectCoinTransfer(txn, txHash, blockHeight, verifySignatures, true)
}

func (bav *UtxoView) IsValidDAOCoinTransfer(
	creatorProfileEntry *ProfileEntry, senderPublicKey []byte, receiverPublicKey []byte) error {
	// If there TransferRestrictionStatus is unrestricted, there are no further checks required.
	if creatorProfileEntry.DAOCoinEntry.TransferRestrictionStatus.IsUnrestricted() {
		return nil
	}

	// If the sender or receiver is the creator, we allow the DAO coin transfer.
	if reflect.DeepEqual(creatorProfileEntry.PublicKey, senderPublicKey) ||
		reflect.DeepEqual(creatorProfileEntry.PublicKey, receiverPublicKey) {
		return nil
	}

	// We've just proven above that neither the sender nor receiver are the profile owner, so we can safely return
	// false as either the sender or receiver must be the profile owner if the status is ProfileOwnerOnly.
	if creatorProfileEntry.DAOCoinEntry.TransferRestrictionStatus == TransferRestrictionStatusProfileOwnerOnly {
		return RuleErrorDAOCoinTransferProfileOwnerOnlyViolation
	}

	// For TransferRestrictionStatusDAOMembersOnly, we need to check that the receiver already has a balance for this
	// DAO coin. We do not need to check the sender since a sender with no balance of DAO coins will not be able to
	// perform a transfer.
	if creatorProfileEntry.DAOCoinEntry.TransferRestrictionStatus == TransferRestrictionStatusDAOMembersOnly {
		receiverBalanceEntry, _, _ := bav.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			receiverPublicKey, creatorProfileEntry.PublicKey)
		if receiverBalanceEntry == nil || receiverBalanceEntry.isDeleted || receiverBalanceEntry.BalanceNanos.IsZero() {
			return RuleErrorDAOCoinTransferDAOMemberOnlyViolation
		}
	}

	return nil
}
