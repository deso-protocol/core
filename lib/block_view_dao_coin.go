package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
	"math"
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

	if blockHeight < DAOCoinBlockHeight {
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
			BalanceNanos: uint64(0),
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
		if txMeta.CoinsToMintNanos == 0 {
			return fmt.Errorf("_disconnectDAOCoin: Must mint more than zero coins; this should never happen")
		}
		// Coins minted + prev coin entry's coins in circulation matches new coin entry's coins in circulation
		if existingProfileEntry.DAOCoinEntry.CoinsInCirculationNanos !=
			operationData.PrevCoinEntry.CoinsInCirculationNanos+txMeta.CoinsToMintNanos {
			return fmt.Errorf("_disconnectDAOCoin: existingProfileEntry's Coins in circulation does not "+
				"equal previous coins in circulation + txMeta.CoinsToMintNanos: %v, %v, %v",
				existingProfileEntry.DAOCoinEntry.CoinsInCirculationNanos,
				operationData.PrevCoinEntry.CoinsInCirculationNanos,
				txMeta.CoinsToMintNanos)
		}
		// Check that creator's current balance is equal to previous balance plus coins to mint. Note: the creator is
		// the transactor in this case
		if transactorBalanceEntry.BalanceNanos !=
			operationData.PrevCreatorBalanceEntry.BalanceNanos+txMeta.CoinsToMintNanos {
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
		if txMeta.CoinsToBurnNanos == 0 {
			return fmt.Errorf("_disconnctDAOCoin: Must burn more than zero coins; this should never happen")
		}
		// prev coin entry's coins in circulation minus coins burned matches new coin entry's coins in circulation
		if existingProfileEntry.DAOCoinEntry.CoinsInCirculationNanos !=
			operationData.PrevCoinEntry.CoinsInCirculationNanos-txMeta.CoinsToBurnNanos {
			return fmt.Errorf("_disconnectDAOCoin: existingProfileEntry's Coins in circulation does not "+
				"equal previous coins in circulation + txMeta.CoinsToBurnNanos: %v, %v, %v",
				existingProfileEntry.DAOCoinEntry.CoinsInCirculationNanos,
				operationData.PrevCoinEntry.CoinsInCirculationNanos,
				txMeta.CoinsToBurnNanos)
		}
		// prev balance entry - coins burned matches the new balance entry's balance
		// Check that transactor's current balance is equal to previous balance minus coins to mint. Note: the creator is
		// the transactor in this case
		if transactorBalanceEntry.BalanceNanos !=
			operationData.PrevTransactorBalanceEntry.BalanceNanos-txMeta.CoinsToBurnNanos {
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
			return fmt.Errorf("_disconnectDAOCoin: Disabling minting on a CoinEntry that already has minting " +
				"disabled; this should never happen")
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
	var senderCurrBalanceNanos uint64
	// Since the sender may have given away their whole balance, their BalanceEntry can be nil.
	if senderBalanceEntry != nil && !senderBalanceEntry.isDeleted {
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
	var receiverPrevBalanceNanos uint64
	if operationData.PrevReceiverBalanceEntry != nil {
		receiverPrevBalanceNanos = operationData.PrevReceiverBalanceEntry.BalanceNanos
	}

	// Sanity check that the sender's current balance is less than their previous balance.
	if senderCurrBalanceNanos > senderPrevBalanceNanos {
		return fmt.Errorf("_disconnectDAOCoinTransfer: Sender's current balance %d is "+
			"greater than their previous balance %d",
			senderCurrBalanceNanos, senderPrevBalanceNanos)
	}

	// Sanity check that the receiver's previous balance is less than their current balance.
	if receiverPrevBalanceNanos > receiverCurrBalanceNanos {
		return fmt.Errorf("_disconnectDAOCoinTransfer: Receiver's previous balance %d is "+
			"greater than their current balance %d",
			receiverPrevBalanceNanos, receiverCurrBalanceNanos)
	}

	// Sanity check the sender's increase equals the receiver's decrease after disconnect.
	senderBalanceIncrease := senderPrevBalanceNanos - senderCurrBalanceNanos
	receiverBalanceDecrease := receiverCurrBalanceNanos - receiverPrevBalanceNanos
	if senderBalanceIncrease != receiverBalanceDecrease {
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
	if operationData.PrevReceiverBalanceEntry != nil && operationData.PrevReceiverBalanceEntry.BalanceNanos != 0 {
		bav._setDAOCoinBalanceEntryMappings(operationData.PrevReceiverBalanceEntry)
	}

	// Reset the CoinEntry on the profile to what it was previously now that we
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

	if blockHeight < DAOCoinBlockHeight {
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

	// First, only the profile associated with the DAO coin can mint or disable minting
	if !reflect.DeepEqual(txMeta.ProfilePublicKey, txn.PublicKey) {
		return 0, 0, nil, RuleErrorOnlyProfileOwnerCanMintDAOCoin
	}

	// Must mint non-zero amount of DAO coins
	if txMeta.CoinsToMintNanos == 0 {
		return 0, 0, nil, RuleErrorDAOCoinMustMintNonZeroDAOCoin
	}

	// At this point we are confident that we have the profile owner minting DAO coins for themselves.
	prevDAOCoinEntry := creatorProfileEntry.DAOCoinEntry

	// Increase coins in circulation
	if creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos > math.MaxUint64-txMeta.CoinsToMintNanos {
		return 0, 0, nil, fmt.Errorf(
			"_connectDAOCoin: Overflow while summing CoinsInCirculationNanos and CoinsToMinNanos: %v, %v",
			creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos, txMeta.CoinsToMintNanos)
	}
	creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos += txMeta.CoinsToMintNanos

	// Increase Balance entry for owner
	profileOwnerBalanceEntry, hodlerPKID, creatorPKID := bav.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txn.PublicKey, txMeta.ProfilePublicKey)
	if profileOwnerBalanceEntry == nil || profileOwnerBalanceEntry.isDeleted {
		profileOwnerBalanceEntry = &BalanceEntry{
			HODLerPKID:   hodlerPKID,
			CreatorPKID:  creatorPKID,
			BalanceNanos: uint64(0),
		}
	}

	// Save a copy of the balance entry
	prevProfileOwnerBalanceEntry := *profileOwnerBalanceEntry

	if profileOwnerBalanceEntry.BalanceNanos > math.MaxUint64-txMeta.CoinsToMintNanos {
		return 0, 0, nil, fmt.Errorf(
			"_connectDAOCoin: Overflow while summing profileOwnerBalanceEntry.BalanceNanos and CoinsToMintNanos: %v, %v",
			profileOwnerBalanceEntry.BalanceNanos, txMeta.CoinsToMintNanos)
	}

	profileOwnerBalanceEntry.BalanceNanos += txMeta.CoinsToMintNanos
	bav._setDAOCoinBalanceEntryMappings(profileOwnerBalanceEntry)

	// Increment the number of holders if necessary
	if prevProfileOwnerBalanceEntry.BalanceNanos == 0 {
		creatorProfileEntry.DAOCoinEntry.NumberOfHolders++

		bav._setProfileEntryMappings(creatorProfileEntry)
	}

	// Add an operation to the list at the end indicating we've executed a
	// CreatorCoin txn. Save the previous state of the CoinEntry for easy
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
	if daoCoinToBurn == 0 {
		return 0, 0, nil, RuleErrorDAOCoinBurnMustBurnNonZeroDAOCoin
	}

	// Check that the amount of DAO coin being burned does not exceed the user's balance
	if daoCoinToBurn > burnerBalanceEntry.BalanceNanos {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorDAOCoinBurnInsufficientCoins,
			"_connectDAOCoin: DAO Coin nanos being burned %v exceeds user's DAO coin balance %v",
			daoCoinToBurn,
			burnerBalanceEntry.BalanceNanos)
	}

	// Sanity check that the amount being burned is less than the total circulation
	if daoCoinToBurn > creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorDAOCoinBurnAmountExceedsCoinsInCirculation,
			"_connectDAOCoin: DAO Coin nanos being burned %v exceeds coins in circulation %v; this should never happen.",
			daoCoinToBurn, creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos)
	}

	// Now we're safe to burn the coins
	// Reduce the total number of coins in circulation
	prevCoinEntry := creatorProfileEntry.DAOCoinEntry
	creatorProfileEntry.DAOCoinEntry.CoinsInCirculationNanos -= daoCoinToBurn

	// Burn them from the burner's balance entry
	prevTransactorBalanceEntry := *burnerBalanceEntry
	burnerBalanceEntry.BalanceNanos -= daoCoinToBurn

	// Reduce number of holders if necessary
	if burnerBalanceEntry.BalanceNanos == 0 {
		creatorProfileEntry.DAOCoinEntry.NumberOfHolders--
	}

	// Delete the burner's balance entry under the assumption that the burner burned all of their coins.
	// We add it back later, if this is not the case.
	bav._deleteDAOCoinBalanceEntryMappings(burnerBalanceEntry, txn.PublicKey, txMeta.ProfilePublicKey)

	// Set the new BalanceEntry in our mappings for the burner and set the
	// ProfileEntry mappings as well since everything is up to date.
	if burnerBalanceEntry.BalanceNanos > 0 {
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

	// First, only the profile associated with the DAO coin can mint or disable minting
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
	}

	return 0, 0, nil, fmt.Errorf("_connectDAOCoin: Unrecognized DAOCoin "+
		"OperationType: %v", txMeta.OperationType)
}

func (bav *UtxoView) _connectDAOCoinTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < DAOCoinBlockHeight {
		return 0, 0, nil, errors.Wrapf(RuleErrorDAOCoinBeforeDAOCoinBlockHeight,
			"_connectDAOCoinTransfer: ")
	}
	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeDAOCoinTransfer {
		return 0, 0, nil, fmt.Errorf("_connectDAOCoinTransfer: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*DAOCoinTransferMetadata)

	if txMeta.DAOCoinToTransferNanos == 0 {
		return 0, 0, nil, RuleErrorDAOCOinTransferMustTransferNonZeroDAOCoins
	}
	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectDAOCoinTransfer: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorDAOCoinTransferRequiresNonZeroInput
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Check that the specified receiver public key is valid.
	if len(txMeta.ReceiverPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorDAOCoinTransferInvalidReceiverPubKeySize
	}

	if _, err = btcec.ParsePubKey(txMeta.ReceiverPublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(
			RuleErrorDAOCoinTransferInvalidReceiverPubKey, err.Error())
	}

	// Check that the sender and receiver public keys are different.
	if reflect.DeepEqual(txn.PublicKey, txMeta.ReceiverPublicKey) {
		return 0, 0, nil, RuleErrorDAOCoinTransferCannotTransferToSelf
	}

	// Check that the specified profile public key is valid and that a profile
	// corresponding to that public key exists.
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorDAOCoinTransferInvalidProfilePubKeySize
	}

	if _, err = btcec.ParsePubKey(txMeta.ProfilePublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(
			RuleErrorDAOCoinTransferInvalidProfilePubKey, err.Error())
	}

	// Dig up the profile. It must exist for the user to be able to transfer its coin.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorDAOCoinTransferOnNonexistentProfile,
			"_connectDAOCoinTransfer: Profile pub key: %v %v",
			PkToStringMainnet(txMeta.ProfilePublicKey), PkToStringTestnet(txMeta.ProfilePublicKey))
	}

	// At this point we are confident that we have a profile that
	// exists that corresponds to the profile public key the user provided.

	// Look up a BalanceEntry for the sender. If it doesn't exist then the sender implicitly
	// has a balance of zero coins, and so the transfer shouldn't be allowed.
	senderBalanceEntry, _, _ := bav.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txn.PublicKey, existingProfileEntry.PublicKey)
	if senderBalanceEntry == nil || senderBalanceEntry.isDeleted {
		return 0, 0, nil, RuleErrorDAOCoinTransferBalanceEntryDoesNotExist
	}

	// Check that the amount of DAO coin being transferred does not exceed the user's
	// balance of this particular DAO coin.
	if txMeta.DAOCoinToTransferNanos > senderBalanceEntry.BalanceNanos {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorDAOCoinTransferInsufficientCoins,
			"_connectDAOCoinTransfer: DAOCoin nanos being transferred %v exceeds "+
				"user's DAO coin balance %v",
			txMeta.DAOCoinToTransferNanos, senderBalanceEntry.BalanceNanos)
	}

	// Now that we have validated this transaction, let's build the new BalanceEntry state.

	// Look up a BalanceEntry for the receiver.
	receiverBalanceEntry, _, _ := bav.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)

	// Save the receiver's balance if it is non-nil.
	var prevReceiverBalanceEntry *BalanceEntry
	if receiverBalanceEntry != nil && !receiverBalanceEntry.isDeleted {
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
				"_connectDAOCoinTransfer: Found nil or deleted PKID for receiver or creator, this should never "+
					"happen. Receiver pubkey: %v, creator pubkey: %v",
				PkToStringMainnet(txMeta.ReceiverPublicKey),
				PkToStringMainnet(existingProfileEntry.PublicKey))
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
	senderBalanceEntry.BalanceNanos -= txMeta.DAOCoinToTransferNanos
	receiverBalanceEntry.BalanceNanos += txMeta.DAOCoinToTransferNanos

	// Delete the sender's balance entry under the assumption that the sender gave away all
	// of their coins. We add it back later, if this is not the case.
	bav._deleteDAOCoinBalanceEntryMappings(senderBalanceEntry, txn.PublicKey, txMeta.ProfilePublicKey)
	// Delete the receiver's balance entry just to be safe. Added back immediately after.
	bav._deleteDAOCoinBalanceEntryMappings(
		receiverBalanceEntry, txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)

	bav._setDAOCoinBalanceEntryMappings(receiverBalanceEntry)
	if senderBalanceEntry.BalanceNanos > 0 {
		bav._setDAOCoinBalanceEntryMappings(senderBalanceEntry)
	}

	// Save all the old values from the CoinEntry before we potentially update them. Note
	// that DAOCoinEntry doesn't contain any pointers and so a direct copy is OK.
	prevCoinEntry := existingProfileEntry.DAOCoinEntry

	if prevReceiverBalanceEntry == nil || prevReceiverBalanceEntry.BalanceNanos == 0 ||
		prevReceiverBalanceEntry.isDeleted {
		// The receiver did not have a BalanceEntry before. Increment num holders.
		existingProfileEntry.DAOCoinEntry.NumberOfHolders++
	}

	if senderBalanceEntry.BalanceNanos == 0 {
		// The sender no longer holds any of this creator's coin, so we decrement num holders.
		existingProfileEntry.DAOCoinEntry.NumberOfHolders--
	}

	// Update and set the new profile entry.
	bav._setProfileEntryMappings(existingProfileEntry)

	// Add an operation to the list at the end indicating we've executed a
	// DAOCoinTransfer txn. Save the previous state of the CoinEntry for easy
	// reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                     OperationTypeDAOCoinTransfer,
		PrevSenderBalanceEntry:   &prevSenderBalanceEntry,
		PrevReceiverBalanceEntry: prevReceiverBalanceEntry,
		PrevCoinEntry:            &prevCoinEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}
