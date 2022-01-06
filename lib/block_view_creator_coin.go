package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"math"
	"math/big"
	"reflect"
)

func (bav *UtxoView) _getBalanceEntryForHODLerPKIDAndCreatorPKID(
	hodlerPKID *PKID, creatorPKID *PKID) *BalanceEntry {

	// If an entry exists in the in-memory map, return the value of that mapping.
	balanceEntryKey := MakeCreatorCoinBalanceKey(hodlerPKID, creatorPKID)
	mapValue, existsMapValue := bav.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	var balanceEntry *BalanceEntry
	if bav.Postgres != nil {
		balance := bav.Postgres.GetCreatorCoinBalance(hodlerPKID, creatorPKID)
		if balance != nil {
			balanceEntry = &BalanceEntry{
				HODLerPKID:   balance.HolderPKID,
				CreatorPKID:  balance.CreatorPKID,
				BalanceNanos: balance.BalanceNanos,
				HasPurchased: balance.HasPurchased,
			}
		}
	} else {
		balanceEntry = DBGetCreatorCoinBalanceEntryForHODLerAndCreatorPKIDs(bav.Handle, hodlerPKID, creatorPKID)
	}
	if balanceEntry != nil {
		bav._setBalanceEntryMappingsWithPKIDs(balanceEntry, hodlerPKID, creatorPKID)
	}
	return balanceEntry
}

func (bav *UtxoView) GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
	hodlerPubKey []byte, creatorPubKey []byte) (
	_balanceEntry *BalanceEntry, _hodlerPKID *PKID, _creatorPKID *PKID) {

	// These are guaranteed to be non-nil as long as the public keys are valid.
	hodlerPKID := bav.GetPKIDForPublicKey(hodlerPubKey)
	creatorPKID := bav.GetPKIDForPublicKey(creatorPubKey)

	return bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(hodlerPKID.PKID, creatorPKID.PKID), hodlerPKID.PKID, creatorPKID.PKID
}

func (bav *UtxoView) _setBalanceEntryMappingsWithPKIDs(
	balanceEntry *BalanceEntry, hodlerPKID *PKID, creatorPKID *PKID) {

	// This function shouldn't be called with nil.
	if balanceEntry == nil {
		glog.Errorf("_setBalanceEntryMappings: Called with nil BalanceEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the BalancEntry.
	balanceEntryKey := MakeCreatorCoinBalanceKey(hodlerPKID, creatorPKID)
	bav.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryKey] = balanceEntry
}

func (bav *UtxoView) _setBalanceEntryMappings(
	balanceEntry *BalanceEntry) {

	bav._setBalanceEntryMappingsWithPKIDs(
		balanceEntry, balanceEntry.HODLerPKID, balanceEntry.CreatorPKID)
}

func (bav *UtxoView) _deleteBalanceEntryMappingsWithPKIDs(
	balanceEntry *BalanceEntry, hodlerPKID *PKID, creatorPKID *PKID) {

	// Create a tombstone entry.
	tombstoneBalanceEntry := *balanceEntry
	tombstoneBalanceEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setBalanceEntryMappingsWithPKIDs(&tombstoneBalanceEntry, hodlerPKID, creatorPKID)
}

func (bav *UtxoView) _deleteBalanceEntryMappings(
	balanceEntry *BalanceEntry, hodlerPublicKey []byte, creatorPublicKey []byte) {

	// These are guaranteed to be non-nil as long as the public keys are valid.
	hodlerPKID := bav.GetPKIDForPublicKey(hodlerPublicKey)
	creatorPKID := bav.GetPKIDForPublicKey(creatorPublicKey)

	// Set the mappings to point to the tombstone entry.
	bav._deleteBalanceEntryMappingsWithPKIDs(balanceEntry, hodlerPKID.PKID, creatorPKID.PKID)
}

func (bav *UtxoView) GetHoldings(pkid *PKID, fetchProfiles bool) ([]*BalanceEntry, []*ProfileEntry, error) {
	var entriesYouHold []*BalanceEntry
	if bav.Postgres != nil {
		balances := bav.Postgres.GetHoldings(pkid)
		for _, balance := range balances {
			entriesYouHold = append(entriesYouHold, balance.NewBalanceEntry())
		}
	} else {
		holdings, err := DbGetBalanceEntriesYouHold(bav.Handle, pkid, true)
		if err != nil {
			return nil, nil, err
		}
		entriesYouHold = holdings
	}

	holdingsMap := make(map[PKID]*BalanceEntry)
	for _, balanceEntry := range entriesYouHold {
		holdingsMap[*balanceEntry.CreatorPKID] = balanceEntry
	}

	for _, balanceEntry := range bav.HODLerPKIDCreatorPKIDToBalanceEntry {
		if reflect.DeepEqual(balanceEntry.HODLerPKID, pkid) {
			if _, ok := holdingsMap[*balanceEntry.CreatorPKID]; ok {
				// We found both a mempool and a db balanceEntry. Update the BalanceEntry using mempool data.
				holdingsMap[*balanceEntry.CreatorPKID].BalanceNanos = balanceEntry.BalanceNanos
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

func (bav *UtxoView) GetHolders(pkid *PKID, fetchProfiles bool) ([]*BalanceEntry, []*ProfileEntry, error) {
	var holderEntries []*BalanceEntry
	if bav.Postgres != nil {
		balances := bav.Postgres.GetHolders(pkid)
		for _, balance := range balances {
			holderEntries = append(holderEntries, balance.NewBalanceEntry())
		}
	} else {
		holders, err := DbGetBalanceEntriesHodlingYou(bav.Handle, pkid, true)
		if err != nil {
			return nil, nil, err
		}
		holderEntries = holders
	}

	holdersMap := make(map[PKID]*BalanceEntry)
	for _, balanceEntry := range holderEntries {
		holdersMap[*balanceEntry.HODLerPKID] = balanceEntry
	}

	for _, balanceEntry := range bav.HODLerPKIDCreatorPKIDToBalanceEntry {
		if reflect.DeepEqual(balanceEntry.HODLerPKID, pkid) {
			if _, ok := holdersMap[*balanceEntry.HODLerPKID]; ok {
				// We found both a mempool and a db balanceEntry. Update the BalanceEntry using mempool data.
				holdersMap[*balanceEntry.HODLerPKID].BalanceNanos = balanceEntry.BalanceNanos
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

func CalculateCreatorCoinToMintPolynomial(
	deltaDeSoNanos uint64, currentCreatorCoinSupplyNanos uint64, params *DeSoParams) uint64 {
	// The values our equations take are generally in whole units rather than
	// nanos, so the first step is to convert the nano amounts into floats
	// representing full coin units.
	bigNanosPerUnit := NewFloat().SetUint64(NanosPerUnit)
	bigDeltaDeSo := Div(NewFloat().SetUint64(deltaDeSoNanos), bigNanosPerUnit)
	bigCurrentCreatorCoinSupply :=
		Div(NewFloat().SetUint64(currentCreatorCoinSupplyNanos), bigNanosPerUnit)

	// These calculations are basically what you get when you integrate a
	// polynomial price curve. For more information, see the comment on
	// CreatorCoinSlope in constants.go and check out the Mathematica notebook
	// linked in that comment.
	//
	// This is the formula:
	// - (((dB + m*RR*s^(1/RR))/(m*RR)))^RR-s
	// - where:
	//     dB = bigDeltaDeSo,
	//     m = params.CreatorCoinSlope
	//     RR = params.CreatorCoinReserveRatio
	//     s = bigCurrentCreatorCoinSupply
	//
	// If you think it's hard to understand the code below, don't worry-- I hate
	// the Go float libary syntax too...
	bigRet := Sub(BigFloatPow((Div((Add(bigDeltaDeSo,
		Mul(params.CreatorCoinSlope, Mul(params.CreatorCoinReserveRatio,
			BigFloatPow(bigCurrentCreatorCoinSupply, (Div(bigOne,
				params.CreatorCoinReserveRatio))))))), Mul(params.CreatorCoinSlope,
		params.CreatorCoinReserveRatio))), params.CreatorCoinReserveRatio),
		bigCurrentCreatorCoinSupply)
	// The value we get is generally a number of whole creator coins, and so we
	// need to convert it to "nanos" as a last step.
	retNanos, _ := Mul(bigRet, bigNanosPerUnit).Uint64()
	return retNanos
}

func CalculateCreatorCoinToMintBancor(
	deltaDeSoNanos uint64, currentCreatorCoinSupplyNanos uint64,
	currentDeSoLockedNanos uint64, params *DeSoParams) uint64 {
	// The values our equations take are generally in whole units rather than
	// nanos, so the first step is to convert the nano amounts into floats
	// representing full coin units.
	bigNanosPerUnit := NewFloat().SetUint64(NanosPerUnit)
	bigDeltaDeSo := Div(NewFloat().SetUint64(deltaDeSoNanos), bigNanosPerUnit)
	bigCurrentCreatorCoinSupply := Div(NewFloat().SetUint64(currentCreatorCoinSupplyNanos), bigNanosPerUnit)
	bigCurrentDeSoLocked := Div(NewFloat().SetUint64(currentDeSoLockedNanos), bigNanosPerUnit)

	// These calculations are derived from the Bancor pricing formula, which
	// is proportional to a polynomial price curve (and equivalent to Uniswap
	// under certain assumptions). For more information, see the comment on
	// CreatorCoinSlope in constants.go and check out the Mathematica notebook
	// linked in that comment.
	//
	// This is the formula:
	// - S0 * ((1 + dB / B0) ^ (RR) - 1)
	// - where:
	//     dB = bigDeltaDeSo,
	//     B0 = bigCurrentDeSoLocked
	//     S0 = bigCurrentCreatorCoinSupply
	//     RR = params.CreatorCoinReserveRatio
	//
	// Sorry the code for the equation is so hard to read.
	bigRet := Mul(bigCurrentCreatorCoinSupply,
		Sub(BigFloatPow((Add(bigOne, Div(bigDeltaDeSo,
			bigCurrentDeSoLocked))),
			(params.CreatorCoinReserveRatio)), bigOne))
	// The value we get is generally a number of whole creator coins, and so we
	// need to convert it to "nanos" as a last step.
	retNanos, _ := Mul(bigRet, bigNanosPerUnit).Uint64()
	return retNanos
}

func CalculateDeSoToReturn(
	deltaCreatorCoinNanos uint64, currentCreatorCoinSupplyNanos uint64,
	currentDeSoLockedNanos uint64, params *DeSoParams) uint64 {
	// The values our equations take are generally in whole units rather than
	// nanos, so the first step is to convert the nano amounts into floats
	// representing full coin units.
	bigNanosPerUnit := NewFloat().SetUint64(NanosPerUnit)
	bigDeltaCreatorCoin := Div(NewFloat().SetUint64(deltaCreatorCoinNanos), bigNanosPerUnit)
	bigCurrentCreatorCoinSupply := Div(NewFloat().SetUint64(currentCreatorCoinSupplyNanos), bigNanosPerUnit)
	bigCurrentDeSoLocked := Div(NewFloat().SetUint64(currentDeSoLockedNanos), bigNanosPerUnit)

	// These calculations are derived from the Bancor pricing formula, which
	// is proportional to a polynomial price curve (and equivalent to Uniswap
	// under certain assumptions). For more information, see the comment on
	// CreatorCoinSlope in constants.go and check out the Mathematica notebook
	// linked in that comment.
	//
	// This is the formula:
	// - B0 * (1 - (1 - dS / S0)^(1/RR))
	// - where:
	//     dS = bigDeltaCreatorCoin,
	//     B0 = bigCurrentDeSoLocked
	//     S0 = bigCurrentCreatorCoinSupply
	//     RR = params.CreatorCoinReserveRatio
	//
	// Sorry the code for the equation is so hard to read.
	bigRet := Mul(bigCurrentDeSoLocked, (Sub(bigOne, BigFloatPow((Sub(bigOne,
		Div(bigDeltaCreatorCoin, bigCurrentCreatorCoinSupply))), (Div(bigOne,
		params.CreatorCoinReserveRatio))))))
	// The value we get is generally a number of whole creator coins, and so we
	// need to convert it to "nanos" as a last step.
	retNanos, _ := Mul(bigRet, bigNanosPerUnit).Uint64()
	return retNanos
}

func CalculateCreatorCoinToMint(
	desoToSellNanos uint64,
	coinsInCirculationNanos uint64, desoLockedNanos uint64,
	params *DeSoParams) uint64 {

	if desoLockedNanos == 0 {
		// In this case, there is no DeSo in the profile so we have to use
		// the polynomial equations to initialize the coin and determine how
		// much to mint.
		return CalculateCreatorCoinToMintPolynomial(
			desoToSellNanos, coinsInCirculationNanos,
			params)
	}

	// In this case, we have DeSo locked in the profile and so we use the
	// standard Bancor equations to determine how much creator coin to mint.
	return CalculateCreatorCoinToMintBancor(
		desoToSellNanos, coinsInCirculationNanos,
		desoLockedNanos, params)
}

func (bav *UtxoView) ValidateDiamondsAndGetNumCreatorCoinNanos(
	senderPublicKey []byte,
	receiverPublicKey []byte,
	diamondPostHash *BlockHash,
	diamondLevel int64,
	blockHeight uint32,
) (_numCreatorCoinNanos uint64, _netNewDiamonds int64, _err error) {

	// Check that the diamond level is reasonable
	diamondLevelMap := GetDeSoNanosDiamondLevelMapAtBlockHeight(int64(blockHeight))
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
		return 0, 0, RuleErrorCreatorCoinTransferPostAlreadyHasSufficientDiamonds
	}

	// Calculate the number of creator coin nanos needed vs. already added for previous diamonds.
	currCreatorCoinNanos := GetCreatorCoinNanosForDiamondLevelAtBlockHeight(
		existingProfileEntry.CoinsInCirculationNanos, existingProfileEntry.DeSoLockedNanos,
		currDiamondLevel, int64(blockHeight), bav.Params)
	neededCreatorCoinNanos := GetCreatorCoinNanosForDiamondLevelAtBlockHeight(
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

func (bav *UtxoView) _disconnectCreatorCoin(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a CreatorCoin opration
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectCreatorCoin: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCreatorCoin {
		return fmt.Errorf("_disconnectCreatorCoin: Trying to revert "+
			"OperationTypeCreatorCoin but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*CreatorCoinMetadataa)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// We sometimes have some extra AddUtxo operations we need to remove
	// These are "implicit" outputs that always occur at the end of the
	// list of UtxoOperations. The number of implicit outputs is equal to
	// the total number of "Add" operations minus the explicit outputs.
	numUtxoAdds := 0
	for _, utxoOp := range utxoOpsForTxn {
		if utxoOp.Type == OperationTypeAddUtxo {
			numUtxoAdds += 1
		}
	}
	operationIndex -= numUtxoAdds - len(currentTxn.TxOutputs)

	// Get the profile corresponding to the creator coin txn.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	// Sanity-check that it exists.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoin: CreatorCoin profile for "+
			"public key %v doesn't exist; this should never happen",
			PkToStringBoth(txMeta.ProfilePublicKey))
	}
	// Get the BalanceEntry of the transactor. This should always exist.
	transactorBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		currentTxn.PublicKey, txMeta.ProfilePublicKey)
	// Sanity-check that the transactor BalanceEntry exists
	if transactorBalanceEntry == nil || transactorBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoin: Transactor BalanceEntry "+
			"pubkey %v and creator pubkey %v does not exist; this should "+
			"never happen",
			PkToStringBoth(currentTxn.PublicKey), PkToStringBoth(txMeta.ProfilePublicKey))
	}

	// Get the BalanceEntry of the creator. It could be nil if this is a sell
	// transaction or if the balance entry was deleted by a creator coin transfer.
	creatorBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txMeta.ProfilePublicKey, txMeta.ProfilePublicKey)
	if creatorBalanceEntry == nil || creatorBalanceEntry.isDeleted {
		creatorPKID := bav.GetPKIDForPublicKey(txMeta.ProfilePublicKey)
		creatorBalanceEntry = &BalanceEntry{
			HODLerPKID:   creatorPKID.PKID,
			CreatorPKID:  creatorPKID.PKID,
			BalanceNanos: uint64(0),
		}
	}

	if txMeta.OperationType == CreatorCoinOperationTypeBuy {
		// Set up some variables so that we can run some sanity-checks
		deltaBuyerNanos := transactorBalanceEntry.BalanceNanos - operationData.PrevTransactorBalanceEntry.BalanceNanos
		deltaCreatorNanos := creatorBalanceEntry.BalanceNanos - operationData.PrevCreatorBalanceEntry.BalanceNanos
		deltaCoinsInCirculation := existingProfileEntry.CoinsInCirculationNanos - operationData.PrevCoinEntry.CoinsInCirculationNanos

		// If the creator is distinct from the buyer, then reset their balance.
		// This check avoids double-updating in situations where a creator bought
		// their own coin.
		if !reflect.DeepEqual(currentTxn.PublicKey, txMeta.ProfilePublicKey) {

			// Sanity-check that the amount that we increased the CoinsInCirculation by
			// equals the total amount received by the buyer and the creator.
			if deltaBuyerNanos+deltaCreatorNanos != deltaCoinsInCirculation {
				return fmt.Errorf("_disconnectCreatorCoin: The creator coin nanos "+
					"the buyer and the creator received (%v, %v) does not equal the "+
					"creator coins added to the circulating supply %v",
					deltaBuyerNanos, deltaCreatorNanos, deltaCoinsInCirculation)
			}

			// Sanity-check that the watermark delta equates to what the creator received.
			deltaNanos := uint64(0)
			if blockHeight > DeSoFounderRewardBlockHeight {
				// Do nothing.  After the DeSoFounderRewardBlockHeight, creator coins are not
				// minted as a founder's reward, just DeSo (see utxo reverted later).
			} else if blockHeight > SalomonFixBlockHeight {
				// Following the SalomonFixBlockHeight block, we calculate a founders reward
				// on every buy, not just the ones that push a creator to a new all time high.
				deltaNanos = existingProfileEntry.CoinsInCirculationNanos - operationData.PrevCoinEntry.CoinsInCirculationNanos
			} else {
				// Prior to the SalomonFixBlockHeight block, we calculate the founders reward
				// only for new all time highs.
				deltaNanos = existingProfileEntry.CoinWatermarkNanos - operationData.PrevCoinEntry.CoinWatermarkNanos
			}
			founderRewardNanos := IntDiv(
				IntMul(
					big.NewInt(int64(deltaNanos)),
					big.NewInt(int64(existingProfileEntry.CreatorBasisPoints))),
				big.NewInt(100*100)).Uint64()
			if founderRewardNanos != deltaCreatorNanos {
				return fmt.Errorf("_disconnectCreatorCoin: The creator coin nanos "+
					"the creator received %v does not equal the founder reward %v; "+
					"this should never happen",
					deltaCreatorNanos, founderRewardNanos)
			}

			// Reset the creator's BalanceEntry to what it was previously.
			*creatorBalanceEntry = *operationData.PrevCreatorBalanceEntry
			bav._setBalanceEntryMappings(creatorBalanceEntry)
		} else {
			// We do a simliar sanity-check as above, but in this case we don't need to
			// reset the creator mappings.
			deltaBuyerNanos := transactorBalanceEntry.BalanceNanos - operationData.PrevTransactorBalanceEntry.BalanceNanos
			deltaCoinsInCirculation := existingProfileEntry.CoinsInCirculationNanos - operationData.PrevCoinEntry.CoinsInCirculationNanos
			if deltaBuyerNanos != deltaCoinsInCirculation {
				return fmt.Errorf("_disconnectCreatorCoin: The creator coin nanos "+
					"the buyer/creator received (%v) does not equal the "+
					"creator coins added to the circulating supply %v",
					deltaBuyerNanos, deltaCoinsInCirculation)
			}
		}

		// Reset the Buyer's BalanceEntry to what it was previously.
		*transactorBalanceEntry = *operationData.PrevTransactorBalanceEntry
		bav._setBalanceEntryMappings(transactorBalanceEntry)

		// If a DeSo founder reward was created, revert it.
		if operationData.FounderRewardUtxoKey != nil {
			if err := bav._unAddUtxo(operationData.FounderRewardUtxoKey); err != nil {
				return errors.Wrapf(err, "_disconnectBitcoinExchange: Problem unAdding utxo %v: ", operationData.FounderRewardUtxoKey)
			}
		}

		// The buyer will get the DeSo they locked up back when we revert the
		// basic transfer. This is OK because resetting the CoinEntry to the previous
		// value lowers the amount of DeSo locked in the profile by the same
		// amount the buyer will receive. Thus no DeSo is created in this
		// transaction.
	} else if txMeta.OperationType == CreatorCoinOperationTypeSell {
		// Set up some variables so that we can run some sanity-checks. The coins
		// the transactor has and the coins in circulation should both have gone
		// down as a result of the transaction, so both of these values should be
		// positive.
		deltaCoinNanos := operationData.PrevTransactorBalanceEntry.BalanceNanos - transactorBalanceEntry.BalanceNanos
		deltaCoinsInCirculation := operationData.PrevCoinEntry.CoinsInCirculationNanos - existingProfileEntry.CoinsInCirculationNanos

		// Sanity-check that the amount we decreased CoinsInCirculation by
		// equals the total amount put in by the seller.
		if deltaCoinNanos != deltaCoinsInCirculation {
			return fmt.Errorf("_disconnectCreatorCoin: The creator coin nanos "+
				"the seller put in (%v) does not equal the "+
				"creator coins removed from the circulating supply %v",
				deltaCoinNanos, deltaCoinsInCirculation)
		}

		// In the case of a sell we only need to revert the transactor's balance,
		// and we don't have to worry about the creator's balance.
		// Reset the transactor's BalanceEntry to what it was previously.
		*transactorBalanceEntry = *operationData.PrevTransactorBalanceEntry
		bav._setBalanceEntryMappings(transactorBalanceEntry)

		// Un-add the UTXO taht was created as a result of this transaction. It should
		// be the one at the end of our UTXO list at this point.
		//
		// The UtxoKey is simply the transaction hash with index set to the end of the
		// transaction list.
		utxoKey := UtxoKey{
			TxID: *currentTxn.Hash(),
			// We give all UTXOs that are created as a result of BitcoinExchange transactions
			// an index of zero. There is generally only one UTXO created in a BitcoinExchange
			// transaction so this field doesn't really matter.
			Index: uint32(len(currentTxn.TxOutputs)),
		}
		if err := bav._unAddUtxo(&utxoKey); err != nil {
			return errors.Wrapf(err, "_disconnectBitcoinExchange: Problem unAdding utxo %v: ", utxoKey)
		}
	} else if txMeta.OperationType == CreatorCoinOperationTypeAddDeSo {
		return fmt.Errorf("_disconnectCreatorCoin: Add DeSo operation txn not implemented")
	}

	// Reset the CoinEntry on the profile to what it was previously now that we
	// have reverted the individual users' balances.
	existingProfileEntry.CoinEntry = *operationData.PrevCoinEntry
	bav._setProfileEntryMappings(existingProfileEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the CreatorCoin operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectCreatorCoinTransfer(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
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
	txMeta := currentTxn.TxnMeta.(*CreatorCoinTransferMetadataa)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Get the profile corresponding to the creator coin txn.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	// Sanity-check that it exists.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: CreatorCoinTransfer profile for "+
			"public key %v doesn't exist; this should never happen",
			PkToStringBoth(txMeta.ProfilePublicKey))
	}

	// Get the current / previous balance for the sender for sanity checking.
	senderBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		currentTxn.PublicKey, txMeta.ProfilePublicKey)
	// Sanity-check that the sender had a previous BalanceEntry, it should always exist.
	if operationData.PrevSenderBalanceEntry == nil || operationData.PrevSenderBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Previous sender BalanceEntry "+
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
	receiverBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)
	// Sanity-check that the receiver BalanceEntry exists, it should always exist here.
	if receiverBalanceEntry == nil || receiverBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Receiver BalanceEntry "+
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
	diamondPostHashBytes, hasDiamondPostHash := currentTxn.ExtraData[DiamondPostHashKey]
	if hasDiamondPostHash {
		// Sanity check the post hash bytes before creating the post hash.
		diamondPostHash := &BlockHash{}
		if len(diamondPostHashBytes) != HashSizeBytes {
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

// TODO: A lot of duplicate code between buy and sell. Consider factoring
// out the common code.
func (bav *UtxoView) HelpConnectCreatorCoinBuy(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _creatorCoinReturnedNanos uint64, _founderRewardNanos uint64,
	_utxoOps []*UtxoOperation, _err error) {

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, 0, 0, nil, errors.Wrapf(err, "_connectCreatorCoin: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks. If
	// we didn't do this then someone could replay your sell over and over again
	// to force-convert all your creator coin into DeSo. Think about it.
	if totalInput == 0 {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinRequiresNonZeroInput
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Check that the specified profile public key is valid and that a profile
	// corresponding to that public key exists.
	txMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinInvalidPubKeySize
	}

	// Dig up the profile. It must exist for the user to be able to
	// operate on its coin.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinOperationOnNonexistentProfile,
			"_connectCreatorCoin: Profile pub key: %v %v",
			PkToStringMainnet(txMeta.ProfilePublicKey), PkToStringTestnet(txMeta.ProfilePublicKey))
	}

	// At this point we are confident that we have a profile that
	// exists that corresponds to the profile public key the user
	// provided.

	// Check that the amount of DeSo being traded for creator coin is
	// non-zero.
	desoBeforeFeesNanos := txMeta.DeSoToSellNanos
	if desoBeforeFeesNanos == 0 {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustTradeNonZeroDeSo
	}
	// The amount of DeSo being traded counts as output being spent by
	// this transaction, so add it to the transaction output and check that
	// the resulting output does not exceed the total input.
	//
	// Check for overflow of the outputs before adding.
	if totalOutput > math.MaxUint64-desoBeforeFeesNanos {
		return 0, 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTxnOutputWithInvalidBuyAmount,
			"_connectCreatorCoin: %v", desoBeforeFeesNanos)
	}
	totalOutput += desoBeforeFeesNanos
	// It's assumed the caller code will check that things like output <= input,
	// but we check it here just in case...
	if totalInput < totalOutput {
		return 0, 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTxnOutputExceedsInput,
			"_connectCreatorCoin: Input: %v, Output: %v", totalInput, totalOutput)
	}
	// At this point we have verified that the output is sufficient to cover
	// the amount the user wants to use to buy the creator's coin.

	// Now we burn some DeSo before executing the creator coin buy. Doing
	// this guarantees that floating point errors in our subsequent calculations
	// will not result in a user being able to print infinite amounts of DeSo
	// through the protocol.
	//
	// TODO(performance): We use bigints to avoid overflow in the intermediate
	// stages of the calculation but this most likely isn't necessary. This
	// formula is equal to:
	// - desoAfterFeesNanos = desoBeforeFeesNanos * (CreatorCoinTradeFeeBasisPoints / (100*100))
	desoAfterFeesNanos := IntDiv(
		IntMul(
			big.NewInt(int64(desoBeforeFeesNanos)),
			big.NewInt(int64(100*100-bav.Params.CreatorCoinTradeFeeBasisPoints))),
		big.NewInt(100*100)).Uint64()

	// The amount of DeSo being convertend must be nonzero after fees as well.
	if desoAfterFeesNanos == 0 {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustTradeNonZeroDeSoAfterFees
	}

	// Figure out how much deso goes to the founder.
	// Note: If the user performing this transaction has the same public key as the
	// profile being bought, we do not cut a founder reward.
	desoRemainingNanos := uint64(0)
	desoFounderRewardNanos := uint64(0)
	if blockHeight > DeSoFounderRewardBlockHeight &&
		!reflect.DeepEqual(txn.PublicKey, existingProfileEntry.PublicKey) {

		// This formula is equal to:
		// desoFounderRewardNanos = desoAfterFeesNanos * creatorBasisPoints / (100*100)
		desoFounderRewardNanos = IntDiv(
			IntMul(
				big.NewInt(int64(desoAfterFeesNanos)),
				big.NewInt(int64(existingProfileEntry.CreatorBasisPoints))),
			big.NewInt(100*100)).Uint64()

		// Sanity check, just to be extra safe.
		if desoAfterFeesNanos < desoFounderRewardNanos {
			return 0, 0, 0, 0, nil, fmt.Errorf("HelpConnectCreatorCoinBuy: desoAfterFeesNanos"+
				" less than desoFounderRewardNanos: %v %v",
				desoAfterFeesNanos, desoFounderRewardNanos)
		}

		desoRemainingNanos = desoAfterFeesNanos - desoFounderRewardNanos
	} else {
		desoRemainingNanos = desoAfterFeesNanos
	}

	if desoRemainingNanos == 0 {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustTradeNonZeroDeSoAfterFounderReward
	}

	// If no DeSo is currently locked in the profile then we use the
	// polynomial equation to mint creator coins. We do this because the
	// Uniswap/Bancor equations don't work when zero coins have been minted,
	// and so we have to special case here. See this wolfram sheet for all
	// the equations with tests:
	// - https://pastebin.com/raw/1EmgeW56
	//
	// Note also that we use big floats with a custom math library in order
	// to guarantee that all nodes get the same result regardless of what
	// architecture they're running on. If we didn't do this, then some nodes
	// could round floats or use different levels of precision for intermediate
	// results and get different answers which would break consensus.
	creatorCoinToMintNanos := CalculateCreatorCoinToMint(
		desoRemainingNanos, existingProfileEntry.CoinsInCirculationNanos,
		existingProfileEntry.DeSoLockedNanos, bav.Params)

	// Check if the total amount minted satisfies CreatorCoinAutoSellThresholdNanos.
	// This makes it prohibitively expensive for a user to buy themself above the
	// CreatorCoinAutoSellThresholdNanos and then spam tiny nano DeSo creator
	// coin purchases causing the effective Bancor Creator Coin Reserve Ratio to drift.
	if blockHeight > SalomonFixBlockHeight {
		if creatorCoinToMintNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
			return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustSatisfyAutoSellThresholdNanos
		}
	}

	// At this point, we know how much creator coin we are going to mint.
	// Now it's just a matter of adjusting our bookkeeping and potentially
	// giving the creator a founder reward.

	// Save all the old values from the CoinEntry before we potentially
	// update them. Note that CoinEntry doesn't contain any pointers and so
	// a direct copy is OK.
	prevCoinEntry := existingProfileEntry.CoinEntry

	// Increment DeSoLockedNanos. Sanity-check that we're not going to
	// overflow.
	if existingProfileEntry.DeSoLockedNanos > math.MaxUint64-desoRemainingNanos {
		return 0, 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Overflow while summing"+
			"DeSoLockedNanos and desoAfterFounderRewardNanos: %v %v",
			existingProfileEntry.DeSoLockedNanos, desoRemainingNanos)
	}
	existingProfileEntry.DeSoLockedNanos += desoRemainingNanos

	// Increment CoinsInCirculation. Sanity-check that we're not going to
	// overflow.
	if existingProfileEntry.CoinsInCirculationNanos > math.MaxUint64-creatorCoinToMintNanos {
		return 0, 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Overflow while summing"+
			"CoinsInCirculationNanos and creatorCoinToMintNanos: %v %v",
			existingProfileEntry.CoinsInCirculationNanos, creatorCoinToMintNanos)
	}
	existingProfileEntry.CoinsInCirculationNanos += creatorCoinToMintNanos

	// Calculate the *Creator Coin nanos* to give as a founder reward.
	creatorCoinFounderRewardNanos := uint64(0)
	if blockHeight > DeSoFounderRewardBlockHeight {
		// Do nothing. The chain stopped minting creator coins as a founder reward for
		// creators at this blockheight.  It gives DeSo as a founder reward now instead.

	} else if blockHeight > SalomonFixBlockHeight {
		// Following the SalomonFixBlockHeight block, creator coin buys continuously mint
		// a founders reward based on the CreatorBasisPoints.

		creatorCoinFounderRewardNanos = IntDiv(
			IntMul(
				big.NewInt(int64(creatorCoinToMintNanos)),
				big.NewInt(int64(existingProfileEntry.CreatorBasisPoints))),
			big.NewInt(100*100)).Uint64()
	} else {
		// Up to and including the SalomonFixBlockHeight block, creator coin buys only minted
		// a founders reward if the creator reached a new all time high.

		if existingProfileEntry.CoinsInCirculationNanos > existingProfileEntry.CoinWatermarkNanos {
			// This value must be positive if we made it past the if condition above.
			watermarkDiff := existingProfileEntry.CoinsInCirculationNanos - existingProfileEntry.CoinWatermarkNanos
			// The founder reward is computed as a percentage of the "net coins created,"
			// which is equal to the watermarkDiff
			creatorCoinFounderRewardNanos = IntDiv(
				IntMul(
					big.NewInt(int64(watermarkDiff)),
					big.NewInt(int64(existingProfileEntry.CreatorBasisPoints))),
				big.NewInt(100*100)).Uint64()
		}
	}

	// CoinWatermarkNanos is no longer used, however it may be helpful for
	// future analytics or updates so we continue to update it here.
	if existingProfileEntry.CoinsInCirculationNanos > existingProfileEntry.CoinWatermarkNanos {
		existingProfileEntry.CoinWatermarkNanos = existingProfileEntry.CoinsInCirculationNanos
	}

	// At this point, founderRewardNanos will be non-zero if and only if we increased
	// the watermark *and* there was a non-zero CreatorBasisPoints set on the CoinEntry
	// *and* the blockHeight is less than DeSoFounderRewardBlockHeight.

	// The user gets whatever's left after we pay the founder their reward.
	coinsBuyerGetsNanos := creatorCoinToMintNanos - creatorCoinFounderRewardNanos

	// If the coins the buyer is getting is less than the minimum threshold that
	// they expected to get, then the transaction is invalid. This prevents
	// front-running attacks, but it also prevents the buyer from getting a
	// terrible price.
	//
	// Note that when the min is set to zero it means we should skip this check.
	if txMeta.MinCreatorCoinExpectedNanos != 0 &&
		coinsBuyerGetsNanos < txMeta.MinCreatorCoinExpectedNanos {
		return 0, 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinLessThanMinimumSetByUser,
			"_connectCreatorCoin: Amount that would be minted and given to user: "+
				"%v, amount that would be given to founder: %v, amount user needed: %v",
			coinsBuyerGetsNanos, creatorCoinFounderRewardNanos, txMeta.MinCreatorCoinExpectedNanos)
	}

	// If we get here, we are good to go. We will now update the balance of the
	// buyer and the creator (assuming we had a non-zero founderRewardNanos).

	// Look up a CreatorCoinBalanceEntry for the buyer and the creator. Create
	// an entry for each if one doesn't exist already.
	buyerBalanceEntry, hodlerPKID, creatorPKID :=
		bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			txn.PublicKey, existingProfileEntry.PublicKey)
	// If the user does not have a balance entry or the user's balance entry is deleted and we have passed the
	// BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight, we create a new balance entry.
	if buyerBalanceEntry == nil ||
		(buyerBalanceEntry.isDeleted && blockHeight > BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight) {
		// If there is no balance entry for this mapping yet then just create it.
		// In this case the balance will be zero.
		buyerBalanceEntry = &BalanceEntry{
			// The person who created the txn is they buyer/hodler
			HODLerPKID: hodlerPKID,
			// The creator is the owner of the profile that corresponds to the coin.
			CreatorPKID:  creatorPKID,
			BalanceNanos: uint64(0),
		}
	}

	// Get the balance entry for the creator. In this case the creator owns
	// their own coin and therefore the creator is also the HODLer. We need
	// this so we can pay the creator their founder reward. Note that we have
	// a special case when the creator is purchasing their own coin.
	var creatorBalanceEntry *BalanceEntry
	if reflect.DeepEqual(txn.PublicKey, existingProfileEntry.PublicKey) {
		// If the creator is buying their own coin, don't fetch/create a
		// duplicate entry. If we didn't do this, we might wind up with two
		// duplicate BalanceEntrys when a creator is buying their own coin.
		creatorBalanceEntry = buyerBalanceEntry
	} else {
		// In this case, the creator is distinct from the buyer, so fetch and
		// potentially create a new BalanceEntry for them rather than using the
		// existing one.
		creatorBalanceEntry, hodlerPKID, creatorPKID = bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			existingProfileEntry.PublicKey, existingProfileEntry.PublicKey)
		// If the creator does not have a balance entry or the creator's balance entry is deleted and we have passed the
		// BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight, we create a new balance entry.
		if creatorBalanceEntry == nil ||
			(creatorBalanceEntry.isDeleted && blockHeight > BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight) {
			// If there is no balance entry then it means the creator doesn't own
			// any of their coin yet. In this case we create a new entry for them
			// with a zero balance.
			creatorBalanceEntry = &BalanceEntry{
				HODLerPKID:   hodlerPKID,
				CreatorPKID:  creatorPKID,
				BalanceNanos: uint64(0),
			}
		}
	}
	// At this point we should have a BalanceEntry for the buyer and the creator.
	// These may be the same BalancEntry if the creator is buying their own coin,
	// but that is OK.

	// Save the previous balance entry before modifying it. If the creator is
	// buying their own coin, this will be the same BalanceEntry, which is fine.
	prevBuyerBalanceEntry := *buyerBalanceEntry
	prevCreatorBalanceEntry := *creatorBalanceEntry

	// Increase the buyer and the creator's balances by the amounts computed
	// previously. Always check for overflow.
	if buyerBalanceEntry.BalanceNanos > math.MaxUint64-coinsBuyerGetsNanos {
		return 0, 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Overflow while summing"+
			"buyerBalanceEntry.BalanceNanos and coinsBuyerGetsNanos %v %v",
			buyerBalanceEntry.BalanceNanos, coinsBuyerGetsNanos)
	}
	// Check that if the buyer is receiving nanos for the first time, it's enough
	// to push them above the CreatorCoinAutoSellThresholdNanos threshold. This helps
	// prevent tiny amounts of nanos from drifting the ratio of creator coins to DeSo locked.
	if blockHeight > SalomonFixBlockHeight {
		if buyerBalanceEntry.BalanceNanos == 0 && coinsBuyerGetsNanos != 0 &&
			coinsBuyerGetsNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
			return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustSatisfyAutoSellThresholdNanosForBuyer
		}
	}

	// Check if this is the buyers first buy or first buy after a complete sell.
	// If it is, we increment the NumberOfHolders to reflect this value.
	if buyerBalanceEntry.BalanceNanos == 0 && coinsBuyerGetsNanos != 0 {
		// Increment number of holders by one to reflect the buyer
		existingProfileEntry.NumberOfHolders += 1

		// Update the profile to reflect the new number of holders
		bav._setProfileEntryMappings(existingProfileEntry)
	}
	// Finally increment the buyerBalanceEntry.BalanceNanos to reflect
	// the purchased coinsBuyerGetsNanos. If coinsBuyerGetsNanos is greater than 0, we set HasPurchased to true.
	buyerBalanceEntry.BalanceNanos += coinsBuyerGetsNanos
	buyerBalanceEntry.HasPurchased = true

	// If the creator is buying their own coin, this will just be modifying
	// the same pointer as the buyerBalanceEntry, which is what we want.
	if creatorBalanceEntry.BalanceNanos > math.MaxUint64-creatorCoinFounderRewardNanos {
		return 0, 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Overflow while summing"+
			"creatorBalanceEntry.BalanceNanos and creatorCoinFounderRewardNanos %v %v",
			creatorBalanceEntry.BalanceNanos, creatorCoinFounderRewardNanos)
	}
	// Check that if the creator is receiving nanos for the first time, it's enough
	// to push them above the CreatorCoinAutoSellThresholdNanos threshold. This helps
	// prevent tiny amounts of nanos from drifting the effective creator coin reserve ratio drift.
	if creatorBalanceEntry.BalanceNanos == 0 &&
		creatorCoinFounderRewardNanos != 0 &&
		creatorCoinFounderRewardNanos < bav.Params.CreatorCoinAutoSellThresholdNanos &&
		blockHeight > SalomonFixBlockHeight {

		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustSatisfyAutoSellThresholdNanosForCreator
	}
	// Check if the creator's balance is going from zero to non-zero and increment the NumberOfHolders if so.
	if creatorBalanceEntry.BalanceNanos == 0 && creatorCoinFounderRewardNanos != 0 {
		// Increment number of holders by one to reflect the creator
		existingProfileEntry.NumberOfHolders += 1

		// Update the profile to reflect the new number of holders
		bav._setProfileEntryMappings(existingProfileEntry)
	}
	creatorBalanceEntry.BalanceNanos += creatorCoinFounderRewardNanos

	// At this point the balances for the buyer and the creator should be correct
	// so set the mappings in the view.
	bav._setBalanceEntryMappings(buyerBalanceEntry)
	// Avoid setting the same entry twice if the creator is buying their own coin.
	if buyerBalanceEntry != creatorBalanceEntry {
		bav._setBalanceEntryMappings(creatorBalanceEntry)
	}

	// Finally, if the creator is getting a deso founder reward, add a UTXO for it.
	var outputKey *UtxoKey
	if blockHeight > DeSoFounderRewardBlockHeight {
		if desoFounderRewardNanos > 0 {
			// Create a new entry for this output and add it to the view. It should be
			// added at the end of the utxo list.
			outputKey = &UtxoKey{
				TxID: *txHash,
				// The output is like an extra virtual output at the end of the transaction.
				Index: uint32(len(txn.TxOutputs)),
			}

			utxoEntry := UtxoEntry{
				AmountNanos: desoFounderRewardNanos,
				PublicKey:   existingProfileEntry.PublicKey,
				BlockHeight: blockHeight,
				UtxoType:    UtxoTypeCreatorCoinFounderReward,
				UtxoKey:     outputKey,
				// We leave the position unset and isSpent to false by default.
				// The position will be set in the call to _addUtxo.
			}

			utxoOp, err := bav._addUtxo(&utxoEntry)
			if err != nil {
				return 0, 0, 0, 0, nil, errors.Wrapf(err, "HelpConnectCreatorCoinBuy: Problem adding output utxo")
			}

			// Rosetta uses this UtxoOperation to provide INPUT amounts
			utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
		}
	}

	// Compute the change in DESO locked. This information is needed by Rosetta
	// and it's much more efficient to compute it here than it is to recompute
	// it later.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, 0, 0, nil, errors.Wrapf(err, "HelpConnectCreatorCoinBuy: Error computing "+
			"desoLockedNanosDiff: Missing profile")
	}
	desoLockedNanosDiff := int64(existingProfileEntry.DeSoLockedNanos) - int64(prevCoinEntry.DeSoLockedNanos)

	// Add an operation to the list at the end indicating we've executed a
	// CreatorCoin txn. Save the previous state of the CoinEntry for easy
	// reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                           OperationTypeCreatorCoin,
		PrevCoinEntry:                  &prevCoinEntry,
		PrevTransactorBalanceEntry:     &prevBuyerBalanceEntry,
		PrevCreatorBalanceEntry:        &prevCreatorBalanceEntry,
		FounderRewardUtxoKey:           outputKey,
		CreatorCoinDESOLockedNanosDiff: desoLockedNanosDiff,
	})

	return totalInput, totalOutput, coinsBuyerGetsNanos, creatorCoinFounderRewardNanos, utxoOpsForTxn, nil
}

// TODO: A lot of duplicate code between buy and sell. Consider factoring
// out the common code.
func (bav *UtxoView) HelpConnectCreatorCoinSell(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _desoReturnedNanos uint64,
	_utxoOps []*UtxoOperation, _err error) {

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, 0, nil, errors.Wrapf(err, "_connectCreatorCoin: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks. If
	// we didn't do this then someone could replay your sell over and over again
	// to force-convert all your creator coin into DeSo. Think about it.
	if totalInput == 0 {
		return 0, 0, 0, nil, RuleErrorCreatorCoinRequiresNonZeroInput
	}

	// Verify that the output does not exceed the input. This check should also
	// be done by the caller, but we do it here as well.
	if totalInput < totalOutput {
		return 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTxnOutputExceedsInput,
			"_connectCreatorCoin: Input: %v, Output: %v", totalInput, totalOutput)
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Check that the specified profile public key is valid and that a profile
	// corresponding to that public key exists.
	txMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, 0, nil, RuleErrorCreatorCoinInvalidPubKeySize
	}

	// Dig up the profile. It must exist for the user to be able to
	// operate on its coin.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinOperationOnNonexistentProfile,
			"_connectCreatorCoin: Profile pub key: %v %v",
			PkToStringMainnet(txMeta.ProfilePublicKey), PkToStringTestnet(txMeta.ProfilePublicKey))
	}

	// At this point we are confident that we have a profile that
	// exists that corresponds to the profile public key the user
	// provided.

	// Look up a BalanceEntry for the seller. If it doesn't exist then the seller
	// implicitly has a balance of zero coins, and so the sell transaction shouldn't be
	// allowed.
	sellerBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txn.PublicKey, existingProfileEntry.PublicKey)
	if sellerBalanceEntry == nil || sellerBalanceEntry.isDeleted {
		return 0, 0, 0, nil, RuleErrorCreatorCoinSellerBalanceEntryDoesNotExist
	}

	// Check that the amount of creator coin being sold is non-zero.
	creatorCoinToSellNanos := txMeta.CreatorCoinToSellNanos
	if creatorCoinToSellNanos == 0 {
		return 0, 0, 0, nil, RuleErrorCreatorCoinSellMustTradeNonZeroCreatorCoin
	}

	// Check that the amount of creator coin being sold does not exceed the user's
	// balance of this particular creator coin.
	if creatorCoinToSellNanos > sellerBalanceEntry.BalanceNanos {
		return 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinSellInsufficientCoins,
			"_connectCreatorCoin: CreatorCoin nanos being sold %v exceeds "+
				"user's creator coin balance %v",
			creatorCoinToSellNanos, sellerBalanceEntry.BalanceNanos)
	}

	// If the amount of DeSo locked in the profile is zero then selling is
	// not allowed.
	if existingProfileEntry.DeSoLockedNanos == 0 {
		return 0, 0, 0, nil, RuleErrorCreatorCoinSellNotAllowedWhenZeroDeSoLocked
	}

	desoBeforeFeesNanos := uint64(0)
	// Compute the amount of DeSo to return.
	if blockHeight > SalomonFixBlockHeight {
		// Following the SalomonFixBlockHeight block, if a user would be left with less than
		// bav.Params.CreatorCoinAutoSellThresholdNanos, we clear all their remaining holdings
		// to prevent 1 or 2 lingering creator coin nanos from staying in their wallet.
		// This also gives a method for cleanly and accurately reducing the numberOfHolders.

		// Note that we check that sellerBalanceEntry.BalanceNanos >= creatorCoinToSellNanos above.
		if sellerBalanceEntry.BalanceNanos-creatorCoinToSellNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
			// Setup to sell all the creator coins the seller has.
			creatorCoinToSellNanos = sellerBalanceEntry.BalanceNanos

			// Compute the amount of DeSo to return with the new creatorCoinToSellNanos.
			desoBeforeFeesNanos = CalculateDeSoToReturn(
				creatorCoinToSellNanos, existingProfileEntry.CoinsInCirculationNanos,
				existingProfileEntry.DeSoLockedNanos, bav.Params)

			// If the amount the formula is offering is more than what is locked in the
			// profile, then truncate it down. This addresses an edge case where our
			// equations may return *too much* DeSo due to rounding errors.
			if desoBeforeFeesNanos > existingProfileEntry.DeSoLockedNanos {
				desoBeforeFeesNanos = existingProfileEntry.DeSoLockedNanos
			}
		} else {
			// If we're above the CreatorCoinAutoSellThresholdNanos, we can safely compute
			// the amount to return based on the Bancor curve.
			desoBeforeFeesNanos = CalculateDeSoToReturn(
				creatorCoinToSellNanos, existingProfileEntry.CoinsInCirculationNanos,
				existingProfileEntry.DeSoLockedNanos, bav.Params)

			// If the amount the formula is offering is more than what is locked in the
			// profile, then truncate it down. This addresses an edge case where our
			// equations may return *too much* DeSo due to rounding errors.
			if desoBeforeFeesNanos > existingProfileEntry.DeSoLockedNanos {
				desoBeforeFeesNanos = existingProfileEntry.DeSoLockedNanos
			}
		}
	} else {
		// Prior to the SalomonFixBlockHeight block, coins would be minted based on floating point
		// arithmetic with the exception being if a creator was selling all remaining creator coins. This caused
		// a rare issue where a creator would be left with 1 creator coin nano in circulation
		// and 1 nano DeSo locked after completely selling. This in turn made the Bancor Curve unstable.

		if creatorCoinToSellNanos == existingProfileEntry.CoinsInCirculationNanos {
			desoBeforeFeesNanos = existingProfileEntry.DeSoLockedNanos
		} else {
			// Calculate the amount to return based on the Bancor Curve.
			desoBeforeFeesNanos = CalculateDeSoToReturn(
				creatorCoinToSellNanos, existingProfileEntry.CoinsInCirculationNanos,
				existingProfileEntry.DeSoLockedNanos, bav.Params)

			// If the amount the formula is offering is more than what is locked in the
			// profile, then truncate it down. This addresses an edge case where our
			// equations may return *too much* DeSo due to rounding errors.
			if desoBeforeFeesNanos > existingProfileEntry.DeSoLockedNanos {
				desoBeforeFeesNanos = existingProfileEntry.DeSoLockedNanos
			}
		}
	}

	// Save all the old values from the CoinEntry before we potentially
	// update them. Note that CoinEntry doesn't contain any pointers and so
	// a direct copy is OK.
	prevCoinEntry := existingProfileEntry.CoinEntry

	// Subtract the amount of DeSo the seller is getting from the amount of
	// DeSo locked in the profile. Sanity-check that it does not exceed the
	// total amount of DeSo locked.
	if desoBeforeFeesNanos > existingProfileEntry.DeSoLockedNanos {
		return 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: DeSo nanos seller "+
			"would get %v exceeds DeSo nanos locked in profile %v",
			desoBeforeFeesNanos, existingProfileEntry.DeSoLockedNanos)
	}
	existingProfileEntry.DeSoLockedNanos -= desoBeforeFeesNanos

	// Subtract the number of coins the seller is selling from the number of coins
	// in circulation. Sanity-check that it does not exceed the number of coins
	// currently in circulation.
	if creatorCoinToSellNanos > existingProfileEntry.CoinsInCirculationNanos {
		return 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: CreatorCoin nanos seller "+
			"is selling %v exceeds CreatorCoin nanos in circulation %v",
			creatorCoinToSellNanos, existingProfileEntry.CoinsInCirculationNanos)
	}
	existingProfileEntry.CoinsInCirculationNanos -= creatorCoinToSellNanos

	// Check if this is a complete sell of the seller's remaining creator coins
	if sellerBalanceEntry.BalanceNanos == creatorCoinToSellNanos {
		existingProfileEntry.NumberOfHolders -= 1
	}

	// If the number of holders has reached zero, we clear all the DeSoLockedNanos and
	// creatorCoinToSellNanos to ensure that the profile is reset to its normal initial state.
	// It's okay to modify these values because they are saved in the PrevCoinEntry.
	if existingProfileEntry.NumberOfHolders == 0 {
		existingProfileEntry.DeSoLockedNanos = 0
		existingProfileEntry.CoinsInCirculationNanos = 0
	}

	// Save the seller's balance before we modify it. We don't need to save the
	// creator's BalancEntry on a sell because the creator's balance will not
	// be modified.
	prevTransactorBalanceEntry := *sellerBalanceEntry

	// Subtract the number of coins the seller is selling from the number of coins
	// they HODL. Note that we already checked that this amount does not exceed the
	// seller's balance above. Note that this amount equals sellerBalanceEntry.BalanceNanos
	// in the event where the requested remaining creator coin balance dips
	// below CreatorCoinAutoSellThresholdNanos.
	sellerBalanceEntry.BalanceNanos -= creatorCoinToSellNanos

	// If the seller's balance will be zero after this transaction, set HasPurchased to false
	if sellerBalanceEntry.BalanceNanos == 0 {
		sellerBalanceEntry.HasPurchased = false
	}

	// Set the new BalanceEntry in our mappings for the seller and set the
	// ProfileEntry mappings as well since everything is up to date.
	bav._setBalanceEntryMappings(sellerBalanceEntry)
	bav._setProfileEntryMappings(existingProfileEntry)

	// Charge a fee on the DeSo the seller is getting to hedge against
	// floating point errors
	desoAfterFeesNanos := IntDiv(
		IntMul(
			big.NewInt(int64(desoBeforeFeesNanos)),
			big.NewInt(int64(100*100-bav.Params.CreatorCoinTradeFeeBasisPoints))),
		big.NewInt(100*100)).Uint64()

	// Check that the seller is getting back an amount of DeSo that is
	// greater than or equal to what they expect. Note that this check is
	// skipped if the min amount specified is zero.
	if txMeta.MinDeSoExpectedNanos != 0 &&
		desoAfterFeesNanos < txMeta.MinDeSoExpectedNanos {

		return 0, 0, 0, nil, errors.Wrapf(
			RuleErrorDeSoReceivedIsLessThanMinimumSetBySeller,
			"_connectCreatorCoin: DeSo nanos that would be given to seller: "+
				"%v, amount user needed: %v",
			desoAfterFeesNanos, txMeta.MinDeSoExpectedNanos)
	}

	// Now that we have all the information we need, save a UTXO allowing the user to
	// spend the DeSo from the sale in the future.
	outputKey := UtxoKey{
		TxID: *txn.Hash(),
		// The output is like an extra virtual output at the end of the transaction.
		Index: uint32(len(txn.TxOutputs)),
	}
	utxoEntry := UtxoEntry{
		AmountNanos: desoAfterFeesNanos,
		PublicKey:   txn.PublicKey,
		BlockHeight: blockHeight,
		UtxoType:    UtxoTypeCreatorCoinSale,
		UtxoKey:     &outputKey,
		// We leave the position unset and isSpent to false by default.
		// The position will be set in the call to _addUtxo.
	}
	// If we have a problem adding this utxo return an error but don't
	// mark this block as invalid since it's not a rule error and the block
	// could therefore benefit from being processed in the future.
	utxoOp, err := bav._addUtxo(&utxoEntry)
	if err != nil {
		return 0, 0, 0, nil, errors.Wrapf(
			err, "_connectBitcoinExchange: Problem adding output utxo")
	}

	// Rosetta uses this UtxoOperation to provide INPUT amounts
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)

	// Compute the change in DESO locked. This information is needed by Rosetta
	// and it's much more efficient to compute it here than it is to recompute
	// it later.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, 0, nil, errors.Wrapf(
			err, "HelpConnectCreatorCoinSell: Error computing "+
				"desoLockedNanosDiff: Missing profile")
	}
	desoLockedNanosDiff := int64(existingProfileEntry.DeSoLockedNanos) - int64(prevCoinEntry.DeSoLockedNanos)

	// Add an operation to the list at the end indicating we've executed a
	// CreatorCoin txn. Save the previous state of the CoinEntry for easy
	// reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                           OperationTypeCreatorCoin,
		PrevCoinEntry:                  &prevCoinEntry,
		PrevTransactorBalanceEntry:     &prevTransactorBalanceEntry,
		PrevCreatorBalanceEntry:        nil,
		CreatorCoinDESOLockedNanosDiff: desoLockedNanosDiff,
	})

	// The DeSo that the user gets from selling their creator coin counts
	// as both input and output in the transaction.
	return totalInput + desoAfterFeesNanos,
		totalOutput + desoAfterFeesNanos,
		desoAfterFeesNanos, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectCreatorCoin(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCreatorCoin {
		return 0, 0, nil, fmt.Errorf("_connectCreatorCoin: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*CreatorCoinMetadataa)

	// We save the previous CoinEntry so that we can revert things easily during a
	// disconnect. If we didn't do this, it would be annoying to reset the coin
	// state when reverting a transaction.
	switch txMeta.OperationType {
	case CreatorCoinOperationTypeBuy:
		// We don't need the creatorCoinsReturned return value
		totalInput, totalOutput, _, _, utxoOps, err :=
			bav.HelpConnectCreatorCoinBuy(txn, txHash, blockHeight, verifySignatures)
		return totalInput, totalOutput, utxoOps, err

	case CreatorCoinOperationTypeSell:
		// We don't need the desoReturned return value
		totalInput, totalOutput, _, utxoOps, err :=
			bav.HelpConnectCreatorCoinSell(txn, txHash, blockHeight, verifySignatures)
		return totalInput, totalOutput, utxoOps, err

	case CreatorCoinOperationTypeAddDeSo:
		return 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Add DeSo not implemented")
	}

	return 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Unrecognized CreatorCoin "+
		"OperationType: %v", txMeta.OperationType)
}

func (bav *UtxoView) _connectCreatorCoinTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCreatorCoinTransfer {
		return 0, 0, nil, fmt.Errorf("_connectCreatorCoinTransfer: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*CreatorCoinTransferMetadataa)

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
		return 0, 0, nil, RuleErrorCreatorCoinTransferRequiresNonZeroInput
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Check that the specified receiver public key is valid.
	if len(txMeta.ReceiverPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorCreatorCoinTransferInvalidReceiverPubKeySize
	}

	// Check that the sender and receiver public keys are different.
	if reflect.DeepEqual(txn.PublicKey, txMeta.ReceiverPublicKey) {
		return 0, 0, nil, RuleErrorCreatorCoinTransferCannotTransferToSelf
	}

	// Check that the specified profile public key is valid and that a profile
	// corresponding to that public key exists.
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorCreatorCoinTransferInvalidProfilePubKeySize
	}

	// Dig up the profile. It must exist for the user to be able to transfer its coin.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTransferOnNonexistentProfile,
			"_connectCreatorCoin: Profile pub key: %v %v",
			PkToStringMainnet(txMeta.ProfilePublicKey), PkToStringTestnet(txMeta.ProfilePublicKey))
	}

	// At this point we are confident that we have a profile that
	// exists that corresponds to the profile public key the user provided.

	// Look up a BalanceEntry for the sender. If it doesn't exist then the sender implicitly
	// has a balance of zero coins, and so the transfer shouldn't be allowed.
	senderBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txn.PublicKey, existingProfileEntry.PublicKey)
	if senderBalanceEntry == nil || senderBalanceEntry.isDeleted {
		return 0, 0, nil, RuleErrorCreatorCoinTransferBalanceEntryDoesNotExist
	}

	// Check that the amount of creator coin being transferred is not less than the min threshold.
	if txMeta.CreatorCoinToTransferNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
		return 0, 0, nil, RuleErrorCreatorCoinTransferMustBeGreaterThanMinThreshold
	}

	// Check that the amount of creator coin being transferred does not exceed the user's
	// balance of this particular creator coin.
	if txMeta.CreatorCoinToTransferNanos > senderBalanceEntry.BalanceNanos {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTransferInsufficientCoins,
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
	diamondPostHashBytes, hasDiamondPostHash := txn.ExtraData[DiamondPostHashKey]
	diamondPostHash := &BlockHash{}
	diamondLevelBytes, hasDiamondLevel := txn.ExtraData[DiamondLevelKey]
	var previousDiamondPostEntry *PostEntry
	var previousDiamondEntry *DiamondEntry
	// After the DeSoDiamondsBlockHeight, we no longer accept creator coin diamonds.
	if hasDiamondPostHash && blockHeight > DeSoDiamondsBlockHeight {
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

		if !reflect.DeepEqual(txn.PublicKey, existingProfileEntry.PublicKey) {
			return 0, 0, nil, RuleErrorCreatorCoinTransferCantSendDiamondsForOtherProfiles
		}
		if reflect.DeepEqual(txMeta.ReceiverPublicKey, existingProfileEntry.PublicKey) {
			return 0, 0, nil, RuleErrorCreatorCoinTransferCantDiamondYourself
		}

		if len(diamondPostHashBytes) != HashSizeBytes {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorCreatorCoinTransferInvalidLengthForPostHashBytes,
				"_connectCreatorCoin: DiamondPostHashBytes length: %d", len(diamondPostHashBytes))
		}
		copy(diamondPostHash[:], diamondPostHashBytes[:])

		previousDiamondPostEntry = bav.GetPostEntryForPostHash(diamondPostHash)
		if previousDiamondPostEntry == nil || previousDiamondPostEntry.isDeleted {
			return 0, 0, nil, RuleErrorCreatorCoinTransferDiamondPostEntryDoesNotExist
		}

		expectedCreatorCoinNanosToTransfer, netNewDiamonds, err := bav.ValidateDiamondsAndGetNumCreatorCoinNanos(
			txn.PublicKey, txMeta.ReceiverPublicKey, diamondPostHash, diamondLevel, blockHeight)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectCreatorCoin: ")
		}

		if txMeta.CreatorCoinToTransferNanos < expectedCreatorCoinNanosToTransfer {
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
