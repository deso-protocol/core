package lib

import (
	"bytes"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"math"
	"math/big"
	"sort"
	"strings"
)

func adjustBalance(
	balance *uint256.Int, delta *big.Int) (*uint256.Int, error) {

	balanceBig := balance.ToBig()
	retBig := big.NewInt(0).Add(balanceBig, delta)
	// If we're below zero, just return zero. The caller should generally
	// prevent this from happening.
	if retBig.Cmp(big.NewInt(0)) < 0 {
		return nil, fmt.Errorf("adjustBalance: Went below zero. This should never happen.")
	}
	if retBig.Cmp(MaxUint256.ToBig()) > 0 {
		return nil, fmt.Errorf("adjustBalance: Went above max Uint256. This should never happen.")
	}
	ret, _ := uint256.FromBig(retBig)
	return ret, nil
}

// Should never go below zero. The caller should make sure of that.
func (bav *UtxoView) getAdjustedDAOCoinBalanceForUserInBaseUnits(
	userPKID *PKID, daoCoinPKID *PKID,
	balanceDeltas map[PKID]map[PKID]*big.Int) (*uint256.Int, error) {

	delta := big.NewInt(0)
	if balanceDeltas != nil {
		if innerMap, exists := balanceDeltas[*userPKID]; exists {
			if val, exists := innerMap[*daoCoinPKID]; exists {
				delta = val
			}
		}
	}

	// If it's DESO, we have to use a slightly different lookup vs if it's
	// a DAO coin.
	if *daoCoinPKID == ZeroPKID {
		userPubKey := bav.GetPublicKeyForPKID(userPKID)
		transactorDESOBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(userPubKey)
		if err != nil {
			return nil, err
		}
		return adjustBalance(
			uint256.NewInt().SetUint64(transactorDESOBalanceNanos), delta)
	}

	// If we get here, we know we're dealing with a DAO coin now.
	transactorBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(
		userPKID, daoCoinPKID, true)

	// If the balance entry doesn't exist or is deleted then return zero
	if transactorBalanceEntry == nil || transactorBalanceEntry.isDeleted {
		return adjustBalance(uint256.NewInt(), delta)
	}

	// Make a copy and return just to be safe
	ret := transactorBalanceEntry.BalanceNanos.Clone()
	return adjustBalance(ret, delta)
}

func (bav *UtxoView) balanceChange(
	userPKID *PKID, daoCoinPKID *PKID, val *big.Int,
	deltasMap map[PKID]map[PKID]*big.Int,
	prevBalances map[PKID]map[PKID]*BalanceEntry) {

	if deltasMap != nil {
		if innerMap, userExists := deltasMap[*userPKID]; userExists {
			if oldVal, daoCoinExists := innerMap[*daoCoinPKID]; daoCoinExists {
				innerMap[*daoCoinPKID] = big.NewInt(0).Add(oldVal, val)
			} else {
				innerMap[*daoCoinPKID] = val
			}
		} else {
			newMap := make(map[PKID]*big.Int)
			newMap[*daoCoinPKID] = val
			deltasMap[*userPKID] = newMap
		}
	}

	// Always save the old balance in prevBalance if we haven't
	// seen it yet. This ensures that all the modified balances
	// will be saved in our UtxoOperations when all is said and
	// done.
	if prevBalances != nil {
		if _, exists := prevBalances[*userPKID]; !exists {
			prevBalances[*userPKID] = make(map[PKID]*BalanceEntry)
		}

		// This inner if statement only executes if we do NOT have a balance in
		// this map yet.
		if _, innerExists := prevBalances[*userPKID][*daoCoinPKID]; !innerExists {
			oldBalance, err := bav.getAdjustedDAOCoinBalanceForUserInBaseUnits(
				userPKID, daoCoinPKID, nil)
			if err != nil {
				glog.Error(err)
				return
			}

			var oldBalanceEntry *BalanceEntry
			if *daoCoinPKID == ZeroPKID {
				// When we're dealing with DESO we use a dummy BalanceEntry
				// since that uses UTXOs.
				oldBalanceEntry = &BalanceEntry{
					HODLerPKID:   userPKID,
					CreatorPKID:  &ZeroPKID,
					BalanceNanos: *oldBalance.Clone(),
				}
			} else {
				oldBalanceEntry = bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(
					userPKID, daoCoinPKID, true)
				if oldBalanceEntry == nil || oldBalanceEntry.isDeleted {
					// In this case, we create a dummy balance entry, so
					// we can credit the user their money. Otherwise,
					// if a user has never owned this DAO coin, they will
					// not be able to buy it.
					oldBalanceEntry = &BalanceEntry{
						HODLerPKID:   userPKID,
						CreatorPKID:  daoCoinPKID,
						BalanceNanos: *uint256.NewInt(),
					}
				}
			}

			newMap, newMapExists := prevBalances[*userPKID]
			if !newMapExists {
				newMap = make(map[PKID]*BalanceEntry)
			}
			newMap[*daoCoinPKID] = oldBalanceEntry
			prevBalances[*userPKID] = newMap
		}
	}
}

func (bav *UtxoView) _sanityCheckLimitOrderMoneyPrinting(
	prevBalances map[PKID]map[PKID]*BalanceEntry) error {

	// We include a more hardcore balance check to make sure that we are not printing money.
	// For each item in our prevBalance map, we go through it and verify that the new balance
	// minus the previous balance sums to <= zero. First, we create a finalDeltasMap which maps a
	// coin creatorPKID to the delta in base units for that particular PKID in this transaction.
	finalDeltasMap := make(map[PKID]*big.Int)

	// Next, we loop through all the original coin base unit balances in prevBalances and
	// compute the delta between the original balance in prevBalances and the new balance
	// for that creatorPKID. Note that prevBalances is a nested map, with
	// {userPKID: {creatorPKID: *BalanceEntry}}, so we use nested loops here. We want to
	// calculate the delta for each creatorPKID across all userPKIDs in this transaction.
	for userPKID, prevBalancesPerCreatorPKID := range prevBalances {
		for creatorPKID, prevBalanceBaseUnits := range prevBalancesPerCreatorPKID {
			// Calculate new balance in base units for this userPKID, creatorPKID.
			newBalanceBaseUnits, err := bav.getAdjustedDAOCoinBalanceForUserInBaseUnits(
				&userPKID, &creatorPKID, nil)
			if err != nil {
				return errors.Wrapf(err, "_sanityCheckLimitOrderMoneyPrinting: ")
			}

			// Calculate the delta in balance base units using a big.Int.
			// delta balance = new balance - old balance
			thisDelta := big.NewInt(0).Sub(
				newBalanceBaseUnits.ToBig(), prevBalanceBaseUnits.BalanceNanos.ToBig())

			// Update the finalDeltasMap with this delta balance.
			if _, exists := finalDeltasMap[creatorPKID]; !exists {
				finalDeltasMap[creatorPKID] = thisDelta
			} else {
				finalDeltasMap[creatorPKID] = big.NewInt(0).Add(
					finalDeltasMap[creatorPKID], thisDelta)
			}
		}
	}

	// Loop through all the coin base unit deltas in finalDeltasMap and confirm that
	// they are <= 0. As long as this is the case, then we are guaranteed that
	// we did not print money.
	for creatorPKID, deltaBalanceBaseUnits := range finalDeltasMap {
		// If delta is > 0, throw an error.
		if deltaBalanceBaseUnits.Cmp(big.NewInt(0)) > 0 {
			return fmt.Errorf(
				"_connectDAOCoinLimitOrder: printing %v new coin base units for creatorPKID %v",
				deltaBalanceBaseUnits, creatorPKID)
		}
	}

	return nil
}

func (bav *UtxoView) _connectDAOCoinLimitOrder(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < bav.Params.ForkHeights.DAOCoinLimitOrderBlockHeight {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeDAOCoinLimitOrder {
		return 0, 0, nil, fmt.Errorf("_connectDAOCoinLimitOrder: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*DAOCoinLimitOrderMetadata)

	// Validate txn metadata.
	err := bav.IsValidDAOCoinLimitOrderMetadata(txn.PublicKey, txMeta)
	if err != nil {
		return 0, 0, nil, err
	}

	// Get the transactor PKID and validate it.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf(
			"_connectDAOCoinLimitOrder: transactorPKIDEntry is deleted: %v",
			spew.Sdump(transactorPKIDEntry))
	}

	// Define the prevBalances map, and initialize the balances for all public keys involved in
	// inputs and outputs of the txn. If we wait until after _connectBasicTransfer to do this,
	// then the balances will be messed up. Note that we don't really need to do this for the
	// output pubkeys, but it's just a little safer and more future-proof to grab their balances
	// now vs later.
	//
	// We save the pre-existing balances of both DESO and DAO coins as we modify
	// other bookkeeping maps. This makes it easy to sanity-check and revert things in
	// disconnect.
	prevBalances := make(map[PKID]map[PKID]*BalanceEntry)
	bav.balanceChange(transactorPKIDEntry.PKID, &ZeroPKID, big.NewInt(0), nil, prevBalances)
	for _, txOutput := range txn.TxOutputs {
		pkidEntry := bav.GetPKIDForPublicKey(txOutput.PublicKey)
		if pkidEntry == nil || pkidEntry.isDeleted {
			return 0, 0, nil, fmt.Errorf(
				"_connectDAOCoinLimitOrder: outputPKIDEntry is deleted: %v",
				spew.Sdump(pkidEntry))
		}
		bav.balanceChange(pkidEntry.PKID, &ZeroPKID, big.NewInt(0), nil, prevBalances)
	}
	// Get balances for all bidders as well.
	for _, inputsByTransactor := range txMeta.BidderInputs {
		pkidEntry := bav.GetPKIDForPublicKey(inputsByTransactor.TransactorPublicKey.ToBytes())
		if pkidEntry == nil || pkidEntry.isDeleted {
			return 0, 0, nil, fmt.Errorf(
				"_connectDAOCoinLimitOrder: bidderPKIDEntry is deleted: %v",
				spew.Sdump(pkidEntry))
		}
		bav.balanceChange(pkidEntry.PKID, &ZeroPKID, big.NewInt(0), nil, prevBalances)
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// Validate FeeNanos is a valid value, and is more than the minimum fee rate allowed
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return 0, 0, nil, err
	}
	if (txMeta.FeeNanos * 1000) <= txMeta.FeeNanos {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderFeeNanosOverflow
	}
	if (txMeta.FeeNanos*1000)/uint64(len(txnBytes)) < bav.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB ||
		txMeta.FeeNanos == 0 {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderFeeNanosBelowMinTxFee
	}

	// If the transactor just wants to cancel an
	// existing order, find and delete by OrderID.
	if txMeta.CancelOrderID != nil {
		// Connect basic txn to get the total input and the total output without
		// considering the transaction metadata.
		totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
			txn, txHash, blockHeight, verifySignatures)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectDAOCoinLimitOrder")
		}

		// Search for an existing order by OrderID.
		existingTransactorOrder, err := bav._getDAOCoinLimitOrderEntry(txMeta.CancelOrderID)
		if err != nil {
			return 0, 0, nil, err
		}
		if existingTransactorOrder == nil {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderToCancelNotFound
		}
		if !transactorPKIDEntry.PKID.Eq(existingTransactorOrder.TransactorPKID) {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderToCancelNotYours
		}

		// Save the existing order in case we need to revert.
		prevTransactorOrder := existingTransactorOrder.Copy()

		// Delete existing limit order for this transactor.
		bav._deleteDAOCoinLimitOrderEntryMappings(existingTransactorOrder)

		utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
			Type:                                 OperationTypeDAOCoinLimitOrder,
			PrevTransactorDAOCoinLimitOrderEntry: prevTransactorOrder,
		})

		return totalInput, totalOutput, utxoOpsForTxn, nil
	}

	// Extract the buyCoin and sellCoin PKIDs from the txn's public keys.
	// Note that if any of these are ZeroPublicKey, then GetPKIDForPublicKey will
	// return ZeroPKID back to us, which is what we want. Recall that ZeroPKID
	// is how we signal that we're buying/selling DESO rather than a particular
	// DAO coin.
	sellCoinPKIDEntry := bav.GetPKIDForPublicKey(txMeta.SellingDAOCoinCreatorPublicKey.ToBytes())
	if sellCoinPKIDEntry == nil || sellCoinPKIDEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf(
			"_connectDAOCoinLimitOrder: sellCoinPKIDEntry is deleted: %v",
			spew.Sdump(sellCoinPKIDEntry))
	}
	buyCoinPKIDEntry := bav.GetPKIDForPublicKey(txMeta.BuyingDAOCoinCreatorPublicKey.ToBytes())
	if buyCoinPKIDEntry == nil || buyCoinPKIDEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf(
			"_connectDAOCoinLimitOrder: buyCoinPKIDEntry is deleted: %v",
			spew.Sdump(buyCoinPKIDEntry))
	}

	// Create entry from txn metadata for the transactor.
	transactorOrder := &DAOCoinLimitOrderEntry{
		OrderID:                   txHash,
		TransactorPKID:            transactorPKIDEntry.PKID,
		BuyingDAOCoinCreatorPKID:  buyCoinPKIDEntry.PKID,
		SellingDAOCoinCreatorPKID: sellCoinPKIDEntry.PKID,
		ScaledExchangeRateCoinsToSellPerCoinToBuy: txMeta.ScaledExchangeRateCoinsToSellPerCoinToBuy,
		QuantityToFillInBaseUnits:                 txMeta.QuantityToFillInBaseUnits,
		OperationType:                             txMeta.OperationType,
		FillType:                                  txMeta.FillType,
		BlockHeight:                               blockHeight,
	}

	// These maps contain all of the balance changes that this transaction
	// demands, including DESO ones. We update these balance changes as we
	// iterate through all the
	// matching orders and adjust them. We use a bigint to store the deltas because
	// there could be negative balance changes, indicating that someone's balance
	// decreased. Once we're at the end, we're going to use these increases
	// and decreases to compute deltas that will allow us to debit and credit
	// all the right accounts. Note that a ZeroPKID corresponds to DESO.
	//
	// Note that, as we iterate, we won't modify any actual balances. We will just
	// use these maps to track everything until the very end. Note however that we
	// DO update orders as we go.
	//
	// The schema is (user PKID, dao coin PKID) -> balance change
	// Note that DESO is just dao coin PKID = ZeroPKID
	balanceDeltas := make(map[PKID]map[PKID]*big.Int)

	// Now, we find all the orders that we can match against the seller, and adjust the
	// increase and decrease maps accordingly.
	//
	// Fetch all the orders, and copy them over into a new list so that we can revert in
	// the disconnect case.
	matchingOrders, err := bav.GetNextLimitOrdersToFill(transactorOrder, nil, blockHeight)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(
			err, "Error getting next limit orders to fill: ")
	}
	prevMatchingOrders := []*DAOCoinLimitOrderEntry{}
	// We track a lastSeenOrder in order to fetch more orders to iterate over. This is
	// a bit complicated, but what can happen is that if we CANCEL a matching order
	// because the seller's balance is below what the order is offering, then we will
	// need to query the DB again for *more* matching orders. When we do this, we use
	// lastSeenOrder to mark the beginning of this iteration.
	var lastSeenOrder *DAOCoinLimitOrderEntry
	// Track all orders that get filled for notification purposes.
	//
	// TODO: This change makes it so that the "state" required to support the exchange
	// grows a lot faster. Moreover, it can be easily replaced by a hook after a
	// transaction is connected to index the appropriate fields. But we keep it as-is
	// for now.
	filledOrders := []*FilledDAOCoinLimitOrder{}
	orderFilled := false
	for len(matchingOrders) > 0 {
		// 1-by-1 match existing orders to the transactor's order.
		for _, matchingOrder := range matchingOrders {
			prevMatchingOrders = append(prevMatchingOrders, matchingOrder.Copy())
			// In what follows, we refer to the coin the transactor is trying to buy as the
			// "buy coin" and we refer to the coin the transactor is trying to sell as the
			// "sell coin." This means that the main transactor whose order we're trying to
			// fill is going to (sell sellCoin, buy buyCoin). This can get a bit confusing
			// though because the matching orders that
			// we're iterating over have the reverse. That means the other person is trying
			// to (sell buyCoin, buy sellCoin). Hang in there, though. It all makes sense
			// after you've stared at it for a bit.

			// Validate matching order. Delete from order book if invalid.
			// It was validated when stored but things could have changed
			// like the submitter's $DESO and DAO coin balances.
			//
			// TODO: As an optimization, we could offer partial fills in situations like this,
			// where we use whatever's left of the user's balance to fill the order.
			if err = bav.IsValidDAOCoinLimitOrder(matchingOrder); err != nil {
				bav._deleteDAOCoinLimitOrderEntryMappings(matchingOrder)
				continue
			}

			// Calculate leftover transactor and matching order quantities
			// as well as the number of coins exchanged.
			updatedTransactorOrderQuantityToFill,
				updatedMatchingOrderQuantityToFill,
				coinBaseUnitsBoughtByTransactor,
				coinBaseUnitsSoldByTransactor,
				err := _calculateDAOCoinsTransferredInLimitOrderMatch(
				matchingOrder, transactorOrder.OperationType, transactorOrder.QuantityToFillInBaseUnits)
			if err != nil {
				return 0, 0, nil, err
			}

			// Compute the amount of the buyCoin that the seller currently has. Factor in
			// all balance increases and decreases that we've applied.
			sellerBuyCoinBalanceBaseUnits, err := bav.getAdjustedDAOCoinBalanceForUserInBaseUnits(
				matchingOrder.TransactorPKID,
				buyCoinPKIDEntry.PKID,
				balanceDeltas)
			if err != nil {
				return 0, 0, nil, fmt.Errorf(
					"Error computing seller balance: %v", err)
			}

			// Sanity-check the order, and potentially cancel it if the matching order
			// doesn't have enough coins to give the transactor as promised.
			if sellerBuyCoinBalanceBaseUnits.Lt(coinBaseUnitsBoughtByTransactor) {
				bav._deleteDAOCoinLimitOrderEntryMappings(matchingOrder)
				continue
			}
			// If we get here, we know that the person who placed the matching order has enough
			// of a balance of the "buy coin" to cover it, even after matching all previous
			// orders.

			// Sanity-check to make sure that the transactor has enough to cover the amount that
			// they're trying to buy here.
			transactorSellCoinBalanceBaseUnits, err := bav.getAdjustedDAOCoinBalanceForUserInBaseUnits(
				transactorPKIDEntry.PKID,
				sellCoinPKIDEntry.PKID,
				balanceDeltas)
			if err != nil {
				return 0, 0, nil, fmt.Errorf(
					"Error computing transactor balance: %v", err)
			}
			if transactorSellCoinBalanceBaseUnits.Lt(coinBaseUnitsSoldByTransactor) {
				return 0, 0, nil, fmt.Errorf("Transactor "+
					"balance %v is not enough to cover the amount they are selling %v of coin PKID %v",
					transactorSellCoinBalanceBaseUnits, coinBaseUnitsSoldByTransactor,
					sellCoinPKIDEntry.PKID)
			}

			// Update quantity for transactor's order.
			transactorOrderFilledOrder := &FilledDAOCoinLimitOrder{
				OrderID:                       transactorOrder.OrderID,
				TransactorPKID:                transactorOrder.TransactorPKID,
				BuyingDAOCoinCreatorPKID:      transactorOrder.BuyingDAOCoinCreatorPKID,
				SellingDAOCoinCreatorPKID:     transactorOrder.SellingDAOCoinCreatorPKID,
				CoinQuantityInBaseUnitsBought: coinBaseUnitsBoughtByTransactor,
				CoinQuantityInBaseUnitsSold:   coinBaseUnitsSoldByTransactor,
			}
			if updatedTransactorOrderQuantityToFill.IsZero() {
				// Transactor's order was fully filled.
				transactorOrder.QuantityToFillInBaseUnits = uint256.NewInt()
				orderFilled = true
				transactorOrderFilledOrder.IsFulfilled = true
			} else {
				// Transactor's order is incomplete. Note we don't store the
				// transactor order in the db until we have finished looping
				// through all matching orders.
				transactorOrder.QuantityToFillInBaseUnits = updatedTransactorOrderQuantityToFill
				transactorOrderFilledOrder.IsFulfilled = false
			}
			filledOrders = append(filledOrders, transactorOrderFilledOrder)

			// Update quantity for matching order.
			matchingOrderFilledOrder := &FilledDAOCoinLimitOrder{
				OrderID:                       matchingOrder.OrderID,
				TransactorPKID:                matchingOrder.TransactorPKID,
				BuyingDAOCoinCreatorPKID:      matchingOrder.BuyingDAOCoinCreatorPKID,
				SellingDAOCoinCreatorPKID:     matchingOrder.SellingDAOCoinCreatorPKID,
				CoinQuantityInBaseUnitsBought: coinBaseUnitsSoldByTransactor,
				CoinQuantityInBaseUnitsSold:   coinBaseUnitsBoughtByTransactor,
			}
			matchingOrder.QuantityToFillInBaseUnits = updatedMatchingOrderQuantityToFill
			remainingUnitsToBuy, err := matchingOrder.BaseUnitsToBuyUint256()
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err,
					"Error computing BaseUnitsToBuy() on updated matching order: %v",
					matchingOrder)
			}
			remainingUnitsToSell, err := matchingOrder.BaseUnitsToSellUint256()
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err,
					"Error computing BaseUnitsToSell() on updated matching order: "+
						"Quantity: %v, ScaledExchangeRateCoinsToSellPerCoinToBuy: %v, OperationType: %v",
					matchingOrder.QuantityToFillInBaseUnits.ToBig().Text(10),
					matchingOrder.ScaledExchangeRateCoinsToSellPerCoinToBuy.ToBig().Text(10),
					matchingOrder.OperationType)
			}
			// When checking if an order was filled, we need to check both the buy side
			// and the sell side. Not doing this would result in weird edge-cases cropping
			// up whereby someone can submit a tiny order, fill part of it, and then get a
			// better deal against the next person who matches against them.
			if remainingUnitsToBuy.IsZero() || remainingUnitsToSell.IsZero() {
				// Matching order was fulfilled. Mark for deletion.
				bav._deleteDAOCoinLimitOrderEntryMappings(matchingOrder)
				matchingOrderFilledOrder.IsFulfilled = true
			} else {
				// Matching order is incomplete. Update remaining quantity to fill.
				matchingOrderFilledOrder.IsFulfilled = false

				// Set the updated matching order in the db.
				// It should replace the existing order.
				bav._setDAOCoinLimitOrderEntryMappings(matchingOrder)
			}
			filledOrders = append(filledOrders, matchingOrderFilledOrder)

			// Now adjust the balances in our maps to reflect the coins that just changed hands.
			// Transactor got buyCoins
			bav.balanceChange(transactorPKIDEntry.PKID, buyCoinPKIDEntry.PKID,
				coinBaseUnitsBoughtByTransactor.ToBig(), balanceDeltas, prevBalances)
			// Seller lost buyCoins
			bav.balanceChange(matchingOrder.TransactorPKID, buyCoinPKIDEntry.PKID,
				big.NewInt(0).Neg(coinBaseUnitsBoughtByTransactor.ToBig()),
				balanceDeltas, prevBalances)
			// Seller got sellCoins
			bav.balanceChange(matchingOrder.TransactorPKID, sellCoinPKIDEntry.PKID,
				coinBaseUnitsSoldByTransactor.ToBig(), balanceDeltas, prevBalances)
			// Transactor lost sellCoins
			bav.balanceChange(transactorPKIDEntry.PKID, sellCoinPKIDEntry.PKID,
				big.NewInt(0).Neg(coinBaseUnitsSoldByTransactor.ToBig()),
				balanceDeltas, prevBalances)

			if orderFilled {
				break
			}
		}
		if orderFilled {
			break
		}
		lastSeenOrder = prevMatchingOrders[len(prevMatchingOrders)-1]
		matchingOrders, err = bav.GetNextLimitOrdersToFill(transactorOrder, lastSeenOrder, blockHeight)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err,
				"_connectDAOCoinLimitOrder: Error getting next set of orders to fill: ")
		}
	}

	// By the time we get here, we've either fully filled the order OR we've exhausted
	// the matching orders on "the book" that this order can fill against.

	// After iterating through all potential matching orders, if transactor's order
	// is still not fully fulfilled, their quantity to fill will be > zero. What
	// we should do with the remaining quantity depends on the FillType.
	if !transactorOrder.QuantityToFillInBaseUnits.IsZero() {
		if txMeta.FillType == DAOCoinLimitOrderFillTypeFillOrKill {
			// If this is a FillOrKill order that is still unfulfilled
			// after matching with all applicable orders, then we need
			// to cancel this entire order.
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderFillOrKillOrderUnfulfilled
		} else if txMeta.FillType == DAOCoinLimitOrderFillTypeImmediateOrCancel {
			// If this is an ImmediateOrCancel order, then we should
			// do nothing with the remaining quantity of this order.
		} else if txMeta.FillType == DAOCoinLimitOrderFillTypeGoodTillCancelled {
			// If this is a GoodTilCancelled order, then we should store
			// whatever is left-over of this order in the database. This
			// is the default case.
			bav._setDAOCoinLimitOrderEntryMappings(transactorOrder)
		} else {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidFillType
		}
	}

	// Now, we need to update all the balances of all the users who were involved in
	// all of the matching that we did above. We do this via the following steps:
	//
	// 1. We aggregate all the DESO we have as input for all the accounts
	//    that the transaction included. We spend all the UTXOs as we do this
	//    so that, once we're done, it's as if we've converted all that DESO
	//    into a set of internal balances.
	// 2. Then we iterate over the deltas in our map and adjust the dao
	//    coin and the deso balances as we go. This will leave us with:
	//     - dao coin balances fully up-to-date
	//     - all of the balances in the deso map being "change" amounts
	// 3. Then we create "implicit outputs" for all the change amounts and
	//    we're done.

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectDAOCoinLimitOrder")
	}

	// This is the amount of DESO each account is allowed to spend based on the
	// UTXOs passed-in. We compute this first to know what our "budget" is for
	// each account. At the end, we will use this map to compute change amounts
	// for everyone and create "implicit outputs" using whatever is left over.
	desoAllowedToSpendByPublicKey := make(map[PublicKey]uint64)
	// Start by adding the output minus input for the transactor, since they can
	// technically spend this amount if they want. Later on, we'll make sure that
	// we're accounting for the fee as well.
	if totalInput > totalOutput {
		desoAllowedToSpendByPublicKey[*NewPublicKey(txn.PublicKey)] = totalInput - totalOutput
	} else {
		desoAllowedToSpendByPublicKey[*NewPublicKey(txn.PublicKey)] = 0
	}
	// Iterate through all the inputs and spend them. Any amount we don't use will be returned
	// as change.
	for _, transactor := range txMeta.BidderInputs {
		publicKey := *transactor.TransactorPublicKey

		// Do a noop balanceChange to save the prevBalance for this pubkey. We need this
		// prevBalance for our sanity-scheck at the end. We use ZeroPKID for DESO. Note that
		// balanceChange is smart, and only saves the prevBalance the FIRST time we call it
		// for a particular pkid.
		pkid := bav.GetPKIDForPublicKey(publicKey.ToBytes())
		bav.balanceChange(pkid.PKID, &ZeroPKID, big.NewInt(0), nil, prevBalances)

		// If no balance recorded so far, initialize to zero.
		if _, exists := desoAllowedToSpendByPublicKey[publicKey]; !exists {
			desoAllowedToSpendByPublicKey[publicKey] = 0
		}

		for _, matchingBidInput := range transactor.Inputs {
			utxoKey := UtxoKey(*matchingBidInput)
			utxoEntry := bav.GetUtxoEntryForUtxoKey(&utxoKey)
			if utxoEntry == nil || utxoEntry.isSpent {
				return 0, 0, nil, RuleErrorDAOCoinLimitOrderBidderInputNoLongerExists
			}

			// Make sure that the UTXO specified is actually from the bidder.
			if !bytes.Equal(utxoEntry.PublicKey, publicKey.ToBytes()) {
				return 0, 0, nil, RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey
			}

			// If the UTXO is from a block reward txn, make sure enough time has passed to make it spendable.
			if _isEntryImmatureBlockReward(utxoEntry, blockHeight, bav.Params) {
				return 0, 0, nil, RuleErrorInputSpendsImmatureBlockReward
			}

			desoAllowedToSpendByPublicKey[publicKey], err = SafeUint64().Add(
				desoAllowedToSpendByPublicKey[publicKey], utxoEntry.AmountNanos)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectDAOCoinLimitOrder: ")
			}

			// Make sure we spend the UTXO so that the bidder can't reuse it.
			utxoOp, err := bav._spendUtxo(&utxoKey)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(
					err, "_connectDAOCoinLimitOrder: Problem spending bidder utxo")
			}

			// Increase total input to account for inputs contributed by bidders.
			totalInput, err = SafeUint64().Add(totalInput, utxoEntry.AmountNanos)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err,
					"_connectDAOCoinLimitOrder: Adding to totalInput overflows uint64: ")
			}

			// Track the UtxoOperations so we can rollback, and for Rosetta.
			utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
		}
		// If this bidder isn't in the balance deltas map yet, then
		// we know they did not have their DESO balance changed
		// due to a matching order. Adding them to the balance
		// deltas maps with a delta of 0 ensures they receive
		// all their money back.
		if _, exists := balanceDeltas[*pkid.PKID]; !exists {
			balanceDeltas[*pkid.PKID] = make(map[PKID]*big.Int)
		}
		if _, exists := balanceDeltas[*pkid.PKID][ZeroPKID]; !exists {
			balanceDeltas[*pkid.PKID][ZeroPKID] = big.NewInt(0)
		}
	}
	// At this point, we have fully spent all of the passed-in UTXOs. Now, we are free
	// to move the DESO around according to the laws of the exchange.

	// Helpers to create UTXOs as we iterate over the balance changes for each account.
	daoCoinLimitOrderPaymentUtxoKeys := []*UtxoKey{}
	// This may start negative but that's OK because the first thing we do is increment it in createUTXO.
	nextUtxoIndex := len(txn.TxOutputs) - 1
	// Helper function to create UTXOs.
	createUTXO := func(amountNanos uint64, publicKeyArg []byte, utxoType UtxoType) (_err error) {
		publicKey := publicKeyArg

		// nextUtxoIndex is guaranteed to be >= 0 after this increment
		nextUtxoIndex += 1

		outputKey := &UtxoKey{
			TxID:  *txHash,
			Index: uint32(nextUtxoIndex),
		}

		utxoEntry := UtxoEntry{
			AmountNanos: amountNanos,
			PublicKey:   publicKey,
			BlockHeight: blockHeight,
			UtxoType:    utxoType,

			UtxoKey: outputKey,
			// We leave the position unset and isSpent to false by default.
			// The position will be set in the call to _addUtxo.
		}

		utxoOp, err := bav._addUtxo(&utxoEntry)
		if err != nil {
			return errors.Wrapf(err, "_connectDAOCoinLimitOrder: Problem adding output utxo")
		}

		daoCoinLimitOrderPaymentUtxoKeys = append(daoCoinLimitOrderPaymentUtxoKeys, outputKey)

		// Rosetta uses this UtxoOperation to provide INPUT amounts
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
		return nil
	}

	// Sanity-check: Make sure that all of the increases and
	// decreases sum to zero. If this is the case we're pretty protected
	// against any money-printer bugs. We do a second check later on that is a
	// bit redundant, but that's OK.
	balanceDeltaSanityCheckMap := make(map[PKID]*big.Int)
	for _, creatorPKIDMap := range balanceDeltas {
		for creatorPKIDIter, balanceDelta := range creatorPKIDMap {
			creatorPKID := creatorPKIDIter
			if _, exists := balanceDeltaSanityCheckMap[creatorPKID]; !exists {
				balanceDeltaSanityCheckMap[creatorPKID] = big.NewInt(0)
			}
			balanceDeltaSanityCheckMap[creatorPKID] = big.NewInt(0).Add(
				balanceDeltaSanityCheckMap[creatorPKID],
				balanceDelta,
			)
		}
	}
	for creatorPKIDIter, balanceDelta := range balanceDeltaSanityCheckMap {
		if balanceDelta.Cmp(big.NewInt(0)) != 0 {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorDAOCoinLimitOrderBalanceDeltasNonZero,
				"_connectDAOCoinLimitOrder: Balance for PKID %v is %v", creatorPKIDIter, balanceDelta.String(),
			)
		}
	}

	// prevBalances will have the previous balances for all users, mapped
	// by each coin that changed, including DESO that changed.
	//
	// Note that we need to sort the map so that iteration remains deterministic!
	// Not doing this could break our hypersync checksum.
	userPKIDs := []PKID{}
	for userPKIDIter := range balanceDeltas {
		userPKID := userPKIDIter
		userPKIDs = append(userPKIDs, userPKID)
	}
	sortedUserPKIDs := SortPKIDs(userPKIDs)
	for _, userPKIDIter := range sortedUserPKIDs {
		userPKID := userPKIDIter
		innerMap := balanceDeltas[userPKID]
		innerMapPKIDs := []PKID{}
		for innerMapPKIDIter := range innerMap {
			innerMapPKID := innerMapPKIDIter
			innerMapPKIDs = append(innerMapPKIDs, innerMapPKID)
		}
		sortedInnerMapPKIDs := SortPKIDs(innerMapPKIDs)
		for _, daoCoinPKIDIter := range sortedInnerMapPKIDs {
			daoCoinPKID := daoCoinPKIDIter
			delta := innerMap[daoCoinPKIDIter]
			if daoCoinPKID == ZeroPKID {
				// If this is DESO, add/subtract the amount to the amount
				// we're allowed to spend. Check for overflow/underflow.
				// Create a change output if there's any left over.
				pubKey := bav.GetPublicKeyForPKID(&userPKID)
				desoSurplus := desoAllowedToSpendByPublicKey[*NewPublicKey(pubKey)]
				newDESOSurplus := big.NewInt(0).Add(
					delta, big.NewInt(0).SetUint64(desoSurplus))

				// If the current delta is for the transactor, we need
				// to deduct the fees specified in the metadata from the output
				// we will create.
				if transactorPKIDEntry.PKID.Eq(&userPKID) {
					newDESOSurplus = big.NewInt(0).Sub(newDESOSurplus, big.NewInt(0).SetUint64(txMeta.FeeNanos))
				}

				// Check that we didn't overflow or underflow the DESO surplus.
				// Note that if we ever go negative then that's an error because
				// we already maxed out the DESO we're allowed to spend before
				// entering this loop.
				if newDESOSurplus.Cmp(big.NewInt(0)) < 0 {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderOverspendingDESO
				}
				if newDESOSurplus.Cmp(big.NewInt(0).SetUint64(math.MaxUint64)) > 0 {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderOverflowsDESO
				}

				// Now create an implicit output for whatever surplus remains, if any.
				if newDESOSurplus.Uint64() != 0 {
					if err = createUTXO(newDESOSurplus.Uint64(), pubKey, UtxoTypeDAOCoinLimitOrderPayout); err != nil {
						return 0, 0, nil, err
					}

					// Increase totalOutput to account for outputs generated by matching orders.
					totalOutput, err = SafeUint64().Add(totalOutput, newDESOSurplus.Uint64())
					if err != nil {
						return 0, 0, nil, errors.Wrapf(err,
							"_connectDAOCoinLimitOrder: Adding to totalOutput overflows uint64: ")
					}
				}
			} else {
				// In this case we're dealing with a DAO coin so simply
				// update the value in the DB and call it a day.
				prevBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(
					&userPKID, &daoCoinPKID, true)
				var newBalanceEntry *BalanceEntry
				// If the user doesn't have a balance entry, we need to create one.
				// If the delta is negative, this is an error since the user can't
				// spend DAO coins it doesn't have.
				if prevBalanceEntry == nil || prevBalanceEntry.isDeleted {
					if delta.Sign() < 0 {
						return 0, 0, nil, errors.Wrapf(
							RuleErrorDAOCoinLimitOrderBalanceEntryDoesNotExist,
							"_connectDAOCoinLimitOrder: BalanceEntry is nil or deleted and delta is negative: ",
						)
					}
					// We initialize a newBalance for this user.
					newBalanceEntry = &BalanceEntry{
						HODLerPKID:   &userPKID,
						CreatorPKID:  &daoCoinPKID,
						BalanceNanos: *uint256.NewInt(),
					}
				} else {
					// Otherwise, we create a copy of the previous balance entry before updating.
					newBalanceEntry = prevBalanceEntry.Copy()
				}
				newBalance := big.NewInt(0).Add(newBalanceEntry.BalanceNanos.ToBig(), delta)

				if newBalance.Cmp(big.NewInt(0)) < 0 {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderOverspendingDAOCoin
				}
				if newBalance.Cmp(MaxUint256.ToBig()) > 0 {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderOverflowsDAOCoin
				}
				// At this point we're certain that the new balance didn't underflow or
				// overflow. Set it in the db without fear.
				newBalanceUint256, _ := uint256.FromBig(newBalance)
				newBalanceEntry.BalanceNanos = *newBalanceUint256
				bav._setDAOCoinBalanceEntryMappings(newBalanceEntry)
			}
		}
	}

	if err = bav._sanityCheckLimitOrderMoneyPrinting(prevBalances); err != nil {
		return 0, 0, nil, err
	}

	// We included the transactor in the slices of the prev balance entries
	// and the prev DAO coin limit order entries. Usually we leave them in
	// a separate place, but here it makes sense.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                                 OperationTypeDAOCoinLimitOrder,
		PrevTransactorDAOCoinLimitOrderEntry: nil, // prevTransactorOrder is only used in cancelling an order.
		PrevBalanceEntries:                   prevBalances,
		PrevMatchingOrders:                   prevMatchingOrders,
		FilledDAOCoinLimitOrders:             filledOrders,
	})

	// Just to be safe, we confirm that totalOutput doesn't exceed totalInput.
	if totalInput < totalOutput {
		return 0, 0, nil, RuleErrorTxnOutputExceedsInput
	}

	// The difference between totalInput and totalOutput should be EXACTLY equal to the fee specified
	// in the transaction metadata.
	if totalInput-totalOutput != txMeta.FeeNanos {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderTotalInputMinusTotalOutputNotEqualToFee
	}

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

// GetNextLimitOrdersToFill retrieves the next set of candidate DAOCoinLimitOrderEntries
// to fulfill the quantity specified by the transactorOrder. If lastSeenOrder is specified
// we will exclude lastSeenOrder and all BETTER orders from the result set.
func (bav *UtxoView) GetNextLimitOrdersToFill(
	transactorOrder *DAOCoinLimitOrderEntry, lastSeenOrder *DAOCoinLimitOrderEntry, blockHeight uint32) (
	[]*DAOCoinLimitOrderEntry, error) {
	// Construct map of potential-matching orders in the view. We skip
	// pulling these from the db as we already have them in the view.
	// This was a breaking-change efficiency improvement, so we gate
	// by block height.
	orderEntriesInView := map[DAOCoinLimitOrderMapKey]bool{}
	if blockHeight >= bav.Params.ForkHeights.OrderBookDBFetchOptimizationBlockHeight {
		for _, orderEntry := range bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry {
			if transactorOrder.BuyingDAOCoinCreatorPKID.Eq(orderEntry.SellingDAOCoinCreatorPKID) &&
				transactorOrder.SellingDAOCoinCreatorPKID.Eq(orderEntry.BuyingDAOCoinCreatorPKID) {
				orderEntriesInView[orderEntry.ToMapKey()] = true
			}
		}
	}

	// Get matching limit order entries from database.
	matchingOrders, err := bav.GetDbAdapter().GetMatchingDAOCoinLimitOrders(transactorOrder, lastSeenOrder, orderEntriesInView)
	if err != nil {
		return nil, err
	}

	// Update UTXO with relevant limit order entries from database.
	for _, matchingOrder := range matchingOrders {
		if _, exists := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[matchingOrder.ToMapKey()]; !exists {
			bav._setDAOCoinLimitOrderEntryMappings(matchingOrder)
		}
	}

	// Aggregate all matching orders then sort.
	sortedMatchingOrders := []*DAOCoinLimitOrderEntry{}

	// Aggregate matching orders.
	for _, matchingOrder := range bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry {
		// This doesn't mean that the matching order is invalid and should be deleted.
		// It just means that the matching order isn't actually a viable match.
		err := bav.IsValidDAOCoinLimitOrderMatch(transactorOrder, matchingOrder)
		if err != nil {
			// If matching own order, fail immediately. Otherwise just skip this order.
			if err == RuleErrorDAOCoinLimitOrderMatchingOwnOrder {
				return nil, err
			}

			continue
		}

		// We should have seen this order already.
		if lastSeenOrder != nil && !lastSeenOrder.IsBetterMatchingOrderThan(matchingOrder) {
			continue
		}

		sortedMatchingOrders = append(sortedMatchingOrders, matchingOrder)
	}

	// Sort matching orders by best matching.
	// Sort logic first looks at price, then block height (FIFO), then quantity (lowest first).
	sort.Slice(sortedMatchingOrders, func(ii, jj int) bool {
		return sortedMatchingOrders[ii].IsBetterMatchingOrderThan(sortedMatchingOrders[jj])
	})

	// Pull orders up to when the quantity is filled or we run out of orders.
	outputMatchingOrders := []*DAOCoinLimitOrderEntry{}
	transactorOrderQuantityToFill := transactorOrder.QuantityToFillInBaseUnits.Clone()

	for _, matchingOrder := range sortedMatchingOrders {
		outputMatchingOrders = append(outputMatchingOrders, matchingOrder)

		// Calculate transactor's updated quantity
		// to fill after matching with this order.
		transactorOrderQuantityToFill, _, _, _, err = _calculateDAOCoinsTransferredInLimitOrderMatch(
			matchingOrder, transactorOrder.OperationType, transactorOrderQuantityToFill)
		if err != nil {
			return nil, err
		}

		// Break once the transactor's quantity to fill is zero.
		if transactorOrderQuantityToFill.IsZero() {
			break
		}
	}

	return outputMatchingOrders, nil
}

func (bav *UtxoView) _disconnectDAOCoinLimitOrder(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a DAOCoinLimitOrder operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectDAOCoinLimitOrder: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeDAOCoinLimitOrder {
		return fmt.Errorf("_disconnectDAOCoinLimitOrder: Trying to revert "+
			"OperationTypeDAOCoinLimitOrder but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*DAOCoinLimitOrderMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	transactorPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey).PKID

	if txMeta.CancelOrderID == nil {
		// Delete the order created by this txn.
		bav._deleteDAOCoinLimitOrderEntryMappings(&DAOCoinLimitOrderEntry{
			OrderID:                   txnHash,
			TransactorPKID:            transactorPKID,
			BuyingDAOCoinCreatorPKID:  bav.GetPKIDForPublicKey(txMeta.BuyingDAOCoinCreatorPublicKey.ToBytes()).PKID,
			SellingDAOCoinCreatorPKID: bav.GetPKIDForPublicKey(txMeta.SellingDAOCoinCreatorPublicKey.ToBytes()).PKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: txMeta.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			QuantityToFillInBaseUnits:                 txMeta.QuantityToFillInBaseUnits,
			BlockHeight:                               blockHeight,
		})
	} else {
		// Replace the order cancelled by this txn. Note:
		// PrevTransactorDAOCoinLimitOrderEntry is only set
		// if this transaction cancelled an existing order.
		bav._setDAOCoinLimitOrderEntryMappings(operationData.PrevTransactorDAOCoinLimitOrderEntry)
	}

	// Revert DAO Coin balance entries
	if len(operationData.PrevBalanceEntries) != 0 {
		for _, daoCoinPKIDToBalanceEntryMap := range operationData.PrevBalanceEntries {
			for _, balanceEntry := range daoCoinPKIDToBalanceEntryMap {
				bav._setDAOCoinBalanceEntryMappings(balanceEntry)
			}
		}
	}

	// Revert previous matching orders
	if len(operationData.PrevMatchingOrders) != 0 {
		for _, prevMatchingOrder := range operationData.PrevMatchingOrders {
			bav._setDAOCoinLimitOrderEntryMappings(prevMatchingOrder)
		}
	}

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

	// Un-add UTXOs for orders that paid out DESO.
	for ii := operationIndex; ii > operationIndex-numUtxoAdds+len(currentTxn.TxOutputs); ii-- {
		utxoOp := utxoOpsForTxn[ii]
		if err := bav._unAddUtxo(utxoOp.Key); err != nil {
			return errors.Wrapf(err, "_disconnectDAOCoinLimitOrder: Problem unAdding UTXO %v: ", utxoOp.Key)
		}
	}

	// Set operation index to end of implicit output utxos
	operationIndex = operationIndex - numUtxoAdds + len(currentTxn.TxOutputs)

	// We will have additional spend utxo operations for each matching order input.
	numMatchingOrderInputs := 0

	for _, transactor := range txMeta.BidderInputs {
		numMatchingOrderInputs += len(transactor.Inputs)
	}

	// Unspend utxos for matched bid transactors.
	for jj := operationIndex; jj > operationIndex-numMatchingOrderInputs; jj-- {
		utxoOp := utxoOpsForTxn[jj]
		if err := bav._unSpendUtxo(utxoOp.Entry); err != nil {
			return errors.Wrapf(err, "_disconnectDAOCoinLimitOrder: Problem unSpending UTXO %v: ", utxoOp.Entry)
		}
	}
	// Set operation index appropriately.
	operationIndex = operationIndex - numMatchingOrderInputs

	// Finally disconnect basic transfer
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _setDAOCoinLimitOrderEntryMappings(entry *DAOCoinLimitOrderEntry) {
	// This function shouldn't be called with nil.
	if entry == nil {
		glog.Errorf("_setDAOCoinLimitOrderEntryMappings: Called with nil entry; this should never happen")
		return
	}

	bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[entry.ToMapKey()] = entry
}

func (bav *UtxoView) _deleteDAOCoinLimitOrderEntryMappings(entry *DAOCoinLimitOrderEntry) {
	// This function shouldn't be called with nil.
	if entry == nil {
		glog.Errorf("_deleteDAOCoinLimitOrderEntryMappings: Called with nil entry; this should never happen")
		return
	}

	// Create a tombstone entry.
	tombstoneEntry := *entry
	tombstoneEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setDAOCoinLimitOrderEntryMappings(&tombstoneEntry)
}

func _calculateDAOCoinsTransferredInLimitOrderMatch(
	matchingOrder *DAOCoinLimitOrderEntry,
	transactorOrderOperationType DAOCoinLimitOrderOperationType,
	transactorQuantityToFillInBaseUnits *uint256.Int) (
	__updatedTransactorQuantityToFillInBaseUnits *uint256.Int,
	__updatedMatchingQuantityToFillInBaseUnits *uint256.Int,
	__transactorBuyingCoinBaseUnitsTransferred *uint256.Int,
	__transactorSellingCoinBaseUnitsTransferred *uint256.Int,
	__err error) {
	// Calculate coins transferred between two matching orders.
	// Note: we assume that the input orders are a valid match, and we validate this below.

	if transactorOrderOperationType == DAOCoinLimitOrderOperationTypeASK &&
		matchingOrder.OperationType == DAOCoinLimitOrderOperationTypeASK {
		// The transactor quantity specifies the amount of coin they want to sell.
		// The matching order's quantity specifies the amount of coin they want to sell.
		// Since the transactor is selling the coin that the matching order is buying,
		// to compare these two quantities, we need to convert the matching order's
		// quantity to the amount they would like to buy.
		matchingOrderQuantityToBuy, err := matchingOrder.BaseUnitsToBuyUint256()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		if transactorQuantityToFillInBaseUnits.Lt(matchingOrderQuantityToBuy) ||
			transactorQuantityToFillInBaseUnits.Eq(matchingOrderQuantityToBuy) {
			// The matching order fully fills the transactor's order, so there won't be anything
			// left to fill after this order is matched.
			updatedTransactorQuantityToFillInBaseUnits := uint256.NewInt()

			// The transactor quantity specifies the amount of coin they want to sell
			// and their order is fully filled. We use the matching order's exchange
			// rate and the transactor's quantity to calculate how many coins were
			// bought by the transactor.
			transactorBuyingCoinBaseUnitsTransferred, err := ComputeBaseUnitsToSellUint256(
				matchingOrder.ScaledExchangeRateCoinsToSellPerCoinToBuy,
				transactorQuantityToFillInBaseUnits)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			// If the amount we're pulling from the matching order is more than that order has
			// to give, then "snap" the value to the order's sell amount.
			if transactorBuyingCoinBaseUnitsTransferred.Cmp(matchingOrder.QuantityToFillInBaseUnits) >= 0 {
				transactorBuyingCoinBaseUnitsTransferred = matchingOrder.QuantityToFillInBaseUnits.Clone()
			}

			// We use the transactor's quantity as-is as the number
			// of coins that were sold by the transactor.
			transactorSellingCoinBaseUnitsTransferred := transactorQuantityToFillInBaseUnits

			// Compute matching order's remaining quantity to fill. The matching
			// order is an ASK order so their quantity specifies their desired
			// amount to sell. The updated matching order's quantity to fill
			// (sell) is equal to their original quantity minus the number of
			// coins that they sold i.e. the transactor bought.
			updatedMatchingQuantityToFillInBaseUnits, err := SafeUint256().Sub(
				matchingOrder.QuantityToFillInBaseUnits,
				transactorBuyingCoinBaseUnitsTransferred)
			if err != nil {
				return nil, nil, nil, nil, err
			}

			return updatedTransactorQuantityToFillInBaseUnits,
				updatedMatchingQuantityToFillInBaseUnits,
				transactorBuyingCoinBaseUnitsTransferred,
				transactorSellingCoinBaseUnitsTransferred,
				nil
		}
		// If we get here, then the transactor's order fully fills the matching order, rather
		// than the other way around.

		// There is nothing left in the matching order
		updatedMatchingQuantityToFillInBaseUnits := uint256.NewInt()

		// We calculate what is left over for the transactor's order. Note that matchingOrderQuantityToBuy
		// can't overflow because we checked it earlier.
		updatedTransactorQuantityToFillInBaseUnits, err := SafeUint256().Sub(
			transactorQuantityToFillInBaseUnits, matchingOrderQuantityToBuy)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		// The matching order is filled, so its quantity sold is equal to
		// the quantity bought by the transactor.
		transactorBuyingCoinBaseUnitsTransferred := matchingOrder.QuantityToFillInBaseUnits.Clone()

		// And its quantity to buy is equal to the quantity sold by the transactor.
		transactorSellingCoinBaseUnitsTransferred := matchingOrderQuantityToBuy

		return updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			nil
	}

	if transactorOrderOperationType == DAOCoinLimitOrderOperationTypeBID &&
		matchingOrder.OperationType == DAOCoinLimitOrderOperationTypeBID {
		// The transactor quantity specifies the amount of coin they want to buy.
		// The matching order's quantity specifies the amount of coin they want to buy.
		// Since the transactor is buying the coin that the matching order is selling,
		// to compare these two quantities, we need to convert the matching order's
		// quantity to the amount they would like to sell.
		matchingOrderQuantityToSell, err := matchingOrder.BaseUnitsToSellUint256()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		if transactorQuantityToFillInBaseUnits.Lt(matchingOrderQuantityToSell) ||
			transactorQuantityToFillInBaseUnits.Eq(matchingOrderQuantityToSell) {
			// The matching order fulfills the transactor's order.
			updatedTransactorQuantityToFillInBaseUnits := uint256.NewInt()

			// The transactor quantity specifies the amount of coin they want to buy
			// and their order is fully fulfilled.
			transactorBuyingCoinBaseUnitsTransferred := transactorQuantityToFillInBaseUnits

			transactorSellingCoinBaseUnitsTransferred, err := ComputeBaseUnitsToBuyUint256(
				matchingOrder.ScaledExchangeRateCoinsToSellPerCoinToBuy,
				transactorQuantityToFillInBaseUnits)
			if err != nil {
				return nil, nil, nil, nil, err
			}

			// Compute matching order's remaining quantity to fill. The matching
			// order is a BID order so their quantity specifies their desired
			// amount to buy. The updated matching order's quantity to fill (buy)
			// is equal to their original quantity minus the number of coins that
			// they bought i.e. the transactor sold.
			updatedMatchingQuantityToFillInBaseUnits, err := SafeUint256().Sub(
				matchingOrder.QuantityToFillInBaseUnits,
				transactorSellingCoinBaseUnitsTransferred)
			if err != nil {
				return nil, nil, nil, nil, err
			}

			return updatedTransactorQuantityToFillInBaseUnits,
				updatedMatchingQuantityToFillInBaseUnits,
				transactorBuyingCoinBaseUnitsTransferred,
				transactorSellingCoinBaseUnitsTransferred,
				nil
		}
		// If we get here, it means the transactor's order fully covers the matching order
		// in terms of quantity.

		// The matching order has no quantity left after this match.
		updatedMatchingQuantityToFillInBaseUnits := uint256.NewInt()

		// We calculate what is left over for the transactor's order.
		updatedTransactorQuantityToFillInBaseUnits, err := SafeUint256().Sub(
			transactorQuantityToFillInBaseUnits, matchingOrderQuantityToSell)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		// The matching order is fully filled so its quantity to sell is equal
		// to the quantity bought by the transactor.
		transactorBuyingCoinBaseUnitsTransferred := matchingOrderQuantityToSell

		// And its quantity bought is equal to the quantity sold by the transactor.
		transactorSellingCoinBaseUnitsTransferred := matchingOrder.QuantityToFillInBaseUnits.Clone()

		return updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			nil
	}

	// Else, the transactor and matching order have opposite operation types,
	// i.e. ASK-BID or BID-ASK, and the transactor is selling the coin that the
	// matching order is buying (or vice versa). We can compare their quantities
	// directly without conversion.
	if transactorQuantityToFillInBaseUnits.Lt(matchingOrder.QuantityToFillInBaseUnits) ||
		transactorQuantityToFillInBaseUnits.Eq(matchingOrder.QuantityToFillInBaseUnits) {
		// The matching order will fully fill the transactor's order.
		updatedTransactorQuantityToFillInBaseUnits := uint256.NewInt()

		// We calculate what is left for the matching order.
		updatedMatchingQuantityToFillInBaseUnits, err := SafeUint256().Sub(
			matchingOrder.QuantityToFillInBaseUnits, transactorQuantityToFillInBaseUnits)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		if transactorOrderOperationType == DAOCoinLimitOrderOperationTypeASK {
			// The transactor's quantity represents their selling coin.
			transactorBuyingCoinBaseUnitsTransferred, err := ComputeBaseUnitsToSellUint256(
				matchingOrder.ScaledExchangeRateCoinsToSellPerCoinToBuy,
				transactorQuantityToFillInBaseUnits)
			if err != nil {
				return nil, nil, nil, nil, err
			}

			transactorSellingCoinBaseUnitsTransferred := transactorQuantityToFillInBaseUnits

			return updatedTransactorQuantityToFillInBaseUnits,
				updatedMatchingQuantityToFillInBaseUnits,
				transactorBuyingCoinBaseUnitsTransferred,
				transactorSellingCoinBaseUnitsTransferred,
				nil
		}

		// If we get here, then we know the transactor's quantity represents their buying coin.
		transactorBuyingCoinBaseUnitsTransferred := transactorQuantityToFillInBaseUnits

		transactorSellingCoinBaseUnitsTransferred, err := ComputeBaseUnitsToBuyUint256(
			matchingOrder.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			transactorQuantityToFillInBaseUnits)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		return updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			nil
	}

	// If we get here, the transactor's order fully covers the matching order.
	updatedMatchingQuantityToFillInBaseUnits := uint256.NewInt()

	// We calculate what is left for the transactor.
	updatedTransactorQuantityToFillInBaseUnits, err := SafeUint256().Sub(
		transactorQuantityToFillInBaseUnits, matchingOrder.QuantityToFillInBaseUnits)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if matchingOrder.OperationType == DAOCoinLimitOrderOperationTypeASK {
		// The matching order's quantity represents their selling coin.
		// Which is equivalent to the transactor's buying coin.
		transactorBuyingCoinBaseUnitsTransferred := matchingOrder.QuantityToFillInBaseUnits.Clone()

		transactorSellingCoinBaseUnitsTransferred, err := matchingOrder.BaseUnitsToBuyUint256()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		return updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			nil
	}

	// Else, the matching order's quantity represents their buying coin.
	// Which is equivalent to the transactor's selling coin.
	transactorBuyingCoinBaseUnitsTransferred, err := matchingOrder.BaseUnitsToSellUint256()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	transactorSellingCoinBaseUnitsTransferred := matchingOrder.QuantityToFillInBaseUnits.Clone()

	return updatedTransactorQuantityToFillInBaseUnits,
		updatedMatchingQuantityToFillInBaseUnits,
		transactorBuyingCoinBaseUnitsTransferred,
		transactorSellingCoinBaseUnitsTransferred,
		nil
}

// ###########################
// ## API Getter Functions
// ###########################

func (bav *UtxoView) _getDAOCoinLimitOrderEntry(orderID *BlockHash) (*DAOCoinLimitOrderEntry, error) {
	// This function shouldn't be called with nil.
	if orderID == nil {
		return nil, errors.Errorf("_getDAOCoinLimitOrderEntry: Called with nil orderID; this should never happen")
	}

	// First check if we have the order entry in the UTXO view.
	mapKey := DAOCoinLimitOrderMapKey{OrderID: *orderID.NewBlockHash()}
	outputEntry, _ := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[mapKey]
	if outputEntry != nil {
		return outputEntry, nil
	}

	// If not, next check if we have the order entry in the database.
	return bav.GetDbAdapter().GetDAOCoinLimitOrder(orderID)
}

func (bav *UtxoView) _getAllDAOCoinLimitOrders() ([]*DAOCoinLimitOrderEntry, error) {
	// This function is used in testing to retrieve all open orders.
	outputEntries := []*DAOCoinLimitOrderEntry{}

	// Iterate over matching database orders and add them to the
	// UTXO view if they are not already there. This dedups orders
	// from the database + orders from the UTXO view as well.
	dbOrderEntries, err := bav.GetDbAdapter().GetAllDAOCoinLimitOrders()
	if err != nil {
		return nil, err
	}

	for _, orderEntry := range dbOrderEntries {
		orderMapKey := orderEntry.ToMapKey()

		if _, exists := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderMapKey]; !exists {
			bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderMapKey] = orderEntry
		}
	}

	// Get matching orders from the UTXO view.
	//   + orderEntry is not deleted.
	for _, orderEntry := range bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry {
		if !orderEntry.isDeleted {
			outputEntries = append(outputEntries, orderEntry)
		}
	}

	return outputEntries, nil
}

func (bav *UtxoView) GetAllDAOCoinLimitOrdersForThisDAOCoinPair(
	buyingDAOCoinCreatorPKID *PKID, sellingDAOCoinCreatorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {
	// This function is used by the API to construct all open
	// orders for the input buying and selling DAO coins.
	if buyingDAOCoinCreatorPKID == nil {
		return nil, errors.Errorf("GetAllDAOCoinLimitOrdersForThisDAOCoinPair: Called with nil buy coin PKID; this should never happen")
	}
	if sellingDAOCoinCreatorPKID == nil {
		return nil, errors.Errorf("GetAllDAOCoinLimitOrdersForThisDAOCoinPair: Called with nil sell coin PKID; this should never happen")
	}

	outputEntries := []*DAOCoinLimitOrderEntry{}

	// Iterate over matching database orders and add them to the
	// UTXO view if they are not already there. This dedups orders
	// from the database + orders from the UTXO view as well.
	dbOrderEntries, err := bav.GetDbAdapter().GetAllDAOCoinLimitOrdersForThisDAOCoinPair(
		buyingDAOCoinCreatorPKID, sellingDAOCoinCreatorPKID)
	if err != nil {
		return nil, err
	}

	for _, orderEntry := range dbOrderEntries {
		orderMapKey := orderEntry.ToMapKey()

		if _, exists := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderMapKey]; !exists {
			bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderMapKey] = orderEntry
		}
	}

	// Get matching orders from the UTXO view.
	//   + BuyingDAOCoinCreatorPKID should match.
	//   + SellingDAOCoincreatorPKID should match.
	//   + orderEntry is not deleted.
	for _, orderEntry := range bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry {
		if !orderEntry.isDeleted &&
			orderEntry.BuyingDAOCoinCreatorPKID.Eq(buyingDAOCoinCreatorPKID) &&
			orderEntry.SellingDAOCoinCreatorPKID.Eq(sellingDAOCoinCreatorPKID) {
			outputEntries = append(outputEntries, orderEntry)
		}
	}

	return outputEntries, nil
}

func (bav *UtxoView) GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {
	// This function is used by the API to construct all open orders for the input transactor.
	if transactorPKID == nil {
		return nil, errors.Errorf("GetAllDAOCoinLimitOrdersForThisTransactor: Called with nil transactor PKID; this should never happen")
	}

	outputEntries := []*DAOCoinLimitOrderEntry{}

	// Iterate over matching database orders and add them to the
	// UTXO view if they are not already there. This dedups orders
	// from the database + orders from the UTXO view as well.
	dbOrderEntries, err := bav.GetDbAdapter().GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID)
	if err != nil {
		return nil, err
	}

	for _, orderEntry := range dbOrderEntries {
		orderMapKey := orderEntry.ToMapKey()

		if _, exists := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderMapKey]; !exists {
			bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderMapKey] = orderEntry
		}
	}

	// Get matching orders from the UTXO view.
	//   + TransactorPKID should match.
	//   + orderEntry is not deleted.
	for _, orderEntry := range bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry {
		if !orderEntry.isDeleted && transactorPKID.Eq(orderEntry.TransactorPKID) {
			outputEntries = append(outputEntries, orderEntry)
		}
	}

	return outputEntries, nil
}

// ###########################
// ## VALIDATIONS
// ###########################

func (bav *UtxoView) IsValidDAOCoinLimitOrderMetadata(transactorPK []byte, metadata *DAOCoinLimitOrderMetadata) error {
	// Returns an error if the input order metadata is invalid. Otherwise returns nil.

	// Validate FeeNanos.
	if metadata.FeeNanos == 0 {
		return RuleErrorDAOCoinLimitOrderFeeNanosBelowMinTxFee
	}

	// If the transactor is just cancelling an order,
	// then the below validations do not apply.
	if metadata.CancelOrderID != nil {
		return nil
	}

	// Validate TransactorPublicKey.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPK)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorDAOCoinLimitOrderInvalidTransactorPKID
	}

	// Validate BuyingDAOCoinCreatorPublicKey.
	buyCoinPKIDEntry := bav.GetPKIDForPublicKey(metadata.BuyingDAOCoinCreatorPublicKey.ToBytes())
	if buyCoinPKIDEntry == nil || buyCoinPKIDEntry.isDeleted {
		return RuleErrorDAOCoinLimitOrderInvalidBuyingDAOCoinCreatorPKID
	}

	// Validate SellingDAOCoinCreatorPublicKey.
	sellCoinPKIDEntry := bav.GetPKIDForPublicKey(metadata.SellingDAOCoinCreatorPublicKey.ToBytes())
	if sellCoinPKIDEntry == nil || sellCoinPKIDEntry.isDeleted {
		return RuleErrorDAOCoinLimitOrderInvalidSellingDAOCoinCreatorPKID
	}

	// Construct order entry from metadata.
	order := &DAOCoinLimitOrderEntry{
		TransactorPKID:                            transactorPKIDEntry.PKID,
		BuyingDAOCoinCreatorPKID:                  buyCoinPKIDEntry.PKID,
		SellingDAOCoinCreatorPKID:                 sellCoinPKIDEntry.PKID,
		ScaledExchangeRateCoinsToSellPerCoinToBuy: metadata.ScaledExchangeRateCoinsToSellPerCoinToBuy,
		QuantityToFillInBaseUnits:                 metadata.QuantityToFillInBaseUnits,
		OperationType:                             metadata.OperationType,
		FillType:                                  metadata.FillType,
	}

	// Validate order entry.
	return bav.IsValidDAOCoinLimitOrder(order)
}

func (bav *UtxoView) IsValidDAOCoinLimitOrder(order *DAOCoinLimitOrderEntry) error {
	// Returns an error if the input order is invalid. Otherwise returns nil.

	// Validate TransactorPKID.
	if order.TransactorPKID == nil {
		// This should never happen but worth double-checking.
		return RuleErrorDAOCoinLimitOrderInvalidTransactorPKID
	}

	// Validate BuyingDAOCoinCreatorPKID.
	if order.BuyingDAOCoinCreatorPKID == nil {
		// This should never happen but worth double-checking.
		return RuleErrorDAOCoinLimitOrderInvalidBuyingDAOCoinCreatorPKID
	}

	// Validate SellingDAOCoinCreatorPKID.
	if order.SellingDAOCoinCreatorPKID == nil {
		// This should never happen but worth double-checking.
		return RuleErrorDAOCoinLimitOrderInvalidSellingDAOCoinCreatorPKID
	}

	// Validate not buying and selling the same coin.
	if order.BuyingDAOCoinCreatorPKID.Eq(order.SellingDAOCoinCreatorPKID) {
		return RuleErrorDAOCoinLimitOrderCannotBuyAndSellSameCoin
	}

	// Validate OperationType.
	if order.OperationType != DAOCoinLimitOrderOperationTypeASK &&
		order.OperationType != DAOCoinLimitOrderOperationTypeBID {
		// OperationType can't be nil but worth double-checking.
		// This check will fail if it's nil.
		return RuleErrorDAOCoinLimitOrderInvalidOperationType
	}

	// Validate FillType.
	if order.FillType != DAOCoinLimitOrderFillTypeGoodTillCancelled &&
		order.FillType != DAOCoinLimitOrderFillTypeImmediateOrCancel &&
		order.FillType != DAOCoinLimitOrderFillTypeFillOrKill {
		return RuleErrorDAOCoinLimitOrderInvalidFillType
	}

	// If buying a DAO coin, validate buy coin creator exists and has a profile.
	// Note that ZeroPKID indicates that we are buying $DESO.
	isBuyingDESO := order.BuyingDAOCoinCreatorPKID.IsZeroPKID()
	var buyCoinCreatorProfileEntry *ProfileEntry
	if !isBuyingDESO {
		buyCoinCreatorProfileEntry = bav.GetProfileEntryForPKID(order.BuyingDAOCoinCreatorPKID)
		if buyCoinCreatorProfileEntry == nil || buyCoinCreatorProfileEntry.isDeleted {
			return RuleErrorDAOCoinLimitOrderBuyingDAOCoinCreatorMissingProfile
		}
	}

	// If selling DAO coins, validate sell coin creator exists and has a profile.
	// Note that ZeroPKID indicates that we are selling $DESO.
	isSellingDESO := order.SellingDAOCoinCreatorPKID.IsZeroPKID()
	var sellCoinCreatorProfileEntry *ProfileEntry
	if !isSellingDESO {
		sellCoinCreatorProfileEntry = bav.GetProfileEntryForPKID(order.SellingDAOCoinCreatorPKID)
		if sellCoinCreatorProfileEntry == nil || sellCoinCreatorProfileEntry.isDeleted {
			return RuleErrorDAOCoinLimitOrderSellingDAOCoinCreatorMissingProfile
		}
	}

	// Validate exchange rate.
	if order.ScaledExchangeRateCoinsToSellPerCoinToBuy == nil {
		// This should never happen.
		return RuleErrorDAOCoinLimitOrderInvalidExchangeRate
	}

	// For non-market orders, the exchange rate must be > 0.
	// For market orders, the exchange rate can be 0.
	if !order.IsMarketOrder() && order.ScaledExchangeRateCoinsToSellPerCoinToBuy.IsZero() {
		return RuleErrorDAOCoinLimitOrderInvalidExchangeRate
	}

	// Validate quantity > 0.
	if order.QuantityToFillInBaseUnits == nil ||
		order.QuantityToFillInBaseUnits.IsZero() {
		// QuantityToFillInBaseUnits can't be nil but worth double-checking.
		return RuleErrorDAOCoinLimitOrderInvalidQuantity
	}

	// The following validations only apply for non-market orders. For market orders,
	// we don't know at this point what the exchange rate and thus the selling quantity
	// for the transactor will be, so we can't know if the transactor has sufficient
	// coins to cover their selling amount here. This is validated later, once
	// the transactor's order is matched with matching orders. But in the
	// market-order case, we skip the following validations below.
	if order.IsMarketOrder() {
		return nil
	}
	// If we get here, we assume we are dealing with a non-market order.

	// Validate quantity to buy > 0.
	baseUnitsToBuy, err := order.BaseUnitsToBuyUint256()
	if err != nil {
		return err
	}
	if baseUnitsToBuy.Eq(uint256.NewInt()) {
		return errors.Wrapf(RuleErrorDAOCoinLimitOrderTotalCostIsLessThanOneNano, "baseUnitsToBuy: ")
	}
	// If buying $DESO, validate that qty to buy is less than the max uint64.
	if isBuyingDESO && !baseUnitsToBuy.IsUint64() {
		return RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint64
	}

	// Calculate order total amount to sell from price and quantity.
	baseUnitsToSell, err := order.BaseUnitsToSellUint256()
	if err != nil {
		return err
	}
	if baseUnitsToSell.Eq(uint256.NewInt()) {
		return errors.Wrapf(RuleErrorDAOCoinLimitOrderTotalCostIsLessThanOneNano, "baseUnitsToSell: ")
	}

	// If selling $DESO, validate that order total cost is less than the max uint64.
	if isSellingDESO && !baseUnitsToSell.IsUint64() {
		return RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint64
	}

	// If selling $DESO, make sure the transactor has enough $DESO to execute the txn.
	// If selling DAO coins, make sure the transactor has enough DAO coins to execute the txn.
	transactorBalanceBaseUnits, err := bav.getAdjustedDAOCoinBalanceForUserInBaseUnits(
		order.TransactorPKID, order.SellingDAOCoinCreatorPKID, nil)
	if err != nil {
		return err
	}

	if transactorBalanceBaseUnits.Lt(baseUnitsToSell) {
		if isSellingDESO {
			err = RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenOrder
		} else {
			err = RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenOrder
		}

		return errors.Wrapf(
			err,
			"transactorBalance amount: %v, for coin pkid (zero = DESO) %v, baseUnitsToSell: %v",
			transactorBalanceBaseUnits.Hex(),
			PkToStringMainnet(order.SellingDAOCoinCreatorPKID.ToBytes()),
			baseUnitsToSell.Hex())
	}

	return nil
}

func (order *DAOCoinLimitOrderEntry) IsValidMatchingOrderPrice(matchingOrder *DAOCoinLimitOrderEntry) bool {
	// If the transactor order is a market order then the transactor is
	// willing to accept any price, so we should always return true here.
	// The matching orders are sorted elsewhere by best-price first, so the
	// transactor is guaranteed that they are getting the best price available
	// in the order book for the specified buying + selling coin pair.
	if order.IsMarketOrder() {
		return true
	}

	// Return false if the price on the order exceeds the value we're looking for. We have
	// a special formula that allows us to do this without overflowing and without
	// losing precision. It looks like this:
	// - Want: 1 / exchangeRatePassed >= exchangeRateFound
	// -> exchangeRateFound * exchangeRatePassed >= 1
	//
	// Because of the quirks of the fixed-point format we're using, this formula actually
	// becomes:
	// - Start:
	//   * exchangeRateFound = scaledExchangeRateFound / OneE38
	//   * exchangeRatePassed = scaledExchangeRatePassed / OneE38
	// -> exchangeRateFound * exchangeRatePassed >= OneE38 * OneE38
	exchangeRateProduct := big.NewInt(0).Mul(
		order.ScaledExchangeRateCoinsToSellPerCoinToBuy.ToBig(),
		matchingOrder.ScaledExchangeRateCoinsToSellPerCoinToBuy.ToBig())
	rightHandSide := big.NewInt(0).Mul(
		OneE38.ToBig(),
		OneE38.ToBig())
	if exchangeRateProduct.Cmp(rightHandSide) < 0 {
		return false
	}
	return true
}

func (bav *UtxoView) IsValidDAOCoinLimitOrderMatch(
	transactorOrder *DAOCoinLimitOrderEntry, matchingOrder *DAOCoinLimitOrderEntry) error {
	// Returns an error if the input order is invalid. Otherwise returns nil.

	// Validate matching order exists.
	if matchingOrder.isDeleted {
		return RuleErrorDAOCoinLimitOrderMatchingOrderIsDeleted
	}

	// Validate transactor order buying coin == matching order selling coin and vice versa.
	if !transactorOrder.BuyingDAOCoinCreatorPKID.Eq(matchingOrder.SellingDAOCoinCreatorPKID) {
		return RuleErrorDAOCoinLimitOrderMatchingOrderSellingDifferentCoins
	}

	if !transactorOrder.SellingDAOCoinCreatorPKID.Eq(matchingOrder.BuyingDAOCoinCreatorPKID) {
		return RuleErrorDAOCoinLimitOrderMatchingOrderBuyingDifferentCoins
	}

	// Validate price.
	if !transactorOrder.IsValidMatchingOrderPrice(matchingOrder) {
		return RuleErrorDAOCoinLimitOrderInvalidExchangeRate
	}

	// Validate DAO coin transfer restriction status, i.e. if the
	// DAO coin can only be transferred to whitelisted members.
	transactorPublicKey := bav.GetPublicKeyForPKID(transactorOrder.TransactorPKID)
	matchingOrderTransactorPublicKey := bav.GetPublicKeyForPKID(matchingOrder.TransactorPKID)

	if !transactorOrder.BuyingDAOCoinCreatorPKID.IsZeroPKID() {
		// The matching order is selling DAO coin(s) to the transactor.
		buyCoinCreatorProfileEntry := bav.GetProfileEntryForPKID(transactorOrder.BuyingDAOCoinCreatorPKID)

		if buyCoinCreatorProfileEntry == nil || buyCoinCreatorProfileEntry.isDeleted {
			return RuleErrorDAOCoinLimitOrderBuyingDAOCoinCreatorMissingProfile
		}

		err := bav.IsValidDAOCoinTransfer(
			buyCoinCreatorProfileEntry, matchingOrderTransactorPublicKey, transactorPublicKey)

		if err != nil {
			return err
		}
	}

	if !transactorOrder.SellingDAOCoinCreatorPKID.IsZeroPKID() {
		// The transactor is selling DAO coin(s) to the matching order.
		sellCoinCreatorProfileEntry := bav.GetProfileEntryForPKID(transactorOrder.SellingDAOCoinCreatorPKID)

		if sellCoinCreatorProfileEntry == nil || sellCoinCreatorProfileEntry.isDeleted {
			return RuleErrorDAOCoinLimitOrderBuyingDAOCoinCreatorMissingProfile
		}

		err := bav.IsValidDAOCoinTransfer(
			sellCoinCreatorProfileEntry, transactorPublicKey, matchingOrderTransactorPublicKey)

		if err != nil {
			return err
		}
	}

	// Validate transactor != matching order transactor. This should be the last validation we do
	// as it's a failing validation whereas the other validations are just skipping validations,
	// and we only want to fail if the matching order is valid and would have otherwise matched.
	if transactorOrder.TransactorPKID.Eq(matchingOrder.TransactorPKID) {
		return RuleErrorDAOCoinLimitOrderMatchingOwnOrder
	}

	return nil
}

func CalculateScaledExchangeRateFromString(priceStr string) (*uint256.Int, error) {
	return ScaleFloatFormatStringToUint256(priceStr, OneE38)
}

func CalculateScaledExchangeRate(price float64) (*uint256.Int, error) {
	return CalculateScaledExchangeRateFromString(fmt.Sprintf("%v", price))
}

// ScaleFloatFormatStringToUint256 The most accurate way we've found to convert a decimal into a
// "scaled" value is to parse a string representation into a "whole" bigint
// and a "decimal" bigint. Once we have these two pieces of the number, we
// can scale the value without losing any precision.
//
// In contrast, note that performing these operations on a big.Float results
// in an immediate loss of precision.
func ScaleFloatFormatStringToUint256(floatStr string, scaleFactor *uint256.Int) (*uint256.Int, error) {
	vals := strings.Split(floatStr, ".")
	if len(vals) == 0 {
		vals = []string{"0", "0"}
	}
	// In this case, we had a whole number like 123, with no decimal
	// so we add a "0" as the decimal.
	if len(vals) != 2 {
		vals = append(vals, "0")
	}
	// This can happen if we have something like ".123"
	if vals[0] == "" {
		vals[0] = "0"
	}
	// This can happen if we have something like "123."
	if vals[1] == "" {
		vals[1] = "0"
	}

	// The first value is the integer part, the second value is the
	// decimal part. We multiply both by 1e38 and add
	wholePart, worked := big.NewInt(0).SetString(vals[0], 10)
	if !worked {
		return nil, fmt.Errorf("Failed to convert whole part %v to bigint for float string %v", wholePart, floatStr)
	}
	decimalPartStr := vals[1]
	numDecimals := len(scaleFactor.ToBig().String()) - 1
	decimalExponent := numDecimals - len(decimalPartStr)
	if decimalExponent < 0 {
		// If the decimal portion is too large then truncate it
		decimalExponent = 0
		decimalPartStr = decimalPartStr[:numDecimals]
	}
	decimalPart, worked := big.NewInt(0).SetString(decimalPartStr, 10)
	if !worked {
		return nil, fmt.Errorf("Failed to convert decimal part %v to bigint for float string %v", decimalPartStr, floatStr)
	}
	newWholePart := big.NewInt(0).Mul(wholePart, scaleFactor.ToBig())
	newDecimalPart := big.NewInt(0).Mul(decimalPart, big.NewInt(0).Exp(
		big.NewInt(0).SetUint64(10), big.NewInt(0).SetUint64(uint64(decimalExponent)), nil))

	sumBig := big.NewInt(0).Add(newWholePart, newDecimalPart)
	ret, overflow := uint256.FromBig(sumBig)
	if overflow {
		return nil, fmt.Errorf(
			"Sum of whole part %v and decimal part %v overflows with value %v for float string %v",
			wholePart,
			decimalPart,
			sumBig,
			floatStr,
		)
	}

	return ret, nil
}
