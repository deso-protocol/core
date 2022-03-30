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

	{
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
	{
		if _, exists := prevBalances[*userPKID]; !exists {
			if _, exists := prevBalances[*userPKID][*daoCoinPKID]; !exists {
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
						BalanceNanos: *oldBalance,
					}
				} else {
					oldBalanceEntry = bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(
						userPKID, daoCoinPKID, true)
				}

				newMap := make(map[PKID]*BalanceEntry)
				newMap[*daoCoinPKID] = oldBalanceEntry
				prevBalances[*userPKID] = newMap
			}
		}
	}
}

func (bav *UtxoView) _connectDAOCoinLimitOrder(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	// ----- BOILER-PLATE VALIDATIONS

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeDAOCoinLimitOrder {
		return 0, 0, nil, fmt.Errorf("_connectDAOCoinLimitOrder: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}

	txMeta := txn.TxnMeta.(*DAOCoinLimitOrderMetadata)

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)

	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectDAOCoinLimitOrder")
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
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
	transactorPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf(
			"_connectDAOCoinLimitOrder: transactorPKIDEntry is deleted: %v",
			spew.Sdump(transactorPKIDEntry))
	}

	// Create entry from txn metadata for the transactor.
	transactorOrder := &DAOCoinLimitOrderEntry{
		TransactorPKID:                            transactorPKIDEntry.PKID,
		BuyingDAOCoinCreatorPKID:                  buyCoinPKIDEntry.PKID,
		SellingDAOCoinCreatorPKID:                 sellCoinPKIDEntry.PKID,
		ScaledExchangeRateCoinsToSellPerCoinToBuy: txMeta.ScaledExchangeRateCoinsToSellPerCoinToBuy,
		QuantityToBuyInBaseUnits:                  txMeta.QuantityToBuyInBaseUnits,
		BlockHeight:                               blockHeight,
	}

	// Validate transactor order.
	err = bav.IsValidDAOCoinLimitOrder(transactorOrder)
	if err != nil {
		return 0, 0, nil, err
	}

	// Get all existing limit orders:
	//   + For this transactor PKID
	//   + For this buying DAO coin PKID
	//   + For this selling DAO coin PKID
	//   + For this price
	//   - Any block height
	existingTransactorOrderss, err :=
		bav._getAllDAOCoinLimitOrderEntriesForThisTransactorAtThisPrice(transactorOrder)
	if err != nil {
		return 0, 0, nil, err
	}

	// If the transactor just wants to cancel an existing order(s),
	// cancel all that match the input order across any block height.
	if txMeta.CancelExistingOrder {
		if len(existingTransactorOrderss) == 0 {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderToCancelNotFound
		}

		prevMatchingOrders := []*DAOCoinLimitOrderEntry{}

		// Delete all existing limit orders for this trans
		for _, existingTransactorOrder := range existingTransactorOrderss {
			prevMatchingOrders = append(prevMatchingOrders, existingTransactorOrder)
			bav._deleteDAOCoinLimitOrderEntryMappings(existingTransactorOrder)
		}

		utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
			Type:                                 OperationTypeDAOCoinLimitOrder,
			PrevTransactorDAOCoinLimitOrderEntry: nil,
			PrevBalanceEntries:                   nil,
			PrevMatchingOrders:                   prevMatchingOrders,
			SpentUtxoEntries:                     nil,
		})

		return totalInput, totalOutput, utxoOpsForTxn, nil
	}

	// See if we have an existing limit order at this price and in this block
	// and set up a variable for it if we do. Save the previous version in case
	// we need to disconnect. We do this because we don't want to create a
	// fresh order if one already exists. Rather, in this case we'll just
	// modify the existing order.
	var prevTransactorOrder *DAOCoinLimitOrderEntry

	for _, existingTransactorOrder := range existingTransactorOrderss {
		// The existing transactor orders are across any block height.
		// We would only want to update a order if it occurs at the
		// current block height. Otherwise, we would be messing up
		// the FIFO ordering of the older order being deleted instead
		// of resolved first.
		if existingTransactorOrder.BlockHeight == blockHeight {
			prevTransactorOrder, err = existingTransactorOrder.Copy()
			if err != nil {
				return 0, 0, nil, errors.Wrapf(
					err, "Error copying order entry to generate prev order: %v",
					spew.Sdump(existingTransactorOrderss))
			}
		}
	}

	// Check to see if we have an existing order. If we do, then update our
	// transactor order and delete the old one.
	if prevTransactorOrder != nil {
		// Mark old order for deletion. Note that this order is saved as the
		// only element in the prevDAOCoinLimitOrders list by the time we get
		// here.
		bav._deleteDAOCoinLimitOrderEntryMappings(prevTransactorOrder)

		// Update quantity to add that of the previous order at this level.
		transactorOrder.QuantityToBuyInBaseUnits, err = SafeUint256().Add(
			transactorOrder.QuantityToBuyInBaseUnits,
			prevTransactorOrder.QuantityToBuyInBaseUnits)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "Error updating order quantity: ")
		}
	}

	// These maps contains all of the balance changes that this transaction
	// demands, including DESO ones. We update these balance changes as we
	// iterate through all the
	// matching orders and adjust them. Because we're using uint256 to store balances,
	// we use two maps: One to store balance increases and one to store balance
	// decreases. Once we're at the end, we're going to use these increases
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
	// We also save the pre-existing balances of both DESO and DAO coins as we modify
	// the above maps. This makes it easy to sanity-check and revert things in
	// disconnect.
	prevBalances := make(map[PKID]map[PKID]*BalanceEntry)

	// Now, we find all the orders that we can match against the seller, and adjust the
	// increase and decrease maps accordingly.
	//
	// FIXME: In pathalogical cases, this could return a lot of orders, allowing someone to
	// DOS the chain by placing a lot of orders and then filling really teeny ones.
	// Maybe instead what we want is to fetch one order at a time from the db and
	// call this single-order-fetcher in a loop with lastSeenOrder until it returns nothing
	// OR until we fill our order.
	//
	// Fetch all the orders, and copy them over into a new list so that we can revert in
	// the disconnect case.
	prevMatchingOrders, err := bav._getNextLimitOrdersToFill(transactorOrder, nil)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(
			err, "Error getting next limit orders to fill: ")
	}

	// Track all orders that get filled for notification purposes.
	fulfilledOrders := []*FulfilledDAOCoinLimitOrder{}

	matchingOrders := []*DAOCoinLimitOrderEntry{}
	for _, matchingOrder := range prevMatchingOrders {
		orderCopy, err := matchingOrder.Copy()
		if err != nil {
			return 0, 0, nil, errors.Wrapf(
				err, "Error copying order %v", spew.Sdump(matchingOrder))
		}
		matchingOrders = append(matchingOrders, orderCopy)
	}
	// 1-by-1 match existing orders to the transactor's order.
	orderFilled := false
	for _, matchingOrder := range matchingOrders {
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
		err := bav.IsValidDAOCoinLimitOrder(matchingOrder)
		if err != nil {
			bav._deleteDAOCoinLimitOrderEntryMappings(matchingOrder)
			continue
		}

		// This is the total amount of sellCoin the current order is willing to sell. Note that
		// the asset the matching order is SELLING is the same asset that the
		// transactor's order is BUYING.
		matchingOrderTotalBuyCoinToSell, err := matchingOrder.BaseUnitsToSellUint256()
		if err != nil {
			return 0, 0, nil, err
		}

		// Compute the amount of the asset that the seller currently has. Factor in
		// all balance increases and decreases that we've applied.
		sellerBuyCoinBalanceBaseUnits, err := bav.getAdjustedDAOCoinBalanceForUserInBaseUnits(
			matchingOrder.TransactorPKID,
			buyCoinPKIDEntry.PKID,
			balanceDeltas)
		if err != nil {
			return 0, 0, nil, fmt.Errorf(
				"Error computing seller balance: %v", err)
		}

		// Sanity-check the order, and potentially cancel it if the user
		// doesn't have the proper balance.
		if sellerBuyCoinBalanceBaseUnits.Lt(matchingOrderTotalBuyCoinToSell) {
			bav._deleteDAOCoinLimitOrderEntryMappings(matchingOrder)
			continue
		}
		// If we get here, we know that the person who placed the matching order has enough
		// of a balance of the "sell coin" to cover it, even after matching all previous
		// orders.

		// Now we have two cases. If the order has *MORE* buyCoin for us than what we
		// want, we update the matching order and break. Otherwise, we delete the
		// matching order and continue matching.
		var buyCoinBaseUnitsBought *uint256.Int
		var sellCoinBaseUnitsSold *uint256.Int
		if transactorOrder.QuantityToBuyInBaseUnits.Lt(matchingOrderTotalBuyCoinToSell) {
			// Since the transactor order's quantity is less than the amount the matching
			// order is willing to sell, we buy just the transactor order's quantity.
			buyCoinBaseUnitsBought = transactorOrder.QuantityToBuyInBaseUnits

			// The transactor is going (sell A, buy B) whereas the matching order is doing
			// (sell B, buy A). Thus to convert daoCoinBaseUnitsBought into
			// matchingOrder.QuantityToBuyInBaseUnits, we need to do the following (note that
			// we use an underscore to denote the UNITS of each value:
			// - daoCoinBaseUnitsBought_B / matchingOrderExhangeRate_BPerA = daoCoinBaseUnitsToDeductFromOrder_A
			//
			// Now, in order to keep everything kosher with regard to the UQ128x128 format we're using,
			// we have to "scale up" the daoCoinBaseUnitsBought_B before dividing.
			sellCoinBaseUnitsSoldBig := big.NewInt(0).Div(big.NewInt(0).Mul(
				buyCoinBaseUnitsBought.ToBig(), OneUQ128x128.ToBig()),
				matchingOrder.ScaledExchangeRateCoinsToSellPerCoinToBuy.ToBig())
			// The number of coins sold shouldn't exceed a uint256
			if sellCoinBaseUnitsSoldBig.Cmp(MaxUint256.ToBig()) > 0 {
				return 0, 0, nil, errors.Wrapf(
					RuleErrorDAOCoinLimitOrderMatchingCostOverflowsUint256, "sellCoinBaseUnitsSold: %v",
					sellCoinBaseUnitsSoldBig)
			}
			// Convert to uint256
			sellCoinBaseUnitsSold, _ = uint256.FromBig(sellCoinBaseUnitsSoldBig)
			// Ensure the number of coins we're selling is non-zero. This prevents an edge case
			// whereby someone can put in teeny orders and drain the seller's order without
			// actually having to transfer anything.
			if sellCoinBaseUnitsSold.IsZero() && !matchingOrder.QuantityToBuyInBaseUnits.IsZero() {
				sellCoinBaseUnitsSold, _ = uint256.FromBig(bigOneInt)
			}

			// Sanity-check that this amount is always less than the matching order's quantity
			// to buy.
			if sellCoinBaseUnitsSold.Cmp(matchingOrder.QuantityToBuyInBaseUnits) > 0 {
				return 0, 0, nil, fmt.Errorf(
					"Sanity-check failed. sellCoinBaseUnitsSold %v is "+
						"more than matchingOrder.QuantityToBuyInBaseUnits %v", sellCoinBaseUnitsSold,
					matchingOrder.QuantityToBuyInBaseUnits)

			}

			originalQuantityToBuyInBaseUnits := matchingOrder.QuantityToBuyInBaseUnits

			// Update matching order's quantity by deducting the number of dao coins
			// sold from the order quantity.
			matchingOrder.QuantityToBuyInBaseUnits, err = SafeUint256().Sub(
				originalQuantityToBuyInBaseUnits, sellCoinBaseUnitsSold)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "Error updating order quantity: ")
			}

			// Append a DAOCoinLimitOrderEntry to the slice of filled orders representing the
			// amount purchased by the matching order.
			fulfilledOrders = append(fulfilledOrders, &FulfilledDAOCoinLimitOrder{
				TransactorPKID:                 matchingOrder.TransactorPKID,
				BuyingDAOCoinCreatorPKID:       matchingOrder.BuyingDAOCoinCreatorPKID,
				SellingDAOCoinCreatorPKID:      matchingOrder.SellingDAOCoinCreatorPKID,
				BuyingDAOCoinQuantityPurchased: sellCoinBaseUnitsSold,
				BuyingDAOCoinQuantityRequested: originalQuantityToBuyInBaseUnits,
				SellingDAOCoinQuantitySold:     buyCoinBaseUnitsBought,
			})

			// Set the updated order in the db. It should replace the existing order.
			bav._setDAOCoinLimitOrderEntryMappings(matchingOrder)

			transactorOriginalQuantityToBuyInBaseUnits := transactorOrder.QuantityToBuyInBaseUnits
			// Decrement the transactor's order and sanity-check that its new value is zero.
			transactorOrder.QuantityToBuyInBaseUnits, err = SafeUint256().Sub(
				transactorOriginalQuantityToBuyInBaseUnits, buyCoinBaseUnitsBought)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "Error updating order quantity: ")
			}

			if !transactorOrder.QuantityToBuyInBaseUnits.IsZero() {
				return 0, 0, nil, fmt.Errorf(
					"Sanity-check failed. transactorOrder.QuantityToBuyInBaseUnits %v is "+
						"not zero. This should never happen %v",
					transactorOrder.QuantityToBuyInBaseUnits, buyCoinBaseUnitsBought)
			}

			// Append a DAOCoinLimitOrderEntry to the slice of filled orders representing the
			// amount purchased by the transactor.
			fulfilledOrders = append(fulfilledOrders, &FulfilledDAOCoinLimitOrder{
				TransactorPKID:                 transactorPKIDEntry.PKID,
				BuyingDAOCoinCreatorPKID:       buyCoinPKIDEntry.PKID,
				SellingDAOCoinCreatorPKID:      sellCoinPKIDEntry.PKID,
				BuyingDAOCoinQuantityPurchased: buyCoinBaseUnitsBought,
				BuyingDAOCoinQuantityRequested: transactorOriginalQuantityToBuyInBaseUnits,
				SellingDAOCoinQuantitySold:     sellCoinBaseUnitsSold,
			})

			// If we're here it means we fully covered the transactor's order
			// so we're done
			orderFilled = true
		} else {
			// Since the transactor's order's quantity is greater than or equal to the matching
			// order's quantity, we transfer the matching order's quantity. This case is a lot
			// easier because we don't need to do much interpolation.
			//
			// Remember that the transactor order is doing (sell A, buy B) while the matching order
			// is doing (sell B, buy A). That means that the number of B units being BOUGHT is
			// actually the number of B units that the matching order is SELLING.
			buyCoinBaseUnitsBought = matchingOrderTotalBuyCoinToSell

			transactorOriginalQuanityToBuyInBaseUnits := transactorOrder.QuantityToBuyInBaseUnits
			// Update transactor order's quantity.
			transactorOrder.QuantityToBuyInBaseUnits, err = SafeUint256().Sub(
				transactorOriginalQuanityToBuyInBaseUnits, matchingOrderTotalBuyCoinToSell)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "Error updating order quantity: ")
			}

			// Save the quantity of the matching order. This is the number of coins
			// the transactor is selling.
			sellCoinBaseUnitsSold = matchingOrder.QuantityToBuyInBaseUnits

			// Mark matching order for deletion.
			bav._deleteDAOCoinLimitOrderEntryMappings(matchingOrder)

			// Append a DAOCoinLimitOrderEntry to the slice of filled orders representing the
			// amount purchased by the matching order.
			fulfilledOrders = append(fulfilledOrders, &FulfilledDAOCoinLimitOrder{
				TransactorPKID:                 matchingOrder.TransactorPKID,
				BuyingDAOCoinCreatorPKID:       matchingOrder.BuyingDAOCoinCreatorPKID,
				SellingDAOCoinCreatorPKID:      matchingOrder.SellingDAOCoinCreatorPKID,
				BuyingDAOCoinQuantityPurchased: sellCoinBaseUnitsSold,
				// We filled the whole order so BuyingCoinQuantityPurchased = BuyingCoinQuantityRequested
				BuyingDAOCoinQuantityRequested: sellCoinBaseUnitsSold,
				SellingDAOCoinQuantitySold:     buyCoinBaseUnitsBought,
			})

			// Append a DAOCoinLimitOrderEntry to the slice of filled orders representing the
			// amount purchased by the transactor.
			fulfilledOrders = append(fulfilledOrders, &FulfilledDAOCoinLimitOrder{
				TransactorPKID:                 transactorPKIDEntry.PKID,
				BuyingDAOCoinCreatorPKID:       buyCoinPKIDEntry.PKID,
				SellingDAOCoinCreatorPKID:      sellCoinPKIDEntry.PKID,
				BuyingDAOCoinQuantityPurchased: buyCoinBaseUnitsBought,
				BuyingDAOCoinQuantityRequested: transactorOriginalQuanityToBuyInBaseUnits,
				SellingDAOCoinQuantitySold:     sellCoinBaseUnitsSold,
			})
			// In the case where the transactor and matching order's quantities were
			// equal to each other, mark transactor's order as complete so that this
			// is our last iteration of this loop.
			if transactorOrder.QuantityToBuyInBaseUnits.IsZero() {
				orderFilled = true
			}
		}

		// Now adjust the balances in our maps to reflect the coins that just changed hands.
		// Transactor got buyCoins
		bav.balanceChange(transactorPKIDEntry.PKID, buyCoinPKIDEntry.PKID,
			buyCoinBaseUnitsBought.ToBig(), balanceDeltas, prevBalances)
		// Seller lost buyCoins
		bav.balanceChange(matchingOrder.TransactorPKID, buyCoinPKIDEntry.PKID,
			big.NewInt(0).Neg(buyCoinBaseUnitsBought.ToBig()),
			balanceDeltas, prevBalances)
		// Seller got sellCoins
		bav.balanceChange(matchingOrder.TransactorPKID, sellCoinPKIDEntry.PKID,
			sellCoinBaseUnitsSold.ToBig(), balanceDeltas, prevBalances)
		// Transactor lost sellCoins
		bav.balanceChange(transactorPKIDEntry.PKID, sellCoinPKIDEntry.PKID,
			big.NewInt(0).Neg(sellCoinBaseUnitsSold.ToBig()),
			balanceDeltas, prevBalances)

		if orderFilled {
			break
		}
	}
	// By the time we get here, we've either fully filled the order OR we've exhausted
	// the matching orders on "the book" that this order can fill against.

	// After iterating through all potential matching orders, if transactor's order
	// is still not fully fulfilled, submit it to be stored.
	if !transactorOrder.QuantityToBuyInBaseUnits.IsZero() {
		bav._setDAOCoinLimitOrderEntryMappings(transactorOrder)
	}

	// Now, we need to update all the balanced of all the users who were involved in
	// all of the matching that we did above. We do this via the following steps:
	//
	// 1. We aggregate all the DESO we have as input for all the accounts
	//    that the transaction included. We spend all the UTXOs as we do this
	//    so that, once we're done, it's as if we've converted all that DESO
	//    into a set of internal balances.
	// 2. Then we iterate over the increases+decreases maps and adjust the dao
	//    coin and the deso balances as we go. This will leave us with:
	//     - dao coin balances fully up-to-date
	//     - all of the balances in the deso map being "change" amounts
	// 3. Then we create "implicit outputs" for all the change amounts and
	//    we're done.

	// This is the amount of DESO each account is allowed to spend based on the
	// UTXOs passed-in. We compute this first to know what our "budget" is for
	// each account. At the end, we will use this map to compute change amounts
	// for everyone and create "implicit outputs" using whatever is left over.
	desoAllowedToSpendByPublicKey := make(map[PublicKey]uint64)
	// Start by adding the output minus input for the transactor, since they can
	// technically spend this amount if they want (and the amount that's left over
	// goes to miners).
	// TODO: confirm we want to subtract totalInput - totalOutput because that's
	// the amount of $DESO the transactor has to spend in this transaction.
	if totalInput > totalOutput {
		desoAllowedToSpendByPublicKey[*NewPublicKey(txn.PublicKey)] = totalInput - totalOutput
	} else {
		desoAllowedToSpendByPublicKey[*NewPublicKey(txn.PublicKey)] = 0
	}
	// Iterate over all the UTXOs in the txn and spend them. As we spend each one,
	// add the amount each account is allowed to spend to our map.
	spentUtxoEntries := []*UtxoEntry{}
	publicKeys := []PublicKey{}
	for publicKey := range txMeta.MatchingBidsInputsMap {
		publicKeys = append(publicKeys, publicKey)
	}
	sort.Slice(publicKeys, func(ii, jj int) bool {
		return bytes.Compare(publicKeys[ii].ToBytes(), publicKeys[jj].ToBytes()) > 0
	})
	for _, publicKey := range publicKeys {
		matchingBidsInputs := txMeta.MatchingBidsInputsMap[publicKey]
		// If no balance recorded so far, initialize to zero.
		if _, exists := desoAllowedToSpendByPublicKey[publicKey]; !exists {
			desoAllowedToSpendByPublicKey[publicKey] = 0
		}

		for _, matchingBidInput := range matchingBidsInputs {
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

			// Track spent UTXO entries.
			spentUtxoEntries = append(spentUtxoEntries, utxoEntry)

			// Track the UtxoOperations so we can rollback, and for Rosetta.
			utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
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

	// FIXME: Add sanity-check: Make sure that all of the increases and
	// decreases sum to zero. If this is the case we're pretty protected
	// against any money-printer bugs.

	// prevBalances will have the previous balances for all users, mapped
	// by each coin that changed. The values will be incorrect for DESO, but
	// that's OK because we don't need the balances for DESO in the disconnect
	// logic because simply reverting the UTXOs will be sufficient.
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

				// Check that we didn't overflow or underflow the DESO surplus
				// Note that if we ever go negative then that's an error because
				// we already maxed out the DESO we're allowed to spend before
				// entering this loop.
				if newDESOSurplus.Cmp(big.NewInt(0)) < 0 {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderOverspendingDESO
				}
				if newDESOSurplus.Cmp(big.NewInt(0).SetUint64(math.MaxUint64)) > 0 {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderOverflowsDESO
				}

				// Now create an implicit output for whatever surplus remains.
				//
				// If we're dealing with the transactor, then we assume it's
				// their responsibility to set an output for themselves. We
				// don't create a change output for them for this reason.
				// You might wonder why we do this. Well, it's because if we
				// didn't do it then it would be impossible to determine how
				// much the transactor wanted to give to the miner vs back to
				// themselves as change. Making them set an output for themselves
				// when constructing the txn mitigates this problem, and allows
				// the fee to be implicitly computed from whatever's left.
				if *transactorPKIDEntry.PKID != userPKID {
					err = createUTXO(newDESOSurplus.Uint64(), pubKey, UtxoTypeDAOCoinLimitOrderPayout)
					if err != nil {
						return 0, 0, nil, err
					}
				}
			} else {
				// In this case we're dealing with a DAO coin so simply
				// update the value in the DB and call it a day.
				prevBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(
					&userPKID, &daoCoinPKID, true)
				if prevBalanceEntry == nil || prevBalanceEntry.isDeleted {
					// FIXME: this isn't a proper error to return.
					// It's whatever was set above which is most likely nil.
					return 0, 0, nil, err
				}
				newBalance := big.NewInt(0).Add(prevBalanceEntry.BalanceNanos.ToBig(), delta)

				if newBalance.Cmp(big.NewInt(0)) < 0 {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderOverspendingDAOCoin
				}
				if newBalance.Cmp(MaxUint256.ToBig()) > 0 {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderOverflowsDAOCoin
				}
				// At this point we're certain that the new balance didn't underflow or
				// overflow. Set it in the db without fear.
				newBalanceUint256, _ := uint256.FromBig(newBalance)
				newBalanceEntry := prevBalanceEntry.Copy()
				newBalanceEntry.BalanceNanos = *newBalanceUint256
				bav._setDAOCoinBalanceEntryMappings(newBalanceEntry)
			}
		}
	}

	// We included the transactor in the slices of the prev balance entries
	// and the prev DAO coin limit order entries. Usually we leave them in
	// a separate place, but here it makes sense.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                                 OperationTypeDAOCoinLimitOrder,
		PrevTransactorDAOCoinLimitOrderEntry: prevTransactorOrder,
		PrevBalanceEntries:                   prevBalances,
		PrevMatchingOrders:                   prevMatchingOrders,
		SpentUtxoEntries:                     spentUtxoEntries,
		FulfilledDAOCoinLimitOrders:          fulfilledOrders,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

// FIXME: Add a comment here
func (bav *UtxoView) _getNextLimitOrdersToFill(
	transactorOrder *DAOCoinLimitOrderEntry, lastSeenOrder *DAOCoinLimitOrderEntry) (
	[]*DAOCoinLimitOrderEntry, error) {
	// Get matching limit order entries from database.
	dbAdapter := DbAdapter{
		badgerDb:   bav.Handle,
		postgresDb: bav.Postgres,
	}

	matchingOrders, err := dbAdapter.GetMatchingDAOCoinLimitOrders(transactorOrder, lastSeenOrder)

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
			continue
		}

		// We should have seen this order already.
		if lastSeenOrder != nil && matchingOrder.IsBetterMatchingOrderThan(lastSeenOrder) {
			continue
		}

		sortedMatchingOrders = append(sortedMatchingOrders, matchingOrder)
	}

	// Sort matching orders by best matching.
	// Sort logic first looks at price, then block height (FIFO), then quantity (lowest first).
	sort.Slice(sortedMatchingOrders, func(ii, jj int) bool {
		return sortedMatchingOrders[ii].IsBetterMatchingOrderThan(sortedMatchingOrders[jj])
	})

	// Pull orders up to when the quantity is fulfilled or we run out of orders.
	outputMatchingOrders := []*DAOCoinLimitOrderEntry{}
	transactorOrderBuyingQuantity := transactorOrder.QuantityToBuyInBaseUnits

	for _, matchingOrder := range sortedMatchingOrders {
		outputMatchingOrders = append(outputMatchingOrders, matchingOrder)

		// To properly compare quantities, we need to compare the quantity
		// that the transactor order is interested in buying to the quantity
		// the matching order is interested in selling.
		matchingOrderSellingQuantity, err := matchingOrder.BaseUnitsToSellUint256()
		if err != nil {
			// This should never happen as we validate the
			// stored orders when they are submitted.
			return nil, err
		}

		// Break once the transactor's buying quantity is <= this matching
		// order's selling quantity or their buying quantity is <= 0.
		if transactorOrderBuyingQuantity.Eq(matchingOrderSellingQuantity) ||
			transactorOrderBuyingQuantity.Lt(matchingOrderSellingQuantity) ||
			transactorOrderBuyingQuantity.LtUint64(1) {
			break
		}

		transactorOrderBuyingQuantity, err = SafeUint256().Sub(
			transactorOrderBuyingQuantity, matchingOrderSellingQuantity)
		if err != nil {
			// This should never happen because of the check above.
			return nil, errors.Wrapf(err, "Error updating order quantity: ")
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
	//operationData := utxoOpsForTxn[operationIndex]
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

	//transactorPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey).PKID

	//// If buying DAO coins, revert the transactor's buying DAO coin balance entry.
	//transactorIsBuyingDESO := reflect.DeepEqual(*txMeta.BuyingDAOCoinCreatorPublicKey, ZeroPublicKey)
	//
	//if !transactorIsBuyingDESO {
	//	prevTransactorBalanceEntry := operationData.PrevBalanceEntries
	//
	//	if prevTransactorBalanceEntry == nil {
	//		prevTransactorBalanceEntry = &BalanceEntry{
	//			HODLerPKID:   transactorPKID,
	//			CreatorPKID:  DBGetPKIDEntryForPublicKey(txMeta.BuyingDAOCoinCreatorPublicKey),
	//			BalanceNanos: *uint256.NewInt(),
	//		}
	//	}
	//
	//	bav._setDAOCoinBalanceEntryMappings(prevTransactorBalanceEntry)
	//}
	//
	//// If selling DAO coins, revert the transactors' selling DAO coin balance entry.
	//transactorIsSellingDESO := reflect.DeepEqual(*txMeta.SellingDAOCoinCreatorPKID, ZeroPKID)
	//
	//if !transactorIsSellingDESO {
	//	prevTransactorBalanceEntry := operationData.PrevTransactorSellingDAOCoinBalanceEntry
	//
	//	if prevTransactorBalanceEntry == nil {
	//		prevTransactorBalanceEntry = &BalanceEntry{
	//			HODLerPKID:   transactorPKID,
	//			CreatorPKID:  txMeta.SellingDAOCoinCreatorPKID,
	//			BalanceNanos: *uint256.NewInt(),
	//		}
	//	}
	//
	//	bav._setDAOCoinBalanceEntryMappings(prevTransactorBalanceEntry)
	//}
	//
	//// Revert the transactor's limit order entry.
	//prevTransactorOrderEntry := operationData.PrevTransactorDAOCoinLimitOrderEntry
	//
	//if !operationData.DAOCoinLimitOrderIsCancellation {
	//	// For a cancellation limit order, there is nothing to revert here as the
	//	// new transactor limit order is never saved and the existing transactor
	//	// limit orders are stored/reverted in PrevDAOCoinLimitOrderEntries.
	//	if prevTransactorOrderEntry != nil {
	//		// If previous transactor order entry is not null, set it
	//		// which overwrites whatever is currently stored there.
	//		bav._setDAOCoinLimitOrderEntryMappings(prevTransactorOrderEntry)
	//	} else {
	//		// Else, we need to explicitly delete the transactor's order entry
	//		// from this transaction.
	//		transactorOrderEntry := txMeta.ToEntry(transactorPKID, blockHeight)
	//		bav._deleteDAOCoinLimitOrderEntryMappings(transactorOrderEntry)
	//	}
	//}
	//
	//// Revert the deleted limit orders in reverse order.
	//for ii := len(operationData.PrevDAOCoinLimitOrderEntries) - 1; ii >= 0; ii-- {
	//	orderEntry := operationData.PrevDAOCoinLimitOrderEntries[ii]
	//	bav._setDAOCoinLimitOrderEntryMappings(orderEntry)
	//}
	//
	//// Revert the balance entries in reverse order.
	//for ii := len(operationData.PrevBalanceEntries) - 1; ii >= 0; ii-- {
	//	balanceEntry := operationData.PrevBalanceEntries[ii]
	//	bav._setDAOCoinBalanceEntryMappings(balanceEntry)
	//}
	//
	//// Disconnect payment UTXOs.
	//// TODO: confirm we don't need this. If we have an order that doesn't match anything
	//// we're not going to have any payments.
	////if operationData.DAOCoinLimitOrderPaymentUtxoKeys == nil || len(operationData.DAOCoinLimitOrderPaymentUtxoKeys) == 0 {
	////	return fmt.Errorf("_disconnectDAOCoinLimitOrder: DAOCoinLimitOrderPaymentUtxoKeys was nil; " +
	////		"this should never happen")
	////}
	//
	//for ii := len(operationData.DAOCoinLimitOrderPaymentUtxoKeys) - 1; ii >= 0; ii-- {
	//	paymentUtxoKey := operationData.DAOCoinLimitOrderPaymentUtxoKeys[ii]
	//	if err := bav._unAddUtxo(paymentUtxoKey); err != nil {
	//		return errors.Wrapf(err, "_disconnectDAOCoinLimitOrder: Problem unAdding UTXO %v: ", paymentUtxoKey)
	//	}
	//}

	// Un-spend spent UTXOs.
	// TODO: what should we do here?
	//if txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
	//	// Un-spending UTXOs on behalf of the matching BID orders.
	//	for ii := len(operationData.SpentUtxoEntries) - 1; ii >= 0; ii-- {
	//		spentUtxoEntry := operationData.SpentUtxoEntries[ii]
	//
	//		if err := bav._unSpendUtxo(spentUtxoEntry); err != nil {
	//			return errors.Wrapf(err, "_disconnectDAOCoinLimitOrder: Problem unSpending UTXO %v: ", spentUtxoEntry)
	//		}
	//	}
	//} else if txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
	//	if len(operationData.SpentUtxoEntries) > 0 {
	//		return errors.New("_disconnectDAOCoinLimitOrder: unspent UTXO entries for BID order" +
	//			"this should never happen!")
	//	}
	//}

	// Now revert the basic transfer with the remaining operations.
	numMatchingOrderInputs := 0

	for _, inputs := range txMeta.MatchingBidsInputsMap {
		numMatchingOrderInputs += len(inputs)
	}

	numOrderOperations := (numUtxoAdds - len(currentTxn.TxOutputs) + numMatchingOrderInputs)
	operationIndex -= numOrderOperations
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

func (bav *UtxoView) _getDAOCoinLimitOrderEntry(inputEntry *DAOCoinLimitOrderEntry) (*DAOCoinLimitOrderEntry, error) {
	// This function shouldn't be called with nil.
	if inputEntry == nil {
		return nil, errors.Errorf("_getDAOCoinLimitOrderEntry: Called with nil entry; this should never happen")
	}

	// First check if we have the order entry in the UTXO view.
	outputEntry, _ := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[inputEntry.ToMapKey()]

	if outputEntry != nil {
		return outputEntry, nil
	}

	// If not, next check if we have the order entry in the database.
	dbAdapter := DbAdapter{
		badgerDb:   bav.Handle,
		postgresDb: bav.Postgres,
	}

	return dbAdapter.GetDAOCoinLimitOrder(inputEntry)
}

// FIXME: Leave a comment here stating in what ORDER these orders are returned.
// I think they're returned with the latest block height first. This means that
// cancelling them will deterministically cancel the most recent orders. Seems
// fine, but double-check that, and document it.
func (bav *UtxoView) _getAllDAOCoinLimitOrderEntriesForThisTransactorAtThisPrice(
	inputEntry *DAOCoinLimitOrderEntry) ([]*DAOCoinLimitOrderEntry, error) {

	// This function shouldn't be called with nil.
	if inputEntry == nil {
		return nil, errors.Errorf("_getAllDAOCoinLimitOrderEntriesForThisTransactorAtThisPrice: Called with nil entry; this should never happen")
	}

	// First, check if we have order entries in the database for this transactor at this price.
	// There can be multiple here as we include BlockHeight in the index, but here we are
	// searching for matching orders across block heights.
	dbAdapter := DbAdapter{
		badgerDb:   bav.Handle,
		postgresDb: bav.Postgres,
	}

	outputEntries, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisTransactorAtThisPrice(inputEntry)
	if err != nil {
		return nil, err
	}

	// Next check the UTXO view. The map key does not include block height as these are
	// unmined transactions so the block height isn't set yet. So here, there will only
	// ever be one transaction that matches for a given transactor PKID.
	outputEntry, _ := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[inputEntry.ToMapKey()]

	if outputEntry != nil {
		outputEntries = append(outputEntries, outputEntry)
	}

	return outputEntries, nil
}

func (bav *UtxoView) IsValidDAOCoinLimitOrder(order *DAOCoinLimitOrderEntry) error {
	// Returns an error if the input order is invalid. Otherwise returns nil.

	// Validate not buying and selling the same coin.
	if order.BuyingDAOCoinCreatorPKID.Eq(order.SellingDAOCoinCreatorPKID) {
		return RuleErrorDAOCoinLimitOrderCannotBuyAndSellSameCoin
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

	// Validate price > 0.
	if !order.ScaledExchangeRateCoinsToSellPerCoinToBuy.Gt(uint256.NewInt()) {
		return RuleErrorDAOCoinLimitOrderInvalidExchangeRate
	}

	// Validate quantity > 0.
	if !order.QuantityToBuyInBaseUnits.Gt(uint256.NewInt()) {
		return RuleErrorDAOCoinLimitOrderInvalidQuantity
	}

	// Calculate order total amount to sell from price and quantity.
	baseUnitsToSell, err := order.BaseUnitsToSellUint256()
	if err != nil {
		return err
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

	// TODO: we should also validate that the price is actually better.

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

	return nil
}
