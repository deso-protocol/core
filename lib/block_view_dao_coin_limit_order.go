package lib

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"math"
	"math/big"
	"reflect"
	"sort"
)

func (bav *UtxoView) _connectDAOCoinLimitOrder(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	// ----- Begin boiler-plate txn validations

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

	// ----- Begin custom validations

	// Validate TransactorPKID exists.
	transactorPKID := bav.GetPKIDForPublicKey(txn.PublicKey).PKID

	if transactorPKID == nil {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidTransactorPKID
	}

	// Validate DenominatedCoinType is one of our supported enum values and is always $DESO for now.
	switch txMeta.DenominatedCoinType {
	case DAOCoinLimitOrderEntryDenominatedCoinTypeDESO:
		break
	case DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin:
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
	default:
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
	}

	// If denominated in $DESO, validate DenominatedCoinCreatorPKID is all zeroes.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO {
		if !reflect.DeepEqual(ZeroPKID, *txMeta.DenominatedCoinCreatorPKID) {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidDenominatedCoinCreatorPKID
		}
	}

	// If denominated in a DAO coin, validate DenominatedCoinCreatorPKID exists and has a profile.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin {
		profileEntry := bav.GetProfileEntryForPKID(txMeta.DenominatedCoinCreatorPKID)

		if profileEntry == nil || profileEntry.isDeleted {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderDenominatedCoinCreatorMissingProfile
		}
	}

	// Validate DAOCoinCreatorPKID exists and has a profile.
	profileEntry := bav.GetProfileEntryForPKID(txMeta.DAOCoinCreatorPKID)

	if profileEntry == nil || profileEntry.isDeleted {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderDAOCoinCreatorMissingProfile
	}

	// Validate OperationType is one of our supported enum values.
	switch txMeta.OperationType {
	case DAOCoinLimitOrderEntryOrderTypeAsk:
		break
	case DAOCoinLimitOrderEntryOrderTypeBid:
		break
	default:
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedOperationType
	}

	// Validate price > 0.
	if !txMeta.PriceNanosPerDenominatedCoin.Gt(uint256.NewInt()) {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidPrice
	}

	// Validate quantity > 0.
	if !txMeta.Quantity.Gt(uint256.NewInt()) {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidQuantity
	}

	// Calculate order total cost from price and quantity.
	transactorOrderTotalCost, err := _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
		txMeta.Quantity, txMeta.PriceNanosPerDenominatedCoin)

	if err != nil {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidTotalCost
	}

	// If $DESO buy, validate that order total cost is less than the max uint64.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO &&
		!transactorOrderTotalCost.IsUint64() {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidTotalCost
	}

	// Validate transfer restriction status, if DAO coin can only be transferred to whitelisted members.
	// TODO

	// If ASK order, validate that the seller has enough of the DAO coin they're trying to sell.
	if txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
		transactorBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(transactorPKID, txMeta.DAOCoinCreatorPKID, true)

		// Transactor is trying to open an ASK order but doesn't have any of the promised DAO coins.
		if transactorBalanceEntry == nil || transactorBalanceEntry.isDeleted {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenAskOrder
		}

		// Transactor is trying to open an ASK order but doesn't have enough of the promised DAO coins.
		if transactorBalanceEntry.BalanceNanos.Lt(txMeta.Quantity) {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenAskOrder
		}
	}

	// If BID order, validate that the buyer has enough denominated coin to buy the DAO coin.
	if txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
		if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO {
			transactorDESOBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(bav.GetPublicKeyForPKID(transactorPKID))

			if err != nil {
				return 0, 0, nil, err
			}

			// User is trying to open a BID order but doesn't have enough $DESO.
			if transactorDESOBalanceNanos < transactorOrderTotalCost.Uint64() {
				return 0, 0, nil, RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenBidOrder
			}
		} else if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin {
			// We currently don't support DAO coins as the denominated type.
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
		} else {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
		}
	}

	// Validate that txn specifies inputs to cover $DESO spent on DAO coins.
	// This is checked in the loop over matching orders.
	// Possible that an input could cover multiple orders.
	// A balance model makes those checks easier.
	// Track how much $DESO is available for each matching order PKID.
	// Create temporary in-memory balance model for tracking.

	// PKID -> leftover change after performing operations
	pkidToLeftoverChangeDESONanos := make(map[PKID]uint64)

	// PKID -> DAO coin limit order payout
	pkidToOutputDESONanos := make(map[PKID]uint64)

	spentUtxoEntries := []*UtxoEntry{}

	// If transactor is submitting a BID order and it's denominated in $DESO,
	// we need to track how much $DESO they're spending on this txn.
	// TODO: double-check this.
	// We need to decrease totalInput by fees. Figure that out later.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO &&
		txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
		pkidToLeftoverChangeDESONanos[*bav.GetPKIDForPublicKey(txn.PublicKey).PKID] = totalInput
	}

	for pkid, matchingBidsInputs := range txMeta.MatchingBidsInputsMap {
		publicKey := bav.GetPublicKeyForPKID(&pkid)

		// If no balance recorded so far, initialize to zero.
		if _, exists := pkidToLeftoverChangeDESONanos[pkid]; !exists {
			pkidToLeftoverChangeDESONanos[pkid] = 0
		}

		for _, matchingBidInput := range matchingBidsInputs {
			utxoKey := UtxoKey(*matchingBidInput)
			utxoEntry := bav.GetUtxoEntryForUtxoKey(&utxoKey)

			if utxoEntry == nil || utxoEntry.isSpent {
				return 0, 0, nil, RuleErrorDAOCoinLimitOrderBidderInputNoLongerExists
			}

			// Make sure that the UTXO specified is actually from the bidder.
			if !reflect.DeepEqual(utxoEntry.PublicKey, publicKey) {
				return 0, 0, nil, RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey
			}

			// If the UTXO is from a block reward txn, make sure enough time has passed to make it spendable.
			if _isEntryImmatureBlockReward(utxoEntry, blockHeight, bav.Params) {
				return 0, 0, nil, RuleErrorInputSpendsImmatureBlockReward
			}

			pkidToLeftoverChangeDESONanos[pkid] += utxoEntry.AmountNanos

			// Make sure we spend the UTXO so that the bidder can't reuse it.
			utxoOp, err := bav._spendUtxo(&utxoKey)

			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectDAOCoinLimitOrder: Problem spending bidder utxo")
			}

			// Track spent UTXO entries.
			spentUtxoEntries = append(spentUtxoEntries, utxoEntry)

			// Track the UtxoOperations so we can rollback, and for Rosetta.
			utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
		}
	}

	// Helpers to create UTXOs.
	daoCoinLimitOrderPaymentUtxoKeys := []*UtxoKey{}

	// This may start negative but that's OK because the first thing we do
	// is increment it in createUTXO.
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
			// TODO: fix error
			return errors.Wrapf(err, "_connectDAOCoinLimitOrder: Problem adding output utxo")
		}

		daoCoinLimitOrderPaymentUtxoKeys = append(daoCoinLimitOrderPaymentUtxoKeys, outputKey)

		// Rosetta uses this UtxoOperation to provide INPUT amounts
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
		return nil
	}

	// ------ End custom validations

	// Create entry from txn metadata for the transactor.
	transactorOrder := txMeta.ToEntry(transactorPKID, blockHeight)

	// Keep track of state in case of reverting txn.
	prevDAOCoinLimitOrders := []*DAOCoinLimitOrderEntry{}
	prevTransactorBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(transactorOrder.TransactorPKID, transactorOrder.DAOCoinCreatorPKID, true)
	prevMatchingBalanceEntries := []*BalanceEntry{}

	// Logic to cancel an existing order
	if txMeta.CancelExistingOrder {
		// Get all existing limit orders:
		//   + For this transactor
		//   + For this denominated coin
		//   + For this DAO coin
		//   + For this operation type
		//   + For this price
		//   - Any block height
		//   - Any quantity
		existingTransactorOrders, err := bav._getAllDAOCoinLimitOrderEntriesForThisTransactorAtThisPrice(transactorOrder)

		if err != nil {
			return 0, 0, nil, err
		}

		if len(existingTransactorOrders) == 0 {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderToCancelNotFound
		}

		quantityToReduce := transactorOrder.Quantity

		for _, existingTransactorOrder := range existingTransactorOrders {
			prevDAOCoinLimitOrders = append(prevDAOCoinLimitOrders, existingTransactorOrder)

			if existingTransactorOrder.Quantity.Gt(quantityToReduce) {
				// If existing transactor order quantity > cancellation quantity...

				// Reduce existing quantity and store.
				existingTransactorOrder.Quantity = uint256.NewInt().Sub(
					existingTransactorOrder.Quantity, quantityToReduce)

				bav._setDAOCoinLimitOrderEntryMappings(existingTransactorOrder)

				// No more orders to cancel. Break.
				break
			} else {
				// If existing transactor order quantity <= cancellation quantity...

				// Reduce quantity to cancel.
				quantityToReduce = uint256.NewInt().Sub(
					quantityToReduce, existingTransactorOrder.Quantity)

				// Delete existing transactor order.
				bav._deleteDAOCoinLimitOrderEntryMappings(existingTransactorOrder)

				// If no more orders to cancel, break.
				if quantityToReduce.Eq(uint256.NewInt()) {
					break
				}
			}
		}

		utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
			Type:                                 OperationTypeDAOCoinLimitOrder,
			PrevTransactorBalanceEntry:           prevTransactorBalanceEntry,
			PrevTransactorDAOCoinLimitOrderEntry: nil,
			PrevBalanceEntries:                   prevMatchingBalanceEntries,
			PrevDAOCoinLimitOrderEntries:         prevDAOCoinLimitOrders,
			SpentUtxoEntries:                     spentUtxoEntries,
			DAOCoinLimitOrderPaymentUtxoKeys:     daoCoinLimitOrderPaymentUtxoKeys,
			DAOCoinLimitOrderIsCancellation:      true,
		})

		return totalInput, totalOutput, utxoOpsForTxn, nil
	}

	// Check if you already have an existing order for this transactor at this price in this block.
	// If exists, update new order with previous order's quantity and mark previous order for deletion.
	prevTransactorOrder, err := bav._getDAOCoinLimitOrderEntry(transactorOrder)

	if err != nil {
		return 0, 0, nil, err
	}

	if prevTransactorOrder != nil {
		transactorOrder.Quantity = uint256.NewInt().Add(transactorOrder.Quantity, prevTransactorOrder.Quantity)
		bav._deleteDAOCoinLimitOrderEntryMappings(prevTransactorOrder)
	}

	// Seek matching orders
	prevMatchingOrders, _ := bav._getNextLimitOrdersToFill(transactorOrder, nil)
	matchingOrders := []*DAOCoinLimitOrderEntry{}
	var lastSeenOrder *DAOCoinLimitOrderEntry

	for len(prevMatchingOrders) > 0 {
		// Cache previous state of potential matching orders in case of revert.
		for _, matchingOrder := range prevMatchingOrders {
			matchingOrders = append(matchingOrders, matchingOrder.Copy())
		}

		// 1-by-1 match existing orders to the transactor's order.
		for _, matchingOrder := range matchingOrders {
			// Validate that the matching seller has the DAO coin they're selling.
			if matchingOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
				matchingBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(matchingOrder.TransactorPKID, matchingOrder.DAOCoinCreatorPKID, true)

				// Seller with open ASK order doesn't have any of the promised DAO coins.
				// Don't include and mark their order for deletion.
				if matchingBalanceEntry == nil || matchingBalanceEntry.isDeleted {
					prevDAOCoinLimitOrders = append(prevDAOCoinLimitOrders, matchingOrder)
					bav._deleteDAOCoinLimitOrderEntryMappings(matchingOrder)
					continue
				}

				// Seller with open ASK order doesn't have enough of the promised DAO coins.
				// Don't include and mark their order for deletion.
				// TODO: maybe we should partially fulfill the order? Maybe less error-prone to just close.
				if matchingBalanceEntry.BalanceNanos.Lt(matchingOrder.Quantity) {
					prevDAOCoinLimitOrders = append(prevDAOCoinLimitOrders, matchingOrder)
					bav._deleteDAOCoinLimitOrderEntryMappings(matchingOrder)
					continue
				}
			}

			// Validate that the matching buyer has enough $ to buy the DAO coin.
			if matchingOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
				if matchingOrder.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO {
					matchingDESOBalanceNanos := pkidToLeftoverChangeDESONanos[*matchingOrder.TransactorPKID]

					// Calculate matching order total cost from price and quantity.
					matchingOrderTotalCost, err := _getOrderTotalCost(matchingOrder)

					if err != nil {
						return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidTotalCost
					}

					// Validate that order total cost is an uint64.
					if !matchingOrderTotalCost.IsUint64() {
						return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidTotalCost
					}

					// Buyer with open BID order doesn't have enough $DESO.
					// Don't include and mark their order for deletion.
					if matchingDESOBalanceNanos < matchingOrderTotalCost.Uint64() {
						// If order creator doesn't have enough $DESO to cover BID order,
						// then delete their BID order.
						globalDesoBalance, err := bav.GetDeSoBalanceNanosForPublicKey(bav.GetPublicKeyForPKID(matchingOrder.TransactorPKID))

						if err != nil {
							return 0, 0, nil, err
						}

						if globalDesoBalance < matchingOrderTotalCost.Uint64() {
							prevDAOCoinLimitOrders = append(prevDAOCoinLimitOrders, matchingOrder)
							bav._deleteDAOCoinLimitOrderEntryMappings(matchingOrder)
						}

						continue
					}
				} else if matchingOrder.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin {
					// We currently don't support DAO coins as the denominated type.
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
				} else {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
				}
			}

			// Update order quantities.
			var daoCoinsToTransfer *uint256.Int
			transactorOrderIsComplete := false

			if transactorOrder.Quantity.Lt(matchingOrder.Quantity) {
				// Since the transactor order's quantity is less than the matching
				// order's quantity, we transfer the transactor order's quantity.
				daoCoinsToTransfer = transactorOrder.Quantity

				// Update matching order's quantity and store.
				matchingOrder.Quantity = uint256.NewInt().Sub(matchingOrder.Quantity, transactorOrder.Quantity)
				bav._setDAOCoinLimitOrderEntryMappings(matchingOrder)

				// Set transactor order's quantity to zero.
				transactorOrder.Quantity = uint256.NewInt()

				// Mark transactor's order complete so that this
				// is our last iteration of this loop.
				transactorOrderIsComplete = true
			} else {
				// Since the transactor's order's quantity is greater than or equal to the matching
				// order's quantity, we transfer the matching order's quantity.
				daoCoinsToTransfer = matchingOrder.Quantity

				// Update transactor order's quantity.
				transactorOrder.Quantity = uint256.NewInt().Sub(transactorOrder.Quantity, matchingOrder.Quantity)

				// Mark matching order for deletion.
				prevDAOCoinLimitOrders = append(prevDAOCoinLimitOrders, matchingOrder)
				bav._deleteDAOCoinLimitOrderEntryMappings(matchingOrder)

				// In the case where the transactor and matching order's quantities were
				// equal to each other, mark transactor's order as complete so that this
				// is our last iteration of this loop.
				if transactorOrder.Quantity.IsZero() {
					transactorOrderIsComplete = true
				}
			}

			// Find or create DAO coin balance entries.
			prevTransactorCurrentBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(transactorOrder.TransactorPKID, transactorOrder.DAOCoinCreatorPKID, true)
			prevMatchingBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(matchingOrder.TransactorPKID, matchingOrder.DAOCoinCreatorPKID, true)

			var newTransactorBalanceEntry *BalanceEntry
			var newMatchingBalanceEntry *BalanceEntry

			if prevTransactorCurrentBalanceEntry == nil || prevTransactorCurrentBalanceEntry.isDeleted {
				newTransactorBalanceEntry = &BalanceEntry{
					HODLerPKID:   transactorOrder.TransactorPKID,
					CreatorPKID:  transactorOrder.DenominatedCoinCreatorPKID,
					BalanceNanos: *uint256.NewInt(),
				}
			} else {
				newTransactorBalanceEntry = prevTransactorCurrentBalanceEntry.Copy()
			}

			if prevMatchingBalanceEntry == nil || prevMatchingBalanceEntry.isDeleted {
				newMatchingBalanceEntry = &BalanceEntry{
					HODLerPKID:   matchingOrder.TransactorPKID,
					CreatorPKID:  matchingOrder.DenominatedCoinCreatorPKID,
					BalanceNanos: *uint256.NewInt(),
				}
			} else {
				newMatchingBalanceEntry = prevMatchingBalanceEntry.Copy()
			}

			// Transfer DAO coins.
			prevMatchingBalanceEntries = append(prevMatchingBalanceEntries, prevMatchingBalanceEntry)

			if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
				// Transactor placed ASK order:
				// Send DAO coins from transactorBalanceEntry to matched BalanceEntry.
				newTransactorBalanceEntry.BalanceNanos = *uint256.NewInt().Sub(&newTransactorBalanceEntry.BalanceNanos, daoCoinsToTransfer)
				newMatchingBalanceEntry.BalanceNanos = *uint256.NewInt().Add(&newMatchingBalanceEntry.BalanceNanos, daoCoinsToTransfer)
			}

			if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
				// Transactor placed BID order:
				// Send DAO coins from matchedBalanceEntry to transactorBalanceEntry.
				newMatchingBalanceEntry.BalanceNanos = *uint256.NewInt().Sub(&newMatchingBalanceEntry.BalanceNanos, daoCoinsToTransfer)
				newTransactorBalanceEntry.BalanceNanos = *uint256.NewInt().Add(&newTransactorBalanceEntry.BalanceNanos, daoCoinsToTransfer)
			}

			bav._setDAOCoinBalanceEntryMappings(newTransactorBalanceEntry)
			bav._setDAOCoinBalanceEntryMappings(newMatchingBalanceEntry)

			// Track how much denominated coin to transfer.
			denominatedCoinToTransfer, err := _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
				daoCoinsToTransfer, matchingOrder.PriceNanosPerDenominatedCoin)

			if err != nil {
				return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidTotalCost
			}

			if transactorOrder.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO {
				if !denominatedCoinToTransfer.IsUint64() {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidPrice
				}

				desoToTransfer := denominatedCoinToTransfer.Uint64()
				var inputPKID PKID
				var outputPKID PKID

				if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
					inputPKID = *matchingOrder.TransactorPKID
					outputPKID = *transactorOrder.TransactorPKID
				} else if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
					inputPKID = *transactorOrder.TransactorPKID
					outputPKID = *matchingOrder.TransactorPKID
				} else {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedOperationType
				}

				if _, exists := pkidToOutputDESONanos[outputPKID]; !exists {
					pkidToOutputDESONanos[outputPKID] = 0
				}

				// Check for underflow in user sending $DESO.
				if pkidToLeftoverChangeDESONanos[inputPKID] < desoToTransfer {
					// TODO: revisit rule error
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenBidOrder
				}

				pkidToLeftoverChangeDESONanos[inputPKID] -= desoToTransfer

				// Check for overflow in user receiving $DESO.
				if pkidToOutputDESONanos[outputPKID] > math.MaxUint64-desoToTransfer {
					// TODO: revisit rule error --> have specified too big of an order
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenBidOrder
				}

				pkidToOutputDESONanos[outputPKID] += desoToTransfer
			} else if transactorOrder.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin {
				// TODO: DAO coin denominated types not supported yet.
				return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
			} else {
				return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
			}

			// Break if transactor's order is complete.
			if transactorOrderIsComplete {
				break
			}
		}

		// If order is fulfilled, done.
		if transactorOrder.Quantity.IsZero() {
			break
		}

		// Else transactor's order is still not fully fulfilled, so loop.
		lastSeenOrder = prevMatchingOrders[len(prevMatchingOrders)-1]
		prevMatchingOrders, _ = bav._getNextLimitOrdersToFill(transactorOrder, lastSeenOrder)
	}

	// After iterating through all potential matching orders, if transactor's order
	// is still not fully fulfilled, submit it to be stored.
	if transactorOrder.Quantity.GtUint64(0) {
		bav._setDAOCoinLimitOrderEntryMappings(transactorOrder)
	}

	// Create UTXOs.

	// UTXOs representing payments.
	for pkid, desoNanos := range pkidToOutputDESONanos {
		err = createUTXO(desoNanos, bav.GetPublicKeyForPKID(&pkid), UtxoTypeDAOCoinLimitOrderPayout)

		if err != nil {
			return 0, 0, nil, err
		}
	}

	// UTXOs representing leftover change from input UTXOs after users make payments.
	for pkid, balanceNanos := range pkidToLeftoverChangeDESONanos {
		// We don't generate a change output for the transactor since
		// that is handled by the basic transfer.
		if reflect.DeepEqual(pkid, *transactorOrder.TransactorPKID) {
			// Total output = how much is spent by this txn.
			// I.e. not given as change to the transactor.
			// TODO: check for underflow.
			// TODO: check for overflow.
			totalOutput += totalInput - balanceNanos
			continue
		}

		err = createUTXO(balanceNanos, bav.GetPublicKeyForPKID(&pkid), UtxoTypeDAOCoinLimitOrderChange)

		if err != nil {
			return 0, 0, nil, err
		}
	}

	// We included the transactor in the slices of the prev balance entries
	// and the prev DAO coin limit order entries. Usually we leave them in
	// a separate place, but here it makes sense.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                                 OperationTypeDAOCoinLimitOrder,
		PrevTransactorBalanceEntry:           prevTransactorBalanceEntry,
		PrevTransactorDAOCoinLimitOrderEntry: prevTransactorOrder,
		PrevBalanceEntries:                   prevMatchingBalanceEntries,
		PrevDAOCoinLimitOrderEntries:         prevDAOCoinLimitOrders,
		SpentUtxoEntries:                     spentUtxoEntries,
		DAOCoinLimitOrderPaymentUtxoKeys:     daoCoinLimitOrderPaymentUtxoKeys,
		DAOCoinLimitOrderIsCancellation:      false,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

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
		if matchingOrder.isDeleted {
			continue
		}

		if transactorOrder.DenominatedCoinType != matchingOrder.DenominatedCoinType {
			continue
		}

		if transactorOrder.OperationType == matchingOrder.OperationType {
			continue
		}

		// ASK: reject if transactorOrder.PriceNanos > order.PriceNanos
		// I.e. transactorOrder.PriceNanosPerDenominatedCoin < order.PriceNanosPerDenominatedCoin
		if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
			// We should have seen this order already.
			if lastSeenOrder != nil && matchingOrder.IsBetterBidThan(lastSeenOrder) {
				continue
			}
			if transactorOrder.PriceNanosPerDenominatedCoin.Lt(matchingOrder.PriceNanosPerDenominatedCoin) {
				continue
			}
		}

		// Bid: reject if transactorOrder.PriceNanos < order.PriceNanos
		// I.e. transactorOrder.PriceNanosPerDenominatedCoin > order.PriceNanosPerDenominatedCoin
		if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
			// We should have seen this order already
			if lastSeenOrder != nil && matchingOrder.IsBetterAskThan(lastSeenOrder) {
				continue
			}
			if transactorOrder.PriceNanosPerDenominatedCoin.Gt(matchingOrder.PriceNanosPerDenominatedCoin) {
				continue
			}
		}

		if !reflect.DeepEqual(transactorOrder.DenominatedCoinCreatorPKID, matchingOrder.DenominatedCoinCreatorPKID) {
			continue
		}

		if !reflect.DeepEqual(transactorOrder.DAOCoinCreatorPKID, matchingOrder.DAOCoinCreatorPKID) {
			continue
		}

		sortedMatchingOrders = append(sortedMatchingOrders, matchingOrder)
	}

	// Sort matching orders by best matching.
	// Sort logic first looks at price, then block height (FIFO), then quantity (lowest first).
	sort.Slice(sortedMatchingOrders, func(ii, jj int) bool {
		if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
			// If transactor's order is an ASK, we want to sort by the best BID orders.
			return sortedMatchingOrders[ii].IsBetterBidThan(sortedMatchingOrders[jj])
		}

		if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
			// If transactor's order is a BID, we want to sort by the best ASK orders.
			return sortedMatchingOrders[ii].IsBetterAskThan(sortedMatchingOrders[jj])
		}

		return false
	})

	// Pull orders up to the when the quantity is fulfilled or we run out of orders.
	outputMatchingOrders := []*DAOCoinLimitOrderEntry{}
	transactorOrderQuantity := transactorOrder.Quantity

	for _, matchingOrder := range sortedMatchingOrders {
		outputMatchingOrders = append(outputMatchingOrders, matchingOrder)
		transactorOrderQuantity = uint256.NewInt().Sub(transactorOrderQuantity, matchingOrder.Quantity)

		if transactorOrderQuantity.LtUint64(0) {
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

	// Revert the transactor's balance entry.
	transactorPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey).PKID
	prevTransactorBalanceEntry := operationData.PrevTransactorBalanceEntry

	if prevTransactorBalanceEntry == nil {
		prevTransactorBalanceEntry = &BalanceEntry{
			HODLerPKID:   transactorPKID,
			CreatorPKID:  txMeta.DAOCoinCreatorPKID,
			BalanceNanos: *uint256.NewInt(),
		}
	}

	bav._setDAOCoinBalanceEntryMappings(prevTransactorBalanceEntry)

	// Revert the transactor's limit order entry.
	prevTransactorOrderEntry := operationData.PrevTransactorDAOCoinLimitOrderEntry

	if !operationData.DAOCoinLimitOrderIsCancellation {
		// For a cancellation limit order, there is nothing to revert here as the
		// new transactor limit order is never saved and the existing transactor
		// limit orders are stored/reverted in PrevDAOCoinLimitOrderEntries.
		if prevTransactorOrderEntry != nil {
			// If previous transactor order entry is not null, set it
			// which overwrites whatever is currently stored there.
			bav._setDAOCoinLimitOrderEntryMappings(prevTransactorOrderEntry)
		} else {
			// Else, we need to explicitly delete the transactor's order entry
			// from this transaction.
			transactorOrderEntry := txMeta.ToEntry(transactorPKID, blockHeight)
			bav._deleteDAOCoinLimitOrderEntryMappings(transactorOrderEntry)
		}
	}

	// Revert the deleted limit orders in reverse order.
	for ii := len(operationData.PrevDAOCoinLimitOrderEntries) - 1; ii >= 0; ii-- {
		orderEntry := operationData.PrevDAOCoinLimitOrderEntries[ii]
		bav._setDAOCoinLimitOrderEntryMappings(orderEntry)
	}

	// Revert the balance entries in reverse order.
	for ii := len(operationData.PrevBalanceEntries) - 1; ii >= 0; ii-- {
		balanceEntry := operationData.PrevBalanceEntries[ii]
		bav._setDAOCoinBalanceEntryMappings(balanceEntry)
	}

	// Disconnect payment UTXOs.
	// TODO: confirm we don't need this. If we have an order that doesn't match anything
	// we're not going to have any payments.
	//if operationData.DAOCoinLimitOrderPaymentUtxoKeys == nil || len(operationData.DAOCoinLimitOrderPaymentUtxoKeys) == 0 {
	//	return fmt.Errorf("_disconnectDAOCoinLimitOrder: DAOCoinLimitOrderPaymentUtxoKeys was nil; " +
	//		"this should never happen")
	//}

	for ii := len(operationData.DAOCoinLimitOrderPaymentUtxoKeys) - 1; ii >= 0; ii-- {
		paymentUtxoKey := operationData.DAOCoinLimitOrderPaymentUtxoKeys[ii]
		if err := bav._unAddUtxo(paymentUtxoKey); err != nil {
			return errors.Wrapf(err, "_disconnectDAOCoinLimitOrder: Problem unAdding UTXO %v: ", paymentUtxoKey)
		}
	}

	// Un-spend spent UTXOs.
	if txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
		// Un-spending UTXOs on behalf of the matching BID orders.
		for ii := len(operationData.SpentUtxoEntries) - 1; ii >= 0; ii-- {
			spentUtxoEntry := operationData.SpentUtxoEntries[ii]

			if err := bav._unSpendUtxo(spentUtxoEntry); err != nil {
				return errors.Wrapf(err, "_disconnectDAOCoinLimitOrder: Problem unSpending UTXO %v: ", spentUtxoEntry)
			}
		}
	} else if txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
		if len(operationData.SpentUtxoEntries) > 0 {
			return errors.New("_disconnectDAOCoinLimitOrder: unspent UTXO entries for BID order" +
				"this should never happen!")
		}
	} else {
		// TODO: is this rule kosher?
		return RuleErrorDAOCoinLimitOrderUnsupportedOperationType
	}

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

	return dbAdapter.GetDAOCoinLimitOrder(inputEntry, false)
}

func (bav *UtxoView) _getAllDAOCoinLimitOrderEntriesForThisTransactorAtThisPrice(inputEntry *DAOCoinLimitOrderEntry) ([]*DAOCoinLimitOrderEntry, error) {
	// This function shouldn't be called with nil.
	if inputEntry == nil {
		return nil, errors.Errorf("_getAllDAOCoinLimitOrderEntriesForThisTransactorAtThisPrice: Called with nil entry; this should never happen")
	}

	// First, check if we have order entries in the database for this transactor at this price.
	dbAdapter := DbAdapter{
		badgerDb:   bav.Handle,
		postgresDb: bav.Postgres,
	}

	outputEntries, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisTransactorAtThisPrice(inputEntry)

	if err != nil {
		return nil, err
	}

	// Next check the UTXO view.
	outputEntry, _ := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[inputEntry.ToMapKey()]

	if outputEntry != nil {
		outputEntries = append(outputEntries, outputEntry)
	}

	return outputEntries, nil
}

func _getOrderTotalCost(order *DAOCoinLimitOrderEntry) (*uint256.Int, error) {
	return _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(order.Quantity, order.PriceNanosPerDenominatedCoin)
}

// TotalCost = Quantity * (Nanos / DenominatedCoin) * ( 1 / PriceNanosPerDenominatedCoin )
func _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
	quantity *uint256.Int, priceNanosPerDenominatedCoin *uint256.Int) (*uint256.Int, error) {
	totalCostBigInt := big.NewInt(0).Mul(quantity.ToBig(), big.NewInt(int64(NanosPerUnit)))
	totalCostBigInt = big.NewInt(0).Div(totalCostBigInt, priceNanosPerDenominatedCoin.ToBig())
	totalCost, totalCostOverflow := uint256.FromBig(totalCostBigInt)

	if totalCostOverflow {
		return nil, fmt.Errorf("Order total cost overflows uint256")
	}

	return totalCost, nil
}
