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
	if txMeta.PriceNanosPerDenominatedCoin.IsZero() ||
		txMeta.PriceNanosPerDenominatedCoin.Lt(uint256.NewInt()) {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidPrice
	}

	// If denominated in $DESO, confirm PriceNanos is uint64.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO &&
		!txMeta.PriceNanosPerDenominatedCoin.IsUint64() {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidPrice
	}

	// Validate quantity > 0.
	if !txMeta.Quantity.Gt(uint256.NewInt()) {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidQuantity
	}

	// requestedOrderTotalCost = Quantity * (Nanos / DenominatedCoin) * ( 1 / PriceNanosPerDenominatedCoin )
	var requestedOrderTotalCost *uint256.Int
	requestedOrderTotalCost, err = _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
		txMeta.Quantity, txMeta.PriceNanosPerDenominatedCoin)
	if err != nil {
		// TODO: wrap with rule error describing overflow
		return 0, 0, nil, err
	}

	// If $DESO buy, validate that order total cost is less than the max uint64.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO &&
		!requestedOrderTotalCost.IsUint64() {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidQuantity
	}

	// Validate transfer restriction status, if DAO coin can only be transferred to whitelisted members.
	// TODO

	// If ask order, validate that the seller has enough of the DAO coin they're trying to sell.
	if txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
		balanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(transactorPKID, txMeta.DAOCoinCreatorPKID, true)

		// User is trying to open an ask order but doesn't have any of the promised DAO coins.
		if balanceEntry == nil || balanceEntry.isDeleted {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenAskOrder
		}

		// User is trying to open an ask order but doesn't have enough of the promised DAO coins.
		if balanceEntry.BalanceNanos.Lt(txMeta.Quantity) {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenAskOrder
		}
	}

	// Validate if bid order, that buyer has enough $ to buy the DAO coin.
	if txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
		if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO {
			desoBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(bav.GetPublicKeyForPKID(transactorPKID))

			if err != nil {
				return 0, 0, nil, err
			}

			// User is trying to open a bid order but doesn't have enough $DESO.
			if desoBalanceNanos < requestedOrderTotalCost.Uint64() {
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
	// Track how much DESO is available for each matching order PKID.
	// Create temporary in-memory balance model for tracking.

	// PKID -> leftover change after performing operations
	pkidToNetDesoBalanceNanos := make(map[PKID]uint64)

	// PKID -> DAO coin limit order payout
	pkidToOutputDesoNanos := make(map[PKID]uint64)

	spentUtxoEntries := []*UtxoEntry{}

	// If requester is submitting a bid order and it's denominated in $DESO,
	// we need to track how much $DESO they're spending on this txn.
	// TODO: double-check this.
	// We need to decrease totalInput by fees. Figure that out later.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO &&
		txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
		pkidToNetDesoBalanceNanos[*bav.GetPKIDForPublicKey(txn.PublicKey).PKID] = totalInput
	}

	for pkid, inputs := range txMeta.MatchingBidsInputsMap {
		publicKey := bav.GetPublicKeyForPKID(&pkid)

		// If no balance recorded so far, initialize to zero.
		if _, exists := pkidToNetDesoBalanceNanos[pkid]; !exists {
			pkidToNetDesoBalanceNanos[pkid] = 0
		}

		for _, input := range inputs {
			utxoKey := UtxoKey(*input)
			utxoEntry := bav.GetUtxoEntryForUtxoKey(&utxoKey)

			if utxoEntry == nil || utxoEntry.isSpent {
				// TODO: update rule error
				return 0, 0, nil, errors.Wrapf(RuleErrorBidderInputForAcceptedNFTBidNoLongerExists, "_helpConnectNFTSold: ")
			}

			// Make sure that the utxo specified is actually from the bidder.
			if !reflect.DeepEqual(utxoEntry.PublicKey, publicKey) {
				// TODO check rule error
				return 0, 0, nil, errors.Wrapf(RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey, "_helpConnectNFTSold: ")
			}

			// If the utxo is from a block reward txn, make sure enough time has passed to make it spendable.
			if _isEntryImmatureBlockReward(utxoEntry, blockHeight, bav.Params) {
				// TODO check rule error
				return 0, 0, nil, errors.Wrapf(RuleErrorInputSpendsImmatureBlockReward, "_helpConnectNFTSold: ")
			}

			pkidToNetDesoBalanceNanos[pkid] += utxoEntry.AmountNanos

			// Make sure we spend the utxo so that the bidder can't reuse it.
			utxoOp, err := bav._spendUtxo(&utxoKey)

			if err != nil {
				// TODO: check rule error
				return 0, 0, nil, errors.Wrapf(err, "_helpConnectNFTSold: Problem spending bidder utxo")
			}

			// Track spent UTXO entries
			spentUtxoEntries = append(spentUtxoEntries, utxoEntry)

			// Track the UtxoOperations so we can rollback, and for Rosetta
			utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
		}
	}

	// Helpers to create UTXOs.
	daoCoinLimitOrderPaymentUtxoKeys := []*UtxoKey{}
	// This may start negative but that's OK because the first thing we do is increment it
	// in createUTXO
	nextUtxoIndex := len(txn.TxOutputs) - 1

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

	// Create entry from txn metadata.
	requestedOrder := &DAOCoinLimitOrderEntry{
		TransactorPKID:               transactorPKID,
		DenominatedCoinType:          txMeta.DenominatedCoinType,
		DenominatedCoinCreatorPKID:   txMeta.DenominatedCoinCreatorPKID,
		DAOCoinCreatorPKID:           txMeta.DAOCoinCreatorPKID,
		OperationType:                txMeta.OperationType,
		PriceNanosPerDenominatedCoin: txMeta.PriceNanosPerDenominatedCoin,
		BlockHeight:                  blockHeight,
		Quantity:                     txMeta.Quantity,
	}

	// Check if you already have an existing order at this price in this block.
	// If exists, update new order with previous order's quantity and mark previous order for deletion.
	// Only have to check UTXO and not Badger because we are only aggregating within the block height.
	orderKey := requestedOrder.ToMapKey()

	prevOrder, _ := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderKey]

	if prevOrder != nil {
		requestedOrder.Quantity = uint256.NewInt().Add(requestedOrder.Quantity, prevOrder.Quantity)
		bav._deleteDAOCoinLimitOrderEntryMappings(prevOrder)
	}

	// Seek matching orders
	prevMatchingOrders, _ := bav._getNextLimitOrdersToFill(requestedOrder, nil)
	matchingOrders := []*DAOCoinLimitOrderEntry{}
	var lastSeenOrder *DAOCoinLimitOrderEntry

	// Keep track of state in case of reverting txn.
	deletedDAOCoinLimitOrders := []*DAOCoinLimitOrderEntry{}
	prevRequesterBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(requestedOrder.TransactorPKID, requestedOrder.DAOCoinCreatorPKID, true)
	prevMatchingBalanceEntries := []*BalanceEntry{}

	for len(prevMatchingOrders) > 0 {
		// Cache previous state of potential matching orders in case of revert.
		for _, order := range prevMatchingOrders {
			matchingOrders = append(matchingOrders, order.Copy())
		}

		// 1-by-1 match existing orders to the requested order.
		for _, order := range matchingOrders {
			// Validate that the seller has the DAO coin they're selling.
			if order.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
				balanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(order.TransactorPKID, order.DAOCoinCreatorPKID, true)

				// Seller with open ask order doesn't have any of the promised DAO coins.
				// Don't include and mark their order for deletion.
				if balanceEntry == nil || balanceEntry.isDeleted {
					deletedDAOCoinLimitOrders = append(deletedDAOCoinLimitOrders, order)
					bav._deleteDAOCoinLimitOrderEntryMappings(order)
					continue
				}

				// Seller with open ask order doesn't have enough of the promised DAO coins.
				// Don't include and mark their order for deletion.
				// TODO: maybe we should partially fulfill the order? Maybe less error-prone to just close.
				if balanceEntry.BalanceNanos.Lt(order.Quantity) {
					deletedDAOCoinLimitOrders = append(deletedDAOCoinLimitOrders, order)
					bav._deleteDAOCoinLimitOrderEntryMappings(order)
					continue
				}
			}

			// Validate that the buyer has enough $ to buy the DAO coin.
			if order.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
				if order.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO {
					desoBalanceNanos := pkidToNetDesoBalanceNanos[*order.TransactorPKID]

					// Order total cost = price x quantity.
					var orderTotalCost *uint256.Int
					orderTotalCost, err = _getOrderTotalCost(order)
					if err != nil {
						// TODO: wrap error with RuleError for overflow
						return 0, 0, nil, err
					}

					// Validate that order total cost is an uint64.
					if !orderTotalCost.IsUint64() {
						// TODO: replace with Rule Error Invalid Price or Quantity
						panic("Invalid order total cost")
					}

					// Buyer with open bid order doesn't have enough $DESO.
					// Don't include and mark their order for deletion.
					if desoBalanceNanos < orderTotalCost.Uint64() {
						// If order creator doesn't have enough DESO to cover bid order,
						// then delete their bid order.
						globalDesoBalance, err := bav.GetDeSoBalanceNanosForPublicKey(bav.GetPublicKeyForPKID(order.TransactorPKID))

						if err != nil {
							return 0, 0, nil, err
						}

						if globalDesoBalance < orderTotalCost.Uint64() {
							deletedDAOCoinLimitOrders = append(deletedDAOCoinLimitOrders, order)
							bav._deleteDAOCoinLimitOrderEntryMappings(order)
						}

						continue
					}
				} else if order.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin {
					// We currently don't support DAO coins as the denominated type.
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
				} else {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
				}
			}

			// Update order quantities.
			var daoCoinsToTransfer *uint256.Int
			orderIsComplete := false

			if requestedOrder.Quantity.Lt(order.Quantity) {
				// Since the transactor order's quantity is less than the matching order's
				// quantity, we will be transferring the transactor order's quantity.
				daoCoinsToTransfer = requestedOrder.Quantity

				// Update matching order's quantity and store.
				order.Quantity = uint256.NewInt().Sub(order.Quantity, requestedOrder.Quantity)
				bav._setDAOCoinLimitOrderEntryMappings(order)

				// Set transactor order's quantity to zero.
				requestedOrder.Quantity = uint256.NewInt()

				// Mark order is complete to braek out of loop.
				orderIsComplete = true
			} else {
				daoCoinsToTransfer = order.Quantity
				requestedOrder.Quantity = uint256.NewInt().Sub(requestedOrder.Quantity, order.Quantity)
				deletedDAOCoinLimitOrders = append(deletedDAOCoinLimitOrders, order)
				bav._deleteDAOCoinLimitOrderEntryMappings(order)

				if requestedOrder.Quantity.IsZero() {
					orderIsComplete = true
				}
			}

			// Find or create DAO coin balance entries.
			prevRequesterCurrentBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(requestedOrder.TransactorPKID, requestedOrder.DAOCoinCreatorPKID, true)
			prevMatchingBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(order.TransactorPKID, order.DAOCoinCreatorPKID, true)

			var newRequesterBalanceEntry *BalanceEntry
			var newMatchingBalanceEntry *BalanceEntry

			if prevRequesterCurrentBalanceEntry == nil || prevRequesterCurrentBalanceEntry.isDeleted {
				newRequesterBalanceEntry = &BalanceEntry{
					HODLerPKID:   requestedOrder.TransactorPKID,
					CreatorPKID:  requestedOrder.DenominatedCoinCreatorPKID,
					BalanceNanos: *uint256.NewInt(),
				}
			} else {
				newRequesterBalanceEntry = prevRequesterCurrentBalanceEntry.Copy()
			}

			if prevMatchingBalanceEntry == nil || prevMatchingBalanceEntry.isDeleted {
				newMatchingBalanceEntry = &BalanceEntry{
					HODLerPKID:   order.TransactorPKID,
					CreatorPKID:  order.DenominatedCoinCreatorPKID,
					BalanceNanos: *uint256.NewInt(),
				}
			} else {
				newMatchingBalanceEntry = prevMatchingBalanceEntry.Copy()
			}

			// Transfer DAO coins.
			prevMatchingBalanceEntries = append(prevMatchingBalanceEntries, prevMatchingBalanceEntry)

			if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
				// Requested ask order:
				// Send DAO coins from requesterBalanceEntry to matchedBalanceEntry.
				newRequesterBalanceEntry.BalanceNanos = *uint256.NewInt().Sub(&newRequesterBalanceEntry.BalanceNanos, daoCoinsToTransfer)
				newMatchingBalanceEntry.BalanceNanos = *uint256.NewInt().Add(&newMatchingBalanceEntry.BalanceNanos, daoCoinsToTransfer)
			}

			if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
				// Send DAO coins from matchedBalanceEntry to requesterBalanceEntry.
				// Requested bid order:
				newMatchingBalanceEntry.BalanceNanos = *uint256.NewInt().Sub(&newMatchingBalanceEntry.BalanceNanos, daoCoinsToTransfer)
				newRequesterBalanceEntry.BalanceNanos = *uint256.NewInt().Add(&newRequesterBalanceEntry.BalanceNanos, daoCoinsToTransfer)
			}

			bav._setDAOCoinBalanceEntryMappings(newRequesterBalanceEntry)
			bav._setDAOCoinBalanceEntryMappings(newMatchingBalanceEntry)

			// Track how much denominated coin to transfer.
			var denominatedCoinToTransfer *uint256.Int
			denominatedCoinToTransfer, err = _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
				daoCoinsToTransfer, order.PriceNanosPerDenominatedCoin)

			if err != nil {
				// TODO: wrap with rule error describing overflow
				return 0, 0, nil, err
			}

			if requestedOrder.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO {
				if !denominatedCoinToTransfer.IsUint64() {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidPrice
				}

				desoToTransfer := denominatedCoinToTransfer.Uint64()
				var inputPKID PKID
				var outputPKID PKID

				if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
					inputPKID = *order.TransactorPKID
					outputPKID = *requestedOrder.TransactorPKID
				} else if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
					inputPKID = *requestedOrder.TransactorPKID
					outputPKID = *order.TransactorPKID
				} else {
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedOperationType
				}

				if _, exists := pkidToOutputDesoNanos[outputPKID]; !exists {
					pkidToOutputDesoNanos[outputPKID] = 0
				}

				// TODO: rename pkidToNetDesoBalanceNanos to pkidToDESOChangeNanos

				// Check for underflow in user sending $DESO.
				if pkidToNetDesoBalanceNanos[inputPKID] < desoToTransfer {
					// TODO: revisit rule error
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenBidOrder
				}

				pkidToNetDesoBalanceNanos[inputPKID] -= desoToTransfer

				// Check for overflow in user receiving $DESO.
				if pkidToOutputDesoNanos[outputPKID] > math.MaxUint64-desoToTransfer {
					// TODO: revisit rule error --> have specified too big of an order
					return 0, 0, nil, RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenBidOrder
				}

				pkidToOutputDesoNanos[outputPKID] += desoToTransfer
			} else if requestedOrder.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin {
				// TODO: DAO coin denominated types not supported yet.
				return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
			} else {
				return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
			}

			// Break if order is complete.
			if orderIsComplete {
				break
			}
		}

		// If order is fulfilled, done.
		if requestedOrder.Quantity.IsZero() {
			break
		}

		// Else requested order is still not fully fulfilled, so loop.
		lastSeenOrder = prevMatchingOrders[len(prevMatchingOrders)-1]
		prevMatchingOrders, _ = bav._getNextLimitOrdersToFill(requestedOrder, lastSeenOrder)
	}

	// If requested order is still not fully fulfilled, submit it to be stored.
	if requestedOrder.Quantity.GtUint64(0) {
		bav._setDAOCoinLimitOrderEntryMappings(requestedOrder)
	}

	// Create UTXOs.

	// UTXOs representing payments.
	for pkid, desoNanos := range pkidToOutputDesoNanos {
		err = createUTXO(desoNanos, bav.GetPublicKeyForPKID(&pkid), UtxoTypeDAOCoinLimitOrderPayout)

		if err != nil {
			return 0, 0, nil, err
		}
	}

	// UTXOs representing leftover change from input UTXOs after users make payments.
	for pkid, balanceNanos := range pkidToNetDesoBalanceNanos {
		// We don't generate a change output for the transactor since
		// that is handled by the basic transfer.
		if reflect.DeepEqual(pkid, *requestedOrder.TransactorPKID) {
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
		PrevTransactorBalanceEntry:           prevRequesterBalanceEntry,
		PrevTransactorDAOCoinLimitOrderEntry: prevOrder,
		PrevBalanceEntries:                   prevMatchingBalanceEntries,
		PrevDAOCoinLimitOrderEntries:         deletedDAOCoinLimitOrders,
		SpentUtxoEntries:                     spentUtxoEntries,
		DAOCoinLimitOrderPaymentUtxoKeys:     daoCoinLimitOrderPaymentUtxoKeys,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _getNextLimitOrdersToFill(
	requestedOrder *DAOCoinLimitOrderEntry, lastSeenOrder *DAOCoinLimitOrderEntry) (
	[]*DAOCoinLimitOrderEntry, error) {
	// Get matching limit order entries from database.
	dbAdapter := DbAdapter{
		badgerDb:   bav.Handle,
		postgresDb: bav.Postgres,
	}

	orders, err := dbAdapter.GetMatchingDAOCoinLimitOrders(requestedOrder, lastSeenOrder)

	if err != nil {
		return nil, err
	}

	// Update UTXO with relevant limit order entries from database.
	for _, order := range orders {
		orderKey := order.ToMapKey()

		if _, exists := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderKey]; !exists {
			bav._setDAOCoinLimitOrderEntryMappings(order)
		}
	}

	// Aggregate all applicable orders then sort.
	sortedOrders := []*DAOCoinLimitOrderEntry{}

	// 1. Aggregate orders.
	for _, order := range bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry {
		if order.isDeleted {
			continue
		}

		if requestedOrder.DenominatedCoinType != order.DenominatedCoinType {
			continue
		}

		if requestedOrder.OperationType == order.OperationType {
			continue
		}

		// Ask: reject if requestedOrder.PriceNanos > order.PriceNanos
		// I.e. requestedOrder.PriceNanosPerDenominatedCoin < order.PriceNanosPerDenominatedCoin
		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
			// We should have seen this order already.
			if lastSeenOrder != nil && order.IsBetterBidThan(lastSeenOrder) {
				continue
			}
			if requestedOrder.PriceNanosPerDenominatedCoin.Lt(order.PriceNanosPerDenominatedCoin) {
				continue
			}
		}

		// Bid: reject if requestedOrder.PriceNanos < order.PriceNanos
		// I.e. requestedOrder.PriceNanosPerDenominatedCoin > order.PriceNanosPerDenominatedCoin
		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
			// We should have seen this order already
			if lastSeenOrder != nil && order.IsBetterAskThan(lastSeenOrder) {
				continue
			}
			if requestedOrder.PriceNanosPerDenominatedCoin.Gt(order.PriceNanosPerDenominatedCoin) {
				continue
			}
		}

		if !reflect.DeepEqual(requestedOrder.DenominatedCoinCreatorPKID, order.DenominatedCoinCreatorPKID) {
			continue
		}

		if !reflect.DeepEqual(requestedOrder.DAOCoinCreatorPKID, order.DAOCoinCreatorPKID) {
			continue
		}

		sortedOrders = append(sortedOrders, order)
	}

	// 2. Sort orders by best matching.
	// Sort logic first looks at price, then block height (FIFO), then quantity (lowest first).
	sort.Slice(sortedOrders, func(ii, jj int) bool {
		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
			// If requested order is an ask, we want to sort by the best bids.
			return sortedOrders[ii].IsBetterBidThan(sortedOrders[jj])
		}

		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
			// If requested order is a bid, we want to sort by the best asks.
			return sortedOrders[ii].IsBetterAskThan(sortedOrders[jj])
		}

		return false
	})

	// Pull orders up to the when the quantity is fulfilled or we run out of orders.
	includedOrders := []*DAOCoinLimitOrderEntry{}
	requestedQuantity := requestedOrder.Quantity

	for _, order := range sortedOrders {
		includedOrders = append(includedOrders, order)
		requestedQuantity = uint256.NewInt().Sub(requestedQuantity, order.Quantity)

		if requestedQuantity.LtUint64(0) {
			break
		}
	}

	return includedOrders, nil
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

	if prevTransactorOrderEntry != nil {
		// If previous transactor order entry is not null, set it
		// which overwrites whatever is currently stored there.
		bav._setDAOCoinLimitOrderEntryMappings(prevTransactorOrderEntry)
	} else {
		// Else, we need to explicitly delete the requested order entry
		// from this transaction.
		transactorOrderEntry := txMeta.ToEntry(transactorPKID, blockHeight)
		bav._deleteDAOCoinLimitOrderEntryMappings(transactorOrderEntry)
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
			return errors.Wrapf(err, "_disconnectDAOCoinLimitOrder: Problem unAdding utxo %v: ", paymentUtxoKey)
		}
	}

	// Un-spend spent UTXOs.
	if txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
		// Un-spending UTXOs on behalf of the matching bid orders.
		for ii := len(operationData.SpentUtxoEntries) - 1; ii >= 0; ii-- {
			spentUtxoEntry := operationData.SpentUtxoEntries[ii]

			if err := bav._unSpendUtxo(spentUtxoEntry); err != nil {
				return errors.Wrapf(err, "_disconnectDAOCoinLimitOrder: Problem unSpending utxo %v: ", spentUtxoEntry)
			}
		}
	} else if txMeta.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
		if len(operationData.SpentUtxoEntries) > 0 {
			return errors.New("_disconnectDAOCoinLimitOrder: unspent UTXO entries for bid" +
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

	orderKey := entry.ToMapKey()
	bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderKey] = entry
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

func _getOrderTotalCost(order *DAOCoinLimitOrderEntry) (*uint256.Int, error) {
	return _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(order.Quantity, order.PriceNanosPerDenominatedCoin)
}

// TotalCost = Quantity * (Nanos / DenominatedCoin) * ( 1 / PriceNanosPerDenominatedCoin )
func _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
	quantity *uint256.Int, priceNanosPerDenominatedCoin *uint256.Int) (
	*uint256.Int, error) {
	totalCostBigInt := big.NewInt(0).Mul(quantity.ToBig(), big.NewInt(int64(NanosPerUnit)))
	totalCostBigInt = big.NewInt(0).Div(totalCostBigInt, priceNanosPerDenominatedCoin.ToBig())
	totalCost, totalCostOverflow := uint256.FromBig(totalCostBigInt)
	if totalCostOverflow {
		return nil, fmt.Errorf("Order overflows uint256")
	}
	return totalCost, nil
}
