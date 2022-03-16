package lib

import (
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"math"
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

	// TODO: in the for loop, when matching orders, send $ to the right person.
	// Create UTXO, append to list of utxoOpsForTxn.

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
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidDAOCoinCreatorPKID
		}
	}

	// If denominated in a DAO coin, validate DenominatedCoinCreatorPKID exists and has a profile.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin {
		profileEntry := bav.GetProfileEntryForPKID(txMeta.DenominatedCoinCreatorPKID)

		if profileEntry == nil || profileEntry.isDeleted {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidDenominatedCoinCreatorPKID
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
	if txMeta.PriceNanos.Cmp(NewFloat()) <= 0 {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidPrice
	}

	// If denominated in $DESO, confirm PriceNanos is uint64.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO && !IsUint64(&txMeta.PriceNanos) {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidPrice
	}

	// If denominated in DAO coins, confirm PriceNanos is uint256.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin && !IsUint256(&txMeta.PriceNanos) {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidPrice
	}

	// Validate quantity > 0.
	if !txMeta.Quantity.Gt(uint256.NewInt()) {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidQuantity
	}

	// Order total cost = price x quantity.
	// Price is a big Float. Quantity is an uint256.
	// Cast Quantity to big Float so can multiply.
	requestedOrderTotalCost := NewFloat().Mul(&txMeta.PriceNanos, NewFloat().SetInt(txMeta.Quantity.ToBig()))

	// If $DESO buy, validate that order total cost is less than the max uint64.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO {
		if !IsUint64(requestedOrderTotalCost) {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidQuantity
		}
	}

	// If DAO coin buy, validate that order total cost is less than the max uint256.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin {
		if !IsUint256(requestedOrderTotalCost) {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidQuantity
		}
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
		if balanceEntry.BalanceNanos.Lt(&txMeta.Quantity) {
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
			requestedOrderTotalCostUint64, _ := requestedOrderTotalCost.Uint64()

			if desoBalanceNanos < requestedOrderTotalCostUint64 {
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

	// TODO: add to UTXO operation.
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
	// TODO: add to UTXO operation.
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
			return errors.Wrapf(err, "_helpConnectNFTSold: Problem adding output utxo")
		}
		daoCoinLimitOrderPaymentUtxoKeys = append(daoCoinLimitOrderPaymentUtxoKeys, outputKey)

		// Rosetta uses this UtxoOperation to provide INPUT amounts
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
		return nil
	}

	// ------ End custom validations

	// Create entry from txn metadata.
	requestedOrder := &DAOCoinLimitOrderEntry{
		TransactorPKID:             transactorPKID,
		DenominatedCoinType:        txMeta.DenominatedCoinType,
		DenominatedCoinCreatorPKID: txMeta.DenominatedCoinCreatorPKID,
		DAOCoinCreatorPKID:         txMeta.DAOCoinCreatorPKID,
		OperationType:              txMeta.OperationType,
		PriceNanos:                 txMeta.PriceNanos,
		BlockHeight:                blockHeight,
		Quantity:                   txMeta.Quantity,
	}

	// Check if you already have an existing order at this price in this block.
	// If exists, update new order with previous order's quantity and mark previous order for deletion.
	// Only have to check UTXO and not Badger because we are only aggregating within the block height.
	orderKey := requestedOrder.ToMapKey()

	// TODO: add to UTXO operation.
	prevOrder, _ := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderKey]

	if prevOrder != nil {
		requestedOrder.Quantity = *uint256.NewInt().Add(&requestedOrder.Quantity, &prevOrder.Quantity)
		bav._deleteDAOCoinLimitOrderEntryMappings(prevOrder)
	}

	// Seek matching orders
	prevMatchingOrders, _ := bav._getNextLimitOrdersToFill(requestedOrder, nil)
	matchingOrders := []*DAOCoinLimitOrderEntry{}
	var lastSeenOrder *DAOCoinLimitOrderEntry

	// Keep track of state in case of reverting txn.
	// TODO: add to UTXO operation.
	deletedDAOCoinLimitOrders := []*DAOCoinLimitOrderEntry{}
	deletedBalanceEntries := []*BalanceEntry{}

	for len(prevMatchingOrders) > 0 {
		// Cache previous state of potential matching orders in case of revert.
		for _, order := range prevMatchingOrders {
			matchingOrders = append(matchingOrders, order.Copy())
		}

		// 1-by-1 match existing orders to the requested order.
		prevMatchingBalanceEntries := []*BalanceEntry{}

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
				if balanceEntry.BalanceNanos.Lt(&order.Quantity) {
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
					// Price is a big Float. Quantity is an uint256.
					// Cast Quantity to big Float so can multiply.
					orderTotalCost := NewFloat().Mul(&order.PriceNanos, NewFloat().SetInt(order.Quantity.ToBig()))

					// Validate that order total cost is an uint64.
					if !IsUint64(orderTotalCost) {
						// TODO: replace with Rule Error Invalid Price or Quantity
						panic("Invalid order total cost")
					}

					// Buyer with open bid order doesn't have enough $DESO.
					// Don't include and mark their order for deletion.
					orderTotalCostUint64, _ := orderTotalCost.Uint64()

					if desoBalanceNanos < orderTotalCostUint64 {
						// If order creator doesn't have enough DESO to cover bid order,
						// then delete their bid order.
						globalDesoBalance, err := bav.GetDeSoBalanceNanosForPublicKey(bav.GetPublicKeyForPKID(order.TransactorPKID))

						if err != nil {
							return 0, 0, nil, err
						}

						if globalDesoBalance < orderTotalCostUint64 {
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

			if requestedOrder.Quantity.Lt(&order.Quantity) {
				daoCoinsToTransfer = &requestedOrder.Quantity
				order.Quantity = *uint256.NewInt().Sub(&order.Quantity, &requestedOrder.Quantity)
				requestedOrder.Quantity = *uint256.NewInt()
				orderIsComplete = true
			} else {
				daoCoinsToTransfer = &order.Quantity
				requestedOrder.Quantity = *uint256.NewInt().Sub(&requestedOrder.Quantity, &order.Quantity)
				deletedDAOCoinLimitOrders = append(deletedDAOCoinLimitOrders, order)
				bav._deleteDAOCoinLimitOrderEntryMappings(order)

				if requestedOrder.Quantity.IsZero() {
					orderIsComplete = true
				}
			}

			// Find or create DAO coin balance entries.
			prevRequesterBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(requestedOrder.TransactorPKID, requestedOrder.DAOCoinCreatorPKID, true)
			prevMatchingBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(order.TransactorPKID, order.DAOCoinCreatorPKID, true)

			var newRequesterBalanceEntry *BalanceEntry
			var newMatchingBalanceEntry *BalanceEntry

			if prevRequesterBalanceEntry == nil || prevRequesterBalanceEntry.isDeleted {
				newRequesterBalanceEntry = &BalanceEntry{
					HODLerPKID:   requestedOrder.TransactorPKID,
					CreatorPKID:  requestedOrder.DenominatedCoinCreatorPKID,
					BalanceNanos: *uint256.NewInt(),
				}
			}

			if prevMatchingBalanceEntry == nil || prevMatchingBalanceEntry.isDeleted {
				newMatchingBalanceEntry = &BalanceEntry{
					HODLerPKID:   order.TransactorPKID,
					CreatorPKID:  order.DenominatedCoinCreatorPKID,
					BalanceNanos: *uint256.NewInt(),
				}
			}

			// Transfer DAO coins.
			// TODO: update to prevMatchingBalanceEntries.
			prevMatchingBalanceEntries = append(prevMatchingBalanceEntries, prevMatchingBalanceEntry)

			if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
				// Requested ask order:
				// Send DAO coins from requesterBalanceEntry to matchedBalanceEntry.
				requesterBalanceEntry.BalanceNanos = *uint256.NewInt().Sub(&requesterBalanceEntry.BalanceNanos, daoCoinsToTransfer)
				matchingBalanceEntry.BalanceNanos = *uint256.NewInt().Add(&matchingBalanceEntry.BalanceNanos, daoCoinsToTransfer)
			}

			if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
				// Send DAO coins from matchedBalanceEntry to requesterBalanceEntry.
				// Requested bid order:
				matchingBalanceEntry.BalanceNanos = *uint256.NewInt().Sub(&matchingBalanceEntry.BalanceNanos, daoCoinsToTransfer)
				requesterBalanceEntry.BalanceNanos = *uint256.NewInt().Add(&requesterBalanceEntry.BalanceNanos, daoCoinsToTransfer)
			}

			bav._setDAOCoinBalanceEntryMappings(requesterBalanceEntry)
			bav._setDAOCoinBalanceEntryMappings(matchingBalanceEntry)

			// Track how much denominated coin to transfer.
			orderPrice := uint256.NewInt()
			orderPriceInt, _ := order.PriceNanos.Int(nil)
			orderPrice.SetFromBig(orderPriceInt)
			denominatedCoinToTransfer := uint256.NewInt().Mul(daoCoinsToTransfer, orderPrice)
			_ = denominatedCoinToTransfer

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

	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypeDAOCoinLimitOrder,
		//TODO: populate with data we need for disconnect
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _getNextLimitOrdersToFill(
	requestedOrder *DAOCoinLimitOrderEntry, lastSeenOrder *DAOCoinLimitOrderEntry) (
	[]*DAOCoinLimitOrderEntry, error) {
	orders := []*DAOCoinLimitOrderEntry{}

	if bav.Postgres != nil {
		// TODO
	} else {
		var lastSeenKey []byte

		if lastSeenOrder != nil {
			lastSeenKey = DBKeyForDAOCoinLimitOrder(lastSeenOrder, false)
		}

		var dbFunc func(*badger.Txn, *DAOCoinLimitOrderEntry, []byte) ([]*DAOCoinLimitOrderEntry, error)

		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
			dbFunc = DBGetHighestDAOCoinBidOrders
		} else if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
			dbFunc = DBGetLowestDAOCoinAskOrders
		} else {
			// TODO: switch to RuleErrorDAOCoinLimitOrderUnsupportedOperationType
			return nil, fmt.Errorf("Invalid operation type")
		}

		err := bav.Handle.View(func(txn *badger.Txn) error {
			var err error
			orders, err = dbFunc(txn, requestedOrder, lastSeenKey)
			return err
		})

		if err != nil {
			return nil, err
		}
	}

	// Update UTXO with relevant values pulled from Badger.
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
		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk &&
			requestedOrder.PriceNanos.Cmp(&order.PriceNanos) > 0 {
			continue
		}

		// Bid: reject if requestedOrder.PriceNanos < order.PriceNanos
		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid &&
			requestedOrder.PriceNanos.Cmp(&order.PriceNanos) < 0 {
			continue
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
		requestedQuantity = *uint256.NewInt().Sub(&requestedQuantity, &order.Quantity)

		if requestedQuantity.LtUint64(0) {
			break
		}
	}

	return includedOrders, nil
}

func (bav *UtxoView) _disconnectDAOCoinLimitOrder(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {
	// TODO
	return nil
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
