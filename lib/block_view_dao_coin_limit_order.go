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

	_, _, _ = totalInput, totalOutput, utxoOpsForTxn

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
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderMissingTransactorPKID
	}

	// Validate DenominatedCoinType is one of our supported enum values and is DESO for now.
	switch txMeta.DenominatedCoinType {
	case DAOCoinLimitOrderEntryDenominatedCoinTypeDESO:
		break
	case DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin:
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
	default:
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType
	}

	// Validate DenominatedCoinCreatorPKID exists and has a profile or is all zeroes if $DESO.
	// TODO

	// Validate DAOCoinCreatorPKID exists and has a profile.
	// TODO

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
	if !txMeta.PriceNanos.Gt(uint256.NewInt()) {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidPrice
	}

	// If denominated in DESO, confirm PriceNanos is uint64.
	if !txMeta.PriceNanos.IsUint64() {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidPrice
	}

	// If denominated in DAO coins, confirm PriceNanos is uint256.
	// TODO

	// Validate quantity > 0.
	if !txMeta.Quantity.Gt(uint256.NewInt()) {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidQuantity
	}

	// Validate quantity is uint64.
	if !txMeta.Quantity.IsUint64() {
		return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidQuantity
	}

	// If DESO buy, validate price * quantity < max uint64.
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO {
		if txMeta.PriceNanos.Uint64()*txMeta.Quantity.Uint64() >= math.MaxUint64 {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidQuantity
		}
	}

	// If DAO coin buy, validate price * quantity < max uint256
	if txMeta.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin {
		if !MaxUint256.Gt(uint256.NewInt().Mul(&txMeta.PriceNanos, &txMeta.Quantity)) {
			return 0, 0, nil, RuleErrorDAOCoinLimitOrderInvalidQuantity
		}
	}

	// Validate transfer restriction status, if Dao coin can only be transferred to whitelisted members.
	// TODO

	// Validate if ask order, that the seller has enough of the DAO coin they're trying to sell.
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
			if desoBalanceNanos < (txMeta.PriceNanos.Uint64() * txMeta.Quantity.Uint64()) {
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
	// TODO

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
	prevOrder, _ := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderKey]

	if prevOrder != nil {
		requestedOrder.Quantity = *uint256.NewInt().Add(&requestedOrder.Quantity, &prevOrder.Quantity)
		bav._deleteDAOCoinLimitOrderEntryMappings(prevOrder)
	}

	// Seek matching orders
	prevMatchingOrders, _ := bav._getNextLimitOrdersToFill(requestedOrder, nil)
	matchingOrders := []*DAOCoinLimitOrderEntry{}

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
				bav._deleteDAOCoinLimitOrderEntryMappings(order)
				continue
			}

			// Seller with open ask order doesn't have enough of the promised DAO coins.
			// Don't include and mark their order for deletion.
			// TODO: maybe we should partially fulfill the order? Maybe less error-prone to just close.
			if balanceEntry.BalanceNanos.Lt(&order.Quantity) {
				bav._deleteDAOCoinLimitOrderEntryMappings(order)
				continue
			}
		}

		// Validate that the buyer has enough $ to buy the DAO coin.
		if order.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
			if order.DenominatedCoinType == DAOCoinLimitOrderEntryDenominatedCoinTypeDESO {
				desoBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(bav.GetPublicKeyForPKID(order.TransactorPKID))

				if err != nil {
					return 0, 0, nil, err
				}

				// Buyer with open bid order doesn't have enough $DESO.
				// Don't include and mark their order for deletion.
				if desoBalanceNanos < (order.PriceNanos.Uint64() * order.Quantity.Uint64()) {
					bav._deleteDAOCoinLimitOrderEntryMappings(order)
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
		var daoCoinsToTransfer uint256.Int

		if requestedOrder.Quantity.Lt(&order.Quantity) {
			daoCoinsToTransfer = requestedOrder.Quantity
			order.Quantity = *uint256.NewInt().Sub(&order.Quantity, &requestedOrder.Quantity)
			requestedOrder.Quantity = *uint256.NewInt()
			break
		} else {
			daoCoinsToTransfer = order.Quantity
			requestedOrder.Quantity = *uint256.NewInt().Sub(&requestedOrder.Quantity, &order.Quantity)
			bav._deleteDAOCoinLimitOrderEntryMappings(order)

			if requestedOrder.Quantity.IsZero() {
				break
			}
		}

		// Find or create balance entries.
		requesterBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(requestedOrder.TransactorPKID, requestedOrder.DAOCoinCreatorPKID, true)
		matchingBalanceEntry := bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(order.TransactorPKID, order.DAOCoinCreatorPKID, true)

		if requesterBalanceEntry == nil || requesterBalanceEntry.isDeleted {
			requesterBalanceEntry = &BalanceEntry{
				HODLerPKID:   requestedOrder.TransactorPKID,
				CreatorPKID:  requestedOrder.DenominatedCoinCreatorPKID,
				BalanceNanos: *uint256.NewInt(),
			}
		}

		if matchingBalanceEntry == nil || matchingBalanceEntry.isDeleted {
			matchingBalanceEntry = &BalanceEntry{
				HODLerPKID:   order.TransactorPKID,
				CreatorPKID:  order.DenominatedCoinCreatorPKID,
				BalanceNanos: *uint256.NewInt(),
			}
		}

		// Transfer DAO coins.
		prevMatchingBalanceEntries = append(prevMatchingBalanceEntries, matchingBalanceEntry)

		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
			// Requested ask order:
			// Send DAO coins from requesterBalanceEntry to matchedBalanceEntry.
			requesterBalanceEntry.BalanceNanos = *uint256.NewInt().Sub(&requesterBalanceEntry.BalanceNanos, &daoCoinsToTransfer)
			matchingBalanceEntry.BalanceNanos = *uint256.NewInt().Add(&matchingBalanceEntry.BalanceNanos, &daoCoinsToTransfer)
		}

		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
			// Send DAO coins from matchedBalanceEntry to requesterBalanceEntry.
			// Requested bid order:
			matchingBalanceEntry.BalanceNanos = *uint256.NewInt().Sub(&matchingBalanceEntry.BalanceNanos, &daoCoinsToTransfer)
			requesterBalanceEntry.BalanceNanos = *uint256.NewInt().Add(&requesterBalanceEntry.BalanceNanos, &daoCoinsToTransfer)
		}

		bav._setDAOCoinBalanceEntryMappings(requesterBalanceEntry)
		bav._setDAOCoinBalanceEntryMappings(matchingBalanceEntry)
	}

	// If requested order is still not fully fulfilled, submit it to be stored.
	if requestedOrder.Quantity.GtUint64(0) {
		bav._setDAOCoinLimitOrderEntryMappings(requestedOrder)
	}

	// Will have to charge extra for DAO coin transfer

	return 0, 0, nil, nil
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

		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
			err := bav.Handle.View(func(txn *badger.Txn) error {
				var err error
				orders, err = DBGetLowestDAOCoinAskOrders(txn, requestedOrder, lastSeenKey)
				return err
			})

			if err != nil {
				return nil, err
			}
		}
	}

	// Update UTXO with relevant values pulled from Badger.
	for _, order := range orders {
		orderKey := order.ToMapKey()

		if _, exists := bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[orderKey]; !exists {
			bav._setDAOCoinLimitOrderEntryMappings(order)
		}
	}

	// Sort orders by best matching.
	// Sort logic first looks at price, then block height (FIFO), then quantity (lowest first).
	sortedOrders := []*DAOCoinLimitOrderEntry{}

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

		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk &&
			requestedOrder.PriceNanos.Gt(&order.PriceNanos) {
			continue
		}

		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid &&
			requestedOrder.PriceNanos.Lt(&order.PriceNanos) {
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

	sort.Slice(sortedOrders, func(ii, jj int) bool {
		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
			// If requested order is an ask, we want to sort by the best bids.
			return sortedOrders[ii].IsBetterBidThan(sortedOrders[jj])
		}

		if requestedOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
			// If requested order is an bid, we want to sort by the best asks.
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
	// Create a tombstone entry.
	tombstoneEntry := *entry
	tombstoneEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setDAOCoinLimitOrderEntryMappings(&tombstoneEntry)
}
