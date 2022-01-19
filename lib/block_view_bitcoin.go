package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/pkg/errors"
	"math"
	"math/big"
)

// The blockchain used to store the USD to BTC exchange rate in bav.USDCentsPerBitcoin, which was set by a
// UPDATE_BITCOIN_USD_EXCHANGE_RATE txn, but has since moved to the GlobalParamsEntry, which is set by a
// UPDATE_GLOBAL_PARAMS txn.
func (bav *UtxoView) GetCurrentUSDCentsPerBitcoin() uint64 {
	usdCentsPerBitcoin := bav.USDCentsPerBitcoin
	if bav.GlobalParamsEntry.USDCentsPerBitcoin != 0 {
		usdCentsPerBitcoin = bav.GlobalParamsEntry.USDCentsPerBitcoin
	}
	return usdCentsPerBitcoin
}

func (bav *UtxoView) _existsBitcoinTxIDMapping(bitcoinBurnTxID *BlockHash) bool {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.BitcoinBurnTxIDs[*bitcoinBurnTxID]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return true. If not, return
	// false. Either way, save the value to the in-memory view mapping got later.
	dbHasMapping := DbExistsBitcoinBurnTxID(bav.Handle, bitcoinBurnTxID)
	bav.BitcoinBurnTxIDs[*bitcoinBurnTxID] = dbHasMapping
	return dbHasMapping
}

func (bav *UtxoView) _setBitcoinBurnTxIDMappings(bitcoinBurnTxID *BlockHash) {
	bav.BitcoinBurnTxIDs[*bitcoinBurnTxID] = true
}

func (bav *UtxoView) _deleteBitcoinBurnTxIDMappings(bitcoinBurnTxID *BlockHash) {
	bav.BitcoinBurnTxIDs[*bitcoinBurnTxID] = false
}

func ExtractBitcoinPublicKeyFromBitcoinTransactionInputs(
	bitcoinTransaction *wire.MsgTx, btcdParams *chaincfg.Params) (
	_publicKey *btcec.PublicKey, _err error) {

	for _, input := range bitcoinTransaction.TxIn {
		// P2PKH follows the form: <sig len> <sig> <pubKeyLen> <pubKey>
		if len(input.SignatureScript) == 0 {
			continue
		}
		sigLen := input.SignatureScript[0]
		pubKeyStart := sigLen + 2
		pubKeyBytes := input.SignatureScript[pubKeyStart:]
		addr, err := btcutil.NewAddressPubKey(pubKeyBytes, btcdParams)
		if err != nil {
			continue
		}

		// If we were able to successfully decode the bytes into a public key, return it.
		if addr.PubKey() != nil {
			return addr.PubKey(), nil
		}

		// If we get here it means we could not extract a public key from this
		// particular input. This is OK as long as we can find a public key in
		// one of the other inputs.
	}

	// If we get here it means we went through all the inputs and were not able to
	// successfully decode a public key from the inputs. Error in this case.
	return nil, fmt.Errorf("ExtractBitcoinPublicKeyFromBitcoinTransactionInputs: " +
		"No valid public key found after scanning all input signature scripts")
}

func _computeBitcoinBurnOutput(bitcoinTransaction *wire.MsgTx, bitcoinBurnAddress string,
	btcdParams *chaincfg.Params) (_burnedOutputSatoshis int64, _err error) {

	totalBurnedOutput := int64(0)
	for _, output := range bitcoinTransaction.TxOut {
		class, addresses, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, btcdParams)
		if err != nil {
			// If we hit an error processing an output just let it slide. We only honor
			// P2PKH transactions and even this we do on a best-effort basis.
			//
			// TODO: Run this over a few Bitcoin blocks to see what its errors look like
			// so we can catch them here.
			continue
		}
		// We only allow P2PK and P2PKH transactions to be counted as burns. Allowing
		// anything else would require making this logic more sophisticated. Additionally,
		// limiting the gamut of possible transactions protects us from weird attacks
		// whereby someone could make us think that some Bitcoin was burned when really
		// it's just some fancy script that fools us into thinking that.
		if !(class == txscript.PubKeyTy || class == txscript.PubKeyHashTy) {
			continue
		}
		// We only process outputs if they have a single address in them, which should
		// be the case anyway given the classes we're limiting ourselves to above.
		if len(addresses) != 1 {
			continue
		}

		// At this point we're confident that we're dealing with a nice vanilla
		// P2PK or P2PKH output that contains just one address that its making a
		// simple payment to.

		// Extract the address and add its output to the total if it happens to be
		// equal to the burn address.
		outputAddress := addresses[0]
		if outputAddress.EncodeAddress() == bitcoinBurnAddress {
			// Check for overflow just in case.
			if output.Value < 0 || totalBurnedOutput > math.MaxInt64-output.Value {
				return 0, fmt.Errorf("_computeBitcoinBurnOutput: output value %d would "+
					"overflow totalBurnedOutput %d; this should never happen",
					output.Value, totalBurnedOutput)
			}
			totalBurnedOutput += output.Value
		}
	}

	return totalBurnedOutput, nil
}

func (bav *UtxoView) _connectBitcoinExchange(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if bav.Params.ForkHeights.DeflationBombBlockHeight != 0 &&
		uint64(blockHeight) >= bav.Params.ForkHeights.DeflationBombBlockHeight {

		return 0, 0, nil, RuleErrorDeflationBombForbidsMintingAnyMoreDeSo
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeBitcoinExchange {
		return 0, 0, nil, fmt.Errorf("_connectBitcoinExchange: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMetaa := txn.TxnMeta.(*BitcoinExchangeMetadata)

	// Verify that the the transaction has:
	// - no inputs
	// - no outputs
	// - no public key
	// - no signature
	//
	// For BtcExchange transactions the only thing that should be set is the
	// BitcoinExchange metadata. This is because we derive all of the other
	// fields for this transaction from the underlying BitcoinTransaction in
	// the metadata. Not doing this would potentially open up avenues for people
	// to repackage Bitcoin burn transactions paying themselves rather than the person
	// who originally burned the Bitcoin.
	if len(txn.TxInputs) != 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHaveInputs
	}
	if len(txn.TxOutputs) != 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHaveOutputs
	}
	if len(txn.PublicKey) != 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHavePublicKey
	}
	if txn.Signature != nil {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHaveSignature
	}

	// Check that the BitcoinTransactionHash has not been used in a BitcoinExchange
	// transaction in the past. This ensures that all the Bitcoin that is burned can
	// be converted to DeSo precisely one time. No need to worry about malleability
	// because we also verify that the transaction was mined into a valid Bitcoin block
	// with a lot of work on top of it, which means we can't be tricked by someone
	// twiddling the transaction to give it a different hash (unless the Bitcoin chain
	// is also tricked, in which case we have bigger problems).
	bitcoinTxHash := (BlockHash)(txMetaa.BitcoinTransaction.TxHash())
	if bav._existsBitcoinTxIDMapping(&bitcoinTxHash) {
		return 0, 0, nil, RuleErrorBitcoinExchangeDoubleSpendingBitcoinTransaction
	}

	if verifySignatures {
		// We don't check for signatures and we don't do any checks to verify that
		// the inputs of the BitcoinTransaction are actually entitled to spend their
		// outputs. We get away with this because we check that the transaction
		// was mined into a Bitcoin block with a lot of work on top of it, which
		// would presumably be near-impossible if the Bitcoin transaction were invalid.
	}

	// Extract a public key from the BitcoinTransaction's inputs. Note that we only
	// consider P2PKH inputs to be valid. If no P2PKH inputs are found then we consider
	// the transaction as a whole to be invalid since we don't know who to credit the
	// new DeSo to. If we find more than one P2PKH input, we consider the public key
	// corresponding to the first of these inputs to be the one that will receive the
	// DeSo that will be created.
	publicKey, err := ExtractBitcoinPublicKeyFromBitcoinTransactionInputs(
		txMetaa.BitcoinTransaction, bav.Params.BitcoinBtcdParams)
	if err != nil {
		return 0, 0, nil, RuleErrorBitcoinExchangeValidPublicKeyNotFoundInInputs
	}
	// At this point, we should have extracted a public key from the Bitcoin transaction
	// that we expect to credit the newly-created DeSo to.

	// The burn address cannot create this type of transaction.
	addrFromPubKey, err := btcutil.NewAddressPubKey(
		publicKey.SerializeCompressed(), bav.Params.BitcoinBtcdParams)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("_connectBitcoinExchange: Error "+
			"converting public key to Bitcoin address: %v", err)
	}
	if addrFromPubKey.AddressPubKeyHash().EncodeAddress() == bav.Params.BitcoinBurnAddress {
		return 0, 0, nil, RuleErrorBurnAddressCannotBurnBitcoin
	}

	// Go through the transaction's outputs and count up the satoshis that are being
	// allocated to the burn address. If no Bitcoin is being sent to the burn address
	// then we consider the transaction to be invalid. Watch out for overflow as we do
	// this.
	totalBurnOutput, err := _computeBitcoinBurnOutput(
		txMetaa.BitcoinTransaction, bav.Params.BitcoinBurnAddress,
		bav.Params.BitcoinBtcdParams)
	if err != nil {
		return 0, 0, nil, RuleErrorBitcoinExchangeProblemComputingBurnOutput
	}
	if totalBurnOutput <= 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeTotalOutputLessThanOrEqualZero
	}

	// At this point we know how many satoshis were burned and we know the public key
	// that should receive the DeSo we are going to create.
	usdCentsPerBitcoin := bav.GetCurrentUSDCentsPerBitcoin()
	// Compute the amount of DeSo that we should create as a result of this transaction.
	nanosToCreate := CalcNanosToCreate(bav.NanosPurchased, uint64(totalBurnOutput), usdCentsPerBitcoin)

	// Compute the amount of DeSo that the user will receive. Note
	// that we allocate a small fee to the miner to incentivize her to include the
	// transaction in a block. The fee for BitcoinExchange transactions is fixed because
	// if it weren't then a miner could theoretically repackage the BitcoinTransaction
	// into a new BitcoinExchange transaction that spends all of the newly-created DeSo as
	// a fee. This way of doing it is a bit annoying because it means that for small
	// BitcoinExchange transactions they might have to wait a long time and for large
	// BitcoinExchange transactions they are highly likely to be overpaying. But it has
	// the major benefit that all miners can autonomously scan the Bitcoin chain for
	// burn transactions that they can turn into BitcoinExchange transactions, effectively
	// making it so that the user doesn't have to manage the process of wrapping the
	// Bitcoin burn into a BitcoinExchange transaction herself.
	//
	// We use bigints because we're paranoid about overflow. Realistically, though,
	// it will never happen.
	nanosToCreateBigint := big.NewInt(int64(nanosToCreate))
	bitcoinExchangeFeeBigint := big.NewInt(
		int64(bav.Params.BitcoinExchangeFeeBasisPoints))
	// = nanosToCreate * bitcoinExchangeFeeBps
	nanosTimesFeeBps := big.NewInt(0).Mul(nanosToCreateBigint, bitcoinExchangeFeeBigint)
	// feeNanos = nanosToCreate * bitcoinExchangeFeeBps / 10000
	feeNanosBigint := big.NewInt(0).Div(nanosTimesFeeBps, big.NewInt(10000))
	if feeNanosBigint.Cmp(big.NewInt(math.MaxInt64)) > 0 ||
		nanosToCreate < uint64(feeNanosBigint.Int64()) {

		return 0, 0, nil, RuleErrorBitcoinExchangeFeeOverflow
	}
	feeNanos := feeNanosBigint.Uint64()
	userNanos := nanosToCreate - feeNanos

	// Now that we have all the information we need, save a UTXO allowing the user to
	// spend the DeSo she's purchased in the future.
	outputKey := UtxoKey{
		TxID: *txn.Hash(),
		// We give all UTXOs that are created as a result of BitcoinExchange transactions
		// an index of zero. There is generally only one UTXO created in a BitcoinExchange
		// transaction so this field doesn't really matter.
		Index: 0,
	}
	utxoEntry := UtxoEntry{
		AmountNanos: userNanos,
		PublicKey:   publicKey.SerializeCompressed(),
		BlockHeight: blockHeight,
		UtxoType:    UtxoTypeBitcoinBurn,
		UtxoKey:     &outputKey,
		// We leave the position unset and isSpent to false by default.
		// The position will be set in the call to _addUtxo.
	}
	// If we have a problem adding this utxo return an error but don't
	// mark this block as invalid since it's not a rule error and the block
	// could therefore benefit from being processed in the future.
	newUtxoOp, err := bav._addUtxo(&utxoEntry)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectBitcoinExchange: Problem adding output utxo")
	}

	// Rosetta uses this UtxoOperation to provide INPUT amounts
	var utxoOpsForTxn []*UtxoOperation
	utxoOpsForTxn = append(utxoOpsForTxn, newUtxoOp)

	// Increment NanosPurchased to reflect the total nanos we created with this
	// transaction, which includes the fee paid to the miner. Save the previous
	// value so it can be easily reverted.
	prevNanosPurchased := bav.NanosPurchased
	bav.NanosPurchased += nanosToCreate

	// Add the Bitcoin TxID to our unique mappings
	bav._setBitcoinBurnTxIDMappings(&bitcoinTxHash)

	// Save a UtxoOperation of type OperationTypeBitcoinExchange that will allow
	// us to easily revert NanosPurchased when we disconnect the transaction.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:               OperationTypeBitcoinExchange,
		PrevNanosPurchased: prevNanosPurchased,
	})

	// Note that the fee is implicitly equal to (nanosToCreate - userNanos)
	return nanosToCreate, userNanos, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectUpdateBitcoinUSDExchangeRate(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeUpdateBitcoinUSDExchangeRate {
		return 0, 0, nil, fmt.Errorf("_connectUpdateBitcoinUSDExchangeRate: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*UpdateBitcoinUSDExchangeRateMetadataa)

	// Validate that the exchange rate is not less than the floor as a sanity-check.
	if txMeta.USDCentsPerBitcoin < MinUSDCentsPerBitcoin {
		return 0, 0, nil, RuleErrorExchangeRateTooLow
	}
	if txMeta.USDCentsPerBitcoin > MaxUSDCentsPerBitcoin {
		return 0, 0, nil, RuleErrorExchangeRateTooHigh
	}

	// Validate the public key. Only a paramUpdater is allowed to trigger this.
	_, updaterIsParamUpdater := bav.Params.ParamUpdaterPublicKeys[MakePkMapKey(txn.PublicKey)]
	if !updaterIsParamUpdater {
		return 0, 0, nil, RuleErrorUserNotAuthorizedToUpdateExchangeRate
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUpdateBitcoinUSDExchangeRate: ")
	}

	// Output must be non-zero
	if totalOutput == 0 {
		return 0, 0, nil, RuleErrorUserOutputMustBeNonzero
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which is all we need.
	}

	// Update the exchange rate using the txn metadata. Save the previous value
	// so it can be easily reverted.
	prevUSDCentsPerBitcoin := bav.USDCentsPerBitcoin
	bav.USDCentsPerBitcoin = txMeta.USDCentsPerBitcoin

	// Save a UtxoOperation of type OperationTypeUpdateBitcoinUSDExchangeRate that will allow
	// us to easily revert  when we disconnect the transaction.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                   OperationTypeUpdateBitcoinUSDExchangeRate,
		PrevUSDCentsPerBitcoin: prevUSDCentsPerBitcoin,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectBitcoinExchange(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Check that the last operation has the required OperationType
	operationIndex := len(utxoOpsForTxn) - 1
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectBitcoinExchange: Trying to revert "+
			"%v but utxoOperations are missing",
			OperationTypeBitcoinExchange)
	}
	if utxoOpsForTxn[operationIndex].Type != OperationTypeBitcoinExchange {
		return fmt.Errorf("_disconnectBitcoinExchange: Trying to revert "+
			"%v but found type %v",
			OperationTypeBitcoinExchange, utxoOpsForTxn[operationIndex].Type)
	}
	operationData := utxoOpsForTxn[operationIndex]

	// Get the transaction metadata from the transaction now that we know it has
	// OperationTypeBitcoinExchange.
	txMeta := currentTxn.TxnMeta.(*BitcoinExchangeMetadata)

	// Remove the BitcoinTransactionHash from our TxID mappings since we are
	// unspending it. This makes it so that this hash can be processed again in
	// the future in order to re-grant the public key the DeSo they are entitled
	// to (though possibly more or less than the amount of DeSo they had before
	// because they might execute at a different conversion price).
	bitcoinTxHash := (BlockHash)(txMeta.BitcoinTransaction.TxHash())
	bav._deleteBitcoinBurnTxIDMappings(&bitcoinTxHash)

	// Un-add the UTXO taht was created as a result of this transaction. It should
	// be the one at the end of our UTXO list at this point.
	//
	// The UtxoKey is simply the transaction hash with index zero.
	utxoKey := UtxoKey{
		TxID: *currentTxn.Hash(),
		// We give all UTXOs that are created as a result of BitcoinExchange transactions
		// an index of zero. There is generally only one UTXO created in a BitcoinExchange
		// transaction so this field doesn't really matter.
		Index: 0,
	}
	if err := bav._unAddUtxo(&utxoKey); err != nil {
		return errors.Wrapf(err, "_disconnectBitcoinExchange: Problem unAdding utxo %v: ", utxoKey)
	}

	// Reset NanosPurchased to the value it was before granting this DeSo to this user.
	// This previous value comes from the UtxoOperation data.
	prevNanosPurchased := operationData.PrevNanosPurchased
	bav.NanosPurchased = prevNanosPurchased

	// At this point the BitcoinExchange transaction should be fully reverted.
	return nil
}

func (bav *UtxoView) _disconnectUpdateBitcoinUSDExchangeRate(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Check that the last operation has the required OperationType
	operationIndex := len(utxoOpsForTxn) - 1
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUpdateBitcoinUSDExchangeRate: Trying to revert "+
			"%v but utxoOperations are missing",
			OperationTypeUpdateBitcoinUSDExchangeRate)
	}
	if utxoOpsForTxn[operationIndex].Type != OperationTypeUpdateBitcoinUSDExchangeRate {
		return fmt.Errorf("_disconnectUpdateBitcoinUSDExchangeRate: Trying to revert "+
			"%v but found type %v",
			OperationTypeUpdateBitcoinUSDExchangeRate, utxoOpsForTxn[operationIndex].Type)
	}
	operationData := utxoOpsForTxn[operationIndex]

	// Get the transaction metadata from the transaction now that we know it has
	// OperationTypeUpdateBitcoinUSDExchangeRate.
	txMeta := currentTxn.TxnMeta.(*UpdateBitcoinUSDExchangeRateMetadataa)
	_ = txMeta

	// Reset exchange rate to the value it was before granting this DeSo to this user.
	// This previous value comes from the UtxoOperation data.
	prevUSDCentsPerBitcoin := operationData.PrevUSDCentsPerBitcoin
	bav.USDCentsPerBitcoin = prevUSDCentsPerBitcoin

	// Now revert the basic transfer with the remaining operations. Cut off
	// the UpdateBitcoinUSDExchangeRate operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
