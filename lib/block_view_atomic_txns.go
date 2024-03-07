package lib

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"reflect"
)

//
// TYPES: AtomicTxnsWrapperMetadata
//

type AtomicTxnsWrapperMetadata struct {
	// The AtomicTxnsWrapperMetadata represents the transaction structure for the
	// TxnTypeAtomicTxnsWrapper transaction type. The transactions in the
	// AtomicTxnsWrapperMetadata.Txns slice are committed atomically in-order on the
	// blockchain. This means either all the transactions with be executed
	// on the blockchain in the order specified or none of the transactions
	// will be executed.
	//
	// The AtomicTxnsWrapperMetadata.Txns field must be a specially formed
	// slice of DeSo transactions to ensure their atomic execution on the blockchain.
	// If this field is not properly structured, the AtomicTxns 'wrapper' transaction
	// will be rejected. The transactions in AtomicTxnsWrapperMetadata.Txns and their corresponding
	// ExtraData must form a circular doubly linked list. The links are embedded in the extra data map as follows:
	// ** Take special note of the encoding schema for the AtomicTxnsChainLength **
	//
	// For the first transaction:
	// AtomicTxnsWrapperMetadata.Txns[0].ExtraData = {
	// 		AtomicTxnsChainLength: 		UintToBuf(uint64(len(AtomicTxnsWrapperMetadata.Txns)))...
	// 		NextAtomicTxnPreHash:  		AtomicTxnsWrapperMetadata.Txns[1].AtomicHash()
	//		PreviousAtomicTxnPreHash: 	AtomicTxnsWrapperMetadata.Txns[len(AtomicTxnsWrapperMetadata.Txns)-1].AtomicHash()
	// }
	//
	// For the ith transaction where 0 < i < len(AtomicTxnsWrapperMetadata.Txns)-1:
	// AtomicTxnsWrapperMetadata.Txns[i].ExtraData = {
	// 		NextAtomicTxnPreHash:  		AtomicTxnsWrapperMetadata.Txns[i+1].AtomicHash()
	//		PreviousAtomicTxnPreHash: 	AtomicTxnsWrapperMetadata.Txns[i-1].AtomicHash()
	// }
	//
	// For the last transaction:
	// AtomicTxnsWrapperMetadata.Txns[len(AtomicTxnsWrapperMetadata.Txns)-1].ExtraData = {
	// 		NextAtomicTxnPreHash:  		AtomicTxnsWrapperMetadata.Txns[0].AtomicHash()
	//		PreviousAtomicTxnPreHash: 	AtomicTxnsWrapperMetadata.Txns[len(AtomicTxnsWrapperMetadata.Txns)-2].AtomicHash()
	// }
	//
	// The "AtomicHash()" function is a special transaction hash taken without consideration for the signature
	// on a transaction as well as certain extra data fields. Otherwise, constructing an atomic transaction
	// would be impossible as deriving the links using MsgDeSoTxn.Hash() would have circular dependencies.
	// The purpose of using the AtomicHash for links is to prevent a malicious 3rd party from injecting or
	// modifying the transactions included in the atomic transaction. This helps ensure the atomicity of the
	// atomic transactions. NOTE: The MsgDeSoTxn.AtomicHash() operation DOES keep the AtomicTxnsChainLength
	// key in the ExtraData map to ensure that start of the chain is not compromised.
	//
	// The AtomicTxnsChainLength key is crucial for pinning the start of the atomic transaction. It's
	// arbitrary and redundant that we use the chains length, but it adds an extra sanity check when
	// connecting the transaction to the blockchain. Without a key representing the starting transaction,
	// a malicious entity could reorder the transactions while still preserving the validity of the hashes
	// in the circularly linked list. The AtomicTxnsChainLength included in the first transaction ensures
	// the transactions are atomically executed in the order specified.
	// NOTE: As a measure to reduce potential mempool divergences, only one transaction can have an
	// AtomicTxnsChainLength key.
	Txns []*MsgDeSoTxn
}

func (txnData *AtomicTxnsWrapperMetadata) GetTxnType() TxnType {
	return TxnTypeAtomicTxnsWrapper
}

func (txnData *AtomicTxnsWrapperMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, UintToBuf(uint64(len(txnData.Txns)))...)
	for _, txn := range txnData.Txns {
		txnBytes, err := txn.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrap(err,
				"AtomicTxnsWrapperMetadata.ToBytes: Problem serializing txn")
		}
		data = append(data, UintToBuf(uint64(len(txnBytes)))...)
		data = append(data, txnBytes...)
	}
	return data, nil
}

func (txnData *AtomicTxnsWrapperMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// Read the number of transactions within the atomic transaction.
	numTxns, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrap(err,
			"AtomicTxnsWrapperMetadata.FromBytes: Problem reading numTxns")
	}
	txnData.Txns, err = SafeMakeSliceWithLength[*MsgDeSoTxn](numTxns)
	if err != nil {
		return errors.Wrap(err, "AtomicTxnsWrapperMetadata.FromBytes: Problem allocating txnData.Txns")
	}

	// Read the transactions.
	for ii := uint64(0); ii < numTxns; ii++ {
		txnData.Txns[ii] = &MsgDeSoTxn{}

		// Figure out how many bytes are associated with the ith transaction.
		numTxnBytes, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrap(err,
				"AtomicTxnsWrapperMetadata.FromBytes: Problem reading number of bytes in transaction")
		}

		// Allocate memory for the transaction bytes to be read into.
		txnBytes, err := SafeMakeSliceWithLength[byte](numTxnBytes)
		if err != nil {
			return errors.Wrap(err,
				"AtomicTxnsWrapperMetadata.FromBytes: Problem allocating bytes for transaction")
		}

		// Read the transaction into the txnBytes memory buffer.
		if _, err = io.ReadFull(rr, txnBytes); err != nil {
			return errors.Wrap(err,
				"AtomicTxnsWrapperMetadata.FromBytes: Problem reading bytes for transaction")
		}

		// Convert the txnBytes buffer to a MsgDeSoTxn struct.
		if err = txnData.Txns[ii].FromBytes(txnBytes); err != nil {
			return errors.Wrap(err,
				"AtomicTxnsWrapperMetadata.FromBytes: Problem parsing transaction bytes")
		}
	}
	return nil
}

func (txnData *AtomicTxnsWrapperMetadata) New() DeSoTxnMetadata {
	return &AtomicTxnsWrapperMetadata{}
}

//
// HELPER FUNCTIONS: MsgDeSoTxn
//

func (msg *MsgDeSoTxn) IsAtomicTxnsInnerTxn() bool {
	// An atomic transaction is qualified by the existence of the NextAtomicTxnPreHash
	// and PreviousAtomicTxnPreHash keys in the ExtraData map.
	if _, keyExists := msg.ExtraData[NextAtomicTxnPreHash]; !keyExists {
		return false
	}
	if _, keyExists := msg.ExtraData[PreviousAtomicTxnPreHash]; !keyExists {
		return false
	}
	return true
}

func (msg *MsgDeSoTxn) AtomicHash() (*BlockHash, error) {
	// Create a duplicate of the transaction to ensure we don't edit the existing transaction.
	msgDuplicate, err := msg.Copy()
	if err != nil {
		return nil, errors.Wrap(err, "MsgDeSoTxn.AtomicHash: Cannot create duplicate transaction")
	}

	// Sanity check that the transaction includes the necessary extra data to be included in an atomic transaction.
	if !msgDuplicate.IsAtomicTxnsInnerTxn() {
		return nil, errors.New("MsgDeSoTxn.AtomicHash: Cannot compute atomic hash on non-atomic transaction")
	}

	// Delete the NextAtomicTxnPreHash and PreviousAtomicTxnPreHash from the ExtraData map.
	delete(msgDuplicate.ExtraData, NextAtomicTxnPreHash)
	delete(msgDuplicate.ExtraData, PreviousAtomicTxnPreHash)

	// Convert the transaction to bytes but do NOT encode the transaction signature.
	preSignature := true
	txBytes, err := msgDuplicate.ToBytes(preSignature)
	if err != nil {
		return nil, errors.Wrap(err, "MsgDeSoTxn.AtomicHash: cannot convert modified transaction to bytes")
	}

	// Return the SHA256 double hash of the resulting bytes.
	return Sha256DoubleHash(txBytes), nil
}

//
// Connect and Disconnect Atomic Txn Logic
//

func (bav *UtxoView) _connectAtomicTxnsWrapper(
	txn *MsgDeSoTxn,
	txHash *BlockHash,
	blockHeight uint32,
	blockTimestampNanoSecs int64,
	verifySignatures bool,
	ignoreUtxos bool,
) (
	_utxoOps []*UtxoOperation,
	_totalInput uint64,
	_totalOutput uint64,
	_fees uint64,
	_err error,
) {
	var utxoOpsForTxn []*UtxoOperation

	// Don't allow the atomic transactions and the wrapper to take up more than half of the block.
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "_connectTransaction: Problem serializing transaction: ")
	}
	txnSizeBytes := uint64(len(txnBytes))
	if txnSizeBytes > bav.Params.MaxBlockSizeBytes/2 {
		return nil, 0, 0, 0, RuleErrorTxnTooBig
	}

	// Validate the connecting block height.
	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight {
		return nil, 0, 0, 0,
			errors.Wrap(RuleErrorAtomicTxnBeforeBlockHeight, "_connectAtomicTxnsWrapper")
	}

	// Validate the transaction metadata type.
	if txn.TxnMeta.GetTxnType() != TxnTypeAtomicTxnsWrapper {
		return nil, 0, 0, 0,
			fmt.Errorf("_connectAtomicTxnsWrapper: TxnMeta type: %v", txn.TxnMeta.GetTxnType().GetTxnString())
	}

	// Verify the wrapper of the transaction. This does not verify the txn.TxnMeta contents, just that
	// the wrapper is well formatted.
	if err := _verifyAtomicTxnsWrapper(txn); err != nil {
		return nil, 0, 0, 0, errors.Wrap(err, "_connectAtomicTxnsWrapper")
	}

	// Extract the metadata from the transaction.
	txMeta := txn.TxnMeta.(*AtomicTxnsWrapperMetadata)

	// Verify the chain of transactions as being not tampered with. This verifies the txn.TxnMeta contents.
	if err := _verifyAtomicTxnsChain(txMeta); err != nil {
		return nil, 0, 0, 0, errors.Wrap(err, "_connectAtomicTxnsWrapper")
	}

	// Execute the internal transactions.
	var innerUtxoOps [][]*UtxoOperation
	var totalInput, totalOutput, totalFees uint64
	for _, innerTxn := range txMeta.Txns {
		// NOTE: By recursively calling _connectNonAtomicTransaction, each inner transaction is checked that
		// it is capable of paying for its own fees as well as having a valid signature.
		innerTxnUtxoOps, txnInput, txnOutput, txnFees, err := bav._connectNonAtomicTransaction(
			innerTxn, txHash, blockHeight, blockTimestampNanoSecs, verifySignatures, ignoreUtxos)
		if err != nil {
			return nil, 0, 0, 0,
				errors.Wrap(err, "_connectAtomicTxnsWrapper")
		}

		// Collect the inner txn utxo ops. We will use these if we ever disconnect.
		innerUtxoOps = append(innerUtxoOps, innerTxnUtxoOps)

		// Collect the input/output/fees to ensure fees are being paid properly.
		totalInput, err = SafeUint64().Add(totalInput, txnInput)
		if err != nil {
			return nil, 0, 0, 0,
				errors.Wrap(err, "_connectAtomicTxnsWrapper")
		}
		totalOutput, err = SafeUint64().Add(totalOutput, txnOutput)
		if err != nil {
			return nil, 0, 0, 0,
				errors.Wrap(err, "_connectAtomicTxnsWrapper")
		}
		totalFees, err = SafeUint64().Add(totalFees, txnFees)
		if err != nil {
			return nil, 0, 0, 0,
				errors.Wrap(err, "_connectAtomicTxnsWrapper")
		}
	}

	// Validate that the internal transactions cumulatively pay enough in fees to
	// cover the atomic transactions AS WELL AS the wrapper.
	if txnSizeBytes != 0 && bav.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB != 0 {
		// Make sure there isn't overflow in the fee.
		if txn.TxnFeeNanos != ((txn.TxnFeeNanos * 1000) / 1000) {
			return nil, 0, 0, 0, RuleErrorOverflowDetectedInFeeRateCalculation
		}
		// If the fee is less than the minimum network fee per KB, return an error.
		if (txn.TxnFeeNanos*1000)/uint64(txnSizeBytes) < bav.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB {
			return nil, 0, 0, 0, RuleErrorTxnFeeBelowNetworkMinimum
		}
	}

	// Construct a UtxoOp for the atomic transactions wrapper.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                   OperationTypeAtomicTxnsWrapper,
		AtomicTxnsInnerUtxoOps: innerUtxoOps,
	})

	return utxoOpsForTxn, totalInput, totalOutput, totalFees, nil
}

func _verifyAtomicTxnsWrapper(txn *MsgDeSoTxn) error {
	// Since the wrapper does not require a public key nor a corresponding signature, we force both
	// the transaction public key to be the ZeroPublicKey and the signature to be nil.
	if !NewPublicKey(txn.PublicKey).IsZeroPublicKey() {
		return RuleErrorAtomicTxnsWrapperPublicKeyMustBeZero
	}
	if txn.Signature.Sign != nil {
		return RuleErrorAtomicTxnsWrapperSignatureMustBeNil
	}

	// We force TxInputs on the wrapper to be empty for several reasons:
	//	(1) This is consistent with the logic found in _connectBasicTransferWithExtraSpend()
	//		that forces TxInputs to be empty following the balance model fork.
	//	(2) Allowing TxInputs to not be empty would lead to an attack vector were the transaction
	//		size may be bloated with random TxInputs that do nothing.
	//	(3) Leads to consistent hashing for the same atomic transaction wrapper and its inner transactions.
	//	(4) It's generally safer to be more restrictive on the transaction structure.
	if len(txn.TxInputs) != 0 {
		return RuleErrorAtomicTxnsWrapperMustHaveZeroInputs
	}

	// We force TxOutputs on the wrapper to be empty even though this field is still used post balance model fork.
	// The reason is this transaction is effectively "signed" by the ZeroPublicKey which is a potential
	// burn address. Hence, allowing TxOutputs to be populated would enable un-burning DESO which we do not want.
	if len(txn.TxOutputs) != 0 {
		return RuleErrorAtomicTxnsWrapperMustHaveZeroOutputs
	}

	// There exists three design options for txn.TxnFeeNanos rules in atomic transaction wrappers:
	//	(1) Force txn.TxnFeeNanos to equal zero.
	//	(2) Force txn.TxnFeeNanos to equal the sum of the internal transaction's txn.TxnFeeNanos fields.
	//	(3) Ignore txn.TxnFeeNanos entirely.
	//
	// Because txn.TxnFeeNanos gets used in several places for non-connection logic (e.g. BMF),
	// it's important to use design option (2) to be consistent across core. This check as a result
	// becomes extremely important in _connectAtomicTxns().
	var totalInnerTxnFees uint64
	var err error
	for _, innerTxn := range txn.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns {
		totalInnerTxnFees, err = SafeUint64().Add(totalInnerTxnFees, innerTxn.TxnFeeNanos)
		if err != nil {
			return RuleErrorAtomicTxnsWrapperHasInternalFeeOverflow
		}
	}
	if txn.TxnFeeNanos != totalInnerTxnFees {
		return RuleErrorAtomicTxnsWrapperMustHaveEqualFeeToInternalTxns
	}

	// Technically, the txn.TxnNonce field could be
	if txn.TxnNonce.ExpirationBlockHeight != 0 || txn.TxnNonce.PartialID != 0 {
		return RuleErrorAtomicTxnsWrapperMustHaveZeroedNonce
	}

	// Since the wrapper is free and modifiable by anyone, we check to ensure the
	// associated ExtraData is empty to prevent free storage on the blockchain.
	if len(txn.ExtraData) != 0 {
		return RuleErrorAtomicTxnsWrapperMustHaveZeroExtraData
	}

	return nil
}

func _verifyAtomicTxnsChain(txnMeta *AtomicTxnsWrapperMetadata) error {
	// Validate:
	//	(1) The inner transactions are not additional redundant atomic transactions wrappers.
	//  (2) The inner transactions are meant to be included in an atomic transaction.
	//	(3) The start point is the first inner transaction and there's only one start point.
	// We also collect the atomic hash of each inner transaction here for convenience.
	var atomicHashes []*BlockHash
	for ii, innerTxn := range txnMeta.Txns {
		// Validate this transaction is not another redundant atomic transaction.
		if innerTxn.TxnMeta.GetTxnType() == TxnTypeAtomicTxnsWrapper {
			return RuleErrorAtomicTxnsHasAtomicTxnsInnerTxn
		}

		// Validate the inner transaction as meant to be included in an atomic transaction.
		if !innerTxn.IsAtomicTxnsInnerTxn() {
			return RuleErrorAtomicTxnsHasNonAtomicInnerTxn
		}

		// Validate the starting point of the atomic transactions chain.
		_, keyExists := innerTxn.ExtraData[AtomicTxnsChainLength]
		if keyExists && ii == 0 {
			return RuleErrorAtomicTxnsMustStartWithChainLength
		}
		if keyExists && ii > 0 {
			return RuleErrorAtomicTxnsHasMoreThanOneStartPoint
		}

		// The error check in AtomicHash() is almost redundant, but we must keep it in the event
		// that the byte buffer for the Sha256 hash fails to allocate. This should almost never
		// occur, and there's more serious issues if it does.
		innerTxnAtomicHash, err := innerTxn.AtomicHash()
		if err != nil {
			return errors.Wrap(err, "_verifyAtomicTxnsChain")
		}
		atomicHashes = append(atomicHashes, innerTxnAtomicHash)
	}

	// Construct special helper functions for circular doubly linked list indexing.
	nextIndex := func(currentIndex int, chainLength int) int {
		// Check for the special case of an atomic chain of length 1.
		if chainLength == 1 {
			return currentIndex
		}
		return (currentIndex + 1) % chainLength
	}
	prevIndex := func(currentIndex int, chainLength int) int {
		// Check for the special case of an atomic chain of length 1.
		if chainLength == 1 {
			return currentIndex
		}

		// Check for the wrap around case.
		if currentIndex == 0 {
			return chainLength - 1
		}
		return currentIndex - 1
	}

	// Validate the chain sequence specified.
	for ii, innerTxn := range txnMeta.Txns {
		// Check the next transaction.
		if !reflect.DeepEqual(
			innerTxn.ExtraData[NextAtomicTxnPreHash],
			atomicHashes[nextIndex(ii, len(txnMeta.Txns))]) {
			return RuleErrorAtomicTxnsHasBrokenChain
		}

		// Check the previous transaction
		if !reflect.DeepEqual(
			innerTxn.ExtraData[PreviousAtomicTxnPreHash],
			atomicHashes[prevIndex(ii, len(txnMeta.Txns))]) {
			return RuleErrorAtomicTxnsHasBrokenChain
		}
	}
	return nil
}

func (bav *UtxoView) _disconnectAtomicTxnsWrapper(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAtomicTxnsWrapper: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1

	// Verify the last operation as being of type OperationTypeAtomicTxns.
	if utxoOpsForTxn[operationIndex].Type != OperationTypeAtomicTxnsWrapper {
		return fmt.Errorf("_disconnectAtomicTxnsWrapper: Trying to revert "+
			"OperationTypeAtomicTxns but found type %v", utxoOpsForTxn[operationIndex].Type)
	}

	// Gather the transaction metadata so we know the internal transactions.
	txMeta := currentTxn.TxnMeta.(*AtomicTxnsWrapperMetadata)

	// Sanity check the AtomicTxns operation exists.
	operationData := utxoOpsForTxn[operationIndex]
	if operationData.AtomicTxnsInnerUtxoOps == nil ||
		len(operationData.AtomicTxnsInnerUtxoOps) != len(txMeta.Txns) {
		return fmt.Errorf("_disconnectAtomicTxnsWrapper: Trying to revert OperationTypeAtomicTxns " +
			"but found nil or mistmatched number of UtxoOps for inner transactions")
	}

	// Disconnect the internal transactions in reverse.
	for ii := len(txMeta.Txns) - 1; ii >= 0; ii-- {
		innerTxn := txMeta.Txns[ii]

		if err := bav.DisconnectTransaction(
			innerTxn,
			innerTxn.Hash(),
			operationData.AtomicTxnsInnerUtxoOps[ii],
			blockHeight); err != nil {
			return errors.Wrapf(err, "_disconnectAtomicTxnsWrapper")
		}
	}

	return nil
}
