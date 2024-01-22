package lib

import (
	"bytes"
	"fmt"
	"github.com/deso-protocol/core/collections"
	"github.com/pkg/errors"
	"io"
)

type AtomicTxnsMetadata struct {
	Txns []*MsgDeSoTxn
	// TODO: scheme for transactor signing some authorization for their txn to be included in an atomic txn.
	// Option 1: each transactor must sign the list of txn hashes included in Txns. This is pretty extreme and
	// not a great DX.
	// Option 2: each transactor signs the nonce + their index in the atomic txn
	// There are other options out there, but it's all a trade-off between preventing abuse
	// and making the DX good.
}

func (txnData *AtomicTxnsMetadata) GetTotalFee() (uint64, error) {
	fee := uint64(0)
	var err error
	for _, txn := range txnData.Txns {
		if fee, err = SafeUint64().Add(fee, txn.TxnFeeNanos); err != nil {
			return 0, errors.Wrapf(err, "AtomicTxnsMetadata.GetTotalFee: Problem computing fee")
		}
	}
	return fee, nil
}

func (txnData *AtomicTxnsMetadata) GetTxnType() TxnType {
	return TxnTypeAtomicTxns
}

func (txnData *AtomicTxnsMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, UintToBuf(uint64(len(txnData.Txns)))...)
	for _, txn := range txnData.Txns {
		txnBytes, err := txn.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "AtomicTxnsMetadata.ToBytes: Problem serializing txn: ")
		}
		data = append(data, UintToBuf(uint64(len(txnBytes)))...)
		data = append(data, txnBytes...)
	}
	return data, nil
}

func (txnData *AtomicTxnsMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// NumTxns
	numTxns, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrap(err, "AtomicTxnsMetadata.FromBytes: Problem reading NumTxns")
	}
	txnData.Txns, err = SafeMakeSliceWithLength[*MsgDeSoTxn](numTxns)
	if err != nil {
		return errors.Wrap(err, "AtomicTxnsMetadata.FromBytes: Problem allocating Txns")
	}
	for ii := uint64(0); ii < numTxns; ii++ {
		txnData.Txns[ii] = &MsgDeSoTxn{}
		numTxnBytes, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrap(err, "AtomicTxnsMetadata.FromBytes: Problem reading NumTxnBytes")
		}
		txnBytes, err := SafeMakeSliceWithLength[byte](numTxnBytes)
		if err != nil {
			return errors.Wrap(err, "AtomicTxnsMetadata.FromBytes: Problem allocating TxnBytes")
		}
		if _, err = io.ReadFull(rr, txnBytes); err != nil {
			return errors.Wrap(err, "AtomicTxnsMetadata.FromBytes: Problem reading TxnBytes")
		}
		if err = txnData.Txns[ii].FromBytes(txnBytes); err != nil {
			return errors.Wrapf(err, "AtomicTxnsMetadata.FromBytes: Problem parsing txn %d: ", ii)
		}
	}
	return nil
}

func (txnData *AtomicTxnsMetadata) New() DeSoTxnMetadata {
	return &AtomicTxnsMetadata{}
}

func (bav *UtxoView) _connectAtomicTxns(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, blockTimestampNanoSecs int64, verifySignatures bool,
	ignoreUtxos bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error,
) {

	// Verify the transaction is well-formed.
	// TODO: verify

	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight {
		return 0, 0, nil, errors.Wrap(RuleErrorAtomicTxnBeforeBlockHeight, "_connectAtomicTxns")
	}

	if txn.TxnMeta.GetTxnType() != TxnTypeAtomicTxns {
		return 0, 0, nil, fmt.Errorf(
			"_connectAtomicTxns: TxnMeta type: %v", txn.TxnMeta.GetTxnType().GetTxnString())
	}

	var totalInput, totalOutput, totalFees uint64
	var utxoOps []*UtxoOperation
	// Create copy of view. We apply all transactions to the copy first, and then
	// if successful, apply to the real view.
	viewCopy, err := bav.CopyUtxoView()
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAtomicTxns: Problem copying view: ")
	}
	_ = viewCopy
	for _, innerTxn := range txn.TxnMeta.(*AtomicTxnsMetadata).Txns {
		innerTxHash := innerTxn.Hash()
		innerTxBytes, err := innerTxn.ToBytes(false)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAtomicTxns: Problem serializing txn: ")
		}
		// Connect the transaction and update the view.
		innerUtxoOps, innerTotalInput, innerTotalOutput, innerFees, err := viewCopy.ConnectTransaction(
			innerTxn, innerTxHash, int64(len(innerTxBytes)), blockHeight, blockTimestampNanoSecs, verifySignatures, ignoreUtxos,
		)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAtomicTxns: Problem connecting txn: ")
		}
		totalInput, err = SafeUint64().Add(totalInput, innerTotalInput)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAtomicTxns: Problem adding totalInput: ")
		}
		totalOutput, err = SafeUint64().Add(totalOutput, innerTotalOutput)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAtomicTxns: Problem adding totalOutput: ")
		}
		totalFees, err = SafeUint64().Add(totalFees, innerFees)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAtomicTxns: Problem adding totalFees: ")
		}
		finalInnerUtxoOps := collections.Transform(innerUtxoOps, func(op *UtxoOperation) *UtxoOperation {
			op.TxnHash = innerTxHash
			return op
		})
		utxoOps = append(utxoOps, finalInnerUtxoOps...)
	}

	for _, innerTxn := range txn.TxnMeta.(*AtomicTxnsMetadata).Txns {
		innerTxHash := innerTxn.Hash()
		innerTxBytes, err := innerTxn.ToBytes(false)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAtomicTxns: Problem serializing txn: ")
		}
		// Connect the transaction and update the view.
		_, _, _, _, err = bav.ConnectTransaction(
			innerTxn, innerTxHash, int64(len(innerTxBytes)), blockHeight, blockTimestampNanoSecs, verifySignatures, ignoreUtxos,
		)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAtomicTxns: Problem connecting transaction after"+
				" applying to viewCopy: THIS SHOULD NEVER HAPPEN.")
		}
	}

	return totalInput, totalOutput, utxoOps, nil

}

// TODO: more validations
func (bav *UtxoView) _verifyAtomicTxn(txn *MsgDeSoTxn) error {
	// Verify the transaction is well-formed.
	if !NewPublicKey(txn.PublicKey).IsZeroPublicKey() {
		return RuleErrorAtomicTxnPublicKeyMustBeZero
	}

	if len(txn.TxOutputs) != 0 {
		return RuleErrorAtomicTxnMustHaveZeroOutputs
	}

	if txn.TxnFeeNanos != 0 {
		return RuleErrorAtomicTxnMustHaveZeroFee
	}

	if len(txn.ExtraData) != 0 {
		return RuleErrorAtomicTxnMustHaveZeroExtraData
	}

	if txn.TxnMeta.GetTxnType() != TxnTypeAtomicTxns {
		return RuleErrorAtomicTxnMetaTypeMustBeAtomicTxns
	}

	if txn.Signature.Sign != nil {
		return RuleErrorAtomicTxnSignatureMustBeNil
	}

	// No inner transaction can be of type AtomicTransaction
	if collections.Any(txn.TxnMeta.(*AtomicTxnsMetadata).Txns, func(innerTxn *MsgDeSoTxn) bool {
		return innerTxn.TxnMeta.GetTxnType() == TxnTypeAtomicTxns
	}) {
		return RuleErrorAtomicTxnInnerTxnCannotBeAtomicTxn
	}

	return nil
}

func (bav *UtxoView) _disconnectAtomicTxns(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32) error {

	// Verify the transaction is well-formed.
	// TODO: verify

	if blockHeight < bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight {
		return errors.Wrap(RuleErrorAtomicTxnBeforeBlockHeight, "_disconnectAtomicTxns")
	}

	for ii := len(currentTxn.TxnMeta.(*AtomicTxnsMetadata).Txns) - 1; ii >= 0; ii-- {
		innerTxn := currentTxn.TxnMeta.(*AtomicTxnsMetadata).Txns[ii]
		// Disconnect the transaction and update the view.
		utxoOpsForInnerTxn := collections.Filter(utxoOpsForTxn, func(op *UtxoOperation) bool {
			return op.TxnHash.IsEqual(innerTxn.Hash())
		})
		// TODO: Figure out which utxo operations are for THIS txn.
		err := bav.DisconnectTransaction(innerTxn, innerTxn.Hash(), utxoOpsForInnerTxn, blockHeight)
		if err != nil {
			return errors.Wrapf(err, "_disconnectAtomicTxns: Problem disconnecting txn: ")
		}
	}

	return nil
}

func (bc *Blockchain) CreateAtomicTxns(txns []*MsgDeSoTxn, minFeeRateNanosPerKB uint64, mempool Mempool) (
	_txn *MsgDeSoTxn,
	_totalInput uint64,
	_changeAmount uint64,
	_fees uint64,
	_err error) {
	// TODO: huh? what should I really do here?

	// Create the transaction metadata.
	txnMeta := &AtomicTxnsMetadata{
		Txns: txns,
	}

	// Create the transaction.
	txn := &MsgDeSoTxn{
		PublicKey: ZeroPublicKey.ToBytes(),
		TxnMeta:   txnMeta,
	}

	totalInput, _, changeAmount, fee, err := bc.AddInputsAndChangeToTransaction(
		txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateAtomicTxns: ")
	}
	return txn, totalInput, changeAmount, fee, nil
}
