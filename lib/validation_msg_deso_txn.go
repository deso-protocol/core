package lib

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"math"
)

type MsgDeSoTxnValidator struct {
	*DeSoParams
	*GlobalParamsEntry
	txn *MsgDeSoTxn
}

func NewMsgDeSoTxnValidator(txn *MsgDeSoTxn, params *DeSoParams, globalParams *GlobalParamsEntry) *MsgDeSoTxnValidator {
	return &MsgDeSoTxnValidator{
		DeSoParams:        params,
		GlobalParamsEntry: globalParams,
		txn:               txn,
	}
}

func (m *MsgDeSoTxnValidator) ValidateTransactionSanityBalanceModel(blockHeight uint64) error {
	// Validate encoding
	if err := m.ValidateEncoding(); err != nil {
		return errors.Wrapf(err, "ValidateTransactionSanityBalanceModel: ")
	}
	// Validate transaction metadata
	if err := m.ValidateTransactionMetadata(); err != nil {
		return errors.Wrapf(err, "ValidateTransactionSanityBalanceModel: ")
	}
	// Validate transaction Hash
	if err := m.ValidateHash(); err != nil {
		return errors.Wrapf(err, "ValidateTransactionSanityBalanceModel: ")
	}
	// Validate public key
	if err := m.ValidatePublicKey(); err != nil {
		return errors.Wrapf(err, "ValidateTransactionSanityBalanceModel: ")
	}
	// Validate transaction is above network's minimal fee
	if err := m.ValidateMinimalNetworkFee(); err != nil {
		return errors.Wrapf(err, "ValidateTransactionSanityBalanceModel: ")
	}
	// Validate transaction is properly formatted according to the balance model
	if err := m.ValidateFormatBalanceModel(blockHeight); err != nil {
		return errors.Wrapf(err, "ValidateTransactionSanityBalanceModel: ")
	}
	return nil
}

func (m *MsgDeSoTxnValidator) ValidateEncoding() error {
	// Validate transaction to/from bytes encoding
	txnBytes, err := m.txn.ToBytes(false)
	if err != nil {
		return fmt.Errorf("ValidateEncoding: Problem encoding transaction: %v", err)
	}
	dummyTxn := &MsgDeSoTxn{}
	err = dummyTxn.FromBytes(txnBytes)
	if err != nil {
		return fmt.Errorf("ValidateEncoding: Problem decoding transaction: %v", err)
	}
	reTxnBytes, err := dummyTxn.ToBytes(false)
	if err != nil {
		return fmt.Errorf("ValidateEncoding: Problem re-encoding transaction: %v", err)
	}
	if !bytes.Equal(txnBytes, reTxnBytes) {
		return fmt.Errorf("ValidateEncoding: Transaction bytes are not equal: %v, %v", txnBytes, reTxnBytes)
	}

	// TODO: Do we want a separate parameter for transaction size? Should it be a part of GlobalDeSoParams?
	// Validate transaction size
	if uint64(len(txnBytes)) > m.MaxBlockSizeBytes/2 {
		return errors.Wrapf(RuleErrorTxnTooBig, "ValidateEncoding: Transaction size %d is greater than "+
			"MaxBlockSizeBytes/2 %d", len(txnBytes), m.MaxBlockSizeBytes/2)
	}
	if uint64(len(txnBytes)) > MaxUnconnectedTxSizeBytes {
		return errors.Wrapf(TxErrorTooLarge, "ValidateEncoding: Transaction size %d is greater than "+
			"MaxUnconnectedTxSizeBytes %d", len(txnBytes), MaxUnconnectedTxSizeBytes)
	}
	return nil
}

func (m *MsgDeSoTxnValidator) ValidateTransactionMetadata() error {
	// Validate that the transaction has correct metadata
	if m.txn.TxnMeta == nil {
		return fmt.Errorf("ValidateTransactionSanityBalanceModel: Transaction is missing TxnMeta")
	}
	if _, err := NewTxnMetadata(m.txn.TxnMeta.GetTxnType()); err != nil {
		return errors.Wrapf(err, "ValidateTransactionSanityBalanceModel: Problem parsing TxnType")
	}
	return nil
}

func (m *MsgDeSoTxnValidator) ValidateHash() error {
	// Validate transaction hash
	if m.txn.Hash() == nil {
		return fmt.Errorf("ValidateTransactionSanityBalanceModel: Problem computing tx hash")
	}
	return nil
}

func (m *MsgDeSoTxnValidator) ValidatePublicKey() error {
	// Validate public key
	if err := IsByteArrayValidPublicKey(m.txn.PublicKey); err != nil {
		return errors.Wrapf(err, "ValidateTransactionSanityBalanceModel: Problem with public key")
	}
	return nil
}

func (m *MsgDeSoTxnValidator) ValidateFormatBalanceModel(blockHeight uint64) error {
	// Validate transaction version
	if m.txn.TxnVersion == DeSoTxnVersion0 {
		return fmt.Errorf("ValidateTransactionSanityBalanceModel: DeSoTxnVersion0 is outdated in balance model")
	}

	if m.txn.TxnNonce == nil {
		return errors.Wrapf(TxErrorNoNonceAfterBalanceModelBlockHeight, "ValidateFormatBalanceModel: Transaction "+
			"does not have a nonce.")
	}
	if m.txn.TxnNonce.ExpirationBlockHeight < blockHeight {
		return errors.Wrapf(TxErrorNonceExpired, "ValidateFormatBalanceModel: Transaction nonce has expired")
	}
	if m.MaxNonceExpirationBlockHeightOffset != 0 &&
		m.txn.TxnNonce.ExpirationBlockHeight > blockHeight+m.MaxNonceExpirationBlockHeightOffset {
		return errors.Wrapf(TxErrorNonceExpirationBlockHeightOffsetExceeded, "ValidateFormatBalanceModel: Transaction "+
			"nonce expiration block height offset exceeded")
	}

	// Verify inputs/outputs.
	if len(m.txn.TxInputs) != 0 {
		return errors.Wrapf(RuleErrorBalanceModelDoesNotUseUTXOInputs, "ValidateTransactionSanityBalanceModel: Balance model "+
			"transactions should not have any inputs")
	}

	// Loop through the outputs and do a few sanity checks.
	var totalOutNanos uint64
	for _, txout := range m.txn.TxOutputs {
		// Check that each output's amount is not bigger than the max as a
		// sanity check.
		if txout.AmountNanos > MaxNanos {
			return errors.Wrapf(RuleErrorOutputExceedsMax, "ValidateTransactionSanityBalanceModel: Output amount %d "+
				"exceeds max %d", txout.AmountNanos, MaxNanos)
		}
		// Check that this output doesn't overflow the total as a sanity
		// check. This is frankly impossible since our maximum limit is
		// not close to the max size of a uint64 but check it nevertheless.
		if totalOutNanos >= math.MaxUint64-txout.AmountNanos {
			return errors.Wrapf(RuleErrorOutputOverflowsTotal, "ValidateTransactionSanityBalanceModel: Output amount %d "+
				"overflows total %d", txout.AmountNanos, totalOutNanos)
		}
		// Check that the total isn't bigger than the max supply.
		if totalOutNanos > MaxNanos {
			return errors.Wrapf(RuleErrorTotalOutputExceedsMax, "ValidateTransactionSanityBalanceModel: Total output "+
				"amount %d exceeds max %d", totalOutNanos, MaxNanos)
		}
	}
	return nil
}

func (m *MsgDeSoTxnValidator) ValidateMinimalNetworkFee() error {
	// Verify the transaction fee
	feeNanosPerKb, err := m.txn.ComputeFeePerKB()
	if err != nil {
		return errors.Wrapf(err, "ValidateTransactionSanityBalanceModel: Problem computing fee per KB")
	}
	if feeNanosPerKb < m.MinimumNetworkFeeNanosPerKB {
		return errors.Wrapf(RuleErrorTxnFeeBelowNetworkMinimum, "ValidateTransactionSanityBalanceModel: Transaction fee "+
			"per KB %d is less than the network minimum %d", feeNanosPerKb, m.MinimumNetworkFeeNanosPerKB)
	}
	return nil
}
