package lib

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
)

// ValidateDeSoTxnSanityBalanceModel performs a variety of sanity checks to ensure transaction is correctly formatted
// under the balance model. The test checks pretty much everything, except validating the transaction's signature or
// that the transaction is valid given a BlockView.
func ValidateDeSoTxnSanityBalanceModel(txn *MsgDeSoTxn, blockHeight uint64,
	params *DeSoParams, globalParams *GlobalParamsEntry) error {

	if txn == nil || params == nil || globalParams == nil {
		return fmt.Errorf("ValidateDeSoTxnSanityBalanceModel: Transaction, params, and globalParams cannot be nil")
	}

	// Validate encoding
	if err := ValidateDeSoTxnEncoding(txn, blockHeight, globalParams, params); err != nil {
		return errors.Wrapf(err, "ValidateDeSoTxnSanityBalanceModel: ")
	}
	// Validate transaction metadata
	if err := ValidateDeSoTxnMetadata(txn); err != nil {
		return errors.Wrapf(err, "ValidateDeSoTxnSanityBalanceModel: ")
	}
	// Validate transaction Hash
	if err := ValidateDeSoTxnHash(txn); err != nil {
		return errors.Wrapf(err, "ValidateTransactionSanityBalanceModel: ")
	}
	// Validate public key
	if err := ValidateDeSoTxnPublicKey(txn); err != nil {
		return errors.Wrapf(err, "ValidateDeSoTxnSanityBalanceModel: ")
	}
	// Validate transaction is above network's minimal fee
	if err := ValidateDeSoTxnMinimalNetworkFee(txn, globalParams); err != nil {
		return errors.Wrapf(err, "ValidateDeSoTxnSanityBalanceModel: ")
	}
	// Validate transaction is properly formatted according to the balance model
	if err := ValidateDeSoTxnFormatBalanceModel(txn, blockHeight, globalParams); err != nil {
		return errors.Wrapf(err, "ValidateDeSoTxnSanityBalanceModel: ")
	}
	return nil
}

// ValidateDeSoTxnEncoding validates that the transaction encoding works as expected.
func ValidateDeSoTxnEncoding(
	txn *MsgDeSoTxn,
	blockHeight uint64,
	globalParams *GlobalParamsEntry,
	params *DeSoParams,
) error {
	if txn == nil || params == nil {
		return fmt.Errorf("ValidateDeSoTxnEncoding: Transaction and params cannot be nil")
	}

	// Validate transaction to/from bytes encoding
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return fmt.Errorf("ValidateDeSoTxnEncoding: Problem encoding transaction: %v", err)
	}
	dummyTxn := &MsgDeSoTxn{}
	err = dummyTxn.FromBytes(txnBytes)
	if err != nil {
		return fmt.Errorf("ValidateDeSoTxnEncoding: Problem decoding transaction: %v", err)
	}
	reTxnBytes, err := dummyTxn.ToBytes(false)
	if err != nil {
		return fmt.Errorf("ValidateDeSoTxnEncoding: Problem re-encoding transaction: %v", err)
	}
	if !bytes.Equal(txnBytes, reTxnBytes) {
		return fmt.Errorf("ValidateDeSoTxnEncoding: Transaction bytes are not equal: %v, %v", txnBytes, reTxnBytes)
	}

	// TODO: Do we want a separate parameter for transaction size? Should it be a part of GlobalDeSoParams?
	maxBlockSizeBytes := params.MaxBlockSizeBytesPoW
	if params.IsPoSBlockHeight(blockHeight) {
		maxBlockSizeBytes = MergeGlobalParamEntryDefaults(globalParams, params).MaxBlockSizeBytesPoS
	}
	// Validate transaction size
	if uint64(len(txnBytes)) > maxBlockSizeBytes/2 {
		return errors.Wrapf(RuleErrorTxnTooBig, "ValidateDeSoTxnEncoding: Transaction size %d is greater than "+
			"MaxBlockSizeBytesPoW/2 %d", len(txnBytes), maxBlockSizeBytes/2)
	}
	return nil
}

// ValidateDeSoTxnMetadata validates that the transaction metadata is correctly formatted.
func ValidateDeSoTxnMetadata(txn *MsgDeSoTxn) error {
	if txn == nil || txn.TxnMeta == nil {
		return fmt.Errorf("ValidateDeSoTxnMetadata: Transaction is nil or is missing TxnMeta")
	}
	if _, err := NewTxnMetadata(txn.TxnMeta.GetTxnType()); err != nil {
		return errors.Wrapf(err, "ValidateDeSoTxnMetadata: Problem parsing TxnType")
	}
	return nil
}

// ValidateDeSoTxnHash validates that the transaction hash is correctly computed.
func ValidateDeSoTxnHash(txn *MsgDeSoTxn) error {
	if txn == nil {
		return fmt.Errorf("ValidateDeSoTxnHash: Transaction cannot be nil")
	}

	// Validate transaction hash
	if txn.Hash() == nil {
		return fmt.Errorf("ValidateDeSoTxnHash: Problem computing tx hash")
	}
	return nil
}

// ValidateDeSoTxnPublicKey validates that the transaction public key is correctly formatted.
func ValidateDeSoTxnPublicKey(txn *MsgDeSoTxn) error {
	if txn == nil {
		return fmt.Errorf("ValidateDeSoTxnPublicKey: Transaction cannot be nil")
	}

	// Validate public key
	if err := IsByteArrayValidPublicKey(txn.PublicKey); err != nil {
		return errors.Wrapf(err, "ValidateDeSoTxnPublicKey: Problem with public key")
	}
	return nil
}

// ValidateDeSoTxnFormatBalanceModel validates that the transaction is correctly formatted according to the balance model.
func ValidateDeSoTxnFormatBalanceModel(txn *MsgDeSoTxn, blockHeight uint64, globalParams *GlobalParamsEntry) error {
	var err error

	if txn == nil || globalParams == nil || txn.TxnNonce == nil {
		return fmt.Errorf("ValidateDeSoTxnFormatBalanceModel: Transaction, globalParams, and nonce cannot be nil")
	}

	// Validate transaction version
	if txn.TxnVersion == DeSoTxnVersion0 {
		return fmt.Errorf("ValidateDeSoTxnFormatBalanceModel: DeSoTxnVersion0 is outdated in balance model")
	}

	if txn.TxnNonce == nil {
		return errors.Wrapf(TxErrorNoNonceAfterBalanceModelBlockHeight, "ValidateDeSoTxnFormatBalanceModel: Transaction "+
			"does not have a nonce.")
	}
	if txn.TxnNonce.ExpirationBlockHeight < blockHeight {
		return errors.Wrapf(TxErrorNonceExpired, "ValidateDeSoTxnFormatBalanceModel: Transaction nonce has expired")
	}
	if globalParams.MaxNonceExpirationBlockHeightOffset != 0 &&
		txn.TxnNonce.ExpirationBlockHeight > blockHeight+globalParams.MaxNonceExpirationBlockHeightOffset {
		return errors.Wrapf(TxErrorNonceExpirationBlockHeightOffsetExceeded, "ValidateDeSoTxnFormatBalanceModel: Transaction "+
			"nonce expiration block height offset exceeded")
	}

	// Verify inputs/outputs.
	if len(txn.TxInputs) != 0 {
		return errors.Wrapf(RuleErrorBalanceModelDoesNotUseUTXOInputs, "ValidateDeSoTxnFormatBalanceModel: Balance model "+
			"transactions should not have any inputs")
	}

	// Loop through the outputs and do a few sanity checks.
	var totalOutNanos uint64
	for _, txout := range txn.TxOutputs {
		// Check that each output's amount is not bigger than the max as a
		// sanity check.
		if txout.AmountNanos > MaxNanos {
			return errors.Wrapf(RuleErrorOutputExceedsMax, "ValidateDeSoTxnFormatBalanceModel: Output amount %d "+
				"exceeds max %d", txout.AmountNanos, MaxNanos)
		}
		// Check that this output doesn't overflow the total as a sanity
		// check. This is frankly impossible since our maximum limit is
		// not close to the max size of a uint64 but check it nevertheless.
		if totalOutNanos, err = SafeUint64().Add(totalOutNanos, txout.AmountNanos); err != nil {
			return errors.Wrapf(RuleErrorOutputOverflowsTotal, "ValidateDeSoTxnFormatBalanceModel: Output amount %d "+
				"overflows total %d", txout.AmountNanos, totalOutNanos)
		}
		// Check that the total isn't bigger than the max supply.
		if totalOutNanos > MaxNanos {
			return errors.Wrapf(RuleErrorTotalOutputExceedsMax, "ValidateDeSoTxnFormatBalanceModel: Total output "+
				"amount %d exceeds max %d", totalOutNanos, MaxNanos)
		}
	}
	return nil
}

// ValidateDeSoTxnMinimalNetworkFee validates that the transaction is above the network's minimal fee.
func ValidateDeSoTxnMinimalNetworkFee(txn *MsgDeSoTxn, globalParams *GlobalParamsEntry) error {
	if txn == nil || globalParams == nil {
		return fmt.Errorf("ValidateDeSoTxnMinimalNetworkFee: Transaction and globalParams cannot be nil")
	}

	// Verify the transaction fee
	feeNanosPerKb, err := txn.ComputeFeeRatePerKBNanos()
	if err != nil {
		return errors.Wrapf(err, "ValidateDeSoTxnMinimalNetworkFee: Problem computing fee per KB")
	}
	if feeNanosPerKb < globalParams.MinimumNetworkFeeNanosPerKB {
		return errors.Wrapf(RuleErrorTxnFeeBelowNetworkMinimum, "ValidateDeSoTxnMinimalNetworkFee: Transaction fee "+
			"per KB %d is less than the network minimum %d", feeNanosPerKb, globalParams.MinimumNetworkFeeNanosPerKB)
	}
	return nil
}
