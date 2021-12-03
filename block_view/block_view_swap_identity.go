package block_view

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/network"
	"github.com/deso-protocol/core/types"
	"github.com/pkg/errors"
)

func (bav *UtxoView) _connectSwapIdentity(
	txn *network.MsgDeSoTxn, txHash *types.BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != network.TxnTypeSwapIdentity {
		return 0, 0, nil, fmt.Errorf(
			"_connectSwapIdentity: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*network.SwapIdentityMetadataa)

	// The txn.PublicKey must be paramUpdater
	_, updaterIsParamUpdater := bav.Params.ParamUpdaterPublicKeys[MakePkMapKey(txn.PublicKey)]
	if !updaterIsParamUpdater {
		return 0, 0, nil, types.RuleErrorSwapIdentityIsParamUpdaterOnly
	}

	// call _connectBasicTransfer to verify signatures
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectSwapIdentity: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, types.RuleErrorProfileUpdateRequiresNonZeroInput
	}

	// The "from " public key must be set and valid.
	fromPublicKey := txMeta.FromPublicKey
	if len(fromPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, types.RuleErrorFromPublicKeyIsRequired
	}
	if _, err := btcec.ParsePubKey(fromPublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(types.RuleErrorInvalidFromPublicKey, err.Error())
	}

	// The "to" public key must be set and valid.
	toPublicKey := txMeta.ToPublicKey
	if len(toPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, types.RuleErrorToPublicKeyIsRequired
	}
	if _, err := btcec.ParsePubKey(toPublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(types.RuleErrorInvalidToPublicKey, err.Error())
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// If a profile is associated with either of the public keys then change the public
	// key embedded in the profile. Note that we don't need to delete and re-add the
	// ProfileEntry mappings because everything other than the embedded public key stays
	// the same (basically the public key is the only thing that's de-normalized that we
	// need to manually adjust). Note that we must do this lookup *before* we swap the
	// PKID's or else we're get opposite profiles back.
	fromProfileEntry := bav.GetProfileEntryForPublicKey(fromPublicKey)
	if fromProfileEntry != nil && !fromProfileEntry.isDeleted {
		fromProfileEntry.PublicKey = toPublicKey
	}
	toProfileEntry := bav.GetProfileEntryForPublicKey(toPublicKey)
	if toProfileEntry != nil && !toProfileEntry.isDeleted {
		toProfileEntry.PublicKey = fromPublicKey
	}

	// Get the existing PKID mappings. These are guaranteed to be set (they default to
	// the existing public key if they are unset).
	oldFromPKIDEntry := bav.GetPKIDForPublicKey(fromPublicKey)
	if oldFromPKIDEntry == nil || oldFromPKIDEntry.isDeleted {
		// This should basically never happen since we never delete PKIDs.
		return 0, 0, nil, types.RuleErrorOldFromPublicKeyHasDeletedPKID
	}
	oldToPKIDEntry := bav.GetPKIDForPublicKey(toPublicKey)
	if oldToPKIDEntry == nil || oldToPKIDEntry.isDeleted {
		// This should basically never happen since we never delete PKIDs.
		return 0, 0, nil, types.RuleErrorOldToPublicKeyHasDeletedPKID
	}

	// At this point, we are certain that the *from* and the *to* public keys
	// have valid PKID's.

	// Create copies of the old PKID's so we can safely update the mappings.
	newFromPKIDEntry := *oldFromPKIDEntry
	newToPKIDEntry := *oldToPKIDEntry

	// Swap the PKID's on the entry copies.
	newFromPKIDEntry.PKID = oldToPKIDEntry.PKID
	newToPKIDEntry.PKID = oldFromPKIDEntry.PKID

	// Delete the old mappings for the *from* and *to* PKID's. This isn't really needed
	// because the calls to _setPKIDMappings below will undo the deletions we just did,
	// but we do it to maintain consistency with other functions.
	bav._deletePKIDMappings(oldFromPKIDEntry)
	bav._deletePKIDMappings(oldToPKIDEntry)

	// Set the new mappings for the *from* and *to* PKID's.
	bav._setPKIDMappings(&newFromPKIDEntry)
	bav._setPKIDMappings(&newToPKIDEntry)

	// Postgres doesn't have a concept of PKID Mappings. Instead, we need to save an empty
	// profile with the correct PKID and public key
	if bav.Postgres != nil {
		if fromProfileEntry == nil {
			bav._setProfileEntryMappings(&ProfileEntry{
				PublicKey: toPublicKey,
			})
		}

		if toProfileEntry == nil {
			bav._setProfileEntryMappings(&ProfileEntry{
				PublicKey: fromPublicKey,
			})
		}
	}

	// Rosetta needs to know the current locked deso in each profile so it can model the swap of
	// the creator coins. Rosetta models a swap identity as two INPUTs and two OUTPUTs effectively
	// swapping the balances of total deso locked. If no profile exists, from/to is zero.
	fromNanos := uint64(0)
	if fromProfileEntry != nil {
		fromNanos = fromProfileEntry.CoinEntry.DeSoLockedNanos
	}
	toNanos := uint64(0)
	if toProfileEntry != nil {
		toNanos = toProfileEntry.CoinEntry.DeSoLockedNanos
	}

	// Add an operation to the list at the end indicating we've swapped identities.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypeSwapIdentity,
		// Rosetta fields
		SwapIdentityFromDESOLockedNanos: fromNanos,
		SwapIdentityToDESOLockedNanos:   toNanos,

		// Note that we don't need any metadata on this operation, since the swap is reversible
		// without it.
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectSwapIdentity(
	operationType OperationType, currentTxn *network.MsgDeSoTxn, txnHash *types.BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an SwapIdentity operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectSwapIdentity: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	currentOperation := utxoOpsForTxn[operationIndex]
	if currentOperation.Type != OperationTypeSwapIdentity {
		return fmt.Errorf("_disconnectSwapIdentity: Trying to revert "+
			"OperationTypeSwapIdentity but found type %v",
			currentOperation.Type)
	}

	// Now we know the txMeta is SwapIdentity
	txMeta := currentTxn.TxnMeta.(*network.SwapIdentityMetadataa)

	// Swap the public keys within the profiles back. Note that this *must* be done
	// before the swapping of the PKID mappings occurs. Not doing this would cause
	// the profiles to be fetched inconsistently from the DB.
	fromProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.FromPublicKey)
	if fromProfileEntry != nil && !fromProfileEntry.isDeleted {
		fromProfileEntry.PublicKey = txMeta.ToPublicKey
	}
	toProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ToPublicKey)
	if toProfileEntry != nil && !toProfileEntry.isDeleted {
		toProfileEntry.PublicKey = txMeta.FromPublicKey
	}

	// Get the PKIDEntries for the *from* and *to* public keys embedded in the txn
	oldFromPKIDEntry := bav.GetPKIDForPublicKey(txMeta.FromPublicKey)
	oldToPKIDEntry := bav.GetPKIDForPublicKey(txMeta.ToPublicKey)

	// Create copies of the old entries with swapped PKIDs.
	newFromPKIDEntry := *oldFromPKIDEntry
	newFromPKIDEntry.PKID = oldToPKIDEntry.PKID

	newToPKIDEntry := *oldToPKIDEntry
	newToPKIDEntry.PKID = oldFromPKIDEntry.PKID

	// Delete the old mappings. This isn't strictly necessary since the sets
	// below will overwrite everything, but it keeps us be consistent with other code.
	bav._deletePKIDMappings(oldFromPKIDEntry)
	bav._deletePKIDMappings(oldToPKIDEntry)

	// Set the new mappings for the *from* and *to* PKID's.
	bav._setPKIDMappings(&newFromPKIDEntry)
	bav._setPKIDMappings(&newToPKIDEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the SwapIdentity operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
