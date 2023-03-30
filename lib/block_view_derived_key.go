package lib

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
	"reflect"
	"strconv"
)

// _verifyAccessSignature verifies if the accessSignature is correct. Valid
// accessSignature is the signed hash of (derivedPublicKey + expirationBlock)
// in DER format, made with the ownerPublicKey.
func _verifyAccessSignature(ownerPublicKey []byte, derivedPublicKey []byte,
	expirationBlock uint64, accessSignature []byte, blockHeight uint32, params *DeSoParams) error {

	// Sanity-check and convert ownerPublicKey to *btcec.PublicKey.
	if err := IsByteArrayValidPublicKey(ownerPublicKey); err != nil {
		return errors.Wrapf(err, "_verifyAccessSignature: Problem parsing owner public key")
	}

	// Sanity-check and convert derivedPublicKey to *btcec.PublicKey.
	if err := IsByteArrayValidPublicKey(derivedPublicKey); err != nil {
		return errors.Wrapf(err, "_verifyAccessSignature: Problem parsing derived public key")
	}

	// Compute a hash of derivedPublicKey+expirationBlock.
	expirationBlockBytes := EncodeUint64(expirationBlock)
	accessBytes := append(derivedPublicKey, expirationBlockBytes[:]...)
	return _verifyBytesSignature(ownerPublicKey, accessBytes, accessSignature, blockHeight, params)
}

// _verifyAccessSignatureWithTransactionSpendingLimit verifies if the accessSignature is correct. Valid
// accessSignature is the signed hash of (derivedPublicKey + expirationBlock + transaction spending limit)
// in DER format, made with the ownerPublicKey.
func _verifyAccessSignatureWithTransactionSpendingLimit(ownerPublicKey []byte, derivedPublicKey []byte, expirationBlock uint64,
	transactionSpendingLimitBytes []byte, accessSignature []byte, blockHeight uint64, params *DeSoParams) error {

	// Sanity-check and convert ownerPublicKey to *btcec.PublicKey.
	if err := IsByteArrayValidPublicKey(ownerPublicKey); err != nil {
		return errors.Wrapf(err, "_verifyAccessSignatureWithTransactionSpendingLimit: Problem parsing owner public key")
	}

	// Sanity-check and convert derivedPublicKey to *btcec.PublicKey.
	if err := IsByteArrayValidPublicKey(derivedPublicKey); err != nil {
		return errors.Wrapf(err, "_verifyAccessSignatureWithTransactionSpendingLimit: Problem parsing derived public key")
	}

	if len(transactionSpendingLimitBytes) == 0 {
		return fmt.Errorf("_verifyAccessSignatureWithTransactionSpendingLimit: Transaction Spending limit object is required")
	}
	transactionSpendingLimit := &TransactionSpendingLimit{}
	rr := bytes.NewReader(transactionSpendingLimitBytes)
	// This error is fine because transaction should fail anyway if spending limit cannot be decoded.
	if err := transactionSpendingLimit.FromBytes(blockHeight, rr); err != nil {
		return errors.Wrapf(err, "Error decoding transaction spending limit from extra data")
	}

	// Check if signature matches Access Bytes Encoding 1.0
	// Assemble standard access signature of derivedPublicKey || expirationBlock || transactionSpendingLimits
	expirationBlockBytes := EncodeUint64(expirationBlock)
	accessBytes := append(derivedPublicKey, expirationBlockBytes[:]...)
	accessBytes = append(accessBytes, transactionSpendingLimitBytes[:]...)
	verifySignature := _verifyBytesSignature(ownerPublicKey, accessBytes, accessSignature, uint32(blockHeight), params)
	if verifySignature == nil {
		return nil
	}

	// Check if signature matches Access Bytes Encoding 2.0
	// Assemble access bytes that use Metamask-compatible strings.
	accessBytes = AssembleAccessBytesWithMetamaskStrings(derivedPublicKey, expirationBlock, transactionSpendingLimit, params)
	verifySignatureNew := _verifyBytesSignature(ownerPublicKey, accessBytes, accessSignature, uint32(blockHeight), params)
	if verifySignatureNew != nil {
		return fmt.Errorf("Failed to verify signature under all possible encodings. Access Bytes Encoding 1.0 "+
			"Error: %v. Access Bytes Encoding 2.0 Error: %v", verifySignature, verifySignatureNew)
	}
	return nil
}

// AssembleAccessBytesWithMetamaskStrings constructs Access Bytes Encoding 2.0. It encodes the derived key access bytes into a
// Metamask-compatible string. There are three components of a derived key that comprise the access bytes, it is the
// derived public key, expiration block, and transaction spending limit. We encode these three into a single string that
// is unique, displays nicely, and can be signed with MetaMask. This is intended to be an equivalent alternative to the
// standard Access Bytes Encoding 1.0.
func AssembleAccessBytesWithMetamaskStrings(derivedPublicKey []byte, expirationBlock uint64,
	transactionSpendingLimit *TransactionSpendingLimit, params *DeSoParams) []byte {

	encodingString := "DECENTRALIZED SOCIAL\n\n"
	encodingString += "Your derived public key: " + Base58CheckEncode(derivedPublicKey, false, params) + "\n\n"
	encodingString += "The expiration block of your key: " + strconv.FormatUint(expirationBlock, 10) + "\n\n"
	encodingString += transactionSpendingLimit.ToMetamaskString(params)
	return []byte(encodingString)
}

func (bav *UtxoView) _connectAuthorizeDerivedKey(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < bav.Params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight {
		return 0, 0, nil, RuleErrorDerivedKeyBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeAuthorizeDerivedKey {
		return 0, 0, nil, fmt.Errorf(
			"_connectAuthorizeDerivedKey: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}

	txMeta := txn.TxnMeta.(*AuthorizeDerivedKeyMetadata)

	// Validate the operation type.
	if txMeta.OperationType != AuthorizeDerivedKeyOperationValid &&
		txMeta.OperationType != AuthorizeDerivedKeyOperationNotValid {
		return 0, 0, nil, fmt.Errorf(
			"_connectAuthorizeDerivedKey: called with bad OperationType %s",
			txn.TxnMeta.GetTxnType().String())
	}

	// Make sure transaction hasn't expired.
	if txMeta.ExpirationBlock <= uint64(blockHeight) {
		return 0, 0, nil, RuleErrorAuthorizeDerivedKeyExpiredDerivedPublicKey
	}

	// Validate the owner public key.
	ownerPublicKey := txn.PublicKey
	if len(ownerPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorAuthorizeDerivedKeyInvalidOwnerPublicKey
	}
	if _, err := btcec.ParsePubKey(ownerPublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(
			RuleErrorAuthorizeDerivedKeyInvalidOwnerPublicKey, err.Error())
	}

	// Validate the derived public key.
	derivedPublicKey := txMeta.DerivedPublicKey
	if err := IsByteArrayValidPublicKey(derivedPublicKey); err != nil {
		return 0, 0, nil, errors.Wrap(
			RuleErrorAuthorizeDerivedKeyInvalidDerivedPublicKey, err.Error())
	}

	// Get current (previous) derived key entry. We might revert to it later so we copy it.
	prevDerivedKeyEntry := bav.GetDerivedKeyMappingForOwner(ownerPublicKey, derivedPublicKey)

	// Authorize transactions can be signed by both owner and derived keys. However, this
	// poses a risk in a situation where a malicious derived key, which has previously been
	// de-authorized by the owner, were to attempt to re-authorize itself.
	// To prevent this, the following check completely blocks a derived key once it has been
	// de-authorized. This makes the lifecycle of a derived key more controllable.
	if prevDerivedKeyEntry != nil && !prevDerivedKeyEntry.isDeleted {
		if prevDerivedKeyEntry.OperationType == AuthorizeDerivedKeyOperationNotValid {
			return 0, 0, nil, RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey
		}
	}

	var extraData map[string][]byte
	if blockHeight >= bav.Params.ForkHeights.ExtraDataOnEntriesBlockHeight {
		var prevExtraData map[string][]byte
		if prevDerivedKeyEntry != nil && !prevDerivedKeyEntry.isDeleted {
			prevExtraData = prevDerivedKeyEntry.ExtraData
		}
		extraData = mergeExtraData(prevExtraData, txn.ExtraData)
	}

	// This is the new state of transaction spending limits after merging in the transaction spending limit object
	// defined in extra data
	var newTransactionSpendingLimit *TransactionSpendingLimit
	var memo []byte
	if blockHeight >= bav.Params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight {
		// TODO: Break the logic in this if out into its own function at some point.

		// Extract TransactionSpendingLimit from extra data
		// We need to merge the new transaction spending limit struct into the old one
		//
		// This will get overwritten if there's an existing spending limit struct.
		//
		// ====== Access Group Fork ======
		// We set the mappings for access group map and access group member map to avoid nil pointer reference in
		// validation checks such as unlimited spending limit. This won't affect the spending limit prior to the fork
		// block height because the entry will always be encoded based on the current block height.
		newTransactionSpendingLimit = &TransactionSpendingLimit{
			TransactionCountLimitMap:     make(map[TxnType]uint64),
			CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
			DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
			NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
			DAOCoinLimitOrderLimitMap:    make(map[DAOCoinLimitOrderLimitKey]uint64),
			AssociationLimitMap:          make(map[AssociationLimitKey]uint64),
			AccessGroupMap:               make(map[AccessGroupLimitKey]uint64),
			AccessGroupMemberMap:         make(map[AccessGroupMemberLimitKey]uint64),
		}
		if prevDerivedKeyEntry != nil && !prevDerivedKeyEntry.isDeleted {
			// Copy the existing transaction spending limit.
			newTransactionSpendingLimitCopy := *prevDerivedKeyEntry.TransactionSpendingLimitTracker
			newTransactionSpendingLimit = &newTransactionSpendingLimitCopy
			memo = prevDerivedKeyEntry.Memo
		}
		// This is the transaction spending limit object passed in the extra data field. This is required for verifying the
		// signature later.
		var transactionSpendingLimit *TransactionSpendingLimit
		var transactionSpendingLimitBytes []byte
		if txn.ExtraData != nil {
			// Only overwrite the memo if the key exists in extra data
			if blockHeight >= bav.Params.ForkHeights.AssociationsAndAccessGroupsBlockHeight {
				if memoBytes, exists := txn.ExtraData[DerivedKeyMemoKey]; exists {
					memo = memoBytes
				}
			} else if memoBytes, exists := txn.ExtraData[DerivedPublicKey]; exists {
				memo = memoBytes
			}
			exists := false
			// If the transaction spending limit key exists, parse it and merge it into the existing transaction
			// spending limit tracker.
			if transactionSpendingLimitBytes, exists = txn.ExtraData[TransactionSpendingLimitKey]; exists {
				// ====== Access Group Fork ======
				// We've previously set access group mappings; however, to/from byte encoding/decoding will never overwrite these
				// mappings prior to the fork blockheight.
				transactionSpendingLimit = &TransactionSpendingLimit{}
				rr := bytes.NewReader(transactionSpendingLimitBytes)
				if err := transactionSpendingLimit.FromBytes(uint64(blockHeight), rr); err != nil {
					return 0, 0, nil, errors.Wrapf(
						err, "Error decoding transaction spending limit from extra data")
				}

				isUnlimited, err := bav.CheckIfValidUnlimitedSpendingLimit(transactionSpendingLimit, blockHeight)
				if err != nil {
					return 0, 0, nil, errors.Wrapf(err,
						"_connectAuthorizeDerivedKey: invalid unlimited spending limit")
				}

				// A valid unlimited spending limit object only has the IsUnlimited field set.
				newTransactionSpendingLimit.IsUnlimited = isUnlimited
				if !newTransactionSpendingLimit.IsUnlimited {

					// TODO: how can we serialize this in a way that we don't have to specify it everytime
					// Always overwrite the global DESO limit...
					newTransactionSpendingLimit.GlobalDESOLimit = transactionSpendingLimit.GlobalDESOLimit
					// Iterate over transaction types and update the counts. Delete keys if the transaction count is zero.
					for txnType, transactionCount := range transactionSpendingLimit.TransactionCountLimitMap {
						if transactionCount == 0 {
							delete(newTransactionSpendingLimit.TransactionCountLimitMap, txnType)
						} else {
							newTransactionSpendingLimit.TransactionCountLimitMap[txnType] = transactionCount
						}
					}
					for ccLimitKey, transactionCount := range transactionSpendingLimit.CreatorCoinOperationLimitMap {
						if transactionCount == 0 {
							delete(newTransactionSpendingLimit.CreatorCoinOperationLimitMap, ccLimitKey)
						} else {
							newTransactionSpendingLimit.CreatorCoinOperationLimitMap[ccLimitKey] = transactionCount
						}
					}
					for daoCoinLimitKey, transactionCount := range transactionSpendingLimit.DAOCoinOperationLimitMap {
						if transactionCount == 0 {
							delete(newTransactionSpendingLimit.DAOCoinOperationLimitMap, daoCoinLimitKey)
						} else {
							newTransactionSpendingLimit.DAOCoinOperationLimitMap[daoCoinLimitKey] = transactionCount
						}
					}
					for nftLimitKey, transactionCount := range transactionSpendingLimit.NFTOperationLimitMap {
						if transactionCount == 0 {
							delete(newTransactionSpendingLimit.NFTOperationLimitMap, nftLimitKey)
						} else {
							newTransactionSpendingLimit.NFTOperationLimitMap[nftLimitKey] = transactionCount
						}
					}
					for daoCoinLimitOrderLimitKey, transactionCount := range transactionSpendingLimit.DAOCoinLimitOrderLimitMap {
						if transactionCount == 0 {
							delete(newTransactionSpendingLimit.DAOCoinLimitOrderLimitMap, daoCoinLimitOrderLimitKey)
						} else {
							newTransactionSpendingLimit.DAOCoinLimitOrderLimitMap[daoCoinLimitOrderLimitKey] = transactionCount
						}
					}

					// ====== Associations And Access Groups Fork ======
					// Note that we don't really need to gate this logic by the blockheight because the to/from bytes
					// encoding/decoding will never overwrite these maps prior to the fork blockheight. We do it
					// anyway as a sanity-check.
					if blockHeight >= bav.Params.ForkHeights.AssociationsAndAccessGroupsBlockHeight {
						for associationLimitKey, transactionCount := range transactionSpendingLimit.AssociationLimitMap {
							// Validate association spending limit.
							if blockHeight >= bav.Params.ForkHeights.AssociationsDerivedKeySpendingLimitBlockHeight &&
								associationLimitKey.AppScopeType == AssociationAppScopeTypeAny &&
								!associationLimitKey.AppPKID.IsZeroPKID() {
								return 0, 0, nil, errors.New("error creating Association spending limit: cannot specify an AppPublicKey if ScopeType is Any")
							}
							if transactionCount == 0 {
								delete(newTransactionSpendingLimit.AssociationLimitMap, associationLimitKey)
							} else {
								newTransactionSpendingLimit.AssociationLimitMap[associationLimitKey] = transactionCount
							}
						}
						for accessGroupLimitKey, transactionCount := range transactionSpendingLimit.AccessGroupMap {
							if transactionCount == 0 {
								delete(newTransactionSpendingLimit.AccessGroupMap, accessGroupLimitKey)
							} else {
								newTransactionSpendingLimit.AccessGroupMap[accessGroupLimitKey] = transactionCount
							}
						}
						for accessGroupMemberLimitKey, transactionCount := range transactionSpendingLimit.AccessGroupMemberMap {
							if transactionCount == 0 {
								delete(newTransactionSpendingLimit.AccessGroupMemberMap, accessGroupMemberLimitKey)
							} else {
								newTransactionSpendingLimit.AccessGroupMemberMap[accessGroupMemberLimitKey] = transactionCount
							}
						}
					}
				}
			}
		}
		// We skip verifying the access signature if the transaction is signed by the owner.
		_, isDerived, err := IsDerivedSignature(txn, blockHeight)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAuthorizeDerivedKey: "+
				"It looks like this transaction was signed with a derived key, but the signature is malformed: ")
		}
		if isDerived {
			if err = _verifyAccessSignatureWithTransactionSpendingLimit(
				ownerPublicKey,
				derivedPublicKey,
				txMeta.ExpirationBlock,
				transactionSpendingLimitBytes,
				txMeta.AccessSignature,
				uint64(blockHeight),
				bav.Params); err != nil {

				return 0, 0, nil, errors.Wrap(
					RuleErrorAuthorizeDerivedKeyAccessSignatureNotValid, err.Error())
			}
		}
	} else {
		// Verify that the access signature is valid. This means the derived key is authorized.
		if err := _verifyAccessSignature(ownerPublicKey, derivedPublicKey,
			txMeta.ExpirationBlock, txMeta.AccessSignature, blockHeight, bav.Params); err != nil {
			return 0, 0, nil, errors.Wrap(
				RuleErrorAuthorizeDerivedKeyAccessSignatureNotValid, err.Error())
		}
	}

	// At this point we've verified the access signature, which means the derived key is authorized
	// to sign on behalf of the owner. In particular, if this authorize transaction was signed
	// by the derived key, we would accept it. We accommodate this by adding a temporary derived
	// key entry to UtxoView, to support first-time derived keys (they don't exist in the DB yet).
	// As a result, and if the derived key is present in transaction's ExtraData, we will
	// pass signature verification in _connectBasicTransfer() -> _verifySignature().
	//
	// NOTE: Setting a mapping in UtxoView prior to fully validating a transaction shouldn't be
	// reproduced elsewhere. It's error-prone, controversial, some even call it "a dirty hack!"
	// All considered, this feature greatly simplifies the flow in identity - from the moment you
	// generate a derived key, you can use it to sign any transaction offline, including authorize
	// transactions. It also resolves issues in situations where the owner account has insufficient
	// balance to submit an authorize transaction.
	derivedKeyEntry := DerivedKeyEntry{
		OwnerPublicKey:   *NewPublicKey(ownerPublicKey),
		DerivedPublicKey: *NewPublicKey(derivedPublicKey),
		ExpirationBlock:  txMeta.ExpirationBlock,
		// See comment above for why we're hardcoding OperationValid here.
		OperationType:                   AuthorizeDerivedKeyOperationValid,
		TransactionSpendingLimitTracker: newTransactionSpendingLimit,
		Memo:                            memo,
		ExtraData:                       extraData,
		isDeleted:                       false,
	}
	bav._setDerivedKeyMapping(&derivedKeyEntry)

	// Call _connectBasicTransfer() to verify txn signature.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		// Since we've failed, we revert the UtxoView mapping to what it was previously.
		// We're doing this manually because we've set a temporary entry in UtxoView.
		bav._deleteDerivedKeyMapping(&derivedKeyEntry)
		bav._setDerivedKeyMapping(prevDerivedKeyEntry)
		return 0, 0, nil, errors.Wrapf(err, "_connectAuthorizeDerivedKey: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		// Since we've failed, we revert the UtxoView mapping to what it was previously.
		// We're doing this manually because we've set a temporary entry in UtxoView.
		bav._deleteDerivedKeyMapping(&derivedKeyEntry)
		bav._setDerivedKeyMapping(prevDerivedKeyEntry)
		return 0, 0, nil, RuleErrorAuthorizeDerivedKeyRequiresNonZeroInput
	}

	// If we're past the derived key spending limit block height, we actually need to fetch the derived key
	// entry again since the basic transfer reduced the txn count on the derived key txn
	if blockHeight >= bav.Params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight {
		derivedKeyEntry = *bav.GetDerivedKeyMappingForOwner(ownerPublicKey, derivedPublicKey)
	}

	// Earlier we've set a temporary derived key entry that had OperationType set to Valid.
	// So if the txn metadata had OperationType set to NotValid, we update the entry here.
	bav._deleteDerivedKeyMapping(&derivedKeyEntry)
	derivedKeyEntry.OperationType = txMeta.OperationType
	bav._setDerivedKeyMapping(&derivedKeyEntry)

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the owner key or the derived key.
	}

	// Add an operation to the list at the end indicating we've authorized a derived key.
	// Also add the prevDerivedKeyEntry for disconnecting.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                OperationTypeAuthorizeDerivedKey,
		PrevDerivedKeyEntry: prevDerivedKeyEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectAuthorizeDerivedKey(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a AuthorizeDerivedKey operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeAuthorizeDerivedKey {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey: Trying to revert "+
			"OperationTypeAuthorizeDerivedKey but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	txMeta := currentTxn.TxnMeta.(*AuthorizeDerivedKeyMetadata)
	prevDerivedKeyEntry := utxoOpsForTxn[operationIndex].PrevDerivedKeyEntry

	// Sanity check that txn public key is valid. Assign this public key to ownerPublicKey.
	var ownerPublicKey []byte
	if len(currentTxn.PublicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid public key: %v", currentTxn.PublicKey)
	}
	_, err := btcec.ParsePubKey(currentTxn.PublicKey, btcec.S256())
	if err != nil {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid public key: %v", err)
	}
	ownerPublicKey = currentTxn.PublicKey

	// Sanity check that derived key is valid. Assign this key to derivedPublicKey.
	var derivedPublicKey []byte
	if len(txMeta.DerivedPublicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid derived key: %v", txMeta.DerivedPublicKey)
	}
	_, err = btcec.ParsePubKey(txMeta.DerivedPublicKey, btcec.S256())
	if err != nil {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid derived key: %v", err)
	}
	derivedPublicKey = txMeta.DerivedPublicKey

	// Get the derived key entry. If it's nil or is deleted then we have an error.
	derivedKeyEntry := bav.GetDerivedKeyMappingForOwner(ownerPublicKey, derivedPublicKey)
	if derivedKeyEntry == nil || derivedKeyEntry.isDeleted {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey: DerivedKeyEntry for "+
			"public key %v, derived key %v was found to be nil or deleted: %v",
			PkToString(ownerPublicKey, bav.Params), PkToString(derivedPublicKey, bav.Params),
			derivedKeyEntry)
	}

	// If we had a previous derivedKeyEntry set then compare it with the current entry.
	if prevDerivedKeyEntry != nil && !prevDerivedKeyEntry.isDeleted {
		// Sanity check public keys. This should never fail.
		if !reflect.DeepEqual(ownerPublicKey, prevDerivedKeyEntry.OwnerPublicKey[:]) {
			return fmt.Errorf("_disconnectAuthorizeDerivedKey: Owner public key in txn "+
				"differs from that in previous derivedKeyEntry (%v %v)", prevDerivedKeyEntry.OwnerPublicKey, ownerPublicKey)
		}
		if !reflect.DeepEqual(derivedPublicKey, prevDerivedKeyEntry.DerivedPublicKey[:]) {
			return fmt.Errorf("_disconnectAuthorizeDerivedKey: Derived public key in txn "+
				"differs from that in existing derivedKeyEntry (%v %v)", prevDerivedKeyEntry.DerivedPublicKey, derivedPublicKey)
		}
	}

	// After the derived key spending limit block height, we need to revert the basic transfer prior to
	// reverting the DerivedKeyEntry mappings because the basic transfer connect logic modifies the
	// transaction spending limit for the derived key entry prior to it being updated in the connect logic for
	// authorize derived key.
	if blockHeight >= bav.Params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight {
		if err = bav._disconnectBasicTransfer(
			currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight); err != nil {
			return err
		}

		// Now that we are confident the derivedKeyEntry lines up with the transaction we're
		// rolling back, delete the mapping from utxoView. We need to do this to prevent
		// a fetch from a db later on.
		bav._deleteDerivedKeyMapping(derivedKeyEntry)

		// Set the previous derivedKeyEntry.
		bav._setDerivedKeyMapping(prevDerivedKeyEntry)
		return nil
	}

	// Now that we are confident the derivedKeyEntry lines up with the transaction we're
	// rolling back, delete the mapping from utxoView. We need to do this to prevent
	// a fetch from a db later on.
	bav._deleteDerivedKeyMapping(derivedKeyEntry)

	// Set the previous derivedKeyEntry.
	bav._setDerivedKeyMapping(prevDerivedKeyEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the authorizeDerivedKey operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
