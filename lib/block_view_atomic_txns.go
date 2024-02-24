package lib

import (
	"bytes"
	"github.com/pkg/errors"
	"io"
)

//
// TYPES: AtomicTxnsMetadata
//

type AtomicTxnsMetadata struct {
	// The AtomicTxnsMetadata represents the transaction structure for the
	// TxnTypeAtomicTxns transaction type. The transactions in the
	// AtomicTxnsMetadata.Txns slice are committed atomically in-order on the
	// blockchain. This means either all the transactions with be executed
	// on the blockchain in the order specified or none of the transactions
	// will be executed.
	//
	// The AtomicTxnsMetadata.Txns field must be a specially formed
	// slice of DeSo transactions to ensure their atomic execution on the blockchain.
	// If this field is not properly structured, the AtomicTxns 'wrapper' transaction
	// will be rejected. The transactions in AtomicTxnsMetadata.Txns and their corresponding
	// ExtraData must form a circular doubly linked list. The links are embedded in the extra data map as follows:
	// ** Take special note of the encoding schema for the AtomicTxnsChainLength **
	//
	// For the first transaction:
	// AtomicTxnsMetadata.Txns[0].ExtraData = {
	// 		AtomicTxnsChainLength: 		UintToBuf(uint64(len(AtomicTxnsMetadata.Txns)))...
	// 		NextAtomicTxnPreHash:  		AtomicTxnsMetadata.Txns[1].AtomicHash()
	//		PreviousAtomicTxnPreHash: 	AtomicTxnsMetadata.Txns[len(AtomicTxnsMetadata.Txns)-1].AtomicHash()
	// }
	//
	// For the ith transaction where 0 < i < len(AtomicTxnsMetadata.Txns)-1:
	// AtomicTxnsMetadata.Txns[i].ExtraData = {
	// 		NextAtomicTxnPreHash:  		AtomicTxnsMetadata.Txns[i+1].AtomicHash()
	//		PreviousAtomicTxnPreHash: 	AtomicTxnsMetadata.Txns[i-1].AtomicHash()
	// }
	//
	// For the last transaction:
	// AtomicTxnsMetadata.Txns[len(AtomicTxnsMetadata.Txns)-1].ExtraData = {
	// 		NextAtomicTxnPreHash:  		AtomicTxnsMetadata.Txns[0].AtomicHash()
	//		PreviousAtomicTxnPreHash: 	AtomicTxnsMetadata.Txns[len(AtomicTxnsMetadata.Txns)-2].AtomicHash()
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
	// NOTE: Technically, multiple transactions can include a AtomicTxnsChainLength key in their extra data
	// which would enable the atomic transactions to be possibly reordered. While this is possible,
	// it's not necessarily recommended.
	Txns []*MsgDeSoTxn
}

func (msg *MsgDeSoTxn) IsAtomicTxn() bool {
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
	if !msgDuplicate.IsAtomicTxn() {
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

func (txnData *AtomicTxnsMetadata) GetTxnType() TxnType {
	return TxnTypeAtomicTxns
}

func (txnData *AtomicTxnsMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, UintToBuf(uint64(len(txnData.Txns)))...)
	for _, txn := range txnData.Txns {
		txnBytes, err := txn.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrap(err,
				"AtomicTxnsMetadata.ToBytes: Problem serializing txn")
		}
		data = append(data, UintToBuf(uint64(len(txnBytes)))...)
		data = append(data, txnBytes...)
	}
	return data, nil
}

func (txnData *AtomicTxnsMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// Read the number of transactions within the atomic transaction.
	numTxns, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrap(err,
			"AtomicTxnsMetadata.FromBytes: Problem reading numTxns")
	}
	txnData.Txns, err = SafeMakeSliceWithLength[*MsgDeSoTxn](numTxns)
	if err != nil {
		return errors.Wrap(err, "AtomicTxnsMetadata.FromBytes: Problem allocating txnData.Txns")
	}

	// Read the transactions.
	for ii := uint64(0); ii < numTxns; ii++ {
		txnData.Txns[ii] = &MsgDeSoTxn{}

		// Figure out how many bytes are associated with the ith transaction.
		numTxnBytes, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrap(err,
				"AtomicTxnsMetadata.FromBytes: Problem reading number of bytes in transaction")
		}

		// Allocate memory for the transaction bytes to be read into.
		txnBytes, err := SafeMakeSliceWithLength[byte](numTxnBytes)
		if err != nil {
			return errors.Wrap(err,
				"AtomicTxnsMetadata.FromBytes: Problem allocating bytes for transaction")
		}

		// Read the transaction into the txnBytes memory buffer.
		if _, err = io.ReadFull(rr, txnBytes); err != nil {
			return errors.Wrap(err,
				"AtomicTxnsMetadata.FromBytes: Problem reading bytes for transaction")
		}

		// Convert the txnBytes buffer to a MsgDeSoTxn struct.
		if err = txnData.Txns[ii].FromBytes(txnBytes); err != nil {
			return errors.Wrap(err,
				"AtomicTxnsMetadata.FromBytes: Problem parsing transaction bytes")
		}
	}
	return nil
}

func (txnData *AtomicTxnsMetadata) New() DeSoTxnMetadata {
	return &AtomicTxnsMetadata{}
}
