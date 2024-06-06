package lib

import (
	"bytes"

	"golang.org/x/crypto/sha3"

	"github.com/deso-protocol/core/bls"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

//
// TYPES: RandomSeedHash
//

type RandomSeedHash [32]byte

func (randomSeedHash *RandomSeedHash) ToUint256() *uint256.Int {
	return uint256.NewInt().SetBytes(randomSeedHash.ToBytes())
}

func (randomSeedHash *RandomSeedHash) Copy() *RandomSeedHash {
	randomSeedHashCopy := &RandomSeedHash{}
	copy(randomSeedHashCopy[:], randomSeedHash[:])
	return randomSeedHashCopy
}

func (randomSeedHash *RandomSeedHash) Eq(other *RandomSeedHash) bool {
	return bytes.Equal(randomSeedHash.ToBytes(), other.ToBytes())
}

func (randomSeedHash *RandomSeedHash) ToBytes() []byte {
	return randomSeedHash[:]
}

func (randomSeedHash *RandomSeedHash) FromBytes(randomSeedHashBytes []byte) (*RandomSeedHash, error) {
	if len(randomSeedHashBytes) != 32 {
		return nil, errors.Errorf("RandomSeedHash.FromBytes: input has length %d but should have length 32", len(randomSeedHashBytes))
	}
	copy(randomSeedHash[:], randomSeedHashBytes)
	return randomSeedHash, nil
}

func GenerateNextRandomSeedSignature(currentRandomSeedHash *RandomSeedHash, signerPrivateKey *bls.PrivateKey) (*bls.Signature, error) {
	// This function generates a RandomSeedSignature by signing the CurrentRandomSeedHash
	// with the provided bls.PrivateKey. This signature is deterministic: given the same
	// CurrentRandomSeedHash and bls.PrivateKey, the same signature will always be generated.
	randomSeedSignature, err := SignRandomSeedHash(signerPrivateKey, currentRandomSeedHash)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GenerateNextRandomSeedSignature: problem generating RandomSeedSignature: ")
	}
	return randomSeedSignature, nil
}

func SignRandomSeedHash(
	signerPrivateKey *bls.PrivateKey, randomSeedHash *RandomSeedHash,
) (*bls.Signature, error) {
	randomSeedSignature, err := signerPrivateKey.Sign(randomSeedHash[:])
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.SignRandomSeedHash: problem signing CurrentRandomSeedHash: ")
	}
	return randomSeedSignature, nil
}

func (bav *UtxoView) VerifyRandomSeedSignature(
	signerPublicKey *bls.PublicKey,
	randomSeedSignature *bls.Signature,
) (*RandomSeedHash, error) {
	// This function verifies that the provided RandomSeedSignature was signed by the corresponding
	// bls.PrivateKey for the provided bls.PublicKey. If the RandomSeedSignature is invalid, we
	// return an error. If the RandomSeedSignature is valid, we take the SHA256 of it to produce
	// a RandomSeedHash, which is then returned.

	// Verify the RandomSeedSignature.
	currentRandomSeedHash, err := bav.GetCurrentRandomSeedHash()
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.VerifyRandomSeedSignature: problem retrieving CurrentRandomSeedHash: ")
	}
	isVerified, err := verifySignatureOnRandomSeedHash(signerPublicKey, randomSeedSignature, currentRandomSeedHash)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.VerifyRandomSeedSignature: problem verifying RandomSeedSignature: ")
	}
	if !isVerified {
		return nil, errors.Errorf("UtxoView.VerifyRandomSeedSignature: invalid RandomSeedSignature provided")
	}
	return HashRandomSeedSignature(randomSeedSignature)
}

func verifySignatureOnRandomSeedHash(
	signerPublicKey *bls.PublicKey, randomSeedSignature *bls.Signature, randomSeedHash *RandomSeedHash,
) (bool, error) {
	return signerPublicKey.Verify(randomSeedSignature, randomSeedHash[:])
}

func HashRandomSeedSignature(randomSeedSignature *bls.Signature) (*RandomSeedHash, error) {
	// This function takes in a random seed signature and computes the random seed hash for it
	// Convert the RandomSeedSignature to a RandomSeedHash.
	randomSeedSHA256 := sha3.Sum256(randomSeedSignature.ToBytes())
	newRandomSeedHash, err := (&RandomSeedHash{}).FromBytes(randomSeedSHA256[:])
	if err != nil {
		return nil, errors.Wrapf(err, "hashRandomSeedSignature: problem hashing RandomSeedSignature: ")
	}
	return newRandomSeedHash, nil
}

//
// UTXO VIEW UTILS
//

func (bav *UtxoView) GetCurrentRandomSeedHash() (*RandomSeedHash, error) {
	// First, check the UtxoView.
	if bav.CurrentRandomSeedHash != nil {
		return bav.CurrentRandomSeedHash, nil
	}
	// Then, check the db.
	currentRandomSeedHash, err := DBGetCurrentRandomSeedHash(bav.Handle, bav.Snapshot)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetCurrentRandomSeedHash: problem retrieving CurrentRandomSeedHash from the db: ")
	}
	if currentRandomSeedHash != nil {
		// If a RandomSeedHash is found in the db, cache in the UtxoView and return.
		bav.CurrentRandomSeedHash = currentRandomSeedHash.Copy()
		return currentRandomSeedHash, nil
	}
	// If no RandomSeedHash is found in the UtxoView or db, return the
	// GenesisRandomSeedHash which is 32 bytes of zeroes.
	return &RandomSeedHash{}, nil
}

func (bav *UtxoView) _setCurrentRandomSeedHash(randomSeedHash *RandomSeedHash) {
	if randomSeedHash == nil {
		glog.Errorf("UtxoView._setCurrentRandomSeedHash: called with nil entry, this should never happen")
		return
	}
	bav.CurrentRandomSeedHash = randomSeedHash.Copy()
}

func (bav *UtxoView) _flushCurrentRandomSeedHashToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// If CurrentRandomSeedHash is nil, then it was never
	// set and shouldn't overwrite the value in the db.
	if bav.CurrentRandomSeedHash == nil {
		return nil
	}
	return DBPutCurrentRandomSeedHashWithTxn(txn, bav.Snapshot, bav.CurrentRandomSeedHash, blockHeight, bav.EventManager)
}

//
// DB UTILS
//

func DBKeyForCurrentRandomSeedHash() []byte {
	return append([]byte{}, Prefixes.PrefixCurrentRandomSeedHash...)
}

func DBGetCurrentRandomSeedHash(handle *badger.DB, snap *Snapshot) (*RandomSeedHash, error) {
	var ret *RandomSeedHash
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetCurrentRandomSeedHashWithTxn(txn, snap)
		return innerErr
	})
	return ret, err
}

func DBGetCurrentRandomSeedHashWithTxn(txn *badger.Txn, snap *Snapshot) (*RandomSeedHash, error) {
	// Retrieve from db.
	key := DBKeyForCurrentRandomSeedHash()
	currentRandomSeedHashBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetCurrentRandomSeedHashWithTxn: problem retrieving value")
	}
	// Decode from bytes.
	return (&RandomSeedHash{}).FromBytes(currentRandomSeedHashBytes)
}

func DBPutCurrentRandomSeedHashWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	currentRandomSeedHash *RandomSeedHash,
	blockHeight uint64,
	eventManager *EventManager,
) error {
	if currentRandomSeedHash == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutCurrentRandomSeedHashWithTxn: called with nil CurrentRandomSeedHash")
		return nil
	}
	key := DBKeyForCurrentRandomSeedHash()
	return DBSetWithTxn(txn, snap, key, currentRandomSeedHash.ToBytes(), eventManager)
}
