package lib

import (
	"sync"
)

// NonceTracker is a helper struct that is used to track (public key, nonce) pairs in pos mempool.
// It is used to facilitate the "replace by higher fee" feature, which allows users to resubmit transactions.
// If a user submits a transaction with an existing DeSoNonce.PartialID (among this user's transactions in the mempool),
// then the new transaction will replace the old one if the new transaction has a higher fee.
type NonceTracker struct {
	sync.RWMutex

	// nonceMap indexes mempool transactions by (PKID, nonce) pairs.
	nonceMap map[TransactorNonceMapKey]*MempoolTx
	// latestBlockView is used to get the PKID for a given public key. NonceTracker only needs read-access to the
	// block view, so it isn't necessary to copy the block view before passing it to this struct.
	latestBlockView *UtxoView
}

func NewNonceTracker(latestBlockView *UtxoView) *NonceTracker {
	return &NonceTracker{
		nonceMap:        make(map[TransactorNonceMapKey]*MempoolTx),
		latestBlockView: latestBlockView,
	}
}

// GetTxnByPublicKeyNonce returns the transaction with the given public key and nonce pair.
func (pmnt *NonceTracker) GetTxnByPublicKeyNonce(pk PublicKey, nonce DeSoNonce) *MempoolTx {
	pmnt.RLock()
	defer pmnt.RUnlock()

	nonceKey, ok := pmnt._getNonceKey(pk, nonce)
	if !ok {
		return nil
	}
	txn, _ := pmnt.nonceMap[nonceKey]
	return txn
}

// RemoveTxnByPublicKeyNonce removes a (pk, nonce) pair from the nonce tracker.
func (pmnt *NonceTracker) RemoveTxnByPublicKeyNonce(pk PublicKey, nonce DeSoNonce) {
	pmnt.Lock()
	defer pmnt.Unlock()

	nonceKey, ok := pmnt._getNonceKey(pk, nonce)
	if !ok {
		return
	}

	delete(pmnt.nonceMap, nonceKey)
}

// AddTxnByPublicKeyNonce adds a new (pk, nonce) -> txn mapping to the nonce tracker.
func (pmnt *NonceTracker) AddTxnByPublicKeyNonce(txn *MempoolTx, pk PublicKey, nonce DeSoNonce) {
	pmnt.Lock()
	defer pmnt.Unlock()

	nonceKey, ok := pmnt._getNonceKey(pk, nonce)
	if !ok {
		return
	}

	pmnt.nonceMap[nonceKey] = txn
}

// UpdateLatestBlock updates the latest block view used by the nonce tracker.
func (pmnt *NonceTracker) UpdateLatestBlock(latestBlockView *UtxoView) {
	pmnt.Lock()
	defer pmnt.Unlock()

	pmnt.latestBlockView = latestBlockView
}

func (pmnt *NonceTracker) Reset() {
	pmnt.Lock()
	defer pmnt.Unlock()

	pmnt.nonceMap = make(map[TransactorNonceMapKey]*MempoolTx)
}

// _getNonceKey returns the nonce map key for a given public key and nonce. The function retrieves the PKID for the public key.
func (pmnt *NonceTracker) _getNonceKey(pk PublicKey, nonce DeSoNonce) (TransactorNonceMapKey, bool) {
	pkidEntry := pmnt.latestBlockView.GetPKIDForPublicKey(pk.ToBytes())
	if pkidEntry == nil || pkidEntry.isDeleted || pkidEntry.PKID == nil {
		return TransactorNonceMapKey{}, false
	}

	return NewTransactorNonceMapKey(nonce, *pkidEntry.PKID), true
}
