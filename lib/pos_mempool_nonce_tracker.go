package lib

import (
	"sync"
)

// nonceTrackerKey is a private type used by the NonceTracker to index transactions by (public key, nonce) pairs.
// While the chain tracks nonces by (PKID, nonce), or TransactorNonceMapKey, the mempool uses the public key instead.
// This is because the mempool does not update its state on SwapIdentity transactions, unlike the chain. So if NonceTracker
// used PKID to index transactions, there's a possibility some related SwapIdentity gets committed, impacting the current
// NonceTracker's state. This could result in some weirdness of overlapping or outdated (PKID, nonce) pairs.
type nonceTrackerKey struct {
	publicKey PublicKey
	nonce     DeSoNonce
}

func newNonceTrackerKey(publicKey PublicKey, nonce DeSoNonce) nonceTrackerKey {
	return nonceTrackerKey{
		publicKey: publicKey,
		nonce:     nonce,
	}
}

// NonceTracker is a helper struct that is used to track (public key, nonce) pairs in pos mempool.
// It is used to facilitate the "replace by higher fee" feature, which allows users to resubmit transactions.
// If a user submits a transaction with an existing DeSoNonce.PartialID (among this user's transactions in the mempool),
// then the new transaction will replace the old one if the new transaction has a higher fee.
type NonceTracker struct {
	sync.RWMutex

	// nonceMap indexes mempool transactions by (PKID, nonce) pairs.
	nonceMap map[nonceTrackerKey]*MempoolTx
}

func NewNonceTracker() *NonceTracker {
	return &NonceTracker{
		nonceMap: make(map[nonceTrackerKey]*MempoolTx),
	}
}

// GetTxnByPublicKeyNonce returns the transaction with the given public key and nonce pair.
func (pmnt *NonceTracker) GetTxnByPublicKeyNonce(pk PublicKey, nonce DeSoNonce) *MempoolTx {
	pmnt.RLock()
	defer pmnt.RUnlock()

	key := newNonceTrackerKey(pk, nonce)
	txn, _ := pmnt.nonceMap[key]
	return txn
}

// RemoveTxnByPublicKeyNonce removes a (pk, nonce) pair from the nonce tracker.
func (pmnt *NonceTracker) RemoveTxnByPublicKeyNonce(pk PublicKey, nonce DeSoNonce) {
	pmnt.Lock()
	defer pmnt.Unlock()

	key := newNonceTrackerKey(pk, nonce)
	delete(pmnt.nonceMap, key)
}

// AddTxnByPublicKeyNonce adds a new (pk, nonce) -> txn mapping to the nonce tracker.
func (pmnt *NonceTracker) AddTxnByPublicKeyNonce(txn *MempoolTx, pk PublicKey, nonce DeSoNonce) {
	pmnt.Lock()
	defer pmnt.Unlock()

	key := newNonceTrackerKey(pk, nonce)
	pmnt.nonceMap[key] = txn
}

func (pmnt *NonceTracker) Reset() {
	pmnt.Lock()
	defer pmnt.Unlock()

	pmnt.nonceMap = make(map[nonceTrackerKey]*MempoolTx)
}
