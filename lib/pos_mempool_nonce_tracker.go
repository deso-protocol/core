package lib

// PosMempoolNonceTracker is a helper struct that is used to track (public key, nonce) pairs in pos mempool.
// It is used to facilitate the "replace by higher fee" feature, which allows users to resubmit transactions.
// If a user submits a transaction with an existing DeSoNonce.PartialID (among this user's transactions in the mempool),
// then the new transaction will replace the old one if the new transaction has a higher fee.
type PosMempoolNonceTracker struct {
	// nonceMap indexes mempool transactions by (public key, nonce) pairs.
	nonceMap map[PublicKey]map[uint64]*MempoolTx
}

func NewPosMempoolNonceTracker() *PosMempoolNonceTracker {
	return &PosMempoolNonceTracker{
		nonceMap: make(map[PublicKey]map[uint64]*MempoolTx),
	}
}

// GetTxnByPublicKeyNonce returns the transaction with the given public key and nonce pair.
func (pmnt *PosMempoolNonceTracker) GetTxnByPublicKeyNonce(pk PublicKey, nonce uint64) *MempoolTx {
	innerMap, ok := pmnt.nonceMap[pk]
	if !ok {
		return nil
	}
	txn, ok := innerMap[nonce]
	if !ok {
		return nil
	}
	return txn
}

// RemoveTxnByPublicKeyNonce removes a (pk, nonce) pair from the nonce tracker.
func (pmnt *PosMempoolNonceTracker) RemoveTxnByPublicKeyNonce(pk PublicKey, nonce uint64) {
	innerMap, ok := pmnt.nonceMap[pk]
	if !ok {
		return
	}
	delete(innerMap, nonce)
}

// AddTxnByPublicKeyNonce adds a new (pk, nonce) -> txn mapping to the nonce tracker.
func (pmnt *PosMempoolNonceTracker) AddTxnByPublicKeyNonce(pk PublicKey, nonce uint64, txn *MempoolTx) {
	innerMap, ok := pmnt.nonceMap[pk]
	if !ok {
		innerMap = make(map[uint64]*MempoolTx)
		pmnt.nonceMap[pk] = innerMap
	}
	innerMap[nonce] = txn
}

func (pmnt *PosMempoolNonceTracker) Reset() {
	pmnt.nonceMap = make(map[PublicKey]map[uint64]*MempoolTx)
}
