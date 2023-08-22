package lib

import (
	"github.com/pkg/errors"
	"math"
	"sync"
)

// BalanceLedger is a simple in-memory ledger of balances for user public keys. The balances in the ledger can be
// increased or decreased, as long as user's new balance doesn't exceed the user's total max balance.
type BalanceLedger struct {
	sync.RWMutex

	// Map of public keys to balances.
	balances map[PublicKey]uint64
}

func NewBalanceLedger() *BalanceLedger {
	return &BalanceLedger{
		balances: make(map[PublicKey]uint64),
	}
}

// CanIncreaseEntryWithLimit checks if the user's ledger entry can be increased by delta. If the user's
// balance + delta is less or equal than the balanceLimit, the increase is allowed. Otherwise, an error is returned.
func (bl *BalanceLedger) CanIncreaseEntryWithLimit(publicKey PublicKey, delta uint64, balanceLimit uint64) error {
	bl.RLock()
	defer bl.RUnlock()

	balance, exists := bl.balances[publicKey]

	// Check for balance overflow.
	if exists && delta > math.MaxUint64-balance {
		return errors.Errorf("CanIncreaseEntryWithLimit: balance overflow")
	}

	newBalance := balance + delta
	if newBalance > balanceLimit {
		return errors.Errorf("CanIncreaseEntryWithLimit: Balance + delta exceeds balance limit "+
			"(balance: %d, delta %v, balanceLimit: %d)", balance, delta, balanceLimit)
	}
	return nil
}

// IncreaseEntry increases the user's ledger entry by delta. CanIncreaseEntryWithLimit should be called before
// calling this function to ensure the increase is allowed.
func (bl *BalanceLedger) IncreaseEntry(publicKey PublicKey, delta uint64) {
	bl.Lock()
	defer bl.Unlock()

	balance, _ := bl.balances[publicKey]
	// Check for balance overflow.
	if delta > math.MaxUint64-balance {
		bl.balances[publicKey] = math.MaxUint64
		return
	}

	bl.balances[publicKey] = balance + delta
}

// DecreaseEntry decreases the user's ledger entry by delta.
func (bl *BalanceLedger) DecreaseEntry(publicKey PublicKey, delta uint64) {
	bl.Lock()
	defer bl.Unlock()

	balance, exists := bl.balances[publicKey]
	if !exists {
		return
	}
	// Check for balance underflow.
	if delta > balance {
		delete(bl.balances, publicKey)
		return
	}

	bl.balances[publicKey] = balance - delta
}

// GetEntry returns the user's ledger entry.
func (bl *BalanceLedger) GetEntry(publicKey PublicKey) uint64 {
	bl.RLock()
	defer bl.RUnlock()

	balance, _ := bl.balances[publicKey]
	return balance
}

func (bl *BalanceLedger) Reset() {
	bl.Lock()
	defer bl.Unlock()

	bl.balances = make(map[PublicKey]uint64)
}
