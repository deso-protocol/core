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

// CanIncreaseBalance checks if the user's balance can be increased by the given amount. If the user's balance + amount
// is less or equal than the provided maxBalance, the increase is allowed. Otherwise, an error is returned.
func (bl *BalanceLedger) CanIncreaseBalance(publicKey PublicKey, amount uint64, maxBalance uint64) error {
	bl.RLock()
	defer bl.RUnlock()

	balance, exists := bl.balances[publicKey]

	// Check for balance overflow.
	if exists && amount > math.MaxUint64-balance {
		return errors.Errorf("CanIncreaseBalance: balance overflow")
	}

	newBalance := balance + amount
	if newBalance > maxBalance {
		return errors.Errorf("CanIncreaseBalance: Not enough balance to cover txn fees "+
			"(newBalance: %d, maxBalance: %d)", newBalance, maxBalance)
	}
	return nil
}

// CanDecreaseBalance checks if the user's balance can be decreased by the given amount. If the user's balance is
// greater or equal to the amount, the decrease is allowed. Otherwise, an error is returned.
func (bl *BalanceLedger) CanDecreaseBalance(publicKey PublicKey, amountNanos uint64) error {
	bl.RLock()
	defer bl.RUnlock()

	balance, exists := bl.balances[publicKey]
	if !exists {
		return errors.Errorf("CanDecreaseBalance: No balance for public key")
	}
	if amountNanos > balance {
		return errors.Errorf("CanDecreaseBalance: Amount exceeds current balance")
	}
	return nil
}

// IncreaseBalance increases the user's balance by the given amount. CanIncreaseBalance should be called before
// calling this function to ensure the increase is allowed.
func (bl *BalanceLedger) IncreaseBalance(publicKey PublicKey, amount uint64) {
	bl.Lock()
	defer bl.Unlock()

	balance, _ := bl.balances[publicKey]
	// Check for balance overflow.
	if amount > math.MaxUint64-balance {
		bl.balances[publicKey] = math.MaxUint64
		return
	}

	bl.balances[publicKey] = balance + amount
}

// DecreaseBalance decreases the user's balance by the given amount. CanDecreaseBalance should be called before
// calling this function to ensure the decrease is allowed.
func (bl *BalanceLedger) DecreaseBalance(publicKey PublicKey, amount uint64) {
	bl.Lock()
	defer bl.Unlock()

	balance, exists := bl.balances[publicKey]
	if !exists {
		return
	}
	// Check for balance underflow.
	if amount > balance {
		delete(bl.balances, publicKey)
		return
	}

	bl.balances[publicKey] = balance - amount
}

// GetBalance returns the user's balance in nanos.
func (bl *BalanceLedger) GetBalance(publicKey PublicKey) uint64 {
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
