package lib

import (
	"github.com/pkg/errors"
	"math"
	"sync"
)

// BalanceLedger is a simple in-memory ledger of reserved balances for user public keys. The values in the ledger can be
// increased or decreased, as long as user's reserved balance doesn't exceed the user's spendable balance.
type BalanceLedger struct {
	sync.RWMutex

	// Map of public keys to reserved balances in nanos.
	reservedBalancesNanos map[PublicKey]uint64
}

func NewBalanceLedger() *BalanceLedger {
	return &BalanceLedger{
		reservedBalancesNanos: make(map[PublicKey]uint64),
	}
}

// CheckBalanceIncrease checks if the user's reserved balance can be increased by the given amount. If the user's
// reserved balance + amountNanos is less than their spendableBalanceNanos, the increase is allowed. Otherwise, an error is returned.
func (pml *BalanceLedger) CheckBalanceIncrease(publicKey PublicKey, amountNanos uint64, spendableBalanceNanos uint64) error {
	pml.RLock()
	defer pml.RUnlock()

	reservedBalance, exists := pml.reservedBalancesNanos[publicKey]

	// Check for reserved balance overflow.
	if exists && amountNanos > math.MaxUint64-reservedBalance {
		return errors.Errorf("CheckBalanceIncrease: Reserved balance overflow")
	}

	newReservedBalance := reservedBalance + amountNanos
	if newReservedBalance > spendableBalanceNanos {
		return errors.Errorf("PosMempool.AddTransaction: Not enough balance to cover txn fees "+
			"(newReservedBalance: %d, spendableBalanceNanos: %d)", newReservedBalance, spendableBalanceNanos)
	}
	return nil
}

// CheckBalanceDecrease checks if the user's reserved balance can be decreased by the given amount. If the user's
// reserved balance is greater or equal to the amountNanos, the decrease is allowed. Otherwise, an error is returned.
func (pml *BalanceLedger) CheckBalanceDecrease(publicKey PublicKey, amountNanos uint64) error {
	pml.RLock()
	defer pml.RUnlock()

	reservedBalance, exists := pml.reservedBalancesNanos[publicKey]
	if !exists {
		return errors.Errorf("CheckBalanceDecrease: No reserved balance for public key")
	}
	if amountNanos > reservedBalance {
		return errors.Errorf("CheckBalanceDecrease: Amount exceeds reserved balance")
	}
	return nil
}

// IncreaseBalance increases the user's reserved balance by the given amount.
func (pml *BalanceLedger) IncreaseBalance(publicKey PublicKey, amount uint64) {
	pml.Lock()
	defer pml.Unlock()

	reservedBalance, _ := pml.reservedBalancesNanos[publicKey]
	pml.reservedBalancesNanos[publicKey] = reservedBalance + amount
}

// DecreaseBalance decreases the user's reserved balance by the given amount.
func (pml *BalanceLedger) DecreaseBalance(publicKey PublicKey, amount uint64) {
	pml.Lock()
	defer pml.Unlock()

	reservedBalance, exists := pml.reservedBalancesNanos[publicKey]
	if !exists {
		return
	}
	if amount > reservedBalance {
		pml.reservedBalancesNanos[publicKey] = 0
		return
	}

	pml.reservedBalancesNanos[publicKey] = reservedBalance - amount
}

// GetReservedBalanceNanos returns the user's reserved balance in nanos.
func (pml *BalanceLedger) GetReservedBalanceNanos(publicKey PublicKey) uint64 {
	pml.RLock()
	defer pml.RUnlock()

	reservedBalance, _ := pml.reservedBalancesNanos[publicKey]
	return reservedBalance
}

func (pml *BalanceLedger) Reset() {
	pml.Lock()
	defer pml.Unlock()

	pml.reservedBalancesNanos = make(map[PublicKey]uint64)
}
