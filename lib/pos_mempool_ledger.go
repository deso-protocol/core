package lib

import (
	"github.com/pkg/errors"
	"math"
	"sync"
)

// BalanceLedger is a simple in-memory ledger of reserved balances for user public keys. The entries in the ledger can be
// increased or decreased, as long as user's reserved balance doesn't exceed the user's spendable balance. It allows for checking
// whether a balance can be safely increased without going over the user's spendable balance. It also allows for
// increasing and decreasing balances.
type BalanceLedger struct {
	sync.RWMutex

	reservedBalancesNanos map[PublicKey]uint64
}

func NewPosMempoolLedger() *BalanceLedger {
	return &BalanceLedger{
		reservedBalancesNanos: make(map[PublicKey]uint64),
	}
}

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

func (pml *BalanceLedger) CheckBalanceDecrease(publicKey PublicKey, amount uint64) error {
	pml.RLock()
	defer pml.RUnlock()

	reservedBalance, exists := pml.reservedBalancesNanos[publicKey]
	if !exists {
		return errors.Errorf("CheckBalanceDecrease: No reserved balance for public key")
	}
	if amount > reservedBalance {
		return errors.Errorf("CheckBalanceDecrease: Amount exceeds reserved balance")
	}
	return nil
}

func (pml *BalanceLedger) IncreaseBalance(publicKey PublicKey, amount uint64) {
	pml.Lock()
	defer pml.Unlock()

	reservedBalance, exists := pml.reservedBalancesNanos[publicKey]
	if !exists {
		pml.reservedBalancesNanos[publicKey] = amount
		return
	}
	pml.reservedBalancesNanos[publicKey] = reservedBalance + amount
}

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

func (pml *BalanceLedger) GetReservedBalance(publicKey PublicKey) uint64 {
	pml.RLock()
	defer pml.RUnlock()

	reservedBalance, exists := pml.reservedBalancesNanos[publicKey]
	if !exists {
		return 0
	}
	return reservedBalance
}

func (pml *BalanceLedger) Reset() {
	pml.Lock()
	defer pml.Unlock()

	pml.reservedBalancesNanos = make(map[PublicKey]uint64)
}
