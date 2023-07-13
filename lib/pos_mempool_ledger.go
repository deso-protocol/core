package lib

import (
	"github.com/pkg/errors"
	"math"
	"sync"
)

type PosMempoolLedger struct {
	sync.RWMutex

	reservedBalances map[PublicKey]uint64
}

func NewPosMempoolLedger() *PosMempoolLedger {
	return &PosMempoolLedger{
		reservedBalances: make(map[PublicKey]uint64),
	}
}

func (pml *PosMempoolLedger) CheckBalanceIncrease(publicKey PublicKey, amount uint64, blockView *UtxoView, blockHeight uint32) error {
	pml.RLock()
	defer pml.RUnlock()

	reservedBalance, exists := pml.reservedBalances[publicKey]

	// Check for reserved balance overflow.
	if exists && amount > math.MaxUint64-reservedBalance {
		return errors.Errorf("CheckBalanceIncrease: Reserved balance overflow")
	}

	newReservedBalance := reservedBalance + amount
	spendableBalanceNanos, err := blockView.GetSpendableDeSoBalanceNanosForPublicKey(publicKey.ToBytes(), blockHeight)
	if err != nil {
		return errors.Wrapf(err, "CheckBalanceIncrease: Problem getting spendable balance")
	}
	if newReservedBalance > spendableBalanceNanos {
		return errors.Errorf("PosMempool.AddTransaction: Not enough balance to cover txn fees "+
			"(newReservedBalance: %d, spendableBalanceNanos: %d)", newReservedBalance, spendableBalanceNanos)
	}
	return nil
}

func (pml *PosMempoolLedger) CheckBalanceDecrease(publicKey PublicKey, amount uint64) error {
	pml.RLock()
	defer pml.RUnlock()

	reservedBalance, exists := pml.reservedBalances[publicKey]
	if !exists {
		return errors.Errorf("CheckBalanceDecrease: No reserved balance for public key")
	}
	if amount > reservedBalance {
		return errors.Errorf("CheckBalanceDecrease: Amount exceeds reserved balance")
	}
	return nil
}

func (pml *PosMempoolLedger) IncreaseBalance(publicKey PublicKey, amount uint64) {
	pml.Lock()
	defer pml.Unlock()

	reservedBalance, exists := pml.reservedBalances[publicKey]
	if !exists {
		pml.reservedBalances[publicKey] = amount
		return
	}
	pml.reservedBalances[publicKey] = reservedBalance + amount
}

func (pml *PosMempoolLedger) DecreaseBalance(publicKey PublicKey, amount uint64) {
	pml.Lock()
	defer pml.Unlock()

	reservedBalance, exists := pml.reservedBalances[publicKey]
	if !exists {
		return
	}
	if amount > reservedBalance {
		pml.reservedBalances[publicKey] = 0
		return
	}

	pml.reservedBalances[publicKey] = reservedBalance - amount
}

func (pml *PosMempoolLedger) GetReservedBalance(publicKey PublicKey) uint64 {
	pml.RLock()
	defer pml.RUnlock()

	reservedBalance, exists := pml.reservedBalances[publicKey]
	if !exists {
		return 0
	}
	return reservedBalance
}

func (pml *PosMempoolLedger) Reset() {
	pml.Lock()
	defer pml.Unlock()

	pml.reservedBalances = make(map[PublicKey]uint64)
}
