package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/holiman/uint256"
	"math"
	"math/big"
)

// This library implements basic float functions using big.Float objects.
// This is necessary in order to ensure interoperability across different
// machines. If we instead were to use float64's for our computations
// naively, then machines with different rounding rules or different
// precision for intermediate values could produce different results that
// would cause blockchain forks. Having our own library ensures not only
// that such forks can't occur but also makes it so that implementing a
// node in another language is fairly straightforward because all of the
// operations are implemented in software.

const (
	FloatPrecision uint = 53
)

func NewFloat() *big.Float {
	// We force all calculations be done at a particular precision. This keeps
	// all nodes in sync and avoids consensus issues around one node using a
	// different precision than another node. We also force the same rounding
	// mode for all calculations.
	return big.NewFloat(0.0).SetPrec(FloatPrecision).SetMode(big.ToNearestEven)
}

func IntSub(a *big.Int, b *big.Int) *big.Int {
	// TODO(performance): We should do this without creating an int copy, but
	// this is easier to understand and deal with for now.
	return big.NewInt(0).Sub(a, b)
}

func IntMul(a *big.Int, b *big.Int) *big.Int {
	// TODO(performance): We should do this without creating an int copy, but
	// this is easier to understand and deal with for now.
	return big.NewInt(0).Mul(a, b)
}

func IntDiv(a *big.Int, b *big.Int) *big.Int {
	// TODO(performance): We should do this without creating an int copy, but
	// this is easier to understand and deal with for now.
	return big.NewInt(0).Quo(a, b)
}

func IntAdd(a *big.Int, b *big.Int) *big.Int {
	// TODO(performance): We should do this without creating an int copy, but
	// this is easier to understand and deal with for now.
	return big.NewInt(0).Add(a, b)
}

func Sub(a *big.Float, b *big.Float) *big.Float {
	// TODO(performance): This code currently calls NewFloat() too often. It
	// does this in order to make the code easier to read but if it ever becomes
	// an issue, the superfluous calls to NewFloat() should be a quick win.
	return NewFloat().Sub(a, b)
}

func Mul(a *big.Float, b *big.Float) *big.Float {
	// TODO(performance): This code currently calls NewFloat() too often. It
	// does this in order to make the code easier to read but if it ever becomes
	// an issue, the superfluous calls to NewFloat() should be a quick win.
	return NewFloat().Mul(a, b)
}

func Div(a *big.Float, b *big.Float) *big.Float {
	// TODO(performance): This code currently calls NewFloat() too often. It
	// does this in order to make the code easier to read but if it ever becomes
	// an issue, the superfluous calls to NewFloat() should be a quick win.
	return NewFloat().Quo(a, b)
}

func Add(a *big.Float, b *big.Float) *big.Float {
	// TODO(performance): This code currently calls NewFloat() too often. It
	// does this in order to make the code easier to read but if it ever becomes
	// an issue, the superfluous calls to NewFloat() should be a quick win.
	return NewFloat().Add(a, b)
}

var (
	// Constants for BigFloatLog
	bigLn2Hi          = NewFloat().SetFloat64(6.93147180369123816490e-01) /* 3fe62e42 fee00000 */
	bigLn2Lo          = NewFloat().SetFloat64(1.90821492927058770002e-10) /* 3dea39ef 35793c76 */
	bigL1             = NewFloat().SetFloat64(6.666666666666735130e-01)   /* 3FE55555 55555593 */
	bigL2             = NewFloat().SetFloat64(3.999999999940941908e-01)   /* 3FD99999 9997FA04 */
	bigL3             = NewFloat().SetFloat64(2.857142874366239149e-01)   /* 3FD24924 94229359 */
	bigL4             = NewFloat().SetFloat64(2.222219843214978396e-01)   /* 3FCC71C5 1D8E78AF */
	bigL5             = NewFloat().SetFloat64(1.818357216161805012e-01)   /* 3FC74664 96CB03DE */
	bigL6             = NewFloat().SetFloat64(1.531383769920937332e-01)   /* 3FC39A09 D078C69F */
	bigL7             = NewFloat().SetFloat64(1.479819860511658591e-01)   /* 3FC2F112 DF3E5244 */
	bigSqrt2          = NewFloat().SetFloat64(1.41421356237309504880168872420969807856967187537694807317667974)
	bigHalf           = NewFloat().SetFloat64(.5)
	bigNegativeOneOne = NewFloat().SetUint64(1)
	bigOne            = NewFloat().SetUint64(1)
	bigTwo            = NewFloat().SetUint64(2)
	bigSqrt2Over2     = NewFloat().Quo(bigSqrt2, bigTwo)

	// Constants for BigFloatExpMulti
	bigP1 = NewFloat().SetFloat64(1.66666666666666657415e-01)  /* 0x3FC55555; 0x55555555 */
	bigP2 = NewFloat().SetFloat64(-2.77777777770155933842e-03) /* 0xBF66C16C; 0x16BEBD93 */
	bigP3 = NewFloat().SetFloat64(6.61375632143793436117e-05)  /* 0x3F11566A; 0xAF25DE2C */
	bigP4 = NewFloat().SetFloat64(-1.65339022054652515390e-06) /* 0xBEBBBD41; 0xC5D26BF1 */
	bigP5 = NewFloat().SetFloat64(4.13813679705723846039e-08)  /* 0x3E663769; 0x72BEA4D0 */

	// Constants for BigFloatExp
	bigZero  = NewFloat().SetUint64(0)
	bigLog2e = NewFloat().SetFloat64(1.44269504088896338700e+00)
)

// Log returns the natural logarithm of x.
func BigFloatLog(x *big.Float) *big.Float {
	// special cases
	// TODO: We should make the special cases work at some point.
	switch {
	case x.IsInf():
		panic(fmt.Sprintf("BigFloatLog: Cannot take log of an infinite number: %v", x))
	case x.Sign() <= 0:
		panic(fmt.Sprintf("BigFloatLog: Cannot take log of a number <= 0: %v", x))
	}

	// Reduce
	f1 := NewFloat()
	ki := x.MantExp(f1)
	if f1.Cmp(bigSqrt2Over2) < 0 {
		f1 = Mul(f1, bigTwo)
		ki--
	}
	f := Sub(f1, bigOne)
	k := NewFloat().SetInt64(int64(ki))

	// Compute
	twoPlusF := Add(bigTwo, f)
	s := Div(f, twoPlusF)
	s2 := Mul(s, s)
	s4 := Mul(s2, s2)

	t1 := Mul(s2, (Add(bigL1, Mul(s4, (Add(bigL3, Mul(s4, (Add(bigL5, Mul(s4, bigL7))))))))))
	t2 := Mul(s4, Add(bigL2, Mul(s4, Add(bigL4, Mul(s4, bigL6)))))
	R := Add(t1, t2)
	hfsq := Mul(bigHalf, NewFloat().Mul(f, f))

	return Sub(Mul(k, bigLn2Hi), Sub(Sub(hfsq, (Add(Mul(s, Add(hfsq, R)), Mul(k, bigLn2Lo)))), f))
}

// Log2 returns the binary logarithm of x.
// The special cases are the same as for Log.
func BigFloatLog2(x *big.Float) *big.Float {
	bigTwo := NewFloat().SetUint64(2)
	return Div(BigFloatLog(x), BigFloatLog(bigTwo))
}

func BigFloatExpMulti(hi, lo *big.Float, k int64) *big.Float {
	r := Sub(hi, lo)
	t := Mul(r, r)
	c := Sub(r, Mul(t, (Add(bigP1, Mul(t, (Add(bigP2, Mul(t, (Add(bigP3, Mul(t, (Add(bigP4, Mul(t, bigP5))))))))))))))
	y := Sub(bigOne, (Sub((Sub(lo, Div((Mul(r, c)), (Sub(bigTwo, c))))), hi)))

	// TODO: make sure Ldexp can handle boundary k
	return NewFloat().SetMantExp(y, int(k))
}

// Exp returns a big.Float representation of exp(z).
func BigFloatExp(z *big.Float) *big.Float {
	if z.IsInf() {
		panic("BigFloatExp: Cannot call exp with infinity")
	}

	// reduce; computed as r = hi - lo for extra precision.
	var k int64
	switch {
	case z.Cmp(bigZero) < 0:
		k, _ = Sub(Mul(bigLog2e, z), bigHalf).Int64()
	case z.Cmp(bigZero) > 0:
		k, _ = Add(Mul(bigLog2e, z), bigHalf).Int64()
	}
	hi := Sub(z, Mul(NewFloat().SetInt64(k), bigLn2Hi))
	lo := Mul(NewFloat().SetInt64(k), bigLn2Lo)

	// compute
	return BigFloatExpMulti(hi, lo, k)
}

// Pow returns a big.Float representation of z**w.
func BigFloatPow(z *big.Float, w *big.Float) *big.Float {
	if z.Sign() < 0 {
		panic("Pow: negative base")
	}
	if z.Cmp(bigZero) == 0 {
		return bigZero
	}

	// Pow(z, 0) = 1.0
	if w.Sign() == 0 {
		return bigOne
	}

	// Pow(z, 1) = z
	// Pow(+Inf, n) = +Inf
	if w.Cmp(bigOne) == 0 || z.IsInf() {
		return NewFloat().Copy(z)
	}

	// Pow(z, -w) = 1 / Pow(z, w)
	if w.Sign() < 0 {
		x := NewFloat()
		zExt := NewFloat().Copy(z).SetPrec(z.Prec() + 64)
		wNeg := NewFloat().Neg(w)
		return x.Quo(bigOne, BigFloatPow(zExt, wNeg)).SetPrec(z.Prec())
	}

	// compute w**z as exp(z log(w))
	x := NewFloat().SetPrec(z.Prec() + 64)
	logZ := BigFloatLog(NewFloat().Copy(z).SetPrec(z.Prec() + 64))
	x.Mul(w, logZ)
	x = BigFloatExp(x)
	return x.SetPrec(z.Prec())
}

func GetS256BasePointCompressed() []byte {
	basePoint, _ := btcec.S256().CurveParams.Gx.GobEncode()
	return basePoint
}

// SafeUint256 allows for arithmetic operations that error
// if an overflow or underflow situation is detected.
type _SafeUint256 struct{}

func SafeUint256() *_SafeUint256 {
	return &_SafeUint256{}
}

func (safeUint256 *_SafeUint256) Add(x *uint256.Int, y *uint256.Int) (*uint256.Int, error) {
	if uint256.NewInt().Sub(MaxUint256, y).Lt(x) {
		return nil, fmt.Errorf("addition overflows uint256")
	}

	return uint256.NewInt().Add(x, y), nil
}

func (safeUint256 *_SafeUint256) Sub(x *uint256.Int, y *uint256.Int) (*uint256.Int, error) {
	if x.Lt(y) {
		return nil, fmt.Errorf("subtraction underflows uint256")
	}

	return uint256.NewInt().Sub(x, y), nil
}

func (safeUint256 *_SafeUint256) Mul(x *uint256.Int, y *uint256.Int) (*uint256.Int, error) {
	if uint256.NewInt().Div(MaxUint256, y).Lt(x) {
		return nil, fmt.Errorf("multiplication overflows uint256")
	}

	return uint256.NewInt().Mul(x, y), nil
}

func (safeUint256 *_SafeUint256) Div(x *uint256.Int, y *uint256.Int) (*uint256.Int, error) {
	if y.IsZero() {
		return nil, fmt.Errorf("division by zero")
	}

	return uint256.NewInt().Div(x, y), nil
}

// SafeUint64 allows for arithmetic operations that error
// if an overflow or underflow situation is detected.
type _SafeUint64 struct{}

func SafeUint64() *_SafeUint64 {
	return &_SafeUint64{}
}

func (safeUint64 *_SafeUint64) Add(x uint64, y uint64) (uint64, error) {
	if uint64(math.MaxUint64)-y < x {
		return 0, fmt.Errorf("addition overflows uint64")
	}

	return x + y, nil
}

func (safeUint64 *_SafeUint64) Sub(x uint64, y uint64) (uint64, error) {
	if x < y {
		return 0, fmt.Errorf("subtraction underflows uint64")
	}

	return x - y, nil
}

func (safeUint64 *_SafeUint64) Mul(x uint64, y uint64) (uint64, error) {
	if uint64(math.MaxUint64)/y < x {
		return 0, fmt.Errorf("multiplication overflows uint64")
	}

	return x * y, nil
}

func (safeUint64 *_SafeUint64) Div(x uint64, y uint64) (uint64, error) {
	if y == 0 {
		return 0, fmt.Errorf("division by zero")
	}

	return x / y, nil
}
