package types

import (
	"encoding/hex"
	"github.com/deso-protocol/core/desohash"
	"github.com/golang/glog"
	"math/big"
)

// ProofOfWorkHash is a hash function designed for computing DeSo block hashes.
// It seems the optimal hash function is one that satisfies two properties:
// 1) It is not computable by any existing ASICs. If this property isn't satisfied
//    then miners with pre-existing investments in ASICs for other coins can very
//    cheaply mine on our chain for a short period of time to pull off a 51% attack.
//    This has actually happened with "merge-mined" coins like Namecoin.
// 2) If implemented on an ASIC, there is an "orders of magnitude" speed-up over
//    using a CPU or GPU. This is because ASICs require some amount of capital
//    expenditure up-front in order to mine, which then aligns the owner of the
//    ASIC to care about the health of the network over a longer period of time. In
//    contrast, a hash function that is CPU or GPU-mineable can be attacked with
//    an AWS fleet early on. This also may result in a more eco-friendly chain, since
//    the hash power will be more bottlenecked by up-front CapEx rather than ongoing
//    electricity cost, as is the case with GPU-mined coins.
//
// Note that our pursuit of (2) above runs counter to existing dogma which seeks to
// prioritize "ASIC-resistance" in hash functions.
//
// Given the above, the hash function chosen is a simple twist on sha3
// that we don't think any ASIC exists for currently. Note that creating an ASIC for
// this should be relatively straightforward, however, which allows us to satisfy
// property (2) above.
func ProofOfWorkHash(inputBytes []byte, version uint32) *BlockHash {
	output := BlockHash{}

	if version == HeaderVersion0 {
		hashBytes := desohash.DeSoHashV0(inputBytes)
		copy(output[:], hashBytes[:])
	} else if version == HeaderVersion1 {
		hashBytes := desohash.DeSoHashV1(inputBytes)
		copy(output[:], hashBytes[:])
	} else {
		// If we don't recognize the version, we return the v0 hash. We do
		// this to avoid having to return an error or panic.
		hashBytes := desohash.DeSoHashV0(inputBytes)
		copy(output[:], hashBytes[:])
	}

	return &output
}

var (
	maxHash = BlockHash{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff}
	maxHashBigint = HashToBigint(&maxHash)
	bigOneInt     = big.NewInt(1)
)

// The number of hashing attempts in expectation it would take to produce the
// hash passed in. This is computed as:
//    E(min(X_i, ..., X_n)) where:
//    - n = (number of attempted hashes) and
//    - the X_i are all U(0, MAX_HASH)
// -> E(min(X_i, ..., X_n)) = MAX_HASH / (n + 1)
// -> E(n) ~= MAX_HASH / min_hash - 1
//    - where min_hash is the block hash
//
// We approximate this as MAX_HASH / (min_hash + 1), adding 1 to min_hash in
// order to mitigate the possibility of a divide-by-zero error.
//
// The value returned is the expected number of hashes performed to produce
// the input hash formatted as a big-endian big integer that uses the
// BlockHash type for convenience (though it is likely to be much lower
// in terms of magnitude than a typical BlockHash object).
func ExpectedWorkForBlockHash(hash *BlockHash) *BlockHash {
	hashBigint := HashToBigint(hash)
	ratioBigint := new(big.Int)
	ratioBigint.Div(maxHashBigint, hashBigint.Add(hashBigint, bigOneInt))
	return BigintToHash(ratioBigint)
}

func BytesToBigint(bb []byte) *big.Int {
	val, itWorked := new(big.Int).SetString(hex.EncodeToString(bb), 16)
	if !itWorked {
		glog.Errorf("Failed in converting []byte (%#v) to bigint.", bb)
	}
	return val
}
