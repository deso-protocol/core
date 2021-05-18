package merkletree

import "crypto/sha256"

func Sha256DoubleHash(data []byte) []byte {
	first := sha256.Sum256(data)
	secnd := sha256.Sum256(first[:])

	return secnd[:]
}

func IdentityHashForTest(strbytes []byte) []byte {
	return strbytes
}
