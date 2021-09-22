package clouthash

import (
	"crypto/sha256"

	"github.com/bitclout/core/clouthash/sha3m"
	"golang.org/x/crypto/sha3"
)

var CloutHashV1MixConstant = [32]byte{140, 179, 163, 187, 73, 73, 228, 174, 70, 139, 110, 123, 77, 160, 46, 52, 165, 81, 68, 184, 179, 231, 190, 73, 152, 85, 103, 158, 216, 208, 207, 245}

func CloutHashV1(input []byte) [32]byte {
	result := sha3m.Sum256(input[:])

	for i, c := range CloutHashV1MixConstant {
		result[i] ^= c
	}

	return result
}

func CloutHashV0(input []byte) [32]byte {
	output := sha256.Sum256(input)

	for ii := 0; ii < 100; ii++ {
		if ii%7 == 0 {
			output = sha3.Sum256(output[:])
		}
		output = sha256.Sum256(output[:])
	}

	return output
}
