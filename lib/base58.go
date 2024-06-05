package lib

import (
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

func Base58CheckEncode(input []byte, isPrivate bool, params *DeSoParams) string {
	prefix := params.Base58PrefixPublicKey
	if isPrivate {
		prefix = params.Base58PrefixPrivateKey
	}
	return Base58CheckEncodeWithPrefix(input, prefix)
}

func Base58CheckEncodeWithPrefix(input []byte, prefix [3]byte) string {
	b := []byte{}
	b = append(b, prefix[:]...)
	b = append(b, input[:]...)
	cksum := _checksum(b)
	b = append(b, cksum[:]...)
	return base58.Encode(b)
}

func MustBase58CheckDecode(input string) []byte {
	if input == "" {
		return nil
	}
	ret, _, err := Base58CheckDecode(input)
	if err != nil {
		glog.Fatal(err)
	}
	return ret
}

func Base58CheckDecode(input string) (_result []byte, _prefix []byte, _err error) {
	return Base58CheckDecodePrefix(input, 3 /*prefixLen*/)
}

func Base58CheckDecodePrefix(input string, prefixLen int) (_result []byte, _prefix []byte, _err error) {
	decoded := base58.Decode(input)
	if len(decoded) < 5 {
		return nil, nil, errors.Wrap(fmt.Errorf("CheckDecode: Invalid input format"), "")
	}
	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if _checksum(decoded[:len(decoded)-4]) != cksum {
		return nil, nil, errors.Wrap(fmt.Errorf("CheckDecode: Checksum does not match"), "")
	}
	prefix := decoded[:prefixLen]
	payload := decoded[prefixLen : len(decoded)-4]
	return payload, prefix, nil
}

func _checksum(input []byte) (cksum [4]byte) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(cksum[:], h2[:4])
	return
}
