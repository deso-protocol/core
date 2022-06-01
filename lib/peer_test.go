package lib
import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"testing"
)

func TestSigVerify(t *testing.T) {
	signStr := "0xe1ddc8f4a6004439988a7578299856cdaa1a211e39ecbe57a500e1c3a65bb389779adf0472812fb35500e5b49ce679a3ed8b2cc4fac851e8783835bd7b82f0721c"
	signStr2 := hexutil.MustDecode(signStr)
	_ = signStr2
	signBytes, _ := hex.DecodeString(signStr)
	fmt.Println("length of signature:", len(signBytes))
	sign, err := btcec.ParseSignature(signBytes, btcec.S256())
	if err != nil {
		fmt.Println("sign error", err)
	}
	_ = sign

	privKey, _ := btcec.NewPrivateKey(btcec.S256())
	hash := Sha256DoubleHash([]byte{1,2,3,4})
	signature, err := btcec.SignCompact(btcec.S256(), privKey, hash[:], false)
	if err != nil {
		fmt.Println("signature err:", err)
	}
	signature2, err := privKey.Sign(hash[:])
	if err != nil {
		fmt.Println("signature2 err:", err)
	}
	fmt.Println(len(signature))

	fmt.Println(signBytes)
	fmt.Println(signature)
	fmt.Println(len(signature2.Serialize()), signature2.Serialize())
	ss, err := btcec.ParseSignature(signature2.Serialize(), btcec.S256())
	if err != nil {
		fmt.Println("ss error:", err)
	}
	_ = ss
	msg := "0000000000000e16e8b0331bedf6c9ca52d5c1ddd7143caf480dadcf7659e76e"
	msgBytes, _ := hex.DecodeString(msg)
	pubKeyRec, err := secp256k1.RecoverPubkey(msgBytes, signBytes)
	if err != nil {
		fmt.Println("pubKeyRec", err)
	}
	fmt.Println(pubKeyRec)

	ethPubKey := "0x1A779DD3677C04A0225Ea4C72058dAF5A83CFD8E"
	fmt.Println("address", common.IsHexAddress(ethPubKey))
}