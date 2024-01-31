//go:build relic

package main

import (
	"fmt"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/lib"
)

func getBLSVotingAuthorizationAndPublicKey(blsPrivateKeyHex string) (*bls.PublicKey, *bls.Signature) {
	// TODO: seed phrase or private key hex?
	// privKey, err := bls.PrivateKey{}.FromSeed(blsPrivateKeyHex)
	privKey, err := (&bls.PrivateKey{}).FromString(blsPrivateKeyHex)
	if err != nil {
		panic(err)
	}
	pubKey := privKey.PublicKey()
	votingAuthPayload := lib.CreateValidatorVotingAuthorizationPayload(pubKey.ToBytes())
	votingAuthorization, err := privKey.Sign(votingAuthPayload)
	if err != nil {
		panic(err)
	}
	return pubKey, votingAuthorization
}

// You must have relic installed to run this code.
// To install relic, use the install-relic.sh script in the scripts directory.
// go run -tags relic validator_registration_utils.go
func main() {
	// Replace with your own BLS private key hex.
	// blsPrivateKey, err := bls.PrivateKey{}.FromString("...")
	blsPrivateKey, err := bls.NewPrivateKey()
	if err != nil {
		panic(err)
	}
	blsPrivateKeyHex := blsPrivateKey.ToString()
	publicKey, votingAuthorization := getBLSVotingAuthorizationAndPublicKey(blsPrivateKeyHex)
	fmt.Println("Validator BLS PublicKey: ", publicKey.ToString())
	// If you're generating a new BLS private key, you can use the following line to print it.
	// fmt.Println("Validator BLS PrivateKey: ", blsPrivateKeyHex)
	fmt.Println("Validator Voting Authorization: ", votingAuthorization.ToString())
}
