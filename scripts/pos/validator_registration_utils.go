//go:build relic

package main

import (
	"fmt"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/lib"
)

func getBLSVotingAuthorizationAndPublicKey(blsKeyStore *lib.BLSKeystore, transactorPublicKey *lib.PublicKey) (
	*bls.PublicKey, *bls.Signature,
) {
	votingAuthPayload := lib.CreateValidatorVotingAuthorizationPayload(transactorPublicKey.ToBytes())
	votingAuthorization, err := blsKeyStore.GetSigner().Sign(votingAuthPayload)
	if err != nil {
		panic(err)
	}
	return blsKeyStore.GetSigner().GetPublicKey(), votingAuthorization
}

// You must have relic installed to run this code.
// To install relic, use the install-relic.sh script in the scripts directory.
// go run -tags relic validator_registration_utils.go
func main() {
	// Replace with your own BIP39 Validator seed phrase
	keystore, err := lib.NewBLSKeystore("...")
	if err != nil {
		panic(err)
	}
	// Replace with  your DeSo Public Key
	pubKeyBytes, _, err := lib.Base58CheckDecode("...")
	if err != nil {
		panic(err)
	}
	publicKey, votingAuthorization := getBLSVotingAuthorizationAndPublicKey(keystore, lib.NewPublicKey(pubKeyBytes))
	fmt.Println("Validator BLS PublicKey: ", publicKey.ToString())
	fmt.Println("Validator Voting Authorization: ", votingAuthorization.ToString())
}
