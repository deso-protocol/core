//go:build !relic

package lib

func _generateValidatorVotingPublicKeyAndSignature(t *testing.T) (*bls.PublicKey, *bls.Signature) {
	panic(bls.BLSNoRelicError)
}
