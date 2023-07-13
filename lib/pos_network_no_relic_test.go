//go:build !relic

package lib

import (
	"testing"

	"github.com/deso-protocol/core/bls"
)

// This function is a placeholder needed to make the lib tests compile when the relic build tag
// isn't defined. Without the relic build tag, we are not able to generate any BLS keys. This
// function immediately fails the parent test that called it.
func _generateValidatorVotingPublicKeyAndSignature(t *testing.T) (*bls.PublicKey, *bls.Signature) {
	t.FailNow()
	return nil, nil
}
