//go:build !relic

package lib

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyingBLSSignatures(t *testing.T) {
	assert.Panics(t, func() { (&BLSPrivateKey{}).FromString("") })
	assert.Panics(t, func() { (&BLSPublicKey{}).FromString("") })
	assert.Panics(t, func() { (&BLSSignature{}).FromString("") })
}
