//go:build !relic

package bls

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyingBLSSignatures(t *testing.T) {
	assert.Panics(t, func() { NewPrivateKey() })
	assert.Panics(t, func() { (&PrivateKey{}).FromString("") })
	assert.Panics(t, func() { (&PublicKey{}).FromString("") })
	assert.Panics(t, func() { (&Signature{}).FromString("") })
}
