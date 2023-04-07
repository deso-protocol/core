//go:build !relic

package lib

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyingBLSSignatures(t *testing.T) {
	assert.Panics(t, func() { NewBLSPublicKey(nil) })
	assert.Panics(t, func() { NewBLSSignature(nil) })
}
