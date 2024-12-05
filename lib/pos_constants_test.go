package lib

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildProofOfStakeCutoverValidatorBLSPrivateKey(t *testing.T) {
	t.Parallel()
	privateKey, err := BuildProofOfStakeCutoverValidatorBLSPrivateKey()
	require.NoError(t, err)

	privateKeyString := privateKey.ToString()
	require.Equal(t, privateKeyString, "0x0570b78ce822f902b203ee075a7e2147d6b9a420a9409c038154589de64eec96")
}

func TestBuildProofOfStakeCutoverValidator(t *testing.T) {
	t.Parallel()
	validator, err := BuildProofOfStakeCutoverValidator()
	require.NoError(t, err)

	validatorPublicKeyString := validator.GetPublicKey().ToString()
	require.Equal(t, validatorPublicKeyString, "0x91c92a48cc731489deeaa6752ebeab8410f2f25b4cce5415495d39b7ffdc32e257cdb7eaeefe1c3d6f607a248a057f530c7a55b0755a2c9adb48a5da19cc1ef55c46c4fd4719c1a63224e302b2da5a1d394fe6e516f56a021c8a5a3048a2a794")

	validatorStakeAmount := validator.GetStakeAmount().ToBig().String()
	require.Equal(t, validatorStakeAmount, "1000000000")
}
