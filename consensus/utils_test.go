package consensus

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/holiman/uint256"
)

func createDummyValidatorSet() []Validator {
	validators := []*validator{
		{
			publicKey:   createDummyBLSPublicKey(),
			stakeAmount: uint256.NewInt().SetUint64(100),
		},
		{
			publicKey:   createDummyBLSPublicKey(),
			stakeAmount: uint256.NewInt().SetUint64(50),
		},
	}
	// Cast the slice of concrete structs []*validators to a slice of interfaces []Validator
	return collections.TransformSlice(validators, func(v *validator) Validator {
		return v
	})
}

func createDummyBlock() *block {
	return &block{
		blockHash: createDummyBlockHash(),
		view:      0,
		height:    0,
		qc:        createDummyQC(),
	}
}

func createDummyQC() *quorumCertificate {
	return &quorumCertificate{
		blockHash:           createDummyBlockHash(),
		view:                0,
		signersList:         bitset.NewBitset().FromBytes([]byte{0x3}),
		aggregatedSignature: createDummyBLSSignature(),
	}
}

func createDummyBLSSignature() *bls.Signature {
	blsPrivateKey, _ := bls.NewPrivateKey()
	blockHashValue := createDummyBlockHash().GetValue()
	blsSignature, _ := blsPrivateKey.Sign(blockHashValue[:])
	return blsSignature
}

func createDummyBLSPublicKey() *bls.PublicKey {
	blsPrivateKey, _ := bls.NewPrivateKey()
	return blsPrivateKey.PublicKey()
}

func createDummyBlockHash() *blockHash {
	return &blockHash{
		value: [32]byte{
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xf,
			0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
			0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		},
	}
}
