package toolslib

import (
	"github.com/bitclout/core/lib"
	"github.com/tyler-smith/go-bip39"
	"github.com/btcsuite/btcd/btcec"
)

// GenerateMnemonicPublicPrivate,,,
func GenerateMnemonicPublicPrivate(params *lib.BitCloutParams) (mnemonic string, pubKey *btcec.PublicKey, privKey *btcec.PrivateKey) {
	entropy, _ := bip39.NewEntropy(128)
	mnemonic, _ = bip39.NewMnemonic(entropy)
	seedBytes, _ := bip39.NewSeedWithErrorChecking(mnemonic, "")
	pubKey, privKey, _, _ = lib.ComputeKeysFromSeed(seedBytes, 0, params)
	return
}
