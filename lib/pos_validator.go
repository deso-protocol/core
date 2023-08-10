package lib

import "github.com/deso-protocol/core/bls"

type Validator struct {
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) SetSigner(signer *bls.PrivateKey) error {
	// TODO
	return nil
}

func (v *Validator) ConstructVote(blockHeader *MsgDeSoHeader) (*MsgDeSoValidatorVote, error) {
	// TODO
	return nil, nil
}

func (v *Validator) ConstructTimeout(previousBlockHeader *MsgDeSoHeader, timedOutView uint64) (*MsgDeSoValidatorTimeout, error) {
	// TODO
	return nil, nil
}
