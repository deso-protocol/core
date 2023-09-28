package lib

import "github.com/pkg/errors"

func (bc *Blockchain) validateDeSoBlockPoS(desoBlock *MsgDeSoBlock) error {
	// Surface Level validation of the block
	if err := bc.validateBlockGeneral(desoBlock); err != nil {
		return err
	}
	// Validate Block Height
	if err := bc.validateBlockHeight(desoBlock); err != nil {
		return err
	}
	// Validate View
	if err := bc.validateBlockView(desoBlock); err != nil {
		// Check if err is for view > latest committed block view and <= latest uncommitted block.
		// If so, we need to perform the rest of the validations and then add to our block index.
		// TODO: implement check on error described above. Caller will handle this.
		return err
	}
	// Validate Leader
	if err := bc.validateBlockLeader(desoBlock); err != nil {
		return err
	}
	return nil
}

// validateBlockGeneral validates the block at a surface level. It checks
// that the timestamp is valid, that the version of the header is valid,
// and other general integrity checks (such as not malformed).
func (bc *Blockchain) validateBlockGeneral(desoBlock *MsgDeSoBlock) error {
	// TODO: Implement me
	return errors.New("IMPLEMENT ME")
}

// validateBlockHeight validates the block height for a given block. It checks
// that this block height is exactly one greater than the current block height.
// TODO: Are we sure that's the correct validation here?
func (bc *Blockchain) validateBlockHeight(desoBlock *MsgDeSoBlock) error {
	// TODO: Implement me
	return errors.New("IMPLEMENT ME")
}

// validateBlockView validates the view for a given block. First, it checks that
// the view is greater than the latest committed block view. If not,
// we return an error indicating that we'll never accept this block. Next,
// it checks that the view is less than or equal to the latest uncommitted block.
// If not, we return an error indicating that we'll want to add this block as an
// orphan. Then it will check if that the view is exactly one greater than the
// latest uncommitted block if we have an regular vote QC. If this block has a
// timeout QC, it will check that the view is at least greater than the latest
// uncommitted block's view + 1.
func (bc *Blockchain) validateBlockView(desoBlock *MsgDeSoBlock) error {
	// TODO: Implement me
	return errors.New("IMPLEMENT ME")
}

// validateBlockLeader validates that the proposer is the expected proposer for the
// block height + view number pair.
func (bc *Blockchain) validateBlockLeader(desoBlock *MsgDeSoBlock) error {
	// TODO: Implement me
	return errors.New("IMPLEMENT ME")
}

// validateQC validates that the QC of this block is valid, meaning a super majority
// of the validator set has voted (or timed out). Assumes ValidatorEntry list is sorted.
func (bc *Blockchain) validateQC(desoBlock *MsgDeSoBlock, validatorSet []*ValidatorEntry) error {
	// TODO: Implement me
	return errors.New("IMPLEMENT ME")
}

// validateTimeoutQC validates that the parent block hash is not too far back from the latest.
// Specifically, it checks that the parent block hash is at least the latest committed block.
func (bc *Blockchain) validateTimeoutQC(desoBlock *MsgDeSoBlock, validatorSet []*ValidatorEntry) error {
	// TODO: Implement me
	return errors.New("IMPLEMENT ME")
}
