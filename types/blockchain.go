package types

import (
	"fmt"
	"math/big"
	"strings"
)

// Add some fields in addition to the header to aid in the selection
// of the best chain.
type BlockNode struct {
	// Pointer to a node representing the block's parent.
	Parent *BlockNode

	// The hash computed on this block.
	Hash *BlockHash

	// Height is the position in the block chain.
	Height uint32

	// The difficulty target for this block. Used to compute the next
	// block's difficulty target so it can be validated.
	DifficultyTarget *BlockHash

	// A computation of the total amount of work that has been performed
	// on this chain, including the current node.
	CumWork *big.Int

	// The block header.
	Header *MsgDeSoHeader

	// Status holds the validation state for the block and whether or not
	// it's stored in the database.
	Status BlockStatus
}

func (nn *BlockNode) String() string {
	var parentHash *BlockHash
	if nn.Parent != nil {
		parentHash = nn.Parent.Hash
	}
	tstamp := uint32(0)
	if nn.Header != nil {
		tstamp = uint32(nn.Header.TstampSecs)
	}
	return fmt.Sprintf("< TstampSecs: %d, Height: %d, Hash: %s, ParentHash %s, Status: %s, CumWork: %v>",
		tstamp, nn.Header.Height, nn.Hash, parentHash, nn.Status, nn.CumWork)
}

// TODO: Height not needed in this since it's in the header.
func NewBlockNode(
	parent *BlockNode,
	hash *BlockHash,
	height uint32,
	difficultyTarget *BlockHash,
	cumWork *big.Int,
	header *MsgDeSoHeader,
	status BlockStatus) *BlockNode {

	return &BlockNode{
		Parent:           parent,
		Hash:             hash,
		Height:           height,
		DifficultyTarget: difficultyTarget,
		CumWork:          cumWork,
		Header:           header,
		Status:           status,
	}
}

func (nn *BlockNode) Ancestor(height uint32) *BlockNode {
	if height > nn.Height {
		return nil
	}

	node := nn
	for ; node != nil && node.Height != height; node = node.Parent {
		// Keep iterating node until the condition no longer holds.
	}

	return node
}

// RelativeAncestor returns the ancestor block node a relative 'distance' blocks
// before this node. This is equivalent to calling Ancestor with the node's
// height minus provided distance.
//
// This function is safe for concurrent access.
func (nn *BlockNode) RelativeAncestor(distance uint32) *BlockNode {
	return nn.Ancestor(nn.Height - distance)
}

type BlockStatus uint32

const (
	StatusNone BlockStatus = 0

	// Headers must always be Validated or ValidateFailed. We
	// don't store orphan headers and therefore any header that we do
	// have in our node index will be known definitively to be valid or
	// invalid one way or the other.
	StatusHeaderValidated = 1 << iota
	StatusHeaderValidateFailed

	StatusBlockProcessed
	StatusBlockStored
	StatusBlockValidated
	StatusBlockValidateFailed

	// These statuses are only used for Bitcoin header blocks in the BitcoinManager,
	// not DeSo blocks. As such, you should only see these referenced in the BitcoinManager.
	// We include them here because overloading the DeSo data structures to make it
	// so that the BitcoinManager can use them is easier than defining whole new data
	// structures that are incompatible with existing methods like LatestLocator(). If
	// Go supported generics, this would probably not be necessary but it doesn't and
	// so this is the path of least resistance.
	StatusBitcoinHeaderValidated
	StatusBitcoinHeaderValidateFailed
)

func (blockStatus BlockStatus) String() string {
	if blockStatus == 0 {
		return "NONE"
	}

	statuses := []string{}
	if blockStatus&StatusHeaderValidated != 0 {
		statuses = append(statuses, "HEADER_VALIDATED")
		blockStatus ^= StatusHeaderValidated
	}
	if blockStatus&StatusHeaderValidateFailed != 0 {
		statuses = append(statuses, "HEADER_VALIDATE_FAILED")
		blockStatus ^= StatusHeaderValidateFailed
	}
	if blockStatus&StatusBlockProcessed != 0 {
		statuses = append(statuses, "BLOCK_PROCESSED")
		blockStatus ^= StatusBlockProcessed
	}
	if blockStatus&StatusBlockStored != 0 {
		statuses = append(statuses, "BLOCK_STORED")
		blockStatus ^= StatusBlockStored
	}
	if blockStatus&StatusBlockValidated != 0 {
		statuses = append(statuses, "BLOCK_VALIDATED")
		blockStatus ^= StatusBlockValidated
	}
	if blockStatus&StatusBlockValidateFailed != 0 {
		statuses = append(statuses, "BLOCK_VALIDATE_FAILED")
		blockStatus ^= StatusBlockValidateFailed
	}

	// If at this point the blockStatus isn't zeroed out then
	// we have an unknown status remaining.
	if blockStatus != 0 {
		statuses = append(statuses, "ERROR_UNKNOWN_STATUS!")
	}

	return strings.Join(statuses, " | ")
}
