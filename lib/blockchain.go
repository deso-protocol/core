package lib

import (
	"bytes"
	"container/list"
	"encoding/hex"
	"fmt"
	"github.com/holiman/uint256"
	"math"
	"math/big"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	btcdchain "github.com/btcsuite/btcd/blockchain"
	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/deso-protocol/go-deadlock"
	merkletree "github.com/deso-protocol/go-merkle-tree"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// blockchain.go is the work-horse for validating DeSo blocks and updating the
// database after each block is processed. The ProcessBlock function is probably
// a good place to start to understand this file.

const (
	// MaxOrphansInMemory is the maximum number of orphan blocks that we're willing to keep in memory. We set
	// a maximum here in order to prevent memory exhaustion from someone sending us too
	// many unconnectedTxns.
	MaxOrphansInMemory = 100

	// MaxBlockIndexNodes needs to allow the block index to grow large enough to accommodate multiple
	// forks of material length while allowing us to avoid an out-of-memory issue due to
	// a "disk-fill" attack. Notice that because we will only ever download blocks
	// after we have a header chain that has beaten all other header chains we're aware
	// of, the common case for an attack will be someone sending us long useless header
	// chains that we never actually download blocks for. This results in the block index
	// bloating up (indefinitely if we don't prune it) due to storing useless headers
	// but not resulting in the downloading of any blocks, which is a good thing.
	//
	// At ten minute block times, 5,000,000 comes out to roughly 95 years worth of blocks,
	// which seems like a reasonable limit for now (if we had 25 years of blocks, we'd still
	// have room for multiple forks each an entire history's length with this value). If
	// each node takes up 100 bytes of space this amounts to around 500MB, which also seems
	// like a reasonable size.
	MaxBlockIndexNodes = 5000000
)

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

func _difficultyBitsToHash(diffBits uint32) (_diffHash *BlockHash) {
	diffBigint := btcdchain.CompactToBig(diffBits)
	return BigintToHash(diffBigint)
}

func ExtractBitcoinBurnTransactionsFromBitcoinBlock(
	bitcoinBlock *wire.MsgBlock, bitcoinBurnAddress string, params *DeSoParams) []*wire.MsgTx {

	burnTxns := []*wire.MsgTx{}
	for _, txn := range bitcoinBlock.Transactions {
		burnOutput, err := _computeBitcoinBurnOutput(
			txn, bitcoinBurnAddress, params.BitcoinBtcdParams)
		if err != nil {
			glog.Errorf("ExtractBitcoinBurnTransactionsFromBitcoinBlock: Problem "+
				"extracting Bitcoin transaction: %v", err)
			continue
		}

		if burnOutput > 0 {
			burnTxns = append(burnTxns, txn)
		}
	}

	return burnTxns
}

func ExtractBitcoinBurnTransactionsFromBitcoinBlockWithMerkleProofs(
	bitcoinBlock *wire.MsgBlock, burnAddress string, params *DeSoParams) (
	_txns []*wire.MsgTx, _merkleProofs [][]*merkletree.ProofPart, _err error) {

	// Extract the Bitcoin burn transactions.
	burnTxns := ExtractBitcoinBurnTransactionsFromBitcoinBlock(
		bitcoinBlock, burnAddress, params)

	// If there weren't any burn transactions then there's nothing to do.
	if len(burnTxns) == 0 {
		return nil, nil, nil
	}

	// Compute all of the transaction hashes for the block.
	txHashes := [][]byte{}
	for _, txn := range bitcoinBlock.Transactions {
		txnBytes := bytes.Buffer{}
		err := txn.SerializeNoWitness(&txnBytes)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"ExtractBitcoinBurnTransactionsFromBitcoinBlockWithMerkleProofs: "+
					"Error computing all the txn hashes for block: %v",
				err)
		}
		txHashes = append(txHashes, txnBytes.Bytes())
	}

	// Compute a merkle tree for the block.
	merkleTree := merkletree.NewTree(merkletree.Sha256DoubleHash, txHashes)

	if !reflect.DeepEqual(merkleTree.Root.GetHash(), bitcoinBlock.Header.MerkleRoot[:]) {
		return nil, nil, fmt.Errorf(
			"ExtractBitcoinBurnTransactionsFromBitcoinBlockWithMerkleProofs: "+
				"Merkle proof computed from txns %#v != to Merkle proof in Bitcoin block %#v",
			merkleTree.Root.GetHash(), bitcoinBlock.Header.MerkleRoot[:])
	}

	// Use the Merkle tree to compute a Merkle proof for each transaction.
	burnTxnsWithProofs := []*wire.MsgTx{}
	merkleProofs := [][]*merkletree.ProofPart{}
	for _, txn := range burnTxns {
		txHash := txn.TxHash()
		proof, err := merkleTree.CreateProof(txHash[:])
		if err != nil {
			return nil, nil, fmt.Errorf(
				"ExtractBitcoinBurnTransactionsFromBitcoinBlockWithMerkleProofs: Problem "+
					"computing Merkle proof for txn %v for block %v: %v",
				txn, bitcoinBlock, err)
		}

		burnTxnsWithProofs = append(burnTxnsWithProofs, txn)
		merkleProofs = append(merkleProofs, proof.PathToRoot)
	}

	return burnTxnsWithProofs, merkleProofs, nil
}

func ExtractBitcoinExchangeTransactionsFromBitcoinBlock(
	bitcoinBlock *wire.MsgBlock, burnAddress string, params *DeSoParams) (
	_txns []*MsgDeSoTxn, _err error) {

	bitcoinBurnTxns, merkleProofs, err :=
		ExtractBitcoinBurnTransactionsFromBitcoinBlockWithMerkleProofs(
			bitcoinBlock, burnAddress, params)
	if err != nil {
		return nil, errors.Wrapf(err, "ExtractBitcoinExchangeTransactionsFromBitcoinBlock: "+
			"Problem extracting raw Bitcoin burn transactions from Bitcoin Block")
	}

	bitcoinExchangeTxns := []*MsgDeSoTxn{}
	blockHash := (BlockHash)(bitcoinBlock.BlockHash())
	merkleRoot := (BlockHash)(bitcoinBlock.Header.MerkleRoot)
	for ii := range bitcoinBurnTxns {
		bitcoinExchangeMetadata := &BitcoinExchangeMetadata{
			BitcoinTransaction: bitcoinBurnTxns[ii],
			BitcoinBlockHash:   &blockHash,
			BitcoinMerkleRoot:  &merkleRoot,
			BitcoinMerkleProof: merkleProofs[ii],
		}

		// The only thing a BitcoinExchange transaction has set is its TxnMeta.
		// Everything else is left blank because it is not needed. Note that the
		// recipient of the DeSo that will be created is the first valid input in
		// the BitcoinTransaction specified. Note also that the
		// fee is deducted as a percentage of the eventual DeSo that will get
		// created as a result of this transaction.
		currentTxn := &MsgDeSoTxn{
			TxnMeta: bitcoinExchangeMetadata,
		}
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}

	return bitcoinExchangeTxns, nil
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

// CalcNextDifficultyTarget computes the difficulty target expected of the
// next block.
func CalcNextDifficultyTarget(
	lastNode *BlockNode, version uint32, params *DeSoParams) (*BlockHash, error) {

	// Compute the blocks in each difficulty cycle.
	blocksPerRetarget := uint32(params.TimeBetweenDifficultyRetargets / params.TimeBetweenBlocks)

	// We effectively skip the first difficulty retarget by returning the default
	// difficulty value for the first cycle. Not doing this (or something like it)
	// would cause the genesis block's timestamp, which could be off by several days
	// to significantly skew the first cycle in a way that is mostly annoying for
	// testing but also suboptimal for the mainnet.
	minDiffBytes, err := hex.DecodeString(params.MinDifficultyTargetHex)
	if err != nil {
		return nil, errors.Wrapf(err, "CalcNextDifficultyTarget: Problem computing min difficulty")
	}
	var minDiffHash BlockHash
	copy(minDiffHash[:], minDiffBytes)
	if lastNode == nil || lastNode.Height <= blocksPerRetarget {
		return &minDiffHash, nil
	}

	// If we get here we know we are dealing with a block whose height exceeds
	// the height of the first difficulty adjustment (that is
	//   lastNode.Height > blocksPerRetarget

	// If we're not at a difficulty retarget point, return the previous
	// block's difficulty.
	if lastNode.Height%blocksPerRetarget != 0 {
		return lastNode.DifficultyTarget, nil
	}

	// If we get here it means we reached a difficulty retarget point.
	targetSecs := int64(params.TimeBetweenDifficultyRetargets / time.Second)
	minRetargetTimeSecs := targetSecs / params.MaxDifficultyRetargetFactor
	maxRetargetTimeSecs := targetSecs * params.MaxDifficultyRetargetFactor

	firstNodeHeight := lastNode.Height - blocksPerRetarget
	firstNode := lastNode.Ancestor(firstNodeHeight)
	if firstNode == nil {
		return nil, fmt.Errorf("CalcNextDifficultyTarget: Problem getting block at "+
			"beginning of retarget interval at height %d during retarget from height %d",
			firstNodeHeight, lastNode.Height)
	}

	actualTimeDiffSecs := int64(lastNode.Header.TstampSecs - firstNode.Header.TstampSecs)
	clippedTimeDiffSecs := actualTimeDiffSecs
	if actualTimeDiffSecs < minRetargetTimeSecs {
		clippedTimeDiffSecs = minRetargetTimeSecs
	} else if actualTimeDiffSecs > maxRetargetTimeSecs {
		clippedTimeDiffSecs = maxRetargetTimeSecs
	}

	numerator := new(big.Int).Mul(
		HashToBigint(lastNode.DifficultyTarget),
		big.NewInt(clippedTimeDiffSecs))
	nextDiffBigint := numerator.Div(numerator, big.NewInt(targetSecs))

	// If the next difficulty is nil or if it passes the min difficulty, set it equal
	// to the min difficulty. This should never happen except for weird instances where
	// we're testing edge cases.
	if nextDiffBigint == nil || nextDiffBigint.Cmp(HashToBigint(&minDiffHash)) > 0 {
		nextDiffBigint = HashToBigint(&minDiffHash)
	}

	return BigintToHash(nextDiffBigint), nil
}

type OrphanBlock struct {
	Block *MsgDeSoBlock
	Hash  *BlockHash
}

type Blockchain struct {
	db                              *badger.DB
	postgres                        *Postgres
	timeSource                      chainlib.MedianTimeSource
	trustedBlockProducerPublicKeys  map[PkMapKey]bool
	trustedBlockProducerStartHeight uint64
	params                          *DeSoParams
	eventManager                    *EventManager
	// Returns true once all of the housekeeping in creating the
	// blockchain is complete. This includes setting up the genesis block.
	isInitialized bool

	// Protects most of the fields below this point.
	ChainLock deadlock.RWMutex

	// These should only be accessed after acquiring the ChainLock.
	//
	// An in-memory index of the "tree" of blocks we are currently aware of.
	// This index includes forks and side-chains but does not include unconnectedTxns.
	blockIndex map[BlockHash]*BlockNode
	// An in-memory slice of the blocks on the main chain only. The end of
	// this slice is the best known tip that we have at any given time.
	bestChain    []*BlockNode
	bestChainMap map[BlockHash]*BlockNode

	bestHeaderChain    []*BlockNode
	bestHeaderChainMap map[BlockHash]*BlockNode

	// We keep track of orphan blocks with the following data structures. Orphans
	// are not written to disk and are only cached in memory. Moreover we only keep
	// up to MaxOrphansInMemory of them in order to prevent memory exhaustion.
	orphanList *list.List
}

func (bc *Blockchain) CopyBlockIndex() map[BlockHash]*BlockNode {
	newBlockIndex := make(map[BlockHash]*BlockNode)
	for kk, vv := range bc.blockIndex {
		newBlockIndex[kk] = vv
	}
	return newBlockIndex
}

func (bc *Blockchain) CopyBestChain() ([]*BlockNode, map[BlockHash]*BlockNode) {
	newBestChain := []*BlockNode{}
	newBestChainMap := make(map[BlockHash]*BlockNode)
	newBestChain = append(newBestChain, bc.bestChain...)
	for kk, vv := range bc.bestChainMap {
		newBestChainMap[kk] = vv
	}

	return newBestChain, newBestChainMap
}

func (bc *Blockchain) CopyBestHeaderChain() ([]*BlockNode, map[BlockHash]*BlockNode) {
	newBestChain := []*BlockNode{}
	newBestChainMap := make(map[BlockHash]*BlockNode)
	newBestChain = append(newBestChain, bc.bestHeaderChain...)
	for kk, vv := range bc.bestHeaderChainMap {
		newBestChainMap[kk] = vv
	}

	return newBestChain, newBestChainMap
}

// _initChain initializes the in-memory data structures for the Blockchain object
// by reading from the database. If the database has never been initialized before
// then _initChain will initialize it to contain only the genesis block before
// proceeding to read from it.
func (bc *Blockchain) _initChain() error {
	// See if we have a best chain hash stored in the db.
	var bestBlockHash *BlockHash
	if bc.postgres != nil {
		chain := bc.postgres.GetChain(MAIN_CHAIN)
		if chain != nil {
			bestBlockHash = chain.TipHash
		}
	} else {
		bestBlockHash = DbGetBestHash(bc.db, ChainTypeDeSoBlock)
	}
	// When we load up initially, the best header hash is just the tip of the best
	// block chain, since we don't store headers for which we don't have corresponding
	// blocks.
	bestHeaderHash := bestBlockHash

	// If there is no best chain hash in the db then it means we've never
	// initialized anything so take the time to do it now.
	if bestBlockHash == nil || bestHeaderHash == nil {
		var err error

		if bc.postgres != nil {
			err = bc.postgres.InitGenesisBlock(bc.params, bc.db)
		} else {
			err = InitDbWithDeSoGenesisBlock(bc.params, bc.db, bc.eventManager)
		}
		if err != nil {
			return errors.Wrapf(err, "_initChain: Problem initializing db with genesis block")
		}

		// After initializing the db to contain only the genesis block,
		// set the best hash we're aware of equal to it.
		bestBlockHash = MustDecodeHexBlockHash(bc.params.GenesisBlockHashHex)
		bestHeaderHash = bestBlockHash
	}

	// At this point we should have bestHashes set and the db should have been
	// initialized to contain a block index and a best chain that we can read
	// in.

	// Read in the nodes using the (<height, hash> -> node) index. The nodes will
	// be iterated over starting with height 0 and ending with the height of the
	// longest chain we're aware of. As we go, check that all the blocks connect
	// to previous blocks we've read in and error if they don't. This works because
	// reading blocks in height order as we do here ensures that we'll always
	// add a block's parents, if they exist, before adding the block itself.
	var err error
	if bc.postgres != nil {
		bc.blockIndex, err = bc.postgres.GetBlockIndex()
	} else {
		bc.blockIndex, err = GetBlockIndex(bc.db, false /*bitcoinNodes*/)
	}
	if err != nil {
		return errors.Wrapf(err, "_initChain: Problem reading block index from db")
	}

	// At this point the blockIndex should contain a full node tree with all
	// nodes pointing to valid parent nodes.
	{
		// Find the tip node with the best node hash.
		tipNode := bc.blockIndex[*bestBlockHash]
		if tipNode == nil {
			return fmt.Errorf("_initChain(block): Best hash (%#v) not found in block index", bestBlockHash)
		}

		// Walk back from the best node to the genesis block and store them all
		// in bestChain.
		bc.bestChain, err = GetBestChain(tipNode, bc.blockIndex)
		if err != nil {
			return errors.Wrapf(err, "_initChain(block): Problem reading best chain from db")
		}
		for _, bestChainNode := range bc.bestChain {
			bc.bestChainMap[*bestChainNode.Hash] = bestChainNode
		}
	}

	// TODO: This code is a bit repetitive but this seemed clearer than factoring it out.
	{
		// Find the tip node with the best node hash.
		tipNode := bc.blockIndex[*bestHeaderHash]
		if tipNode == nil {
			return fmt.Errorf("_initChain(header): Best hash (%#v) not found in block index", bestHeaderHash)
		}

		// Walk back from the best node to the genesis block and store them all
		// in bestChain.
		bc.bestHeaderChain, err = GetBestChain(tipNode, bc.blockIndex)
		if err != nil {
			return errors.Wrapf(err, "_initChain(header): Problem reading best chain from db")
		}
		for _, bestHeaderChainNode := range bc.bestHeaderChain {
			bc.bestHeaderChainMap[*bestHeaderChainNode.Hash] = bestHeaderChainNode
		}
	}

	bc.isInitialized = true

	return nil
}

// NewBlockchain returns a new blockchain object. It initializes some in-memory
// data structures by reading from the db. It also initializes the db if it hasn't
// been initialized in the past. This function should only be called once per
// db, and one should never run two blockhain objects over the same db at the same
// time as they will likely step on each other and become inconsistent.
func NewBlockchain(
	trustedBlockProducerPublicKeyStrs []string,
	trustedBlockProducerStartHeight uint64,
	params *DeSoParams,
	timeSource chainlib.MedianTimeSource,
	db *badger.DB,
	postgres *Postgres,
	eventManager *EventManager,
) (*Blockchain, error) {

	trustedBlockProducerPublicKeys := make(map[PkMapKey]bool)
	for _, keyStr := range trustedBlockProducerPublicKeyStrs {
		pkBytes, _, err := Base58CheckDecode(keyStr)
		if err != nil {
			return nil, fmt.Errorf("Error decoding trusted block producer public key: %v", err)
		}
		trustedBlockProducerPublicKeys[MakePkMapKey(pkBytes)] = true
	}

	bc := &Blockchain{
		db:                              db,
		postgres:                        postgres,
		timeSource:                      timeSource,
		trustedBlockProducerPublicKeys:  trustedBlockProducerPublicKeys,
		trustedBlockProducerStartHeight: trustedBlockProducerStartHeight,
		params:                          params,
		eventManager:                    eventManager,

		blockIndex:   make(map[BlockHash]*BlockNode),
		bestChainMap: make(map[BlockHash]*BlockNode),

		bestHeaderChainMap: make(map[BlockHash]*BlockNode),

		orphanList: list.New(),
	}

	// Hold the chain lock whenever we modify this object from now on.
	bc.ChainLock.Lock()
	defer bc.ChainLock.Unlock()

	// Initialize all the in-memory data structures by loading our state
	// from the db. This function creates an initial database state containing
	// only the genesis block if we've never initialized the database before.
	if err := bc._initChain(); err != nil {
		return nil, errors.Wrapf(err, "NewBlockchain: ")
	}

	return bc, nil
}

// log2FloorMasks defines the masks to use when quickly calculating
// floor(log2(x)) in a constant log2(32) = 5 steps, where x is a uint32, using
// shifts.  They are derived from (2^(2^x) - 1) * (2^(2^x)), for x in 4..0.
var log2FloorMasks = []uint32{0xffff0000, 0xff00, 0xf0, 0xc, 0x2}

// fastLog2Floor calculates and returns floor(log2(x)) in a constant 5 steps.
func fastLog2Floor(n uint32) uint8 {
	rv := uint8(0)
	exponent := uint8(16)
	for i := 0; i < 5; i++ {
		if n&log2FloorMasks[i] != 0 {
			rv += exponent
			n >>= exponent
		}
		exponent >>= 1
	}
	return rv
}

// locateInventory returns the node of the block after the first known block in
// the locator along with the number of subsequent nodes needed to either reach
// the provided stop hash or the provided max number of entries.
//
// In addition, there are two special cases:
//
// - When no locators are provided, the stop hash is treated as a request for
//   that block, so it will either return the node associated with the stop hash
//   if it is known, or nil if it is unknown
// - When locators are provided, but none of them are known, nodes starting
//   after the genesis block will be returned
//
// This is primarily a helper function for the locateBlocks and locateHeaders
// functions.
//
// This function MUST be called with the chain state lock held (for reads).
func locateInventory(locator []*BlockHash, stopHash *BlockHash, maxEntries uint32,
	blockIndex map[BlockHash]*BlockNode, bestChainList []*BlockNode,
	bestChainMap map[BlockHash]*BlockNode) (*BlockNode, uint32) {

	// There are no block locators so a specific block is being requested
	// as identified by the stop hash.
	stopNode, stopNodeExists := blockIndex[*stopHash]
	if len(locator) == 0 {
		if !stopNodeExists {
			// No blocks with the stop hash were found so there is
			// nothing to do.
			return nil, 0
		}
		return stopNode, 1
	}

	// Find the most recent locator block hash in the main chain. In the
	// case none of the hashes in the locator are in the main chain, fall
	// back to the genesis block.
	startNode := bestChainList[0]
	for _, hash := range locator {
		node, bestChainContainsNode := bestChainMap[*hash]
		if bestChainContainsNode {
			startNode = node
			break
		}
	}

	// Start at the block after the most recently known block. When there
	// is no next block it means the most recently known block is the tip of
	// the best chain, so there is nothing more to do.
	nextNodeHeight := uint32(startNode.Header.Height) + 1
	if uint32(len(bestChainList)) <= nextNodeHeight {
		return nil, 0
	}
	startNode = bestChainList[nextNodeHeight]

	// Calculate how many entries are needed.
	tip := bestChainList[len(bestChainList)-1]
	total := uint32((tip.Header.Height - startNode.Header.Height) + 1)
	if stopNodeExists && stopNode.Header.Height >= startNode.Header.Height {

		_, bestChainContainsStopNode := bestChainMap[*stopNode.Hash]
		if bestChainContainsStopNode {
			total = uint32((stopNode.Header.Height - startNode.Header.Height) + 1)
		}
	}
	if total > maxEntries {
		total = maxEntries
	}

	return startNode, total
}

// locateHeaders returns the headers of the blocks after the first known block
// in the locator until the provided stop hash is reached, or up to the provided
// max number of block headers.
//
// See the comment on the exported function for more details on special cases.
//
// This function MUST be called with the ChainLock held (for reads).
func locateHeaders(locator []*BlockHash, stopHash *BlockHash, maxHeaders uint32,
	blockIndex map[BlockHash]*BlockNode, bestChainList []*BlockNode,
	bestChainMap map[BlockHash]*BlockNode) []*MsgDeSoHeader {

	// Find the node after the first known block in the locator and the
	// total number of nodes after it needed while respecting the stop hash
	// and max entries.
	node, total := locateInventory(locator, stopHash, maxHeaders,
		blockIndex, bestChainList, bestChainMap)
	if total == 0 {
		return nil
	}

	// Populate and return the found headers.
	headers := make([]*MsgDeSoHeader, 0, total)
	for ii := uint32(0); ii < total; ii++ {
		headers = append(headers, node.Header)
		if uint32(len(headers)) == total {
			break
		}
		node = bestChainList[node.Header.Height+1]
	}
	return headers
}

// LocateBestBlockChainHeaders returns the headers of the blocks after the first known block
// in the locator until the provided stop hash is reached, or up to a max of
// wire.MaxBlockHeadersPerMsg headers. Note that it returns the best headers
// considering only headers for which we have blocks (that is, it considers the
// best *block* chain we have rather than the best *header* chain). This is
// the correct thing to do because in general this function is called in order
// to serve a response to a peer's GetHeaders request.
//
// In addition, there are two special cases:
//
// - When no locators are provided, the stop hash is treated as a request for
//   that header, so it will either return the header for the stop hash itself
//   if it is known, or nil if it is unknown
// - When locators are provided, but none of them are known, headers starting
//   after the genesis block will be returned
//
// This function is safe for concurrent access.
func (bc *Blockchain) LocateBestBlockChainHeaders(locator []*BlockHash, stopHash *BlockHash) []*MsgDeSoHeader {
	headers := locateHeaders(locator, stopHash, MaxHeadersPerMsg,
		bc.blockIndex, bc.bestChain, bc.bestChainMap)

	return headers
}

// LatestLocator returns a block locator for the passed block node. The passed
// node can be nil in which case the block locator for the current tip
// associated with the view will be returned.
//
// BlockLocator is used to help locate a specific block.  The algorithm for
// building the block locator is to add the hashes in reverse order until
// the genesis block is reached.  In order to keep the list of locator hashes
// to a reasonable number of entries, first the most recent previous 12 block
// hashes are added, then the step is doubled each loop iteration to
// exponentially decrease the number of hashes as a function of the distance
// from the block being located.
//
// For example, assume a block chain with a side chain as depicted below:
// 	genesis -> 1 -> 2 -> ... -> 15 -> 16  -> 17  -> 18
// 	                              \-> 16a -> 17a
//
// The block locator for block 17a would be the hashes of blocks:
// [17a 16a 15 14 13 12 11 10 9 8 7 6 4 genesis]
//
// Caller is responsible for acquiring the ChainLock before calling this function.
func (bc *Blockchain) LatestLocator(tip *BlockNode) []*BlockHash {

	// Calculate the max number of entries that will ultimately be in the
	// block locator. See the description of the algorithm for how these
	// numbers are derived.
	var maxEntries uint8
	if tip.Header.Height <= 12 {
		maxEntries = uint8(tip.Header.Height) + 1
	} else {
		// Requested hash itself + previous 10 entries + genesis block.
		// Then floor(log2(height-10)) entries for the skip portion.
		adjustedHeight := uint32(tip.Header.Height) - 10
		maxEntries = 12 + fastLog2Floor(adjustedHeight)
	}
	locator := make([]*BlockHash, 0, maxEntries)

	step := int32(1)
	for tip != nil {
		locator = append(locator, tip.Hash)

		// Nothing more to add once the genesis block has been added.
		if tip.Header.Height == 0 {
			break
		}

		// Calculate height of previous node to include ensuring the
		// final node is the genesis block.
		height := int32(tip.Header.Height) - step
		if height < 0 {
			height = 0
		}

		// When the node is in the current chain view, all of its
		// ancestors must be too, so use a much faster O(1) lookup in
		// that case.  Otherwise, fall back to walking backwards through
		// the nodes of the other chain to the correct ancestor.
		if _, exists := bc.bestHeaderChainMap[*tip.Hash]; exists {
			tip = bc.bestHeaderChain[height]
		} else {
			tip = tip.Ancestor(uint32(height))
		}

		// Once 11 entries have been included, start doubling the
		// distance between included hashes.
		if len(locator) > 10 {
			step *= 2
		}
	}

	return locator
}

func (bc *Blockchain) HeaderLocatorWithNodeHash(blockHash *BlockHash) ([]*BlockHash, error) {
	node, exists := bc.blockIndex[*blockHash]
	if !exists {
		return nil, fmt.Errorf("Blockchain.HeaderLocatorWithNodeHash: Node for hash %v is not in our blockIndex", blockHash)
	}

	return bc.LatestLocator(node), nil
}

// LatestHeaderLocator calls LatestLocator in order to fetch a locator
// for the best header chain.
func (bc *Blockchain) LatestHeaderLocator() []*BlockHash {
	headerTip := bc.headerTip()

	return bc.LatestLocator(headerTip)
}

func (bc *Blockchain) GetBlockNodesToFetch(
	numBlocks int, _maxHeight int, blocksToIgnore map[BlockHash]bool) []*BlockNode {

	// Get the tip of the main block chain.
	bestBlockTip := bc.blockTip()

	// If the maxHeight is set to < 0, then we don't want to use it as a constraint.
	maxHeight := uint32(math.MaxUint32)
	if _maxHeight >= 0 {
		maxHeight = uint32(_maxHeight)
	}

	// If the tip of the best block chain is in the main header chain, make that
	// the start point for our fetch.
	headerNodeStart, blockTipExistsInBestHeaderChain := bc.bestHeaderChainMap[*bestBlockTip.Hash]
	if !blockTipExistsInBestHeaderChain {
		// If the hash of the tip of the best blockchain is not in the best header chain, then
		// this is a case where the header chain has forked off from the best block
		// chain. In this situation, the best header chain is taken as the source of truth
		// and so we iterate backward over the best header chain starting at the tip
		// until we find the first block that has StatusBlockProcessed. Then we fetch
		// blocks starting from there. Note that, at minimum, the genesis block has
		// StatusBlockProcessed so this loop is guaranteed to terminate successfully.
		headerNodeStart = bc.headerTip()
		for headerNodeStart != nil && (headerNodeStart.Status&StatusBlockProcessed) == 0 {
			headerNodeStart = headerNodeStart.Parent
		}

		if headerNodeStart == nil {
			// If for some reason we ended up with the headerNode being nil, log
			// an error and set it to the genesis block.
			glog.Errorf("GetBlockToFetch: headerNode was nil after iterating " +
				"backward through best header chain; using genesis block")
			headerNodeStart = bc.bestHeaderChain[0]
		}
	}

	// At this point, headerNodeStart should point to a node in the best header
	// chain that has StatusBlockProcessed set. As such, the blocks we need to
	// fetch are those right after this one. Fetch the desired number.
	currentHeight := headerNodeStart.Height + 1
	blockNodesToFetch := []*BlockNode{}
	heightLimit := maxHeight
	if heightLimit >= uint32(len(bc.bestHeaderChain)) {
		heightLimit = uint32(len(bc.bestHeaderChain) - 1)
	}
	for currentHeight <= heightLimit &&
		len(blockNodesToFetch) < numBlocks {

		// Get the current hash and increment the height.
		currentNode := bc.bestHeaderChain[currentHeight]
		currentHeight++

		if _, exists := blocksToIgnore[*currentNode.Hash]; exists {
			continue
		}

		blockNodesToFetch = append(blockNodesToFetch, currentNode)
	}

	// Return the nodes for the blocks we should fetch.
	return blockNodesToFetch
}

func (bc *Blockchain) HasHeader(headerHash *BlockHash) bool {
	_, exists := bc.blockIndex[*headerHash]
	return exists
}

func (bc *Blockchain) HeaderAtHeight(blockHeight uint32) *BlockNode {
	if blockHeight >= uint32(len(bc.bestHeaderChain)) {
		return nil
	}

	return bc.bestHeaderChain[blockHeight]
}

func (bc *Blockchain) HasBlock(blockHash *BlockHash) bool {
	node, nodeExists := bc.blockIndex[*blockHash]
	if !nodeExists {
		glog.V(2).Infof("Blockchain.HasBlock: Node with hash %v does not exist in node index", blockHash)
		return false
	}

	if (node.Status & StatusBlockProcessed) == 0 {
		glog.V(2).Infof("Blockchain.HasBlock: Node %v does not have StatusBlockProcessed so we don't have the block", node)
		return false
	}

	// Node exists with StatusBlockProcess set means we have it.
	return true
}

// Don't need a lock because blocks don't get removed from the db after they're added
func (bc *Blockchain) GetBlock(blockHash *BlockHash) *MsgDeSoBlock {
	blk, err := GetBlock(blockHash, bc.db)
	if err != nil {
		glog.V(2).Infof("Blockchain.GetBlock: Failed to fetch node with hash %v from the db: %v", blockHash, err)
		return nil
	}

	return blk
}

func (bc *Blockchain) GetBlockAtHeight(height uint32) *MsgDeSoBlock {
	numBlocks := uint32(len(bc.bestChain))

	if height >= numBlocks {
		return nil
	}

	return bc.GetBlock(bc.bestChain[height].Hash)
}

func (bc *Blockchain) isTipCurrent(tip *BlockNode) bool {
	minChainWorkBytes, _ := hex.DecodeString(bc.params.MinChainWorkHex)

	// Not current if the cumulative work is below the threshold.
	if tip.CumWork.Cmp(BytesToBigint(minChainWorkBytes)) < 0 {
		//glog.V(2).Infof("Blockchain.isTipCurrent: Tip not current because "+
		//"CumWork (%v) is less than minChainWorkBytes (%v)",
		//tip.CumWork, BytesToBigint(minChainWorkBytes))
		return false
	}

	// Not current if the tip has a timestamp older than the maximum
	// tip age.
	tipTime := time.Unix(int64(tip.Header.TstampSecs), 0)
	oldestAllowedTipTime := bc.timeSource.AdjustedTime().Add(-1 * bc.params.MaxTipAge)

	return !tipTime.Before(oldestAllowedTipTime)
}

type SyncState uint8

const (
	// SyncStateSyncingHeaders indicates that our header chain is not current.
	// This is the state a node will start in when it hasn't downloaded
	// anything from its peers. Because we always download headers and
	// validate them before we download blocks, SyncingHeaders implies that
	// the block tip is also not current yet.
	SyncStateSyncingHeaders SyncState = iota
	// SyncStateSyncingBlocks indicates that our header chain is current but
	// that the block chain we have is not current yet. In particular, it
	// means, among other things, that the tip of the block chain is still
	// older than max tip age.
	SyncStateSyncingBlocks
	// SyncStateNeedBlocksss indicates that our header chain is current and our
	// block chain is current but that there are headers in our main chain for
	// which we have not yet processed blocks.
	SyncStateNeedBlocksss
	// SyncStateFullyCurrent indicates that our header chain is current and that
	// we've fetched all the blocks corresponding to this chain.
	SyncStateFullyCurrent
)

func (ss SyncState) String() string {
	switch ss {
	case SyncStateSyncingHeaders:
		return "SYNCING_HEADERS"
	case SyncStateSyncingBlocks:
		return "SYNCING_BLOCKS"
	case SyncStateNeedBlocksss:
		return "NEED_BLOCKS"
	case SyncStateFullyCurrent:
		return "FULLY_CURRENT"
	default:
		return fmt.Sprintf("UNRECOGNIZED(%d) - make sure String() is up to date", ss)
	}
}

//  - Latest block height is after the latest checkpoint (if enabled)
//  - Latest block has a timestamp newer than 24 hours ago
//
// This function MUST be called with the ChainLock held (for reads).
func (bc *Blockchain) chainState() SyncState {
	// If the header is not current, then we're in the SyncStateSyncingHeaders.
	headerTip := bc.headerTip()
	if !bc.isTipCurrent(headerTip) {
		return SyncStateSyncingHeaders
	}

	// If the header tip is current but the block tip isn't then we're in
	// the SyncStateSyncingBlocks state.
	blockTip := bc.blockTip()
	if !bc.isTipCurrent(blockTip) {
		return SyncStateSyncingBlocks
	}

	// If the header tip is current and the block tip is current but the block
	// tip is not equal to the header tip then we're in SyncStateNeedBlocks.
	if *blockTip.Hash != *headerTip.Hash {
		return SyncStateNeedBlocksss
	}

	// If none of the checks above returned it means we're current.
	return SyncStateFullyCurrent
}

func (bc *Blockchain) ChainState() SyncState {
	return bc.chainState()
}

func (bc *Blockchain) isSyncing() bool {
	syncState := bc.chainState()
	return syncState == SyncStateSyncingHeaders || syncState == SyncStateSyncingBlocks
}

// headerTip returns the tip of the header chain. Because we fetch headers
// before we fetch blocks, we track a chain for headers as separate from the
// main chain for blocks, which is why separate functions are required for
// each of them.
func (bc *Blockchain) headerTip() *BlockNode {
	if len(bc.bestHeaderChain) == 0 {
		return nil
	}

	// Note this should always work because we should have the genesis block
	// in here.
	return bc.bestHeaderChain[len(bc.bestHeaderChain)-1]
}

func (bc *Blockchain) HeaderTip() *BlockNode {
	return bc.headerTip()
}

func (bc *Blockchain) DB() *badger.DB {
	return bc.db
}

// blockTip returns the tip of the main block chain. We fetch headers first
// and then, once the header chain looks good, we fetch blocks. As such, we
// store two separate "best" chains: One containing the best headers, and
// the other containing the best blocks. The header chain is essentially a
// trail-blazer, validating headers as fast as it can before later fetching
// blocks for the headers that seem legitimate and adding them to the "real"
// best chain. If, while adding blocks to the best block chain, we realize
// some of the blocks are invalid, the best header chain is then adjusted to
// invalidate and chop off the headers corresponding to those blocks and
// their ancestors so the two generally stay in sync.
func (bc *Blockchain) blockTip() *BlockNode {
	var tip *BlockNode

	if len(bc.bestChain) == 0 {
		return nil
	}

	tip = bc.bestChain[len(bc.bestChain)-1]

	return tip
}

func (bc *Blockchain) BlockTip() *BlockNode {
	return bc.blockTip()
}

func (bc *Blockchain) BestChain() []*BlockNode {
	return bc.bestChain
}

func (bc *Blockchain) SetBestChain(bestChain []*BlockNode) {
	bc.bestChain = bestChain
}

func (bc *Blockchain) SetBestChainMap(bestChain []*BlockNode, bestChainMap map[BlockHash]*BlockNode, blockIndex map[BlockHash]*BlockNode) {
	bc.bestChain = bestChain
	bc.bestChainMap = bestChainMap
	bc.blockIndex = blockIndex
}

func (bc *Blockchain) _validateOrphanBlock(desoBlock *MsgDeSoBlock) error {
	// Error if the block is missing a parent hash or header.
	if desoBlock.Header == nil {
		return fmt.Errorf("_validateOrphanBlock: Block is missing header")
	}
	parentHash := desoBlock.Header.PrevBlockHash
	if parentHash == nil {
		return fmt.Errorf("_validateOrphanBlock: Block is missing parent hash")
	}

	// Check that the block size isn't bigger than the max allowed. This prevents
	// an attack vector where someone might try and send us very large orphan blocks in
	// an attempt to exhaust our memory.
	serializedBlock, err := desoBlock.ToBytes(false)
	if err != nil {
		return fmt.Errorf("_validateOrphanBlock: Could not serialize block")
	}
	if uint64(len(serializedBlock)) > bc.params.MaxBlockSizeBytes {
		return RuleErrorBlockTooBig
	}

	// No more validation is needed since the orphan will be properly validated
	// if and when we ever end up adding it to our block index either on the main
	// chain or on a side chain.
	//
	// TODO: It would be nice to do some kind of PoW check on unconnectedTxns, but it
	// seems useless because anyone who has access to MaxOrphansInMemory orphan
	// blocks has the ability to fill our orphan lists with garbage. Put another
	// way, a simple PoW check on orphan blocks doesn't seem to increase the cost
	// of an attack materially and could have negative effects if e.g. legitimate unconnectedTxns
	// earlier in the chain get filtered out because their difficulty is too low.
	// Moreover, while being attacked would be a minor inconvenience it doesn't
	// stop the node from reaching consensus eventually. So we'll punt on defending
	// against it unless/until it actually becomes a problem.

	return nil
}

// ProcessOrphanBlock runs some very basic validation on the orphan block and adds
// it to our orphan data structure if it passes. If there are too many orphan blocks
// in our data structure, it also evicts the oldest block to make room for this one.
//
// TODO: Currently we only remove orphan blocks if we have too many. This means in
// a steady state we are potentially keeping MaxOrphansInMemory at all times, which
// is wasteful of resources. Better would be to clean up orphan blocks once they're
// too old or something like that.
func (bc *Blockchain) ProcessOrphanBlock(desoBlock *MsgDeSoBlock, blockHash *BlockHash) error {
	err := bc._validateOrphanBlock(desoBlock)
	if err != nil {
		return errors.Wrapf(err, "ProcessOrphanBlock: Problem validating orphan block")
	}

	// If this block is already in the orphan list then don't add it.
	//
	// TODO: We do a basic linear search here because there are so few unconnectedTxns
	// in our list. If we want to track more unconnectedTxns in the future we would probably
	// want to manage this with a map.
	for orphanElem := bc.orphanList.Front(); orphanElem != nil; orphanElem = orphanElem.Next() {
		orphanBlock := orphanElem.Value.(*OrphanBlock)
		if *orphanBlock.Hash == *blockHash {
			return RuleErrorDuplicateOrphan
		}
	}

	// At this point we know we are adding a new orphan to the list.

	// If we are at capacity remove an orphan block by simply deleting the front
	// element of the orphan list, which is also the oldest orphan.
	if bc.orphanList.Len() >= MaxOrphansInMemory {
		elemToRemove := bc.orphanList.Front()
		bc.orphanList.Remove(elemToRemove)
	}

	// Add the orphan block to our data structure. We can also assume the orphan
	// is not a duplicate and therefore simply add a new entry to the end of the list.
	bc.orphanList.PushBack(&OrphanBlock{
		Block: desoBlock,
		Hash:  blockHash,
	})

	return nil
}

func (bc *Blockchain) MarkBlockInvalid(node *BlockNode, errOccurred RuleError) {
	// Print a stack trace when this happens
	glog.Errorf("MarkBlockInvalid: Block height: %v, Block hash: %v, Error: %v", node.Height, node.Hash, errOccurred)
	glog.Error("MarkBlockInvalid: Printing stack trace so error is easy to find: ")
	glog.Error(string(debug.Stack()))

	// TODO: Not marking blocks invalid makes debugging easier when we hit an issuse,
	// and makes it so that we don't need to start the node from scratch when it has a
	// problem. But it can also make connecting to a bad peer more risky. In the future, once
	// syncing issues are all resolved, bad blocks should be marked as such and probably
	// not reprocessed.
	glog.Error("MarkBlockInvalid: Not marking blocks invalid for now because it makes debugging easier")

	//panic(errOccurred)

	// Mark the node's block as invalid.
	//node.Status |= StatusBlockValidateFailed
	//
	//// If this node happens to be in the main header chain, mark
	//// every node after this one in the header chain as invalid and
	//// remove these nodes from the header chain to keep it in sync.
	//if _, nodeInHeaderChain := bc.bestHeaderChainMap[*node.Hash]; nodeInHeaderChain {
	//	for ii := node.Height; ii < uint32(len(bc.bestHeaderChain)); ii++ {
	//		// Update the status of the node. Mark it as processed since that's used
	//		// to determine whether we shoudl fetch the block.
	//		headerNode := bc.bestHeaderChain[ii]
	//		headerNode.Status |= (StatusBlockProcessed & StatusBlockValidateFailed)
	//		if err := PutHeightHashToNodeInfo(headerNode, bc.db, false /*bitcoinNodes*/); err != nil {
	//			// Log if an error occurs but no need to return it.
	//			glog.Error(errors.Wrapf(err,
	//				"MarkBlockInvalid: Problem calling PutHeightHashToNodeInfo on header node"))
	//		}
	//
	//		delete(bc.bestHeaderChainMap, *headerNode.Hash)
	//	}
	//	// Chop off the nodes now that we've updated the status of all of them.
	//	bc.bestHeaderChain = bc.bestHeaderChain[:node.Height]
	//
	//	// Note there is no need to update the db for the header chain because we don't
	//	// store nodes for headers on the db.
	//
	//	// At this point the header main chain should be fully updated in memory
	//	// and in the db to reflect that all nodes from this one onward are invalid
	//	// and should no longer be considered as part of the main chain.
	//}
	//
	//// Update the node on the db to reflect the status change.
	////
	//// Put the node in our node index in the db under the
	////   <height uin32, blockhash BlockHash> -> <node info>
	//// index.
	//if err := PutHeightHashToNodeInfo(node, bc.db, false /*bitcoinNodes*/); err != nil {
	//	// Log if an error occurs but no need to return it.
	//	glog.Error(errors.Wrapf(err,
	//		"MarkBlockInvalid: Problem calling PutHeightHashToNodeInfo"))
	//}
}

func _FindCommonAncestor(node1 *BlockNode, node2 *BlockNode) *BlockNode {
	if node1 == nil || node2 == nil {
		// If either node is nil then there can't be a common ancestor.
		return nil
	}

	// Get the two nodes to be at the same height.
	if node1.Height > node2.Height {
		node1 = node1.Ancestor(node2.Height)
	} else if node1.Height < node2.Height {
		node2 = node2.Ancestor(node1.Height)
	}

	// Iterate the nodes backward until they're either the same or we
	// reach the end of the lists. We only need to check node1 for nil
	// since they're the same height and we are iterating both back
	// in tandem.
	for node1 != nil && node1 != node2 {
		node1 = node1.Parent
		node2 = node2.Parent
	}

	// By now either node1 == node2 and we found the common ancestor or
	// both nodes are nil, which means we reached the bottom without finding
	// a common ancestor.
	return node1
}

func CheckTransactionSanity(txn *MsgDeSoTxn) error {
	// We don't check the sanity of block reward transactions.
	if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
		return nil
	}

	// All transactions are required to have a valid public key set unless they are one
	// of the following:
	// - BitcoinExchange transactions don't need a PublicKey because the public key can
	//   easily be derived from the BitcoinTransaction embedded in the TxnMeta.
	requiresPublicKey := txn.TxnMeta.GetTxnType() != TxnTypeBitcoinExchange
	if requiresPublicKey {
		if len(txn.PublicKey) != btcec.PubKeyBytesLenCompressed {
			return errors.Wrapf(RuleErrorTransactionMissingPublicKey, "CheckTransactionSanity: ")
		}
	}

	// Every txn must have at least one input unless it is one of the following
	// transaction types.
	// - BitcoinExchange transactions will be rejected if they're duplicates in
	//   spite of the fact that they don't have inputs or outputs.
	//
	// Note this function isn't run on BlockReward transactions, but that they're
	// allowed to have zero inputs as well. In the case of BlockRewards, they could
	// have duplicates if someone uses the same public key without changing the
	// ExtraNonce field, but this is not the default behavior, and in general the
	// only thing a duplicate will do is make a previous transaction invalid, so
	// there's not much incentive to do it.
	//
	// TODO: The above is easily fixed by requiring something like block height to
	// be present in the ExtraNonce field.
	canHaveZeroInputs := (txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange ||
		txn.TxnMeta.GetTxnType() == TxnTypePrivateMessage)
	if len(txn.TxInputs) == 0 && !canHaveZeroInputs {
		glog.V(2).Infof("CheckTransactionSanity: Txn needs at least one input: %v", spew.Sdump(txn))
		return RuleErrorTxnMustHaveAtLeastOneInput
	}

	// Loop through the outputs and do a few sanity checks.
	var totalOutNanos uint64
	for _, txout := range txn.TxOutputs {
		// Check that each output's amount is not bigger than the max as a
		// sanity check.
		if txout.AmountNanos > MaxNanos {
			return RuleErrorOutputExceedsMax
		}
		// Check that this output doesn't overflow the total as a sanity
		// check. This is frankly impossible since our maximum limit is
		// not close to the max size of a uint64 but check it nevertheless.
		if totalOutNanos >= math.MaxUint64-txout.AmountNanos {
			return RuleErrorOutputOverflowsTotal
		}
		// Check that the total isn't bigger than the max supply.
		if totalOutNanos > MaxNanos {
			return RuleErrorTotalOutputExceedsMax
		}
	}

	// Loop through the inputs and do a few sanity checks.
	existingInputs := make(map[DeSoInput]bool)
	for _, txin := range txn.TxInputs {
		if _, exists := existingInputs[*txin]; exists {
			return RuleErrorDuplicateInputs
		}
		existingInputs[*txin] = true
	}

	return nil
}

func GetReorgBlocks(tip *BlockNode, newNode *BlockNode) (_commonAncestor *BlockNode, _detachNodes []*BlockNode, _attachNodes []*BlockNode) {
	// Find the common ancestor of this block and the main header chain.
	commonAncestor := _FindCommonAncestor(tip, newNode)
	// Log a warning if the reorg is going to be a big one.
	numBlocks := tip.Height - commonAncestor.Height
	if numBlocks > 10 {
		glog.Warningf("GetReorgBlocks: Proceeding with reorg of (%d) blocks from "+
			"block (%v) at height (%d) to block (%v) at height of (%d)",
			numBlocks, tip, tip.Height, newNode, newNode.Height)
	}

	// Get the blocks to detach. Start at the tip and work backwards to the
	// common ancestor (but don't include the common ancestor since we don't
	// need to roll that back).
	//
	// detachBlocks will have the current tip as its first element and parents
	// of the tip thereafter.
	detachBlocks := []*BlockNode{}
	for currentBlock := tip; *currentBlock.Hash != *commonAncestor.Hash; currentBlock = currentBlock.Parent {
		detachBlocks = append(detachBlocks, currentBlock)
	}

	// Get the blocks to attach. Start at the new node and work backwards to
	// the common ancestor (but don't include the common ancestor since we'll
	// be using it as the new tip after we detach all the blocks from the current
	// tip).
	//
	// attachNodes will have the new node as its first element and work back to
	// the node right after the common ancestor as its last element.
	attachBlocks := []*BlockNode{}
	for currentBlock := newNode; *currentBlock.Hash != *commonAncestor.Hash; currentBlock = currentBlock.Parent {
		attachBlocks = append(attachBlocks, currentBlock)
	}
	// Reverse attachBlocks so that the node right after the common ancestor
	// will be the first element and the node at the end of the list will be
	// the new node.
	for i, j := 0, len(attachBlocks)-1; i < j; i, j = i+1, j-1 {
		attachBlocks[i], attachBlocks[j] = attachBlocks[j], attachBlocks[i]
	}

	return commonAncestor, detachBlocks, attachBlocks
}

func updateBestChainInMemory(mainChainList []*BlockNode, mainChainMap map[BlockHash]*BlockNode, detachBlocks []*BlockNode, attachBlocks []*BlockNode) (
	chainList []*BlockNode, chainMap map[BlockHash]*BlockNode) {

	// Remove the nodes we detached from the end of the best chain node list.
	tipIndex := len(mainChainList) - 1
	for blockOffset := 0; blockOffset < len(detachBlocks); blockOffset++ {
		blockIndex := tipIndex - blockOffset
		delete(mainChainMap, *mainChainList[blockIndex].Hash)
	}
	mainChainList = mainChainList[:len(mainChainList)-len(detachBlocks)]

	// Add the nodes we attached to the end of the list. Note that this loop iterates
	// forward because because attachBlocks has the node right after the common ancestor
	// first, with the new tip at the end.
	for _, attachNode := range attachBlocks {
		mainChainList = append(mainChainList, attachNode)
		mainChainMap[*attachNode.Hash] = attachNode
	}

	return mainChainList, mainChainMap
}

// Caller must acquire the ChainLock for writing prior to calling this.
func (bc *Blockchain) processHeader(blockHeader *MsgDeSoHeader, headerHash *BlockHash) (_isMainChain bool, _isOrphan bool, _err error) {
	// Start by checking if the header already exists in our node
	// index. If it does, then return an error. We should generally
	// expect that processHeader will only be called on headers we
	// haven't seen before.
	_, nodeExists := bc.blockIndex[*headerHash]
	if nodeExists {
		return false, false, HeaderErrorDuplicateHeader
	}

	// If we're here then it means we're processing a header we haven't
	// seen before.

	// Reject the header if it is more than N seconds in the future.
	tstampDiff := int64(blockHeader.TstampSecs) - bc.timeSource.AdjustedTime().Unix()
	if tstampDiff > int64(bc.params.MaxTstampOffsetSeconds) {
		glog.V(1).Infof("HeaderErrorBlockTooFarInTheFuture: tstampDiff %d > "+
			"MaxTstampOffsetSeconds %d. blockHeader.TstampSecs=%d; adjustedTime=%d",
			tstampDiff, bc.params.MaxTstampOffsetSeconds, blockHeader.TstampSecs,
			bc.timeSource.AdjustedTime().Unix())
		return false, false, HeaderErrorBlockTooFarInTheFuture
	}

	// Try to find this header's parent in our block index.
	// If we can't find the parent then this header is an orphan and we
	// can return early because we don't process unconnectedTxns.
	// TODO: Should we just return an error if the header is an orphan?
	if blockHeader.PrevBlockHash == nil {
		return false, false, HeaderErrorNilPrevHash
	}
	parentNode, parentNodeExists := bc.blockIndex[*blockHeader.PrevBlockHash]
	if !parentNodeExists {
		// This block is an orphan if its parent doesn't exist and we don't
		// process unconnectedTxns.
		return false, true, nil
	}

	// If the parent node is invalid then this header is invalid as well. Note that
	// if the parent node exists then its header must either be Validated or
	// ValidateFailed.
	parentHeader := parentNode.Header
	if parentHeader == nil || (parentNode.Status&(StatusHeaderValidateFailed|StatusBlockValidateFailed)) != 0 {
		return false, false, errors.Wrapf(
			HeaderErrorInvalidParent, "Parent header: %v, Status check: %v, Parent node status: %v, Parent node header: %v",
			parentHeader, (parentNode.Status&(StatusHeaderValidateFailed|StatusBlockValidateFailed)) != 0,
			parentNode.Status,
			parentNode.Header)
	}

	// Verify that the height is one greater than the parent.
	prevHeight := parentHeader.Height
	if blockHeader.Height != prevHeight+1 {
		glog.Errorf("processHeader: Height of block (=%d) is not equal to one greater "+
			"than the parent height (=%d)", blockHeader.Height, prevHeight)
		return false, false, HeaderErrorHeightInvalid
	}

	// Make sure the block timestamp is greater than the previous block's timestamp.
	// Note Bitcoin checks that the timestamp is greater than the median
	// of the last 11 blocks. While this seems to work for Bitcoin for now it seems
	// vulnerable to a "time warp" attack (requires 51%) and
	// we can do a little better by forcing a harder constraint of making
	// sure a timestamp is larger than the of the previous block. It seems
	// the only real downside of this is some complexity on the miner side
	// of having to account for what happens if a block appears that is from
	// some nearby time in the future rather than the current time. But this
	// burden seems worth it in order to
	// preclude a known and fairly damaging attack from being possible. Moreover,
	// while there are more complicated schemes to fight other attacks based on
	// timestamp manipulation, their benefits seem marginal and not worth the
	// added complexity they entail for now.
	//
	// Discussion of time warp attack and potential fixes for BTC:
	// https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-August/016342.html
	// Discussion of more complex attacks and potential fixes:
	// https://github.com/zawy12/difficulty-algorithms/issues/30
	//
	// TODO: Consider a per-block difficulty adjustment scheme like Ethereum has.
	// This commentary is useful to consider with regard to that:
	//   https://github.com/zawy12/difficulty-algorithms/issues/45
	if blockHeader.TstampSecs <= parentHeader.TstampSecs {
		glog.Warningf("processHeader: Rejecting header because timestamp %v is "+
			"before timestamp of previous block %v",
			time.Unix(int64(blockHeader.TstampSecs), 0),
			time.Unix(int64(parentHeader.TstampSecs), 0))
		return false, false, HeaderErrorTimestampTooEarly
	}

	// Check that the proof of work beats the difficulty as calculated from
	// the parent block. Note that if the parent block is in the block index
	// then it has necessarily had its difficulty validated, and so using it to
	// do this check makes sense.
	diffTarget, err := CalcNextDifficultyTarget(
		parentNode, blockHeader.Version, bc.params)
	if err != nil {
		return false, false, errors.Wrapf(err,
			"ProcessBlock: Problem computing difficulty "+
				"target from parent block %s", hex.EncodeToString(parentNode.Hash[:]))
	}
	diffTargetBigint := HashToBigint(diffTarget)
	blockHashBigint := HashToBigint(headerHash)
	if diffTargetBigint.Cmp(blockHashBigint) < 0 {
		return false, false,
			errors.Wrapf(HeaderErrorBlockDifficultyAboveTarget, "Target: %v, Actual: %v", diffTarget, headerHash)
	}

	// At this point the header seems sane so we store it in the db and add
	// it to our in-memory block index. Note we're not doing this atomically.
	// Worst-case, we have a block in our db with no pointer to it in our index,
	// which isn't a big deal.
	//
	// Note in the calculation of CumWork below we are adding the work specified
	// in the difficulty *target* rather than the work actually done to mine the
	// block. There is a very good reason for this, which is that it materially
	// increases a miner's incentive to reveal their block immediately after it's
	// been mined as opposed to try and play games where they withhold their block
	// and try to mine on top of it before revealing it to everyone.
	newWork := BytesToBigint(ExpectedWorkForBlockHash(diffTarget)[:])
	cumWork := newWork.Add(newWork, parentNode.CumWork)
	newNode := NewBlockNode(
		parentNode,
		headerHash,
		uint32(blockHeader.Height),
		diffTarget,
		cumWork,
		blockHeader,
		StatusHeaderValidated)

	// Note that we don't store a node for this header on the db until we have downloaded
	// a corresponding block. This has the effect of preventing us against disk-fill
	// attacks. If we instead stored headers on the db then we'd have to deal with an
	// attack that looks as follows:
	// - Attacker makes us download a lot of low-difficulty headers until we eventually
	//   get current and disconnect because the chainwork is too low (having stored all
	//   of those header nodes on the db).
	// - Attacker repeats this over and over again until our db on disk is really full.
	//
	// The above is mitigated because we don't download blocks until we have a header chain
	// with enough work, which means we won't store anything that doesn't have a lot of work
	// built on it.

	// If all went well with storing the header, set it in our in-memory
	// index. If we're still syncing then it's safe to just set it. Otherwise, we
	// need to make a copy first since there could be some concurrency issues.
	if bc.isSyncing() {
		bc.blockIndex[*newNode.Hash] = newNode
	} else {
		newBlockIndex := bc.CopyBlockIndex()
		newBlockIndex[*newNode.Hash] = newNode
		bc.blockIndex = newBlockIndex
	}

	// Update the header chain if this header has more cumulative work than
	// the header chain's tip. Note that we can assume all ancestors of this
	// header are valid at this point.
	isMainChain := false
	headerTip := bc.headerTip()
	if headerTip.CumWork.Cmp(newNode.CumWork) < 0 {
		isMainChain = true

		_, detachBlocks, attachBlocks := GetReorgBlocks(headerTip, newNode)
		bc.bestHeaderChain, bc.bestHeaderChainMap = updateBestChainInMemory(
			bc.bestHeaderChain, bc.bestHeaderChainMap, detachBlocks, attachBlocks)

		// Note that we don't store the best header hash here and so this is an
		// in-memory-only adjustment. See the comment above on preventing attacks.
	}

	return isMainChain, false, nil
}

// ProcessHeader is a wrapper around processHeader, which does the leg-work, that
// acquires the ChainLock first.
func (bc *Blockchain) ProcessHeader(blockHeader *MsgDeSoHeader, headerHash *BlockHash) (_isMainChain bool, _isOrphan bool, _err error) {
	bc.ChainLock.Lock()
	defer bc.ChainLock.Unlock()

	return bc.processHeader(blockHeader, headerHash)
}

// Note: It is the caller's responsibility to ensure that the BitcoinManager is
// time-current prior to calling ProcessBlock on any transactions that require the
// BitcoinManager for validation (e.g. BitcoinExchange transactions). Failure to
// do so will cause ProcessBlock to error on blocks that could otherwise be valid
// if a time-current BitcoinManager were available. If it is known for sure that
// no BitcoinExchange transactions need to be validated then it is OK for the
// BitcoinManager to not be time-current and even for it to be nil entirely. This
// is useful e.g. for tests where we want to exercise ProcessBlock without setting
// up a time-current BitcoinManager.
func (bc *Blockchain) ProcessBlock(desoBlock *MsgDeSoBlock, verifySignatures bool) (_isMainChain bool, _isOrphan bool, _err error) {
	// TODO: Move this to be more isolated.
	bc.ChainLock.Lock()
	defer bc.ChainLock.Unlock()

	if desoBlock == nil {
		return false, false, fmt.Errorf("ProcessBlock: Block is nil")
	}

	// Start by getting and validating the block's header.
	blockHeader := desoBlock.Header
	if blockHeader == nil {
		return false, false, fmt.Errorf("ProcessBlock: Block header was nil")
	}
	blockHash, err := blockHeader.Hash()
	if err != nil {
		return false, false, errors.Wrapf(err, "ProcessBlock: Problem computing block hash")
	}
	// If a trusted block producer public key is set, then we only accept blocks
	// if they have been signed by one of these public keys.
	if len(bc.trustedBlockProducerPublicKeys) > 0 {
		if blockHeader.Height >= bc.trustedBlockProducerStartHeight {
			if desoBlock.BlockProducerInfo == nil ||
				desoBlock.BlockProducerInfo.Signature == nil {

				return false, false, errors.Wrapf(RuleErrorMissingBlockProducerSignature,
					"ProcessBlock: Block signature is required since "+
						"--trusted_block_producer_public_keys is set *and* block height "+
						"%v is >= --trusted_block_producer_block_height %v.", blockHeader.Height,
					bc.trustedBlockProducerStartHeight)
			}
			// At this point, we are confident that a signature is embedded in
			// the block.

			// Verify that the public key has the valid length
			publicKey := desoBlock.BlockProducerInfo.PublicKey
			if len(publicKey) != btcec.PubKeyBytesLenCompressed {
				return false, false, errors.Wrapf(RuleErrorInvalidBlockProducerPublicKey,
					"ProcessBlock: Block producer public key is invalid even though "+
						"--trusted_block_producer_public_keys is set *and* block height "+
						"%v is >= --trusted_block_producer_block_height %v.", blockHeader.Height,
					bc.trustedBlockProducerStartHeight)
			}

			// Verify that the public key is in the allowed set.
			if _, exists := bc.trustedBlockProducerPublicKeys[MakePkMapKey(publicKey)]; !exists {
				return false, false, errors.Wrapf(RuleErrorBlockProducerPublicKeyNotInWhitelist,
					"ProcessBlock: Block producer public key %v is not in the allowed list of "+
						"--trusted_block_producer_public_keys: %v.", PkToStringBoth(publicKey),
					bc.trustedBlockProducerPublicKeys)
			}

			// Verify that the public key has not been forbidden.
			dbEntry := DbGetForbiddenBlockSignaturePubKey(bc.db, publicKey)
			if dbEntry != nil {
				return false, false, errors.Wrapf(RuleErrorForbiddenBlockProducerPublicKey,
					"ProcessBlock: Block producer public key %v is forbidden", PkToStringBoth(publicKey))
			}

			// At this point we are confident that we have a valid public key that is
			// trusted.

			signature := desoBlock.BlockProducerInfo.Signature
			pkObj, err := btcec.ParsePubKey(publicKey, btcec.S256())
			if err != nil {
				return false, false, errors.Wrapf(err,
					"ProcessBlock: Error parsing block producer public key: %v.",
					PkToStringBoth(publicKey))
			}
			if !signature.Verify(blockHash[:], pkObj) {
				return false, false, errors.Wrapf(RuleErrorInvalidBlockProducerSIgnature,
					"ProcessBlock: Error validating signature %v for public key %v: %v.",
					hex.EncodeToString(signature.Serialize()),
					PkToStringBoth(publicKey),
					err)
			}
		}
	}

	// See if a node for the block exists in our node index.
	nodeToValidate, nodeExists := bc.blockIndex[*blockHash]
	// If no node exists for this block at all, then process the header
	// first before we do anything. This should create a node and set
	// the header validation status for it.
	if !nodeExists {
		_, isOrphan, err := bc.processHeader(blockHeader, blockHash)
		if err != nil {
			// If an error occurred processing the header, then the header
			// should be marked as invalid, which should be sufficient.
			return false, false, err
		}
		// If the header is an orphan, return early. We don't process orphan
		// blocks. If the block and its header are truly legitimate then we
		// should re-request it and its parents from a peer and reprocess it
		// once it is no longer an orphan.
		if isOrphan {
			return false, true, nil
		}

		// Reset the pointers after having presumably added the header to the
		// block index.
		nodeToValidate, nodeExists = bc.blockIndex[*blockHash]
	}
	// At this point if the node still doesn't exist or if the header's validation
	// failed then we should return an error for the block. Note that at this point
	// the header must either be Validated or ValidateFailed.
	if !nodeExists || (nodeToValidate.Status&StatusHeaderValidated) == 0 {
		return false, false, RuleErrorInvalidBlockHeader
	}

	// At this point, we are sure that the block's header is not an orphan and
	// that its header has been properly validated. The block itself could still
	// be an orphan, however, for example if we've processed the header of the parent but
	// not the parent block itself.
	//
	// Find the parent node in our block index. If the node doesn't exist or if the
	// node exists without StatusBlockProcessed, then the current block is an orphan.
	// In this case go ahead and return early. If its parents are truly legitimate then we
	// should re-request it and its parents from a node and reprocess it
	// once it is no longer an orphan.
	parentNode, parentNodeExists := bc.blockIndex[*blockHeader.PrevBlockHash]
	if !parentNodeExists || (parentNode.Status&StatusBlockProcessed) == 0 {
		return false, true, nil
	}

	// At this point, because we know the block isn't an orphan, go ahead and mark
	// it as processed. This flag is basically used to avoid situations in which we
	// continuously try to fetch and reprocess a block because we forgot to mark
	// it as invalid (which would be a bug but this behavior allows us to handle
	// it more gracefully).
	nodeToValidate.Status |= StatusBlockProcessed

	if bc.postgres != nil {
		if err := bc.postgres.UpsertBlock(nodeToValidate); err != nil {
			return false, false, errors.Wrapf(err,
				"ProcessBlock: Problem saving block with StatusBlockProcessed")
		}
	} else {
		if err := PutHeightHashToNodeInfo(nodeToValidate, bc.db, false /*bitcoinNodes*/); err != nil {
			return false, false, errors.Wrapf(
				err, "ProcessBlock: Problem calling PutHeightHashToNodeInfo with StatusBlockProcessed")
		}
	}

	// Reject the block if any of the following apply to the parent:
	// - Its header is nil.
	// - Its header or its block validation failed.
	if parentNode.Header == nil ||
		(parentNode.Status&(StatusHeaderValidateFailed|StatusBlockValidateFailed)) != 0 {

		bc.MarkBlockInvalid(nodeToValidate, RuleErrorPreviousBlockInvalid)
		return false, false, RuleErrorPreviousBlockInvalid
	}

	// At this point, we know that we are processing a block we haven't seen
	// before and we know that the parent block is stored and not invalid.

	// Make sure the block size is not too big.
	serializedBlock, err := desoBlock.ToBytes(false)
	if err != nil {
		// Don't mark the block invalid here since the serialization is
		// potentially a network issue not an issue with the actual block.
		return false, false, fmt.Errorf("ProcessBlock: Problem serializing block")
	}
	if uint64(len(serializedBlock)) > bc.params.MaxBlockSizeBytes {
		bc.MarkBlockInvalid(nodeToValidate, RuleErrorBlockTooBig)
		return false, false, RuleErrorBlockTooBig
	}

	// Block must have at least one transaction.
	if len(desoBlock.Txns) == 0 {
		bc.MarkBlockInvalid(nodeToValidate, RuleErrorNoTxns)
		return false, false, RuleErrorNoTxns
	}

	// The first transaction in a block must be a block reward.
	firstTxn := desoBlock.Txns[0]
	if firstTxn.TxnMeta.GetTxnType() != TxnTypeBlockReward {
		return false, false, RuleErrorFirstTxnMustBeBlockReward
	}

	// Do some txn sanity checks.
	for _, txn := range desoBlock.Txns[1:] {
		// There shouldn't be more than one block reward in the transaction list.
		if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
			bc.MarkBlockInvalid(nodeToValidate, RuleErrorMoreThanOneBlockReward)
			return false, false, RuleErrorMoreThanOneBlockReward
		}

		if err := CheckTransactionSanity(txn); err != nil {
			bc.MarkBlockInvalid(
				nodeToValidate, RuleError(errors.Wrapf(RuleErrorTxnSanity, "Error: %v", err).Error()))
			return false, false, err
		}
	}

	// Compute and check the merkle root of all the txns.
	merkleRoot, txHashes, err := ComputeMerkleRoot(desoBlock.Txns)
	if err != nil {
		// Don't mark the block invalid here since the serialization is
		// potentially a network issue not an issue with the actual block.
		return false, false, errors.Wrapf(err, "ProcessBlock: Problem computing merkle root")
	}
	if *merkleRoot != *blockHeader.TransactionMerkleRoot {
		bc.MarkBlockInvalid(nodeToValidate, RuleErrorInvalidTxnMerkleRoot)
		glog.Errorf("ProcessBlock: Merkle root in block %v does not match computed "+
			"merkle root %v", blockHeader.TransactionMerkleRoot, merkleRoot)
		return false, false, RuleErrorInvalidTxnMerkleRoot
	}

	// Check for duplicate txns now that they're hashed.
	existingTxns := make(map[BlockHash]bool)
	for ii := range desoBlock.Txns {
		currentHash := *txHashes[ii]
		if _, exists := existingTxns[currentHash]; exists {
			bc.MarkBlockInvalid(nodeToValidate, RuleErrorDuplicateTxn)
			return false, false, RuleErrorDuplicateTxn
		}
		existingTxns[currentHash] = true
	}

	// Try and store the block and its corresponding node info since it has passed
	// basic validation.
	nodeToValidate.Status |= StatusBlockStored

	if bc.postgres != nil {
		if err = bc.postgres.UpsertBlock(nodeToValidate); err != nil {
			err = errors.Wrapf(err, "ProcessBlock: Problem saving block with StatusBlockStored")
		}
	} else {
		err = bc.db.Update(func(txn *badger.Txn) error {
			// Store the new block in the db under the
			//   <blockHash> -> <serialized block>
			// index.
			if err := PutBlockWithTxn(txn, desoBlock); err != nil {
				return errors.Wrapf(err, "ProcessBlock: Problem calling PutBlock")
			}

			// Store the new block's node in our node index in the db under the
			//   <height uin32, blockhash BlockHash> -> <node info>
			// index.
			if err := PutHeightHashToNodeInfoWithTxn(txn, nodeToValidate, false /*bitcoinNodes*/); err != nil {
				return errors.Wrapf(err, "ProcessBlock: Problem calling PutHeightHashToNodeInfo before validation")
			}

			return nil
		})
	}

	if err != nil {
		return false, false, errors.Wrapf(err, "ProcessBlock: Problem storing block after basic validation")
	}

	// Now we try and add the block to the main block chain (note that it should
	// already be on the main header chain if we've made it this far).

	// Get the current tip.
	currentTip := bc.blockTip()

	// See if the current tip is equal to the block's parent.
	isMainChain := false

	if *parentNode.Hash == *currentTip.Hash {
		// Create a new UtxoView representing the current tip.
		//
		// TODO: An optimization can be made here where we pre-load all the inputs this txn
		// requires into the view before-hand. This basically requires two passes over
		// the txns to account for txns that spend previous txns in the block, but it would
		// almost certainly be more efficient than doing a separate db call for each input
		// and output.
		utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres)
		if err != nil {
			return false, false, errors.Wrapf(err, "ProcessBlock: Problem initializing UtxoView in simple connect to tip")
		}

		// Preload the view with almost all of the data it will need to connect the block
		err = utxoView.Preload(desoBlock)
		if err != nil {
			glog.Errorf("ProcessBlock: Problem preloading the view: %v", err)
		}

		// Verify that the utxo view is pointing to the current tip.
		if *utxoView.TipHash != *currentTip.Hash {
			//return false, false, fmt.Errorf("ProcessBlock: Tip hash for utxo view (%v) is "+
			//	"not the current tip hash (%v)", utxoView.TipHash, currentTip.Hash)
			glog.Errorf("ProcessBlock: Tip hash for utxo view (%v) is "+
				"not the current tip hash (%v)", utxoView.TipHash, currentTip.Hash)
		}

		utxoOpsForBlock, err := utxoView.ConnectBlock(desoBlock, txHashes, verifySignatures, nil)
		if err != nil {
			if IsRuleError(err) {
				// If we have a RuleError, mark the block as invalid before
				// returning.
				bc.MarkBlockInvalid(nodeToValidate, RuleError(err.Error()))
				return false, false, err
			}

			// If the error wasn't a RuleError, return without marking the
			// block as invalid, since this means the block may benefit from
			// being reprocessed in the future, which will happen if a reorg
			// puts this block on the main chain.
			return false, false, err
		}
		// If all of the above passed it means the block is valid. So set the
		// status flag on the block to indicate that and write the status to disk.
		nodeToValidate.Status |= StatusBlockValidated

		// Now that we have a valid block that we know is connecting to the tip,
		// update our data structures to actually make this connection. Do this
		// in a transaction so that it is atomic.
		if bc.postgres != nil {
			if err = bc.postgres.UpsertBlockAndTransactions(nodeToValidate, desoBlock); err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem upserting block and transactions")
			}

			// Write the modified utxo set to the view.
			// FIXME: This codepath breaks the balance computation in handleBlock for Rosetta
			// because it clears the UtxoView before balances can be snapshotted.
			if err := utxoView.FlushToDb(); err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem flushing view to db")
			}

			// Since we don't have utxo operations in postgres, always write UTXO operations for the block to badger
			err = bc.db.Update(func(txn *badger.Txn) error {
				if err = PutUtxoOperationsForBlockWithTxn(txn, blockHash, utxoOpsForBlock); err != nil {
					return errors.Wrapf(err, "ProcessBlock: Problem writing utxo operations to db on simple add to tip")
				}
				return nil
			})
		} else {
			err = bc.db.Update(func(txn *badger.Txn) error {
				// This will update the node's status.
				if err := PutHeightHashToNodeInfoWithTxn(txn, nodeToValidate, false /*bitcoinNodes*/); err != nil {
					return errors.Wrapf(
						err, "ProcessBlock: Problem calling PutHeightHashToNodeInfo after validation")
				}

				// Set the best node hash to this one. Note the header chain should already
				// be fully aware of this block so we shouldn't update it here.
				if err := PutBestHashWithTxn(txn, blockHash, ChainTypeDeSoBlock); err != nil {
					return err
				}

				// Write the modified utxo set to the view.
				if err := utxoView.FlushToDbWithTxn(txn); err != nil {
					return errors.Wrapf(err, "ProcessBlock: Problem writing utxo view to db on simple add to tip")
				}

				// Write the utxo operations for this block to the db so we can have the
				// ability to roll it back in the future.
				if err := PutUtxoOperationsForBlockWithTxn(txn, blockHash, utxoOpsForBlock); err != nil {
					return errors.Wrapf(err, "ProcessBlock: Problem writing utxo operations to db on simple add to tip")
				}

				return nil
			})
		}

		if err != nil {
			return false, false, errors.Wrapf(err, "ProcessBlock: Problem writing block info to db on simple add to tip")
		}

		// Now that we've set the best chain in the db, update our in-memory data
		// structure to reflect this. Do a quick check first to make sure it's consistent.
		lastIndex := len(bc.bestChain) - 1
		bestChainHash := bc.bestChain[lastIndex].Hash

		if *bestChainHash != *nodeToValidate.Header.PrevBlockHash {
			return false, false, fmt.Errorf("ProcessBlock: Last block in bestChain "+
				"data structure (%v) is not equal to parent hash of block being "+
				"added to tip (%v)", bestChainHash, nodeToValidate.Header.PrevBlockHash)
		}

		// If we're syncing there's no risk of concurrency issues. Otherwise, we
		// need to make a copy in order to be save.
		if bc.isSyncing() {
			bc.bestChain = append(bc.bestChain, nodeToValidate)
			bc.bestChainMap[*nodeToValidate.Hash] = nodeToValidate
		} else {
			newBestChain, newBestChainMap := bc.CopyBestChain()
			newBestChain = append(newBestChain, nodeToValidate)
			newBestChainMap[*nodeToValidate.Hash] = nodeToValidate
			bc.bestChain, bc.bestChainMap = newBestChain, newBestChainMap
		}

		// This node is on the main chain so set this variable.
		isMainChain = true

		// At this point we should have the following:
		// * The block has been written to disk.
		// * The block is in our in-memory node tree data structure.
		// * The node tree has been updated on disk.
		// * The block is on our in-memory main chain data structure.
		// * The on-disk data structure should be updated too:
		//   - The best hash should now be set to this block.
		//   - The <height -> hash> index representing the main chain should be updated
		//     to have this block.
		//   - The utxo db should be updated to reflect the effects of adding this block.
		//   - The utxo operations performed for this block should also be stored so we
		//     can roll the block back in the future if needed.

		// Notify any listeners.
		if bc.eventManager != nil {
			bc.eventManager.blockConnected(&BlockEvent{
				Block:    desoBlock,
				UtxoView: utxoView,
				UtxoOps:  utxoOpsForBlock,
			})
		}

	} else if nodeToValidate.CumWork.Cmp(currentTip.CumWork) <= 0 {
		// A block has less cumulative work than our tip. In this case, we just ignore
		// the block for now. It is stored in our <hash -> block_data> map on disk as well
		// as in our in-memory node tree data structure (which is also stored on disk).
		// Eventually, if enough work gets added to the block, then we'll
		// add it via a reorg.
	} else {
		// In this case the block is not attached to our tip and the cumulative work
		// of the block is greater than our tip. This means we have a fork that has
		// the potential to become our new main chain so we need to do a reorg to
		// process it. A reorg consists of the following:
		// 1) Find the common ancecstor of this block and the main chain.
		// 2) Roll back all of the main chain blocks back to this common ancestor.
		// 3) Verify and add the new blocks up to this one.
		//
		// Note that if verification fails while trying to add the new blocks then
		// we will not wind up accepting the changes. For this reason all of the
		// above steps are processed using an in-memory view before writing anything
		// to the database.

		// Find the common ancestor of this block and the main chain.
		commonAncestor, detachBlocks, attachBlocks := GetReorgBlocks(currentTip, nodeToValidate)
		// Log a warning if the reorg is going to be a big one.
		numBlocks := currentTip.Height - commonAncestor.Height
		if numBlocks > 10 {
			glog.Warningf("ProcessBlock: Proceeding with reorg of (%d) blocks from "+
				"block (%v) at height (%d) to block (%v) at height of (%d)",
				numBlocks, currentTip, currentTip.Height, nodeToValidate, nodeToValidate.Height)
		}

		// Create an empty view referencing the current tip.
		//
		// TODO: An optimization can be made here where we pre-load all the inputs this txn
		// requires into the view before-hand. This basically requires two passes over
		// the txns to account for txns that spend previous txns in the block, but it would
		// almost certainly be more efficient than doing a separate db call for each input
		// and output
		utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres)
		if err != nil {
			return false, false, errors.Wrapf(err, "processblock: Problem initializing UtxoView in reorg")
		}
		// Verify that the utxo view is pointing to the current tip.
		if *utxoView.TipHash != *currentTip.Hash {
			return false, false, fmt.Errorf("ProcessBlock: Tip hash for utxo view (%v) is "+
				"not the current tip hash (%v)", *utxoView.TipHash, *currentTip)
		}

		// Go through and detach all of the blocks down to the common ancestor. We
		// shouldn't encounter any errors but if we do, return without marking the
		// block as invalid.
		for _, nodeToDetach := range detachBlocks {
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			utxoOps, err := GetUtxoOperationsForBlock(bc.db, nodeToDetach.Hash)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem fetching "+
					"utxo operations during detachment of block (%v) "+
					"in reorg", nodeToDetach)
			}

			// Fetch the block itself since we need some info from it to roll
			// it back.
			blockToDetach, err := GetBlock(nodeToDetach.Hash, bc.db)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem fetching "+
					"block (%v) during detach in reorg", nodeToDetach)
			}

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(blockToDetach.Txns)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem computing "+
					"transaction hashes during detachment of block (%v)", nodeToDetach)
			}

			// Now roll the block back in the view.
			if err := utxoView.DisconnectBlock(blockToDetach, txHashes, utxoOps); err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem rolling back "+
					"block (%v) during detachment in reorg", nodeToDetach)
			}
			// Double-check that the view's hash is now at the block's parent.
			if *utxoView.TipHash != *blockToDetach.Header.PrevBlockHash {
				return false, false, fmt.Errorf("ProcessBlock: Block hash in utxo view (%v) "+
					"does not match parent block hash (%v) after executing "+
					"DisconnectBlock", utxoView.TipHash, blockToDetach.Header.PrevBlockHash)
			}
		}

		// If we made it here, we were able to successfully detach all of the blocks
		// such that the view is now at the common ancestor. Double-check that this is
		// the case.
		if *utxoView.TipHash != *commonAncestor.Hash {
			return false, false, fmt.Errorf("ProcessBlock: Block hash in utxo view (%v) "+
				"does not match common ancestor hash (%v) after executing "+
				"DisconnectBlock", utxoView.TipHash, commonAncestor.Hash)
		}

		// Now that the view has the common ancestor as the tip, we can try and attach
		// each new block to it to see if the reorg will work.
		//
		// Keep track of the utxo operations we get from attaching the blocks.
		utxoOpsForAttachBlocks := [][][]*UtxoOperation{}
		// Also keep track of any errors that we might have come across.
		ruleErrorsFound := []RuleError{}
		// The first element will be the node right after the common ancestor and
		// the last element will be the new node we need to attach.
		for _, attachNode := range attachBlocks {

			// Fetch the block itself since we need some info from it to try and
			// connect it.
			blockToAttach, err := GetBlock(attachNode.Hash, bc.db)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem fetching "+
					"block (%v) during attach in reorg", attachNode)
			}

			// If the parent node has been marked as invalid then mark this node as
			// invalid as well.
			if (attachNode.Parent.Status & StatusBlockValidateFailed) != 0 {
				bc.MarkBlockInvalid(attachNode, RuleErrorPreviousBlockInvalid)
				continue
			}

			// Compute the tx hashes for the block since we need them to perform
			// the connection.
			txHashes, err := ComputeTransactionHashes(blockToAttach.Txns)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem computing "+
					"transaction hashes during attachment of block (%v) in reorg", blockToAttach)
			}

			// Initialize the utxo operations slice.
			utxoOps, err := utxoView.ConnectBlock(
				blockToAttach, txHashes, verifySignatures, nil)
			if err != nil {
				if IsRuleError(err) {
					// If we have a RuleError, mark the block as invalid. But don't return
					// yet because we need to mark all of the child blocks as invalid as
					// well first.
					bc.MarkBlockInvalid(attachNode, RuleError(err.Error()))
					ruleErrorsFound = append(ruleErrorsFound, RuleError(err.Error()))
					continue
				} else {
					// If the error wasn't a RuleError, return without marking the
					// block as invalid, since this means the block may benefit from
					// being reprocessed in the future.
					return false, false, errors.Wrapf(err, "ProcessBlock: Problem trying to attach block (%v) in reorg", attachNode)
				}
			}

			// If we made it here then we were able to connect the block successfully.
			// So mark its status as valid and update the node index accordingly.
			attachNode.Status |= StatusBlockValidated
			if err := PutHeightHashToNodeInfo(attachNode, bc.db, false /*bitcoinNodes*/); err != nil {
				return false, false, errors.Wrapf(
					err, "ProcessBlock: Problem calling PutHeightHashToNodeInfo after validation in reorg")
			}

			// Add the utxo operations to our list.
			utxoOpsForAttachBlocks = append(utxoOpsForAttachBlocks, utxoOps)
		}

		// At this point, either we were able to attach all of the blocks OR the block
		// we are processing is invalid (possibly due to one of its parents to being
		// invalid). Regardless, because the attach worked if and only if the block we
		// are processing is valid, it is sufficient to use this block's validity to decide
		// if we want to perform this reorg.
		//
		// Recall that newNode is the node at the tip of the new chain we're trying to
		// reorg to which is also the last node in attachBlocks.
		newTipNode := attachBlocks[len(attachBlocks)-1]
		if (newTipNode.Status & StatusBlockValidateFailed) != 0 {
			// In the case where the new tip is invalid, we encountered an error while
			// processing. Return the first error we encountered. Note we should already
			// have marked all the blocks as invalid so no need to do it here.
			return false, false, ruleErrorsFound[0]
		}

		// If we made it this far, we know the reorg will succeed and the view contains
		// the state after applying the reorg. With this information, it is possible to
		// roll back the blocks and fast forward the db to the post-reorg state with a
		// single transaction.
		err = bc.db.Update(func(txn *badger.Txn) error {
			// Set the best node hash to the new tip.
			if err := PutBestHashWithTxn(txn, newTipNode.Hash, ChainTypeDeSoBlock); err != nil {
				return err
			}

			for _, detachNode := range detachBlocks {
				// Delete the utxo operations for the blocks we're detaching since we don't need
				// them anymore.
				if err := DeleteUtxoOperationsForBlockWithTxn(txn, detachNode.Hash); err != nil {
					return errors.Wrapf(err, "ProcessBlock: Problem deleting utxo operations for block")
				}

				// Note we could be even more aggressive here by deleting the nodes and
				// corresponding blocks from the db here (i.e. not storing any side chain
				// data on the db). But this seems like a minor optimization that comes at
				// the minor cost of side chains not being retained by the network as reliably.
			}

			for ii, attachNode := range attachBlocks {
				// Add the utxo operations for the blocks we're attaching so we can roll them back
				// in the future if necessary.
				if err := PutUtxoOperationsForBlockWithTxn(txn, attachNode.Hash, utxoOpsForAttachBlocks[ii]); err != nil {
					return errors.Wrapf(err, "ProcessBlock: Problem putting utxo operations for block")
				}
			}

			// Write the modified utxo set to the view.
			if err := utxoView.FlushToDbWithTxn(txn); err != nil {
				return errors.Wrapf(err, "ProcessBlock: Problem flushing to db")
			}

			return nil
		})
		if err != nil {
			return false, false, errors.Errorf("ProcessBlock: Problem updating: %v", err)
		}

		// Now the the db has been updated, update our in-memory best chain. Note that there
		// is no need to update the node index because it was updated as we went along.
		newBestChain, newBestChainMap := bc.CopyBestChain()
		newBestChain, newBestChainMap = updateBestChainInMemory(
			newBestChain, newBestChainMap, detachBlocks, attachBlocks)
		bc.bestChain, bc.bestChainMap = newBestChain, newBestChainMap

		// If we made it here then this block is on the main chain.
		isMainChain = true

		// Signal to the server about all the blocks that were disconnected and
		// connected as a result of this operation. Do this in a goroutine so that
		// if ProcessBlock is called by a consumer of incomingMessages we don't
		// have any risk of deadlocking.
		for _, nodeToDetach := range detachBlocks {
			// Fetch the block itself since we need some info from it to roll
			// it back.
			blockToDetach, err := GetBlock(nodeToDetach.Hash, bc.db)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem fetching "+
					"block (%v) during detach in server signal", nodeToDetach)
			}

			// If we have a Server object then call its function
			if bc.eventManager != nil {
				// FIXME: We need to add the UtxoOps here to handle reorgs properly in Rosetta
				// For now it's fine because reorgs are virtually impossible.
				bc.eventManager.blockDisconnected(&BlockEvent{Block: blockToDetach})
			}
		}
		for _, attachNode := range attachBlocks {

			// Fetch the block itself since we need some info from it to try and
			// connect it.
			blockToAttach, err := GetBlock(attachNode.Hash, bc.db)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem fetching "+
					"block (%v) during attach in server signal", attachNode)
			}
			// If we have a Server object then call its function
			if bc.eventManager != nil {
				// FIXME: We need to add the UtxoOps here to handle reorgs properly in Rosetta
				// For now it's fine because reorgs are virtually impossible.
				bc.eventManager.blockConnected(&BlockEvent{Block: blockToAttach})
			}
		}

		// If we have a Server object then call its function
		// TODO: Is this duplicated / necessary?
		if bc.eventManager != nil {
			// FIXME: We need to add the UtxoOps here to handle reorgs properly in Rosetta
			// For now it's fine because reorgs are virtually impossible.
			bc.eventManager.blockConnected(&BlockEvent{Block: desoBlock})
		}
	}

	// If we've made it this far, the block has been validated and we have either added
	// the block to the tip, done nothing with it (because its cumwork isn't high enough)
	// or added it via a reorg and the db and our in-memory data structures reflect this
	// change.
	//
	// Now that we've done all of the above, we need to signal to the server that we've
	// accepted the block

	// Signal the server that we've accepted this block in some way.
	if bc.eventManager != nil {
		bc.eventManager.blockAccepted(&BlockEvent{Block: desoBlock})
	}

	// At this point, the block we were processing originally should have been added
	// to our data structures and any unconnectedTxns that are no longer unconnectedTxns should have
	// also been processed.
	return isMainChain, false, nil
}

// ValidateTransaction creates a UtxoView and sees if the transaction can be connected
// to it. If a mempool is provided, this function tries to find dependencies of the
// passed-in transaction in the pool and connect them before trying to connect the
// passed-in transaction.
func (bc *Blockchain) ValidateTransaction(
	txnMsg *MsgDeSoTxn, blockHeight uint32, verifySignatures bool, mempool *DeSoMempool) error {

	// Create a new UtxoView. If we have access to a mempool object, use it to
	// get an augmented view that factors in pending transactions.
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres)
	if err != nil {
		return errors.Wrapf(err, "ValidateTransaction: Problem Problem creating new utxo view: ")
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUtxoViewForPublicKey(txnMsg.PublicKey, txnMsg)
		if err != nil {
			return errors.Wrapf(err, "ValidateTransaction: Problem getting augmented UtxoView from mempool: ")
		}
	}

	// Hash the transaction.
	txHash := txnMsg.Hash()
	txnBytes, err := txnMsg.ToBytes(false)
	if err != nil {
		return errors.Wrapf(err, "ValidateTransaction: Error serializing txn: %v", err)
	}
	txnSize := int64(len(txnBytes))
	// We don't care about the utxoOps or the fee it returns.
	_, _, _, _, err = utxoView._connectTransaction(
		txnMsg,
		txHash,
		txnSize,
		blockHeight,
		verifySignatures,
		false, /*ignoreUtxos*/
	)
	if err != nil {
		return errors.Wrapf(err, "ValidateTransaction: Problem validating transaction: ")
	}

	return nil
}

var (
	maxHash = BlockHash{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff}
	maxHashBigint = HashToBigint(&maxHash)
	bigOneInt     = big.NewInt(1)
)

// The number of hashing attempts in expectation it would take to produce the
// hash passed in. This is computed as:
//    E(min(X_i, ..., X_n)) where:
//    - n = (number of attempted hashes) and
//    - the X_i are all U(0, MAX_HASH)
// -> E(min(X_i, ..., X_n)) = MAX_HASH / (n + 1)
// -> E(n) ~= MAX_HASH / min_hash - 1
//    - where min_hash is the block hash
//
// We approximate this as MAX_HASH / (min_hash + 1), adding 1 to min_hash in
// order to mitigate the possibility of a divide-by-zero error.
//
// The value returned is the expected number of hashes performed to produce
// the input hash formatted as a big-endian big integer that uses the
// BlockHash type for convenience (though it is likely to be much lower
// in terms of magnitude than a typical BlockHash object).
func ExpectedWorkForBlockHash(hash *BlockHash) *BlockHash {
	hashBigint := HashToBigint(hash)
	ratioBigint := new(big.Int)
	ratioBigint.Div(maxHashBigint, hashBigint.Add(hashBigint, bigOneInt))
	return BigintToHash(ratioBigint)
}

func ComputeTransactionHashes(txns []*MsgDeSoTxn) ([]*BlockHash, error) {
	txHashes := make([]*BlockHash, len(txns))

	for ii, currentTxn := range txns {
		txHashes[ii] = currentTxn.Hash()
	}

	return txHashes, nil
}

func ComputeMerkleRoot(txns []*MsgDeSoTxn) (_merkle *BlockHash, _txHashes []*BlockHash, _err error) {
	if len(txns) == 0 {
		return nil, nil, fmt.Errorf("ComputeMerkleRoot: Block must contain at least one txn")
	}

	// Compute the hashes of all the transactions.
	hashes := [][]byte{}
	for _, txn := range txns {
		txHash := txn.Hash()
		hashes = append(hashes, txHash[:])
	}

	merkleTree := merkletree.NewTreeFromHashes(merkletree.Sha256DoubleHash, hashes)

	rootHash := &BlockHash{}
	copy(rootHash[:], merkleTree.Root.GetHash()[:])

	txHashes := []*BlockHash{}
	for _, leafNode := range merkleTree.Rows[0] {
		currentHash := &BlockHash{}
		copy(currentHash[:], leafNode.GetHash())
		txHashes = append(txHashes, currentHash)
	}

	return rootHash, txHashes, nil
}

func (bc *Blockchain) GetSpendableUtxosForPublicKey(spendPublicKeyBytes []byte, mempool *DeSoMempool, referenceUtxoView *UtxoView) ([]*UtxoEntry, error) {
	// If we have access to a mempool, use it to account for utxos we might not
	// get otherwise.
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres)
	if err != nil {
		return nil, errors.Wrapf(err, "Blockchain.GetSpendableUtxosForPublicKey: Problem initializing UtxoView: ")
	}
	// Use the reference UtxoView if provided. Otherwise try to get one from the mempool.
	// This improves efficiency when we have a UtxoView already handy.
	if referenceUtxoView != nil {
		utxoView = referenceUtxoView
	} else {
		if mempool != nil {
			utxoView, err = mempool.GetAugmentedUtxoViewForPublicKey(spendPublicKeyBytes, nil)
			if err != nil {
				return nil, errors.Wrapf(err, "Blockchain.GetSpendableUtxosForPublicKey: Problem getting augmented UtxoView from mempool: ")
			}
		}
	}

	// Get unspent utxos from the view.
	utxoEntriesFound, err := utxoView.GetUnspentUtxoEntrysForPublicKey(spendPublicKeyBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "Blockchain.GetSpendableUtxosForPublicKey: Problem getting spendable utxos from UtxoView: ")
	}

	// Sort the UTXOs putting the smallest amounts first.
	//
	// TODO: There has generally been a lot of discussion and thought about
	// what the optimal coin selection algorithm should be over the years.
	// Here, we choose to keep things simple and just use the smallest UTXOs
	// first. It has its drawbacks and we should revisit it at some point,
	// but for now it seems like it should be fine, and the reduction of the
	// size of the UTXO set seems like a reasonable benefit of using it. See below
	// for more discussion:
	// https://bitcoin.stackexchange.com/questions/32145/what-are-the-trade-offs-between-the-different-algorithms-for-deciding-which-utxo
	sort.Slice(utxoEntriesFound, func(ii, jj int) bool {
		return utxoEntriesFound[ii].AmountNanos < utxoEntriesFound[jj].AmountNanos
	})

	// Add UtxoEntrys to our list filtering out ones that aren't valid for various
	// reasons.
	spendableUtxoEntries := []*UtxoEntry{}
	for _, utxoEntry := range utxoEntriesFound {
		// If the utxo is an immature block reward, skip it. Use the block chain height
		// not the header chain height since the transaction will need to be validated
		// against existing transactions which are present only if we have blocks.
		//
		// Note we add one to the current block height since it is presumed this
		// transaction will at best be mined into the next block.
		blockHeight := bc.blockTip().Height + 1
		if _isEntryImmatureBlockReward(utxoEntry, blockHeight, bc.params) {
			continue
		}

		// Don't consider utxos that are already consumed by the mempool.
		if mempool != nil && mempool.CheckSpend(*utxoEntry.UtxoKey) != nil {
			continue
		}

		// If we get here we know the utxo is spendable so add it to our list.
		spendableUtxoEntries = append(spendableUtxoEntries, utxoEntry)
	}

	return spendableUtxoEntries, nil
}

func amountEqualsAdditionalOutputs(spendAmount uint64, additionalOutputs []*DeSoOutput) error {
	expectedAdditionalOutputSum := uint64(0)
	for _, output := range additionalOutputs {
		expectedAdditionalOutputSum += output.AmountNanos
	}
	if spendAmount != expectedAdditionalOutputSum {
		return fmt.Errorf("expected spendAmount to be %d, instead got %d", expectedAdditionalOutputSum, spendAmount)
	}
	return nil
}

// Define a helper function for computing the upper bound of the size
// of a transaction and associated fees. This basically serializes the
// transaction without the signature and then accounts for the maximum possible
// size the signature could be.
func _computeMaxTxSize(_tx *MsgDeSoTxn) uint64 {
	// Compute the size of the transaction without the signature.
	txBytesNoSignature, _ := _tx.ToBytes(true /*preSignature*/)
	// Return the size the transaction would be if the signature had its
	// absolute maximum length.

	// MaxDERSigLen is the maximum size that a DER signature can be.
	//
	// Note: I am pretty sure the true maximum is 71. But since this value is
	// dependent on the size of R and S, and since it's generally used for
	// safety purposes (e.g. ensuring that enough space has been allocated),
	// it seems better to pad it a bit and stay on the safe side. You can see
	// some discussion on getting to this number here:
	// https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature
	const MaxDERSigLen = 74

	return uint64(len(txBytesNoSignature)) + MaxDERSigLen
}

// A helper for computing the max fee given a txn. Assumes the longest signature
// length.
func _computeMaxTxFee(_tx *MsgDeSoTxn, minFeeRateNanosPerKB uint64) uint64 {
	maxSizeBytes := _computeMaxTxSize(_tx)
	return maxSizeBytes * minFeeRateNanosPerKB / 1000
}

// Computing maximum fee for tx that doesn't include change output yet.
func _computeMaxTxFeeWithMaxChange(_tx *MsgDeSoTxn, minFeeRateNanosPerKB uint64) uint64 {
	// TODO: This is a hack that we implement in order to remain backward-compatible with
	// hundreds of tests that rely on the change being ommitted from the max fee
	// computation. It shouldn't impact anything in PROD because the min fee rate is
	// significantly higher. Nevertheless, we should fix all the tests at some point
	// and then remove this quick-fix.
	if minFeeRateNanosPerKB <= 100 {
		return _computeMaxTxFee(_tx, minFeeRateNanosPerKB)
	}

	maxSizeBytes := _computeMaxTxSize(_tx)
	res := (maxSizeBytes + MaxDeSoOutputSizeBytes) * minFeeRateNanosPerKB / 1000
	// In the event that there is a remainder, we need to round up to
	// ensure that the fee EXCEEDS the min fee rate.
	// We skip this check if the networkMinFeeRate is zero to keep existing tests working.
	if (maxSizeBytes+MaxDeSoOutputSizeBytes)*minFeeRateNanosPerKB%1000 > 0 {
		res++
	}
	return res
}

func (bc *Blockchain) CreatePrivateMessageTxn(
	senderPublicKey []byte, recipientPublicKey []byte,
	unencryptedMessageText string, encryptedMessageText string,
	senderMessagingPublicKey []byte, senderMessagingKeyName []byte,
	recipientMessagingPublicKey []byte, recipientMessagingKeyName []byte,
	tstampNanos uint64, extraData map[string][]byte,
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	var encryptedMessageBytes []byte
	messageExtraData := make(map[string][]byte)

	if encryptedMessageText == "" {
		// Encrypt the passed-in message text with the recipient's public key.
		//
		// Parse the recipient public key.
		recipientPk, err := btcec.ParsePubKey(recipientPublicKey, btcec.S256())
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err, "CreatePrivateMessageTxn: Problem parsing "+
				"recipient public key: ")
		}
		encryptedMessageBytes, err = EncryptBytesWithPublicKey(
			[]byte(unencryptedMessageText), recipientPk.ToECDSA())
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err, "CreatePrivateMessageTxn: Problem "+
				"encrypting message text to hex: ")
		}

		// Add {V : 1} version field to ExtraData to indicate we are
		// encrypting using legacy public key method.
		messageExtraData[MessagesVersionString] = UintToBuf(MessagesVersion1)
	} else {
		var err error
		// Message is already encrypted, so just decode it to hex format
		encryptedMessageBytes, err = hex.DecodeString(encryptedMessageText)
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err, "CreatePrivateMessageTxn: Problem "+
				"decoding message text to hex: ")
		}

		// Add {V : 2} version field to ExtraData to indicate we are
		// encrypting using shared secret.
		messageExtraData[MessagesVersionString] = UintToBuf(MessagesVersion2)

		// Check for DeSo V3 Messages fields. Specifically, this request could be made with either sender
		// or recipient public keys and key names. Having one key present is sufficient to set V3.
		if len(senderMessagingPublicKey) > 0 || len(recipientMessagingPublicKey) > 0 {

			// If we're using rotating messaging keys, then we're on {V : 3} messages.
			if err = ValidateGroupPublicKeyAndName(senderMessagingPublicKey, senderMessagingKeyName); err == nil {
				messageExtraData[MessagesVersionString] = UintToBuf(MessagesVersion3)
				messageExtraData[SenderMessagingPublicKey] = senderMessagingPublicKey
				messageExtraData[SenderMessagingGroupKeyName] = senderMessagingKeyName
			}

			if err = ValidateGroupPublicKeyAndName(recipientMessagingPublicKey, recipientMessagingKeyName); err != nil {
				// If we didn't pass validation of either sender or recipient, then we return an error.
				if !reflect.DeepEqual(messageExtraData[MessagesVersionString], UintToBuf(MessagesVersion3)) {
					return nil, 0, 0, 0, err
				}
			} else {
				messageExtraData[MessagesVersionString] = UintToBuf(MessagesVersion3)
				messageExtraData[RecipientMessagingPublicKey] = recipientMessagingPublicKey
				messageExtraData[RecipientMessagingGroupKeyName] = recipientMessagingKeyName
			}
		}
	}

	// Delete protected keys
	if extraData != nil {
		delete(extraData, MessagesVersionString)
		delete(extraData, SenderMessagingPublicKey)
		delete(extraData, SenderMessagingGroupKeyName)
		delete(extraData, RecipientMessagingPublicKey)
		delete(extraData, RecipientMessagingGroupKeyName)
	}

	// Going to allow this to merge without a block height check because
	// it seems safe, and threading the block height check into here is pretty annoying.
	finalExtraData := mergeExtraData(extraData, messageExtraData)

	// Don't allow encryptedMessageBytes to be nil.
	if len(encryptedMessageBytes) == 0 {
		encryptedMessageBytes = []byte{}
	}

	// Create a transaction containing the encrypted message text.
	// A PrivateMessage transaction doesn't need any inputs or outputs (except additionalOutputs provided).
	txn := &MsgDeSoTxn{
		PublicKey: senderPublicKey,
		TxnMeta: &PrivateMessageMetadata{
			RecipientPublicKey: recipientPublicKey,
			EncryptedText:      encryptedMessageBytes,
			TimestampNanos:     tstampNanos,
		},
		ExtraData: finalExtraData,
		TxOutputs: additionalOutputs,

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreatePrivateMessageTxn: Problem adding inputs: ")
	}

	// Sanity-check that the spendAmount is zero.
	if err = amountEqualsAdditionalOutputs(spendAmount, additionalOutputs); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("CreatePrivateMessageTxn: %v", err)
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateLikeTxn(
	userPublicKey []byte, likedPostHash BlockHash, isUnlike bool,
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64,
	_err error) {

	// A Like transaction doesn't need any inputs or outputs (except additionalOutputs provided).
	txn := &MsgDeSoTxn{
		PublicKey: userPublicKey,
		TxnMeta: &LikeMetadata{
			LikedPostHash: &likedPostHash,
			IsUnlike:      isUnlike,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "CreateLikeTxn: Problem adding inputs: ")
	}

	// Sanity-check that the spendAmount is zero.
	if err = amountEqualsAdditionalOutputs(spendAmount, additionalOutputs); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("CreateLikeTxn: %v", err)
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateFollowTxn(
	senderPublicKey []byte, followedPublicKey []byte, isUnfollow bool,
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64,
	_err error) {

	// A Follow transaction doesn't need any inputs or outputs (except additionalOutputs provided).
	txn := &MsgDeSoTxn{
		PublicKey: senderPublicKey,
		TxnMeta: &FollowMetadata{
			FollowedPublicKey: followedPublicKey,
			IsUnfollow:        isUnfollow,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "CreateFollowTxn: Problem adding inputs: ")
	}

	// Sanity-check that the spendAmount is zero.
	if err = amountEqualsAdditionalOutputs(spendAmount, additionalOutputs); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("CreateFollowTxn: %v", err)
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateUpdateGlobalParamsTxn(updaterPublicKey []byte,
	usdCentsPerBitcoin int64,
	createProfileFeesNanos int64,
	createNFTFeesNanos int64,
	maxCopiesPerNFT int64,
	minimumNetworkFeeNanosPerKb int64,
	forbiddenPubKey []byte,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Set RepostedPostHash and IsQuotedRepost on the extra data map as necessary to track reposting.
	extraData := make(map[string][]byte)
	if usdCentsPerBitcoin >= 0 {
		extraData[USDCentsPerBitcoinKey] = UintToBuf(uint64(usdCentsPerBitcoin))
	}
	if createProfileFeesNanos >= 0 {
		extraData[CreateProfileFeeNanosKey] = UintToBuf(uint64(createProfileFeesNanos))
	}
	if createNFTFeesNanos >= 0 {
		extraData[CreateNFTFeeNanosKey] = UintToBuf(uint64(createNFTFeesNanos))
	}
	if maxCopiesPerNFT >= 0 {
		extraData[MaxCopiesPerNFTKey] = UintToBuf(uint64(maxCopiesPerNFT))
	}
	if minimumNetworkFeeNanosPerKb >= 0 {
		extraData[MinNetworkFeeNanosPerKBKey] = UintToBuf(uint64(minimumNetworkFeeNanosPerKb))
	}
	if len(forbiddenPubKey) > 0 {
		extraData[ForbiddenBlockSignaturePubKeyKey] = forbiddenPubKey
	}

	txn := &MsgDeSoTxn{
		PublicKey: updaterPublicKey,
		TxnMeta:   &UpdateGlobalParamsMetadata{},
		ExtraData: extraData,
		TxOutputs: additionalOutputs,
	}

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateUpdateGlobalParamsTxn: Problem adding inputs: ")
	}

	// The spend amount should be zero for these txns.
	if err = amountEqualsAdditionalOutputs(spendAmount, additionalOutputs); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("CreateUpdateGlobalParamsTxn %v", err)
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateUpdateBitcoinUSDExchangeRateTxn(
	// Exchange rate update fields
	updaterPublicKey []byte,
	usdCentsPerbitcoin uint64,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the UpdateBitcoinUSDExchangeRate fields.
	txn := &MsgDeSoTxn{
		PublicKey: updaterPublicKey,
		TxnMeta: &UpdateBitcoinUSDExchangeRateMetadataa{
			USDCentsPerBitcoin: usdCentsPerbitcoin,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateUpdateBitcoinUSDExchangeRateTxn: Problem adding inputs: ")
	}

	// The spend amount should be zero for these txns.
	if err = amountEqualsAdditionalOutputs(spendAmount, additionalOutputs); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("CreateUpdateBitcoinUSDExchangeRateTxn: %v", err)
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateSubmitPostTxn(
	// Post fields
	updaterPublicKey []byte,
	postHashToModify []byte,
	parentStakeID []byte,
	body []byte,
	repostPostHashBytes []byte,
	isQuotedRepost bool,
	tstampNanos uint64,
	postExtraData map[string][]byte,
	isHidden bool,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Initialize txnExtraData to postExtraData.
	txnExtraData := postExtraData
	// Remove consensus level attributes from TxnExtraData if they exist.  The consensus logic will set them correctly.
	for _, key := range PostExtraDataConsensusKeys {
		delete(txnExtraData, key)
	}

	// Set RepostedPostHash and IsQuotedRepost on the extra data map as necessary to track reposting.
	if len(repostPostHashBytes) > 0 {
		txnExtraData[RepostedPostHash] = repostPostHashBytes
		if isQuotedRepost {
			txnExtraData[IsQuotedRepostKey] = QuotedRepostVal
		} else {
			txnExtraData[IsQuotedRepostKey] = NotQuotedRepostVal
		}
	}

	// Create a transaction containing the post fields.
	txn := &MsgDeSoTxn{
		PublicKey: updaterPublicKey,
		TxnMeta: &SubmitPostMetadata{
			PostHashToModify:         postHashToModify,
			ParentStakeID:            parentStakeID,
			Body:                     body,
			CreatorBasisPoints:       10 * 100,
			StakeMultipleBasisPoints: 1.25 * 100 * 100,
			TimestampNanos:           tstampNanos,
			IsHidden:                 isHidden,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}
	// Only set transaction's ExtraData if there is at least one key in the extra data map.
	if len(txnExtraData) > 0 {
		txn.ExtraData = txnExtraData
	}

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateSubmitPostTxn: Problem adding inputs: ")
	}

	// The spend amount should be zero for post submissions.
	if err = amountEqualsAdditionalOutputs(spendAmount, additionalOutputs); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("CreateSubmitPostTxn: %v", err)
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateUpdateProfileTxn(
	UpdaterPublicKeyBytes []byte,
	// Optional. Only set when the owner of the profile is != to the updater.
	OptionalProfilePublicKeyBytes []byte,
	NewUsername string,
	NewDescription string,
	NewProfilePic string,
	NewCreatorBasisPoints uint64,
	NewStakeMultipleBasisPoints uint64,
	IsHidden bool,
	AdditionalFees uint64,
	ExtraData map[string][]byte,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the profile fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKeyBytes,
		TxnMeta: &UpdateProfileMetadata{
			ProfilePublicKey:            OptionalProfilePublicKeyBytes,
			NewUsername:                 []byte(NewUsername),
			NewDescription:              []byte(NewDescription),
			NewProfilePic:               []byte(NewProfilePic),
			NewCreatorBasisPoints:       NewCreatorBasisPoints,
			NewStakeMultipleBasisPoints: NewStakeMultipleBasisPoints,
			IsHidden:                    IsHidden,
		},
		TxOutputs: additionalOutputs,
		ExtraData: ExtraData,
		// We wait to compute the signature until we've added all the
		// inputs and change.

	}

	// We directly call AddInputsAndChangeToTransactionWithSubsidy so we can pass through the create profile fee.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransactionWithSubsidy(txn, minFeeRateNanosPerKB, 0, mempool, AdditionalFees)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateUpdateProfileTxn: Problem adding inputs: ")
	}

	// The spend amount should equal to the additional fees for profile submissions.
	if err = amountEqualsAdditionalOutputs(spendAmount-AdditionalFees, additionalOutputs); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("CreateUpdateProfileTxn: %v", err)
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateSwapIdentityTxn(
	UpdaterPublicKeyBytes []byte,
	FromPublicKeyBytes []byte,
	ToPublicKeyBytes []byte,

	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the profile fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKeyBytes,
		TxnMeta: &SwapIdentityMetadataa{
			FromPublicKey: FromPublicKeyBytes,
			ToPublicKey:   ToPublicKeyBytes,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateUpdateProfileTxn: Problem adding inputs: ")
	}

	// The spend amount should be zero for SwapIdentity txns.
	if err = amountEqualsAdditionalOutputs(spendAmount, additionalOutputs); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("CreateUpdateProfileTxn: %v", err)
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateCreatorCoinTxn(
	UpdaterPublicKey []byte,
	// See CreatorCoinMetadataa for an explanation of these fields.
	ProfilePublicKey []byte,
	OperationType CreatorCoinOperationType,
	DeSoToSellNanos uint64,
	CreatorCoinToSellNanos uint64,
	DeSoToAddNanos uint64,
	MinDeSoExpectedNanos uint64,
	MinCreatorCoinExpectedNanos uint64,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the creator coin fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKey,
		TxnMeta: &CreatorCoinMetadataa{
			ProfilePublicKey,
			OperationType,
			DeSoToSellNanos,
			CreatorCoinToSellNanos,
			DeSoToAddNanos,
			MinDeSoExpectedNanos,
			MinCreatorCoinExpectedNanos,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(
			txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateCreatorCoinTxn: Problem adding inputs: ")
	}
	_ = spendAmount

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateCreatorCoinTxn: CreatorCoin txn " +
			"must have at least one input but had zero inputs " +
			"instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateCreatorCoinTransferTxn(
	UpdaterPublicKey []byte,
	ProfilePublicKey []byte,
	CreatorCoinToTransferNanos uint64,
	RecipientPublicKey []byte,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the creator coin fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKey,
		TxnMeta: &CreatorCoinTransferMetadataa{
			ProfilePublicKey,
			CreatorCoinToTransferNanos,
			RecipientPublicKey,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateCreatorCoinTransferTxn: Problem adding inputs: ")
	}
	_ = spendAmount

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateCreatorCoinTransferTxn: CreatorCoinTransfer txn " +
			"must have at least one input but had zero inputs " +
			"instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateDAOCoinTxn(
	UpdaterPublicKey []byte,
	// See CreatorCoinMetadataa for an explanation of these fields.
	metadata *DAOCoinMetadata,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the creator coin fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKey,
		TxnMeta:   metadata,
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(
			txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateDAOCoinTxn: Problem adding inputs: ")
	}
	_ = spendAmount

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateDAOCoinTxn: DAOCoin txn " +
			"must have at least one input but had zero inputs " +
			"instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateDAOCoinTransferTxn(
	UpdaterPublicKey []byte,
	metadata *DAOCoinTransferMetadata,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the creator coin fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKey,
		TxnMeta:   metadata,
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateDAOCoinTransferTxn: Problem adding inputs: ")
	}
	_ = spendAmount

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateDAOCoinTransferTxn: DAOCoinTransfer txn " +
			"must have at least one input but had zero inputs " +
			"instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateDAOCoinLimitOrderTxn(
	UpdaterPublicKey []byte,
	// See DAOCoinLimitOrderMetadata for an explanation of these fields.
	metadata *DAOCoinLimitOrderMetadata,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Initialize FeeNanos to the maximum uint64 to provide an upper bound on the size of the transaction.
	// We will set FeeNanos to it's true value after we add inputs and outputs.
	metadata.FeeNanos = math.MaxUint64

	// Create a transaction containing the create DAO coin limit order fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKey,
		TxnMeta:   metadata,
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Create a new UtxoView. If we have access to a mempool object, use it to
	// get an augmented view that factors in pending transactions.
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err,
			"Blockchain.CreateDAOCoinLimitOrderTxn: Problem creating new utxo view: ")
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err,
				"Blockchain.CreateDAOCoinLimitOrderTxn: Problem getting augmented UtxoView from mempool: ")

		}
	}

	// Validate txn metadata.
	err = utxoView.IsValidDAOCoinLimitOrderMetadata(txn.PublicKey, metadata)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateDAOCoinLimitOrderTxn: ")
	}

	// Construct transactor order if submitting a new order so
	// we can calculate BidderInputs and additional $DESO fees.
	// This is not necessary if cancelling an existing order.
	var transactorOrder *DAOCoinLimitOrderEntry

	if metadata.CancelOrderID == nil {
		// CancelOrderID is nil, so we know we're submitting a new order.
		transactorOrder = &DAOCoinLimitOrderEntry{
			OrderID:                   txn.Hash(),
			TransactorPKID:            utxoView.GetPKIDForPublicKey(UpdaterPublicKey).PKID,
			BuyingDAOCoinCreatorPKID:  utxoView.GetPKIDForPublicKey(metadata.BuyingDAOCoinCreatorPublicKey.ToBytes()).PKID,
			SellingDAOCoinCreatorPKID: utxoView.GetPKIDForPublicKey(metadata.SellingDAOCoinCreatorPublicKey.ToBytes()).PKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: metadata.ScaledExchangeRateCoinsToSellPerCoinToBuy.Clone(),
			QuantityToFillInBaseUnits:                 metadata.QuantityToFillInBaseUnits.Clone(),
			OperationType:                             metadata.OperationType,
			FillType:                                  metadata.FillType,
			BlockHeight:                               bc.blockTip().Height + 1,
		}
	}

	// We use "additionalFees" to track how much we need to spend to cover the transactor's bid in DESO.
	var additionalFees uint64
	if metadata.CancelOrderID == nil &&
		metadata.BuyingDAOCoinCreatorPublicKey.IsZeroPublicKey() {
		// If buying $DESO, we need to find inputs from all the orders that match.
		// This will move to txn construction as this will be put in the metadata.
		var lastSeenOrder *DAOCoinLimitOrderEntry
		desoNanosToConsumeMap := make(map[PKID]uint64)
		transactorQuantityToFill := transactorOrder.QuantityToFillInBaseUnits.Clone()

		for transactorQuantityToFill.GtUint64(0) {
			var matchingOrderEntries []*DAOCoinLimitOrderEntry
			matchingOrderEntries, err = utxoView._getNextLimitOrdersToFill(transactorOrder, lastSeenOrder)
			if err != nil {
				return nil, 0, 0, 0, errors.Wrapf(
					err, "Blockchain.CreateDAOCoinLimitOrderTxn: Error getting Bid orders to match: ")
			}
			if len(matchingOrderEntries) == 0 {
				break
			}
			for _, matchingOrder := range matchingOrderEntries {
				lastSeenOrder = matchingOrder

				var matchingOrderDESOBalanceNanos uint64
				matchingOrderDESOBalanceNanos, err = utxoView.GetDeSoBalanceNanosForPublicKey(
					utxoView.GetPublicKeyForPKID(matchingOrder.TransactorPKID))
				if err != nil {
					return nil, 0, 0, 0, errors.Wrapf(
						err, "Blockchain.CreateDAOCoinLimitOrderTxn: error getting DeSo balance for matching bid order: ")
				}

				// Transactor is buying $DESO so matching order is selling $DESO.
				// Calculate updated order quantities and coins exchanged.
				var desoNanosExchanged *uint256.Int

				transactorQuantityToFill,
					_, // matching order updated quantity, not used here
					desoNanosExchanged,
					_, // dao coin nanos exchanged, not used here
					err = _calculateDAOCoinsTransferredInLimitOrderMatch(
					matchingOrder, transactorOrder.OperationType, transactorQuantityToFill)
				if err != nil {
					return nil, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateDAOCoinLimitOrderTxn: ")
				}

				// Check for overflow in $DESO exchanged.
				if !desoNanosExchanged.IsUint64() {
					return nil, 0, 0, 0, fmt.Errorf("Blockchain.CreateDAOCoinLimitOrderTxn: order cost overflows $DESO")
				}

				// Check if matching order has enough $DESO to
				// fulfill their order. Skip if not.
				if desoNanosExchanged.GtUint64(matchingOrderDESOBalanceNanos) {
					continue
				}

				// Initialize map tracking total $DESO consumed if the matching
				// order transactor PKID hasn't been seen before.
				if _, exists := desoNanosToConsumeMap[*matchingOrder.TransactorPKID]; !exists {
					desoNanosToConsumeMap[*matchingOrder.TransactorPKID] = 0
				}

				// Update matching order's total $DESO consumed.
				desoNanosToConsumeMap[*matchingOrder.TransactorPKID], err = SafeUint64().Add(
					desoNanosToConsumeMap[*matchingOrder.TransactorPKID],
					desoNanosExchanged.Uint64())
				if err != nil {
					return nil, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateDAOCoinLimitOrderTxn: ")
				}
			}
		}

		for pkid, desoNanosToConsume := range desoNanosToConsumeMap {
			var inputs []*DeSoInput
			publicKey := NewPublicKey(utxoView.GetPublicKeyForPKID(&pkid))

			inputs, err = bc.GetInputsToCoverAmount(publicKey.ToBytes(), utxoView, desoNanosToConsume)
			if err != nil {
				return nil, 0, 0, 0, errors.Wrapf(err,
					"Blockchain.CreateDAOCoinLimitOrderTxn: Error getting inputs to cover amount: ")
			}

			inputsByTransactor := DeSoInputsByTransactor{
				TransactorPublicKey: &(*publicKey), // create a pointer to a copy of the public key
				Inputs:              inputs,
			}

			metadata.BidderInputs = append(metadata.BidderInputs, &inputsByTransactor)
		}
	} else if metadata.CancelOrderID == nil &&
		metadata.SellingDAOCoinCreatorPublicKey.IsZeroPublicKey() {
		// If selling $DESO for DAO coins, we need to find the matching orders
		// and add that as an additional fee when adding inputs and outputs.
		var lastSeenOrder *DAOCoinLimitOrderEntry

		desoNanosToFulfillOrders := uint256.NewInt()
		transactorQuantityToFill := transactorOrder.QuantityToFillInBaseUnits.Clone()

		for transactorQuantityToFill.GtUint64(0) {
			var matchingOrderEntries []*DAOCoinLimitOrderEntry
			matchingOrderEntries, err = utxoView._getNextLimitOrdersToFill(transactorOrder, lastSeenOrder)
			if err != nil {
				return nil, 0, 0, 0, errors.Wrapf(
					err, "Blockchain.CreateDAOCoinLimitOrderTxn: Error getting orders to match: ")
			}
			if len(matchingOrderEntries) == 0 {
				break
			}
			for _, matchingOrder := range matchingOrderEntries {
				lastSeenOrder = matchingOrder

				matchingOrderBalanceEntry := utxoView._getBalanceEntryForHODLerPKIDAndCreatorPKID(
					matchingOrder.TransactorPKID, matchingOrder.SellingDAOCoinCreatorPKID, true)

				// Skip if matching order doesn't own any of the DAO coins they're selling.
				if matchingOrderBalanceEntry == nil || matchingOrderBalanceEntry.isDeleted {
					continue
				}

				// Calculate updated order quantities and coins exchanged.
				var updatedTransactorQuantityToFill *uint256.Int
				var daoCoinNanosExchanged *uint256.Int
				var desoNanosExchanged *uint256.Int

				updatedTransactorQuantityToFill,
					_, // matching order updated quantity, not used here
					daoCoinNanosExchanged,
					desoNanosExchanged,
					err = _calculateDAOCoinsTransferredInLimitOrderMatch(
					matchingOrder, transactorOrder.OperationType, transactorQuantityToFill)
				if err != nil {
					return nil, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateDAOCoinLimitOrderTxn: ")
				}

				// Skip if matching order doesn't own enough of the DAO coins they're selling.
				if matchingOrderBalanceEntry.BalanceNanos.Lt(daoCoinNanosExchanged) {
					continue
				}

				// Now that we know this is a legitimate matching order
				// we can update the transactor quantity to fill.
				transactorQuantityToFill = updatedTransactorQuantityToFill

				// Track total $DESO exchanged across all matching orders.
				desoNanosToFulfillOrders, err = SafeUint256().Add(
					desoNanosToFulfillOrders, desoNanosExchanged)
				if err != nil {
					return nil, 0, 0, 0, errors.Wrapf(err,
						"Blockchain.CreateDAOCoinLimitOrderTxn: overflow when adding up $DESO to fill orders")
				}
			}
		}

		// Validate $DESO doesn't overflow uint64.
		if !desoNanosToFulfillOrders.IsUint64() {
			return nil, 0, 0, 0, fmt.Errorf(
				"Blockchain.CreateDAOCoinLimitOrderTxn: fulfilling order $DESO overflows uint64")
		}

		additionalFees = desoNanosToFulfillOrders.Uint64()
	}

	// Add inputs and change for a standard pay per KB transaction.
	totalInput, _, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransactionWithSubsidy(txn, minFeeRateNanosPerKB, 0, mempool, additionalFees)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err,
			"CreateDAOCoinLimitOrderTxn: Problem adding inputs: ")
	}
	// Set fee to its actual value now that we've added inputs and outputs.
	txn.TxnMeta.(*DAOCoinLimitOrderMetadata).FeeNanos = fees

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf(
			"CreateDAOCoinLimitOrderTxn: DAOCoinLimitOrder txn must have at least one input" +
				" but had zero inputs instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateCreateNFTTxn(
	UpdaterPublicKey []byte,
	NFTPostHash *BlockHash,
	NumCopies uint64,
	HasUnlockable bool,
	IsForSale bool,
	MinBidAmountNanos uint64,
	NFTFee uint64,
	NFTRoyaltyToCreatorBasisPoints uint64,
	NFTRoyaltyToCoinBasisPoints uint64,
	IsBuyNow bool,
	BuyNowPriceNanos uint64,
	AdditionalDESORoyalties map[PublicKey]uint64,
	AdditionalCoinRoyalties map[PublicKey]uint64,
	ExtraData map[string][]byte,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the create NFT fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKey,
		TxnMeta: &CreateNFTMetadata{
			NFTPostHash,
			NumCopies,
			HasUnlockable,
			IsForSale,
			MinBidAmountNanos,
			NFTRoyaltyToCreatorBasisPoints,
			NFTRoyaltyToCoinBasisPoints,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	nftExtraData := make(map[string][]byte)
	// If this transactions creates a Buy Now NFT, set the extra data appropriately.
	if IsBuyNow {
		nftExtraData[BuyNowPriceKey] = UintToBuf(BuyNowPriceNanos)
	}

	// If this NFT has royalties that go to other users coins, set the extra data appropriately
	if len(AdditionalDESORoyalties) > 0 {
		additionalDESORoyaltiesBuf, err := SerializePubKeyToUint64Map(AdditionalDESORoyalties)
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err,
				"CreateCreateNFTTxn: Problem encoding additional DESO Royalties map: ")
		}
		nftExtraData[DESORoyaltiesMapKey] = additionalDESORoyaltiesBuf
	}

	// If this NFT has royalties that go to other users coins, set the extra data appropriately
	if len(AdditionalCoinRoyalties) > 0 {
		additionalCoinRoyaltiesBuf, err := SerializePubKeyToUint64Map(AdditionalCoinRoyalties)
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err,
				"CreateCreateNFTTxn: Problem encoding additional Coin Royalties map: ")
		}
		nftExtraData[CoinRoyaltiesMapKey] = additionalCoinRoyaltiesBuf
	}

	// Delete the protected keys from the ExtraData map
	if ExtraData != nil {
		delete(ExtraData, BuyNowPriceKey)
		delete(ExtraData, DESORoyaltiesMapKey)
		delete(ExtraData, CoinRoyaltiesMapKey)
	}

	finalExtraData := mergeExtraData(ExtraData, nftExtraData)

	if len(finalExtraData) > 0 {
		txn.ExtraData = finalExtraData
	}

	// We directly call AddInputsAndChangeToTransactionWithSubsidy so we can pass through the NFT fee.
	totalInput, _, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransactionWithSubsidy(txn, minFeeRateNanosPerKB, 0, mempool, NFTFee)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateCreateNFTTxn: Problem adding inputs: ")
	}

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateCreateNFTTxn: CreateNFT txn " +
			"must have at least one input but had zero inputs " +
			"instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) GetInputsToCoverAmount(spenderPublicKey []byte, utxoView *UtxoView, amountToCover uint64) (
	_inputs []*DeSoInput, _err error) {
	// Get the spendable UtxoEntrys.
	spenderSpendableUtxos, err := bc.GetSpendableUtxosForPublicKey(spenderPublicKey, nil, utxoView)
	if err != nil {
		return nil, errors.Wrapf(err, "Problem getting spendable UtxoEntrys: ")
	}

	// Add input utxos to the transaction until we have enough total input to cover
	// the amount we want to spend plus the maximum fee (or until we've exhausted
	// all the utxos available).
	spenderInputs := []*DeSoInput{}
	totalSpenderInput := uint64(0)
	for _, utxoEntry := range spenderSpendableUtxos {

		// If the amount of input we have isn't enough to cover the bid amount, add an input and continue.
		if totalSpenderInput < amountToCover {
			spenderInputs = append(spenderInputs, (*DeSoInput)(utxoEntry.UtxoKey))

			amountToAdd := utxoEntry.AmountNanos
			// For Bitcoin burns, we subtract a tiny amount of slippage to the amount we can
			// spend. This makes reorderings more forgiving.
			if utxoEntry.UtxoType == UtxoTypeBitcoinBurn {
				amountToAdd = uint64(float64(amountToAdd) * .999)
			}

			totalSpenderInput += amountToAdd
			continue
		}

		// If we get here, we know we have enough input to cover the upper bound
		// estimate of our amount needed so break.
		break
	}
	// If we get here and we don't have sufficient input to cover the bid, error.
	if totalSpenderInput < amountToCover {
		return nil, fmt.Errorf("Spender has insufficient "+
			"UTXOs (%d total) to cover amount %d: ", totalSpenderInput, amountToCover)
	}
	return spenderInputs, nil
}

func (bc *Blockchain) CreateNFTBidTxn(
	UpdaterPublicKey []byte,
	NFTPostHash *BlockHash,
	SerialNumber uint64,
	BidAmountNanos uint64,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {
	// Create a transaction containing the NFT bid fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKey,
		TxnMeta: &NFTBidMetadata{
			NFTPostHash,
			SerialNumber,
			BidAmountNanos,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Add inputs and change for a standard pay per KB transaction.
	totalInput, _, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateNFTBidTxn: Problem adding inputs: ")
	}

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateNFTBidTxn: NFTBid txn " +
			"must have at least one input but had zero inputs " +
			"instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateNFTTransferTxn(
	SenderPublicKey []byte,
	ReceiverPublicKey []byte,
	NFTPostHash *BlockHash,
	SerialNumber uint64,
	EncryptedUnlockableTextBytes []byte,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the NFT transfer fields.
	txn := &MsgDeSoTxn{
		PublicKey: SenderPublicKey,
		TxnMeta: &NFTTransferMetadata{
			NFTPostHash,
			SerialNumber,
			ReceiverPublicKey,
			EncryptedUnlockableTextBytes,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Add inputs and change for a standard pay per KB transaction.
	totalInput, _, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateNFTTransferTxn: Problem adding inputs: ")
	}

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateNFTTransferTxn: NFTTransfer txn must have " +
			"at least one input but had zero inputs instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateAcceptNFTTransferTxn(
	UpdaterPublicKey []byte,
	NFTPostHash *BlockHash,
	SerialNumber uint64,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the accept NFT transfer fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKey,
		TxnMeta: &AcceptNFTTransferMetadata{
			NFTPostHash,
			SerialNumber,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Add inputs and change for a standard pay per KB transaction.
	totalInput, _, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err,
			"CreateAcceptNFTTransferTxn: Problem adding inputs: ")
	}

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf(
			"CreateAcceptNFTTransferTxn: AcceptNFTTransfer txn must have at least one input" +
				" but had zero inputs instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateBurnNFTTxn(
	UpdaterPublicKey []byte,
	NFTPostHash *BlockHash,
	SerialNumber uint64,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the burn NFT fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKey,
		TxnMeta: &BurnNFTMetadata{
			NFTPostHash,
			SerialNumber,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Add inputs and change for a standard pay per KB transaction.
	totalInput, _, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateBurnNFTTxn: Problem adding inputs: ")
	}

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateBurnNFTTxn: BurnNFT txn must have at least " +
			"one input but had zero inputs instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateAcceptNFTBidTxn(
	UpdaterPublicKey []byte,
	NFTPostHash *BlockHash,
	SerialNumber uint64,
	BidderPKID *PKID,
	BidAmountNanos uint64,
	EncryptedUnlockableTextBytes []byte,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a new UtxoView. If we have access to a mempool object, use it to
	// get an augmented view that factors in pending transactions.
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err,
			"Blockchain.CreateAcceptNFTBidTxn: Problem creating new utxo view: ")
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err,
				"Blockchain.CreateAcceptNFTBidTxn: Problem getting augmented UtxoView from mempool: ")
		}
	}

	bidderPublicKey := utxoView.GetPublicKeyForPKID(BidderPKID)
	bidderInputs, err := bc.GetInputsToCoverAmount(bidderPublicKey, utxoView, BidAmountNanos)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err,
			"Blockchain.CreateAcceptNFTBidTxn: Error getting inputs for spend amount: ")
	}

	// Create a transaction containing the accept nft bid fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKey,
		TxnMeta: &AcceptNFTBidMetadata{
			NFTPostHash,
			SerialNumber,
			BidderPKID,
			BidAmountNanos,
			EncryptedUnlockableTextBytes,
			bidderInputs,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Add inputs and change for a standard pay per KB transaction.
	totalInput, _, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateAcceptNFTBidTxn: Problem adding inputs: ")
	}

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateAcceptNFTBidTxn: AcceptNFTBid txn " +
			"must have at least one input but had zero inputs " +
			"instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateUpdateNFTTxn(
	UpdaterPublicKey []byte,
	NFTPostHash *BlockHash,
	SerialNumber uint64,
	IsForSale bool,
	MinBidAmountNanos uint64,
	IsBuyNow bool,
	BuyNowPriceNanos uint64,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a transaction containing the update NFT fields.
	txn := &MsgDeSoTxn{
		PublicKey: UpdaterPublicKey,
		TxnMeta: &UpdateNFTMetadata{
			NFTPostHash,
			SerialNumber,
			IsForSale,
			MinBidAmountNanos,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// If this update makes the NFT a Buy Now NFT, set the extra data appropriately.
	if IsBuyNow {
		extraData := make(map[string][]byte)
		extraData[BuyNowPriceKey] = UintToBuf(BuyNowPriceNanos)
		txn.ExtraData = extraData
	}

	// Add inputs and change for a standard pay per KB transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateUpdateNFTTxn: Problem adding inputs: ")
	}
	_ = spendAmount

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateUpdateNFTTxn: AcceptNFTBid txn " +
			"must have at least one input but had zero inputs " +
			"instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

// Each diamond level is worth a fixed amount of DeSo. These amounts can be changed
// in the future by simply returning a new set of values after a particular block height.
func GetDeSoNanosDiamondLevelMapAtBlockHeight(
	blockHeight int64) map[int64]uint64 {

	return map[int64]uint64{
		1: 50000,
		2: 500000,
		3: 5000000,
		4: 50000000,
		5: 500000000,
		6: 5000000000,
		7: 50000000000,
		8: 500000000000,
	}
}

func GetDeSoNanosForDiamondLevelAtBlockHeight(
	diamondLevel int64, blockHeight int64) uint64 {

	// Caller is responsible for passing a valid diamond level.
	desoNanosMap := GetDeSoNanosDiamondLevelMapAtBlockHeight(blockHeight)
	desoNanosForLevel, levelExists := desoNanosMap[diamondLevel]
	if !levelExists {
		// We allow a special case for diamondLevel zero, in which case we
		// know that the value should also be zero.
		if diamondLevel != 0 {
			// If a non-existent level is requested, return zero
			glog.Errorf("GetDeSoNanosForDiamondLevelAtBlockHeight: "+
				"Diamond level %v does not exist in map %v; this should never happen",
				diamondLevel, desoNanosMap)
		}
		return 0
	}

	return desoNanosForLevel
}

// At a particular diamond level, a fixed amount of DeSo is converted into creator coins
// and then sent to a user. This function computes the amount of creator coins required for
// a particular level.
func GetCreatorCoinNanosForDiamondLevelAtBlockHeight(
	coinsInCirculationNanos uint64, desoLockedNanos uint64,
	diamondLevel int64, blockHeight int64, params *DeSoParams) uint64 {

	// No creator coins are required at level zero
	if diamondLevel == 0 {
		return 0
	}

	// First get the amount of DeSo required by this level.
	desoNanosForLevel := GetDeSoNanosForDiamondLevelAtBlockHeight(
		diamondLevel, blockHeight)

	// Figure out the amount of creator coins to print based on the user's CreatorCoinEntry.
	return CalculateCreatorCoinToMint(
		desoNanosForLevel, coinsInCirculationNanos,
		desoLockedNanos, params)
}

func (bc *Blockchain) CreateCreatorCoinTransferTxnWithDiamonds(
	SenderPublicKey []byte,
	ReceiverPublicKey []byte,
	DiamondPostHash *BlockHash,
	DiamondLevel int64,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a new UtxoView. If we have access to a mempool object, use it to
	// get an augmented view that factors in pending transactions.
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err,
			"Blockchain.CreateCreatorCoinTransferTxnWithDiamonds: "+
				"Problem creating new utxo view: ")
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err,
				"Blockchain.CreateCreatorCoinTransferTxnWithDiamonds: "+
					"Problem getting augmented UtxoView from mempool: ")
		}
	}

	blockHeight := bc.blockTip().Height + 1
	creatorCoinToTransferNanos, _, err := utxoView.ValidateDiamondsAndGetNumCreatorCoinNanos(
		SenderPublicKey, ReceiverPublicKey, DiamondPostHash, DiamondLevel, blockHeight)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateCreatorCoinTransferTxnWithDiamonds: Problem getting creator coin nanos: ")
	}

	// Create a transaction containing the creator coin fields.
	txn := &MsgDeSoTxn{
		PublicKey: SenderPublicKey,
		TxnMeta: &CreatorCoinTransferMetadataa{
			SenderPublicKey,
			// Buffer the creatorCoinToTransferNanos to factor in some slippage in the
			// creator coin price. Transferring more than is needed is allowed, but
			// undershooting will cause the transaction to be rejected.
			uint64(float64(creatorCoinToTransferNanos) * 1.05),
			ReceiverPublicKey,
		},
		TxOutputs: additionalOutputs,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Make a map for the diamond extra data.
	diamondsExtraData := make(map[string][]byte)
	diamondsExtraData[DiamondLevelKey] = IntToBuf(DiamondLevel)
	diamondsExtraData[DiamondPostHashKey] = DiamondPostHash[:]
	txn.ExtraData = diamondsExtraData

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "CreateCreatorCoinTransferTxnWithDiamonds: Problem adding inputs: ")
	}
	_ = spendAmount

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, fmt.Errorf(
			"CreateCreatorCoinTransferTxnWithDiamonds: CreatorCoinTransfer txn must have at" +
				" least one input but had zero inputs instead. Try increasing the fee rate.")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateAuthorizeDerivedKeyTxn(
	ownerPublicKey []byte,
	derivedPublicKey []byte,
	expirationBlock uint64,
	accessSignature []byte,
	deleteKey bool,
	derivedKeySignature bool,
	extraData map[string][]byte,
	memo []byte,
	transactionSpendingLimitHex string,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	blockHeight := bc.blockTip().Height + 1

	transactionSpendingLimitBytes, err := hex.DecodeString(transactionSpendingLimitHex)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err,
			"Blockchain.CreateAuthorizeDerivedKeyTxn: Problem decoding transactionSpendingLimitHex")
	}
	if blockHeight >= bc.params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight {
		if err := _verifyAccessSignatureWithTransactionSpendingLimit(ownerPublicKey, derivedPublicKey,
			expirationBlock, transactionSpendingLimitBytes, accessSignature); err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err,
				"Blockchain.CreateAuthorizeDerivedKeyTxn: Problem verifying access signature with transaction"+
					" spending limit")
		}
	} else {
		// Verify that the signature is valid.
		if err := _verifyAccessSignature(ownerPublicKey, derivedPublicKey,
			expirationBlock, accessSignature); err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err,
				"Blockchain.CreateAuthorizeDerivedKeyTxn: Problem verifying access signature")
		}
	}

	// Check that the expiration block is valid.
	if expirationBlock <= uint64(blockHeight) {
		return nil, 0, 0, 0, fmt.Errorf(
			"Blockchain.CreateAuthorizeDerivedKeyTxn: Expired access signature")
	}

	// Get the appropriate operation type.
	var operationType AuthorizeDerivedKeyOperationType
	if deleteKey {
		operationType = AuthorizeDerivedKeyOperationNotValid
	} else {
		operationType = AuthorizeDerivedKeyOperationValid
	}

	derivedKeyExtraData := make(map[string][]byte)
	if derivedKeySignature {
		derivedKeyExtraData[DerivedPublicKey] = derivedPublicKey
	}

	if blockHeight >= bc.params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight {
		if len(memo) != 0 {
			derivedKeyExtraData[DerivedKeyMemoKey] = memo
		}
		if len(transactionSpendingLimitBytes) != 0 {
			derivedKeyExtraData[TransactionSpendingLimitKey] = transactionSpendingLimitBytes
		}
	}

	// Delete protected keys
	if extraData != nil {
		delete(extraData, DerivedPublicKey)
		delete(extraData, DerivedKeyMemoKey)
		delete(extraData, TransactionSpendingLimitKey)
	}

	finalExtraData := mergeExtraData(extraData, derivedKeyExtraData)

	// Create a transaction containing the authorize derived key fields.
	txn := &MsgDeSoTxn{
		PublicKey: ownerPublicKey,
		TxnMeta: &AuthorizeDerivedKeyMetadata{
			derivedPublicKey,
			expirationBlock,
			operationType,
			accessSignature,
		},
		TxOutputs: additionalOutputs,
		ExtraData: finalExtraData,
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateAuthorizeDerivedKeyTxn: Problem adding inputs: ")
	}

	// Sanity-check that the spendAmount is zero.
	if spendAmount != 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateAuthorizeDerivedKeyTxn: Spend amount "+
			"should be zero but was %d instead: ", spendAmount)
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateMessagingKeyTxn(
	senderPublicKey []byte,
	messagingPublicKey []byte,
	messagingGroupKeyName []byte,
	messagingOwnerKeySignature []byte,
	members []*MessagingGroupMember,
	extraData map[string][]byte,
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// We don't need to validate info here, so just construct the transaction instead.
	txn := &MsgDeSoTxn{
		PublicKey: senderPublicKey,
		TxnMeta: &MessagingGroupMetadata{
			MessagingPublicKey:    messagingPublicKey,
			MessagingGroupKeyName: messagingGroupKeyName,
			GroupOwnerSignature:   messagingOwnerKeySignature,
			MessagingGroupMembers: members,
		},
		ExtraData: extraData,
		TxOutputs: additionalOutputs,
	}

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateMessagingKeyTxn: Problem adding inputs: ")
	}

	// Sanity-check that the spendAmount is zero.
	if spendAmount != 0 {
		return nil, 0, 0, 0, fmt.Errorf("Blockchain.CreateMessagingKeyTxn: Spend amount "+
			"should be zero but was %d instead: ", spendAmount)
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateBasicTransferTxnWithDiamonds(
	SenderPublicKey []byte,
	DiamondPostHash *BlockHash,
	DiamondLevel int64,
	// Standard transaction fields
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _spendAmount uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Create a new UtxoView. If we have access to a mempool object, use it to
	// get an augmented view that factors in pending transactions.
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres)
	if err != nil {
		return nil, 0, 0, 0, 0, errors.Wrapf(err,
			"Blockchain.CreateBasicTransferTxnWithDiamonds: "+
				"Problem creating new utxo view: ")
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		if err != nil {
			return nil, 0, 0, 0, 0, errors.Wrapf(err,
				"Blockchain.CreateBasicTransferTxnWithDiamonds: "+
					"Problem getting augmented UtxoView from mempool: ")
		}
	}

	// Get the post that we are trying to diamond so that we have the receiver public key.
	diamondPostEntry := utxoView.GetPostEntryForPostHash(DiamondPostHash)
	if diamondPostEntry == nil || diamondPostEntry.isDeleted {
		return nil, 0, 0, 0, 0, fmt.Errorf(
			"Blockchain.CreateBasicTransferTxnWithDiamonds: " +
				"Problem getting post entry for post hash")
	}

	blockHeight := bc.blockTip().Height + 1
	desoToTransferNanos, _, err := utxoView.ValidateDiamondsAndGetNumDeSoNanos(
		SenderPublicKey, diamondPostEntry.PosterPublicKey, DiamondPostHash, DiamondLevel, blockHeight)
	if err != nil {
		return nil, 0, 0, 0, 0, errors.Wrapf(
			err, "Blockchain.CreateBasicTransferTxnWithDiamonds: Problem getting deso nanos: ")
	}

	// Build the basic transfer txn.
	txn := &MsgDeSoTxn{
		PublicKey: SenderPublicKey,
		TxnMeta:   &BasicTransferMetadata{},
		TxOutputs: append(additionalOutputs, &DeSoOutput{
			PublicKey:   diamondPostEntry.PosterPublicKey,
			AmountNanos: desoToTransferNanos,
		}),
		// TxInputs and TxOutputs will be set below.
		// This function does not compute a signature.
	}

	// Make a map for the diamond extra data and add it.
	diamondsExtraData := make(map[string][]byte)
	diamondsExtraData[DiamondLevelKey] = IntToBuf(DiamondLevel)
	diamondsExtraData[DiamondPostHashKey] = DiamondPostHash[:]
	txn.ExtraData = diamondsExtraData

	// We don't need to make any tweaks to the amount because it's basically
	// a standard "pay per kilobyte" transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, 0, errors.Wrapf(
			err, "CreateBasicTransferTxnWithDiamonds: Problem adding inputs: ")
	}
	_ = spendAmount

	// We want our transaction to have at least one input, even if it all
	// goes to change. This ensures that the transaction will not be "replayable."
	if len(txn.TxInputs) == 0 {
		return nil, 0, 0, 0, 0, fmt.Errorf(
			"CreateBasicTransferTxnWithDiamonds: CreatorCoinTransfer txn must have at" +
				" least one input but had zero inputs instead. Try increasing the fee rate.")
	}

	return txn, totalInput, spendAmount, changeAmount, fees, nil
}

func (bc *Blockchain) CreateMaxSpend(
	senderPkBytes []byte, recipientPkBytes []byte, minFeeRateNanosPerKB uint64,
	mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInputAdded uint64, _spendAmount uint64, _fee uint64, _err error) {

	txn := &MsgDeSoTxn{
		PublicKey: senderPkBytes,
		TxnMeta:   &BasicTransferMetadata{},
		// Set a single output with the maximum possible size to ensure we don't
		// underestimate the fee. Note it must be a max size output because outputs
		// are encoded as uvarints.
		TxOutputs: append(additionalOutputs, &DeSoOutput{
			PublicKey:   recipientPkBytes,
			AmountNanos: math.MaxUint64,
		}),
		// TxInputs and TxOutputs will be set below.
		// This function does not compute a signature.
	}

	// Get the spendable UtxoEntrys.
	spendableUtxos, err := bc.GetSpendableUtxosForPublicKey(senderPkBytes, mempool, nil)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateMaxSpend: Problem getting spendable UtxoEntrys: ")
	}

	totalInput := uint64(0)
	for _, utxoEntry := range spendableUtxos {
		amountToAdd := utxoEntry.AmountNanos
		// For Bitcoin burns, we subtract a tiny amount of slippage to the amount we can
		// spend. This makes reorderings more forgiving.
		if utxoEntry.UtxoType == UtxoTypeBitcoinBurn {
			amountToAdd = uint64(float64(amountToAdd) * .999)
		}
		totalInput += amountToAdd
		txn.TxInputs = append(txn.TxInputs, (*DeSoInput)(utxoEntry.UtxoKey))

		// Avoid creating transactions that are ridiculously huge. Note this is smaller
		// than what AddInputsAndChangeToTransaction will allow because we want to leave
		// some breathing room to avoid this transaction getting rejected.
		currentTxnSize := _computeMaxTxSize(txn)
		if currentTxnSize > bc.params.MaxBlockSizeBytes/3 {
			if len(txn.TxInputs) > 0 {
				// Cut off the last input if the transaction just became too large.
				txn.TxInputs = txn.TxInputs[:len(txn.TxInputs)-1]
			}
			break
		}
	}

	txnFee := _computeMaxTxFee(txn, minFeeRateNanosPerKB)

	if totalInput < txnFee {
		return nil, 0, 0, 0, fmt.Errorf("CreateMaxSpend: Total input value %d would "+
			"be less than the fee required to spend it %d", totalInput, txnFee)
	}

	// We have multiple outputs, the last one of which pays the receiver whatever is left after subtracting off
	// the fee. We can just set the value of the dummy output we set up earlier.
	txn.TxOutputs[len(txn.TxOutputs)-1].AmountNanos = totalInput - txnFee

	return txn, totalInput, totalInput - txnFee, txnFee, nil
}

// AddInputsAndChangeToTransaction fetches and adds utxos to the transaction passed
// in to meet the desired spend amount while also satisfying the desired minimum fee
// rate. Additionally, if it's worth it, this function will add a change output
// sending excess DeSo back to the spend public key. Note that the final feerate of the
// transaction after calling this function may exceed the minimum feerate requested.
// This can happen if the signature occupies fewer bytes than the expected maximum
// number of bytes or if the change output occupies fewer bytes than the expected
// maximum (though there could be other ways for this to happen).
//
// The transaction passed in should not have any inputs on it before calling this
// function (an error is returned if it does). Additionally, the output of the
// transaction passed in is assumed to be the amount the caller wishes us to find
// inputs for.
//
// An error is returned if there is not enough input associated with this
// public key to satisfy the transaction's output (subject to the minimum feerate).
func (bc *Blockchain) AddInputsAndChangeToTransaction(
	txArg *MsgDeSoTxn, minFeeRateNanosPerKB uint64, mempool *DeSoMempool) (
	_totalInputAdded uint64, _spendAmount uint64, _totalChangeAdded uint64, _fee uint64, _err error) {

	return bc.AddInputsAndChangeToTransactionWithSubsidy(txArg, minFeeRateNanosPerKB, 0, mempool, 0)
}

func (bc *Blockchain) AddInputsAndChangeToTransactionWithSubsidy(
	txArg *MsgDeSoTxn, minFeeRateNanosPerKB uint64, inputSubsidy uint64, mempool *DeSoMempool, additionalFees uint64) (
	_totalInputAdded uint64, _spendAmount uint64, _totalChangeAdded uint64, _fee uint64, _err error) {

	// The transaction we're working with should never have any inputs
	// set since we'll be setting the inputs here and dealing with a case where
	// inputs are partially set before-hand would significantly complicate this
	// function. So return an error if we find any inputs.
	if len(txArg.TxInputs) > 0 {
		return 0, 0, 0, 0, fmt.Errorf("_computeInputsForTxn: Transaction passed in "+
			"txArg should not have any inputs set but found the found %d inputs",
			len(txArg.TxInputs))
	}

	// The output of the transaction is assumed to be the desired amount the
	// caller wants to find inputs for. Start by computing it.
	spendAmount := uint64(0)
	for _, desoOutput := range txArg.TxOutputs {
		spendAmount += desoOutput.AmountNanos
	}
	// If this is a CreatorCoin buy transaction, add the amount of DeSo the
	// user wants to spend on the buy to the amount of output we're asking this
	// function to provide for us.
	if txArg.TxnMeta.GetTxnType() == TxnTypeCreatorCoin {
		txMeta := txArg.TxnMeta.(*CreatorCoinMetadataa)
		if txMeta.OperationType == CreatorCoinOperationTypeBuy {
			// If this transaction is a buy then we need enough DeSo to
			// cover the buy.
			spendAmount += txMeta.DeSoToSellNanos
		}
	}

	// If this is an NFT Bid txn and the NFT entry is a Buy Now, we add inputs to cover the bid amount.
	if txArg.TxnMeta.GetTxnType() == TxnTypeNFTBid && txArg.TxnMeta.(*NFTBidMetadata).SerialNumber > 0 {
		// Create a new UtxoView. If we have access to a mempool object, use it to
		// get an augmented view that factors in pending transactions.
		var utxoView *UtxoView
		if mempool != nil {
			var err error
			utxoView, err = mempool.GetAugmentedUniversalView()
			if err != nil {
				return 0, 0, 0, 0, errors.Wrapf(err,
					"_computeInputsForTxn: Problem getting augmented UtxoView from mempool: ")
			}
		} else {
			var err error
			utxoView, err = NewUtxoView(bc.db, bc.params, bc.postgres)
			if err != nil {
				return 0, 0, 0, 0, errors.Wrapf(err,
					"_computeInputsForTxn: Problem creating new utxo view: ")
			}
		}

		txMeta := txArg.TxnMeta.(*NFTBidMetadata)

		nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
		nftEntry := utxoView.GetNFTEntryForNFTKey(&nftKey)

		if nftEntry != nil && nftEntry.isDeleted {
			return 0, 0, 0, 0, errors.New(
				"_computeInputsForTxn: nftEntry is deleted")
		}

		if nftEntry != nil && nftEntry.IsBuyNow && nftEntry.BuyNowPriceNanos <= txMeta.BidAmountNanos {
			spendAmount += txMeta.BidAmountNanos
		}
	}

	// Add additional fees to the spend amount.
	spendAmount += additionalFees
	// The public key of the transaction is assumed to be the one set at its
	// top level.
	spendPublicKeyBytes := txArg.PublicKey

	// Make a copy of the transaction. This makes it so that we don't need
	// to modify the passed-in transaction until we're absolutely sure we don't
	// have an error.
	txCopyWithChangeOutput, err := txArg.Copy()
	if err != nil {
		return 0, 0, 0, 0, errors.Wrapf(err, "AddInputsAndChangeToTransaction: ")
	}
	// Since we generally want to compute an upper bound on the transaction
	// size, add a change output to the transaction to factor in the
	// worst-case situation in which a change output is required. This
	// assignment and ones like it that follow should leave the original
	// transaction's outputs/slices unchanged.
	changeOutput := &DeSoOutput{
		PublicKey: make([]byte, btcec.PubKeyBytesLenCompressed),
		// Since we want an upper bound on the transaction size, set the amount
		// to the maximum value since that will induce the serializer to encode
		// a maximum-sized uvarint.
		AmountNanos: math.MaxUint64,
	}
	txCopyWithChangeOutput.TxOutputs = append(txCopyWithChangeOutput.TxOutputs, changeOutput)

	// Get the spendable UtxoEntrys.
	spendableUtxos, err := bc.GetSpendableUtxosForPublicKey(spendPublicKeyBytes, mempool, nil)
	if err != nil {
		return 0, 0, 0, 0, errors.Wrapf(err, "AddInputsAndChangeToTransaction: Problem getting spendable UtxoEntrys: ")
	}

	// Add input utxos to the transaction until we have enough total input to cover
	// the amount we want to spend plus the maximum fee (or until we've exhausted
	// all the utxos available).
	utxoEntriesBeingUsed := []*UtxoEntry{}
	totalInput := inputSubsidy
	for _, utxoEntry := range spendableUtxos {
		// As an optimization, don't worry about the fee until the total input has
		// definitively exceeded the amount we want to spend. We do this because computing
		// the fee each time we add an input would result in N^2 behavior.
		maxAmountNeeded := spendAmount
		if totalInput >= spendAmount {
			maxAmountNeeded += _computeMaxTxFeeWithMaxChange(txCopyWithChangeOutput, minFeeRateNanosPerKB)
		}

		// If the amount of input we have isn't enough to cover our upper bound on
		// the total amount we could need, add an input and continue.
		if totalInput < maxAmountNeeded {
			txCopyWithChangeOutput.TxInputs = append(txCopyWithChangeOutput.TxInputs, (*DeSoInput)(utxoEntry.UtxoKey))
			utxoEntriesBeingUsed = append(utxoEntriesBeingUsed, utxoEntry)

			amountToAdd := utxoEntry.AmountNanos
			// For Bitcoin burns, we subtract a tiny amount of slippage to the amount we can
			// spend. This makes reorderings more forgiving.
			if utxoEntry.UtxoType == UtxoTypeBitcoinBurn {
				amountToAdd = uint64(float64(amountToAdd) * .999)
			}
			totalInput += amountToAdd
			continue
		}

		// If we get here, we know we have enough input to cover the upper bound
		// estimate of our amount needed so break.
		break
	}

	// At this point, utxoEntriesBeingUsed should contain enough to cover the
	// maximum amount we'd need in a worst-case scenario (or as close as we could
	// get to that point). Now we add these utxos to a new transaction in order
	// to properly compute the change we might need.

	// Re-copy the passed-in transaction and re-add all the inputs we deemed
	// were necessary but this time don't add a change output unless it's strictly
	// necessary.
	finalTxCopy, _ := txArg.Copy()
	for _, utxoEntry := range utxoEntriesBeingUsed {
		finalTxCopy.TxInputs = append(finalTxCopy.TxInputs, (*DeSoInput)(utxoEntry.UtxoKey))
	}
	maxFeeWithMaxChange := _computeMaxTxFeeWithMaxChange(finalTxCopy, minFeeRateNanosPerKB)
	if totalInput < (spendAmount + maxFeeWithMaxChange) {
		// In this case the total input we were able to gather for the
		// transaction is insufficient to cover the amount we want to
		// spend plus the fee. Return an error in this case so that
		// either the spend amount or the fee rate can be adjusted.
		return 0, 0, 0, 0, fmt.Errorf("AddInputsAndChangeToTransaction: Sanity check failed: Total "+
			"input %d is not sufficient to "+
			"cover the spend amount (=%d) plus the fee (=%d, feerate=%d, txsize=%d), "+
			"total=%d", totalInput, spendAmount, maxFeeWithMaxChange, minFeeRateNanosPerKB,
			_computeMaxTxSize(finalTxCopy), spendAmount+maxFeeWithMaxChange)
	}

	// Now that we know the input will cover the spend amount plus the fee, add
	// a change output if the value of including one definitely exceeds the cost.
	//
	// Note this is an approximation that will result in change not being included
	// in circumstances where the value of including it is very marginal but that
	// seems OK. It also will short-change the user a bit if their output is not
	// at the maximum size but that seems OK as well. In all of these circumstances
	// the user will get a slightly higher feerate than they asked for which isn't
	// really a problem.
	changeAmount := int64(totalInput) - int64(spendAmount) - int64(maxFeeWithMaxChange)
	if changeAmount > 0 {
		finalTxCopy.TxOutputs = append(finalTxCopy.TxOutputs, &DeSoOutput{
			PublicKey:   spendPublicKeyBytes,
			AmountNanos: uint64(changeAmount),
		})
	} else {
		changeAmount = 0
	}

	// The final fee is what's left after subtracting the spend amount and the
	// change from the total input.
	finalFee := totalInput - spendAmount - uint64(changeAmount)

	// If the final transaction is absolutely huge, return an error.
	finalTxnSize := _computeMaxTxSize(finalTxCopy)
	if finalTxnSize > bc.params.MaxBlockSizeBytes/2 {
		return 0, 0, 0, 0, fmt.Errorf("AddInputsAndChangeToTransaction: "+
			"Transaction size (%d bytes) exceeds the maximum sane amount "+
			"allowed (%d bytes)", finalTxnSize, bc.params.MaxBlockSizeBytes/2)
	}

	// At this point, the inputs cover the (spend amount plus transaction fee)
	// and the change output has been added if needed, with the total fees of
	// the transaction set such that the feerate exceeds the minFeeRatePerKB
	// passed in. Set the inputs and outputs of the transaction passed in and
	// return.
	txArg.TxInputs = finalTxCopy.TxInputs
	txArg.TxOutputs = finalTxCopy.TxOutputs

	return totalInput, spendAmount, uint64(changeAmount), finalFee, nil
}

func (bc *Blockchain) EstimateDefaultFeeRateNanosPerKB(
	medianThreshold float64, minFeeRateNanosPerKB uint64) uint64 {

	// Get the block at the tip of our block chain.
	tipNode := bc.blockTip()
	blk, err := GetBlock(tipNode.Hash, bc.db)
	if err != nil {
		return minFeeRateNanosPerKB
	}

	// If the block is less than X% full, use the min fee rate.
	blockBytes, err := blk.ToBytes(false /*preSignature*/)
	if err != nil {
		return minFeeRateNanosPerKB
	}
	numBytes := len(blockBytes)
	if float64(numBytes)/float64(bc.params.MaxBlockSizeBytes) < medianThreshold {
		return minFeeRateNanosPerKB
	}

	// If the block is more than X% full, use the maximum between the min
	// fee rate and the median fees of all the transactions in the block.
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres)
	if err != nil {
		return minFeeRateNanosPerKB
	}
	utxoOps, err := GetUtxoOperationsForBlock(bc.db, tipNode.Hash)
	if err != nil {
		return minFeeRateNanosPerKB
	}
	// Compute the hashes for all the transactions.
	txHashes, err := ComputeTransactionHashes(blk.Txns)
	if err != nil {
		return minFeeRateNanosPerKB
	}
	if err := utxoView.DisconnectBlock(blk, txHashes, utxoOps); err != nil {
		return minFeeRateNanosPerKB
	}

	allFeesNanosPerKB := []uint64{}
	for _, txn := range blk.Txns {
		txnBytes, err := txn.ToBytes(false /*preSignature*/)
		if err != nil {
			return minFeeRateNanosPerKB
		}
		numBytesInTxn := len(txnBytes)
		_, _, _, fees, err := utxoView.ConnectTransaction(
			txn, txn.Hash(), int64(numBytesInTxn), tipNode.Height, false /*verifySignatures*/, false /*ignoreUtxos*/)
		if err != nil {
			return minFeeRateNanosPerKB
		}
		allFeesNanosPerKB = append(
			allFeesNanosPerKB, uint64(fees)*1000/uint64(numBytesInTxn))
	}

	// Sort all the fees.
	sort.Slice(allFeesNanosPerKB, func(ii, jj int) bool {
		return allFeesNanosPerKB[ii] < allFeesNanosPerKB[jj]
	})

	// Choose a fee at the middle of the range, which represents the median.
	medianPos := len(allFeesNanosPerKB) / 2

	// Useful for debugging.
	/*
		for _, val := range allFeesNanosPerKB {
			fmt.Printf("%d ", val)
		}
		fmt.Println()
	*/

	if minFeeRateNanosPerKB > allFeesNanosPerKB[medianPos] {
		return minFeeRateNanosPerKB
	}
	return allFeesNanosPerKB[medianPos]
}
