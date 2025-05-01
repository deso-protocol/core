package lib

import (
	"encoding/hex"
	"fmt"
	ecdsa2 "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/deso-protocol/go-deadlock"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/tyler-smith/go-bip39"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

type DeSoBlockProducer struct {
	// The minimum amount of time we wait before trying to produce a new block
	// template. If this value is set low enough then we will produce a block template
	// continuously.
	minBlockUpdateIntervalSeconds uint64
	// The number of templates to cache so that we can accept headers for blocks
	// that are a bit stale.
	maxBlockTemplatesToCache uint64
	// A private key that is used to sign blocks produced by this block producer. Only
	// set if a blockProducerSeed is provided when constructing the BlockProducer.
	blockProducerPrivateKey *btcec.PrivateKey
	// A lock on the block templates produced to avoid concurrency issues.
	mtxRecentBlockTemplatesProduced deadlock.RWMutex
	// The most recent N blocks that we've produced indexed by their hash.
	// Keeping this list allows us to accept a valid header from a miner without
	// requiring them to download/send the whole block.
	recentBlockTemplatesProduced map[BlockHash]*MsgDeSoBlock
	latestBlockTemplateHash      *BlockHash
	currentDifficultyTarget      *BlockHash

	latestBlockTemplateStats *BlockTemplateStats

	mempool  *DeSoMempool
	chain    *Blockchain
	params   *DeSoParams
	postgres *Postgres

	// producerWaitGroup allows us to wait until the producer has properly closed.
	producerWaitGroup sync.WaitGroup
	// exit is used to signal that DeSoBlockProducer routines should be terminated.
	exit int32
	// isAsleep is a helper variable for quitting that indicates whether the DeSoBlockProducer is asleep. While producing
	// blocks, we sleep for a few seconds. Instead of waiting for the sleep to finish, we use this variable to quit immediately.
	isAsleep int32
}

type BlockTemplateStats struct {
	// The number of txns in the block template.
	TxnCount uint32
	// The final txn we attempted to put in the block.
	FailingTxnHash string
	// The reason why the final txn failed to add.
	FailingTxnError string
	// The "Added" time on a transaction changes every time a block is mined so we record
	// the first time added val we are aware of for a specific txn hash here.
	FailingTxnOriginalTimeAdded time.Time
	// The time since the failing txn was added to the mempool.
	FailingTxnMinutesSinceAdded float64
}

func NewDeSoBlockProducer(
	minBlockUpdateIntervalSeconds uint64,
	maxBlockTemplatesToCache uint64,
	blockProducerSeed string,
	mempool *DeSoMempool,
	chain *Blockchain,
	params *DeSoParams,
	postgres *Postgres,
) (*DeSoBlockProducer, error) {
	var privKey *btcec.PrivateKey
	if blockProducerSeed != "" {
		// If a blockProducerSeed is provided then we use it to generate a private key.
		// If the block producer seed beings with 0x, we treat it as a hex seed. Otherwise,
		// we treat it as a seed phrase.
		if strings.HasPrefix(blockProducerSeed, "0x") {
			privKeyBytes, err := hex.DecodeString(blockProducerSeed[2:])
			if err != nil {
				return nil, fmt.Errorf("NewDeSoBlockProducer: Error decoding hex seed: %+v", err)
			}
			privKey, _ = btcec.PrivKeyFromBytes(privKeyBytes)
		} else {
			seedBytes, err := bip39.NewSeedWithErrorChecking(blockProducerSeed, "")
			if err != nil {
				return nil, fmt.Errorf("NewDeSoBlockProducer: Error converting mnemonic: %+v", err)
			}

			_, privKey, _, err = ComputeKeysFromSeed(seedBytes, 0, params)
			if err != nil {
				return nil, fmt.Errorf(
					"NewDeSoBlockProducer: Error computing keys from seed: %+v", err)
			}
		}
	}

	return &DeSoBlockProducer{
		minBlockUpdateIntervalSeconds: minBlockUpdateIntervalSeconds,
		maxBlockTemplatesToCache:      maxBlockTemplatesToCache,
		blockProducerPrivateKey:       privKey,
		recentBlockTemplatesProduced:  make(map[BlockHash]*MsgDeSoBlock),

		mempool:  mempool,
		chain:    chain,
		params:   params,
		postgres: postgres,
	}, nil
}

func (bbp *DeSoBlockProducer) GetLatestBlockTemplateStats() *BlockTemplateStats {
	return bbp.latestBlockTemplateStats
}

func (desoBlockProducer *DeSoBlockProducer) _updateBlockTimestamp(blk *MsgDeSoBlock, lastNode *BlockNode) {
	// Set the block's timestamp. If the timesource's time happens to be before
	// the timestamp set in the last block then set the time based on the last
	// block's timestamp instead. We do this because consensus rules require a
	// monotonically increasing timestamp.
	blockTstamp := desoBlockProducer.chain.timeSource.AdjustedTime().Unix()
	if blockTstamp <= lastNode.Header.GetTstampSecs() {
		blockTstamp = lastNode.Header.GetTstampSecs() + 1
	}
	blk.Header.SetTstampSecs(blockTstamp)
}

func (desoBlockProducer *DeSoBlockProducer) _getBlockTemplate(publicKey []byte) (
	_blk *MsgDeSoBlock, _diffTarget *BlockHash, _lastNode *BlockNode, _err error) {

	// Get the current tip of the best block chain. Note that using the tip of the
	// best block chain as opposed to the best header chain means we'll be mining
	// stale blocks until we're fully synced. This isn't ideal, but is currently
	// preferred to mining atop the best header chain because the latter currently results
	// in the blocks being rejected as unconnectedTxns before the block tip is in-sync.
	lastNode := desoBlockProducer.chain.blockTip()

	// Compute the public key to contribute the reward to.
	rewardPk, err := btcec.ParsePubKey(publicKey)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "DeSoBlockProducer._getBlockTemplate: ")
	}

	// Construct the next block.
	blockRewardOutput := &DeSoOutput{}
	if rewardPk != nil {
		// This is to account for a really weird edge case where somebody stops the BlockProducer
		// in the middle of us getting a block.
		blockRewardOutput.PublicKey = rewardPk.SerializeCompressed()
	}
	// Set the block reward output initially to the maximum value for a uint64.
	// This ensures it will take the maximum amount of space in the block when
	// encoded as a varint so our size estimates won't get messed up.
	blockRewardOutput.AmountNanos = math.MaxUint64

	// Block reward txn only needs a single output. No need to specify spending
	// pk or sigs.
	blockRewardTxn := NewMessage(MsgTypeTxn).(*MsgDeSoTxn)
	blockRewardTxn.TxOutputs = append(blockRewardTxn.TxOutputs, blockRewardOutput)
	// Set the ExtraData to zero. This gives miners something they can
	// twiddle if they run out of space on their actual nonce.
	blockRewardTxn.TxnMeta = &BlockRewardMetadataa{
		ExtraData: UintToBuf(0),
	}

	// Create the block and add the BlockReward txn to it.
	blockRet := NewMessage(MsgTypeBlock).(*MsgDeSoBlock)
	blockRet.Txns = append(blockRet.Txns, blockRewardTxn)
	// The version may be swapped out in a call to GetBlockTemplate in order to remain
	// backwards-compatible with existing miners that use an older version.
	blockRet.Header.Version = CurrentHeaderVersion
	blockRet.Header.Height = uint64(lastNode.Height + 1)
	blockRet.Header.PrevBlockHash = lastNode.Hash
	desoBlockProducer._updateBlockTimestamp(blockRet, lastNode)
	// Start the nonce at zero. This is OK because we'll set a random ExtraData for the
	// miner later.
	blockRet.Header.Nonce = 0

	// Only add transactions to the block if our chain is done syncing.
	if desoBlockProducer.chain.chainState() != SyncStateSyncingHeaders &&
		desoBlockProducer.chain.chainState() != SyncStateNeedBlocksss {

		// Fetch a bunch of mempool transactions to add.
		txnsOrderedByTimeAdded, _, err := desoBlockProducer.mempool.GetTransactionsOrderedByTimeAdded()
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "DeSoBlockProducer._getBlockTemplate: Problem getting mempool transactions: ")
		}

		// Now keep
		// adding transactions to the block until the block is full.
		//
		// Compute the size of the header and then add the number of bytes used to encode
		// the number of transactions in the block. Note that headers have a fixed size.
		//
		// TODO: The code below is lazily-written and could be optimized to squeeze a few
		// more bytes into each block.
		//
		// Track the total size of the block as we go. Since the number of transactions
		// encoded in the block can become larger as we add transactions to it, add the
		// maximum size for this field to the current size to ensure we don't overfill
		// the block.
		blockBytes, err := blockRet.ToBytes(false)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "DeSoBlockProducer._getBlockTemplate: Problem serializing block: ")
		}
		currentBlockSize := uint64(len(blockBytes) + MaxVarintLen64)

		// Create a new view object.
		utxoView := NewUtxoView(desoBlockProducer.chain.db, desoBlockProducer.params,
			desoBlockProducer.postgres, desoBlockProducer.chain.snapshot, nil)

		txnsAddedToBlock := make(map[BlockHash]bool)
		for ii, mempoolTx := range txnsOrderedByTimeAdded {
			// If we hit a transaction that's too big to fit into a block then we're done.
			if mempoolTx.TxSizeBytes+currentBlockSize > desoBlockProducer.params.MinerMaxBlockSizeBytes {
				break
			}

			// Try to apply the transaction to the view with the strictest possible checks.
			// Make a copy of the view in order to test applying the txn without compromising the
			// integrity of the view.
			// TODO: This is inefficient but we're doing it short-term to fix a bug. Also PoS is
			// coming soon anyway.
			utxoViewCopy := utxoView.CopyUtxoView()
			_, _, _, _, err = utxoViewCopy._connectTransaction(mempoolTx.Tx, mempoolTx.Hash,
				uint32(blockRet.Header.Height), int64(blockRet.Header.TstampNanoSecs), true, false)
			if err != nil {
				// Skip failing txns. This should happen super rarely.
				txnErrorString := fmt.Sprintf(
					"DeSoBlockProducer._getBlockTemplate: Skipping txn %v because it had an error: %v", ii, err)
				glog.Error(txnErrorString)
				glog.Infof("DeSoBlockProducer._getBlockTemplate: Recomputing UtxoView without broken txn...")
				continue
			}
			// At this point, we know the transaction isn't going to break our view so attach it.
			_, _, _, _, err = utxoView._connectTransaction(mempoolTx.Tx, mempoolTx.Hash,
				uint32(blockRet.Header.Height), int64(blockRet.Header.TstampNanoSecs), true, false)
			if err != nil {
				// We should never get an error here since we just attached a txn to an indentical
				// view.
				return nil, nil, nil, errors.Wrapf(err,
					"DeSoBlockProducer._getBlockTemplate: Error attaching txn to main utxoView; "+
						"this should never happen: ")
			}

			// Log some stats
			// TODO: I don't think these are needed anymore. They were useful when we had the Bitcoin->DESO
			// converter baked directly into the chain, whereby the mempool could get stuck on Bitcoin merkle
			// txns.
			if desoBlockProducer.latestBlockTemplateStats != nil {
				desoBlockProducer.latestBlockTemplateStats.FailingTxnError = "You good"
				desoBlockProducer.latestBlockTemplateStats.FailingTxnHash = "Nada"
				desoBlockProducer.latestBlockTemplateStats.FailingTxnMinutesSinceAdded = 0
				desoBlockProducer.latestBlockTemplateStats.FailingTxnOriginalTimeAdded = time.Now()
			}

			// If we get here then it means the txn is ready to be processed *and* we've added
			// all of its dependencies to the block already. So go ahead and it to the block.
			currentBlockSize += mempoolTx.TxSizeBytes + MaxVarintLen64
			blockRet.Txns = append(blockRet.Txns, mempoolTx.Tx)
			txnsAddedToBlock[*mempoolTx.Hash] = true
		}

		// Double-check that the final block size is below the limit.
		blockBytes, err = blockRet.ToBytes(false)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "DeSoBlockProducer._getBlockTemplate: Problem serializing block after txns added: ")
		}
		if uint64(len(blockBytes)) > desoBlockProducer.params.MinerMaxBlockSizeBytes {
			return nil, nil, nil, fmt.Errorf("DeSoBlockProducer._getBlockTemplate: Block created with size "+
				"(%d) exceeds BlockProducerMaxBlockSizeBytes (%d): ", len(blockBytes), desoBlockProducer.params.MinerMaxBlockSizeBytes)
		}
	}

	// Compute the total fee the BlockProducer should get.
	totalFeeNanos := uint64(0)
	feesUtxoView := NewUtxoView(desoBlockProducer.chain.db, desoBlockProducer.params,
		desoBlockProducer.postgres, desoBlockProducer.chain.snapshot, nil)

	// Parse the public key that should be used for the block reward.
	blockRewardOutputPublicKey := NewPublicKey(blockRewardOutput.PublicKey)
	if blockRewardOutputPublicKey == nil {
		return nil, nil, nil, fmt.Errorf(
			"DeSoBlockProducer._getBlockTemplate: problem parsing block reward output public key: %v",
			blockRewardOutput.PublicKey,
		)
	}

	// Skip the block reward, which is the first txn in the block.
	for _, txnInBlock := range blockRet.Txns[1:] {
		var feeNanos uint64
		_, _, _, feeNanos, err = feesUtxoView._connectTransaction(
			txnInBlock, txnInBlock.Hash(), uint32(blockRet.Header.Height), blockRet.Header.TstampNanoSecs, false, false,
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf(
				"DeSoBlockProducer._getBlockTemplate: Error attaching txn to UtxoView for computed block: %v", err)
		}

		includeFeesInBlockReward := true
		if blockRet.Header.Height >= uint64(desoBlockProducer.params.ForkHeights.BlockRewardPatchBlockHeight) {
			if txnInBlock.TxnMeta.GetTxnType() != TxnTypeAtomicTxnsWrapper {
				// Parse the transactor's public key to compare with the block reward output public key.
				transactorPublicKey := NewPublicKey(txnInBlock.PublicKey)
				if transactorPublicKey == nil {
					return nil, nil, nil,
						fmt.Errorf(
							"DeSoBlockProducer._getBlockTemplate: problem parsing transactor public key: %v",
							txnInBlock.PublicKey)
				}
				includeFeesInBlockReward = !transactorPublicKey.Equal(*blockRewardOutputPublicKey)
			} else {
				// In the case of atomic transaction wrappers, we must parse and process each inner transaction
				// independently. We let includeFeesInBlockRewards remain true but decrement feeNanos whenever
				// transactor public key equals block reward output public key. In effect, we ignore
				// fees in atomic transactions where the transactor is equivalent to the block producer.
				txnMeta, ok := txnInBlock.TxnMeta.(*AtomicTxnsWrapperMetadata)
				if !ok {
					return nil, nil, nil,
						errors.Wrapf(err,
							"DeSoBlockProducer._getBlockTemplate: "+
								"problem casting txn metadata to AtomicTxnsWrapperMetadata: ")
				}
				feeNanos, err = filterOutBlockRewardRecipientFees(
					txnMeta.Txns, blockRewardOutputPublicKey)
				if err != nil {
					return nil, nil, nil,
						errors.Wrapf(err,
							"DeSoBlockProducer._getBlockTemplate: "+
								"problem filtering out block reward recipient fees: ")
				}
			}
		}

		// If the transactor is not the block reward output (or we're before the BlockRewardPatchBlockHeight),
		// add the fee to the total.
		// We exclude fees from transactions where the block reward output public key
		// is the same as the transactor public key to prevent the block reward output
		// public key from getting free transaction fees.
		if includeFeesInBlockReward {
			// Check for overflow
			if totalFeeNanos > math.MaxUint64-feeNanos {
				return nil, nil, nil,
					fmt.Errorf("DeSoBlockProducer._getBlockTemplate: Total fee overflowed uint64")
			}
			// Add the fee to the block reward output as we go. Note this has some risk of
			// increasing the size of the block by one byte, but it seems like this is an
			// extreme edge case that goes away as soon as the function is called again.
			totalFeeNanos += feeNanos
		}
	}

	// Now that the total fees have been computed, set the value of the block reward
	// output.
	blockRewardOutput.AmountNanos = CalcBlockRewardNanos(uint32(blockRet.Header.Height), desoBlockProducer.params) +
		totalFeeNanos

	// Compute the merkle root for the block now that all of the transactions have
	// been added.
	merkleRoot, _, err := ComputeMerkleRoot(blockRet.Txns)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "DeSoBlockProducer._getBlockTemplate: Problem computing merkle root: ")
	}
	blockRet.Header.TransactionMerkleRoot = merkleRoot

	// Compute the next difficulty target given the current tip.
	diffTarget, err := desoBlockProducer.chain.CalcNextDifficultyTarget(
		lastNode, CurrentHeaderVersion)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "DeSoBlockProducer._getBlockTemplate: Problem computing next difficulty: ")
	}

	glog.V(1).Infof("Produced block with %v txns with approx %v total txns in mempool",
		len(blockRet.Txns), len(desoBlockProducer.mempool.readOnlyUniversalTransactionList))
	return blockRet, diffTarget, lastNode, nil
}

func (desoBlockProducer *DeSoBlockProducer) Stop() {
	atomic.AddInt32(&desoBlockProducer.exit, 1)
	if atomic.LoadInt32(&desoBlockProducer.isAsleep) == 0 {
		desoBlockProducer.producerWaitGroup.Wait()
	}
}

func (desoBlockProducer *DeSoBlockProducer) GetRecentBlock(blockHash *BlockHash) *MsgDeSoBlock {
	// Find the block and quickly lock/unlock for reading.
	desoBlockProducer.mtxRecentBlockTemplatesProduced.RLock()
	defer desoBlockProducer.mtxRecentBlockTemplatesProduced.RUnlock()

	blockFound, exists := desoBlockProducer.recentBlockTemplatesProduced[*blockHash]
	if !exists {
		return nil
	}

	return blockFound
}

func (desoBlockProducer *DeSoBlockProducer) GetCopyOfRecentBlock(blockID string) (*MsgDeSoBlock, error) {
	blockHashBytes, err := hex.DecodeString(blockID)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	if len(blockHashBytes) != HashSizeBytes {
		return nil, fmt.Errorf("Invalid blockID. Length was %v but must "+
			"be %v", len(blockHashBytes), HashSizeBytes)
	}

	blockHash := &BlockHash{}
	copy(blockHash[:], blockHashBytes)

	blockFound := desoBlockProducer.GetRecentBlock(blockHash)
	if blockFound == nil {
		return nil, fmt.Errorf("Block with blockID %v not found "+
			"in BlockProducer", blockID)
	}

	blockFoundBytes, err := blockFound.ToBytes(false /*preSignature*/)
	if err != nil {
		return nil, fmt.Errorf("Error serializing block: %v", err)
	}

	newBlock := &MsgDeSoBlock{}
	err = newBlock.FromBytes(blockFoundBytes)
	if err != nil {
		return nil, fmt.Errorf("Error de-serializing block: %v", err)
	}

	return newBlock, nil
}

func (desoBlockProducer *DeSoBlockProducer) AddBlockTemplate(block *MsgDeSoBlock, diffTarget *BlockHash) {
	desoBlockProducer.mtxRecentBlockTemplatesProduced.Lock()
	defer desoBlockProducer.mtxRecentBlockTemplatesProduced.Unlock()

	hash, _ := block.Header.Hash()
	desoBlockProducer.recentBlockTemplatesProduced[*hash] = block
	desoBlockProducer.latestBlockTemplateHash = hash
	desoBlockProducer.currentDifficultyTarget = diffTarget

	// Evict entries if we're at capacity.
	for uint64(len(desoBlockProducer.recentBlockTemplatesProduced)) >
		desoBlockProducer.maxBlockTemplatesToCache {

		// TODO: We could be evicting things out of order if they both happen at the same
		// second. The fix is to use nanos rather than seconds but we're skipping the work
		// to do this for now since it doesn't really matter.
		minTstamp := uint32(math.MaxUint32)
		var oldestBlockHash *BlockHash
		for _, cachedBlock := range desoBlockProducer.recentBlockTemplatesProduced {
			if uint32(cachedBlock.Header.GetTstampSecs()) < minTstamp {
				minTstamp = uint32(cachedBlock.Header.GetTstampSecs())
				oldestBlockHash, _ = cachedBlock.Header.Hash()
			}
		}

		delete(desoBlockProducer.recentBlockTemplatesProduced, *oldestBlockHash)
	}
}

func RecomputeBlockRewardWithBlockRewardOutputPublicKey(
	block *MsgDeSoBlock,
	blockRewardOutputPublicKeyBytes []byte,
	params *DeSoParams,
) (*MsgDeSoBlock, error) {
	blockRewardOutputPublicKey := NewPublicKey(blockRewardOutputPublicKeyBytes)
	if blockRewardOutputPublicKey == nil {
		return nil,
			fmt.Errorf(
				"RecomputeBlockRewardWithBlockRewardOutpubPublicKey: Problem parsing block reward output public key: %v",
				blockRewardOutputPublicKeyBytes)
	}

	// Find all transactions in block that have transactor == block reward output public key
	// and sum fees to calculate the block reward
	totalFees := uint64(0)
	for _, txn := range block.Txns[1:] {
		if txn.TxnMeta.GetTxnType() != TxnTypeAtomicTxnsWrapper {
			transactorPublicKey := NewPublicKey(txn.PublicKey)
			if transactorPublicKey == nil {
				glog.Errorf("DeSoMiner._startThread: Error parsing transactor public key: %v", txn.PublicKey)
				continue
			}
			if transactorPublicKey.Equal(*blockRewardOutputPublicKey) {
				continue
			}
			var err error
			totalFees, err = SafeUint64().Add(totalFees, txn.TxnFeeNanos)
			if err != nil {
				glog.Errorf("DeSoMiner._startThread: Error adding txn fee: %v", err)
				continue
			}
		} else {
			txnMeta, ok := txn.TxnMeta.(*AtomicTxnsWrapperMetadata)
			if !ok {
				glog.Errorf("DeSoMiner._startThread: Error casting txn metadata to AtomicTxnsWrapperMetadata")
				continue
			}
			nonBlockRewardRecipientFees, err := filterOutBlockRewardRecipientFees(txnMeta.Txns, blockRewardOutputPublicKey)
			if err != nil {
				glog.Errorf("DeSoMiner._startThread: Error filtering out block reward recipient fees: %v", err)
				continue
			}
			totalFees, err = SafeUint64().Add(totalFees, nonBlockRewardRecipientFees)
			if err != nil {
				glog.Errorf("DeSoMiner._startThread: Error adding txn fee: %v", err)
				continue
			}
		}
	}
	block.Txns[0].TxOutputs[0].AmountNanos = CalcBlockRewardNanos(uint32(block.Header.Height), params) + totalFees
	return block, nil
}

func (blockProducer *DeSoBlockProducer) GetHeadersAndExtraDatas(
	publicKeyBytes []byte, numHeaders int64, headerVersion uint32) (
	_blockID string, _headers [][]byte, _extraNonces []uint64, _diffTarget *BlockHash, _err error) {

	// If we haven't computed the latest block template, then compute it now to bootstrap.
	if blockProducer.latestBlockTemplateHash == nil {
		// Use a dummy public key.
		currentBlockTemplate, diffTarget, _, err :=
			blockProducer._getBlockTemplate(MustBase58CheckDecode(ArchitectPubKeyBase58Check))
		if err != nil {
			return "", nil, nil, nil,
				fmt.Errorf("GetBlockTemplate: Problem computing first block template: %v", err)
		}

		blockProducer.AddBlockTemplate(currentBlockTemplate, diffTarget)
	}
	// BlockProducer.latestBlockTemplateHash should always be set at this point.

	// Get the latest block
	blockID := hex.EncodeToString(blockProducer.latestBlockTemplateHash[:])
	latestBLockCopy, err := blockProducer.GetCopyOfRecentBlock(blockID)
	if err != nil {
		return "", nil, nil, nil, errors.Wrap(
			fmt.Errorf("GetBlockTemplate: Problem getting latest block: %v", err), "")
	}

	// Swap out the public key in the block
	latestBLockCopy.Txns[0].TxOutputs[0].PublicKey = publicKeyBytes
	latestBLockCopy, err = RecomputeBlockRewardWithBlockRewardOutputPublicKey(
		latestBLockCopy, publicKeyBytes, blockProducer.params)
	if err != nil {
		return "", nil, nil, nil, errors.Wrap(
			fmt.Errorf("GetBlockTemplate: Problem recomputing block reward: %v", err), "")
	}
	headers := [][]byte{}
	extraNonces := []uint64{}

	// For each header the caller asked us for, compute an ExtraData nonce and a block header
	// using that nonced block reward.
	for ii := int64(0); ii < numHeaders; ii++ {
		// Set the version of the header
		latestBLockCopy.Header.Version = headerVersion

		extraNonce, err := wire.RandomUint64()
		if err != nil {
			return "", nil, nil, nil, errors.Wrap(
				fmt.Errorf("GetBlockTemplate: Error computing extraNonce: %v", err), "")
		}
		latestBLockCopy.Txns[0].TxnMeta.(*BlockRewardMetadataa).ExtraData = UintToBuf(extraNonce)

		// Compute the merkle root for the block now that all of the transactions have
		// been added.
		merkleRoot, _, err := ComputeMerkleRoot(latestBLockCopy.Txns)
		if err != nil {
			return "", nil, nil, nil, errors.Wrapf(
				err, "GetBlockTemplate: Problem computing merkle root: ")
		}

		// Set the merkle root in the header.
		latestBLockCopy.Header.TransactionMerkleRoot = merkleRoot

		headerBytes, err := latestBLockCopy.Header.ToBytes(false)
		if err != nil {
			return "", nil, nil, nil, errors.Wrapf(
				err, "GetBlockTemplate: Problem serializing header: ")
		}

		// If we get here then the header bytes and the ExtraNonce are good to go.
		headers = append(headers, headerBytes)
		extraNonces = append(extraNonces, extraNonce)
	}
	// At this point we have everything the miner needs so we should be good to go.

	return blockID, headers, extraNonces, blockProducer.currentDifficultyTarget, nil
}

func (desoBlockProducer *DeSoBlockProducer) UpdateLatestBlockTemplate() error {
	// Use a dummy public key.
	currentBlockTemplate, diffTarget, lastNode, err :=
		desoBlockProducer._getBlockTemplate(MustBase58CheckDecode(ArchitectPubKeyBase58Check))
	if err != nil {
		return err
	}

	// Log the results.
	glog.V(1).Infof("Produced block template with difficulty target %v "+
		"and lastNode %v", diffTarget, lastNode)

	desoBlockProducer.AddBlockTemplate(currentBlockTemplate, diffTarget)
	return nil
}

func (desoBlockProducer *DeSoBlockProducer) SignBlock(blockFound *MsgDeSoBlock) error {
	// If there's no private key on this BlockProducer then there's nothing to do.
	if desoBlockProducer.blockProducerPrivateKey == nil {
		return nil
	}

	// If there is a private key on this block producer then sign the block hash with it
	// and include the signature in the block.
	blockHash, err := blockFound.Header.Hash()
	if err != nil {
		return errors.Wrap(
			fmt.Errorf("Error computing block hash from header submitted: %v", err), "")
	}

	signature := ecdsa2.Sign(desoBlockProducer.blockProducerPrivateKey, blockHash[:])
	// If we get here, we now have a valid signature for the block.

	// Embed the signature into the block.
	blockFound.BlockProducerInfo = &BlockProducerInfo{
		PublicKey: desoBlockProducer.blockProducerPrivateKey.PubKey().SerializeCompressed(),
		Signature: signature,
	}

	return nil
}

func (desoBlockProducer *DeSoBlockProducer) Start() {
	// If we set up the max sync block height, we will not be running the block producer.
	glog.V(1).Infof("DeSoBlockProducer.Start() called. MaxSyncBlockHeight: %v",
		desoBlockProducer.chain.MaxSyncBlockHeight)
	if desoBlockProducer.chain.MaxSyncBlockHeight > 0 {
		glog.V(2).Infof("DeSoBlockProducer.Start() exiting because "+
			"MaxSyncBlockHeight: %v is greater than 0", desoBlockProducer.chain.MaxSyncBlockHeight)
		return
	}

	// Set the time to a nil value so we run on the first iteration of the loop.
	lastBlockUpdate := time.Now()
	desoBlockProducer.producerWaitGroup.Add(1)

	for {
		if atomic.LoadInt32(&desoBlockProducer.exit) > 0 {
			desoBlockProducer.producerWaitGroup.Done()
			glog.V(1).Infof("DeSoBlockProducer.Start() Are we returning in here?")
			return
		}

		// Stop the block producer if we're past the pos cutover or if the tip block is the last pow block.
		blockHeight := uint64(desoBlockProducer.chain.blockTip().Height)
		if blockHeight >= desoBlockProducer.params.GetFinalPoWBlockHeight() {
			desoBlockProducer.Stop()
			glog.V(1).Infof("DeSoBlockProducer.Start() Stopping block producer because we're past the PoS cutover" +
				" or the last PoW block.")
			return
		}

		secondsLeft := float64(desoBlockProducer.minBlockUpdateIntervalSeconds) - time.Since(lastBlockUpdate).Seconds()
		glog.V(1).Infof("DeSoBlockProducer.Start(): timings for next run: %v %v %v",
			float64(desoBlockProducer.minBlockUpdateIntervalSeconds), time.Since(lastBlockUpdate).Seconds(), secondsLeft)
		if !lastBlockUpdate.IsZero() && secondsLeft > 0 {
			glog.V(1).Infof("Sleeping for %v seconds before producing next block template...", secondsLeft)
			atomic.AddInt32(&desoBlockProducer.isAsleep, 1)
			time.Sleep(time.Duration(math.Ceil(secondsLeft)) * time.Second)
			atomic.AddInt32(&desoBlockProducer.isAsleep, -1)
			continue
		}

		// Update the time so start the clock for the next iteration.
		lastBlockUpdate = time.Now()

		glog.V(1).Infof("Producing block template...")
		err := desoBlockProducer.UpdateLatestBlockTemplate()
		if err != nil {
			// If we hit an error, log it and sleep for a second. This could happen due to us
			// being in the middle of processing a block or something.
			glog.Errorf("Error producing block template: %v", err)
			time.Sleep(time.Second)
		}
		glog.V(1).Infof("Block template produced successfully")
	}
}
