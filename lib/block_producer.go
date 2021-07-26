package lib

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"github.com/tyler-smith/go-bip39"
	"math"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/sasha-s/go-deadlock"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

type BitCloutBlockProducer struct {
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
	recentBlockTemplatesProduced map[BlockHash]*MsgBitCloutBlock
	latestBlockTemplateHash      *BlockHash
	currentDifficultyTarget      *BlockHash

	latestBlockTemplateStats *BlockTemplateStats

	mempool        *BitCloutMempool
	chain          *Blockchain
	bitcoinManager *BitcoinManager
	params         *BitCloutParams

	producerWaitGroup   sync.WaitGroup
	stopProducerChannel chan struct{}
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

func NewBitCloutBlockProducer(
	_minBlockUpdateIntervalSeconds uint64, _maxBlockTemplatesToCache uint64,
	_blockProducerSeed string,
	_mempool *BitCloutMempool, _chain *Blockchain, _bitcoinManager *BitcoinManager,
	_params *BitCloutParams) (*BitCloutBlockProducer, error) {

	var _privKey *btcec.PrivateKey
	if _blockProducerSeed != "" {
		seedBytes, err := bip39.NewSeedWithErrorChecking(_blockProducerSeed, "")
		if err != nil {
			return nil, fmt.Errorf("NewBitCloutBlockProducer: Error converting mnemonic: %+v", err)
		}

		_, _privKey, _, err = ComputeKeysFromSeed(seedBytes, 0, _params)
		if err != nil {
			return nil, fmt.Errorf(
				"NewBitCloutBlockProducer: Error computing keys from seed: %+v", err)
		}
	}

	return &BitCloutBlockProducer{
		minBlockUpdateIntervalSeconds: _minBlockUpdateIntervalSeconds,
		maxBlockTemplatesToCache:      _maxBlockTemplatesToCache,
		blockProducerPrivateKey:       _privKey,
		recentBlockTemplatesProduced:  make(map[BlockHash]*MsgBitCloutBlock),

		mempool:             _mempool,
		chain:               _chain,
		bitcoinManager:      _bitcoinManager,
		params:              _params,
		stopProducerChannel: make(chan struct{}),
	}, nil
}

func (bbp *BitCloutBlockProducer) GetLatestBlockTemplateStats() *BlockTemplateStats {
	return bbp.latestBlockTemplateStats
}

func (bitcloutBlockProducer *BitCloutBlockProducer) _updateBlockTimestamp(blk *MsgBitCloutBlock, lastNode *BlockNode) {
	// Set the block's timestamp. If the timesource's time happens to be before
	// the timestamp set in the last block then set the time based on the last
	// block's timestamp instead. We do this because consensus rules require a
	// monotonically increasing timestamp.
	blockTstamp := uint32(bitcloutBlockProducer.chain.timeSource.AdjustedTime().Unix())
	if blockTstamp <= uint32(lastNode.Header.TstampSecs) {
		blockTstamp = uint32(lastNode.Header.TstampSecs) + 1
	}
	blk.Header.TstampSecs = uint64(blockTstamp)
}

func (bitcloutBlockProducer *BitCloutBlockProducer) _getBlockTemplate(publicKey []byte) (
	_blk *MsgBitCloutBlock, _diffTarget *BlockHash, _lastNode *BlockNode, _err error) {

	// Get the current tip of the best block chain. Note that using the tip of the
	// best block chain as opposed to the best header chain means we'll be mining
	// stale blocks until we're fully synced. This isn't ideal, but is currently
	// preferred to mining atop the best header chain because the latter currently results
	// in the blocks being rejected as unconnectedTxns before the block tip is in-sync.
	lastNode := bitcloutBlockProducer.chain.blockTip()

	// Compute the public key to contribute the reward to.
	rewardPk, err := btcec.ParsePubKey(publicKey, btcec.S256())
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "BitCloutBlockProducer._getBlockTemplate: ")
	}

	// Construct the next block.
	blockRewardOutput := &BitCloutOutput{}
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
	blockRewardTxn := NewMessage(MsgTypeTxn).(*MsgBitCloutTxn)
	blockRewardTxn.TxOutputs = append(blockRewardTxn.TxOutputs, blockRewardOutput)
	// Set the ExtraData to zero. This gives miners something they can
	// twiddle if they run out of space on their actual nonce.
	blockRewardTxn.TxnMeta = &BlockRewardMetadataa{
		ExtraData: UintToBuf(0),
	}

	// Create the block and add the BlockReward txn to it.
	blockRet := NewMessage(MsgTypeBlock).(*MsgBitCloutBlock)
	blockRet.Txns = append(blockRet.Txns, blockRewardTxn)
	// The version may be swapped out in a call to GetBlockTemplate in order to remain
	// backwards-compatible with existing miners that use an older version.
	blockRet.Header.Version = CurrentHeaderVersion
	blockRet.Header.Height = uint64(lastNode.Height + 1)
	blockRet.Header.PrevBlockHash = lastNode.Hash
	bitcloutBlockProducer._updateBlockTimestamp(blockRet, lastNode)
	// Start the nonce at zero. This is OK because we'll set a random ExtraData for the
	// miner later.
	blockRet.Header.Nonce = 0

	// Only add transactions to the block if our chain is done syncing.
	if bitcloutBlockProducer.chain.chainState() != SyncStateSyncingHeaders &&
		bitcloutBlockProducer.chain.chainState() != SyncStateNeedBlocksss {

		// Fetch a bunch of mempool transactions to add.
		txnsOrderedByTimeAdded, _, err := bitcloutBlockProducer.mempool.GetTransactionsOrderedByTimeAdded()
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "BitCloutBlockProducer._getBlockTemplate: Problem getting mempool transactions: ")
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
			return nil, nil, nil, errors.Wrapf(err, "BitCloutBlockProducer._getBlockTemplate: Problem serializing block: ")
		}
		currentBlockSize := uint64(len(blockBytes) + MaxVarintLen64)

		// Create a new view object.
		utxoView, err := NewUtxoView(
			bitcloutBlockProducer.chain.db, bitcloutBlockProducer.params, bitcloutBlockProducer.bitcoinManager)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err,
				"BitCloutBlockProducer._getBlockTemplate: Error generating checker UtxoView: ")
		}

		txnsAddedToBlock := make(map[BlockHash]bool)
		for ii, mempoolTx := range txnsOrderedByTimeAdded {
			// If we hit a transaction that's too big to fit into a block then we're done.
			if mempoolTx.TxSizeBytes+currentBlockSize > bitcloutBlockProducer.params.MinerMaxBlockSizeBytes {
				break
			}

			// Try to apply the transaction to the view with the strictest possible checks.
			_, _, _, _, err := utxoView._connectTransaction(
				mempoolTx.Tx, mempoolTx.Hash, int64(mempoolTx.TxSizeBytes), uint32(blockRet.Header.Height), true,
				true, /*checkMerkleProof*/
				bitcloutBlockProducer.params.MinerBitcoinMinBurnWorkBlockss,
				false /*ignoreUtxos*/)
			if err != nil {
				// If we fail to apply this transaction then we're done. Don't mine any of the
				// other transactions since they could be dependent on this one.
				txnErrorString := fmt.Sprintf(
					"BitCloutBlockProducer._getBlockTemplate: Stopping at txn %v because it's not ready yet: %v", ii, err)
				glog.Infof(txnErrorString)
				if mempoolTx.Tx.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
					// Print the Bitcoin block hash when we break out due to this.
					btcErrorString := fmt.Sprintf("A bad BitcoinExchange transaction may be holding "+
						"up block production: %v, Current header tip: %v",
						mempoolTx.Tx.TxnMeta.(*BitcoinExchangeMetadata).BitcoinTransaction.TxHash(),
						bitcloutBlockProducer.bitcoinManager.HeaderTip().Hash)
					glog.Infof(btcErrorString)
					txnErrorString += (" " + btcErrorString)
					scs := spew.ConfigState{DisableMethods: true, Indent: "  "}
					glog.Debugf("Spewing Bitcoin txn: %v", scs.Sdump(mempoolTx.Tx))
				}

				// Update the block template stats for the admin dashboard.
				failingTxnHash := mempoolTx.Hash.String()
				failingTxnOriginalTimeAdded := mempoolTx.Added
				if bitcloutBlockProducer.latestBlockTemplateStats != nil &&
					bitcloutBlockProducer.latestBlockTemplateStats.FailingTxnHash == failingTxnHash {
					// If we already have the txn stored, update the error message in case it changed
					// and set the originalTimeAdded variable to compute an accurate staleness metric.
					bitcloutBlockProducer.latestBlockTemplateStats.FailingTxnError = txnErrorString
					failingTxnOriginalTimeAdded = bitcloutBlockProducer.latestBlockTemplateStats.FailingTxnOriginalTimeAdded
				} else {
					// If we haven't seen this txn before, build the block template stats from scratch.
					blockTemplateStats := &BlockTemplateStats{}
					blockTemplateStats.FailingTxnHash = mempoolTx.Hash.String()
					blockTemplateStats.TxnCount = uint32(ii)
					blockTemplateStats.FailingTxnError = txnErrorString
					blockTemplateStats.FailingTxnOriginalTimeAdded = failingTxnOriginalTimeAdded
					bitcloutBlockProducer.latestBlockTemplateStats = blockTemplateStats
				}
				// Compute the time since this txn started holding up the mempool.
				currentTime := time.Now()
				timeElapsed := currentTime.Sub(failingTxnOriginalTimeAdded)
				bitcloutBlockProducer.latestBlockTemplateStats.FailingTxnMinutesSinceAdded = timeElapsed.Minutes()

				break
			} else if bitcloutBlockProducer.latestBlockTemplateStats != nil {
				bitcloutBlockProducer.latestBlockTemplateStats.FailingTxnError = "You good"
				bitcloutBlockProducer.latestBlockTemplateStats.FailingTxnHash = "Nada"
				bitcloutBlockProducer.latestBlockTemplateStats.FailingTxnMinutesSinceAdded = 0
				bitcloutBlockProducer.latestBlockTemplateStats.FailingTxnOriginalTimeAdded = time.Now()
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
			return nil, nil, nil, errors.Wrapf(err, "BitCloutBlockProducer._getBlockTemplate: Problem serializing block after txns added: ")
		}
		if uint64(len(blockBytes)) > bitcloutBlockProducer.params.MinerMaxBlockSizeBytes {
			return nil, nil, nil, fmt.Errorf("BitCloutBlockProducer._getBlockTemplate: Block created with size "+
				"(%d) exceeds BlockProducerMaxBlockSizeBytes (%d): ", len(blockBytes), bitcloutBlockProducer.params.MinerMaxBlockSizeBytes)
		}
	}

	// Compute the total fee the BlockProducer should get.
	totalFeeNanos := uint64(0)
	feesUtxoView, err := NewUtxoView(bitcloutBlockProducer.chain.db, bitcloutBlockProducer.params, bitcloutBlockProducer.bitcoinManager)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"BitCloutBlockProducer._getBlockTemplate: Error generating UtxoView to compute txn fees: %v", err)
	}
	// Skip the block reward, which is the first txn in the block.
	for _, txnInBlock := range blockRet.Txns[1:] {
		var feeNanos uint64
		_, _, _, feeNanos, err = feesUtxoView._connectTransaction(
			txnInBlock, txnInBlock.Hash(), 0, uint32(blockRet.Header.Height), false, /*verifySignatures*/
			false, /*checkMerkleProof*/
			0, false /*ignoreUtxos*/)
		if err != nil {
			return nil, nil, nil, fmt.Errorf(
				"BitCloutBlockProducer._getBlockTemplate: Error attaching txn to UtxoView for computed block: %v", err)
		}

		// Add the fee to the block reward output as we go. Note this has some risk of
		// increasing the size of the block by one byte, but it seems like this is an
		// extreme edge case that goes away as soon as the function is called again.
		totalFeeNanos += feeNanos
	}

	// Now that the total fees have been computed, set the value of the block reward
	// output.
	blockRewardOutput.AmountNanos = CalcBlockRewardNanos(uint32(blockRet.Header.Height)) + totalFeeNanos

	// Compute the merkle root for the block now that all of the transactions have
	// been added.
	merkleRoot, _, err := ComputeMerkleRoot(blockRet.Txns)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "BitCloutBlockProducer._getBlockTemplate: Problem computing merkle root: ")
	}
	blockRet.Header.TransactionMerkleRoot = merkleRoot

	// Compute the next difficulty target given the current tip.
	diffTarget, err := CalcNextDifficultyTarget(
		lastNode, CurrentHeaderVersion, bitcloutBlockProducer.params)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "BitCloutBlockProducer._getBlockTemplate: Problem computing next difficulty: ")
	}

	glog.Infof("Produced block with %v txns with approx %v total txns in mempool",
		len(blockRet.Txns), len(bitcloutBlockProducer.mempool.readOnlyUniversalTransactionList))
	return blockRet, diffTarget, lastNode, nil
}

func (bitcloutBlockProducer *BitCloutBlockProducer) Stop() {
	bitcloutBlockProducer.stopProducerChannel <- struct{}{}
	bitcloutBlockProducer.producerWaitGroup.Wait()
}

func (bitcloutBlockProducer *BitCloutBlockProducer) GetRecentBlock(blockHash *BlockHash) *MsgBitCloutBlock {
	// Find the block and quickly lock/unlock for reading.
	bitcloutBlockProducer.mtxRecentBlockTemplatesProduced.RLock()
	defer bitcloutBlockProducer.mtxRecentBlockTemplatesProduced.RUnlock()

	blockFound, exists := bitcloutBlockProducer.recentBlockTemplatesProduced[*blockHash]
	if !exists {
		return nil
	}

	return blockFound
}

func (bitcloutBlockProducer *BitCloutBlockProducer) GetCopyOfRecentBlock(blockID string) (*MsgBitCloutBlock, error) {
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

	blockFound := bitcloutBlockProducer.GetRecentBlock(blockHash)
	if blockFound == nil {
		return nil, fmt.Errorf("Block with blockID %v not found "+
			"in BlockProducer", blockID)
	}

	blockFoundBytes, err := blockFound.ToBytes(false /*preSignature*/)
	if err != nil {
		return nil, fmt.Errorf("Error serializing block: %v", err)
	}

	newBlock := &MsgBitCloutBlock{}
	err = newBlock.FromBytes(blockFoundBytes)
	if err != nil {
		return nil, fmt.Errorf("Error de-serializing block: %v", err)
	}

	return newBlock, nil
}

func (bitcloutBlockProducer *BitCloutBlockProducer) AddBlockTemplate(block *MsgBitCloutBlock, diffTarget *BlockHash) {
	bitcloutBlockProducer.mtxRecentBlockTemplatesProduced.Lock()
	defer bitcloutBlockProducer.mtxRecentBlockTemplatesProduced.Unlock()

	hash, _ := block.Header.Hash()
	bitcloutBlockProducer.recentBlockTemplatesProduced[*hash] = block
	bitcloutBlockProducer.latestBlockTemplateHash = hash
	bitcloutBlockProducer.currentDifficultyTarget = diffTarget

	// Evict entries if we're at capacity.
	for uint64(len(bitcloutBlockProducer.recentBlockTemplatesProduced)) >
		bitcloutBlockProducer.maxBlockTemplatesToCache {

		// TODO: We could be evicting things out of order if they both happen at the same
		// second. The fix is to use nanos rather than seconds but we're skipping the work
		// to do this for now since it doesn't really matter.
		minTstamp := uint32(math.MaxUint32)
		var oldestBlockHash *BlockHash
		for _, cachedBlock := range bitcloutBlockProducer.recentBlockTemplatesProduced {
			if uint32(cachedBlock.Header.TstampSecs) < minTstamp {
				minTstamp = uint32(cachedBlock.Header.TstampSecs)
				oldestBlockHash, _ = cachedBlock.Header.Hash()
			}
		}

		delete(bitcloutBlockProducer.recentBlockTemplatesProduced, *oldestBlockHash)
	}
}

func (blockProducer *BitCloutBlockProducer) GetHeadersAndExtraDatas(
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

func (bitcloutBlockProducer *BitCloutBlockProducer) UpdateLatestBlockTemplate() error {
	// Use a dummy public key.
	currentBlockTemplate, diffTarget, lastNode, err :=
		bitcloutBlockProducer._getBlockTemplate(MustBase58CheckDecode(ArchitectPubKeyBase58Check))
	if err != nil {
		return err
	}

	// Log the results.
	glog.Debugf("Produced block template with difficulty target %v "+
		"and lastNode %v", diffTarget, lastNode)

	bitcloutBlockProducer.AddBlockTemplate(currentBlockTemplate, diffTarget)
	return nil
}

func (bitcloutBlockProducer *BitCloutBlockProducer) SignBlock(blockFound *MsgBitCloutBlock) error {
	// If there's no private key on this BlockProducer then there's nothing to do.
	if bitcloutBlockProducer.blockProducerPrivateKey == nil {
		return nil
	}

	// If there is a private key on this block producer then sign the block hash with it
	// and include the signature in the block.
	blockHash, err := blockFound.Header.Hash()
	if err != nil {
		return errors.Wrap(
			fmt.Errorf("Error computing block hash from header submitted: %v", err), "")
	}

	signature, err := bitcloutBlockProducer.blockProducerPrivateKey.Sign(blockHash[:])
	if err != nil {
		return errors.Wrap(
			fmt.Errorf("Error signing block: %v", err), "")
	}
	// If we get here, we now have a valid signature for the block.

	// Embed the signature into the block.
	blockFound.BlockProducerInfo = &BlockProducerInfo{
		PublicKey: bitcloutBlockProducer.blockProducerPrivateKey.PubKey().SerializeCompressed(),
		Signature: signature,
	}

	return nil
}

func (bitcloutBlockProducer *BitCloutBlockProducer) Start() {

	for {
		// If we have a bitcoinManager set, wait for it to become time-current before
		// producing blocks. We don't wait for it to become work-current because worst-case
		// the BitcoinManager will reset its underlying chain, causing us to produce
		// stale blocks for a bit.
		if bitcloutBlockProducer.bitcoinManager != nil && !bitcloutBlockProducer.bitcoinManager.IsCurrent(false /*considerCumWork*/) {
			glog.Info("Waiting for BitcoinManager to become time-current before producing blocks...")
			time.Sleep(1 * time.Second)
			continue
		}

		glog.Info("BitcoinManager is time-current; proceeding with producing blocks!")
		break
	}

	// Set the time to a nil value so we run on the first iteration of the loop.
	var lastBlockUpdate time.Time
	bitcloutBlockProducer.producerWaitGroup.Add(1)

	for {
		select {
		case <-bitcloutBlockProducer.stopProducerChannel:
			bitcloutBlockProducer.producerWaitGroup.Done()
			return
		default:
			secondsLeft := float64(bitcloutBlockProducer.minBlockUpdateIntervalSeconds) - time.Since(lastBlockUpdate).Seconds()
			if !lastBlockUpdate.IsZero() && secondsLeft > 0 {
				glog.Debugf("Sleeping for %v seconds before producing next block template...", secondsLeft)
				time.Sleep(time.Duration(math.Ceil(secondsLeft)) * time.Second)
				continue
			}

			// Update the time so start the clock for the next iteration.
			lastBlockUpdate = time.Now()

			glog.Debugf("Producing block template...")
			err := bitcloutBlockProducer.UpdateLatestBlockTemplate()
			if err != nil {
				// If we hit an error, log it and sleep for a second. This could happen due to us
				// being in the middle of processing a block or something.
				glog.Errorf("Error producing block template: %v", err)
				time.Sleep(time.Second)
				continue
			}

		}
	}
}
