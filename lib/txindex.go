package lib

import (
	"encoding/hex"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/deso-protocol/go-deadlock"
	"github.com/golang/glog"
)

type TXIndex struct {
	// TXIndexLock protects the transaction index.
	TXIndexLock deadlock.RWMutex

	// The txindex has it s own separate Blockchain object. This allows us to
	// capture more metadata when collecting transactions without interfering
	// with the goings-on of the main chain.
	TXIndexChain *Blockchain

	// Core objects from Server
	CoreChain *Blockchain

	// Core params object
	Params *DeSoParams

	// Update wait group
	updateWaitGroup sync.WaitGroup

	// Shutdown channel
	stopUpdateChannel chan struct{}
}

func NewTXIndex(coreChain *Blockchain, params *DeSoParams, dataDirectory string) (
	_txindex *TXIndex, _error error) {
	// Initialize database
	txIndexDir := filepath.Join(GetBadgerDbPath(dataDirectory), "txindex")
	txIndexOpts := PerformanceBadgerOptions(txIndexDir)
	txIndexOpts.ValueDir = GetBadgerDbPath(txIndexDir)
	glog.Infof("TxIndex BadgerDB Dir: %v", txIndexOpts.Dir)
	glog.Infof("TxIndex BadgerDB ValueDir: %v", txIndexOpts.ValueDir)
	txIndexDb, err := badger.Open(txIndexOpts)
	if err != nil {
		glog.Fatal(err)
	}

	// See if we have a best chain hash stored in the txindex db.
	bestBlockHashBeforeInit := DbGetBestHash(txIndexDb, nil, ChainTypeDeSoBlock)

	// If we haven't initialized the txIndexChain before, set up the
	// seed mappings.
	if bestBlockHashBeforeInit == nil {
		{
			dummyPk := ArchitectPubKeyBase58Check
			dummyTxn := &MsgDeSoTxn{
				TxInputs:  []*DeSoInput{},
				TxOutputs: params.SeedBalances,
				TxnMeta:   &BlockRewardMetadataa{},
				PublicKey: MustBase58CheckDecode(dummyPk),
			}
			affectedPublicKeys := []*AffectedPublicKey{}
			totalOutput := uint64(0)
			for _, seedBal := range params.SeedBalances {
				affectedPublicKeys = append(affectedPublicKeys, &AffectedPublicKey{
					PublicKeyBase58Check: PkToString(seedBal.PublicKey, params),
					Metadata:             "GenesisBlockSeedBalance",
				})
				totalOutput += seedBal.AmountNanos
			}
			err := DbPutTxindexTransactionMappings(txIndexDb, nil, 0, dummyTxn, params, &TransactionMetadata{
				TransactorPublicKeyBase58Check: dummyPk,
				AffectedPublicKeys:             affectedPublicKeys,
				BlockHashHex:                   GenesisBlockHashHex,
				TxnIndexInBlock:                uint64(0),
				// Just set some dummy metadata
				BasicTransferTxindexMetadata: &BasicTransferTxindexMetadata{
					TotalInputNanos:  0,
					TotalOutputNanos: totalOutput,
					FeeNanos:         0,
				},
			})
			if err != nil {
				return nil, fmt.Errorf("NewTXIndex: Error initializing seed balances in txindex: %v", err)
			}
		}

		// Add the other seed txns to the txn index.
		for txnIndex, txnHex := range params.SeedTxns {
			txnBytes, err := hex.DecodeString(txnHex)
			if err != nil {
				return nil, fmt.Errorf("NewTXIndex: Error decoding seed txn HEX: %v, txn index: %v, txn hex: %v", err, txnIndex, txnHex)
			}
			txn := &MsgDeSoTxn{}
			if err := txn.FromBytes(txnBytes); err != nil {
				return nil, fmt.Errorf("NewTXIndex: Error decoding seed txn BYTES: %v, txn index: %v, txn hex: %v", err, txnIndex, txnHex)
			}
			err = DbPutTxindexTransactionMappings(txIndexDb, nil, 0, txn, params, &TransactionMetadata{
				TransactorPublicKeyBase58Check: PkToString(txn.PublicKey, params),
				// Note that we don't set AffectedPublicKeys for the SeedTxns
				BlockHashHex:    GenesisBlockHashHex,
				TxnIndexInBlock: uint64(0),
				// Just set some dummy metadata
				BasicTransferTxindexMetadata: &BasicTransferTxindexMetadata{
					TotalInputNanos:  0,
					TotalOutputNanos: 0,
					FeeNanos:         0,
				},
			})
			if err != nil {
				return nil, fmt.Errorf("NewTXIndex: Error initializing seed txn %v in txindex: %v", txn, err)
			}
		}
	}

	// Ignore all the notifications from the txindex blockchain object
	txIndexBlockchainNotificationChan := make(chan *ServerMessage, 1000)
	go func() {
		for {
			<-txIndexBlockchainNotificationChan
		}
	}()

	// Note that we *DONT* pass server here because it is already tied to the main blockchain.
	txIndexChain, err := NewBlockchain(
		[]string{}, 0, coreChain.MaxSyncBlockHeight, params, chainlib.NewMedianTime(),
		txIndexDb, nil, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("NewTXIndex: Error initializing TxIndex: %v", err)
	}

	// At this point, we should have set up a blockchain object for our
	// txindex, and initialized all of the seed txns and seed balances
	// correctly. Attaching blocks to our txnindex blockchain or adding
	// txns to our txindex should work smoothly now.

	return &TXIndex{
		TXIndexChain:      txIndexChain,
		CoreChain:         coreChain,
		Params:            params,
		stopUpdateChannel: make(chan struct{}),
	}, nil
}

func (txi *TXIndex) FinishedSyncing() bool {
	return txi.TXIndexChain.BlockTip().Height == txi.CoreChain.BlockTip().Height
}

func (txi *TXIndex) Start() {
	glog.Info("TXIndex: Starting update thread")

	// Run a loop to continuously update the txindex. Note that this is a noop
	// except when run the first time or when a new block has arrived.
	go func() {
		txi.updateWaitGroup.Add(1)

		for {
			select {
			case <-txi.stopUpdateChannel:
				txi.updateWaitGroup.Done()
				return
			default:
				if txi.CoreChain.ChainState() == SyncStateFullyCurrent {
					if !txi.CoreChain.IsFullyStored() {
						glog.V(1).Infof("TXIndex: Waiting, blockchain is not fully stored")
						break
					}
					// If the node is fully synced, then try an update.
					err := txi.Update()
					if err != nil {
						glog.Error(fmt.Errorf("tryUpdateTxindex: Problem running update: %v", err))
					}
				} else {
					glog.V(1).Infof("TXIndex: Waiting for node to sync before updating")
				}
				break
			}

			time.Sleep(1 * time.Second)
		}
	}()
}

// Stop TXIndex node. This method doesn't close the txindex db, make sure to call in the parent context:
// 	txi.TXIndexChain.DB().Close()
// It's important!!! Do it after the txi.updateWaitGroup.Wait().
func (txi *TXIndex) Stop() {
	glog.Info("TXIndex: Stopping updates and closing database")

	txi.stopUpdateChannel <- struct{}{}
	txi.updateWaitGroup.Wait()
}

// GetTxindexUpdateBlockNodes ...
func (txi *TXIndex) GetTxindexUpdateBlockNodes() (
	_txindexTipNode *BlockNode, _blockTipNode *BlockNode, _commonAncestor *BlockNode,
	_detachBlocks []*BlockNode, _attachBlocks []*BlockNode) {

	// Get the current txindex tip.
	txindexTipHash := txi.TXIndexChain.BlockTip()
	if txindexTipHash == nil {
		// The tip hash should never be nil since the txindex chain should have
		// been initialized in the constructor. Print an error and return in this
		// case.
		glog.Error("Error: TXIndexChain had nil tip; this should never " +
			"happen and it means the transaction index is broken.")
		return nil, nil, nil, nil, nil
	}
	// If the tip of the txindex is no longer stored in the block index, it
	// means the txindex hit a fork that we are no longer keeping track of.
	// The only thing we can really do in this case is rebuild the entire index
	// from scratch. To do that, we return all the blocks in the index to detach
	// and all the blocks in the real chain to attach.
	txindexTipNode := txi.CoreChain.CopyBlockIndex()[*txindexTipHash.Hash]

	if txindexTipNode == nil {
		glog.Info("GetTxindexUpdateBlockNodes: Txindex tip was not found; building txindex starting at genesis block")

		newTxIndexBestChain, _ := txi.TXIndexChain.CopyBestChain()
		newBlockchainBestChain, _ := txi.CoreChain.CopyBestChain()

		return txindexTipNode, txi.CoreChain.BlockTip(), nil, newTxIndexBestChain, newBlockchainBestChain
	}

	// At this point, we know our txindex tip is in our block index so
	// there must be a common ancestor between the tip and the block tip.
	blockTip := txi.CoreChain.BlockTip()
	commonAncestor, detachBlocks, attachBlocks := GetReorgBlocks(txindexTipNode, blockTip)

	return txindexTipNode, blockTip, commonAncestor, detachBlocks, attachBlocks
}

// Update syncs the transaction index with the blockchain.
// Specifically, it reads in all the blocks that have come in since the last
// time this function was called and adds the new transactions to the txindex.
// It also handles reorgs properly.
//
// TODO(DELETEME, cleanup): This code is error-prone. Moving the transaction indexing code
// to block_view.go may be a clean way to refactor this.
func (txi *TXIndex) Update() error {
	// If we don't have a chain set, return an error.
	if txi.TXIndexChain == nil {
		return fmt.Errorf("Update: Missing TXIndexChain")
	}

	// Lock the txindex and the blockchain for reading until we're
	// done with the rest of the function.
	txi.TXIndexLock.Lock()
	defer txi.TXIndexLock.Unlock()
	txindexTipNode, blockTipNode, commonAncestor, detachBlocks, attachBlocks := txi.GetTxindexUpdateBlockNodes()

	// Note that the blockchain's ChainLock does not need to be held at this
	// point because we're just reading blocks from the db, which never get
	// deleted and therefore don't need the lock in order to access.

	// If we get to this point, the commonAncestor should never be nil.
	if commonAncestor == nil {
		return fmt.Errorf("Update: Expected common ancestor "+
			"between txindex tip %v and block tip %v but found none; this "+
			"should never happen", txindexTipNode, blockTipNode)
	}
	// If the tip of the txindex is the same as the block tip, don't do
	// an update.
	if reflect.DeepEqual(txindexTipNode.Hash[:], blockTipNode.Hash[:]) {
		glog.V(1).Infof("Update: Skipping update since block tip equals "+
			"txindex tip: Height: %d, Hash: %v", txindexTipNode.Height, txindexTipNode.Hash)
		return nil
	}

	// When the txindex tip does not match the block tip then there's work
	// to do. Log at the info level.
	glog.Infof("Update: Updating txindex tip (height: %d, hash: %v) "+
		"to block tip (height: %d, hash: %v) ...",
		txindexTipNode.Height, txindexTipNode.Hash,
		blockTipNode.Height, blockTipNode.Hash)

	// For each of the blocks we're removing, delete the transactions from
	// the transaction index.
	for _, blockToDetach := range detachBlocks {
		// Go through each txn in the block and delete its mappings from our
		// txindex.
		glog.V(1).Infof("Update: Detaching block (height: %d, hash: %v)",
			blockToDetach.Height, blockToDetach.Hash)
		blockMsg, err := GetBlock(blockToDetach.Hash, txi.TXIndexChain.DB(), nil)
		if err != nil {
			return fmt.Errorf("Update: Problem fetching detach block "+
				"with hash %v: %v", blockToDetach.Hash, err)
		}
		blockHeight := uint64(txi.CoreChain.blockTip().Height)
		err = txi.TXIndexChain.DB().Update(func(dbTxn *badger.Txn) error {
			for _, txn := range blockMsg.Txns {
				if err := DbDeleteTxindexTransactionMappingsWithTxn(dbTxn, nil,
					blockHeight, txn, txi.Params); err != nil {

					return fmt.Errorf("Update: Problem deleting "+
						"transaction mappings for transaction %v: %v", txn.Hash(), err)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Now that all the transactions have been deleted from our txindex,
		// it's safe to disconnect the block from our txindex chain.
		utxoView, err := NewUtxoView(txi.TXIndexChain.DB(), txi.Params, nil, nil)
		if err != nil {
			return fmt.Errorf(
				"Update: Error initializing UtxoView: %v", err)
		}
		utxoOps, err := GetUtxoOperationsForBlock(
			txi.TXIndexChain.DB(), nil, blockToDetach.Hash)
		if err != nil {
			return fmt.Errorf(
				"Update: Error getting UtxoOps for block %v: %v", blockToDetach, err)
		}
		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(blockMsg.Txns)
		if err != nil {
			return fmt.Errorf(
				"Update: Error computing tx hashes for block %v: %v",
				blockToDetach, err)
		}
		if err := utxoView.DisconnectBlock(blockMsg, txHashes, utxoOps, blockHeight); err != nil {
			return fmt.Errorf("Update: Error detaching block "+
				"%v from UtxoView: %v", blockToDetach, err)
		}
		if err := utxoView.FlushToDb(blockHeight); err != nil {
			return fmt.Errorf("Update: Error flushing view to db for block "+
				"%v: %v", blockToDetach, err)
		}
		// We have to flush a couple of extra things that the view doesn't flush...
		if err := PutBestHash(txi.TXIndexChain.DB(), nil, utxoView.TipHash, ChainTypeDeSoBlock); err != nil {
			return fmt.Errorf("Update: Error putting best hash for block "+
				"%v: %v", blockToDetach, err)
		}
		err = txi.TXIndexChain.DB().Update(func(txn *badger.Txn) error {
			if err := DeleteUtxoOperationsForBlockWithTxn(txn, nil, blockToDetach.Hash); err != nil {
				return fmt.Errorf("Update: Error deleting UtxoOperations 1 for block %v, %v", blockToDetach.Hash, err)
			}
			if err := txn.Delete(BlockHashToBlockKey(blockToDetach.Hash)); err != nil {
				return fmt.Errorf("Update: Error deleting UtxoOperations 2 for block %v %v", blockToDetach.Hash, err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("Update: Error updating badgger: %v", err)
		}
		// Delete this block from the chain db so we don't get duplicate block errors.

		// Remove this block from our bestChain data structures.
		newBlockIndex := txi.TXIndexChain.CopyBlockIndex()
		newBestChain, newBestChainMap := txi.TXIndexChain.CopyBestChain()
		newBestChain = newBestChain[:len(newBestChain)-1]
		delete(newBestChainMap, *(blockToDetach.Hash))
		delete(newBlockIndex, *(blockToDetach.Hash))

		txi.TXIndexChain.SetBestChainMap(newBestChain, newBestChainMap, newBlockIndex)

		// At this point the entries for the block should have been removed
		// from both our Txindex chain and our transaction index mappings.
	}

	// For each of the blocks we're adding, process them on our txindex chain
	// and add their mappings to our txn index. Compute any metadata that might
	// be useful.
	for _, blockToAttach := range attachBlocks {
		if blockToAttach.Height%1 == 0 {
			glog.Infof("Update: Txindex progress: block %d / %d",
				blockToAttach.Height, blockTipNode.Height)
		}
		glog.V(2).Infof("Update: Attaching block (height: %d, hash: %v)",
			blockToAttach.Height, blockToAttach.Hash)

		blockMsg, err := GetBlock(blockToAttach.Hash, txi.CoreChain.DB(), nil)
		if err != nil {
			return fmt.Errorf("Update: Problem fetching attach block "+
				"with hash %v: %v", blockToAttach.Hash, err)
		}

		// We use a view to simulate adding transactions to our chain. This allows
		// us to extract custom metadata fields that we can show in our block explorer.
		//
		// Only set a BitcoinManager if we have one. This makes some tests pass.
		utxoView, err := NewUtxoView(txi.TXIndexChain.DB(), txi.Params, nil, nil)
		if err != nil {
			return fmt.Errorf(
				"Update: Error initializing UtxoView: %v", err)
		}

		// Do each block update in a single transaction so we're safe in case the node
		// restarts.
		blockHeight := uint64(txi.CoreChain.BlockTip().Height)
		err = txi.TXIndexChain.DB().Update(func(dbTxn *badger.Txn) error {

			// Iterate through each transaction in the block and do the following:
			// - Connect it to the view
			// - Compute its mapping values, which may include custom metadata fields
			// - add all its mappings to the db.
			for txnIndexInBlock, txn := range blockMsg.Txns {
				txnMeta, err := ConnectTxnAndComputeTransactionMetadata(
					txn, utxoView, blockToAttach.Hash, blockToAttach.Height, uint64(txnIndexInBlock))
				if err != nil {
					return fmt.Errorf("Update: Problem connecting txn %v to txindex: %v",
						txn, err)
				}

				err = DbPutTxindexTransactionMappingsWithTxn(dbTxn, nil, blockHeight,
					txn, txi.Params, txnMeta)
				if err != nil {
					return fmt.Errorf("Update: Problem adding txn %v to txindex: %v",
						txn, err)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Now that we have added all the txns to our TxIndex db, attach the block
		// to update our chain.
		_, _, err = txi.TXIndexChain.ProcessBlock(blockMsg, false /*verifySignatures*/)
		if err != nil {
			return fmt.Errorf("Update: Problem attaching block %v: %v",
				blockToAttach, err)
		}
	}

	glog.Infof("Update: Txindex update complete. New tip: (height: %d, hash: %v)",
		txi.TXIndexChain.BlockTip().Height, txi.TXIndexChain.BlockTip().Hash)

	return nil
}
