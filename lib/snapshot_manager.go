package lib

import (
	"bytes"
	"fmt"
	"github.com/decred/dcrd/lru"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"reflect"
	"time"
)

type SnapshotManager struct {
	Snapshot
}

// GetSnapshot is used for sending MsgDeSoGetSnapshot messages to peers. We will
// check if the passed peer has been assigned to an in-progress prefix and if so,
// we will request a snapshot data chunk from them. Otherwise, we will assign a
// new prefix to that peer.
func (snm *SnapshotManager) GetSnapshot(pp *Peer) {

	// Start the timer to measure how much time passes from a GetSnapshot msg to
	// a SnapshotData message.
	srv.timer.Start("Get Snapshot")

	var prefix []byte
	var lastReceivedKey []byte

	// We will try to determine if the provided peer has been assigned a prefix.
	// Iterate over all incomplete prefixes in the HyperSyncProgress and see if
	// any of them has been assigned to the peer.
	syncingPrefix := false
	for _, prefixProgress := range srv.HyperSyncProgress.PrefixProgress {
		if prefixProgress.Completed {
			continue
		}
		prefix = prefixProgress.Prefix
		lastReceivedKey = prefixProgress.LastReceivedKey
		syncingPrefix = true
		if prefixProgress.PrefixSyncPeer.ID == pp.ID {
			prefix = prefixProgress.Prefix
			lastReceivedKey = prefixProgress.LastReceivedKey
			syncingPrefix = true
			break
		} else {
			glog.V(1).Infof("GetSnapshot: switching peers on prefix (%v), previous peer ID (%v) "+
				"current peer ID (%v)", prefixProgress.Prefix, prefixProgress.PrefixSyncPeer.ID, pp.ID)
			// TODO: Should disable the previous sync peer here somehow

			prefixProgress.PrefixSyncPeer.ID = pp.ID
		}
	}

	// If peer isn't assigned to any prefix, we will assign him now.
	if !syncingPrefix {
		// We will assign the peer to a non-existent prefix.
		for _, prefix = range StatePrefixes.StatePrefixesList {
			exists := false
			for _, prefixProgress := range srv.HyperSyncProgress.PrefixProgress {
				if reflect.DeepEqual(prefix, prefixProgress.Prefix) {
					exists = true
					break
				}
			}
			// If prefix doesn't exist in our prefix progress struct, append new progress tracker
			// and assign it to the current peer.
			if !exists {
				srv.HyperSyncProgress.PrefixProgress = append(srv.HyperSyncProgress.PrefixProgress, &SyncPrefixProgress{
					PrefixSyncPeer:  pp,
					Prefix:          prefix,
					LastReceivedKey: prefix,
					Completed:       false,
				})
				lastReceivedKey = prefix
				syncingPrefix = true
				break
			}
		}
		// If no prefix was found, we error and return because the state is already synced.
		if !syncingPrefix {
			glog.Errorf("Server.GetSnapshot: Error selecting a prefix for peer %v "+
				"all prefixes are synced", pp)
			return
		}
	}
	// If operationQueueSemaphore is full, we are already storing too many chunks in memory. Block the thread while
	// we wait for the queue to clear up.
	srv.snapshot.operationQueueSemaphore <- struct{}{}
	// Now send a message to the peer to fetch the snapshot chunk.
	pp.AddDeSoMessage(&MsgDeSoGetSnapshot{
		SnapshotStartKey: lastReceivedKey,
	}, false)

	glog.V(2).Infof("Server.GetSnapshot: Sending a GetSnapshot message to peer (%v) "+
		"with Prefix (%v) and SnapshotStartEntry (%v)", pp, prefix, lastReceivedKey)
}

// _handleGetSnapshot gets called whenever we receive a GetSnapshot message from a peer. This means
// a peer is asking us to send him some data from our most recent snapshot. To respond to the peer we
// will retrieve the chunk from our main and ancestral records db and attach it to the response message.
func (snm *SnapshotManager) _handleGetSnapshot(pp *Peer, msg *MsgDeSoGetSnapshot) {
	glog.V(1).Infof("srv._handleGetSnapshot: Called with message %v from Peer %v", msg, pp)

	// Let the peer handle this. We will delegate this message to the peer's queue of inbound messages, because
	// fetching a snapshot chunk is an expensive operation.
	pp.AddDeSoMessage(msg, true /*inbound*/)
}

// _handleSnapshot gets called when we receive a SnapshotData message from a peer. The message contains
// a snapshot chunk, which is a sorted list of <key, value> pairs representing a section of the database
// at current snapshot epoch. We will set these entries in our node's database as well as update the checksum.
func (snm *SnapshotManager) _handleSnapshot(pp *Peer, msg *MsgDeSoSnapshotData) {
	srv.timer.End("Get Snapshot")
	srv.timer.Start("Server._handleSnapshot Main")
	// If there are no db entries in the msg, we should also disconnect the peer. There should always be
	// at least one entry sent, which is either the empty entry or the last key we've requested.
	if srv.snapshot == nil {
		glog.Errorf("srv._handleSnapshot: Received a snapshot message from a peer but srv.snapshot is nil. " +
			"This peer shouldn't send us snapshot messages because we didn't pass the SFHyperSync flag.")
		pp.Disconnect()
		return
	}

	// If we're not syncing then we don't need the snapshot chunk so
	if srv.blockchain.ChainState() != SyncStateSyncingSnapshot {
		glog.Errorf("srv._handleSnapshot: Received a snapshot message from peer but chain is not currently syncing from "+
			"snapshot. This means peer is most likely misbehaving so we'll disconnect them. Peer: (%v)", pp)
		pp.Disconnect()
		return
	}

	if len(msg.SnapshotChunk) == 0 {
		// We should disconnect the peer because he is misbehaving or doesn't have the snapshot.
		glog.Errorf("srv._handleSnapshot: Received a snapshot messages with empty snapshot chunk "+
			"disconnecting misbehaving peer (%v)", pp)
		pp.Disconnect()
		return
	}

	glog.V(1).Infof(CLog(Yellow, fmt.Sprintf("Received a snapshot message with entry keys (First entry: "+
		"<%v>, Last entry: <%v>), (number of entries: %v), metadata (%v), and isEmpty (%v), from Peer %v",
		msg.SnapshotChunk[0].Key, msg.SnapshotChunk[len(msg.SnapshotChunk)-1].Key, len(msg.SnapshotChunk),
		msg.SnapshotMetadata, msg.SnapshotChunk[0].IsEmpty(), pp)))

	// There is a possibility that during hypersync the network entered a new snapshot epoch. We handle this case by
	// restarting the node and starting hypersync from scratch.
	if msg.SnapshotMetadata.SnapshotBlockHeight > srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight &&
		uint64(srv.blockchain.HeaderTip().Height) >= msg.SnapshotMetadata.SnapshotBlockHeight {

		// TODO: Figure out how to handle header not reaching us, yet peer is telling us that the new epoch has started.
		if srv.nodeMessageChannel != nil {
			srv.nodeMessageChannel <- NodeRestart
			glog.Infof(CLog(Yellow, fmt.Sprintf("srv._handleSnapshot: Received a snapshot metadata with height (%v) "+
				"which is greater than the hypersync progress height (%v). This can happen when the network entered "+
				"a new snapshot epoch while we were syncing. The node will be restarted to retry hypersync with new epoch.",
				msg.SnapshotMetadata.SnapshotBlockHeight, srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight)))
			return
		} else {
			glog.Errorf(CLog(Red, "srv._handleSnapshot: Trying to restart the node but nodeMessageChannel is empty, "+
				"this should never happen."))
		}
	}

	// Make sure that the expected snapshot height and blockhash match the ones in received message.
	if msg.SnapshotMetadata.SnapshotBlockHeight != srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight ||
		!bytes.Equal(msg.SnapshotMetadata.CurrentEpochBlockHash[:], srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochBlockHash[:]) {

		glog.Errorf("srv._handleSnapshot: blockheight (%v) and blockhash (%v) in msg do not match the expected "+
			"hyper sync height (%v) and hash (%v)",
			msg.SnapshotMetadata.SnapshotBlockHeight, msg.SnapshotMetadata.CurrentEpochBlockHash,
			srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight, srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochBlockHash)
		pp.Disconnect()
		return
	}

	// First find the hyper sync progress struct that matches the received message.
	var syncPrefixProgress *SyncPrefixProgress
	for _, syncProgress := range srv.HyperSyncProgress.PrefixProgress {
		if bytes.Equal(msg.Prefix, syncProgress.Prefix) {
			syncPrefixProgress = syncProgress
			break
		}
	}
	// If peer sent a message with an incorrect prefix, we should disconnect them.
	if syncPrefixProgress == nil {
		// We should disconnect the peer because he is misbehaving
		glog.Errorf("srv._handleSnapshot: Problem finding appropriate sync prefix progress "+
			"disconnecting misbehaving peer (%v)", pp)
		pp.Disconnect()
		return
	}

	// If we haven't yet set the epoch checksum bytes in the hyper sync progress, we'll do it now.
	// If we did set the checksum bytes, we will verify that they match the one that peer has sent us.
	prevChecksumBytes := make([]byte, len(srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes))
	copy(prevChecksumBytes, srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes[:])
	if len(srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes) == 0 {
		srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = msg.SnapshotMetadata.CurrentEpochChecksumBytes
	} else if !reflect.DeepEqual(srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes, msg.SnapshotMetadata.CurrentEpochChecksumBytes) {
		// We should disconnect the peer because he is misbehaving
		glog.Errorf("srv._handleSnapshot: HyperSyncProgress epoch checksum bytes does not match that received from peer, "+
			"disconnecting misbehaving peer (%v)", pp)
		pp.Disconnect()
		return
	}

	// dbChunk will have the entries that we will add to the database. Usually the first entry in the chunk will
	// be the same as the lastKey that we've put in the GetSnapshot request. However, if we've asked for a prefix
	// for the first time, the lastKey can be different from the first chunk entry. Also, if the prefix is empty or
	// we've exhausted all entries for a prefix, the first snapshot chunk entry can be empty.
	var dbChunk []*DBEntry
	chunkEmpty := false
	if msg.SnapshotChunk[0].IsEmpty() {
		// We send the empty DB entry whenever we've exhausted the prefix. It can only be the first entry in the
		// chunk. We set chunkEmpty to true.
		glog.Infof("srv._handleSnapshot: First snapshot chunk is empty")
		chunkEmpty = true
	} else if bytes.Equal(syncPrefixProgress.LastReceivedKey, syncPrefixProgress.Prefix) {
		// If this is the first message that we're receiving for this sync progress, the first entry in the chunk
		// is going to be equal to the prefix.
		if !bytes.HasPrefix(msg.SnapshotChunk[0].Key, msg.Prefix) {
			// We should disconnect the peer because he is misbehaving.
			glog.Errorf("srv._handleSnapshot: Snapshot chunk DBEntry key has mismatched prefix "+
				"disconnecting misbehaving peer (%v)", pp)
			srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
			pp.Disconnect()
			return
		}
		dbChunk = append(dbChunk, msg.SnapshotChunk[0])
	} else {
		// If this is not the first message that we're receiving for this sync prefix, then the LastKeyReceived
		// should be identical to the first key in snapshot chunk. If it is not, then the peer either re-sent
		// the same payload twice, a message was dropped by the network, or he is misbehaving.
		if !bytes.Equal(syncPrefixProgress.LastReceivedKey, msg.SnapshotChunk[0].Key) {
			glog.Errorf("srv._handleSnapshot: Received a snapshot chunk that's not in-line with the sync progress "+
				"disconnecting misbehaving peer (%v)", pp)
			srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
			pp.Disconnect()
			return
		}
	}
	// Now add the remaining snapshot entries to the list of dbEntries we want to set in the DB.
	dbChunk = append(dbChunk, msg.SnapshotChunk[1:]...)

	if !chunkEmpty {
		// Check that all entries in the chunk contain the prefix, and that they are sorted. We skip the first element,
		// because we already validated it contains the prefix and we will refer to ii-1 when verifying ordering.
		for ii := 1; ii < len(dbChunk); ii++ {
			// Make sure that all dbChunk entries have the same prefix as in the message.
			if !bytes.HasPrefix(dbChunk[ii].Key, msg.Prefix) {
				// We should disconnect the peer because he is misbehaving
				glog.Errorf("srv._handleSnapshot: DBEntry key has mismatched prefix "+
					"disconnecting misbehaving peer (%v)", pp)
				srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
				pp.Disconnect()
				return
			}
			// Make sure that the dbChunk is sorted increasingly.
			if bytes.Compare(dbChunk[ii-1].Key, dbChunk[ii].Key) != -1 {
				// We should disconnect the peer because he is misbehaving
				glog.Errorf("srv._handleSnapshot: dbChunk entries are not sorted: first entry at index (%v) with "+
					"value (%v) and second entry with index (%v) and value (%v) disconnecting misbehaving peer (%v)",
					ii-1, dbChunk[ii-1].Key, ii, dbChunk[ii].Key, pp)
				srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
				pp.Disconnect()
				return
			}
		}

		// Process the DBEntries from the msg and add them to the db.
		srv.timer.Start("Server._handleSnapshot Process Snapshot")
		srv.snapshot.ProcessSnapshotChunk(srv.blockchain.db, &srv.blockchain.ChainLock, dbChunk,
			srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight)
		srv.timer.End("Server._handleSnapshot Process Snapshot")
	}

	// We will update the hyper sync progress tracker struct to reflect the newly added snapshot chunk.
	// In particular, we want to update the last received key to the last key in the received chunk.
	for ii := 0; ii < len(srv.HyperSyncProgress.PrefixProgress); ii++ {
		if reflect.DeepEqual(srv.HyperSyncProgress.PrefixProgress[ii].Prefix, msg.Prefix) {
			// We found the hyper sync progress corresponding to this snapshot chunk so update the key.
			lastKey := msg.SnapshotChunk[len(msg.SnapshotChunk)-1].Key
			srv.HyperSyncProgress.PrefixProgress[ii].LastReceivedKey = lastKey

			// If the snapshot chunk is not full, it means that we've completed this prefix. In such case,
			// there is a possibility we've finished hyper sync altogether. We will break out of the loop
			// and try to determine if we're done in the next loop.
			// TODO: verify that the prefix checksum matches the checksum provided by the peer / header checksum.
			//		We'll do this when we want to implement multi-peer sync.
			if !msg.SnapshotChunkFull {
				srv.HyperSyncProgress.PrefixProgress[ii].Completed = true
				break
			} else {
				// If chunk is full it means there's more work to do, so we will resume snapshot sync.
				srv.GetSnapshot(pp)
				return
			}
		}
	}
	srv.timer.End("Server._handleSnapshot Main")

	// If we get here, it means we've finished syncing the prefix, so now we will go through all state prefixes
	// and see what's left to do.

	var completedPrefixes [][]byte
	for _, prefix := range StatePrefixes.StatePrefixesList {
		completed := false
		// Check if the prefix has been completed.
		for _, prefixProgress := range srv.HyperSyncProgress.PrefixProgress {
			if reflect.DeepEqual(prefix, prefixProgress.Prefix) {
				completed = prefixProgress.Completed
				break
			}
		}
		if !completed {
			srv.GetSnapshot(pp)
			return
		}
		completedPrefixes = append(completedPrefixes, prefix)
	}

	srv.HyperSyncProgress.printChannel <- struct{}{}
	// Wait for the snapshot thread to process all operations and print the checksum.
	srv.snapshot.WaitForAllOperationsToFinish()

	// If we get to this point it means we synced all db prefixes, therefore finishing hyper sync.
	// Do some logging.
	srv.timer.End("HyperSync")
	srv.timer.Print("Get Snapshot")
	srv.timer.Print("Server._handleSnapshot Process Snapshot")
	srv.timer.Print("Server._handleSnapshot Checksum")
	srv.timer.Print("Server._handleSnapshot prefix progress")
	srv.timer.Print("Server._handleSnapshot Main")
	srv.timer.Print("HyperSync")
	srv.snapshot.PrintChecksum("Finished hyper sync. Checksum is:")
	glog.Infof(CLog(Magenta, fmt.Sprintf("Metadata checksum: (%v)",
		srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes)))

	glog.Infof(CLog(Yellow, fmt.Sprintf("Best header chain %v best block chain %v",
		srv.blockchain.bestHeaderChain[msg.SnapshotMetadata.SnapshotBlockHeight], srv.blockchain.bestChain)))

	// Verify that the state checksum matches the one in HyperSyncProgress snapshot metadata.
	// If the checksums don't match, it means that we've been interacting with a peer that was misbehaving.
	checksumBytes, err := srv.snapshot.Checksum.ToBytes()
	if err != nil {
		glog.Errorf("Server._handleSnapshot: Problem getting checksum bytes, error (%v)", err)
	}
	if reflect.DeepEqual(checksumBytes, srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes) {
		glog.Infof(CLog(Green, fmt.Sprintf("Server._handleSnapshot: State checksum matched "+
			"what was expected!")))
	} else {
		// Checksums didn't match
		glog.Errorf(CLog(Red, fmt.Sprintf("Server._handleSnapshot: The final db checksum doesn't match the "+
			"checksum received from the peer. It is likely that HyperSync encountered some unexpected error earlier. "+
			"You should report this as an issue on DeSo github https://github.com/deso-protocol/core. It is also possible "+
			"that the peer is misbehaving and sent invalid snapshot chunks. In either way, we'll restart the node and "+
			"attempt to HyperSync from the beginning. Local db checksum %v; peer's snapshot checksum %v",
			checksumBytes, srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes)))
		if srv.forceChecksum {
			// If forceChecksum is true we signal an erasure of the state and return here,
			// which will cut off the sync.
			if srv.nodeMessageChannel != nil {
				srv.nodeMessageChannel <- NodeErase
			}
			return
		} else {
			// Otherwise, if forceChecksum is false, we error but then keep going.
			glog.Errorf(CLog(Yellow, fmt.Sprintf("Server._handleSnapshot: Ignoring checksum mismatch because "+
				"--force-checksum is set to false.")))
		}
	}

	// Reset the badger DB options to the performance options. This is done by closing the current DB instance
	// and re-opening it with the new options.
	// This is necessary because the blocksync process syncs indexes with records that are too large for the default
	// badger options. The large records overflow the default setting value log size and cause the DB to crash.
	dbDir := GetBadgerDbPath(srv.snapshot.mainDbDirectory)
	opts := PerformanceBadgerOptions(dbDir)
	opts.ValueDir = dbDir
	srv.dirtyHackUpdateDbOpts(opts)

	// After syncing state from a snapshot, we will sync remaining blocks. To do so, we will
	// start downloading blocks from the snapshot height up to the blockchain tip. Since we
	// already synced all the state corresponding to the sub-blockchain ending at the snapshot
	// height, we will now mark all these blocks as processed. To do so, we will iterate through
	// the blockNodes in the header chain and set them in the blockchain data structures.
	err = srv.blockchain.db.Update(func(txn *badger.Txn) error {
		for ii := uint64(1); ii <= srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight; ii++ {
			curretNode := srv.blockchain.bestHeaderChain[ii]
			// Do not set the StatusBlockStored flag, because we still need to download the past blocks.
			curretNode.Status |= StatusBlockProcessed
			curretNode.Status |= StatusBlockValidated
			srv.blockchain.blockIndex[*curretNode.Hash] = curretNode
			srv.blockchain.bestChainMap[*curretNode.Hash] = curretNode
			srv.blockchain.bestChain = append(srv.blockchain.bestChain, curretNode)
			err := PutHeightHashToNodeInfoWithTxn(txn, srv.snapshot, curretNode, false /*bitcoinNodes*/)
			if err != nil {
				return err
			}
		}
		// We will also set the hash of the block at snapshot height as the best chain hash.
		err := PutBestHashWithTxn(txn, srv.snapshot, msg.SnapshotMetadata.CurrentEpochBlockHash, ChainTypeDeSoBlock)
		return err
	})
	if err != nil {
		glog.Errorf("Server._handleSnapshot: Problem updating snapshot blocknodes, error: (%v)", err)
	}
	// We also reset the in-memory snapshot cache, because it is populated with stale records after
	// we've initialized the chain with seed transactions.
	srv.snapshot.DatabaseCache = lru.NewKVCache(DatabaseCacheSize)

	// If we got here then we finished the snapshot sync so set appropriate flags.
	srv.blockchain.syncingState = false
	srv.blockchain.snapshot.CurrentEpochSnapshotMetadata = srv.HyperSyncProgress.SnapshotMetadata

	// Update the snapshot epoch metadata in the snapshot DB.
	for ii := 0; ii < MetadataRetryCount; ii++ {
		srv.snapshot.SnapshotDbMutex.Lock()
		err = srv.snapshot.SnapshotDb.Update(func(txn *badger.Txn) error {
			return txn.Set(_prefixLastEpochMetadata, srv.snapshot.CurrentEpochSnapshotMetadata.ToBytes())
		})
		srv.snapshot.SnapshotDbMutex.Unlock()
		if err != nil {
			glog.Errorf("server._handleSnapshot: Problem setting snapshot epoch metadata in snapshot db, error (%v)", err)
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

	// Update the snapshot status in the DB.
	srv.snapshot.Status.CurrentBlockHeight = msg.SnapshotMetadata.SnapshotBlockHeight
	srv.snapshot.Status.SaveStatus()

	glog.Infof("server._handleSnapshot: FINAL snapshot checksum is (%v) (%v)",
		srv.snapshot.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes,
		hex.EncodeToString(srv.snapshot.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes))

	// Take care of any callbacks that need to run once the snapshot is completed.
	srv.eventManager.snapshotCompleted()

	// Now sync the remaining blocks.
	if srv.blockchain.archivalMode {
		srv.blockchain.downloadingHistoricalBlocks = true
		srv.GetBlocksToStore(pp)
		return
	}

	headerTip := srv.blockchain.headerTip()
	srv.GetBlocks(pp, int(headerTip.Height))
}

// HandleGetSnapshot gets called whenever we receive a GetSnapshot message from a peer. This means
// a peer is asking us to send him some data from our most recent snapshot. To respond to the peer we
// will retrieve the chunk from our main and ancestral records db and attach it to the response message.
// This function is handled within peer's inbound message loop because retrieving a chunk is costly.
func (pp *Peer) HandleGetSnapshot(msg *MsgDeSoGetSnapshot) {
	// Start a timer to measure how much time sending a snapshot takes.
	pp.srv.timer.Start("Send Snapshot")
	defer pp.srv.timer.End("Send Snapshot")
	defer pp.srv.timer.Print("Send Snapshot")

	// Make sure this peer can only request one snapshot chunk at a time.
	if pp.snapshotChunkRequestInFlight {
		glog.V(1).Infof("Peer.HandleGetSnapshot: Ignoring GetSnapshot from Peer %v"+
			"because he already requested a GetSnapshot", pp)
		pp.Disconnect()
		return
	}
	pp.snapshotChunkRequestInFlight = true
	defer func(pp *Peer) { pp.snapshotChunkRequestInFlight = false }(pp)

	// Ignore GetSnapshot requests and disconnect the peer if we're not a hypersync node.
	if pp.srv.snapshot == nil {
		glog.Errorf("Peer.HandleGetSnapshot: Ignoring GetSnapshot from Peer %v "+
			"and disconnecting because node doesn't support HyperSync", pp)
		pp.Disconnect()
		return
	}

	// Ignore GetSnapshot requests if we're still syncing. We will only serve snapshot chunk when our
	// blockchain state is fully current.
	if pp.srv.blockchain.isSyncing() {
		chainState := pp.srv.blockchain.chainState()
		glog.V(1).Infof("Peer.HandleGetSnapshot: Ignoring GetSnapshot from Peer %v"+
			"because node is syncing with ChainState (%v)", pp, chainState)
		pp.AddDeSoMessage(&MsgDeSoSnapshotData{
			SnapshotMetadata:  nil,
			SnapshotChunk:     nil,
			SnapshotChunkFull: false,
			Prefix:            msg.GetPrefix(),
		}, false)
		return
	}

	// Make sure that the start key and prefix provided in the message are valid.
	if len(msg.SnapshotStartKey) == 0 || len(msg.GetPrefix()) == 0 {
		glog.Errorf("Peer.HandleGetSnapshot: Ignoring GetSnapshot from Peer %v "+
			"because SnapshotStartKey or Prefix are empty", pp)
		pp.Disconnect()
		return
	}

	// FIXME: Any restrictions on how many snapshots a peer can request?

	// Get the snapshot chunk from the database. This operation can happen concurrently with updates
	// to the main DB or the ancestral records DB, and we don't want to slow down any of these updates.
	// Because of that, we will detect whenever concurrent access takes place with the concurrencyFault
	// variable. If concurrency is detected, we will re-queue the GetSnapshot message.
	var concurrencyFault bool
	var err error

	snapshotDataMsg := &MsgDeSoSnapshotData{
		Prefix:           msg.GetPrefix(),
		SnapshotMetadata: pp.srv.snapshot.CurrentEpochSnapshotMetadata,
	}
	if isStateKey(msg.GetPrefix()) {
		snapshotDataMsg.SnapshotChunk, snapshotDataMsg.SnapshotChunkFull, concurrencyFault, err =
			pp.srv.snapshot.GetSnapshotChunk(pp.srv.blockchain.db, msg.GetPrefix(), msg.SnapshotStartKey)
	} else {
		// If the received prefix is not a state key, then it is likely that the peer has newer code.
		// A peer would be requesting state data for the newly added state prefix, though this node
		// doesn't recognize the prefix yet. We respond to the peer with an empty snapshot chunk,
		// since we don't have any data for the prefix yet. Even if the peer was misbehaving and
		// intentionally requesting non-existing prefix data, it doesn't really matter.
		snapshotDataMsg.SnapshotChunk = []*DBEntry{EmptyDBEntry()}
		snapshotDataMsg.SnapshotChunkFull = false
	}
	if err != nil {
		glog.Errorf("Peer.HandleGetSnapshot: something went wrong during fetching "+
			"snapshot chunk for peer (%v), error (%v)", pp, err)
		return
	}
	// When concurrencyFault occurs, we will wait a bit and then enqueue the message again.
	if concurrencyFault {
		glog.Errorf("Peer.HandleGetSnapshot: concurrency fault occurred so we enqueue the msg again to peer (%v)", pp)
		go func() {
			time.Sleep(GetSnapshotTimeout)
			pp.AddDeSoMessage(msg, true)
		}()
		return
	}

	pp.AddDeSoMessage(snapshotDataMsg, false)

	glog.V(2).Infof("Server._handleGetSnapshot: Sending a SnapshotChunk message to peer (%v) "+
		"with SnapshotHeight (%v) and CurrentEpochChecksumBytes (%v) and Snapshotdata length (%v)", pp,
		pp.srv.snapshot.CurrentEpochSnapshotMetadata.SnapshotBlockHeight,
		snapshotDataMsg.SnapshotMetadata, len(snapshotDataMsg.SnapshotChunk))
}

func (sn *SnapshotManager) _handleOutExpectedResponse(msg DeSoMessage) {
	switch msg.GetMsgType() {
	// If we're sending a GetSnapshot message, the peer should respond within a few seconds with a SnapshotData.
		pp._addExpectedResponse(&ExpectedResponse{
			TimeExpected: time.Now().Add(stallTimeout),
			MessageType:  MsgTypeSnapshotData,
		})
	}
}
