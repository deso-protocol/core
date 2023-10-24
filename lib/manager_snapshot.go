package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/decred/dcrd/lru"
	"github.com/deso-protocol/go-deadlock"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"reflect"
	"time"
)

type SnapshotManager struct {
	// TODO: Right now we're doing a circular reference *SyncManager <-> *SnapshotManager. Any better way?
	sm *SyncManager

	bc   *Blockchain
	snap *Snapshot
	srv  *Server
	// TODO: The two fields below are only needed because of the "dirty hack", fix it.
	mp *DeSoMempool
	// DbMutex protects the badger database from concurrent access when it's being closed & re-opened.
	// This is necessary because the database is closed & re-opened when the node finishes hypersyncing in order
	// to change the database options from Default options to Performance options.
	DbMutex deadlock.Mutex

	eventManager *EventManager

	// We will only allow peer fetch one snapshot chunk at a time so we will keep
	// track whether this peer has a get snapshot request in flight.
	snapshotChunkRequestInFlight bool

	// When --hypersync is set to true we will attempt fast block synchronization
	HyperSync           bool
	forceChecksum       bool
	stallTimeoutSeconds uint64

	// nodeMessageChannel is used to restart the node that's currently running this server.
	// It is basically a backlink to the node that calls Stop() and Start().
	nodeMessageChannel chan NodeMessage

	// If we're syncing state using hypersync, we'll keep track of the progress using HyperSyncProgress.
	// It stores information about all the prefixes that we're fetching. The way that HyperSyncProgress
	// is organized allows for multi-peer state synchronization. In such case, we would assign prefixes
	// to different peers. Whenever we assign a prefix to a peer, we would append a SyncProgressPrefix
	// struct to the HyperSyncProgress.PrefixProgress array.
	HyperSyncProgress SyncProgress
}

func NewSnapshotManager(bc *Blockchain, snap *Snapshot, srv *Server, mp *DeSoMempool, eventManager *EventManager,
	hyperSync bool, forceChecksum bool, stallTimeoutSeconds uint64, nodeMessageChannel chan NodeMessage) *SnapshotManager {

	return &SnapshotManager{
		bc:                  bc,
		snap:                snap,
		srv:                 srv,
		mp:                  mp,
		eventManager:        eventManager,
		HyperSync:           hyperSync,
		forceChecksum:       forceChecksum,
		stallTimeoutSeconds: stallTimeoutSeconds,
		nodeMessageChannel:  nodeMessageChannel,
	}
}

func (snm *SnapshotManager) Init(managers []Manager) {
	for _, manager := range managers {
		if manager.GetType() != ManagerTypeSync {
			continue
		}
		snm.sm = manager.(*SyncManager)
	}

	snm.srv.RegisterIncomingMessagesHandler(MsgTypeGetSnapshot, snm._handleGetSnapshotMessage)
	snm.srv.RegisterIncomingMessagesHandler(MsgTypeSnapshotData, snm._handleSnapshotDataMessage)
}

func (snm *SnapshotManager) Start() {
}

func (snm *SnapshotManager) Stop() {
}

func (snm *SnapshotManager) GetType() ManagerType {
	return ManagerTypeSnapshot
}

// _handleGetSnapshotMessage gets called whenever we receive a GetSnapshot message from a peer. This means
// a peer is asking us to send him some data from our most recent snapshot. To respond to the peer we
// will retrieve the chunk from our main and ancestral records db and attach it to the response message.
// This function is handled within peer's inbound message loop because retrieving a chunk is costly.
func (snm *SnapshotManager) _handleGetSnapshotMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeGetSnapshot {
		return MessageHandlerResponseCodeSkip
	}

	var snapMsg *MsgDeSoGetSnapshot
	var ok bool
	if snapMsg, ok = desoMsg.(*MsgDeSoGetSnapshot); !ok {
		return MessageHandlerResponseCodePeerDisconnect
	}
	glog.V(1).Infof("SnapshotManager._handleGetSnapshotMessage: Called with SnapshotStartKey= %v from Peer "+
		"(id= %v)", hex.EncodeToString(snapMsg.SnapshotStartKey), origin.ID)

	// Make sure this peer can only request one snapshot chunk at a time.
	if snm.snapshotChunkRequestInFlight {
		glog.V(1).Infof("Peer._handleGetSnapshotMessage: Ignoring GetSnapshot from Peer (id= %v)"+
			"because he already requested a GetSnapshot", origin.ID)
		return MessageHandlerResponseCodePeerDisconnect
	}
	snm.snapshotChunkRequestInFlight = true
	defer func(sm *SnapshotManager) { sm.snapshotChunkRequestInFlight = false }(snm)

	// Ignore GetSnapshot requests and disconnect the peer if we're not a hypersync node.
	if snm.snap == nil {
		glog.Errorf("Peer._handleGetSnapshotMessage: Ignoring GetSnapshot from Peer (id= %v) "+
			"and disconnecting because node doesn't support HyperSync", origin.ID)
		return MessageHandlerResponseCodePeerDisconnect
	}

	// Ignore GetSnapshot requests if we're still syncing. We will only serve snapshot chunk when our
	// blockchain state is fully current.
	if snm.bc.isSyncing() {
		chainState := snm.bc.chainState()
		glog.V(1).Infof("Peer._handleGetSnapshotMessage: Ignoring GetSnapshot from Peer (id= %v)"+
			"because node is syncing with ChainState (%v)", origin.ID, chainState)
		msg := &MsgDeSoSnapshotData{
			SnapshotMetadata:  nil,
			SnapshotChunk:     nil,
			SnapshotChunkFull: false,
			Prefix:            snapMsg.GetPrefix(),
		}
		if err := snm.srv.SendMessage(msg, origin.ID, nil); err != nil {
			return MessageHandlerResponseCodePeerUnavailable
		}
		return MessageHandlerResponseCodeOK
	}

	// Make sure that the start key and prefix provided in the message are valid.
	if len(snapMsg.SnapshotStartKey) == 0 || len(snapMsg.GetPrefix()) == 0 {
		glog.Errorf("Peer._handleGetSnapshotMessage: Ignoring GetSnapshot from Peer (id= %v) "+
			"because SnapshotStartKey or Prefix are empty", origin.ID)
		return MessageHandlerResponseCodePeerDisconnect
	}

	// FIXME: Any restrictions on how many snapshots a peer can request?

	// Get the snapshot chunk from the database. This operation can happen concurrently with updates
	// to the main DB or the ancestral records DB, and we don't want to slow down any of these updates.
	// Because of that, we will detect whenever concurrent access takes place with the concurrencyFault
	// variable. If concurrency is detected, we will re-queue the GetSnapshot message.
	var concurrencyFault bool
	var err error

	snapshotDataMsg := &MsgDeSoSnapshotData{
		Prefix:           snapMsg.GetPrefix(),
		SnapshotMetadata: snm.snap.CurrentEpochSnapshotMetadata,
	}
	if isStateKey(snapMsg.GetPrefix()) {
		snapshotDataMsg.SnapshotChunk, snapshotDataMsg.SnapshotChunkFull, concurrencyFault, err =
			snm.snap.GetSnapshotChunk(snm.bc.db, snapMsg.GetPrefix(), snapMsg.SnapshotStartKey)
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
		glog.Errorf("Peer._handleGetSnapshotMessage: something went wrong during fetching "+
			"snapshot chunk for peer (id= %v), error (%v)", origin.ID, err)
		return MessageHandlerResponseCodeSkip
	}
	// When concurrencyFault occurs, we will wait a bit and then enqueue the message again.
	if concurrencyFault {
		glog.Errorf("Peer._handleGetSnapshotMessage: concurrency fault occurred so we re-try this call later; "+
			"peer (id= %v)", origin.ID)
		go func() {
			time.Sleep(GetSnapshotTimeout)
			snm._handleGetSnapshotMessage(snapMsg, origin)
		}()
		return MessageHandlerResponseCodeSkip
	}

	if err := snm.srv.SendMessage(snapshotDataMsg, origin.ID, nil); err != nil {
		return MessageHandlerResponseCodePeerUnavailable
	}

	glog.V(2).Infof("Server._handleGetSnapshot: Sending a SnapshotChunk message to peer (id= %v) "+
		"with SnapshotHeight (%v) and CurrentEpochChecksumBytes (%v) and Snapshotdata length (%v)",
		origin.ID, snm.snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight,
		snapshotDataMsg.SnapshotMetadata, len(snapshotDataMsg.SnapshotChunk))
	return MessageHandlerResponseCodeOK
}

// syncSnapshot is used for sending MsgDeSoGetSnapshot messages to peers. We will
// check if the passed peer has been assigned to an in-progress prefix and if so,
// we will request a snapshot data chunk from them. Otherwise, we will assign a
// new prefix to that peer.
func (snm *SnapshotManager) syncSnapshot(peer *Peer) MessageHandlerResponseCode {
	var prefix []byte
	var lastReceivedKey []byte

	// We will try to determine if the provided peer has been assigned a prefix.
	// Iterate over all incomplete prefixes in the HyperSyncProgress and see if
	// any of them has been assigned to the peer.
	syncingPrefix := false
	for _, prefixProgress := range snm.HyperSyncProgress.PrefixProgress {
		if prefixProgress.Completed {
			continue
		}
		prefix = prefixProgress.Prefix
		lastReceivedKey = prefixProgress.LastReceivedKey
		syncingPrefix = true
		if prefixProgress.PrefixSyncPeer.ID == peer.ID {
			prefix = prefixProgress.Prefix
			lastReceivedKey = prefixProgress.LastReceivedKey
			syncingPrefix = true
			break
		} else {
			glog.V(1).Infof("SnapshotManager.syncSnapshot: switching peers on prefix (%v), previous "+
				"peer ID (id= %v) current peer ID (id= %v)", prefixProgress.Prefix, prefixProgress.PrefixSyncPeer.ID, peer.ID)
			// TODO [OLD]: Should disable the previous sync peer here somehow

			prefixProgress.PrefixSyncPeer.ID = peer.ID
		}
	}

	// If peer isn't assigned to any prefix, we will assign him now.
	if !syncingPrefix {
		// We will assign the peer to a non-existent prefix.
		for _, prefix = range StatePrefixes.StatePrefixesList {
			exists := false
			for _, prefixProgress := range snm.HyperSyncProgress.PrefixProgress {
				if reflect.DeepEqual(prefix, prefixProgress.Prefix) {
					exists = true
					break
				}
			}
			// If prefix doesn't exist in our prefix progress struct, append new progress tracker
			// and assign it to the current peer.
			if !exists {
				snm.HyperSyncProgress.PrefixProgress = append(snm.HyperSyncProgress.PrefixProgress, &SyncPrefixProgress{
					PrefixSyncPeer:  peer,
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
			glog.Errorf("SnapshotManager.syncSnapshot: Error selecting a prefix for peer (id= %v)"+
				"all prefixes are synced", peer.ID)
			return MessageHandlerResponseCodeSkip
		}
	}
	// If operationQueueSemaphore is full, we are already storing too many chunks in memory. Block the thread while
	// we wait for the queue to clear up.
	snm.snap.operationQueueSemaphore <- struct{}{}
	// Now send a message to the peer to fetch the snapshot chunk.
	glog.V(2).Infof("SnapshotManager.syncSnapshot: Sending a syncSnapshot message to peer (id= %v) "+
		"with Prefix (%v) and SnapshotStartEntry (%v)", peer.ID, prefix, lastReceivedKey)
	getSnapshotMsg := &MsgDeSoGetSnapshot{
		SnapshotStartKey: lastReceivedKey,
	}
	return snm.sendGetSnapshotMessage(getSnapshotMsg, peer.ID)
}

func (snm *SnapshotManager) sendGetSnapshotMessage(getSnapshotMsg *MsgDeSoGetSnapshot, peerId uint64) MessageHandlerResponseCode {
	// If we're sending a GetSnapshot message, the peer should respond within a few seconds with a SnapshotData.
	stallTimeout := time.Duration(int64(snm.stallTimeoutSeconds) * int64(time.Second))
	expectedResponses := []*ExpectedResponse{{
		TimeExpected: time.Now().Add(stallTimeout),
		MessageType:  MsgTypeSnapshotData,
	}}

	if err := snm.srv.SendMessage(getSnapshotMsg, peerId, expectedResponses); err != nil {
		return MessageHandlerResponseCodePeerUnavailable
	}
	return MessageHandlerResponseCodeOK
}

// _handleSnapshot gets called when we receive a SnapshotData message from a peer. The message contains
// a snapshot chunk, which is a sorted list of <key, value> pairs representing a section of the database
// at current snapshot epoch. We will set these entries in our node's database as well as update the checksum.
func (snm *SnapshotManager) _handleSnapshotDataMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeSnapshotData {
		return MessageHandlerResponseCodeSkip
	}

	var snapDataMsg *MsgDeSoSnapshotData
	var ok bool
	if snapDataMsg, ok = desoMsg.(*MsgDeSoSnapshotData); !ok {
		glog.Errorf("SnapshotManager._handleSnapshotDataMessage: "+
			"Problem parsing MsgDeSoSnapshotData message from peer %v", origin)
		return MessageHandlerResponseCodePeerDisconnect
	}

	// If there are no db entries in the msg, we should also disconnect the peer. There should always be
	// at least one entry sent, which is either the empty entry or the last key we've requested.
	if snm.snap == nil {
		glog.Errorf("SnapshotManager._handleSnapshotDataMessage: Received a snapshot message from a peer but " +
			"snm.snap is nil. This peer shouldn't send us snapshot messages because we didn't pass the SFHyperSync flag.")
		return MessageHandlerResponseCodePeerDisconnect
	}

	// If we're not syncing then we don't need the snapshot chunk so
	if snm.bc.ChainState() != SyncStateSyncingSnapshot {
		glog.Errorf("SnapshotManager._handleSnapshotDataMessage: Received a snapshot message from peer but chain is "+
			"not currently syncing from snapshot. This means peer is most likely misbehaving so we'll disconnect them. "+
			"Peer: (id= %v)", origin.ID)
		return MessageHandlerResponseCodePeerDisconnect
	}

	if len(snapDataMsg.SnapshotChunk) == 0 {
		// We should disconnect the peer because he is misbehaving or doesn't have the snapshot.
		glog.Errorf("SnapshotManager._handleSnapshotDataMessage: Received a snapshot messages with empty snapshot chunk "+
			"disconnecting misbehaving peer (id= %v)", origin.ID)
		return MessageHandlerResponseCodePeerDisconnect
	}

	glog.V(1).Infof(CLog(Yellow, fmt.Sprintf("SnapshotManager._handleSnapshotDataMessage: Received a "+
		"snapshot message with entry keys (First entry: <%v>, Last entry: <%v>), (number of entries: %v), "+
		"metadata (%v), and isEmpty (%v), from Peer (id= %v)",
		snapDataMsg.SnapshotChunk[0].Key, snapDataMsg.SnapshotChunk[len(snapDataMsg.SnapshotChunk)-1].Key,
		len(snapDataMsg.SnapshotChunk), snapDataMsg.SnapshotMetadata, snapDataMsg.SnapshotChunk[0].IsEmpty(), origin.ID)))

	// There is a possibility that during hypersync the network entered a new snapshot epoch. We handle this case by
	// restarting the node and starting hypersync from scratch.
	if snapDataMsg.SnapshotMetadata.SnapshotBlockHeight > snm.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight &&
		uint64(snm.bc.HeaderTip().Height) >= snapDataMsg.SnapshotMetadata.SnapshotBlockHeight {

		// TODO: Figure out how to handle header not reaching us, yet peer is telling us that the new epoch has started.
		if snm.nodeMessageChannel != nil {
			snm.nodeMessageChannel <- NodeRestart
			glog.Infof(CLog(Yellow, fmt.Sprintf("SnapshotManager._handleSnapshotDataMessage: Received a snapshot metadata "+
				"with height (%v) which is greater than the hypersync progress height (%v). This can happen when the network "+
				"entered a new snapshot epoch while we were syncing. The node will be restarted to retry hypersync with new epoch.",
				snapDataMsg.SnapshotMetadata.SnapshotBlockHeight, snm.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight)))
			return MessageHandlerResponseCodeOK
		} else {
			// TODO: We previously didn't return here, seems like we should?
			glog.Errorf(CLog(Red, "SnapshotManager._handleSnapshotDataMessage: Trying to restart the node but "+
				"nodeMessageChannel is empty, this should never happen."))
			return MessageHandlerResponseCodeSkip
		}
	}

	// Make sure that the expected snapshot height and blockhash match the ones in received message.
	if snapDataMsg.SnapshotMetadata.SnapshotBlockHeight != snm.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight ||
		!bytes.Equal(snapDataMsg.SnapshotMetadata.CurrentEpochBlockHash[:], snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochBlockHash[:]) {

		glog.Errorf("SnapshotManager._handleSnapshotDataMessage: blockheight (%v) and blockhash (%v) in msg do "+
			"not match the expected hyper sync height (%v) and hash (%v)",
			snapDataMsg.SnapshotMetadata.SnapshotBlockHeight, snapDataMsg.SnapshotMetadata.CurrentEpochBlockHash,
			snm.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight, snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochBlockHash)
		return MessageHandlerResponseCodePeerDisconnect
	}

	// First find the hyper sync progress struct that matches the received message.
	var syncPrefixProgress *SyncPrefixProgress
	for _, syncProgress := range snm.HyperSyncProgress.PrefixProgress {
		if bytes.Equal(snapDataMsg.Prefix, syncProgress.Prefix) {
			syncPrefixProgress = syncProgress
			break
		}
	}
	// If peer sent a message with an incorrect prefix, we should disconnect them.
	if syncPrefixProgress == nil {
		// We should disconnect the peer because he is misbehaving
		glog.Errorf("SnapshotManager._handleSnapshotDataMessage: Problem finding appropriate sync prefix progress "+
			"disconnecting misbehaving peer (id= %v)", origin.ID)
		return MessageHandlerResponseCodePeerDisconnect
	}

	// If we haven't yet set the epoch checksum bytes in the hyper sync progress, we'll do it now.
	// If we did set the checksum bytes, we will verify that they match the one that peer has sent us.
	prevChecksumBytes := make([]byte, len(snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes))
	copy(prevChecksumBytes, snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes[:])
	if len(snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes) == 0 {
		snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = snapDataMsg.SnapshotMetadata.CurrentEpochChecksumBytes
	} else if !reflect.DeepEqual(snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes, snapDataMsg.SnapshotMetadata.CurrentEpochChecksumBytes) {
		// We should disconnect the peer because he is misbehaving
		glog.Errorf("SnapshotManager._handleSnapshotDataMessage: HyperSyncProgress epoch checksum bytes does not "+
			"match that received from peer, disconnecting misbehaving peer (id= %v)", origin.ID)
		return MessageHandlerResponseCodePeerDisconnect
	}

	// dbChunk will have the entries that we will add to the database. Usually the first entry in the chunk will
	// be the same as the lastKey that we've put in the GetSnapshot request. However, if we've asked for a prefix
	// for the first time, the lastKey can be different from the first chunk entry. Also, if the prefix is empty or
	// we've exhausted all entries for a prefix, the first snapshot chunk entry can be empty.
	var dbChunk []*DBEntry
	chunkEmpty := false
	if snapDataMsg.SnapshotChunk[0].IsEmpty() {
		// We send the empty DB entry whenever we've exhausted the prefix. It can only be the first entry in the
		// chunk. We set chunkEmpty to true.
		glog.Infof("SnapshotManager._handleSnapshotDataMessage: First snapshot chunk is empty")
		chunkEmpty = true
	} else if bytes.Equal(syncPrefixProgress.LastReceivedKey, syncPrefixProgress.Prefix) {
		// If this is the first message that we're receiving for this sync progress, the first entry in the chunk
		// is going to be equal to the prefix.
		if !bytes.HasPrefix(snapDataMsg.SnapshotChunk[0].Key, snapDataMsg.Prefix) {
			// We should disconnect the peer because he is misbehaving.
			glog.Errorf("SnapshotManager._handleSnapshotDataMessage: Snapshot chunk DBEntry key has mismatched prefix "+
				"disconnecting misbehaving peer (id= %v)", origin.ID)
			snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
			return MessageHandlerResponseCodePeerDisconnect
		}
		dbChunk = append(dbChunk, snapDataMsg.SnapshotChunk[0])
	} else {
		// If this is not the first message that we're receiving for this sync prefix, then the LastKeyReceived
		// should be identical to the first key in snapshot chunk. If it is not, then the peer either re-sent
		// the same payload twice, a message was dropped by the network, or he is misbehaving.
		if !bytes.Equal(syncPrefixProgress.LastReceivedKey, snapDataMsg.SnapshotChunk[0].Key) {
			glog.Errorf("SnapshotManager._handleSnapshotDataMessage: Received a snapshot chunk that's not in-line "+
				"with the sync progress disconnecting misbehaving peer (id= %v)", origin.ID)
			snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
			return MessageHandlerResponseCodePeerDisconnect
		}
	}
	// Now add the remaining snapshot entries to the list of dbEntries we want to set in the DB.
	dbChunk = append(dbChunk, snapDataMsg.SnapshotChunk[1:]...)

	if !chunkEmpty {
		// Check that all entries in the chunk contain the prefix, and that they are sorted. We skip the first element,
		// because we already validated it contains the prefix and we will refer to ii-1 when verifying ordering.
		for ii := 1; ii < len(dbChunk); ii++ {
			// Make sure that all dbChunk entries have the same prefix as in the message.
			if !bytes.HasPrefix(dbChunk[ii].Key, snapDataMsg.Prefix) {
				// We should disconnect the peer because he is misbehaving
				glog.Errorf("SnapshotManager._handleSnapshotDataMessage: DBEntry key has mismatched prefix "+
					"disconnecting misbehaving peer (id= %v)", origin.ID)
				snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
				return MessageHandlerResponseCodePeerDisconnect
			}
			// Make sure that the dbChunk is sorted increasingly.
			if bytes.Compare(dbChunk[ii-1].Key, dbChunk[ii].Key) != -1 {
				// We should disconnect the peer because he is misbehaving
				glog.Errorf("SnapshotManager._handleSnapshotDataMessage: dbChunk entries are not sorted: first entry "+
					"at index (%v) with value (%v) and second entry with index (%v) and value (%v) disconnecting misbehaving "+
					"peer (id= %v)", ii-1, dbChunk[ii-1].Key, ii, dbChunk[ii].Key, origin.ID)
				snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
				return MessageHandlerResponseCodePeerDisconnect
			}
		}

		// Process the DBEntries from the msg and add them to the db.
		snm.snap.ProcessSnapshotChunk(snm.bc.db, &snm.bc.ChainLock, dbChunk,
			snm.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight)
	}

	// We will update the hyper sync progress tracker struct to reflect the newly added snapshot chunk.
	// In particular, we want to update the last received key to the last key in the received chunk.
	for ii := 0; ii < len(snm.HyperSyncProgress.PrefixProgress); ii++ {
		if reflect.DeepEqual(snm.HyperSyncProgress.PrefixProgress[ii].Prefix, snapDataMsg.Prefix) {
			// We found the hyper sync progress corresponding to this snapshot chunk so update the key.
			lastKey := snapDataMsg.SnapshotChunk[len(snapDataMsg.SnapshotChunk)-1].Key
			snm.HyperSyncProgress.PrefixProgress[ii].LastReceivedKey = lastKey

			// If the snapshot chunk is not full, it means that we've completed this prefix. In such case,
			// there is a possibility we've finished hyper sync altogether. We will break out of the loop
			// and try to determine if we're done in the next loop.
			// TODO: verify that the prefix checksum matches the checksum provided by the peer / header checksum.
			//		We'll do this when we want to implement multi-peer sync.
			if !snapDataMsg.SnapshotChunkFull {
				snm.HyperSyncProgress.PrefixProgress[ii].Completed = true
				break
			} else {
				// If chunk is full it means there's more work to do, so we will resume snapshot sync.
				return snm.syncSnapshot(origin)
			}
		}
	}

	// If we get here, it means we've finished syncing the prefix, so now we will go through all state prefixes
	// and see what's left to do.

	var completedPrefixes [][]byte
	for _, prefix := range StatePrefixes.StatePrefixesList {
		completed := false
		// Check if the prefix has been completed.
		for _, prefixProgress := range snm.HyperSyncProgress.PrefixProgress {
			if reflect.DeepEqual(prefix, prefixProgress.Prefix) {
				completed = prefixProgress.Completed
				break
			}
		}
		if !completed {
			return snm.syncSnapshot(origin)
		}
		completedPrefixes = append(completedPrefixes, prefix)
	}

	snm.HyperSyncProgress.printChannel <- struct{}{}
	// Wait for the snapshot thread to process all operations and print the checksum.
	snm.snap.WaitForAllOperationsToFinish()

	// If we get to this point it means we synced all db prefixes, therefore finishing hyper sync.
	// Do some logging.
	snm.snap.PrintChecksum("Finished hyper sync. Checksum is:")
	glog.Infof(CLog(Magenta, fmt.Sprintf("Metadata checksum: (%v)",
		snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes)))

	glog.Infof(CLog(Yellow, fmt.Sprintf("Best header chain %v best block chain %v",
		snm.bc.bestHeaderChain[snapDataMsg.SnapshotMetadata.SnapshotBlockHeight], snm.bc.bestChain)))

	// Verify that the state checksum matches the one in HyperSyncProgress snapshot metadata.
	// If the checksums don't match, it means that we've been interacting with a peer that was misbehaving.
	checksumBytes, err := snm.snap.Checksum.ToBytes()
	if err != nil {
		glog.Errorf("SnapshotManager._handleSnapshotDataMessage: Problem getting checksum bytes, error (%v)", err)
	}
	if reflect.DeepEqual(checksumBytes, snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes) {
		glog.Infof(CLog(Green, fmt.Sprintf("Server._handleSnapshot: State checksum matched "+
			"what was expected!")))
	} else {
		// Checksums didn't match
		glog.Errorf(CLog(Red, fmt.Sprintf("SnapshotManager._handleSnapshotDataMessage: The final db checksum doesn't "+
			"match the checksum received from the peer. It is likely that HyperSync encountered some unexpected error earlier. "+
			"You should report this as an issue on DeSo github https://github.com/deso-protocol/core. It is also possible "+
			"that the peer is misbehaving and sent invalid snapshot chunks. In either way, we'll restart the node and "+
			"attempt to HyperSync from the beginning. Local db checksum %v; peer's snapshot checksum %v",
			checksumBytes, snm.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes)))
		if snm.forceChecksum {
			// If forceChecksum is true we signal an erasure of the state and return here,
			// which will cut off the sync.
			if snm.nodeMessageChannel != nil {
				snm.nodeMessageChannel <- NodeErase
			}
			return MessageHandlerResponseCodeOK
		} else {
			// Otherwise, if forceChecksum is false, we error but then keep going.
			glog.Errorf(CLog(Yellow, fmt.Sprintf("SnapshotManager._handleSnapshotDataMessage: Ignoring checksum "+
				"mismatch because --force-checksum is set to false.")))
		}
	}

	// Reset the badger DB options to the performance options. This is done by closing the current DB instance
	// and re-opening it with the new options.
	// This is necessary because the blocksync process syncs indexes with records that are too large for the default
	// badger options. The large records overflow the default setting value log size and cause the DB to crash.
	dbDir := GetBadgerDbPath(snm.snap.mainDbDirectory)
	opts := PerformanceBadgerOptions(dbDir)
	opts.ValueDir = dbDir
	// TODO: Clean this up later
	snm.dirtyHackUpdateDbOpts(opts)

	// After syncing state from a snapshot, we will sync remaining blocks. To do so, we will
	// start downloading blocks from the snapshot height up to the blockchain tip. Since we
	// already synced all the state corresponding to the sub-blockchain ending at the snapshot
	// height, we will now mark all these blocks as processed. To do so, we will iterate through
	// the blockNodes in the header chain and set them in the blockchain data structures.
	err = snm.bc.db.Update(func(txn *badger.Txn) error {
		for ii := uint64(1); ii <= snm.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight; ii++ {
			curretNode := snm.bc.bestHeaderChain[ii]
			// Do not set the StatusBlockStored flag, because we still need to download the past blocks.
			curretNode.Status |= StatusBlockProcessed
			curretNode.Status |= StatusBlockValidated
			snm.bc.blockIndex[*curretNode.Hash] = curretNode
			snm.bc.bestChainMap[*curretNode.Hash] = curretNode
			snm.bc.bestChain = append(snm.bc.bestChain, curretNode)
			err := PutHeightHashToNodeInfoWithTxn(txn, snm.snap, curretNode, false /*bitcoinNodes*/)
			if err != nil {
				return err
			}
		}
		// We will also set the hash of the block at snapshot height as the best chain hash.
		err := PutBestHashWithTxn(txn, snm.snap, snapDataMsg.SnapshotMetadata.CurrentEpochBlockHash, ChainTypeDeSoBlock)
		return err
	})
	if err != nil {
		glog.Errorf("SnapshotManager._handleSnapshotDataMessage: Problem updating snapshot blocknodes, error: (%v)", err)
	}
	// We also reset the in-memory snapshot cache, because it is populated with stale records after
	// we've initialized the chain with seed transactions.
	snm.snap.DatabaseCache = lru.NewKVCache(DatabaseCacheSize)

	// If we got here then we finished the snapshot sync so set appropriate flags.
	snm.bc.syncingState = false
	snm.bc.snapshot.CurrentEpochSnapshotMetadata = snm.HyperSyncProgress.SnapshotMetadata

	// Update the snapshot epoch metadata in the snapshot DB.
	for ii := 0; ii < MetadataRetryCount; ii++ {
		snm.snap.SnapshotDbMutex.Lock()
		err = snm.snap.SnapshotDb.Update(func(txn *badger.Txn) error {
			return txn.Set(_prefixLastEpochMetadata, snm.snap.CurrentEpochSnapshotMetadata.ToBytes())
		})
		snm.snap.SnapshotDbMutex.Unlock()
		if err != nil {
			glog.Errorf("SnapshotManager._handleSnapshotDataMessage: Problem setting snapshot epoch metadata "+
				"in snapshot db, error (%v)", err)
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

	// Update the snapshot status in the DB.
	snm.snap.Status.CurrentBlockHeight = snapDataMsg.SnapshotMetadata.SnapshotBlockHeight
	snm.snap.Status.SaveStatus()

	glog.Infof("SnapshotManager._handleSnapshotDataMessage: FINAL snapshot checksum is (%v) (%v)",
		snm.snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes,
		hex.EncodeToString(snm.snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes))

	// Take care of any callbacks that need to run once the snapshot is completed.
	snm.eventManager.snapshotCompleted()

	// Now sync the remaining blocks.
	if snm.bc.archivalMode {
		snm.bc.downloadingHistoricalBlocks = true
		// TODO: Right now we're doing a circular reference *SyncManager <-> *SnapshotManager. Any better way?
		if code := snm.sm.SyncMissingBlocksArchivalMode(origin); code != MessageHandlerResponseCodeOK {
			return code
		}
		return MessageHandlerResponseCodeOK
	}

	headerTip := snm.bc.headerTip()
	// TODO: Right now we're doing a circular reference *SyncManager <-> *SnapshotManager. Any better way?
	return snm.sm.SyncMissingBlocks(origin, int(headerTip.Height))
}

func (snm *SnapshotManager) InitSnapshotSync(peer *Peer) MessageHandlerResponseCode {
	// If node is a hyper sync node and we haven't finished syncing state yet, we will kick off state sync.
	// TODO: Multi-peer sync.
	if !snm.HyperSync {
		return MessageHandlerResponseCodeSkip
	}
	bestHeaderHeight := uint64(snm.bc.headerTip().Height)
	expectedSnapshotHeight := bestHeaderHeight - (bestHeaderHeight % snm.snap.SnapshotBlockHeightPeriod)
	snm.snap.Migrations.CleanupMigrations(expectedSnapshotHeight)

	if len(snm.HyperSyncProgress.PrefixProgress) != 0 {
		return snm.syncSnapshot(peer)
	}
	glog.Infof(CLog(Magenta, fmt.Sprintf("Initiating HyperSync after finishing downloading headers. Node "+
		"will quickly download a snapshot of the blockchain taken at height (%v). HyperSync will sync each "+
		"prefix of the node's KV database. Connected peer (ip= %v). Note: State sync is a new feature and hence "+
		"might contain some unexpected behavior. If you see an issue, please report it in DeSo Github "+
		"https://github.com/deso-protocol/core.", expectedSnapshotHeight, peer.IP())))

	// Clean all the state prefixes from the node db so that we can populate it with snapshot entries.
	// When we start a node, it first loads a bunch of seed transactions in the genesis block. We want to
	// remove these entries from the db because we will receive them during state sync.
	glog.Infof(CLog(Magenta, "SnapshotManager.InitSnapshotSync: deleting all state records. This can take a while."))
	shouldErase, err := DBDeleteAllStateRecords(snm.bc.db)
	if err != nil {
		glog.Errorf(CLog(Red, fmt.Sprintf("SnapshotManager.InitSnapshotSync: problem while deleting state "+
			"records, error: %v", err)))
	}
	if shouldErase {
		if snm.nodeMessageChannel != nil {
			snm.nodeMessageChannel <- NodeErase
		}
		glog.Errorf(CLog(Red, fmt.Sprintf("SnapshotManager.InitSnapshotSync: Records were found in the node "+
			"directory, while trying to resync. Now erasing the node directory and restarting the node. "+
			"That's faster than manually expunging all records from the database.")))
		return MessageHandlerResponseCodeOK
	}

	// We set the expected height and hash of the snapshot from our header chain. The snapshots should be
	// taken on a regular basis every SnapshotBlockHeightPeriod number of blocks. This means we can calculate the
	// expected height at which the snapshot should be taking place. We do this to make sure that the
	// snapshot we receive from the peer is up-to-date.
	// TODO: error handle if the hash doesn't exist for some reason.
	snm.HyperSyncProgress.SnapshotMetadata = &SnapshotEpochMetadata{
		SnapshotBlockHeight:       expectedSnapshotHeight,
		FirstSnapshotBlockHeight:  expectedSnapshotHeight,
		CurrentEpochChecksumBytes: []byte{},
		CurrentEpochBlockHash:     snm.bc.bestHeaderChain[expectedSnapshotHeight].Hash,
	}
	snm.HyperSyncProgress.PrefixProgress = []*SyncPrefixProgress{}
	snm.HyperSyncProgress.Completed = false
	go snm.HyperSyncProgress.PrintLoop()

	// Initialize the snapshot checksum so that it's reset. It got modified during chain initialization
	// when processing seed transaction from the genesis block. So we need to clear it.
	snm.snap.Checksum.ResetChecksum()
	if err := snm.snap.Checksum.SaveChecksum(); err != nil {
		glog.Errorf("SnapshotManager.InitSnapshotSync: Problem saving snapshot to database, error (%v)", err)
	}
	// Reset the migrations along with the main checksum.
	snm.snap.Migrations.ResetChecksums()
	if err := snm.snap.Migrations.SaveMigrations(); err != nil {
		glog.Errorf("SnapshotManager.InitSnapshotSync: Problem saving migration checksums to database, error (%v)", err)
	}

	// Now proceed to start fetching snapshot data from the peer.
	return snm.syncSnapshot(peer)
}

// TODO: Clean this up
// dirtyHackUpdateDbOpts closes the current badger DB instance and re-opens it with the provided options.
//
// FIXME: This is a dirty hack that we did in order to decrease memory usage. The reason why we needed it is
// as follows:
//   - When we run a node with --hypersync or --hypersync-archival, using PerformanceOptions the whole way
//     through causes it to use too much memory.
//   - The problem is that if we use DefaultOptions, then the block sync after HyperSync is complete will fail
//     because it writes really big entries in a single transaction to the PrefixBlockHashToUtxoOperations
//     index.
//   - So, in order to keep memory usage reasonable, we need to use DefaultOptions during the HyperSync portion
//     and then *switch over* to PerformanceOptions once the HyperSync is complete. That is what this function
//     is used for.
//   - Running a node with --blocksync requires that we use PerformanceOptions the whole way through, but we
//     are moving away from syncing nodes that way, so we don't need to worry too much about that case right now.
//
// The long-term solution is to break the writing of the PrefixBlockHashToUtxoOperations index into chunks,
// or to remove it entirely. We don't want to do that work right now, but we want to reduce the memory usage
// for the "common" case, which is why we're doing this dirty hack for now.
func (snm *SnapshotManager) dirtyHackUpdateDbOpts(opts badger.Options) {
	// Make sure that a mempool process doesn't try to access the DB while we're closing and re-opening it.
	snm.mp.mtx.Lock()
	defer snm.mp.mtx.Unlock()
	// Make sure that a server process doesn't try to access the DB while we're closing and re-opening it.
	snm.DbMutex.Lock()
	defer snm.DbMutex.Unlock()
	snm.bc.db.Close()
	db, err := badger.Open(opts)
	if err != nil {
		// If we can't open the DB with the new options, we need to exit the process.
		glog.Fatalf("Server._handleSnapshot: Problem switching badger db to performance opts, error: (%v)", err)
	}
	snm.bc.db = db
	snm.snap.mainDb = snm.bc.db
	snm.mp.bc.db = snm.bc.db
	snm.mp.backupUniversalUtxoView.Handle = snm.bc.db
	snm.mp.universalUtxoView.Handle = snm.bc.db
}

// SyncPrefixProgress keeps track of sync progress on an individual prefix. It is used in
// hyper sync to determine which peer to query about each prefix and also what was the last
// db key that we've received from that peer. Peers will send us state by chunks. But first we
// need to tell the peer the starting key for the chunk we want to retrieve.
type SyncPrefixProgress struct {
	// Peer assigned for retrieving this particular prefix.
	PrefixSyncPeer *Peer
	// DB prefix corresponding to this particular sync progress.
	Prefix []byte
	// LastReceivedKey is the last key that we've received from this peer.
	LastReceivedKey []byte

	// Completed indicates whether we've finished syncing this prefix.
	Completed bool
}

// SyncProgress is used to keep track of hyper sync progress. It stores a list of SyncPrefixProgress
// structs which are used to track progress on each individual prefix. It also has the snapshot block
// height and block hash of the current snapshot epoch.
type SyncProgress struct {
	// PrefixProgress includes a list of SyncPrefixProgress objects, each of which represents a state prefix.
	PrefixProgress []*SyncPrefixProgress

	// SnapshotMetadata is the information about the snapshot we're downloading.
	SnapshotMetadata *SnapshotEpochMetadata

	// Completed indicates whether we've finished syncing state.
	Completed bool

	printChannel chan struct{}
}

func (progress *SyncProgress) PrintLoop() {
	progress.printChannel = make(chan struct{})
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-progress.printChannel:
			return
		case <-ticker.C:
			var completedPrefixes [][]byte
			var incompletePrefixes [][]byte
			var currentPrefix []byte

			for _, prefix := range StatePrefixes.StatePrefixesList {
				// Check if the prefix has been completed.
				foundPrefix := false
				for _, prefixProgress := range progress.PrefixProgress {
					if reflect.DeepEqual(prefix, prefixProgress.Prefix) {
						foundPrefix = true
						if prefixProgress.Completed {
							completedPrefixes = append(completedPrefixes, prefix)
							break
						} else {
							currentPrefix = prefix
						}
						break
					}
				}
				if !foundPrefix {
					incompletePrefixes = append(incompletePrefixes, prefix)
				}
			}
			if len(completedPrefixes) > 0 {
				glog.Infof(CLog(Green, fmt.Sprintf("HyperSync: finished downloading prefixes (%v)", completedPrefixes)))
			}
			if len(currentPrefix) > 0 {
				glog.Infof(CLog(Magenta, fmt.Sprintf("HyperSync: currently syncing prefix: (%v)", currentPrefix)))
			}
			if len(incompletePrefixes) > 0 {
				glog.Infof("Remaining prefixes (%v)", incompletePrefixes)
			}
		}
	}
}
