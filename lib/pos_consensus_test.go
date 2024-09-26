package lib

import (
	"sync"
	"testing"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/consensus"
	"github.com/deso-protocol/go-deadlock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestFastHotStuffConsensusHandleLocalVoteEvent(t *testing.T) {
	// Create a test private key for the signer
	blsPrivateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	blsPublicKey := blsPrivateKey.PublicKey()

	// Create a test block header with a valid QC
	blockHeader := createTestBlockHeaderVersion2(t, false)
	blockHash, err := blockHeader.Hash()
	require.NoError(t, err)

	// Create a mock consensus
	fastHotStuffConsensus := FastHotStuffConsensus{
		lock:           sync.RWMutex{},
		networkManager: _createMockNetworkManagerForConsensus(),
		blockchain: &Blockchain{
			params: &DeSoTestnetParams,
		},
		signer: &BLSSigner{
			privateKey: blsPrivateKey,
		},
		fastHotStuffEventLoop: &consensus.MockFastHotStuffEventLoop{
			OnIsInitialized: alwaysReturnTrue,
			OnIsRunning:     alwaysReturnTrue,
			OnProcessValidatorVote: func(vote consensus.VoteMessage) error {
				if !consensus.IsProperlyFormedVote(vote) {
					return errors.Errorf("Bad vote message")
				}

				if vote.GetView() != blockHeader.GetView() || !vote.GetPublicKey().Eq(blsPublicKey) {
					return errors.Errorf("Bad view or public key in vote message")
				}

				if !consensus.IsEqualBlockHash(vote.GetBlockHash(), blockHash) {
					return errors.Errorf("Bad tip block hash in vote message")
				}

				// Verify the vote's signature
				isValidSignature, err := BLSVerifyValidatorVote(blockHeader.GetView(), blockHash, vote.GetSignature(), blsPublicKey)
				if err != nil {
					return err
				}

				if !isValidSignature {
					return errors.Errorf("Bad signature in vote message")
				}

				return nil
			},
		},
	}

	// Test sad path with invalid event type
	{
		event := &consensus.FastHotStuffEvent{
			EventType: consensus.FastHotStuffEventTypeVote,
		}

		err := fastHotStuffConsensus.HandleLocalVoteEvent(event)
		require.Contains(t, err.Error(), "Received improperly formed vote event")
	}

	// Test happy path
	{
		event := &consensus.FastHotStuffEvent{
			EventType:      consensus.FastHotStuffEventTypeVote,
			View:           blockHeader.GetView(),
			TipBlockHeight: blockHeader.GetView(),
			TipBlockHash:   blockHash,
		}
		err := fastHotStuffConsensus.HandleLocalVoteEvent(event)
		require.NoError(t, err)
	}
}

func TestFastHotStuffConsensusHandleLocalTimeoutEvent(t *testing.T) {
	// Create a test private key for the signer
	blsPrivateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	blsPublicKey := blsPrivateKey.PublicKey()

	// Create a test block header with a valid QC
	blockHeader := createTestBlockHeaderVersion2(t, false)
	blockHash, err := blockHeader.Hash()
	require.NoError(t, err)

	// Compute the current and next views
	currentView := blockHeader.ValidatorsVoteQC.GetView() + 1
	nextView := currentView + 1

	blockIndex := NewBlockIndex(nil, nil)
	blockIndex.SetBlockIndexFromMap(map[BlockHash]*BlockNode{
		*blockHash: {Header: blockHeader},
	})

	// Create a mock consensus
	fastHotStuffConsensus := FastHotStuffConsensus{
		lock:           sync.RWMutex{},
		networkManager: _createMockNetworkManagerForConsensus(),
		signer: &BLSSigner{
			privateKey: blsPrivateKey,
		},
		params: &DeSoTestnetParams,
		blockchain: &Blockchain{
			ChainLock:  deadlock.RWMutex{},
			blockIndex: blockIndex,
			params:     &DeSoTestnetParams,
		},
		fastHotStuffEventLoop: &consensus.MockFastHotStuffEventLoop{
			OnIsInitialized: alwaysReturnTrue,
			OnIsRunning:     alwaysReturnTrue,
			OnGetCurrentView: func() uint64 {
				return currentView
			},
			OnAdvanceViewOnTimeout: func() (uint64, error) {
				return nextView, nil
			},
			OnProcessValidatorTimeout: func(timeout consensus.TimeoutMessage) error {
				if !consensus.IsProperlyFormedTimeout(timeout) {
					return errors.Errorf("Bad timeout message")
				}

				if timeout.GetView() != (blockHeader.ValidatorsVoteQC.GetView()+1) || !timeout.GetPublicKey().Eq(blsPublicKey) {
					return errors.Errorf("Bad view or public key in timeout message")
				}

				if timeout.GetHighQC().GetView() != blockHeader.ValidatorsVoteQC.GetView() {
					return errors.Errorf("Bad high QC in timeout message")
				}

				if !timeout.GetHighQC().GetAggregatedSignature().GetSignature().Eq(blockHeader.ValidatorsVoteQC.ValidatorsVoteAggregatedSignature.GetSignature()) {
					return errors.Errorf("Bad high QC in timeout message")
				}

				if timeout.GetHighQC().GetAggregatedSignature().GetSignersList() != blockHeader.ValidatorsVoteQC.ValidatorsVoteAggregatedSignature.GetSignersList() {
					return errors.Errorf("Bad high QC in timeout message")
				}

				// Verify the timeout's signature
				isValidSignature, err := BLSVerifyValidatorTimeout(currentView, blockHeader.ValidatorsVoteQC.GetView(), timeout.GetSignature(), blsPublicKey)
				if err != nil {
					return err
				}

				if !isValidSignature {
					return errors.Errorf("Bad signature in timeout message")
				}

				return nil
			},
		},
	}

	// Test sad path with invalid event type
	{
		event := &consensus.FastHotStuffEvent{
			EventType: consensus.FastHotStuffEventTypeVote,
		}

		err := fastHotStuffConsensus.HandleLocalTimeoutEvent(event)
		require.Contains(t, err.Error(), "Received improperly formed timeout event")
	}

	// Test sad path with stale view
	{
		event := &consensus.FastHotStuffEvent{
			EventType:      consensus.FastHotStuffEventTypeTimeout,
			View:           currentView - 1,
			TipBlockHeight: currentView - 1,
			TipBlockHash:   blockHash,
		}
		err := fastHotStuffConsensus.HandleLocalTimeoutEvent(event)
		require.Contains(t, err.Error(), "Stale timeout event")
	}

	// Test happy path
	{
		event := &consensus.FastHotStuffEvent{
			EventType:      consensus.FastHotStuffEventTypeTimeout,
			View:           currentView,
			TipBlockHeight: currentView,
			TipBlockHash:   blockHash,
		}
		err := fastHotStuffConsensus.HandleLocalTimeoutEvent(event)
		require.NoError(t, err)
	}
}

// Mock function that always returns true
func alwaysReturnTrue() bool {
	return true
}

func _createMockNetworkManagerForConsensus() *NetworkManager {
	return &NetworkManager{
		AllRemoteNodes:            collections.NewConcurrentMap[RemoteNodeId, *RemoteNode](),
		ValidatorOutboundIndex:    collections.NewConcurrentMap[bls.SerializedPublicKey, *RemoteNode](),
		ValidatorInboundIndex:     collections.NewConcurrentMap[bls.SerializedPublicKey, *RemoteNode](),
		NonValidatorOutboundIndex: collections.NewConcurrentMap[RemoteNodeId, *RemoteNode](),
		NonValidatorInboundIndex:  collections.NewConcurrentMap[RemoteNodeId, *RemoteNode](),
	}
}
