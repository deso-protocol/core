package lib

import (
	"bytes"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/glog"
	amqp "github.com/rabbitmq/amqp091-go"
)

// persistent connection and mutex
var (
	amqpConn  *amqp.Connection
	connMutex sync.Mutex
)

// Use an atomic flag where 0 means disabled and 1 means enabled.
var amqpPublisherEnabled int32
var amqpPublisherStarted int32

// EnablePublisher enables AMQP publishing after the node is fully synced.
func AmqpSetEnablePublisher() {
	atomic.StoreInt32(&amqpPublisherEnabled, 1)
}

func AmpqSetStartPublisher() {
	atomic.StoreInt32(&amqpPublisherStarted, 1)
}

func getAMQPConnection(amqpDest string) (*amqp.Connection, error) {
	connMutex.Lock()
	defer connMutex.Unlock()

	// Check if connection exists and is open.
	if amqpConn != nil && !amqpConn.IsClosed() {
		return amqpConn, nil
	}

	// Create a new connection.
	conn, err := amqp.Dial(amqpDest)
	if err != nil {
		return nil, err
	}
	amqpConn = conn
	return amqpConn, nil
}

func PublishBlockEvent(event *BlockEvent, amqpDest string) error {
	if amqpDest == "" {
		// AMQP integration is not enabled.
		return nil
	}
	if event == nil {
		glog.Infoln("event is nil, skipping AMQP publish.")
		return nil
	}
	if event.Block != nil {
		if event.Block.Txns != nil {
			glog.Infoln("BlockEvent %v", len(event.Block.Txns))
			channelName := "block_txns"
			push := true
			//setup node
			conn, err := getAMQPConnection(amqpDest)
			if err != nil {
				glog.Errorf("Failed to get AMQP connection: %v", err)
				return err
			}
			ch, err := conn.Channel()
			if err != nil {
				glog.Errorf("Failed to open an AMQP channel: %v", err)
				return err
			}
			defer ch.Close()

			for _, txn := range event.Block.Txns {
				if txn == nil {
					glog.Infoln("BlockEvent Tx is nil")
				} else {
					glog.Infoln("BlockEvent Tx %v", txn.Hash().String())

					txnType := txn.TxnMeta.GetTxnType()
					push = true

					//check tx, if it is a block reward or validator related, we skip it
					if txnType == TxnTypeBlockReward || txnType == TxnTypeRegisterAsValidator || txnType == TxnTypeUnregisterAsValidator || txnType == TxnTypeUnjailValidator || txnType == TxnTypeUpdateBitcoinUSDExchangeRate || txnType == TxnTypeSwapIdentity || txnType == TxnTypeUnset {
						push = false
					}

					if push {

						err = ch.Publish(
							"",          // default exchange
							channelName, // routing key (queue name)
							false,       // mandatory
							false,       // immediate
							amqp.Publishing{
								ContentType: "application/json",
								Body:        txn.MarshalJSON(),
								Timestamp:   time.Now(),
							},
						)
						if err != nil {
							glog.Errorf("Failed to publish message to AMQP: %v", err)
							return err
						}
					}
				}
			}
		} else {
			glog.Infoln("BlockEvent Txns is nil")
		}

	} else {
		glog.Infoln("BlockEvent block is nil")
	}

	return nil
}

// PublishStateChangeEvent publishes a state change event to AMQP.
// It uses the appropriate adapter based on the underlying encoder type.
func PublishStateChangeEvent(stateChangeEntry *StateChangeEntry, amqpDest string) error {
	if amqpDest == "" {
		// AMQP integration is not enabled.
		return nil
	}
	if stateChangeEntry == nil {
		glog.Infoln("StateChangeEntry is nil, skipping AMQP publish.")
		return nil
	}

	// Check to see if the index in question has a "core_state" annotation in its definition.
	if !isCoreStateKey(stateChangeEntry.KeyBytes) {
		return nil
	}

	channelName := "state_changes"
	push := true

	// Check if the event’s key bytes indicate that the stored value
	// is encoded using one of our DeSoEncoder types.
	var encoderType EncoderType

	if isEncoder, encoder := StateKeyToDeSoEncoder(stateChangeEntry.KeyBytes); isEncoder && encoder != nil {

		encoderType = encoder.GetEncoderType()
		//types we are not interested in
		if encoderType == EncoderTypeValidatorEntry || encoderType == EncoderTypeStakeRewardStateChangeMetadata || encoderType == EncoderTypeStakeEntry {
			return nil
		}
		// (For blocks, we may need to add extra metadata.)
		if encoderType == EncoderTypeBlock {
			stateChangeEntry.EncoderBytes = AddEncoderMetadataToMsgDeSoBlockBytes(stateChangeEntry.EncoderBytes, stateChangeEntry.BlockHeight)
		}
		if encoderType == EncoderTypeBlockNode {
			stateChangeEntry.EncoderBytes = AddEncoderMetadataToBlockNodeBytes(stateChangeEntry.EncoderBytes, stateChangeEntry.BlockHeight)
		}

		glog.Infof("State encoder event for %d", encoderType)
	} else {
		keyEncoder, err := DecodeStateKey(stateChangeEntry.KeyBytes, stateChangeEntry.EncoderBytes)
		if err != nil {
			glog.Infof("PublishStateChangeEvent: Error decoding state key: %v", err)
			// Instead of panicking, skip this event.
			return nil
		}
		if keyEncoder == nil {
			glog.Infof("PublishStateChangeEvent: No key encoder found, skipping event")
			return nil
		}
		encoderType = keyEncoder.GetEncoderType()
		glog.Infof("State event for %d", encoderType)
		stateChangeEntry.Encoder = keyEncoder
		stateChangeEntry.EncoderBytes = nil
	}
	stateChangeEntry.EncoderType = encoderType
	stateChangeEntry.EncoderBytes = EncodeToBytes(stateChangeEntry.BlockHeight, stateChangeEntry, false)
	var body []byte
	var err error

	// Here we try to decode the EncoderBytes into a known type and then use its adapter.
	if push {

		switch encoderType {
		// ----- ProfileEntry Example -----
		case EncoderTypeProfileEntry:
			var profile ProfileEntry
			r := bytes.NewReader(stateChangeEntry.EncoderBytes)
			if err = profile.RawDecodeWithoutMetadata(stateChangeEntry.BlockHeight, r); err != nil {
				glog.Infoln("failed to decode PostEntry: %v", err)
			}
			// Call the adapter.
			profileJSON := profile.ToJSON()
			body, err = json.Marshal(profileJSON)
			if err != nil {
				glog.Infoln("failed to marshal ProfileEntry JSON: %v", err)
			} else {
				glog.Infof("ProfileEntry endcoded")
			}

		// ----- PostEntry Example -----
		case EncoderTypePostEntry:
			var post PostEntry
			r := bytes.NewReader(stateChangeEntry.EncoderBytes)
			if err = post.RawDecodeWithoutMetadata(stateChangeEntry.BlockHeight, r); err != nil {
				glog.Infoln("failed to decode PostEntry: %v", err)
			}
			// Call the adapter.
			postJSON := post.ToJSON()
			body, err = json.Marshal(postJSON)
			if err != nil {
				glog.Infoln("failed to marshal PostEntry JSON: %v", err)
			} else {
				glog.Infof("PostEntry endcoded")
			}

		// ----- NFTEntry Example -----
		case EncoderTypeNFTEntry:
			var nft NFTEntry
			r := bytes.NewReader(stateChangeEntry.EncoderBytes)
			if err = nft.RawDecodeWithoutMetadata(stateChangeEntry.BlockHeight, r); err != nil {
				glog.Infoln("failed to decode NFTEntry: %v", err)
			}
			nftJSON := nft.ToJSON()
			body, err = json.Marshal(nftJSON)
			if err != nil {
				glog.Infoln("failed to marshal NFTEntry JSON: %v", err)
			}

		// ----- DAO Coin Limit Order Example -----
		// case EncoderTypeDAOCoinLimitOrderEntry:
		// 	var daoOrder DAOCoinLimitOrderEntry
		// 	r := bytes.NewReader(event.EncoderBytes)
		// 	if err = daoOrder.RawDecodeWithoutMetadata(event.BlockHeight, r); err != nil {
		// 		glog.Infoln("failed to decode DAOCoinLimitOrderEntry: %v", err)
		// 	}
		// 	daoJSON := daoOrder.ToJSON()
		// 	body, err = json.Marshal(daoJSON)
		// 	if err != nil {
		// 		glog.Infoln("failed to marshal DAOCoinLimitOrderEntry JSON: %v", err)
		// 	}

		// ----- DESO CoinEntry Example -----
		case EncoderTypeCoinEntry:
			var coinEntry CoinEntry
			r := bytes.NewReader(stateChangeEntry.EncoderBytes)
			if err = coinEntry.RawDecodeWithoutMetadata(stateChangeEntry.BlockHeight, r); err != nil {
				glog.Infoln("failed to decode CoinEntry: %v", err)
			}
			coinJSON := coinEntry.ToJSON()
			body, err = json.Marshal(coinJSON)
			if err != nil {
				glog.Infoln("failed to marshal CoinEntry JSON: %v", err)
			}

		// ----- DeSoBalanceEntry Example -----
		case EncoderTypeDeSoBalanceEntry:
			var balance DeSoBalanceEntry
			r := bytes.NewReader(stateChangeEntry.EncoderBytes)
			if err = balance.RawDecodeWithoutMetadata(stateChangeEntry.BlockHeight, r); err != nil {
				glog.Infoln("failed to decode DeSoBalanceEntry: %v", err)
			}
			balanceJSON := balance.ToJSON()
			body, err = json.Marshal(balanceJSON)
			if err != nil {
				glog.Infoln("failed to marshal DeSoBalanceEntry JSON: %v", err)
			}

		// ----- Fallback: Use raw bytes (or add more cases as needed) -----
		default:
			glog.Warningf("No adapter for encoder type %v; falling back to raw bytes", encoderType)
			body, err = json.Marshal(stateChangeEntry.EncoderBytes)
			if err != nil {
				glog.Infoln("failed to marshal raw event bytes: %v", err)
			}
		}
	} else {
		// If no encoder was detected, just marshal the raw EncoderBytes.
		body, err = json.Marshal(stateChangeEntry.EncoderBytes)
		if err != nil {
			glog.Infoln("failed to marshal raw event bytes: %v", err)
		}
	}

	// Now publish the JSON-encoded event.
	conn, err := getAMQPConnection(amqpDest)
	if err != nil {
		glog.Errorf("Failed to get AMQP connection: %v", err)
		return err
	}
	ch, err := conn.Channel()
	if err != nil {
		glog.Errorf("Failed to open an AMQP channel: %v", err)
		return err
	}
	defer ch.Close()

	err = ch.Publish(
		"",          // default exchange
		channelName, // routing key (queue name)
		false,       // mandatory
		false,       // immediate
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
			Timestamp:   time.Now(),
		},
	)
	if err != nil {
		glog.Errorf("Failed to publish message to AMQP: %v", err)
		return err
	}

	return nil
}
