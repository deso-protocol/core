package lib

import (
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
			//glog.Infoln("BlockEvent %v", len(event.Block.Txns))
			channelName := "block_txns"
			push := true

			//setup connection
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
					//glog.Infoln("BlockEvent Tx %v", txn.Hash().String())

					txnType := txn.TxnMeta.GetTxnType()
					push = true

					//check tx, if it is a block reward or validator related, we skip it
					if txnType == TxnTypeBlockReward || txnType == TxnTypeRegisterAsValidator || txnType == TxnTypeUnregisterAsValidator || txnType == TxnTypeUnjailValidator || txnType == TxnTypeUpdateBitcoinUSDExchangeRate || txnType == TxnTypeSwapIdentity || txnType == TxnTypeUnset {
						push = false
					}

					if push {

						body, err := txn.MarshalJSON()
						if err != nil {
							glog.Errorf("Failed to marshal tx to json %v", err)
							return err
						}

						err = ch.Publish(
							"",          // default exchange
							channelName, // routing key (queue name)
							false,       // mandatory
							false,       // immediate
							amqp.Publishing{
								ContentType: "application/json",
								Body:        body,
								Timestamp:   time.Now(),
								MessageId:   txn.Hash().String(),
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
