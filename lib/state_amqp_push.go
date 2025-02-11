package lib

import (
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

// PublishStateChangeEvent publishes a state change event to an AMQP broker.
// It returns an error if the publish fails.
func PublishStateChangeEvent(event *StateChangeEntry, amqpDest string) error {

	glog.Infoln("AMQP publish event")
	if amqpDest == "" {
		// AMQP integration is not enabled.
		return nil
	}

	if event == nil {
		glog.Infoln("StateChangeEntry is nil, skipping AMQP publish.")

		return nil
	}

	conn, err := getAMQPConnection(amqpDest)
	if err != nil {
		glog.Infoln("Failed to get AMQP connection: %v", err)

		return err
	}

	ch, err := conn.Channel()
	if err != nil {
		glog.Infoln("Failed to open an AMQP channel: %v", err)
		return err
	}
	defer ch.Close()

	// Check if we want to have another format if performance requires it.
	// Marshal the state change event into JSON.
	body, err := json.Marshal(event)
	if err != nil {
		glog.Infoln("Failed to marshal event to JSON: %v", err)
		return err
	}

	// Publish the message. Here, we’re using the default exchange and assuming the queue name is "state_changes".
	err = ch.Publish(
		"",              // default exchange
		"state_changes", // routing key (queue name)
		false,           // mandatory
		false,           // immediate
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
			Timestamp:   time.Now(),
		},
	)
	if err != nil {
		glog.Infoln("Failed to publish message to AMQP: %v", err)

		return err
	}
	return nil
}
