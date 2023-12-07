package lib

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/golang/glog"
	"math"
	"net"
	"time"
)

type outboundConnection struct {
	attemptId    uint64
	address      *wire.NetAddress
	connection   net.Conn
	isPersistent bool
	failed       bool
}

func (oc *outboundConnection) GetConnectionType() ConnectionType {
	return ConnectionTypeOutbound
}

func (oc *outboundConnection) Close() {
	oc.connection.Close()
}

type inboundConnection struct {
	connection net.Conn
}

func (ic *inboundConnection) GetConnectionType() ConnectionType {
	return ConnectionTypeInbound
}

func (ic *inboundConnection) Close() {
	ic.connection.Close()
}

type OutboundConnectionAttempt struct {
	attemptId uint64

	netAddr      *wire.NetAddress
	isPersistent bool
	dialTimeout  time.Duration

	exitChan       chan bool
	connectionChan chan *outboundConnection
}

func NewOutboundConnectionAttempt(attemptId uint64, netAddr *wire.NetAddress, isPersistent bool,
	dialTimeout time.Duration, connectionChan chan *outboundConnection) *OutboundConnectionAttempt {

	return &OutboundConnectionAttempt{
		attemptId:      attemptId,
		netAddr:        netAddr,
		isPersistent:   isPersistent,
		dialTimeout:    dialTimeout,
		exitChan:       make(chan bool),
		connectionChan: connectionChan,
	}
}

func (aoc *OutboundConnectionAttempt) Start() {
	go aoc.start()
}

func (aoc *OutboundConnectionAttempt) start() {
	retryCount := 0

out:
	for {
		sleepDuration := 0 * time.Second
		if aoc.isPersistent {
			sleepDuration = _delayRetry(retryCount, aoc.netAddr)
		}

		select {
		case <-aoc.exitChan:
			break out
		case <-time.After(sleepDuration):
			// If the peer is persistent use exponential back off delay before retrying.
			// We want to start backing off exponentially once we've gone through enough
			// unsuccessful retries.
			if aoc.isPersistent {
				retryCount++
			}

			// If we don't have a persistentAddr, pick one from our addrmgr.
			conn := aoc.attemptOutboundConnection()
			if conn == nil {
				break out
			}

			aoc.connectionChan <- &outboundConnection{
				attemptId:    aoc.attemptId,
				address:      aoc.netAddr,
				connection:   conn,
				isPersistent: aoc.isPersistent,
			}
			return
		}
	}
	aoc.connectionChan <- &outboundConnection{
		attemptId: aoc.attemptId,
		address:   aoc.netAddr,
		failed:    true,
	}
}

func (aoc *OutboundConnectionAttempt) Stop() {
	close(aoc.exitChan)
}

func (aoc *OutboundConnectionAttempt) attemptOutboundConnection() net.Conn {
	// If the peer is not persistent, update the addrmgr.
	glog.V(1).Infof("Attempting to connect to addr: %v", aoc.netAddr.IP.String())

	var err error
	tcpAddr := net.TCPAddr{
		IP:   aoc.netAddr.IP,
		Port: int(aoc.netAddr.Port),
	}
	conn, err := net.DialTimeout(tcpAddr.Network(), tcpAddr.String(), aoc.dialTimeout)
	if err != nil {
		// If we failed to connect to this peer, get a new address and try again.
		glog.V(2).Infof("Connection to addr (%v) failed: %v", tcpAddr, err)
		return nil
	}

	return conn
}

func _delayRetry(retryCount int, persistentAddrForLogging *wire.NetAddress) (_retryDuration time.Duration) {
	// No delay if we haven't tried yet or if the number of retries isn't positive.
	if retryCount <= 0 {
		return time.Second
	}
	numSecs := int(math.Pow(2.0, float64(retryCount)))
	retryDelay := time.Duration(numSecs) * time.Second

	if persistentAddrForLogging != nil {
		glog.V(1).Infof("Retrying connection to outbound persistent peer: "+
			"(%s:%d) in (%d) seconds.", persistentAddrForLogging.IP.String(),
			persistentAddrForLogging.Port, numSecs)
	} else {
		glog.V(2).Infof("Retrying connection to outbound non-persistent peer in (%d) seconds.", numSecs)
	}
	return retryDelay
}
