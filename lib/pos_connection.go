package lib

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/golang/glog"
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
	timeoutUnit  time.Duration
	retryCount   uint64

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
		timeoutUnit:    time.Second,
		exitChan:       make(chan bool),
		connectionChan: connectionChan,
	}
}

func (oca *OutboundConnectionAttempt) Start() {
	go oca.start()
}

func (oca *OutboundConnectionAttempt) start() {
	oca.retryCount = 0

out:
	for {
		sleepDuration := 0 * time.Second
		if oca.isPersistent {
			sleepDuration = _delayRetry(oca.retryCount, oca.netAddr, oca.timeoutUnit)
		}

		select {
		case <-oca.exitChan:
			break out
		case <-time.After(sleepDuration):
			// If the peer is persistent use exponential back off delay before retrying.
			// We want to start backing off exponentially once we've gone through enough
			// unsuccessful retries.
			if oca.isPersistent {
				oca.retryCount++
			}

			// If we don't have a persistentAddr, pick one from our addrmgr.
			conn := oca.attemptOutboundConnection()
			if conn == nil && oca.isPersistent {
				break
			}
			if conn == nil {
				break out
			}

			oca.connectionChan <- &outboundConnection{
				attemptId:    oca.attemptId,
				address:      oca.netAddr,
				connection:   conn,
				isPersistent: oca.isPersistent,
				failed:       false,
			}
			return
		}
	}
	oca.connectionChan <- &outboundConnection{
		attemptId:    oca.attemptId,
		address:      oca.netAddr,
		connection:   nil,
		isPersistent: oca.isPersistent,
		failed:       true,
	}
}

func (oca *OutboundConnectionAttempt) Stop() {
	close(oca.exitChan)
}

func (oca *OutboundConnectionAttempt) SetTimeoutUnit(timeoutUnit time.Duration) {
	oca.timeoutUnit = timeoutUnit
}

func (oca *OutboundConnectionAttempt) attemptOutboundConnection() net.Conn {
	// If the peer is not persistent, update the addrmgr.
	glog.V(1).Infof("Attempting to connect to addr: %v", oca.netAddr.IP.String())

	var err error
	tcpAddr := net.TCPAddr{
		IP:   oca.netAddr.IP,
		Port: int(oca.netAddr.Port),
	}
	conn, err := net.DialTimeout(tcpAddr.Network(), tcpAddr.String(), oca.dialTimeout)
	if err != nil {
		// If we failed to connect to this peer, get a new address and try again.
		glog.V(2).Infof("Connection to addr (%v) failed: %v", tcpAddr, err)
		return nil
	}

	return conn
}
