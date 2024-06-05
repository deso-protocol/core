package lib

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/golang/glog"
	"net"
	"sync"
	"time"
)

// outboundConnection is used to store an established connection with a peer. It can also be used to signal that the
// connection was unsuccessful, in which case the failed flag is set to true. outboundConnection is created after an
// OutboundConnectionAttempt concludes. outboundConnection implements the Connection interface.
type outboundConnection struct {
	mtx        sync.Mutex
	terminated bool

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
	oc.mtx.Lock()
	defer oc.mtx.Unlock()

	if oc.terminated {
		return
	}
	if oc.connection != nil {
		oc.connection.Close()
	}
	oc.terminated = true
}

// inboundConnection is used to store an established connection with a peer. inboundConnection is created after
// an external peer connects to the node. inboundConnection implements the Connection interface.
type inboundConnection struct {
	mtx        sync.Mutex
	terminated bool

	connection net.Conn
}

func (ic *inboundConnection) GetConnectionType() ConnectionType {
	return ConnectionTypeInbound
}

func (ic *inboundConnection) Close() {
	ic.mtx.Lock()
	defer ic.mtx.Unlock()

	if ic.terminated {
		return
	}

	if ic.connection != nil {
		ic.connection.Close()
	}
	ic.terminated = true
}

// OutboundConnectionAttempt is used to store the state of an outbound connection attempt. It is used to initiate
// an outbound connection to a peer, and manage the lifecycle of the connection attempt.
type OutboundConnectionAttempt struct {
	mtx sync.Mutex

	// attemptId is used to identify the connection attempt. It will later be the id of the peer,
	// if the connection is successful.
	attemptId uint64

	// netAddr is the address of the peer we are attempting to connect to.
	netAddr *wire.NetAddress
	// isPersistent is used to indicate whether we should retry connecting to the peer if the connection attempt fails.
	// If isPersistent is true, we will retry connecting to the peer until we are successful. Each time such connection
	// fails, we will sleep according to exponential backoff. Otherwise, we will only attempt to connect to the peer once.
	isPersistent bool
	// dialTimeout is the amount of time we will wait before timing out an individual connection attempt.
	dialTimeout time.Duration
	// timeoutUnit is the unit of time we will use to calculate the exponential backoff delay. The initial timeout is
	// calculated as timeoutUnit * 2^0, the second timeout is calculated as timeoutUnit * 2^1, and so on.
	timeoutUnit time.Duration
	// retryCount is the number of times we have attempted to connect to the peer.
	retryCount uint64
	// connectionChan is used to send the result of the connection attempt to the caller thread.
	connectionChan chan *outboundConnection

	startGroup sync.WaitGroup
	exitChan   chan bool
	status     outboundConnectionAttemptStatus
}

type outboundConnectionAttemptStatus int

const (
	outboundConnectionAttemptInitialized outboundConnectionAttemptStatus = 0
	outboundConnectionAttemptRunning     outboundConnectionAttemptStatus = 1
	outboundConnectionAttemptTerminated  outboundConnectionAttemptStatus = 2
)

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
		status:         outboundConnectionAttemptInitialized,
	}
}

func (oca *OutboundConnectionAttempt) Start() {
	oca.mtx.Lock()
	defer oca.mtx.Unlock()

	if oca.status != outboundConnectionAttemptInitialized {
		return
	}

	oca.startGroup.Add(1)
	go oca.start()
	oca.startGroup.Wait()
	oca.status = outboundConnectionAttemptRunning
}

func (oca *OutboundConnectionAttempt) start() {
	oca.startGroup.Done()
	oca.retryCount = 0

out:
	for {
		sleepDuration := 0 * time.Second
		// for persistent peers, calculate the exponential backoff delay.
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
	oca.mtx.Lock()
	defer oca.mtx.Unlock()

	if oca.status == outboundConnectionAttemptTerminated {
		return
	}
	close(oca.exitChan)
	oca.status = outboundConnectionAttemptTerminated
}

func (oca *OutboundConnectionAttempt) SetTimeoutUnit(timeoutUnit time.Duration) {
	oca.timeoutUnit = timeoutUnit
}

// attemptOutboundConnection dials the peer. If the connection attempt is successful, it will return the connection.
// Otherwise, it will return nil.
func (oca *OutboundConnectionAttempt) attemptOutboundConnection() net.Conn {
	// If the peer is not persistent, update the addrmgr.
	glog.V(1).Infof("Attempting to connect to addr: %v:%v", oca.netAddr.IP.String(), oca.netAddr.Port)

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
