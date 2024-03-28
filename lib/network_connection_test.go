package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"net"
	"sync"
	"testing"
	"time"
)

type simpleListener struct {
	t      *testing.T
	ll     net.Listener
	addr   *wire.NetAddress
	closed bool

	connectionChan chan Connection

	exitChan   chan struct{}
	startGroup sync.WaitGroup
	stopGroup  sync.WaitGroup
}

func newSimpleListener(t *testing.T) *simpleListener {
	require := require.New(t)
	ll, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	params := &DeSoTestnetParams
	addr := ll.Addr()
	addrMgr := addrmgr.New("", net.LookupIP)
	na, err := IPToNetAddr(addr.String(), addrMgr, params)

	return &simpleListener{
		t:              t,
		ll:             ll,
		addr:           na,
		closed:         false,
		connectionChan: make(chan Connection, 100),
		exitChan:       make(chan struct{}),
	}
}

func (sl *simpleListener) start() {
	require := require.New(sl.t)
	if sl.closed {
		ll, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%v", sl.addr.Port))
		require.NoError(err)
		sl.ll = ll
		sl.connectionChan = make(chan Connection, 100)
		sl.exitChan = make(chan struct{})
		sl.closed = false
	}
	sl.startGroup.Add(1)
	sl.stopGroup.Add(1)

	go func() {
		sl.startGroup.Done()
		defer sl.stopGroup.Done()
		for {
			select {
			case <-sl.exitChan:
				return
			default:
				conn, err := sl.ll.Accept()
				if err != nil {
					fmt.Println("simpleListener.start: ll.Accept:", err)
					return
				}
				// We use this only to limit maximum number of connections, when channel limit is reached.
				sl.connectionChan <- &inboundConnection{
					connection: conn,
				}
			}
		}
	}()
	sl.startGroup.Wait()
}

func (sl *simpleListener) stop() {
	sl.ll.Close()
	sl.closed = true
	close(sl.exitChan)
	close(sl.connectionChan)
	sl.stopGroup.Wait()
	fmt.Println("simpleListener.stop: stopped")
}

func (sl *simpleListener) getTCPAddr() *net.TCPAddr {
	return sl.ll.Addr().(*net.TCPAddr)
}

func verifyOutboundConnection(t *testing.T, conn *outboundConnection, sl *simpleListener, attemptId uint64, isPersistent bool, failed bool) {
	require := require.New(t)
	require.Equal(attemptId, conn.attemptId)
	require.Equal(isPersistent, conn.isPersistent)
	require.Equal(failed, conn.failed)
	if failed {
		require.Nil(conn.connection)
		return
	}

	require.Equal(conn.address.IP.String(), sl.getTCPAddr().IP.String())
	require.Equal(conn.address.Port, uint16(sl.getTCPAddr().Port))
	require.Equal(conn.address.IP.String(), sl.getTCPAddr().IP.String())
	require.Equal(conn.address.Port, uint16(sl.getTCPAddr().Port))
}

func verifyOutboundConnectionSelect(t *testing.T, connectionChan chan *outboundConnection, timeoutDuration time.Duration,
	sl *simpleListener, attemptId uint64, isPersistent bool, failed bool) {

	select {
	case conn := <-connectionChan:
		verifyOutboundConnection(t, conn, sl, attemptId, isPersistent, failed)
	case <-time.After(2 * timeoutDuration):
		panic("Timed out waiting for outbound connection.")
	}
}

func TestOutboundConnectionAttempt(t *testing.T) {
	require := require.New(t)
	_ = require
	timeoutDuration := 100 * time.Millisecond

	sl := newSimpleListener(t)
	sl.start()

	connectionChan := make(chan *outboundConnection, 100)
	attempt := NewOutboundConnectionAttempt(0, sl.addr, false, timeoutDuration, connectionChan)
	attempt.Start()
	verifyOutboundConnectionSelect(t, connectionChan, 2*timeoutDuration, sl, 0, false, false)
	t.Log("TestOutboundConnectionAttempt #1 | Happy path, non-persistent | PASS")

	sl.stop()
	attemptFailed := NewOutboundConnectionAttempt(1, sl.addr, false, timeoutDuration, connectionChan)
	attemptFailed.Start()
	verifyOutboundConnectionSelect(t, connectionChan, 2*timeoutDuration, sl, 1, false, true)
	t.Log("TestOutboundConnectionAttempt #2 | Failed connection, non-persistent | PASS")

	sl2 := newSimpleListener(t)
	sl2.start()

	attemptPersistent := NewOutboundConnectionAttempt(2, sl2.addr, true, timeoutDuration, connectionChan)
	attemptPersistent.Start()
	verifyOutboundConnectionSelect(t, connectionChan, 2*timeoutDuration, sl2, 2, true, false)
	t.Log("TestOutboundConnectionAttempt #3 | Happy path, persistent | PASS")

	sl2.stop()
	attemptPersistentDelay := NewOutboundConnectionAttempt(3, sl2.addr, true, timeoutDuration, connectionChan)
	attemptPersistentDelay.SetTimeoutUnit(timeoutDuration)
	attemptPersistentDelay.Start()
	time.Sleep(timeoutDuration)
	sl2.start()
	verifyOutboundConnectionSelect(t, connectionChan, 2*timeoutDuration, sl2, 3, true, false)
	require.Greater(attemptPersistentDelay.retryCount, uint64(0))
	t.Log("TestOutboundConnectionAttempt #4 | Failed connection, persistent, delayed | PASS")

	sl2.stop()
	attemptPersistentCancel := NewOutboundConnectionAttempt(4, sl2.addr, true, timeoutDuration, connectionChan)
	attemptPersistentCancel.Start()
	time.Sleep(timeoutDuration)
	attemptPersistentCancel.Stop()
	verifyOutboundConnectionSelect(t, connectionChan, 2*timeoutDuration, sl2, 4, true, true)
	require.Greater(attemptPersistentCancel.retryCount, uint64(0))
	t.Log("TestOutboundConnectionAttempt #5 | Failed connection, persistent, delayed, canceled | PASS")
}
