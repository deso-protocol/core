package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgraph-io/badger/v3"
	merkletree "github.com/laser/go-merkle-tree"
	"github.com/pkg/errors"

	"github.com/btcsuite/btcd/addrmgr"
	btcdchain "github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/go-socks/socks"
	"github.com/golang/glog"
	deadlock "github.com/sasha-s/go-deadlock"
)

// bitcoin_manager.go handles all of the logic around connecting to Bitcoin nodes
// and downloading the Bitcoin header chain. Once it has a header chain with enough
// work on it, it notifies the Server, which takes things from there. In addition to
// syncing the header chain, the bitcoin_manager also downloads any new Bitcoin blocks
// as they are mined and searches their transactions for any that send money to the
// burn address. A good place to start in this file is _startSync() and _loop().

var (
	// Note: Can be updated by various functions. It's a global variable sorry.
	// TODO: We can turn this into a struct if we have more command-specific timeouts
	// and pass it as an argument down the call stack.
	BitcoinGetHeadersTimeout    = 3 * time.Second
	BitcoinHeaderUpdateInterval = 5 * time.Second
)

type ExpectedBitcoinResponse struct {
	TimeExpected time.Time
	Command      string
}

type BroadcastTxn struct {
	Txn *wire.MsgTx
	// Keep track of the time added in case we want to expire broadcast transactions
	// after some time.
	TimeAdded time.Time
	// Indicates whether the transaction has ever been broadcast to a peer.
	WasBroadcast bool
}

type SwitchPeerMsg struct {
	NewAddr   string
	ReplyChan chan error
}

type BitcoinManager struct {
	db         *badger.DB
	params     *BitCloutParams
	timeSource btcdchain.MedianTimeSource

	btcDataDir string

	// The connection we're currently downloading headers from.
	syncConn net.Conn

	// Channel we send updates on. This helps notify whoever is interested
	// whenever a block is added or we do a reorg. Can also be used to send
	// BtcExchange transactions that get fashioned out of Bitcoin blocks.
	updateChan chan *ServerMessage

	// Used to select a node to download headers from.
	addrMgr *addrmgr.AddrManager

	// These should only be accessed after acquiring the BitcoinManagerLock.
	//
	// headerIndex contains a reference to all Bitcoin headers we've downloaded including
	// ones that are not on the main chain.
	BitcoinHeaderIndexLock deadlock.RWMutex
	headerIndex            map[BlockHash]*BlockNode
	// bestHeaderChain is a slice of sequential Bitcoin headers on the main chain.
	bestHeaderChain []*BlockNode
	// bestHeaderChainMap is a map of all of the Bitcoin headers on the main chain.
	bestHeaderChainMap map[BlockHash]*BlockNode

	ExpectedResponsesLock deadlock.RWMutex
	expectedResponses     []*ExpectedBitcoinResponse

	// A channel that services outside the BitcoinManager can use to broadcast
	// transactions. Adding a transaction to this channel will cause it to get
	// broadcast to the currently active Peer if one is set. This is a best-effort
	// process.
	broadcastBitcoinTxnChan chan *wire.MsgTx

	// A channel that can be used to request a particular Bitcoin transaction from
	// a peer. Note that Bitcoin nodes generally only provide mempool txns through
	// this endpoint.
	requestTxnChan chan chainhash.Hash

	// A channel that services outside the BitcoinManager can use to request that
	// a particular Bitcoin block be downloaded from a Peer and processed by the
	// BitcoinManager.
	requestBlockChan chan chainhash.Hash

	// A channel that takes new <IP>:<Port> strings to connect to. When an address
	// is found on this channel, the existing peer is dropped and a new peer is
	// connected to. If a connection to the new peer fails then the switch is not
	// completed.
	SwitchPeerChan chan *SwitchPeerMsg

	// When set, the BitcoinManager connects directly to this peer and doesn't
	// consider connecting to any other peers.
	connectPeer string
}

func (bm *BitcoinManager) GetAddrManager() *addrmgr.AddrManager {
	return bm.addrMgr
}

func (bm *BitcoinManager) SyncConn() net.Conn {
	return bm.syncConn
}

func (bm *BitcoinManager) ResetBitcoinHeaderIndex() error {
	bm.BitcoinHeaderIndexLock.Lock()
	defer bm.BitcoinHeaderIndexLock.Unlock()

	return bm._resetBitcoinHeaderIndex()
}

func (bm *BitcoinManager) _resetBitcoinHeaderIndex() error {
	// Delete any nodes that exist in the db. We check for this by checking to see
	// if a BestHash is set.
	bestHash := DbGetBestHash(bm.db, ChainTypeBitcoinHeader)
	if bestHash != nil {
		// TODO: Make this code less race-ey. I think if you stop the node during the point
		// at which it's deleting nodes you could put the db in an unworkable state. Not a
		// big deal, but annoying for the user because she may have to reset everything.
		headerIndex, err := GetBlockIndex(bm.db, true /*bitcoinNodes*/)
		if err != nil {
			return errors.Wrapf(err, "BitcoinManager._resetBitcoinHeaderIndex: Problem "+
				"loading existing Bitcoin node index: ")
		}
		nodesToDelete := []*BlockNode{}
		for _, node := range headerIndex {
			nodesToDelete = append(nodesToDelete, node)
		}
		if err := DbBulkDeleteHeightHashToNodeInfo(
			nodesToDelete, bm.db, true /*bitcoinNodes*/); err != nil {

			return errors.Wrapf(err, "BitcoinManager._resetBitcoinHeaderIndex: Problem "+
				"deleting existing nodes from the db: %v", nodesToDelete)
		}
	}

	// Put the start node in the HeightHashToNodeInfo index.
	//   <height uin32, blockhash BlockHash> -> <node info>
	if err := bm._writeBitcoinNodeToDB(bm.params.BitcoinStartBlockNode); err != nil {
		return errors.Wrapf(err,
			"BitcoinManager.NewBitcoinManager: Problem calling  _writeBitcoinNodeToDB"+
				"for start node %v: ", bm.params.BitcoinStartBlockNode)
	}

	// Put the start node's hash as the best hash.
	if err := PutBestHash(bm.params.BitcoinStartBlockNode.Hash,
		bm.db, ChainTypeBitcoinHeader); err != nil {

		return errors.Wrapf(err, "BitcoinManager.NewBitcoinManager: Problem "+
			"putting best hash for start node: %v", bm.params.BitcoinStartBlockNode)
	}

	// No locks acquired because caller needs to acquire it.
	bm.headerIndex[*bm.params.BitcoinStartBlockNode.Hash] = bm.params.BitcoinStartBlockNode
	bm.bestHeaderChain = []*BlockNode{bm.params.BitcoinStartBlockNode}
	bm.bestHeaderChainMap[*bm.params.BitcoinStartBlockNode.Hash] = bm.params.BitcoinStartBlockNode

	return nil
}

func (bm *BitcoinManager) SetHeaderIndexAndBestChainListMap(
	bestChain []*BlockNode, headerIndex map[BlockHash]*BlockNode) {

	bm.BitcoinHeaderIndexLock.Lock()
	defer bm.BitcoinHeaderIndexLock.Unlock()

	bm.bestHeaderChain = bestChain
	bm.headerIndex = headerIndex
	for _, bestChainNode := range bm.bestHeaderChain {
		bm.bestHeaderChainMap[*bestChainNode.Hash] = bestChainNode
	}
}

func NewBitcoinManager(_db *badger.DB, _params *BitCloutParams,
	_timeSource btcdchain.MedianTimeSource, _btcDataDir string,
	_updateChan chan *ServerMessage, _connectPeer string) (

	*BitcoinManager, error) {

	bm := &BitcoinManager{
		db:                      _db,
		params:                  _params,
		timeSource:              _timeSource,
		btcDataDir:              _btcDataDir,
		updateChan:              _updateChan,
		addrMgr:                 addrmgr.New(_btcDataDir, net.LookupIP),
		headerIndex:             make(map[BlockHash]*BlockNode),
		bestHeaderChain:         []*BlockNode{},
		bestHeaderChainMap:      make(map[BlockHash]*BlockNode),
		broadcastBitcoinTxnChan: make(chan *wire.MsgTx),
		requestBlockChan:        make(chan chainhash.Hash),
		requestTxnChan:          make(chan chainhash.Hash),
		SwitchPeerChan:          make(chan *SwitchPeerMsg),
		connectPeer:             _connectPeer,
	}

	// Get the best hash we're currently aware of. If it doesn't exist, initialize
	// the db with the start node.
	bestHash := DbGetBestHash(bm.db, ChainTypeBitcoinHeader)
	if bestHash == nil {
		// If there's no best hash set, reset the db and set the best hash to be the
		// new tip.
		if err := bm.ResetBitcoinHeaderIndex(); err != nil {
			return nil, errors.Wrapf(err, "BitcoinManager.NewBitcoinManager: Problem "+
				"initializing header index: ")
		}

	} else {
		// At this point we are confident that a best hash and a best chain exist in our
		// database so get them.
		headerIndex, err := GetBlockIndex(bm.db, true /*bitcoinNodes*/)
		if err != nil {
			return nil, errors.Wrapf(err, "BitcoinManager.NewBitcoinManager: Problem "+
				"loading Bitcoin node index: ")
		}
		bestNode, bestNodeExists := headerIndex[*bestHash]
		if !bestNodeExists {
			return nil, fmt.Errorf("BitcoinManager.NewBitcoinManager: Problem: Best hash "+
				"%v is not present in header index, which has %d items in it",
				bestHash, len(headerIndex))
		}

		// Set the header index and the best chain list and map.
		bestChain, err := GetBestChain(bestNode, headerIndex)
		if err != nil {
			return nil, errors.Wrapf(err, "BitcoinManager.NewBitcoinManager: Problem getting "+
				"best chain for node %v: ", bestNode)
		}

		// Note the headerIndex might have some non-main-chain blocks in it that we need
		// to exclude when setting the bestChainMap.
		bm.SetHeaderIndexAndBestChainListMap(bestChain, headerIndex)
	}

	return bm, nil
}

func (bm *BitcoinManager) HeaderTip() *BlockNode {
	bm.BitcoinHeaderIndexLock.RLock()
	defer bm.BitcoinHeaderIndexLock.RUnlock()

	return bm._headerTip()
}

func (bm *BitcoinManager) _headerTip() *BlockNode {
	return bm.bestHeaderChain[len(bm.bestHeaderChain)-1]
}

// _newNetAddress attempts to extract the IP address and port from the passed
// net.Addr interface and create a bitcoin NetAddress structure using that
// information.
func _newNetAddress(addr net.Addr, services wire.ServiceFlag) (*wire.NetAddress, error) {
	// addr will be a net.TCPAddr when not using a proxy.
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		ip := tcpAddr.IP
		port := uint16(tcpAddr.Port)
		na := wire.NewNetAddressIPPort(ip, port, services)
		return na, nil
	}

	// addr will be a socks.ProxiedAddr when using a proxy.
	if proxiedAddr, ok := addr.(*socks.ProxiedAddr); ok {
		ip := net.ParseIP(proxiedAddr.Host)
		if ip == nil {
			ip = net.ParseIP("0.0.0.0")
		}
		port := uint16(proxiedAddr.Port)
		na := wire.NewNetAddressIPPort(ip, port, services)
		return na, nil
	}

	// For the most part, addr should be one of the two above cases, but
	// to be safe, fall back to trying to parse the information from the
	// address string as a last resort.
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	na := wire.NewNetAddressIPPort(ip, uint16(port), services)
	return na, nil
}

// writeMessage sends a bitcoin message to the peer with logging.
func (bm *BitcoinManager) writeMessage(conn net.Conn, msg wire.Message, params *BitCloutParams) error {
	_, err := wire.WriteMessageWithEncodingN(conn, msg,
		params.BitcoinProtocolVersion, wire.BitcoinNet(params.BitcoinBtcdParams.Net),
		wire.BaseEncoding)
	if err != nil {
		return err
	}

	// The following messages require a prompt response.
	if msg.Command() == "getheaders" {
		bm._addExpectedResponse("headers", time.Now().Add(BitcoinGetHeadersTimeout))
	}
	return err
}

func (bm *BitcoinManager) readMessage(conn net.Conn, params *BitCloutParams) (wire.Message, []byte, error) {
	_, msg, buf, err := wire.ReadMessageWithEncodingN(conn,
		params.BitcoinProtocolVersion, wire.BitcoinNet(params.BitcoinBtcdParams.Net),
		wire.BaseEncoding)
	if err != nil {
		return nil, nil, err
	}

	// The following messages allow us to dequeue an expected response.
	if msg.Command() == "headers" {
		bm._removeEarliestExpectedResponse(msg.Command())
	}

	return msg, buf, nil
}

// _minUint32 is a helper function to return the minimum of two uint32s.
// This avoids a math import and the need to cast to floats.
func _minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// readRemoteVersionMsg waits for the next message to arrive from the remote
// peer.  If the next message is not a version message or the version is not
// acceptable then return an error.
func (bm *BitcoinManager) readRemoteVersionMsg(conn net.Conn, params *BitCloutParams) (_minVersion uint32, _err error) {
	// Read their version message.
	remoteMsg, _, err := bm.readMessage(conn, params)
	if err != nil {
		return 0, err
	}

	// Notify and disconnect clients if the first message is not a version
	// message.
	msg, ok := remoteMsg.(*wire.MsgVersion)
	if !ok {
		return 0, fmt.Errorf("BitcoinManager.readRemoteVersionMsg: First message received was not a version message")
	}
	advertisedProtoVer := uint32(msg.ProtocolVersion)
	minVersion := _minUint32(params.BitcoinProtocolVersion, advertisedProtoVer)
	if msg.Services&wire.SFNodeNetwork == 0 {
		return 0, fmt.Errorf("BitcoinManager.readRemoteVersionMsg: Full node is required as sync peer")
	}

	return minVersion, nil
}

// localVersionMsg creates a version message that can be used to send to the
// remote peer.
func localVersionMsg(conn net.Conn, tipHeight int32, params *BitCloutParams) (*wire.MsgVersion, error) {
	theirNA, err := _newNetAddress(conn.RemoteAddr(), wire.SFNodeNetwork)
	if err != nil {
		return nil, err
	}

	// Create a wire.NetAddress with only the services set to use as the
	// "addrme" in the version message.
	//
	// Older nodes previously added the IP and port information to the
	// address manager which proved to be unreliable as an inbound
	// connection from a peer didn't necessarily mean the peer itself
	// accepted inbound connections.
	//
	// Also, the timestamp is unused in the version message.
	ourNA := &wire.NetAddress{
		Services: 0,
	}

	// Generate a unique nonce for this peer so self connections can be
	// detected. This is accomplished by adding it to a size-limited map of
	// recently seen nonces.
	nonce := uint64(mrand.Int63())

	// Version message.
	msg := wire.NewMsgVersion(ourNA, theirNA, nonce, tipHeight)
	msg.AddUserAgent(params.UserAgent, "1.0", []string{}...)

	// Advertise local services.
	msg.Services = 0

	// Advertise our max supported protocol version.
	msg.ProtocolVersion = int32(params.BitcoinProtocolVersion)

	// Advertise if inv messages for transactions are desired.
	// We don't want inv messages from our Bitcoin peer.
	msg.DisableRelayTx = true

	return msg, nil
}

func (bm *BitcoinManager) AddSeeds() {
	// These constants are used by the DNS seed code to pick a random last
	// seen time.
	secondsIn3Days := int32(24 * 60 * 60 * 3)
	secondsIn4Days := int32(24 * 60 * 60 * 4)

	glog.Debugf("BitcoinManager.AddSeeds: Starting DNS discovery...")
	for _, dnsseed := range bm.params.BitcoinDNSSeeds {
		host := dnsseed
		go func(host string) {
			randSource := mrand.New(mrand.NewSource(time.Now().UnixNano()))

			glog.Tracef("BitcoinManager.AddSeeds: Calling LookupIP on %s", host)
			seedpeers, err := net.LookupIP(host)
			if err != nil {
				glog.Tracef("BitcoinManager.AddSeeds: DNS discovery failed on seed %s: %v", host, err)
				return
			}
			numPeers := len(seedpeers)

			glog.Tracef("BitcoinManager.AddSeeds: %d addresses found from DNS seed %s", numPeers, host)

			if numPeers == 0 {
				return
			}
			addresses := make([]*wire.NetAddress, len(seedpeers))
			// if this errors then we have *real* problems
			intPort, _ := strconv.Atoi(bm.params.BitcoinDefaultPort)
			for i, peer := range seedpeers {
				addresses[i] = wire.NewNetAddressTimestamp(
					// bitcoind seeds with addresses from
					// a time randomly selected between 3
					// and 7 days ago.
					time.Now().Add(-1*time.Second*time.Duration(secondsIn3Days+
						randSource.Int31n(secondsIn4Days))),
					0, peer, uint16(intPort))
			}

			glog.Tracef("BitcoinManager.AddSeeds: Adding %d addresses to addrmgr for host %s",
				len(addresses), host)
			if len(addresses) > 0 {
				bm.addrMgr.AddAddresses(addresses, addresses[0])
				//bm.addrMgr.AddAddressesRelaxed(addIPNetAddrs, addIPNetAddrs[0])
			}
		}(host)
	}
}

func _getRandomPeer(addrMgr *addrmgr.AddrManager, dialTimeout time.Duration) (net.Conn, *wire.NetAddress) {
	glog.Debugf("BitcoinManager.startSync: Trying to find Bitcoin address to connect to")
	// Choose a random Peer from the address manager.
	randomAddr := addrMgr.GetAddress()
	if randomAddr == nil {
		glog.Debugf("BitcoinManager.startSync: No Bitcoin address found to connect to.")
		return nil, nil
	}
	glog.Debugf("BitcoinManager.startSync: Found address to connect to!")

	// If we get here we found a random address to try.
	ipNetAddr := randomAddr.NetAddress()

	netAddr := net.TCPAddr{
		IP:   ipNetAddr.IP,
		Port: int(ipNetAddr.Port),
	}

	// Update the addrmgr with the fact that we're attempting this address.
	glog.Debugf("BitcoinManager.startSync: Attempting to connect to addr: %v", netAddr)
	addrMgr.Attempt(ipNetAddr)

	var err error
	conn, err := net.DialTimeout(netAddr.Network(), netAddr.String(), dialTimeout)
	if err != nil {
		// If we failed to connect to this peer, get a new address and try again.
		glog.Debugf("BitcoinManager.startSync: Connection to addr (%v) failed: %v", netAddr, err)
		return nil, nil
	}

	// We were able to dial successfully so we'll break out now.
	glog.Debugf("BitcoinManager.startSync: Connected to addr: %v", conn.RemoteAddr().String())

	// Mark the address as connected in the addrmgr.
	addrMgr.Connected(ipNetAddr)

	return conn, ipNetAddr
}

func (bm *BitcoinManager) _negotiateVersion(conn net.Conn, height int32, params *BitCloutParams) error {
	// Send the Peer a version message and wait for a response.
	// If the response is positive, then start downloading headers from the Peer.
	// If not, then continue and try the whole process over again.
	glog.Debugf("BitcoinManager.startSync: Writing version message: %v", conn.RemoteAddr().String())
	verMsg, err := localVersionMsg(conn, height, params)
	if err != nil {
		errorMsg := "BitcoinManager.startSync: Problem writing version message"
		glog.Debugf(errorMsg)
		return fmt.Errorf(errorMsg)
	}
	bm.writeMessage(conn, verMsg, params)

	readVersionChan := make(chan error)
	go func() {
		_, err := bm.readRemoteVersionMsg(conn, params)
		readVersionChan <- err
	}()

	// Negotiate the protocol within the specified negotiateTimeout.
	glog.Debugf("BitcoinManager.startSync: Waiting for version response: %v", conn.RemoteAddr().String())
	select {
	case err := <-readVersionChan:
		if err != nil {
			// If we have an error reading the version, sleep and try again
			// with a new Peer.
			errorMsg := fmt.Sprintf("BitcoinManager.startSync: Error in version response for "+
				"addr %v: %v. Sleeping and trying another address.",
				conn.RemoteAddr().String(), err)
			glog.Debugf(errorMsg)
			return fmt.Errorf(errorMsg)
		}
	case <-time.After(params.DialTimeout):
		// Same goes for if we time out.
		errorMsg := fmt.Sprintf("BitcoinManager.startSync: Version response timeout for addr %v. "+
			"Sleeping and trying another address.", conn.RemoteAddr().String())
		glog.Debugf(errorMsg)
		return fmt.Errorf(errorMsg)
	}
	glog.Debugf("BitcoinManager.startSync: Connected to Bitcoin peer: %s", conn.RemoteAddr())

	// Send a verack to the peer.
	glog.Debugf("BitcoinManager.startSync: Writing verack: %s.", conn.RemoteAddr().String())
	bm.writeMessage(conn, wire.NewMsgVerAck(), params)

	// If we get here we should have completed a successful Bitcoin version
	// negotiation with the Peer.
	glog.Debugf("BitcoinManager.startSync: Version negotiation with addr complete: %s.",
		conn.RemoteAddr().String())

	return nil
}

func _difficultyBitsToHash(diffBits uint32) (_diffHash *BlockHash) {
	diffBigint := btcdchain.CompactToBig(diffBits)
	return BigintToHash(diffBigint)
}

func _difficultyHashToBits(diffHash *BlockHash) (_diffBits uint32) {
	diffBigint := HashToBigint(diffHash)
	return btcdchain.BigToCompact(diffBigint)
}

// findPrevTestNetDifficulty returns the difficulty of the previous block which
// did not have the special testnet minimum difficulty rule applied.
//
// This function MUST be called with the chain state lock held (for writes).
func _findPrevTestNetDifficulty(startNode *BlockNode, params *BitCloutParams) *BlockHash {
	powLimitHash := _difficultyBitsToHash(params.BitcoinPowLimitBits)

	// Search backwards through the chain for the last block without
	// the special rule applied.
	iterNode := startNode
	// The node stores a difficulty block hash.
	// Convert it to bigint.
	// Convert the bigint to bits.
	for iterNode != nil && iterNode.Height%params.BitcoinBlocksPerRetarget != 0 &&
		*iterNode.DifficultyTarget == *powLimitHash {

		iterNode = iterNode.Parent
	}

	// Return the found difficulty or the minimum difficulty if no
	// appropriate block was found.
	lastDiffHash := powLimitHash
	if iterNode != nil {
		lastDiffHash = iterNode.DifficultyTarget
	}
	return lastDiffHash
}

// _calcNextRequiredDifficulty calculates the required difficulty for the block
// after the passed previous block node based on the difficulty retarget rules.
// This function differs from the exported CalcNextRequiredDifficulty in that
// the exported version uses the current best chain as the previous block node
// while this function accepts any block node.
func _calcNextRequiredDifficulty(lastNode *BlockNode, newBlockTime time.Time, params *BitCloutParams) (*BlockHash, error) {
	// Genesis block.
	if lastNode == nil {
		return _difficultyBitsToHash(params.BitcoinPowLimitBits), nil
	}

	// Return the previous block's difficulty requirements if this block
	// is not at a difficulty retarget interval.
	if (lastNode.Height+1)%params.BitcoinBlocksPerRetarget != 0 {
		// For networks that support it, allow special reduction of the
		// required difficulty once too much time has elapsed without
		// mining a block.
		if params.BitcoinMinDiffReductionTime != 0 {
			// Return minimum difficulty when more than the desired
			// amount of time has elapsed without mining a block.
			reductionTimeSecs := int64(params.BitcoinMinDiffReductionTime /
				time.Second)
			allowMinTime := int64(lastNode.Header.TstampSecs) + reductionTimeSecs
			if newBlockTime.Unix() > allowMinTime {
				return _difficultyBitsToHash(params.BitcoinPowLimitBits), nil
			}

			// The block was mined within the desired timeframe, so
			// return the difficulty for the last block which did
			// not have the special minimum difficulty rule applied.
			return _findPrevTestNetDifficulty(lastNode, params), nil
		}

		// For the main network (or any unrecognized networks), simply
		// return the previous block's difficulty requirements.
		return lastNode.DifficultyTarget, nil
	}

	// Get the block node at the previous retarget (targetTimespan days
	// worth of blocks).
	firstNode := lastNode.RelativeAncestor(params.BitcoinBlocksPerRetarget - 1)
	if firstNode == nil {
		return nil, fmt.Errorf("_calcNextRequiredDifficulty: Unable to obtain previous retarget block")
	}

	// Limit the amount of adjustment that can occur to the previous
	// difficulty.
	actualTimespan := uint32(lastNode.Header.TstampSecs - firstNode.Header.TstampSecs)
	adjustedTimespan := actualTimespan
	if actualTimespan < params.BitcoinMinRetargetTimespanSecs {
		adjustedTimespan = params.BitcoinMinRetargetTimespanSecs
	} else if actualTimespan > params.BitcoinMaxRetargetTimespanSecs {
		adjustedTimespan = params.BitcoinMaxRetargetTimespanSecs
	}

	// Calculate new target difficulty as:
	//  currentDifficulty * (adjustedTimespan / targetTimespan)
	// The result uses integer division which means it will be slightly
	// rounded down.  Bitcoind also uses integer division to calculate this
	// result.
	oldTarget := HashToBigint(lastNode.DifficultyTarget)
	newTarget := new(big.Int).Mul(oldTarget, big.NewInt(int64(adjustedTimespan)))
	newTarget.Div(newTarget, big.NewInt(int64(params.BitcoinTargetTimespanSecs)))

	// Limit new value to the proof of work limit.
	powLimitBigint := btcdchain.CompactToBig(params.BitcoinPowLimitBits)
	if newTarget.Cmp(powLimitBigint) > 0 {
		newTarget.Set(powLimitBigint)
	}

	// Convert the hash to bits so we lose the precision (yes *lose*) and then
	// go back.
	newTargetHash := BigintToHash(newTarget)
	newTargetBits := _difficultyHashToBits(newTargetHash)

	return _difficultyBitsToHash(newTargetBits), nil
}

// ProcessBitcoinHeaderQuick processes a Bitcoin header without checking its proof
// of work, leaving that to be done in a later post-processing step.
//
// Holds the BitcoinHeaderIndexLock for writing.
func (bm *BitcoinManager) ProcessBitcoinHeaderQuick(bitcoinHeader *wire.BlockHeader, params *BitCloutParams) (
	_isMainChain bool, _isOrphan bool, _err error) {
	bm.BitcoinHeaderIndexLock.Lock()
	defer bm.BitcoinHeaderIndexLock.Unlock()

	headerHash := (BlockHash)(bitcoinHeader.BlockHash())
	parentHash := (BlockHash)(bitcoinHeader.PrevBlock)

	// Reject the header if it is more than N seconds in the future.
	tstampDiff := bitcoinHeader.Timestamp.Unix() - bm.timeSource.AdjustedTime().Unix()
	if tstampDiff > int64(params.BitcoinMaxTstampOffsetSeconds) {
		return false, false, HeaderErrorBlockTooFarInTheFuture
	}

	parentNode, parentNodeExists := bm.headerIndex[parentHash]
	if !parentNodeExists {
		// This block is an orphan if its parent doesn't exist and we don't
		// process unconnectedTxns.
		return false, true, nil
	}

	// Verify that the parent node is the tip.
	if *parentNode.Hash != *bm._headerTip().Hash {
		return false, false, fmt.Errorf("BitcoinManager.ProcessBitcoinHeaderQuick: "+
			"Processing header %v with height %v with parent %v that is not equal to the current "+
			"tip %v; this should never happen",
			bitcoinHeader, parentNode.Height+1, parentNode, bm._headerTip())
	}

	height := parentNode.Height + 1
	if height%params.BitcoinBlocksPerRetarget == 0 {

		glog.Tracef("BitcoinManager.ProcessBitcoinHeaderQuick: Header at retarget point: "+
			"DiffBits: %d, Height: %d, TstampSecs %d, Hash: %v\n",
			bitcoinHeader.Bits,
			height,
			bitcoinHeader.Timestamp.Unix(),
			bitcoinHeader.BlockHash())
	}

	merkleRootHash := (BlockHash)(bitcoinHeader.MerkleRoot)
	newNode := NewBlockNode(
		parentNode,
		&headerHash,
		// Note the height is always one greater than the parent node.
		parentNode.Height+1,
		_difficultyBitsToHash(bitcoinHeader.Bits),
		big.NewInt(0),
		// We are bastardizing the BitClout header to store Bitcoin information here. However,
		// it is important to note that they are similar enough such that if one were to
		// take the MsgBitCloutHeader information stored here and convert it to a wire.BlockHeader,
		// the latter should produce a hash that lines up with the hash we're storing above.
		&MsgBitCloutHeader{
			Version:               uint32(bitcoinHeader.Version),
			PrevBlockHash:         parentNode.Hash,
			TransactionMerkleRoot: &merkleRootHash,
			TstampSecs:            uint64(bitcoinHeader.Timestamp.Unix()),
			Height:                uint64(parentNode.Height + 1),
			Nonce:                 uint64(bitcoinHeader.Nonce),
		},
		StatusNone,
	)

	bm.headerIndex[*newNode.Hash] = newNode

	bm.bestHeaderChain, bm.bestHeaderChainMap = updateBestChainInMemory(
		bm.bestHeaderChain, bm.bestHeaderChainMap, []*BlockNode{}, []*BlockNode{newNode})

	return true, false, nil
}

func (bm *BitcoinManager) _computePow(tstamp time.Time, headerHash *BlockHash,
	parentNode *BlockNode, params *BitCloutParams, optionalDifficultyBits uint32) (
	_diffTarget *BlockHash, _cumWork *big.Int, _err error) {

	// Check that the proof of work beats the difficulty as calculated from
	// the parent block. Note that if the parent block is in the block index
	// then it has necessarily had its difficulty validated, and so using it to
	// do this check makes sense from an induction standpoint.
	diffTarget, err := _calcNextRequiredDifficulty(
		parentNode, tstamp, params)
	if err != nil {
		return nil, nil, errors.Wrapf(err,
			"_computePow: Problem computing difficulty "+
				"target from parent block %s", hex.EncodeToString(parentNode.Hash[:]))
	}
	diffTargetBigint := HashToBigint(diffTarget)
	// If some difficulty bits are set, check that the difficulty target as
	// computed from the parent block matches what is set in the bits.
	if optionalDifficultyBits != 0 {
		difficultyBitsBigint := btcdchain.CompactToBig(optionalDifficultyBits)
		if difficultyBitsBigint.Cmp(diffTargetBigint) != 0 &&
			(*diffTarget != *_difficultyBitsToHash(params.BitcoinPowLimitBits)) {

			glog.Errorf("_computePow: Target difficulty according to bits %v is "+
				"not consistent with target difficulty according to parent %v with "+
				"height %d and hash %v", _difficultyBitsToHash(optionalDifficultyBits), diffTarget,
				parentNode.Height+1, headerHash)
			return nil, nil, HeaderErrorDifficultyBitsNotConsistentWithTargetDifficultyComputedFromParent
		}
	}

	// Reverse the header hash to turn it into a bigint.
	unreversedHeaderHash := BlockHash{}
	for ii := range headerHash {
		unreversedHeaderHash[ii] = headerHash[len(headerHash)-1-ii]
	}
	blockHashBigint := HashToBigint(&unreversedHeaderHash)
	if diffTargetBigint.Cmp(blockHashBigint) < 0 {
		glog.Errorf("_computePow: Block difficulty %v is greater than the target "+
			"difficulty %v for height %d", &unreversedHeaderHash, diffTarget,
			parentNode.Height+1)
		return nil, nil, HeaderErrorBlockDifficultyAboveTarget
	}
	newWork := btcdchain.CalcWork(_difficultyHashToBits(diffTarget))
	cumWork := newWork.Add(newWork, parentNode.CumWork)

	return diffTarget, cumWork, nil
}

func (bm *BitcoinManager) _writeBitcoinNodeToDB(node *BlockNode) error {
	// Store the new node in our node index in the db under the
	//   <height uin32, blockhash BlockHash> -> <node info>
	// index.
	if err := PutHeightHashToNodeInfo(node, bm.db, true /*bitcoinNodes*/); err != nil {
		return errors.Wrapf(err,
			"_writeBitcoinNodeToDB: Problem calling PutHeightHashToNodeInfo for node %v: ", node)
	}

	return nil
}

// Acquires the BitcoinHeaderIndexLock for writing.
func (bm *BitcoinManager) ProcessBitcoinHeaderFull(bitcoinHeader *wire.BlockHeader, params *BitCloutParams) (
	_isMainChain bool, _isOrphan bool, _err error) {
	bm.BitcoinHeaderIndexLock.Lock()
	defer bm.BitcoinHeaderIndexLock.Unlock()

	headerHash := (BlockHash)(bitcoinHeader.BlockHash())
	parentHash := (BlockHash)(bitcoinHeader.PrevBlock)

	// Start by checking if the header already exists in our node
	// index. If it does, then return an error. We should generally
	// expect that processHeader will only be called on headers we
	// haven't seen before.
	existingNode, nodeExists := bm.headerIndex[headerHash]
	if nodeExists {
		return false, false, errors.Wrapf(HeaderErrorDuplicateHeader,
			"Duplicate header has height %v: ", existingNode.Height)
	}

	// If we're here then it means we're processing a header we haven't
	// seen before.

	// Reject the header if it is more than N seconds in the future.
	tstampDiff := bitcoinHeader.Timestamp.Unix() - bm.timeSource.AdjustedTime().Unix()
	if tstampDiff > int64(params.BitcoinMaxTstampOffsetSeconds) {
		return false, false, HeaderErrorBlockTooFarInTheFuture
	}

	// Try to find this header's parent in our block index.
	// If we can't find the parent then this header is an orphan and we
	// can return early because we don't process unconnectedTxns.
	parentNode, parentNodeExists := bm.headerIndex[parentHash]
	if !parentNodeExists {
		// This block is an orphan if its parent doesn't exist and we don't
		// process unconnectedTxns.
		return false, true, nil
	}

	// If the parent node is invalid then this header is invalid as well. Note that
	// if the parent node exists then its header must either be BitcoinValidated or
	// BitcoinValidateFailed.
	parentHeader := parentNode.Header
	parentIsValid := ((parentNode.Status & StatusBitcoinHeaderValidateFailed) == 0)
	if parentHeader == nil || !parentIsValid {
		return false, false, HeaderErrorInvalidParent
	}

	// Note that Bitcoin headers don't have heights so we don't check them.

	// Note Bitcoin checks that the block's timestamp is greater than the median of
	// the last 11 blocks but we forego this check because we're lazy. As long as
	// a critical mass of Bitcoin nodes continues to care about this rule it will be
	// enforced and our free-riding on their validation should be acceptable.
	diffTarget, cumWork, err := bm._computePow(
		bitcoinHeader.Timestamp, &headerHash, parentNode, params,
		bitcoinHeader.Bits)
	if err != nil {
		return false, false, errors.Wrapf(
			err, "ProcessBitcoinHeaderFull: Problem computing PoW: ")
	}

	// At this point the header seems sane so we store it in the db and add
	// it to our in-memory block index. Note we're not doing this atomically.
	// Worst-case, we have a header in our db with no pointer to it in our index,
	// which isn't a big deal.
	//
	// Note in the calculation of CumWork below we are adding the work specified
	// in the difficulty *target* rather than the work actually done to mine the
	// block. There is a good reason for this, which is that it materially
	// increases a miner's incentive to reveal their block immediately after it's
	// been mined as opposed to try and play games where they withhold their block
	// and try to mine on top of it before revealing it to everyone.
	merkleRootHash := (BlockHash)(bitcoinHeader.MerkleRoot)
	newNode := NewBlockNode(
		parentNode,
		&headerHash,
		// Note the height is always one greater than the parent node.
		parentNode.Height+1,
		diffTarget,
		cumWork,
		// We are bastardizing the BitClout header to store Bitcoin information here. However,
		// it is important to note that they are similar enough such that if one were to
		// take the MsgBitCloutHeader information stored here and convert it to a wire.BlockHeader,
		// the latter should produce a hash that lines up with the hash we're storing above.
		&MsgBitCloutHeader{
			Version:               uint32(bitcoinHeader.Version),
			PrevBlockHash:         parentNode.Hash,
			TransactionMerkleRoot: &merkleRootHash,
			TstampSecs:            uint64(bitcoinHeader.Timestamp.Unix()),
			Height:                uint64(parentNode.Height + 1),
			Nonce:                 uint64(bitcoinHeader.Nonce),
		},
		StatusBitcoinHeaderValidated,
	)

	// If all went well with storing the header, set it in our in-memory
	// index.
	bm.headerIndex[*newNode.Hash] = newNode

	// Update the header chain if this header has more cumulative work than
	// the header chain's tip. Note that we can assume all ancestors of this
	// header are valid at this point.
	isMainChain := false
	headerTip := bm._headerTip()
	if headerTip.CumWork.Cmp(newNode.CumWork) < 0 {
		isMainChain = true

		// Get the blocks to attach and detach as a result of this operation.
		_, detachBlocks, attachBlocks := GetReorgBlocks(headerTip, newNode)

		// Update the best chain in memory.
		bm.bestHeaderChain, bm.bestHeaderChainMap = updateBestChainInMemory(
			bm.bestHeaderChain, bm.bestHeaderChainMap, detachBlocks, attachBlocks)

		// Log if we had a large reorg. This should never happen.
		if int64(len(detachBlocks)) > params.MinerBitcoinMinBurnWorkBlockss {
			glog.Errorf("ProcessBitcoinHeaderFull: Bitcoin reorg detached %d blocks "+
				"which is more than the maximum we expect %d. The BitClout chain could be "+
				"corrupted at this point; consider wiping the data directory and rebooting "+
				"the node from scratch", len(detachBlocks),
				params.MinerBitcoinMinBurnWorkBlockss)
		}

		// Update the db to purge the detached blocks and write the attached blocks.
		// Although we store side-chains in memory via the headerIndex, we don't store
		// side chain blocks on the db. With the code below, we guarantee that we always
		// write blocks when we attach them and delete blocks when we detach them, meaning
		// that only the best chain blocks are actually stored in the db at any given time.
		// This is true even given the antics of FullyValidateHeaders.
		if err := DbBulkDeleteHeightHashToNodeInfo(
			detachBlocks, bm.db, true /*bitcoinNodes*/); err != nil {

			return false, false, errors.Wrapf(err, "ProcessBitcoinHeaderFull: Problem "+
				"deleting detached nodes from the db: %v", detachBlocks)
		}
		for _, newlyAttachedNode := range attachBlocks {
			if err := bm._writeBitcoinNodeToDB(newlyAttachedNode); err != nil {
				return false, false, errors.Wrapf(err, "ProcessBitcoinHeaderFull: Problem "+
					"writing new node to db: ")
			}
		}

		// Update the db to reflect the new best Bitcoin chain.
		if err := PutBestHash(&headerHash, bm.db, ChainTypeBitcoinHeader); err != nil {
			return false, false, err
		}
	}

	return isMainChain, false, nil
}

// Note that the amount of work must be determined based on the oldest
// time-current block that we have rather than the tip. If we aren't time-current
// or if the height passed in is greater than that of the oldest time-current
// Bitcoin block then a negative value, specifying the number of blocks this height
// is *behing* the oldest time-current block, is returned. When the height is
// equal to that of the oldest time-current block, zero is returned.
func (bm *BitcoinManager) GetBitcoinBurnWorkBlocks(blockHeight uint32) int64 {
	return int64(bm.HeaderTip().Height) - int64(blockHeight)
}

func (bm *BitcoinManager) IsCurrent(considerCumWork bool) bool {
	bm.BitcoinHeaderIndexLock.RLock()
	defer bm.BitcoinHeaderIndexLock.RUnlock()

	return bm._isCurrent(considerCumWork)
}

func (bm *BitcoinManager) _isCurrent(considerCumWork bool) bool {
	headerTip := bm._headerTip()

	return bm._isCurrentNode(headerTip, considerCumWork)
}

//  - Min difficulty is reached
//  - Latest block has a timestamp newer than 24 hours ago
func (bm *BitcoinManager) _isCurrentNode(node *BlockNode, considerCumWork bool) bool {
	minChainWorkBytes, _ := hex.DecodeString(bm.params.BitcoinMinChainWorkHex)
	minWorkBigint := BytesToBigint(minChainWorkBytes)

	// Not current if the cumulative work is below the threshold.
	if considerCumWork && node.CumWork.Cmp(minWorkBigint) < 0 {
		//glog.Tracef("BitcoinManager.isCurrent: Header tip work %v less than "+
		//"total min chain work %v", node.CumWork, minWorkBigint)
		return false
	}

	// Not current if the tip has a timestamp older than the maximum
	// tip age.
	tipTime := time.Unix(int64(node.Header.TstampSecs), 0)
	oldestAllowedTipTime := bm.timeSource.AdjustedTime().Add(-1 * bm.params.BitcoinMaxTipAge)

	// Tip is current if none of the above thresholds triggered.
	return !tipTime.Before(oldestAllowedTipTime)
}

// Same as _sendGetHeaders but holds the HeaderIndexLock for reading
func (bm *BitcoinManager) SendGetHeaders(conn net.Conn) {
	bm.BitcoinHeaderIndexLock.RLock()
	defer bm.BitcoinHeaderIndexLock.RUnlock()

	bm.__sendGetHeaders(conn)
}

func (bm *BitcoinManager) __sendGetHeaders(conn net.Conn) {
	// Our locator always consists of the "start node"
	// and the top ten blocks of our best Bitcoin header chain when
	// we have enough blocks. It starts with the tip at the front
	// and ends with the genesis block.
	headerHashes := []*BlockHash{}
	if len(bm.bestHeaderChain) > 10 {
		currentNode := bm._headerTip()
		for ii := 0; ii < 10; ii++ {
			headerHashes = append(headerHashes, currentNode.Hash)
			currentNode = currentNode.Parent
		}
	}
	headerHashes = append(headerHashes, bm.params.BitcoinStartBlockNode.Hash)

	getHeadersMsg := wire.NewMsgGetHeaders()
	for _, hash := range headerHashes {
		btcdHash := chainhash.Hash(*hash)
		getHeadersMsg.AddBlockLocatorHash(&btcdHash)
	}
	bm.writeMessage(conn, getHeadersMsg, bm.params)
}

func (bm *BitcoinManager) _notifyServerOfBitcoinUpdate(
	newTransactionsFound []*MsgBitCloutTxn) {

	glog.Tracef("BitcoinManager._notifyServerOfBitcoinUpdate: Being called")
	go func() {
		bm.updateChan <- &ServerMessage{
			Peer: nil,
			Msg: &MsgBitCloutBitcoinManagerUpdate{
				TransactionsFound: newTransactionsFound,
			},
		}
	}()
}

// Acquires the BitcoinHeaderIndexLock for writing.
func (bm *BitcoinManager) FullyValidateHeaderAtIndex(index int) (_finished bool, _err error) {
	bm.BitcoinHeaderIndexLock.Lock()
	defer bm.BitcoinHeaderIndexLock.Unlock()

	glog.Tracef("BitcoinManager.FullyValidateHeaders: Attempting to fully validate "+
		"index: %d", index)
	if index%1000 == 0 {
		glog.Debugf("BitcoinManager.FullyValidateHeaders: Attempting to fully validate "+
			"index: %d", index)
	}

	// If we've hit the last header in our chain, return true.
	if index >= len(bm.bestHeaderChain) {
		return true, nil
	}

	node := bm.bestHeaderChain[index]

	glog.Tracef("BitcoinManager.FullyValidateHeaders: Fully validating node: %v", node)

	// If the node has been validated already, continue.
	if (node.Status & StatusBitcoinHeaderValidated) != 0 {
		return false, nil
	}

	// If we get here then the node requires validation. Verify that its
	// parent node exists and then compute its proof of work.
	parentNode := node.Parent
	if parentNode == nil {
		return false, fmt.Errorf("BitcoinManager.HandleBitcoinHeaders: Node %v missing "+
			"parent with tip %v", node, bm._headerTip())
	}

	// Check that the parent is valid.
	parentHeader := parentNode.Header
	parentIsValid := ((parentNode.Status & StatusBitcoinHeaderValidateFailed) == 0)
	if parentHeader == nil || !parentIsValid {
		glog.Errorf("BitcoinManager.HandleBitcoinHeaders: Node %v has invalid "+
			"parent %v", node, parentNode)
		return false, HeaderErrorInvalidParent
	}

	// We should have everything we need to compute the proof of work and set
	// it now.
	diffTarget, cumWork, err := bm._computePow(
		time.Unix(int64(node.Header.TstampSecs), 0), node.Hash, parentNode, bm.params,
		0 /*optionalDifficultyBits: no need to check this here*/)
	if err != nil {
		return false, errors.Wrapf(
			err, "ProcessBitcoinHeaderFull: Problem computing PoW: ")
	}

	// Set the difficulty target and cumwork on the node and mark it as validated.
	node.DifficultyTarget = diffTarget
	node.CumWork = cumWork
	node.Status |= StatusBitcoinHeaderValidated

	// While we're at it, write the block to the db.
	if err := bm._writeBitcoinNodeToDB(node); err != nil {
		return false, errors.Wrapf(err, "WriteHeaderAtIndex: Problem writing new node to db: ")
	}

	return false, nil
}

// Acquires the BitcoinHeaderIndexLock for writing in its call to
// FullyValidateHeaderAtIndex.
func (bm *BitcoinManager) FullyValidateHeaders() error {
	// If we only have one node in the list, it's the start node which
	// we can assume is valid so return.
	if len(bm.bestHeaderChain) <= 1 {
		glog.Debugf("BitcoinManager.FullyValidateHeaders: No nodes to "+
			"fully validate with tip: %v", bm.HeaderTip())
		return nil
	}
	glog.Debugf("BitcoinManager.FullyValidateHeaders: Fully validating nodes up "+
		"to header: %v", bm.HeaderTip())

	// Process each node until we've run over the end of the node list to
	// fill in the PoW for the ones that have not been validated. Skip the
	// start node since its values should be assumed correct.
	//
	// Note we do this goofy
	// loop structure because it allows us to strategically acquire the
	// BitcoinHeaderIndexLock on a per-node basis. Not doing this would lock
	// out anyone who wants to read the index in its partially-validated state
	// for the entire duration of this processing. This would be highly undesirable
	// since it would mean that the Server cannot check the state of the Bitcoin
	// header chain until this is done, which means its sync would be significantly
	// delayed.
	for index := 1; ; index++ {
		finished, err := bm.FullyValidateHeaderAtIndex(index)
		if err != nil {
			return errors.Wrapf(err, "BitcoinManager.FullyValidateHeaders: Problem "+
				"processing header with index %d: ", index)
		}
		if finished {
			break
		}
	}

	// If after full validation the header chain is not work-current, then this is
	// an invalid chain and we should reset.
	if !bm.IsCurrent(true /*considerCumWork*/) {
		return fmt.Errorf("BitcoinManager.FullyValidateHeaders: CumWork %v after fully "+
			"validating all headers is still below the minimum CumWork %v; this "+
			"means we were fed an invalid chain and should disconnect from the "+
			"Peer and start over from scratch",
			BigintToHash(bm.HeaderTip().CumWork), bm.params.BitcoinMinChainWorkHex)
	}

	// If we get here then all the nodes on the main header chain should now have
	// StatusBitcoinHeaderValidated and should be written to the db. At this point,
	// it should be safe to write the header tip to the db as the best hash.
	if err := PutBestHash(bm.HeaderTip().Hash, bm.db, ChainTypeBitcoinHeader); err != nil {
		return errors.Wrapf(err, "BitcoinManager.FullyValidateHeaders: Problem "+
			"writing Bitcoin BestHash after validation for tip %v", bm.HeaderTip())
	}

	return nil
}

func (bm *BitcoinManager) _requestBitcoinTxn(conn net.Conn, hash chainhash.Hash) error {
	getDataMsg := wire.NewMsgGetData()
	invVect := wire.InvVect{
		Type: wire.InvTypeTx,
		Hash: hash,
	}
	getDataMsg.AddInvVect(&invVect)
	_, err := wire.WriteMessageWithEncodingN(conn, getDataMsg,
		bm.params.BitcoinProtocolVersion, wire.BitcoinNet(bm.params.BitcoinBtcdParams.Net),
		wire.BaseEncoding)
	// Fetching Bitcoin txns is best-effort. If we have an error just log it.
	if err != nil {
		return fmt.Errorf("BitcoinManager.requestBitcoinTxn: Problem requesting "+
			"Bitcoin txn %v: %v", hash, err)
	}

	return nil
}

func (bm *BitcoinManager) _requestBitcoinBlock(conn net.Conn, hash chainhash.Hash) {
	getDataMsg := wire.NewMsgGetData()
	invVect := wire.InvVect{
		Type: wire.InvTypeBlock,
		Hash: hash,
	}
	getDataMsg.AddInvVect(&invVect)
	_, err := wire.WriteMessageWithEncodingN(conn, getDataMsg,
		bm.params.BitcoinProtocolVersion, wire.BitcoinNet(bm.params.BitcoinBtcdParams.Net),
		wire.BaseEncoding)
	// Fetching Bitcoin blocks is best-effort. If we have an error just log it.
	if err != nil {
		glog.Errorf("BitcoinManager.MaybeRequestBitcoinBlock: Problem requesting "+
			"Bitcoin block %v: %v", hash, err)
	}
}

func (bm *BitcoinManager) MaybeRequestBitcoinBlock(conn net.Conn, hash chainhash.Hash) {
	// Don't request Bitcoin blocks until we're time-current. We only request Bitcoin
	// blocks so we can relay any transactions that send Bitcoin to the burn address
	// and so blocks from a long time ago aren't relevant (because all of the burn transactions
	// in them should already have been relayed by other nodes).
	if !bm.IsCurrent(false /*considerCumWork*/) {
		return
	}

	bm._requestBitcoinBlock(conn, hash)
}

// Acquires the BitcoinHeaderIndexLock through calls to various functions.
func (bm *BitcoinManager) HandleBitcoinHeaders(conn net.Conn, msg *wire.MsgHeaders) error {
	glog.Debugf("BitcoinManager.HandleBitcoinHeaders: Processing %d headers "+
		"starting from height %d ending at height %d, header tip hash: %v", len(msg.Headers),
		bm.HeaderTip().Height, uint32(len(msg.Headers))+bm.HeaderTip().Height,
		(chainhash.Hash)(*bm.HeaderTip().Hash))

	// If we are time-current but not work-current, don't do anything. In this case,
	// we must wait for header validation to complete.
	isTimeCurrent := bm.IsCurrent(false /*considerCumWork*/)
	isWorkCurrent := bm.IsCurrent(true /*considerCumWork*/)
	if isTimeCurrent && !isWorkCurrent {
		glog.Debugf("BitcoinManager.HandleBitcoinHeaders: Not processing Bitcoin headers " +
			"because we need to wait for initial validation to complete")
		glog.Tracef("Current Bitcoin CumWork: %v", BigintToHash(bm.HeaderTip().CumWork))
		return nil
	}

	// If we are not time-current, then process the headers quickly since there is
	// no chance of having a fork.
	if !isTimeCurrent {
		glog.Debugf("BitcoinManager.HandleBitcoinHeaders: Doing quick Bitcoin header " +
			"processing to get time-current")
		for _, hdr := range msg.Headers {
			_, isOrphan, err := bm.ProcessBitcoinHeaderQuick(hdr, bm.params)
			if err != nil {
				// If we have an error during quick processing then return. This should
				// never happen and is grounds for disconnecting the Peer.
				return fmt.Errorf(
					"BitcoinManager.HandleBitcoinHeaders: Problem quick processing Bitcoin "+
						"header %v: %v", hdr, err)
			}
			if isOrphan {
				// If we have an orphan during quick processing then return. This should
				// never happen and is grounds for disconnecting the Peer.
				return fmt.Errorf(
					"BitcoinManager.HandleBitcoinHeaders: Bitcoin header was orphan "+
						"for some reason in quick processing (tip: %v) (prev: %v) (current: %v)",
					bm.HeaderTip().Hash, hdr.PrevBlock, hdr.BlockHash())
			}

			if bm.HeaderTip().Height%bm.params.BitcoinBlocksPerRetarget == 0 {
				glog.Tracef("BitcoinManager.HandleBitcoinHeaders: Header tip after retarget: %v",
					bm.HeaderTip())
			}

			// If we are time-current after processing this header, request the block
			// corresponding to this header. We request Bitcoin blocks in order to look
			// for transactions that send BTC to the burn address so we can make sure
			// those get relayed.
			bm.MaybeRequestBitcoinBlock(conn, hdr.BlockHash())
		}

		// If we become time-current as a result of processing this batch of headers,
		// signal the Server to kick off its BitClout sync. We do this now rather than
		// waiting for all the headers to fully validate because it is highly unlikely
		// for an initial header download to result in invalid headers.
		//
		// In addition to kicking off the Server, go ahead and fully validate all
		// of the headers we just called ProcessQuick on.
		//
		// Once it's complete, we
		// shoot off another getheaders to the Peer to put us into our steady-state of
		// sending getheaders at regular intervals.
		hasBecomeTimeCurrent := bm.IsCurrent(false /*considerCumWork*/)
		if hasBecomeTimeCurrent {
			glog.Infof("BitcoinManager.HandleBitcoinHeaders: Bitcoin header chain has "+
				"become time-current with tip %v", bm.HeaderTip())

			// Notify the Server that our headers are now time-current.
			bm._notifyServerOfBitcoinUpdate(nil)

			// TODO: If we get unlucky and validation makes us realize that the Bitcoin header chain
			// is actually invalid, we could end up in a state where some BitClout blocks are
			// rejected that are actually valid according to the "real" Bitcoin header chain.
			// This is extremely unlikely, however, and even if it does happen the quick fix
			// is to delete the node's data directory and start the sync over from a legitimate
			// Bitcoin peer.
			err := bm.FullyValidateHeaders()
			if err != nil {
				// If we run into trouble fully-validating the headers, completely reset
				// our headers and return an error. This is grounds for disconnecting the
				// Peer.
				bm.ResetBitcoinHeaderIndex()
				return fmt.Errorf(
					"BitcoinManager.HandleBitcoinHeaders: Problem validating Bitcoin "+
						"headers when transitioning from quick sync to steady-state. Resetting "+
						"Bitcoin headers and disconnecting from Peer: %v",
					err)
			}

			bm.SendGetHeaders(conn)
			return nil
		}

		// If we get here, it means that we are either not time-current or we have more
		// headers to download from the Peer. Either way it makes sense to send another
		// getheaders in this case.
		bm.SendGetHeaders(conn)

		return nil
	}

	// If we receive headers after we're time-current and work-current then just process
	// them fully.
	if isTimeCurrent && isWorkCurrent {
		glog.Debugf("BitcoinManager.HandleBitcoinHeaders: Doing full Bitcoin header " +
			"processing")
		glog.Tracef("Bitcoin CumWork: %v", BigintToHash(bm.HeaderTip().CumWork))
		for _, hdr := range msg.Headers {
			_, isOrphan, err := bm.ProcessBitcoinHeaderFull(hdr, bm.params)
			if err != nil {
				// If we have an error during full processing then return. This is grounds
				// for disconnecting the Peer.
				return fmt.Errorf(
					"BitcoinManager.HandleBitcoinHeaders: Problem full processing Bitcoin "+
						"header %v: %v", hdr, err)
			}
			if isOrphan {
				// If we have an orphan during full processing then return. This is grounds
				// for disconnecting the Peer.
				return fmt.Errorf(
					"BitcoinManager.HandleBitcoinHeaders: Bitcoin header was orphan "+
						"for some reason in full processing (tip: %v) (prev: %v) (current: %v)",
					bm.HeaderTip().Hash, hdr.PrevBlock, hdr.BlockHash())
			}

			// If we are time-current after processing this header, request the block
			// corresponding to this header. We request Bitcoin blocks in order to look
			// for transactions that send BTC to the burn address so we can make sure
			// those get relayed.
			bm.MaybeRequestBitcoinBlock(conn, hdr.BlockHash())
		}

		// If we get here it means we were able to successfully fully process all headers.
		// Let the Server know when this is the case. Note we notify the Server regardless
		// of whether or not there were new headers because not doing this would lead to a
		// failing edge case where the Server main loop wouldn't start if we were fully
		// current initially.
		//
		// TODO: This should be fixable without introducing a global "hasNotifiedServer"
		// variable, which is one annoying way to do it.
		glog.Debugf("BitcoinManager.HandleBitcoinHeaders: Notifying Server since "+
			"there were %d new headers", len(msg.Headers))
		bm._notifyServerOfBitcoinUpdate(nil)

		// If this headers response was full, fetch another immediately as the Peer likely
		// has more for us.
		if uint32(len(msg.Headers)) == MaxBitcoinHeadersPerMsg {
			bm.SendGetHeaders(conn)
		} else {
			// Otherwise, once we're in the fully-current state, as we are here, we want to
			// process headers at regular intervals. As such, we enqueue the next getheaders
			// message here to give the node some time before our next request.
			go func() {
				time.Sleep(BitcoinHeaderUpdateInterval)
				bm.SendGetHeaders(conn)
			}()
		}
	}

	return nil
}

func (bm *BitcoinManager) _peekEarliestExpectedResponse() *ExpectedBitcoinResponse {
	bm.ExpectedResponsesLock.RLock()
	defer bm.ExpectedResponsesLock.RUnlock()

	if len(bm.expectedResponses) == 0 {
		return nil
	}

	return bm.expectedResponses[0]
}

func (bm *BitcoinManager) _removeEarliestExpectedResponse(command string) *ExpectedBitcoinResponse {
	bm.ExpectedResponsesLock.Lock()
	defer bm.ExpectedResponsesLock.Unlock()

	// Just remove the first instance we find of the passed-in message
	// type and return.
	for ii, res := range bm.expectedResponses {
		if res.Command == command {
			// We found the first occurrence of the message type so remove
			// that message since we're no longer waiting on it.
			left := append([]*ExpectedBitcoinResponse{}, bm.expectedResponses[:ii]...)
			bm.expectedResponses = append(left, bm.expectedResponses[ii+1:]...)

			// Return so we stop processing.
			return res
		}
	}

	return nil
}

func (bm *BitcoinManager) _addExpectedResponse(command string, timeExpected time.Time) {
	bm.ExpectedResponsesLock.Lock()
	defer bm.ExpectedResponsesLock.Unlock()

	item := &ExpectedBitcoinResponse{
		TimeExpected: timeExpected,
		Command:      command,
	}
	if len(bm.expectedResponses) == 0 {
		bm.expectedResponses = []*ExpectedBitcoinResponse{item}
		return
	}

	// Usually the item will need to be added at the end so start
	// from there.
	index := len(bm.expectedResponses)
	for index > 0 &&
		bm.expectedResponses[index-1].TimeExpected.After(item.TimeExpected) {

		index--
	}

	// Have to make sure left and right are copies. Otherwise Go will potentially
	// re-use the underlying array, which will cause havoc.
	left := append([]*ExpectedBitcoinResponse{}, bm.expectedResponses[:index]...)
	right := bm.expectedResponses[index:]
	bm.expectedResponses = append(append(left, item), right...)
}

func (bm *BitcoinManager) _clearExpectedResponses() {
	bm.ExpectedResponsesLock.Lock()
	defer bm.ExpectedResponsesLock.Unlock()

	bm.expectedResponses = []*ExpectedBitcoinResponse{}
}

// GetBitcoinBlockNode returns the BlockNode corresponding to the given hash
// if the hash is in the main Bitcoin header chain. Otherwise it returns nil.
// The caller is free to read the contents of the BlockNode but if they should
// *not* modify it.
func (bm *BitcoinManager) GetBitcoinBlockNode(hash *BlockHash) *BlockNode {
	bm.BitcoinHeaderIndexLock.RLock()
	defer bm.BitcoinHeaderIndexLock.RUnlock()

	header, headerExists := bm.bestHeaderChainMap[*hash]
	if !headerExists {
		return nil
	}

	return header
}

func (bm *BitcoinManager) HeaderForHash(hash *BlockHash) *BlockNode {
	bm.BitcoinHeaderIndexLock.RLock()
	defer bm.BitcoinHeaderIndexLock.RUnlock()

	blockHeader, exists := bm.bestHeaderChainMap[*hash]
	if !exists {
		return nil
	}
	return blockHeader
}

func (bm *BitcoinManager) HeaderAtHeight(blockHeight uint32) *BlockNode {
	bm.BitcoinHeaderIndexLock.RLock()
	defer bm.BitcoinHeaderIndexLock.RUnlock()

	if blockHeight >= uint32(len(bm.bestHeaderChain)) {
		return nil
	}

	return bm.bestHeaderChain[blockHeight]
}

func ExtractBitcoinBurnTransactionsFromBitcoinBlock(
	bitcoinBlock *wire.MsgBlock, bitcoinBurnAddress string, params *BitCloutParams) []*wire.MsgTx {

	burnTxns := []*wire.MsgTx{}
	for _, txn := range bitcoinBlock.Transactions {
		burnOutput, err := _computeBitcoinBurnOutput(
			txn, bitcoinBurnAddress, params.BitcoinBtcdParams)
		if err != nil {
			glog.Errorf("ExtractBitcoinBurnTransactionsFromBitcoinBlock: Problem "+
				"extracting Bitcoin transaction: %v", err)
			continue
		}

		if burnOutput > 0 {
			burnTxns = append(burnTxns, txn)
		}
	}

	return burnTxns
}

func ExtractBitcoinBurnTransactionsFromBitcoinBlockWithMerkleProofs(
	bitcoinBlock *wire.MsgBlock, burnAddress string, params *BitCloutParams) (
	_txns []*wire.MsgTx, _merkleProofs [][]*merkletree.ProofPart, _err error) {

	// Extract the Bitcoin burn transactions.
	burnTxns := ExtractBitcoinBurnTransactionsFromBitcoinBlock(
		bitcoinBlock, burnAddress, params)

	// If there weren't any burn transactions then there's nothing to do.
	if len(burnTxns) == 0 {
		return nil, nil, nil
	}

	// Compute all of the transaction hashes for the block.
	txHashes := [][]byte{}
	for _, txn := range bitcoinBlock.Transactions {
		txnBytes := bytes.Buffer{}
		err := txn.SerializeNoWitness(&txnBytes)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"ExtractBitcoinBurnTransactionsFromBitcoinBlockWithMerkleProofs: "+
					"Error computing all the txn hashes for block: %v",
				err)
		}
		txHashes = append(txHashes, txnBytes.Bytes())
	}

	// Compute a merkle tree for the block.
	merkleTree := merkletree.NewTree(merkletree.Sha256DoubleHash, txHashes)

	if !reflect.DeepEqual(merkleTree.Root.GetHash(), bitcoinBlock.Header.MerkleRoot[:]) {
		return nil, nil, fmt.Errorf(
			"ExtractBitcoinBurnTransactionsFromBitcoinBlockWithMerkleProofs: "+
				"Merkle proof computed from txns %#v != to Merkle proof in Bitcoin block %#v",
			merkleTree.Root.GetHash(), bitcoinBlock.Header.MerkleRoot[:])
	}

	// Use the Merkle tree to compute a Merkle proof for each transaction.
	burnTxnsWithProofs := []*wire.MsgTx{}
	merkleProofs := [][]*merkletree.ProofPart{}
	for _, txn := range burnTxns {
		txHash := txn.TxHash()
		proof, err := merkleTree.CreateProof(txHash[:])
		if err != nil {
			return nil, nil, fmt.Errorf(
				"ExtractBitcoinBurnTransactionsFromBitcoinBlockWithMerkleProofs: Problem "+
					"computing Merkle proof for txn %v for block %v: %v",
				txn, bitcoinBlock, err)
		}

		burnTxnsWithProofs = append(burnTxnsWithProofs, txn)
		merkleProofs = append(merkleProofs, proof.PathToRoot)
	}

	return burnTxnsWithProofs, merkleProofs, nil
}

func ExtractBitcoinExchangeTransactionsFromBitcoinBlock(
	bitcoinBlock *wire.MsgBlock, burnAddress string, params *BitCloutParams) (
	_txns []*MsgBitCloutTxn, _err error) {

	bitcoinBurnTxns, merkleProofs, err :=
		ExtractBitcoinBurnTransactionsFromBitcoinBlockWithMerkleProofs(
			bitcoinBlock, burnAddress, params)
	if err != nil {
		return nil, errors.Wrapf(err, "ExtractBitcoinExchangeTransactionsFromBitcoinBlock: "+
			"Problem extracting raw Bitcoin burn transactions from Bitcoin Block")
	}

	bitcoinExchangeTxns := []*MsgBitCloutTxn{}
	blockHash := (BlockHash)(bitcoinBlock.BlockHash())
	merkleRoot := (BlockHash)(bitcoinBlock.Header.MerkleRoot)
	for ii := range bitcoinBurnTxns {
		bitcoinExchangeMetadata := &BitcoinExchangeMetadata{
			BitcoinTransaction: bitcoinBurnTxns[ii],
			BitcoinBlockHash:   &blockHash,
			BitcoinMerkleRoot:  &merkleRoot,
			BitcoinMerkleProof: merkleProofs[ii],
		}

		// The only thing a BitcoinExchange transaction has set is its TxnMeta.
		// Everything else is left blank because it is not needed. Note that the
		// recipient of the BitClout that will be created is the first valid input in
		// the BitcoinTransaction specified. Note also that the
		// fee is deducted as a percentage of the eventual BitClout that will get
		// created as a result of this transaction.
		currentTxn := &MsgBitCloutTxn{
			TxnMeta: bitcoinExchangeMetadata,
		}
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}

	return bitcoinExchangeTxns, nil
}

func (bm *BitcoinManager) ProcessBitcoinBlock(bitcoinBlock *wire.MsgBlock) {
	// Make sure we have the block in our header map. If not, log an error and return.
	blockHash := (BlockHash)(bitcoinBlock.BlockHash())
	if bm.HeaderForHash(&blockHash) == nil {
		glog.Errorf("BitcoinManager.ProcessBitcoinBlock: Received Bitcoin block "+
			"with hash %v that does not exist in the bestHeaderChainMap; this should "+
			"never happen since we only request blocks after adding them to our best "+
			"header chain", &blockHash)
		return
	}

	glog.Debugf("ProcessBitcoinBlock: Block hash %v; Num txns: %v",
		bitcoinBlock.BlockHash(), len(bitcoinBlock.Transactions))
	for ii, txn := range bitcoinBlock.Transactions {
		glog.Debugf("ProcessBitcoinBlock: Block contains txn %v: %v",
			ii,
			txn.TxHash())
	}

	// Extract the BitcoinExchange transactions from the block.
	bitcoinExchangeTxns, err := ExtractBitcoinExchangeTransactionsFromBitcoinBlock(
		bitcoinBlock, bm.params.BitcoinBurnAddress, bm.params)
	if err != nil {
		glog.Errorf("BitcoinManager.ProcessBitcoinBlock: Problem extracting "+
			"BitcoinExchange transactions from block %v: %v", &blockHash, err)
		return
	}

	for ii, txn := range bitcoinExchangeTxns {
		glog.Debugf("ProcessBitcoinBlock: Accepted bitcoin txn hash %v: %v",
			ii,
			txn.TxnMeta.(*BitcoinExchangeMetadata).BitcoinTransaction.TxHash())
	}

	bm._notifyServerOfBitcoinUpdate(bitcoinExchangeTxns)
}

func (bm *BitcoinManager) BroadcastTxn(txn *wire.MsgTx) {
	go func() {
		bm.broadcastBitcoinTxnChan <- txn
	}()
}

// You can plop this into the BlockCypher decoder and it should work for you:
// https://live.blockcypher.com/btc/decodetx/
func BitcoinTxnToString(txn *wire.MsgTx) string {
	txnBytes := bytes.Buffer{}
	err := txn.SerializeNoWitness(&txnBytes)
	if err != nil {
		return "Error serializing txn: " + err.Error()
	}
	return hex.EncodeToString(txnBytes.Bytes())

}

type MsgWithError struct {
	msg wire.Message
	err error
}

func (bm *BitcoinManager) _broadcastBitcoinTxn(
	conn net.Conn, txn *wire.MsgTx) error {

	_, err := wire.WriteMessageWithEncodingN(conn, txn,
		bm.params.BitcoinProtocolVersion,
		wire.BitcoinNet(bm.params.BitcoinBtcdParams.Net),
		wire.BaseEncoding)
	if err != nil {
		return err
	}
	return nil
}

func (bm *BitcoinManager) _getRandomPeerConn() net.Conn {
	for {
		var ipNetAddr *wire.NetAddress
		conn, ipNetAddr := _getRandomPeer(bm.addrMgr, bm.params.DialTimeout)
		if conn == nil {
			glog.Debugf("BitcoinManager.BroadcastTxnAndCheckAdded: Trying a new Peer after a small break...")
			// It doesn't make sense to keep trying on every iteration without a small
			// amount of rest.
			time.Sleep(time.Millisecond * 100)
			continue
		}
		// If we get here it means we made a successful outbound connection.

		// Negotiate the version.
		err := bm._negotiateVersion(conn, int32(bm.HeaderTip().Height), bm.params)
		if err != nil {
			glog.Debugf("BitcoinManager.BroadcastTxnAndCheckAdded: Trying a new Peer...")
			conn.Close()
			continue
		}
		// If we get here it means we successfully negotiated the version withe Peer.

		// Mark the address as Good in the addrmgr.
		bm.addrMgr.Good(ipNetAddr)

		glog.Debugf("Connected to random Bitcoin peer: %v", conn.RemoteAddr())
		return conn
	}
}

func (bm *BitcoinManager) _getConnectPeer() net.Conn {
	for {
		conn, err := net.DialTimeout("tcp", bm.connectPeer, bm.params.DialTimeout)
		if err != nil {
			// If we failed to connect to this peer, get a new address and try again.
			glog.Errorf("BitcoinManager.startSync: Connection to addr (%v) failed: %v. "+
				"Trying again after a short break...", bm.connectPeer, err)
			time.Sleep(time.Millisecond * 100)
			continue
		}

		// Negotiate the version.
		err = bm._negotiateVersion(conn, int32(bm.HeaderTip().Height), bm.params)
		if err != nil {
			glog.Errorf("BitcoinManager.BroadcastTxnAndCheckAdded: Trying a new Peer...")
			conn.Close()
			continue
		}

		// We were able to dial successfully so we'll break out now.
		glog.Debugf("BitcoinManager.startSync: Connected to known addr: %v", conn.RemoteAddr().String())

		return conn
	}
}

func (bm *BitcoinManager) _getBitcoinPeer() net.Conn {
	if bm.connectPeer != "" {
		return bm._getConnectPeer()
	}
	return bm._getRandomPeerConn()
}

func (bm *BitcoinManager) BroadcastTxnAndCheckAdded(
	txn *wire.MsgTx, timeoutSecs int) (_err error) {

	// Get a connection to a Bitcoin node
	conn := bm._getRandomPeerConn()
	// If we get here, it means conn is a connection to a Bitcoin node
	// with a negotiated version.

	defer func() {
		conn.Close()
	}()

	// Broadcast the txn
	if err := bm._broadcastBitcoinTxn(conn, txn); err != nil {
		retErr := fmt.Errorf("BroadcastTxnAndCheckAdded: Error "+
			"broadcasting txn to Bitcoin peer: %v %v", txn.TxHash(), err)
		glog.Errorf(retErr.Error())
		return retErr
	}

	// Request the txn
	if err := bm._requestBitcoinTxn(conn, txn.TxHash()); err != nil {
		retErr := fmt.Errorf("BroadcastTxnAndCheckAdded: Error "+
			"requesting txn from Bitcoin peer: %v %v", txn.TxHash(), err)
		glog.Errorf(retErr.Error())
		return retErr
	}

	// Loop and wait for the node to send back the txn. Timeout if it takes
	// too long.
	glog.Debugf("BroadcastTxnAndCheckAdded: Looping...")
	readMsgChan := make(chan *MsgWithError)
	go func() {
		for {
			_, msg, _, err := wire.ReadMessageWithEncodingN(conn,
				bm.params.BitcoinProtocolVersion, wire.BitcoinNet(bm.params.BitcoinBtcdParams.Net),
				wire.BaseEncoding)
			readMsgChan <- &MsgWithError{
				msg: msg,
				err: err,
			}
			// Break out if we hit an error.
			if err != nil {
				break
			}
		}
	}()
	timeoutChan := time.After(time.Duration(timeoutSecs) * time.Second)
	waitTime := 250 * time.Millisecond
	for {
		select {
		case msgWithErr := <-readMsgChan:
			if msgWithErr.err != nil {
				retErr := fmt.Errorf("BroadcastTxnAndCheckAdded: Error receiving message from "+
					"Bitcoin peer: %v", msgWithErr.err)
				glog.Errorf(retErr.Error())
				return retErr
			}
			if msgWithErr.msg.Command() == "tx" {
				msgTx := msgWithErr.msg.(*wire.MsgTx)
				glog.Debugf("BroadcastTxnAndCheckAdded: Received txn: %v Waiting for: %v",
					msgTx.TxHash(), txn.TxHash())
				glog.Debugf("BroadcastTxnAndCheckAdded: Received WITNESS txn hash: "+
					"%v Waiting for WITNESS txn hash: %v",
					msgTx.WitnessHash(), txn.WitnessHash())
				// Make sure we got the txn we requested.
				if msgTx.TxHash() == txn.TxHash() {
					glog.Debugf("BroadcastTxnAndCheckAdded: Txn was the one we were looking "+
						"for: %v", txn.TxHash())
					return nil
				} else {
					glog.Debugf("BroadcastTxnAndCheckAdded: Txn was *NOT* the one we were looking "+
						"for: Received: %v Wanted: %v", msgTx.TxHash(), txn.TxHash())
				}
			} else {
				glog.Debugf("BroadcastTxnAndCheckAdded: Received message that is not tx: %v",
					msgWithErr.msg.Command())
			}
		case <-time.After(waitTime):
			glog.Tracef("BroadcastTxnAndCheckAdded: Retrying broadcast and "+
				"request of txn %v", txn.TxHash())
			// Broadcast the txn
			if err := bm._broadcastBitcoinTxn(conn, txn); err != nil {
				retErr := fmt.Errorf("BroadcastTxnAndCheckAdded: Error "+
					"broadcasting txn to Bitcoin peer: %v %v", txn.TxHash(), err)
				glog.Errorf(retErr.Error())
				return retErr
			}

			// Request the txn
			if err := bm._requestBitcoinTxn(conn, txn.TxHash()); err != nil {
				retErr := fmt.Errorf("BroadcastTxnAndCheckAdded: Error "+
					"requesting txn from Bitcoin peer: %v %v", txn.TxHash(), err)
				glog.Errorf(retErr.Error())
				return retErr
			}
		case <-timeoutChan:
			retErr := fmt.Errorf("BroadcastTxnAndCheckAdded: Timed out waiting for "+
				"confirmation of txn broadcast: %v ; Hex: %v",
				txn.TxHash(), BitcoinTxnToString(txn))
			glog.Errorf(retErr.Error())
			return retErr
		}
	}
	// We should never get here.
}

func (bm *BitcoinManager) BroadcastTxnAndCheckAddedRedundant(
	txn *wire.MsgTx, timeoutSecs int, numNodesToPing int) (_err error) {

	// This channel will contain the results of the various calls
	// to BroadcastTxnAndCheckAdded.
	type ErrorWithIndex struct {
		err   error
		index int
	}
	transactionCheckerChan := make(chan *ErrorWithIndex)

	// Kick off the checkers
	for ii := 0; ii < numNodesToPing; ii++ {
		glog.Debugf("BroadcastTxnAndCheckAddedRedundant: Kicking off checker %v", ii)
		go func(_ii int) {
			err := bm.BroadcastTxnAndCheckAdded(txn, timeoutSecs)
			transactionCheckerChan <- &ErrorWithIndex{
				err:   err,
				index: _ii,
			}
		}(ii)
	}

	// As soon as we have a single checker return without an error
	// we're good.
	for ii := 0; ii < numNodesToPing; ii++ {
		errWithIndex := <-transactionCheckerChan
		if errWithIndex.err != nil {
			retErr := fmt.Errorf("BroadcastTxnAndCheckAddedRedundant: "+
				"Error checking bitcoin exchange txn with single node: Index: %v Error: %v",
				errWithIndex.index, errWithIndex.err)
			glog.Error(retErr)
		}

		// If we get here then one of the Bitcoin nodes had this
		// transaction and we're good.
		glog.Debugf("BroadcastTxnAndCheckAddedRedundant: Completed bitcoin " +
			"exchange check successfully")

		return nil
	}

	return fmt.Errorf("BroadcastTxnAndCheckAddedRedundant: " +
		"Error checking bitcoin exchange txn; none of the nodes could " +
		"validate this transaction")
}

func (bm *BitcoinManager) RequestBitcoinTxn(txHash chainhash.Hash) {
	go func() {
		bm.requestTxnChan <- txHash
	}()
}

func (bm *BitcoinManager) RequestBitcoinBlock(blockHash chainhash.Hash) {
	go func() {
		bm.requestBlockChan <- blockHash
	}()
}

func (bm *BitcoinManager) _loop(conn net.Conn, params *BitCloutParams, addrMgr *addrmgr.AddrManager) {
	// If we return it means we had an error and will want to close the connection. As
	// long as we're looping in this function though, the conn passed in is our syncConn.
	bm.syncConn = conn
	defer func() {
		conn.Close()
		bm.syncConn = nil
	}()
	defer bm._clearExpectedResponses()

	// Send a GetAddrs message.
	bm.writeMessage(conn, wire.NewMsgGetAddr(), params)

	bm.SendGetHeaders(conn)

	readMsgChan := make(chan *MsgWithError)
	go func() {
		for {
			remoteMsg, _, err := bm.readMessage(conn, params)
			readMsgChan <- &MsgWithError{
				msg: remoteMsg,
				err: err,
			}
		}
	}()

	// Start a select loop over messages from the Peer.
	pingTicker := time.NewTicker(pingInterval)
	for {
		select {
		case msgWithError := <-readMsgChan:
			unhandledCommand := false
			if msgWithError.err != nil {
				unhandledCommand = strings.Contains(msgWithError.err.Error(), "unhandled command")
				if !unhandledCommand {
					glog.Debugf("BitcoinManager.readMsg: Encountered error reading message from "+
						"Peer. Finding new Peer and trying again %v: %v", conn.RemoteAddr().String(), msgWithError.err)
					return
				}
				continue
			}
			switch msgWithError.msg.Command() {
			case "ping":
				msg := msgWithError.msg.(*wire.MsgPing)
				glog.Debugf("BitcoinManager.startSync: Received ping; responding with pong: %s", conn.RemoteAddr().String())
				bm.writeMessage(conn, wire.NewMsgPong(msg.Nonce), params)
			case "addr":
				msg := msgWithError.msg.(*wire.MsgAddr)
				glog.Debugf("BitcoinManager.startSync: Adding %d addresses to addrmgr from Peer: %s", len(msg.AddrList), conn.RemoteAddr().String())
				netAddr, err := IPToNetAddr(conn.RemoteAddr().String(), bm.addrMgr, bm.params)
				if err != nil {
					glog.Errorf("BitcoinManager.startSync: Error adding %d addresses to addrmgr from "+
						"Peer: %s: %v", len(msg.AddrList), conn.RemoteAddr().String(), err)
					continue
				}
				addrMgr.AddAddresses(msg.AddrList, netAddr)
			case "headers":
				// Process the Bitcoin headers. Disconnect from the Peer and potentially
				// wipe the entire header index if we encounter an error.
				msg := msgWithError.msg.(*wire.MsgHeaders)
				err := bm.HandleBitcoinHeaders(conn, msg)
				if err != nil {
					glog.Errorf("BitcoinManager.startSync: Problem processing "+
						"headers: %v; disconnecting from node %v", err, conn.RemoteAddr())
					// If we encounter an error while processing headers before our header
					// chain is time-current, reset the entire Bitcoin header index so we
					// can start from scratch with another node.
					isTimeCurrent := bm.IsCurrent(false /*considerCumWork*/)
					if !isTimeCurrent {
						glog.Errorf("BitcoinManager.startSync: Wiping index before disconnect "+
							"from node %v since bitcoin header chain is not time-current",
							conn.RemoteAddr())
						bm.ResetBitcoinHeaderIndex()
					}
					return
				}
			case "block":
				msg := msgWithError.msg.(*wire.MsgBlock)
				bm.ProcessBitcoinBlock(msg)

			case "reject":
				glog.Errorf("BitcoinManager.startSync: Got reject message: %s", spew.Sdump(msgWithError.msg))
			}
		case <-time.After(time.Second):
			// Every second check to see if the Peer is late in responding to anything.
			// Disconnect and return if they are.
			expectedRes := bm._peekEarliestExpectedResponse()
			if expectedRes != nil && expectedRes.TimeExpected.Before(time.Now()) {
				timeItTookToRespond := time.Since(expectedRes.TimeExpected).Seconds() + BitcoinGetHeadersTimeout.Seconds()
				glog.Errorf("BitcoinManager.startSync: Peer %v took too long to respond "+
					"to a %s request: %v", conn.RemoteAddr(), expectedRes.Command, timeItTookToRespond)
				return
			}
		case <-pingTicker.C:
			nonce, err := wire.RandomUint64()
			if err != nil {
				glog.Errorf("BitcoinManager.pingHandler: Not sending ping to %s: %v", conn.RemoteAddr().String(), err)
				return
			}
			glog.Debugf("BitcoinManager.startSync: Sending ping message to peer: %s", conn.RemoteAddr().String())
			bm.writeMessage(conn, wire.NewMsgPing(nonce), params)
		case txnToBroadcast := <-bm.broadcastBitcoinTxnChan:
			txHash := txnToBroadcast.TxHash()
			glog.Tracef("BitcoinManager: Broadcasting txn with txid: %v to Peer %s", txHash.String(), conn.RemoteAddr().String())
			bm.writeMessage(conn, txnToBroadcast, params)
		case bitcoinTxHash := <-bm.requestTxnChan:
			glog.Tracef("BitcoinManager: Requesting txn with hash %s Peer %s",
				bitcoinTxHash.String(), conn.RemoteAddr().String())
			bm._requestBitcoinTxn(conn, bitcoinTxHash)
		case bitcoinChainHash := <-bm.requestBlockChan:
			glog.Tracef("BitcoinManager: Requesting block with hash %s Peer %s",
				bitcoinChainHash.String(), conn.RemoteAddr().String())
			bm._requestBitcoinBlock(conn, bitcoinChainHash)
		case switchPeerMsg := <-bm.SwitchPeerChan:
			glog.Debugf("BitcoinManager: Switching from peer with address %s to new peer with address %s",
				conn.RemoteAddr().String(), switchPeerMsg.NewAddr)
			newConn, err := net.DialTimeout("tcp", switchPeerMsg.NewAddr, bm.params.DialTimeout)
			if err != nil {
				// If we failed to connect to this peer just continue.
				glog.Debugf("BitcoinManager: Connection to new addr (%s) failed: %v", switchPeerMsg.NewAddr, err)
				go func() {
					switchPeerMsg.ReplyChan <- err
				}()
				continue
			}
			err = bm._negotiateVersion(newConn, int32(bm.HeaderTip().Height), bm.params)
			if err != nil {
				glog.Debugf("BitcoinManager.startSync: Trying a new Peer...")
				newConn.Close()
				go func() {
					switchPeerMsg.ReplyChan <- err
				}()
				continue
			}

			// At this point we've managed to complete the version negotiation with this new
			// peer so add them and replace our sync peer with them.
			//
			// TODO: There's a small memory leak here where we'll leave the previous channel
			// potentially containing messages. Not too worried about it but probably should
			// be eventually fixed.
			newAddrAsNetAddr, err := IPToNetAddr(newConn.RemoteAddr().String(), bm.addrMgr, bm.params)
			if err != nil {
				bm.addrMgr.Good(newAddrAsNetAddr)
			}
			conn.Close()
			conn = newConn
			bm.syncConn = conn
			bm._clearExpectedResponses()
			// TODO: I think this is buggy and doesn't result in the new channel
			// being added to.
			readMsgChan = make(chan *MsgWithError)
			go func() {
				// No error occurred so tell the reply channel about it.
				switchPeerMsg.ReplyChan <- nil
			}()
		}
	}
}

func (bm *BitcoinManager) startSyncWithBitcoinPeerNode() {
	glog.Debugf("BitcoinManager.startSyncWithBitcoinPeerNodes: Starting...")
	disconnectCount := 0
	for {
		conn := bm._getBitcoinPeer()

		// Read messages from the Peer unless/until we get an error or timeout.
		bm._loop(conn, bm.params, bm.addrMgr)

		// If we get here it means we encountered an issue with the Peer.
		glog.Debugf("BitcoinManager.startSync: Something happened with peer %s; "+
			"finding new Peer to connect to...", conn.RemoteAddr().String())

		// Use longer timeouts if we disconnect a lot. Add one below so it doesn't execute
		// the first time.
		if (disconnectCount+1)%5 == 0 {
			newGetHeadersTimeout := BitcoinGetHeadersTimeout * 2
			glog.Debugf("BitcoinManager.startSync: Increasing getheaders timeout "+
				"from %f secs to %f secs because number of disconnections = %d",
				BitcoinGetHeadersTimeout.Seconds(), newGetHeadersTimeout.Seconds(), disconnectCount)
			BitcoinGetHeadersTimeout = newGetHeadersTimeout
		}
		disconnectCount++
	}
}

func (bm *BitcoinManager) startSync() {
	glog.Debugf("BitcoinManager.startSync: Calling startSync...")
	bm.startSyncWithBitcoinPeerNode()
}

func (bm *BitcoinManager) Start() {
	glog.Debugf("BitcoinManager.Start: Starting BitcoinManager...")
	// Start the addrmgr.
	bm.addrMgr.Start()

	// Populate the addrMgr with useful seeds.
	bm.AddSeeds()

	// Setup a sync peer that we can use to update our header chain.
	bm.startSync()
}
