package lib

import (
	"github.com/golang/glog"
	"time"
)

type MempoolManager struct {
}

func (mm *MempoolManager) NewMempoolManager() *MempoolManager {
	// Start statsd reporter
	if srv.statsdClient != nil {
		srv.StartStatsdReporter()
	}
	return &MempoolManager{}
}

func (mm *MempoolManager) _handleMempool(pp *Peer, msg *MsgDeSoMempool) {
	glog.V(1).Infof("Server._handleMempool: Received Mempool message from Peer %v", pp)

	pp.canReceiveInvMessagess = true
}

func (mm *MempoolManager) StartStatsdReporter() {
	go func() {
	out:
		for {
			select {
			case <-time.After(5 * time.Second):
				tags := []string{}

				// Report mempool size
				mempoolTotal := len(srv.mempool.readOnlyUniversalTransactionList)
				srv.statsdClient.Gauge("MEMPOOL.COUNT", float64(mempoolTotal), tags, 1)

				// Report block + headers height
				blocksHeight := srv.blockchain.BlockTip().Height
				srv.statsdClient.Gauge("BLOCKS.HEIGHT", float64(blocksHeight), tags, 1)

				headersHeight := srv.blockchain.HeaderTip().Height
				srv.statsdClient.Gauge("HEADERS.HEIGHT", float64(headersHeight), tags, 1)

			case <-srv.mempool.quit:
				break out
			}
		}
	}()
}
