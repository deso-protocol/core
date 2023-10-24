package lib

import (
	"github.com/DataDog/datadog-go/statsd"
	"time"
)

type StatsManager struct {
	srv          *Server
	mp           *DeSoMempool
	bc           *Blockchain
	statsdClient *statsd.Client

	exitChan chan struct{}
}

func NewStatsManager(srv *Server, mp *DeSoMempool, bc *Blockchain,
	statsdClient *statsd.Client) *StatsManager {

	return &StatsManager{
		srv:          srv,
		mp:           mp,
		bc:           bc,
		statsdClient: statsdClient,
		exitChan:     make(chan struct{}),
	}
}

func (stam *StatsManager) Init(managers []Manager) {
}

func (stam *StatsManager) Start() {
	go stam.startStatsdReporter()
}

func (stam *StatsManager) Stop() {
	close(stam.exitChan)
}

func (stam *StatsManager) GetType() ManagerType {
	return ManagerTypeStats
}

func (stam *StatsManager) GetStatsdClient() *statsd.Client {
	return stam.statsdClient
}

func (stam *StatsManager) startStatsdReporter() {
	if stam.statsdClient == nil {
		return
	}

	for {
		select {
		case <-time.After(5 * time.Second):
			tags := []string{}

			// Report mempool size
			mempoolTotal := len(stam.mp.readOnlyUniversalTransactionList)
			stam.statsdClient.Gauge("MEMPOOL.COUNT", float64(mempoolTotal), tags, 1)

			// Report block + headers height
			blocksHeight := stam.bc.BlockTip().Height
			stam.statsdClient.Gauge("BLOCKS.HEIGHT", float64(blocksHeight), tags, 1)

			headersHeight := stam.bc.HeaderTip().Height
			stam.statsdClient.Gauge("HEADERS.HEIGHT", float64(headersHeight), tags, 1)

		case <-stam.exitChan:
			return
		}
	}
}
