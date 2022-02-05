package cmd

import (

"github.com/deso-protocol/core/lib"
"github.com/golang/glog"
"os"
"os/signal"
"syscall"
"testing"
)

func TestRun(t *testing.T) {
	config := Config{}
	config.Params = &lib.DeSoMainnetParams
	config.ProtocolPort = uint16(18000)
	config.DataDirectory = "/Users/piotr/data_dirs/n1_23"
	if err := os.MkdirAll(config.DataDirectory, os.ModePerm); err != nil {
		t.Fatalf("Could not create data directories (%s): %v", config.DataDirectory, err)
	}
	config.HyperSync = true
	config.CacheSize = config.Params.DefaultCacheSize
	config.MaxSyncBlockHeight = 2000
	config.ConnectIPs = []string{"localhost:17000"}
	config.LogDirectory = "/Users/piotr/Desktop/Code/DeSo/logs/n1/test23"
	config.GlogV = 1
	config.GlogVmodule = "*bitcoin_manager*=2,*balance*=2,*view*=2,*frontend*=2,*peer*=0,*addr*=0,*network*=0,*utils*=0,*connection*=0,*main*=0,*server*=2,*mempool*=2,*miner*=2,*blockchain*=2"
	config.MaxInboundPeers = 125
	config.TargetOutboundPeers = 8
	config.StallTimeoutSeconds = 900
	config.MinFeerate = 1000
	config.OneInboundPerIp = true
	config.MaxBlockTemplatesCache = 100
	config.MinBlockUpdateInterval = 10

	node := NewNode(&config)
	go node.Start()

	shutdownListener := make(chan os.Signal)
	signal.Notify(shutdownListener, syscall.SIGINT, syscall.SIGTERM)
	defer func() {
		node.Stop()
		glog.Info("Shutdown complete")
	}()

	<-shutdownListener
}