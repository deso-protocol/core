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
	config.ProtocolPort = uint16(19000)
	config.DataDirectory = "/Users/piotr/data_dirs/n98_1"
	if err := os.MkdirAll(config.DataDirectory, os.ModePerm); err != nil {
		t.Fatalf("Could not create data directories (%s): %v", config.DataDirectory, err)
	}
	config.TXIndex = true
	config.HyperSync = false
	config.MaxSyncBlockHeight = 0
	config.ConnectIPs = []string{}
	config.LogDirectory = "/Users/piotr/Desktop/Code/DeSo/logs/n1/test23"
	config.GlogV = 1
	config.GlogVmodule = "*bitcoin_manager*=0,*balance*=0,*view*=0,*frontend*=0,*peer*=0,*addr*=0,*network*=0,*utils*=0,*connection*=0,*main*=0,*server*=0,*mempool*=0,*miner*=0,*blockchain*=0"
	config.MaxInboundPeers = 0
	config.TargetOutboundPeers = 0
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