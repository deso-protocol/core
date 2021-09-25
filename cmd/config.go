package cmd

import (
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"github.com/spf13/viper"
	"os"
)

type Config struct {
	// Core
	Params               *lib.DeSoParams
	ProtocolPort         uint16
	DataDirectory        string
	MempoolDumpDirectory string
	TXIndex              bool
	Regtest              bool
	PostgresURI          string

	// Peers
	ConnectIPs          []string
	AddIPs              []string
	AddSeeds            []string
	TargetOutboundPeers uint32
	StallTimeoutSeconds uint64

	// Peer Restrictions
	PrivateMode       bool
	ReadOnlyMode      bool
	DisableNetworking bool
	IgnoreInboundInvs bool
	MaxInboundPeers   uint32
	OneInboundPerIp   bool

	// Mining
	MinerPublicKeys  []string
	NumMiningThreads uint64

	// Fees
	RateLimitFeerate uint64
	MinFeerate       uint64

	// BlockProducer
	MaxBlockTemplatesCache          uint64
	MinBlockUpdateInterval          uint64
	BlockCypherAPIKey               string
	BlockProducerSeed               string
	TrustedBlockProducerPublicKeys  []string
	TrustedBlockProducerStartHeight uint64

	// Logging
	LogDirectory          string
	GlogV                 uint64
	GlogVmodule           string
	LogDBSummarySnapshots bool
	DatadogProfiler       bool
}

func LoadConfig() *Config {
	config := Config{}

	// Core
	testnet := viper.GetBool("testnet")
	if testnet {
		config.Params = &lib.DeSoTestnetParams
	} else {
		config.Params = &lib.DeSoMainnetParams
	}

	config.ProtocolPort = uint16(viper.GetUint64("protocol-port"))
	if config.ProtocolPort <= 0 {
		config.ProtocolPort = config.Params.DefaultSocketPort
	}

	config.DataDirectory = viper.GetString("data-dir")
	if config.DataDirectory == "" {
		config.DataDirectory = lib.GetDataDir(config.Params)
	}
	if err := os.MkdirAll(config.DataDirectory, os.ModePerm); err != nil {
		glog.Fatalf("Could not create data directories (%s): %v", config.DataDirectory, err)
	}

	config.MempoolDumpDirectory = viper.GetString("mempool-dump-dir")
	config.TXIndex = viper.GetBool("txindex")
	config.Regtest = viper.GetBool("regtest")
	config.PostgresURI = viper.GetString("postgres-uri")

	// Peers
	config.ConnectIPs = viper.GetStringSlice("connect-ips")
	config.AddIPs = viper.GetStringSlice("add-ips")
	config.AddSeeds = viper.GetStringSlice("add-seeds")
	config.TargetOutboundPeers = viper.GetUint32("target-outbound-peers")
	config.StallTimeoutSeconds = viper.GetUint64("stall-timeout-seconds")

	// Peer Restrictions
	config.PrivateMode = viper.GetBool("private-mode")
	config.ReadOnlyMode = viper.GetBool("read-only-mode")
	config.DisableNetworking = viper.GetBool("disable-networking")
	config.IgnoreInboundInvs = viper.GetBool("ignore-inbound-invs")
	config.MaxInboundPeers = viper.GetUint32("max-inbound-peers")
	config.OneInboundPerIp = viper.GetBool("one-inbound-per-ip")

	// Mining + Admin
	config.MinerPublicKeys = viper.GetStringSlice("miner-public-keys")
	config.NumMiningThreads = viper.GetUint64("num-mining-threads")

	// Fees
	config.RateLimitFeerate = viper.GetUint64("rate-limit-feerate")
	config.MinFeerate = viper.GetUint64("min-feerate")

	// BlockProducer
	config.MaxBlockTemplatesCache = viper.GetUint64("max-block-templates-cache")
	config.MinBlockUpdateInterval = viper.GetUint64("min-block-update-interval")
	config.BlockCypherAPIKey = viper.GetString("block-cypher-api-key")
	config.BlockProducerSeed = viper.GetString("block-producer-seed")
	config.TrustedBlockProducerStartHeight = viper.GetUint64("trusted-block-producer-start-height")
	config.TrustedBlockProducerPublicKeys = viper.GetStringSlice("trusted-block-producer-public-keys")

	// Logging
	config.LogDirectory = viper.GetString("log-dir")
	if config.LogDirectory == "" {
		config.LogDirectory = config.DataDirectory
	}
	config.GlogV = viper.GetUint64("glog-v")
	config.GlogVmodule = viper.GetString("glog-vmodule")
	config.LogDBSummarySnapshots = viper.GetBool("log-db-summary-snapshots")
	config.DatadogProfiler = viper.GetBool("datadog-profiler")

	return &config
}

func (config *Config) Print() {
	glog.Infof("Logging to directory %s", config.LogDirectory)
	glog.Infof("Running node in %s mode", config.Params.NetworkType)
	glog.Infof("Data Directory: %s", config.DataDirectory)

	if config.MempoolDumpDirectory != "" {
		glog.Infof("Mempool Dump Directory: %s", config.MempoolDumpDirectory)
	}

	if config.PostgresURI != "" {
		glog.Infof("Postgres URI: %s", config.PostgresURI)
	}

	if len(config.ConnectIPs) > 0 {
		glog.Infof("Connect IPs: %s", config.ConnectIPs)
	}

	if len(config.AddIPs) > 0 {
		glog.Infof("Add IPs: %s", config.ConnectIPs)
	}

	if config.PrivateMode {
		glog.Infof("PRIVATE MODE")
	}

	if config.ReadOnlyMode {
		glog.Infof("READ ONLY MODE")
	}

	if config.DisableNetworking {
		glog.Infof("NETWORKING DISABLED")
	}

	if config.IgnoreInboundInvs {
		glog.Infof("IGNORING INBOUND INVS")
	}

	glog.Infof("Max Inbound Peers: %d", config.MaxInboundPeers)
	glog.Infof("Protocol listening on port %d", config.ProtocolPort)

	if len(config.MinerPublicKeys) > 0 {
		glog.Infof("Mining with public keys: %s", config.MinerPublicKeys)
	}

	glog.Infof("Rate Limit Feerate: %d", config.RateLimitFeerate)
	glog.Infof("Min Feerate: %d", config.MinFeerate)
}
