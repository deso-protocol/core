package cmd

import (
	"fmt"

	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the node",
	Long:  `...`,
	Run:   Run,
}

func init() {
	SetupRunFlags(runCmd)
	rootCmd.AddCommand(runCmd)
}

func Run(cmd *cobra.Command, args []string) {
	// Parse the configuration (can use CLI flags, environment variables, or config file)
	config := LoadConfig()

	// Start the deso node
	shutdownListener := make(chan struct{})
	node := NewNode(config)
	node.Start(&shutdownListener)

	defer func() {
		node.Stop()
		glog.Info("Shutdown complete")
	}()
	<-shutdownListener
}

func SetupRunFlags(cmd *cobra.Command) {
	// Core
	cmd.PersistentFlags().Bool("testnet", false, "Use the DeSo testnet. Mainnet is used by default")
	cmd.PersistentFlags().String("data-dir", "",
		"The location where all of the protocol-related data like blocks is stored. "+
			"Useful for testing situations where multiple clients need to run on the "+
			"same machine without trampling over each other. "+
			"When unset, defaults to the system's configuration directory.")
	cmd.PersistentFlags().String("mempool-dump-dir", "",
		"When set, the mempool is initialized using a db in the directory specified, and"+
			"subsequent dumps are also written to this dir")
	cmd.PersistentFlags().Bool("txindex", false,
		"When set to true, the node will generate an index mapping transaction "+
			"ids to transaction information. This enables the use of certain API calls "+
			"like ones that allow the lookup of particular transactions by their ID. "+
			"Defaults to false because the index can be large.")
	cmd.PersistentFlags().Bool("regtest", false,
		"Can only be used in conjunction with --testnet. Creates a private testnet node with fast block times"+
			"and instantly spendable block rewards.")
	cmd.PersistentFlags().Bool("regtest-accelerated", false, "Can only be used in conjunction with --regtest. "+
		"Accelerates the regtest network by lowering PoS cutover height, lowering epoch duration, and seeding "+
		"some balances. Useful for testing purposes.")
	cmd.PersistentFlags().String("postgres-uri", "", "BETA: Use Postgres as the backing store for chain data."+
		"When enabled, most data is stored in postgres although badger is still currently used for some state. Run your "+
		"Postgres instance on the same machine as your node for optimal performance.")
	cmd.PersistentFlags().Uint32("max-sync-block-height", 0,
		"Max sync block height")
	// Hyper Sync
	cmd.PersistentFlags().Bool("hypersync", true, "Use hyper sync protocol for faster block syncing")
	cmd.PersistentFlags().Bool("force-checksum", false, "When true, the node will panic if the "+
		"local state checksum differs from the network checksum reported by its peers.")
	// Snapshot
	cmd.PersistentFlags().Uint64("snapshot-block-height-period", lib.DefaultSnapshotEpochPeriodPoS, "Set the snapshot epoch period. Snapshots are taken at block heights divisible by the period.")
	// Archival mode
	cmd.PersistentFlags().Bool("archival-mode", true, "Download all historical blocks after finishing hypersync.")
	// Disable encoder migrations
	cmd.PersistentFlags().Bool("disable-encoder-migrations", false, "Disable badgerDB encoder migrations")
	// Semephore cap that limits the number of snapshot chunks stored in the OperationChannel during hypersync.
	cmd.PersistentFlags().Uint32("hypersync-max-queue-size", lib.HypersyncDefaultMaxQueueSize, "Limit number of snapshot chunks stored in the OperationChannel during hypersync.")
	// Disable slow sync
	cmd.PersistentFlags().String("sync-type", "any", `We have the following options for SyncType:
		- any: Will sync with a node no matter what kind of syncing it supports.
		- full-historical: Will sync by connecting blocks from the beginning of time.
		- hypersync-archival: Will sync by hypersyncing state, but then it will
		  still download historical blocks at the end. Can only be set if HyperSync
		  is true.
		- hypersync: Will sync by downloading historical state, and will NOT
		  download historical blocks. Can only be set if HyperSync is true.`)
	// Block Index Size
	cmd.PersistentFlags().Uint64("block-index-size", lib.MaxBlockIndexNodes, "The number of blocks to keep in memory in the block "+
		"index. Setting this to a lower number will reduce memory usage, but will require the node to go to disk "+
		"more when fetching block nodes more often.")

	// PoS Validator
	cmd.PersistentFlags().String("pos-validator-seed", "", "A BIP39 seed phrase or seed hex used to generate the "+
		"private key of the Proof of Stake validator. Setting this flag automatically makes the node run as a Proof "+
		"of Stake Validator.")

	// Mempool
	cmd.PersistentFlags().Uint64("mempool-backup-time-millis", 30000,
		"The frequency in milliseconds with which the mempool will persist its state to disk. "+
			"The default value is 30 seconds, or 30,000 milliseconds.")
	cmd.PersistentFlags().Uint64("mempool-max-validation-view-connects", 10000,
		"The maximum number of connects that the PoS mempool transaction validation routine will perform.")
	cmd.PersistentFlags().Uint64("transaction-validation-refresh-interval-millis", 10,
		"The frequency in milliseconds with which the transaction validation routine is run in mempool. "+
			"The default value is 10 milliseconds.")

	// Peers
	cmd.PersistentFlags().StringSlice("connect-ips", []string{},
		"A comma-separated list of ip:port addresses that we should connect to on startup. "+
			"If this argument is specified, we don't connect to any other peers.")
	cmd.PersistentFlags().StringSlice("add-ips", []string{},
		"A comma-separated list of ip:port addresses that we should connect to on startup. "+
			"If this argument is specified, we will still fetch addresses from DNS seeds and "+
			"potentially connect to them.")
	cmd.PersistentFlags().StringSlice("add-seeds", []string{},
		"A comma-separated list of DNS seeds to be used in addition to the pre-configured seeds.")
	cmd.PersistentFlags().Uint64("target-outbound-peers", 8,
		"The target number of outbound peers. The node will continue attempting to connect to "+
			"random addresses until it has this many outbound connections. During testing it's "+
			"useful to turn this number down and test a small number of nodes in a controlled "+
			"environment.")
	cmd.PersistentFlags().Uint64("stall-timeout-seconds", 900,
		"How long the node will wait for a peer to reply to certain types of requests. "+
			"We make this gratuitous just in case the node we're connecting to is backed up.")

	// Peer Restrictions
	cmd.PersistentFlags().Bool("private-mode", false, "The node does not look up addresses from DNS seeds.")
	cmd.PersistentFlags().Bool("read-only-mode", false, "The node ignores all transactions created on this node.")
	cmd.PersistentFlags().Bool("disable-networking", false, "The node does not make outgoing or accept incoming connections.")
	cmd.PersistentFlags().Bool("ignore-inbound-invs", false,
		"When set to true, the node will ignore all INV messages unless they come from an outbound peer. "+
			"This is useful when setting up a node that you want to have a direct and 1:1 relationship with "+
			"another node, as is common when setting up read sharding.")
	cmd.PersistentFlags().Uint64("max-inbound-peers", 125, "The maximum number of inbound peers a node can have.")
	cmd.PersistentFlags().Bool("one-inbound-per-ip", true,
		"When set, the node will not allow more than one connection to/from a particular "+
			"IP. This prevents forms of attack whereby one node tries to monopolize all of "+
			"our connections and potentially make onerous requests as well. Useful to "+
			"disable this flag when testing locally to allow multiple inbound connections "+
			"from test servers")

	cmd.PersistentFlags().Uint64("peer-connection-refresh-interval-millis", 10000,
		"The frequency in milliseconds with which the node will refresh its peer connections. This applies to"+
			"both outbound validators and outbound persistent non-validators",
	)

	// Listeners
	cmd.PersistentFlags().Uint64("protocol-port", 0,
		"When set, determines the port on which this node will listen for protocol-related "+
			"messages. If unset, the port will default to what is present in the DeSoParams set. "+
			"Note also that even though the node will listen on this port, its outbound "+
			"connections will not be determined by this flag.")

	// Mining + Admin
	cmd.PersistentFlags().StringSlice("miner-public-keys", []string{},
		"A miner is started if and only if this field is set. Indicates where to send "+
			"block rewards from mining blocks. Public keys must be "+
			"comma-separated compressed ECDSA public keys formatted as base58 strings.")
	cmd.PersistentFlags().Uint64("num-mining-threads", 0,
		"How many threads to run for mining. Only has an effect when --miner-public-keys "+
			"is set. If set to zero, which is the default, then the number of "+
			"threads available to the system will be used.")

	// Fees
	cmd.PersistentFlags().Uint64("rate-limit-feerate", 0,
		"Transactions below this feerate will be rate-limited rather than flat-out "+
			"rejected. This is in contrast to min-feerate, which will flat-out reject "+
			"transactions with feerates below what is specified. As such, this value will have no "+
			"effect if it is set below min-feerate. This, along with min-feerate, should "+
			"be the first line of defense against attacks that involve flooding the "+
			"network with low-fee transactions in an attempt to overflow the mempool")
	cmd.PersistentFlags().Uint64("min-feerate", 1000,
		"The minimum feerate this node will accept when processing transactions "+
			"relayed by peers. Increasing this number, along with increasing "+
			"rate-limit-feerate, should be the first line of "+
			"defense against attacks that involve flooding the network with low-fee "+
			"transactions in an attempt to overflow the mempool")

	// BlockProducer
	cmd.PersistentFlags().Uint64("max-block-templates-cache", 100,
		"When set to a non-zero value, the node will generate block "+
			"templates, and cache the number of templates specified by this flag. When set "+
			"to zero, the node will not produce block templates.")
	cmd.PersistentFlags().Uint64("min-block-update-interval", 10,
		"When set to a non-zero value, the node will wait at least this many seconds "+
			"before producing another block template")
	cmd.PersistentFlags().String("block-cypher-api-key", "",
		"When specified, this key is used to power the BitcoinExchange flow "+
			"and to check for double-spends in the mempool")
	cmd.PersistentFlags().String("block-producer-seed", "",
		"When set, all blocks produced by the block producer will be signed by this "+
			"seed.")
	cmd.PersistentFlags().StringSlice("trusted-block-producer-public-keys", []string{
		"BC1YLgS1zDJQqywFpsty4fFheUrZxVQNKEsrttppvUESFZCq6Nfoypm",
		"BC1YLh768bVj2R3QpSiduxcvn7ipxF3L3XHsabZYtCGtsinUnNrZvNN",
		"BC1YLgsiUgM1Vr35YwbkSfZB3NC9tyrMXBPuJ2SEBf8naDf6PRpNit9",
		"BC1YLgW5jWudzSUvrvNkD4GReN3kvGvsTuqLLttKfsCbXb7vLSCjwTk",
		"BC1YLi8X7U9DZc2UqPE4s5PjrNJJUa6PKygD7VF4u8vy96srm18YvEX",
	},
		"When set, this node will only accept new blocks that are signed by the trusted block "+
			"producers. This setting, is pretty novel. It allows a network of full nodes who "+
			"trust each other to create their own network that can't be easily taken over by a 51% "+
			"attack. In some sense, it uses trust in order to lower the amount of work needed to "+
			"protect the network, making it highly eco-friendly. Then, if full nodes ever want to "+
			"allow open mining, all they need to do is unset these public keys (or one of the owners "+
			"of the public keys can release her key material, pulling a metaphorical 'ripcord'). "+
			"Importantly, until this point, the network will be completely protected from a 51% attack, "+
			"giving it time to accumulate the necessary hash power.")
	cmd.PersistentFlags().Uint64("trusted-block-producer-start-height", 37000,
		"If --trusted-block-producer-public-keys is set, then all blocks after this height must "+
			"be signed by one of these keys in order to be considered valid. Setting this value to zero "+
			"enforces that all blocks after genesis must be signed by a trusted block producer. The default "+
			"value was chosen to be in-line with the default trusted public keys chosen.")

	// Logging
	cmd.PersistentFlags().String("log-dir", "", "The directory for logs")
	cmd.PersistentFlags().Uint64("glog-v", 0, "The log level. 0 = INFO, 1 = DEBUG, 2 = TRACE. Defaults to zero")
	cmd.PersistentFlags().String("glog-vmodule", "",
		"The syntax of the argument is a comma-separated list of pattern=N, "+
			"where pattern is a literal file name (minus the \".go\" suffix) or \"glob\" "+
			"pattern and N is a V level. For instance, -vmodule=gopher*=3 sets the V "+
			"level to 3 in all Go files whose names begin \"gopher\".")
	cmd.PersistentFlags().Bool("log-db-summary-snapshots", false, "The node will log a snapshot of all DB keys every 30s.")
	cmd.PersistentFlags().Bool("datadog-profiler", false, "Enable the DataDog profiler for performance testing")
	cmd.PersistentFlags().Bool("time-events", false, "Enable simple event timer, helpful in hands-on performance testing")
	cmd.PersistentFlags().String("state-change-dir", "", "The directory for state change logs. WARNING: Changing this "+
		"from an empty string to a non-empty string (or from a non-empty string to the empty string) requires a resync.")
	cmd.PersistentFlags().Uint("state-syncer-mempool-txn-sync-limit", 10000, "The maximum number of transactions to "+
		"process in the mempool tx state syncer at a time.")

	// PoS Checkpoint Syncing
	cmd.PersistentFlags().StringSlice("checkpoint-syncing-providers", []string{}, fmt.Sprintf("A comma-separated list of URLs that "+
		"supports the committed tip block info endpoint to be used for checkpoint syncing. "+
		"If unset, the field will default to %v on mainnet and %v on testnet",
		lib.DefaultMainnetCheckpointProvider, lib.DefaultTestnetCheckpointProvider))
	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		viper.BindPFlag(flag.Name, flag)
	})
}
