package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/btcsuite/btcd/addrmgr"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
)

var (
	flagNode = flag.String(
		"node", "",
		"When dumping, should be pointed at a JSON API. E.g.: "+
			"https://api.bitclout.com. When loading, should "+
			"be pointed at a protocol port. E.g.: 127.0.0.1:17000")

	flagCommand = flag.String(
		"command", "",
		"Must be dump or load. When dump is specified, txns "+
			"are downloaded from the JSON API node and raw txn hex "+
			"is printed. When load is specified, txns are read from "+
			"stdin and injected into the protocol node specified.")

	flagDiffNode = flag.String(
		"diff_node", "",
		"A node to diff against. When set, "+
			"this should be a protocol port and --node must be a JSON port.")
)

func main() {
	flag.Parse()

	// Set up logging.
	log.Println("To log output on commandline, run with -alsologtostderr")
	glog.CopyStandardLogTo("INFO")

	if *flagNode == "" {
		panic("--node is required and must be a " +
			"JSON API when dumping or a protocol port when loading")
	}

	// Set up the to node as a peer
	netAddrss, err := lib.IPToNetAddr(*flagNode, addrmgr.New("", net.LookupIP), &lib.DeSoMainnetParams)
	if err != nil {
		panic(err)
	}

	netAddr2 := net.TCPAddr{
		IP:   netAddrss.IP,
		Port: int(netAddrss.Port),
	}
	conn, err := net.DialTimeout(netAddr2.Network(), netAddr2.String(), lib.DeSoMainnetParams.DialTimeout)
	if err != nil {
		panic(err)
	}

	messagesFromPeer := make(chan *lib.ServerMessage)
	peer := lib.NewPeer(conn, true, netAddrss, true,
		10000, 0, &lib.DeSoMainnetParams,
		messagesFromPeer, nil, nil)
	time.Sleep(1 * time.Second)
	if err := peer.NegotiateVersion(lib.DeSoMainnetParams.VersionNegotiationTimeout); err != nil {
		panic(err)
	}

	// As a test, send a GetHeaders request and see if we get it back
	if *flagCommand == "get_headers" {
		time.Sleep(1 * time.Second)
		peer.WriteDeSoMessage(&lib.MsgDeSoGetHeaders{
			StopHash: lib.MustDecodeHexBlockHash("0000000000000000000000000000000000000000000000000000000000000000"),
			BlockLocator: []*lib.BlockHash{
				lib.MustDecodeHexBlockHash("0000000000f70d7a6dce5502eddb40772fc4b6b1e54e809b21bd38c6bd447e05"),
				lib.MustDecodeHexBlockHash("0000000000c49db46a5ba1a9d35dfd870c791ea6b695c49e522fe9a7c0f308e8"),
				lib.MustDecodeHexBlockHash("0000000000597c8ebfe3122c2aa003b6dc0fd67e97e6b4cae437517dd2f500a4"),
				lib.MustDecodeHexBlockHash("0000000000da97c2b70bbd5af7d707ff7772ac7064e4946b1aebf5b863902723"),
				lib.MustDecodeHexBlockHash("000000000083a5ef8c0df071362668f1b1bd764f02ef4aeebf25a9f54f721189"),
				lib.MustDecodeHexBlockHash("0000000000f0636590f0d1a1d163edac52611269c56cf1601a27c182af2b7752"),
				lib.MustDecodeHexBlockHash("0000000000fd9249bd4f89e12e74b3107e11694b1b5dadf61af08f1218943861"),
				lib.MustDecodeHexBlockHash("00000000006ad067641de4bd55218fbf2b3b260054a2d8a1a2ca0843199f89ea"),
				lib.MustDecodeHexBlockHash("0000000000e0f41c722d853639b1f9aefd7ac7613f249e6f71c41349b4e03ff3"),
				lib.MustDecodeHexBlockHash("0000000000b0add5db4833d26406625925c5ef4d3097bbee67037723a3f8e391"),
				lib.MustDecodeHexBlockHash("00000000001662747a5f03db9d6551a72250cc32747597b004bf95f328bae57e"),
				lib.MustDecodeHexBlockHash("0000000000d6267bca36f88efa9e6947bbe36149d378fd9464e72db48dc22dca"),
				lib.MustDecodeHexBlockHash("00000000006f422c0bd7f4154cb3a6173e2e7cf2fc10c63ca75c1aeeb9b1d563"),
				lib.MustDecodeHexBlockHash("00000000007da3b19ddcf04c57b3c936ec1dcaa6c21214c33aa256afced22aca"),
				lib.MustDecodeHexBlockHash("00000000003802f3a2fc4fa3775780d704486b65b9ed56b67f6d4c3335a7b9b5"),
				lib.MustDecodeHexBlockHash("00000000009552ebd611e4f9d8c2cb4f08d8f17da2b739979604a2a0743d433d"),
				lib.MustDecodeHexBlockHash("0000000000060c2df58fca53b083dc0b6879a49aa69e5c9c6d12ec7e6e8c8890"),
				lib.MustDecodeHexBlockHash("0000000000032f0ab25daa56eab3000dda92ce52a128ca57e8cb17bb8c1e2ced"),
				lib.MustDecodeHexBlockHash("00000000007b2444f17f8fcf216c52f32d4c0e374c4598957443c20209e7e39b"),
				lib.MustDecodeHexBlockHash("00000000008df3db9dda88e1f2dada964e28e0c05030861eaf351a875cf154bb"),
				lib.MustDecodeHexBlockHash("00000000006bff73eea66c748c089fe384b76fddf24b0830abad8343e2c53813"),
				lib.MustDecodeHexBlockHash("0000000000830059a9eb948f3ed3996ff93efb642d09a71744327ceafe9e10ea"),
				lib.MustDecodeHexBlockHash("0000000000a5da7ccb9a3e6824dedc31ed112cdd22cc2ca9d1e98992deb97225"),
				lib.MustDecodeHexBlockHash("000000004a9facc6804cb39cdf5f1c2360dc372d4e532dccd5c3489671eacd29"),
				lib.MustDecodeHexBlockHash("5567c45b7b83b604f9ff5cb5e88dfc9ad7d5a1dd5818dd19e6d02466f47cbd62"),
			},
		})

		log.Println("Sent GetHeaders message. Waiting for response")

		// There should be a single inv that comes back
		for {
			msg, err := peer.ReadDeSoMessage()
			if err != nil {
				panic(err)
			}
			fmt.Println(msg.GetMsgType())
		}
	} else if *flagCommand == "dump" {
		time.Sleep(1 * time.Second)
		peer.WriteDeSoMessage(&lib.MsgDeSoMempool{})
		log.Println("Sent Mempool message. Waiting for big inv")

		// There should be a single inv that comes back
		for {
			msg, err := peer.ReadDeSoMessage()
			if err != nil {
				panic(err)
			}
			if msg.GetMsgType() == lib.MsgTypeInv {
				invMsg := msg.(*lib.MsgDeSoInv)
				if len(invMsg.InvList) == 0 {
					log.Println("Ignoringing empty INV")
					continue
				}
				if invMsg.InvList[0].Type == lib.InvTypeBlock {
					log.Println("Ignoring BLOCK INV")
					continue
				}
				log.Println("Processing inv of size ", len(invMsg.InvList))
				hashesToRequest := []*lib.BlockHash{}
				for _, inv := range invMsg.InvList {
					if inv.Type == lib.InvTypeTx {
						hashesToRequest = append(hashesToRequest, &inv.Hash)
					}
				}

				// Now we have all the hashes, request the txn.
				getTxns := &lib.MsgDeSoGetTransactions{}
				getTxns.HashList = hashesToRequest

				// Fetch all the txns back from the node
				peer.WriteDeSoMessage(getTxns)
				time.Sleep(100 * time.Millisecond)

			} else if msg.GetMsgType() == lib.MsgTypeTransactionBundle {
				txBundle := msg.(*lib.MsgDeSoTransactionBundle)
				log.Println("Processing txn bundle of size ", len(txBundle.Transactions))
				for _, tx := range txBundle.Transactions {
					bb, _ := tx.ToBytes(false /*preSignature*/)
					fmt.Printf("%v,%v,%v\n", tx.TxnMeta.GetTxnType(), tx.Hash(), hex.EncodeToString(bb))
				}

				time.Sleep(1)
				peer.Disconnect()
				break
			}
		}
	} else if *flagCommand == "load" {
		scanner := bufio.NewScanner(os.Stdin)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 250*1024*1024)
		txnBundle := &lib.MsgDeSoTransactionBundle{}
		getTxnMsg := &lib.MsgDeSoGetTransactions{}
		for scanner.Scan() {
			txnHex := scanner.Text()

			parts := strings.Split(txnHex, ",")
			if len(parts) != 1 {
				txnHex = parts[2]
			}

			bb, err := hex.DecodeString(txnHex)
			if err != nil {
				panic(err)
			}
			txn := &lib.MsgDeSoTxn{}
			if err := txn.FromBytes(bb); err != nil {
				glog.Error(err)
				continue
			}

			txnBundle.Transactions = append(txnBundle.Transactions, txn)

			getTxnMsg.HashList = append(getTxnMsg.HashList, txn.Hash())
		}
		if err := scanner.Err(); err != nil {
			panic(err)
		}

		fmt.Println(len(txnBundle.Transactions))

		// Write all the messages to the node
		peer.WriteDeSoMessage(txnBundle)

		// Fetch all the txns back from the node
		peer.WriteDeSoMessage(getTxnMsg)

		for {
			msg, err := peer.ReadDeSoMessage()
			if err != nil {
				panic(err)
			}
			txnsFound := make(map[lib.BlockHash]*lib.MsgDeSoTxn)
			if msg.GetMsgType() == lib.MsgTypeTransactionBundle {
				for _, txn := range msg.(*lib.MsgDeSoTransactionBundle).Transactions {
					txnsFound[*txn.Hash()] = txn
				}

				summary := make(map[lib.TxnType]int64)
				for _, txn := range txnBundle.Transactions {
					if _, exists := txnsFound[*txn.Hash()]; !exists {
						glog.Infof("NOT LOADED: %v %v", txn.TxnMeta.GetTxnType(), txn.Hash())
						bb, err := txn.ToBytes(false)
						if err != nil {
							panic(err)
						}
						glog.V(1).Infof("TXN HEX: %v", hex.EncodeToString(bb))
						glog.V(2).Infof("DETAILS: %v", spew.Sdump(txn))

						val, _ := summary[txn.TxnMeta.GetTxnType()]
						summary[txn.TxnMeta.GetTxnType()] = val + 1
					}
				}
				glog.Info("Summary of missing txns: ", spew.Sdump(summary))
				break
			}
		}

		peer.Disconnect()

	} else {
		fmt.Println("Command must be 'dump' or 'load'")
		os.Exit(0)
	}
}
