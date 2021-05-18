package main

import (
	"flag"
	"fmt"
	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"os"
)

func main() {
	flag.Parse()

	pkBytes, _, err := lib.Base58CheckDecode("BC1YLg92n7EsQNnd1ryc6t2Fuczi7NSESYEWvqkorAs2Riq3J1PiEbK")
	if err != nil {
		panic(err)
	}
	//pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
	//if err != nil {
	//	panic(err)
	//}
	addressPubKey, err := btcutil.NewAddressPubKey(pkBytes, &chaincfg.MainNetParams)
	if err != nil {
		panic(err)
	}
	fmt.Println(addressPubKey.EncodeAddress())
	os.Exit(0)
}
