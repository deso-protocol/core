package toolslib

import (
	"bytes"
	"encoding/json"
	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

// _generateUnsignedCreatorCoinBuy...
func _generateUnsignedCreatorCoinBuy(buyerPubKey *btcec.PublicKey, creatorPubKey *btcec.PublicKey,
	amountNanos uint64, server string) (*lib.BuyOrSellCreatorCoinResponse, error){
	endpoint := "http://" + server + lib.RoutePathBuyOrSellCreatorCoin

	// Setup request
	payload := &lib.BuyOrSellCreatorCoinRequest{
		lib.PkToStringTestnet(buyerPubKey.SerializeCompressed()),
		lib.PkToStringTestnet(creatorPubKey.SerializeCompressed()),
		"buy",
		amountNanos,
		0,
		0,
		0,
		0,
		1000,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedCreatorCoinBuy() failed to marshal struct")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedCreatorCoinBuy() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedCreatorCoinBuy(): Received non 200 response code: " +
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	buyCCResponse := lib.BuyOrSellCreatorCoinResponse{}
	err = json.NewDecoder(resp.Body).Decode(&buyCCResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedCreatorCoinBuy(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedCreatorCoinBuy(): failed closing body")
	}

	return &buyCCResponse, nil
}

// BuyCreator...
func BuyCreator(buyerPubKey *btcec.PublicKey, buyerPrivKey *btcec.PrivateKey, creatorPubKey *btcec.PublicKey,
	amountNanos uint64, server string) error {

	// Request an unsigned transaction from server
	unsignedCCBuy, err := _generateUnsignedCreatorCoinBuy(buyerPubKey, creatorPubKey , amountNanos, server)
	if err != nil {
		return errors.Wrap(err, "BuyCreator() failed to call _generateUnsignedCreatorCoinBuy()")
	}
	txn := unsignedCCBuy.Transaction

	// Sign the transaction
	signature, err := txn.Sign(buyerPrivKey)
	if err != nil {
		return errors.Wrap(err, "BuyCreator() failed to sign transaction")
	}
	txn.Signature = signature

	// Submit the transaction to server
	err = SubmitTransactionToServer(txn, server)
	if err != nil {
		return errors.Wrap(err, "BuyCreator() failed to submit transaction")
	}
	return nil
}
