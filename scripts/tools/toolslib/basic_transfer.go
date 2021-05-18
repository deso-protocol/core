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

// _generateUnsignedSendBitclout...
func _generateUnsignedSendBitclout(senderPubKey *btcec.PublicKey, recipientPubKey *btcec.PublicKey, amountNanos int64,
	server string) (*lib.SendBitCloutResponse, error) {
	endpoint := "http://" + server + lib.RoutePathSendBitClout

	// Setup request
	payload := &lib.SendBitCloutRequest{
		lib.PkToStringTestnet(senderPubKey.SerializeCompressed()),
		lib.PkToStringTestnet(recipientPubKey.SerializeCompressed()),
		amountNanos,
		0,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendBitclout() failed to marshal struct")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendBitclout() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedSendBitclout(): Received non 200 response code: " +
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	sendBitcloutResponse := lib.SendBitCloutResponse{}
	err = json.NewDecoder(resp.Body).Decode(&sendBitcloutResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendBitclout(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendBitclout(): failed closing body")
	}

	return &sendBitcloutResponse, nil
}

// SendBitClout...
func SendBitClout(senderPubKey *btcec.PublicKey,
	senderPrivKey *btcec.PrivateKey,
	recipientPubKey *btcec.PublicKey, amountNanos int64, server string) error {

	// Request an unsigned transaction from server
	unsignedSendBitclout, err := _generateUnsignedSendBitclout(senderPubKey, recipientPubKey, amountNanos, server)
	if err != nil {
		return errors.Wrap(err, "SendBitclout() failed to call _generateSendBitclout()")
	}
	txn := unsignedSendBitclout.Transaction

	// Sign the transaction
	signature, err := txn.Sign(senderPrivKey)
	if err != nil {
		return errors.Wrap(err, "SendBitclout() failed to sign transaction")
	}
	txn.Signature = signature

	// Submit the transaction to server
	err = SubmitTransactionToServer(txn, server)
	if err != nil {
		return errors.Wrap(err, "SendBitclout() failed to submit transaction")
	}
	return nil
}
