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

func _generateUnsignedMessage(senderPubKey *btcec.PublicKey, recipientPubKey *btcec.PublicKey, message string,
	server string) (*lib.SendMessageStatelessResponse, error){
	endpoint := "http://" + server + lib.RoutePathSendMessageStateless

	// Setup request
	payload := &lib.SendMessageStatelessRequest{
		lib.PkToStringTestnet(senderPubKey.SerializeCompressed()),
		lib.PkToStringTestnet(recipientPubKey.SerializeCompressed()),
		message,
		1000,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedMessage() failed to marshal struct")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedMessage() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedMessage(): Received non 200 response code: " +
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	sendMessageResponse := lib.SendMessageStatelessResponse{}
	err = json.NewDecoder(resp.Body).Decode(&sendMessageResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedMessage(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedMessage(): failed closing body")
	}

	return &sendMessageResponse, nil
}

func SendMessage(senderPubKey *btcec.PublicKey, senderPrivKey *btcec.PrivateKey,
	recipientPubKey *btcec.PublicKey, message string, server string) error {

	// Request an unsigned transaction from server
	unsignedMessage, err := _generateUnsignedMessage(senderPubKey, recipientPubKey, message, server)
	if err != nil {
		return errors.Wrap(err, "SendMessage() failed to call _generateSendBitclout()")
	}
	txn := unsignedMessage.Transaction

	// Sign the transaction
	signature, err := txn.Sign(senderPrivKey)
	if err != nil {
		return errors.Wrap(err, "SendMessage() failed to sign transaction")
	}
	txn.Signature = signature

	// Submit the transaction to server
	err = SubmitTransactionToServer(txn, server)
	if err != nil {
		return errors.Wrap(err, "SendMessage() failed to submit transaction")
	}
	return nil
}
