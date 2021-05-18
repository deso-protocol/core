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

// _generateUnsignedUpdateProfile...
func _generateUnsignedUpdateProfile(updaterPubKey *btcec.PublicKey, newUsername string, newDescription string,
	newProfilePic string, newCreatorBasisPoints uint64, server string) (*lib.UpdateProfileResponse, error) {
	endpoint := "http://" + server + lib.RoutePathUpdateProfile

	// Setup request
	payload := &lib.UpdateProfileRequest{
		lib.PkToStringTestnet(updaterPubKey.SerializeCompressed()),
		"",
		newUsername,
		newDescription,
		newProfilePic,
		newCreatorBasisPoints,
		12500,
		false,
		1000,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedUpdateProfile() failed to marshal json")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedUpdateProfile() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedUpdateProfile(): Received non 200 response code: " +
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	updateProfileResponse := lib.UpdateProfileResponse{}
	err = json.NewDecoder(resp.Body).Decode(&updateProfileResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedUpdateProfile(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedUpdateProfile(): failed closing body")
	}
	return &updateProfileResponse, nil
}

// UpdateProfile...
func UpdateProfile(updaterPubKey *btcec.PublicKey, updaterPrivKey *btcec.PrivateKey, newUsername string, newDescription string,
	newProfilePic string, newCreatorBasisPoints uint64, server string) error {

	// Request an unsigned transaction from server
	unsignedUpdateProfile, err := _generateUnsignedUpdateProfile(updaterPubKey, newUsername, newDescription,
		newProfilePic, newCreatorBasisPoints, server)
	if err != nil {
		return errors.Wrap(err, "UpdateProfile() failed to generate unsigned transaction")
	}
	txn := unsignedUpdateProfile.Transaction

	// Sign the transaction
	signature, err := txn.Sign(updaterPrivKey)
	if err != nil {
		return errors.Wrap(err, "UpdateProfile() failed to sign the transaction")
	}
	txn.Signature = signature

	// Submit the transaction to server
	err = SubmitTransactionToServer(txn, server)
	if err != nil {
		return errors.Wrap(err, "UpdateProfile() failed to submit transaction")
	}
	return nil
}
