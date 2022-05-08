package lib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/pkg/errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// bitcoin_burner.go finds the Bitcoin UTXOs associated with a Bitcoin
// address and constructs a burn transaction on behalf of the user. Note that the
// use of an API here is strictly cosmetic, and that none of this
// logic is used for actually validating anything (that is all done by bitcoin_manager.go,
// which relies on Bitcoin peers and is fully decentralized). The user can
// also simply use an existing Bitcoin wallet to send Bitcoin to the burn address
// rather than this utility, but that is slightly less convenient than just
// baking this functionality in, which is why we do it.
//
// TODO: If this API doesn't work in the long run, I think the ElectrumX network would
// be a pretty good alternative.

type BitcoinUtxo struct {
	TxID           *chainhash.Hash
	Index          int64
	AmountSatoshis int64
}

func _estimateBitcoinTxSize(numInputs int, numOutputs int) int {
	return numInputs*180 + numOutputs*34
}

func EstimateBitcoinTxFee(
	numInputs int, numOutputs int, feeRateSatoshisPerKB uint64) uint64 {

	return uint64(_estimateBitcoinTxSize(numInputs, numOutputs)) * feeRateSatoshisPerKB / 1000
}

func CreateUnsignedBitcoinSpendTransaction(
	spendAmountSatoshis uint64,
	feeRateSatoshisPerKB uint64,
	spendAddrString string,
	recipientAddrString string,
	params *DeSoParams,
	utxoSource func(addr string, params *DeSoParams) ([]*BitcoinUtxo, error)) (
	_txn *wire.MsgTx, _totalInput uint64, _fee uint64, _err error) {

	// Get the utxos for the spend key.
	bitcoinUtxos, err := utxoSource(spendAddrString, params)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem getting "+
			"Bitcoin utxos for Bitcoin address %s",
			spendAddrString)
	}

	glog.V(2).Infof("CreateUnsignedBitcoinSpendTransaction: Found %d BitcoinUtxos", len(bitcoinUtxos))

	// Create the transaction we'll be returning.
	retTxn := &wire.MsgTx{}
	// Set locktime to 0 since we're not using it.
	retTxn.LockTime = 0
	// The version seems to be 2 these days.
	retTxn.Version = 2

	// Add an output sending spendAmountSatoshis to the recipientAddress.
	//
	// We decode it twice in order to guarantee that we're sending to an *address*
	// rather than to a public key.
	recipientOutput := &wire.TxOut{}
	recipientAddrTmp, err := btcutil.DecodeAddress(
		recipientAddrString, params.BitcoinBtcdParams)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem decoding "+
			"recipient address %s", recipientAddrString)
	}
	recipientAddr, err := btcutil.DecodeAddress(
		recipientAddrTmp.EncodeAddress(), params.BitcoinBtcdParams)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem decoding "+
			"recipient address pubkeyhash %s %s", recipientAddrString, recipientAddrTmp.EncodeAddress())
	}
	recipientOutput.PkScript, err = txscript.PayToAddrScript(recipientAddr)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem adding script: %v", err)
	}
	recipientOutput.Value = int64(spendAmountSatoshis)
	retTxn.TxOut = append(retTxn.TxOut, recipientOutput)

	// Decode the spendAddrString.
	//
	// We decode it twice in order to guarantee that we're sending to an *address*
	// rather than to a public key.
	spendAddrTmp, err := btcutil.DecodeAddress(
		spendAddrString, params.BitcoinBtcdParams)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem decoding "+
			"spend address %s", spendAddrString)
	}
	spendAddr, err := btcutil.DecodeAddress(
		spendAddrTmp.EncodeAddress(), params.BitcoinBtcdParams)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem decoding "+
			"spend address pubkeyhash %s %s", spendAddrString, spendAddrTmp.EncodeAddress())
	}

	// Rack up the number of utxos you need to pay the spend amount. Add each
	// one to our transaction until we have enough to cover the spendAmount
	// plus the fee.
	totalInputSatoshis := uint64(0)
	for _, bUtxo := range bitcoinUtxos {
		totalInputSatoshis += uint64(bUtxo.AmountSatoshis)

		// Construct an input corresponding to this utxo.
		txInput := &wire.TxIn{}
		txInput.PreviousOutPoint = *wire.NewOutPoint(bUtxo.TxID, uint32(bUtxo.Index))
		// Set Sequence to the max value to disable locktime and opt out of RBF.
		txInput.Sequence = math.MaxUint32
		// Don't set the SignatureScript yet.

		// Set the input on the transaction.
		retTxn.TxIn = append(retTxn.TxIn, txInput)

		// If the total input we've accrued thus far covers the spend amount and the
		// fee precisely, then we're done.
		txFee := EstimateBitcoinTxFee(
			len(retTxn.TxIn), len(retTxn.TxOut), feeRateSatoshisPerKB)
		if totalInputSatoshis == spendAmountSatoshis+txFee {
			break
		}

		// Since our input did not precisely equal the spend amount plus the fee,
		// see if if the input exceeds the spend amount plus the fee after we add
		// a change output. If it does, then we're done. Note the +1 in the function
		// call below.
		txFeeWithChange := EstimateBitcoinTxFee(
			len(retTxn.TxIn), len(retTxn.TxOut)+1, feeRateSatoshisPerKB)
		if totalInputSatoshis >= spendAmountSatoshis+txFeeWithChange {
			// In this case we add a change output to the transaction that sends the
			// excess Bitcoin back to the spend address.
			changeOutput := &wire.TxOut{}
			changeOutput.PkScript, err = txscript.PayToAddrScript(spendAddr)
			if err != nil {
				return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem adding script: %v", err)
			}

			totalOutputSatoshis := spendAmountSatoshis + txFeeWithChange
			changeOutput.Value = int64(totalInputSatoshis - totalOutputSatoshis)
			// Don't append a change output if it is below the dust threshold.
			// TODO: Is 1,000 enough for the dust threshold?
			dustOutputSatoshis := int64(1000)
			if changeOutput.Value > dustOutputSatoshis {
				retTxn.TxOut = append(retTxn.TxOut, changeOutput)
			}

			break
		}
	}

	// At this point, if the totalInputSatoshis is not greater than or equal to
	// the spend amount plus the estimated fee then we didn't have enough input
	// to successfully form the transaction.
	finalFee := EstimateBitcoinTxFee(
		len(retTxn.TxIn), len(retTxn.TxOut), feeRateSatoshisPerKB)
	if totalInputSatoshis < spendAmountSatoshis+finalFee {
		return nil, 0, 0, fmt.Errorf("CreateUnsignedBitcoinSpendTransaction: Total input satoshis %d is "+
			"not sufficient to cover the spend amount %d plus the fee %d",
			totalInputSatoshis, spendAmountSatoshis, finalFee)
	}

	return retTxn, totalInputSatoshis, finalFee, nil
}

// Check whether the deposits being used to construct this transaction have RBF enabled.
// If they do then we force the user to wait until those deposits have been mined into a
// block before allowing this transaction to go through. This prevents double-spend
// attacks where someone replaces a dependent transaction with a higher fee.
//
// TODO: We use a pretty janky API to check for this, and if it goes down then
// BitcoinExchange txns break. But without it we're vulnerable to double-spends
// so we keep it for now.
func CheckRBF(bitcoinTxn *wire.MsgTx, bitcoinTxnHash chainhash.Hash, desoParams *DeSoParams) (bool, error) {
	// Check whether the deposits being used to construct this transaction have RBF enabled.
	// If they do then we force the user to wait until those deposits have been mined into a
	// block before allowing this transaction to go through. This prevents double-spend
	// attacks where someone replaces a dependent transaction with a higher fee.
	//
	// TODO: We use a pretty janky API to check for this, and if it goes down then
	// BitcoinExchange txns break. But without it we're vulnerable to double-spends
	// so we keep it for now.
	if desoParams.NetworkType == NetworkType_MAINNET {
		// Go through the transaction's inputs. If any of them have RBF set then we
		// must assume that this transaction has RBF as well.
		for _, txIn := range bitcoinTxn.TxIn {
			isRBF, err := BlockonomicsCheckRBF(txIn.PreviousOutPoint.Hash.String())
			if err != nil {
				glog.Errorf("ExchangeBitcoinStateless: ERROR: Blockonomics request to check RBF for txn "+
					"hash %v failed. This is bad because it means users are not able to "+
					"complete Bitcoin burns: %v", txIn.PreviousOutPoint.Hash.String(), err)
				return true, fmt.Errorf(
					"The nodes are still processing your deposit. Please wait a few seconds " +
						"and try again.")
			}
			// If we got a success response from Blockonomics then bail if the transaction has
			// RBF set.
			if isRBF {
				glog.Errorf("ExchangeBitcoinStateless: ERROR: Blockonomics found RBF txn: %v", bitcoinTxnHash.String())
				return true, nil
			}
		}
	}

	return false, nil
}

func CreateBitcoinSpendTransaction(
	spendAmountSatoshis uint64, feeRateSatoshisPerKB uint64,
	pubKey *btcec.PublicKey,
	recipientAddrString string, params *DeSoParams,
	utxoSource func(addr string, params *DeSoParams) ([]*BitcoinUtxo, error)) (_txn *wire.MsgTx, _totalInput uint64, _fee uint64, _unsignedHashes []string, _err error) {

	// Convert the public key into a Bitcoin address.
	spendAddrTmp, err := btcutil.NewAddressPubKey(pubKey.SerializeCompressed(), params.BitcoinBtcdParams)
	spendAddrr := spendAddrTmp.AddressPubKeyHash()
	if err != nil {
		return nil, 0, 0, nil, errors.Wrapf(err, "CreateBitcoinSpendTransaction: Problem converting "+
			"pubkey to address: ")
	}
	spendAddrString := spendAddrr.EncodeAddress()

	glog.V(2).Infof("CreateBitcoinSpendTransaction: Creating spend for "+
		"<from: %s, to: %s> for amount %d, feeRateSatoshisPerKB %d",
		spendAddrString,
		recipientAddrString, spendAmountSatoshis, feeRateSatoshisPerKB)

	retTxn, totalInputSatoshis, finalFee, err := CreateUnsignedBitcoinSpendTransaction(
		spendAmountSatoshis, feeRateSatoshisPerKB, spendAddrString,
		recipientAddrString, params, utxoSource)
	if err != nil {
		return nil, 0, 0, nil, errors.Wrapf(err, "CreateBitcoinSpendTransaction: Problem "+
			"creating unsigned Bitcoin spend: ")
	}

	// At this point we are confident the transaction has enough input to cover its
	// outputs. Now go through and set the input scripts.
	//
	// All the inputs are signing an identical output script corresponding to the
	// spend address.
	outputScriptToSign, err := txscript.PayToAddrScript(spendAddrr)
	if err != nil {
		return nil, 0, 0, nil, errors.Wrapf(err, "CreateBitcoinSpendTransaction: Problem computing "+
			"output script for spendAddr %v", spendAddrr)
	}

	// Calculate the unsigned hash for each input
	// We pass these to the identity service on the frontend for the client to sign
	unsignedHashes := []string{}
	for ii := range retTxn.TxIn {
		hashBytes, err := txscript.CalcSignatureHash(outputScriptToSign, txscript.SigHashAll, retTxn, ii)
		if err != nil {
			return nil, 0, 0, nil, errors.Wrapf(err, "CreateBitcoinSpendTransaction: Problem "+
				"creating signature hash for input %d", ii)
		}

		unsignedHashes = append(unsignedHashes, hex.EncodeToString(hashBytes))
	}

	// At this point all the inputs should be signed and the total input should cover
	// the spend amount plus the fee with any change going back to the spend address.
	glog.V(2).Infof("CreateBitcoinSpendTransaction: Created transaction with "+
		"(%d inputs, %d outputs, %d total input, %d spend amount, %d change, %d fee)",
		len(retTxn.TxIn), len(retTxn.TxOut), totalInputSatoshis,
		spendAmountSatoshis, totalInputSatoshis-spendAmountSatoshis-finalFee, finalFee)

	return retTxn, totalInputSatoshis, finalFee, unsignedHashes, nil
}

func IsBitcoinTestnet(params *DeSoParams) bool {
	return params.BitcoinBtcdParams.Name == "testnet3"
}

// ======================================================================================
// BlockCypher API code
//
// This is bascially a user experience hack. We use BlockCypher to fetch
// BitcoinUtxos to determine what the user is capable of spending from their address
// and to craft burn transactions for the user using their address and available utxos. Note
// that we could do this in the BitcoinManager and cut reliance on BlockCypher to make
// decentralized, but it would increase complexity significantly. Moreover, this
// piece is not critical to the protocol or to consensus, and it breaking doesn't even
// stop people from being able to purchase DeSo since they can always do that by sending
// Bitcoin to the burn address from any standard Bitcoin client after entering their
// seed phrase.
// ======================================================================================

type BlockCypherAPIInputResponse struct {
	PrevTxIDHex    string   `json:"prev_hash"`
	Index          int64    `json:"output_index"`
	ScriptHex      string   `json:"script"`
	AmountSatoshis int64    `json:"output_value"`
	Sequence       int64    `json:"sequence"`
	Addresses      []string `json:"addresses"`
	ScriptType     string   `json:"script_type"`
	Age            int64    `json:"age"`
}

type BlockCypherAPIOutputResponse struct {
	AmountSatoshis int64    `json:"value"`
	ScriptHex      string   `json:"script"`
	Addresses      []string `json:"addresses"`
	ScriptType     string   `json:"script_type"`
	SpentBy        string   `json:"spent_by"`
}

type BlockCypherAPITxnResponse struct {
	BlockHashHex  string                          `json:"block_hash"`
	BlockHeight   int64                           `json:"block_height"`
	LockTime      int64                           `json:"lock_time"`
	TxIDHex       string                          `json:"hash"`
	Inputs        []*BlockCypherAPIInputResponse  `json:"inputs"`
	Outputs       []*BlockCypherAPIOutputResponse `json:"outputs"`
	Confirmations int64                           `json:"confirmations"`
	DoubleSpend   bool                            `json:"double_spend"`
	TxnHex        string                          `json:"hex"`
}

type BlockCypherAPIFullAddressResponse struct {
	Address string `json:"address"`
	// Balance data
	ConfirmedBalance   int64 `json:"balance"`
	UnconfirmedBalance int64 `json:"unconfirmed_balance"`
	FinalBalance       int64 `json:"final_balance"`

	// Transaction data
	Txns []*BlockCypherAPITxnResponse `json:"txs"`

	HasMore bool `json:"hasMore"`

	Error string `json:"error"`
}

type BlockchainInfoAPIResponse struct {
	DoubleSpend bool `json:"double_spend"`
}

func BlockCypherExtractBitcoinUtxosFromResponse(
	apiData *BlockCypherAPIFullAddressResponse, addrString string, params *DeSoParams) (
	[]*BitcoinUtxo, error) {

	glog.V(2).Infof("BlockCypherExtractBitcoinUtxosFromResponse: Extracting BitcoinUtxos "+
		"from %d txns", len(apiData.Txns))
	addr, err := btcutil.DecodeAddress(addrString, params.BitcoinBtcdParams)
	if err != nil {
		return nil, fmt.Errorf("BlockCypherExtractBitcoinUtxosFromResponse: "+
			"Error decoding address %v: %v", addrString, err)
	}
	outputScriptForAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, fmt.Errorf("BlockCypherExtractBitcoinUtxosFromResponse: "+
			"Error creating output script for addr %v: %v", addrString, err)
	}

	// Go through and index all of the outputs that appear as inputs. The reason
	// we must do this is because the API only sets to SpentBy field if a transaction
	// has at least one confirmation. So, in order to mark outputs as spent when they
	// appear in transactions that aren't confirmed, we need to make this adjustment.
	//
	// We overload the BitcoinUtxo here because it's easier than defining a new struct.
	type utxoKey struct {
		TxIDHex string
		Index   int64
	}
	outputsSpentInResponseInputs := make(map[utxoKey]bool)
	for _, txn := range apiData.Txns {
		for _, input := range txn.Inputs {
			currentUtxo := utxoKey{
				TxIDHex: input.PrevTxIDHex,
				Index:   input.Index,
			}
			outputsSpentInResponseInputs[currentUtxo] = true
		}

	}

	bitcoinUtxos := []*BitcoinUtxo{}
	for _, txn := range apiData.Txns {
		for outputIndex, output := range txn.Outputs {
			if output.SpentBy != "" {
				// This is how we determine if an output is spent or not.
				continue
			}
			if output.ScriptHex != hex.EncodeToString(outputScriptForAddr) {
				// Only outputs that are destined for the passed-in address are considered.
				continue
			}
			if output.AmountSatoshis == 0 {
				// Ignore outputs that don't have any BTC in them. This is also helpful
				// to prevent weird bugs where the API response changed the name of a
				// field or something.
				continue
			}

			// If the output is spent in one of the inputs of the API response then
			// consider it spent here. We do this to count confirmed transactions in
			// the utxo set.
			currentUtxo := utxoKey{
				TxIDHex: txn.TxIDHex,
				Index:   int64(outputIndex),
			}
			if _, exists := outputsSpentInResponseInputs[currentUtxo]; exists {
				continue
			}

			// If we get here we know we are dealing with an unspent output destined
			// for the address passed in.

			bUtxo := &BitcoinUtxo{}
			bUtxo.AmountSatoshis = output.AmountSatoshis
			bUtxo.Index = int64(outputIndex)
			txid := (chainhash.Hash)(*mustDecodeHexBlockHashBitcoin(txn.TxIDHex))
			bUtxo.TxID = &txid

			bitcoinUtxos = append(bitcoinUtxos, bUtxo)
		}
	}

	glog.V(2).Infof("BlockCypherExtractBitcoinUtxosFromResponse: Extracted %d BitcoinUtxos",
		len(bitcoinUtxos))

	return bitcoinUtxos, nil
}

func GetBlockCypherAPIFullAddressResponse(addrString string, params *DeSoParams) (
	_apiData *BlockCypherAPIFullAddressResponse, _err error) {

	URL := fmt.Sprintf("http://api.blockcypher.com/v1/btc/main/addrs/%s/full", addrString)
	if IsBitcoinTestnet(params) {
		URL = fmt.Sprintf("http://api.blockcypher.com/v1/btc/test3/addrs/%s/full", addrString)
	}
	glog.V(2).Infof("GetBlockCypherAPIFullAddressResponse: Querying URL: %s", URL)

	// jsonValue, err := json.Marshal(postData)
	req, _ := http.NewRequest("GET", URL, nil)
	req.Header.Set("Content-Type", "application/json")

	// To add a ?a=b query string, use the below.
	q := req.URL.Query()
	// TODO: Right now we'll only fetch a maximum of 50 transactions from the API.
	// This means if the user has done more than 50 transactions with their address
	// we'll start missing some of the older utxos. This is easy to fix, though, and
	// just amounts to cycling through the API's pages. Note also that this does not
	// prevent a user from buying DeSo in this case nor does it prevent her from being
	// able to recover her Bitcoin. Both of these can be accomplished by loading the
	// address in a standard Bitcoin wallet like Electrum.
	q.Add("limit", "50")
	req.URL.RawQuery = q.Encode()
	glog.V(2).Infof("GetBlockCypherAPIFullAddressResponse: URL with params: %s", req.URL)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GetBlockCypherAPIFullAddressResponse: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	// Decode the response into the appropriate struct.
	body, _ := ioutil.ReadAll(resp.Body)
	responseData := &BlockCypherAPIFullAddressResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return nil, fmt.Errorf("GetBlockCypherAPIFullAddressResponse: Problem decoding response JSON into "+
			"interface %v, response: %v, error: %v", responseData, resp, err)
	}
	//glog.V(2).Infof("BlockCypherUtxoSource: Received response: %v", responseData)

	if responseData.Error != "" {
		return nil, fmt.Errorf("GetBlockCypherAPIFullAddressResponse: Had an "+
			"error in the response: %s", responseData.Error)
	}

	return responseData, nil
}

func BlockCypherUtxoSource(addrString string, params *DeSoParams) (
	[]*BitcoinUtxo, error) {

	apiData, err := GetBlockCypherAPIFullAddressResponse(addrString, params)
	if err != nil {
		return nil, errors.Wrapf(err, "BlockCypherUtxoSource: Problem getting API data "+
			"for address %s: ", addrString)
	}

	return BlockCypherExtractBitcoinUtxosFromResponse(apiData, addrString, params)
}

// The frontend passes in the apiData. We do this so that our server doesn't
// get rate-limited by the free tier.
func FrontendBlockCypherUtxoSource(
	apiData *BlockCypherAPIFullAddressResponse, addrString string,
	params *DeSoParams) (
	[]*BitcoinUtxo, error) {

	return BlockCypherExtractBitcoinUtxosFromResponse(apiData, addrString, params)
}

func BlockchainInfoCheckBitcoinDoubleSpend(txnHash *chainhash.Hash, blockCypherAPIKey string, params *DeSoParams) (
	_isDoubleSpend bool, _err error) {

	// Always pass on testnet for simplicity.
	if IsBitcoinTestnet(params) {
		return false, nil
	}
	URL := fmt.Sprintf("https://blockchain.info/rawtx/%s", txnHash.String())
	glog.V(2).Infof("BlockchainInfoCheckBitcoinDoubleSpend: Querying URL: %s", URL)

	req, _ := http.NewRequest("GET", URL, nil)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("BlockchainInfoCheckBitcoinDoubleSpend: "+
			"Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		glog.V(2).Infof("BlockchainInfoCheckBitcoinDoubleSpend: Bitcoin txn with "+
			"hash %v was not found in Blockchain.info OR an error occurred: %v", txnHash, spew.Sdump(resp))
		return true, nil
	}

	// Decode the response into the appropriate struct.
	body, _ := ioutil.ReadAll(resp.Body)
	responseData := &BlockchainInfoAPIResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return false, fmt.Errorf("BlockchainInfoCheckBitcoinDoubleSpend: "+
			"Problem decoding response JSON into "+
			"interface %v, response: %v, error: %v", responseData, resp, err)
	}

	if responseData.DoubleSpend {
		glog.V(2).Infof("BlockchainInfoCheckBitcoinDoubleSpend: Bitcoin "+
			"txn with hash %v was a double spend", txnHash)
		return true, nil
	}

	return false, nil
}

func GetBlockCypherTxnResponse(txnHash *chainhash.Hash, blockCypherAPIKey string, params *DeSoParams) (*BlockCypherAPITxnResponse, error) {
	URL := fmt.Sprintf("http://api.blockcypher.com/v1/btc/main/txs/%s", txnHash.String())
	if IsBitcoinTestnet(params) {
		URL = fmt.Sprintf("http://api.blockcypher.com/v1/btc/test3/txs/%s", txnHash.String())
	}
	glog.V(2).Infof("CheckBitcoinDoubleSpend: Querying URL: %s", URL)

	// jsonValue, err := json.Marshal(postData)
	req, _ := http.NewRequest("GET", URL, nil)
	req.Header.Set("Content-Type", "application/json")

	// To add a ?a=b query string, use the below.
	q := req.URL.Query()
	// TODO: Right now we'll only fetch a maximum of 50 transactions from the API.
	// This means if the user has done more than 50 transactions with their address
	// we'll start missing some of the older utxos. This is easy to fix, though, and
	// just amounts to cycling through the API's pages. Note also that this does not
	// prevent a user from buying DeSo in this case nor does it prevent her from being
	// able to recover her Bitcoin. Both of these can be accomplished by loading the
	// address in a standard Bitcoin wallet like Electrum.
	q.Add("token", blockCypherAPIKey)
	req.URL.RawQuery = q.Encode()
	glog.V(2).Infof("CheckBitcoinDoubleSpend: URL with params: %s", req.URL)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CheckBitcoinDoubleSpend: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil
	} else if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("CheckBitcoinDoubleSpend: Error code returned "+
			"from BlockCypher: %v %v", resp.StatusCode, string(body))
	}

	// Decode the response into the appropriate struct.
	body, _ := ioutil.ReadAll(resp.Body)
	responseData := &BlockCypherAPITxnResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return nil, fmt.Errorf("CheckBitcoinDoubleSpend: Problem decoding response JSON into "+
			"interface %v, response: %v, error: %v", responseData, resp, err)
	}

	return responseData, nil
}

func BlockCypherCheckBitcoinDoubleSpend(txnHash *chainhash.Hash, blockCypherAPIKey string, params *DeSoParams) (
	_isDoubleSpend bool, _err error) {

	glog.Infof("CheckBitcoinDoubleSpend: Checking txn %v for double-spend", txnHash)
	responseData, err := GetBlockCypherTxnResponse(txnHash, blockCypherAPIKey, params)
	if err != nil {
		return false, errors.Wrapf(err, "BlockCypherCheckBitcoinDoubleSpend: Error fetching txn: ")
	}

	// If we didn't find the txn in BlockCypher then we consider this a double-spend
	if responseData == nil {
		glog.V(2).Infof("CheckBitcoinDoubleSpend: Bitcoin txn with hash %v was not found in BlockCypher", txnHash)
		return true, nil
	}

	if responseData.DoubleSpend {
		glog.V(2).Infof("CheckBitcoinDoubleSpend: Bitcoin txn with hash %v was a double spend", txnHash)
		return true, nil
	}

	// If the transaction is not mined, then we need to recursively check
	// its inputs to determine whether they are double-spends.
	if responseData.Confirmations == 0 {
		// If there are too many inputs on this txn, then just mark it as a double-spend.
		// This avoids us having to use our API quota unnecessarily.
		if len(responseData.Inputs) > 25 {
			glog.Warningf("CheckBitcoinDoubleSpend: Unmined bitcoin txn with hash %v had %v inputs, "+
				"which made us label it as a double-spend. If this is happening a lot, consider "+
				"increasing the limit on this if statement", txnHash, len(responseData.Inputs))
			return true, nil
		}
		// Recursively scan through the unmined inputs one at a time to see
		// if any ancestors contain double-spends. If they do, then this txn is
		// a double-spend by transitivity.
		for _, txIn := range responseData.Inputs {
			inputTxHash, err := chainhash.NewHashFromStr(txIn.PrevTxIDHex)
			if err != nil {
				return false, errors.Wrapf(
					err, "BlockCypherCheckBitcoinDoubleSpend: Error parsing INPUT txn hash: %v", inputTxHash)
			}
			glog.V(1).Infof("CheckBitcoinDoubleSpend: Checking INPUT %v for double-spend", inputTxHash)
			inputIsDoubleSpend, err := BlockCypherCheckBitcoinDoubleSpend(inputTxHash, blockCypherAPIKey, params)
			if err != nil {
				return false, errors.Wrapf(
					err, "BlockCypherCheckBitcoinDoubleSpend: Error fetching INPUT txn: %v", inputTxHash)
			}
			if inputIsDoubleSpend {
				return true, nil
			}
		}
	}
	// If we get here, it means that this txn wasn't a double-spend *and*
	// none of its unmined inputs were double-spends either.

	return false, nil
}
func BlockCypherPushTransaction(txnHex string, txnHash *chainhash.Hash, blockCypherAPIKey string, params *DeSoParams) (
	_added bool, _err error) {

	URL := fmt.Sprintf("http://api.blockcypher.com/v1/btc/main/txs/push")
	if IsBitcoinTestnet(params) {
		URL = fmt.Sprintf("http://api.blockcypher.com/v1/btc/test3/txs/push")
	}
	glog.V(2).Infof("PushTransaction: Querying URL: %s", URL)

	json_data, err := json.Marshal(map[string]string{
		"tx": txnHex,
	})
	if err != nil {
		return false, fmt.Errorf(
			"PushTransaction: Error encoding request as JSON %s: %v", URL, err)
	}

	// jsonValue, err := json.Marshal(postData)
	req, _ := http.NewRequest("POST", URL, bytes.NewBuffer(json_data))
	req.Header.Set("Content-Type", "application/json")

	// To add a ?a=b query string, use the below.
	q := req.URL.Query()
	// TODO: Right now we'll only fetch a maximum of 50 transactions from the API.
	// This means if the user has done more than 50 transactions with their address
	// we'll start missing some of the older utxos. This is easy to fix, though, and
	// just amounts to cycling through the API's pages. Note also that this does not
	// prevent a user from buying DeSo in this case nor does it prevent her from being
	// able to recover her Bitcoin. Both of these can be accomplished by loading the
	// address in a standard Bitcoin wallet like Electrum.
	q.Add("token", blockCypherAPIKey)
	req.URL.RawQuery = q.Encode()
	glog.V(2).Infof("PushTransaction: URL with params: %s", req.URL)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("PushTransaction: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode == 201 {
		glog.V(1).Infof("PushTransaction: Successfully added BitcoinExchange "+
			"txn hash: %v, full txn: %v body: %v", txnHash, txnHex, string(body))
		return true, nil
	}

	// If we get here then we had a bad status code.
	return false, fmt.Errorf("PushTransaction: Failed to submit transaction "+
		"to Bitcoin blockchain: %v, Body: %v, Txn Hash: %v", resp.StatusCode, string(body), txnHash)
}

func CheckBitcoinDoubleSpend(txnHash *chainhash.Hash, blockCypherAPIKey string, params *DeSoParams) error {

	{
		isDoubleSpend, err := BlockCypherCheckBitcoinDoubleSpend(txnHash, blockCypherAPIKey, params)
		if err != nil {
			return fmt.Errorf("PushAndWaitForTxn: Error occurred when checking for "+
				"double-spend on BlockCypher. Your transaction will go through once it "+
				"has been mined into a Bitcoin block. Txn hash: %v", txnHash)
		}
		if isDoubleSpend {
			return fmt.Errorf("PushAndWaitForTxn: Error: double-spend detected "+
				"by BlockCypher. Your transaction will go through once it mines into the "+
				"next Bitcoin block, which should take about ten minutes. Txn hash: %v", txnHash)
		}
	}

	// Also check the Blockchain.com API for a double-spend. This prevents an attack
	// that exploits a weakness in BlockCypher's APIs.
	//
	// TODO: Document this attack later.
	{
		isDoubleSpend, err := BlockchainInfoCheckBitcoinDoubleSpend(txnHash, blockCypherAPIKey, params)
		if err != nil {
			return fmt.Errorf("PushAndWaitForTxn: Error occurred when checking for "+
				"double-spend on blockchain.info. Your transaction will go through once "+
				"it has been mined into a Bitcoin block. Txn hash: %v", txnHash)
		}
		if isDoubleSpend {
			return fmt.Errorf("PushAndWaitForTxn: Error: double-spend detected "+
				"by blockchain.info. Your transaction will go through once it mines "+
				"into the next Bitcoin block. Txn hash: %v", txnHash)
		}
	}

	// If we get here then there was no double-spend detected.
	return nil
}

func BlockCypherPushAndWaitForTxn(txnHex string, txnHash *chainhash.Hash,
	blockCypherAPIKey string, doubleSpendWaitSeconds float64, params *DeSoParams) (_isDoubleSpend bool, _err error) {
	_, err := BlockCypherPushTransaction(txnHex, txnHash, blockCypherAPIKey, params)
	if err != nil {
		return false, fmt.Errorf("PushAndWaitForTxn: %v", err)
	}
	// Wait some amount of time before checking for a double-spend.
	time.Sleep(time.Duration(doubleSpendWaitSeconds) * time.Second)

	if err := CheckBitcoinDoubleSpend(txnHash, blockCypherAPIKey, params); err != nil {
		return true, err
	}

	return false, nil
}

type BlockonomicsRBFResponse struct {
	RBF    int64  `json:"rbf"`
	Status string `json:"status"`
}

func BlockonomicsCheckRBF(bitcoinTxnHash string) (
	_hasRBF bool, _err error) {

	URL := fmt.Sprintf("https://www.blockonomics.co/api/tx_detail?txid=%s", bitcoinTxnHash)
	glog.V(1).Infof("BlockonomicsCheckRBF: Querying URL: %s", URL)

	req, _ := http.NewRequest("GET", URL, nil)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("BlockonomicsCheckRBF: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	// Decode the body.
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		retErr := fmt.Errorf("BlockonomicsCheckRBF: Error when checking "+
			"RBF tatus for txn %v: %v", bitcoinTxnHash, string(body))
		return false, retErr
	}

	responseData := &BlockonomicsRBFResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return false, fmt.Errorf("BlockonomicsCheckRBF: Problem decoding response JSON into "+
			"interface %v, response: %v, body: %v, error: %v", responseData, resp, string(body), err)
	}
	//glog.V(2).Infof("UtxoSource: Received response: %v", responseData)

	if strings.ToLower(responseData.Status) == "unconfirmed" &&
		(responseData.RBF == 1 || responseData.RBF == 2) {

		glog.V(1).Infof("BlockonomicsCheckRBF: Bitcoin txn with hash %v has RBF set", bitcoinTxnHash)
		return true, nil
	}

	return false, nil
}
