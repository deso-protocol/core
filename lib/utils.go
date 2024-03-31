package lib

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"math/big"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/pkg/errors"
	"github.com/unrolled/secure"
	"golang.org/x/crypto/sha3"
)

const SECURE_MIDDLEWARE_RESTRICTIVE_CONTENT_SECURITY_POLICY = "default-src 'self'"

// allowedHost is expected to be of the form "bitclout.com"
// See comments in this function for a description of these params
//
// Note: FeaturePolicy is apparently renamed to PermissionsPolicy. Maybe we should fork
// secure.go and add that. https://scotthelme.co.uk/goodbye-feature-policy-and-hello-permissions-policy/
func InitializeSecureMiddleware(allowedHosts []string, isDevelopment bool, contentSecurityPolicy string) *secure.Secure {
	// For more info about these fields, see:
	//   https://github.com/unrolled/secure
	//   https://blog.rapid7.com/2016/07/13/quick-security-wins-in-golang/
	return secure.New(secure.Options{
		AllowedHosts:          allowedHosts,                                    // AllowedHosts is a list of fully qualified domain names that are allowed. Default is empty list, which allows any and all host names.
		AllowedHostsAreRegex:  true,                                            // AllowedHostsAreRegex determines, if the provided AllowedHosts slice contains valid regular expressions. Default is false.
		HostsProxyHeaders:     []string{"X-Forwarded-Hosts"},                   // HostsProxyHeaders is a set of header keys that may hold a proxied hostname value for the request.
		SSLRedirect:           false,                                           // If SSLRedirect is set to true, then only allow HTTPS requests. Default is false.
		SSLTemporaryRedirect:  false,                                           // If SSLTemporaryRedirect is true, the a 302 will be used while redirecting. Default is false (301).
		SSLHost:               "",                                              // SSLHost is the host name that is used to redirect HTTP requests to HTTPS. Default is "", which indicates to use the same host.
		SSLHostFunc:           nil,                                             // SSLHostFunc is a function pointer, the return value of the function is the host name that has same functionality as `SSHost`. Default is nil. If SSLHostFunc is nil, the `SSLHost` option will be used.
		SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"}, // SSLProxyHeaders is set of header keys with associated values that would indicate a valid HTTPS request. Useful when using Nginx: `map[string]string{"X-Forwarded-Proto": "https"}`. Default is blank map.
		STSSeconds:            31536000,                                        // STSSeconds is the max-age of the Strict-Transport-Security header. Default is 0, which would NOT include the header.
		STSIncludeSubdomains:  true,                                            // If STSIncludeSubdomains is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false.
		STSPreload:            false,                                           // If STSPreload is set to true, the `preload` flag will be appended to the Strict-Transport-Security header. Default is false. [TODO: this seems like a good security feature, but we'd have to submit our domain to Google]
		ForceSTSHeader:        false,                                           // STS header is only included when the connection is HTTPS. If you want to force it to always be added, set to true. `IsDevelopment` still overrides this. Default is false.
		FrameDeny:             true,                                            // If FrameDeny is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false.
		ContentTypeNosniff:    true,                                            // If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false.
		BrowserXssFilter:      true,                                            // If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false.
		ContentSecurityPolicy: contentSecurityPolicy,                           // ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "". Passing a template string will replace `$NONCE` with a dynamic nonce value of 16 bytes for each request which can be later retrieved using the Nonce function.
		ReferrerPolicy:        "same-origin",                                   // ReferrerPolicy allows the Referrer-Policy header with the value to be set with a custom value. Default is "".
		FeaturePolicy:         "",                                              // FeaturePolicy allows the Feature-Policy header with the value to be set with a custom value. Default is "".
		IsDevelopment:         isDevelopment,                                   // This will cause the AllowedHosts, SSLRedirect, and STSSeconds/STSIncludeSubdomains options to be ignored during development. When deploying to production, be sure to set this to false.
	})
}

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func MinUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func ComputeKeysFromSeed(seedBytes []byte, index uint32, params *DeSoParams) (_pubKey *btcec.PublicKey, _privKey *btcec.PrivateKey, _btcAddress string, _err error) {
	isTestnet := params.NetworkType == NetworkType_TESTNET
	return ComputeKeysFromSeedWithNet(seedBytes, index, isTestnet)
}

func ComputeKeysFromSeedWithNet(seedBytes []byte, index uint32, isTestnet bool) (_pubKey *btcec.PublicKey, _privKey *btcec.PrivateKey, _btcAddress string, _err error) {
	// Get the pubkey and privkey from the seed. We use the Bitcoin parameters
	// to generate them.
	// TODO: We should get this from the DeSoParams, not reference them directly.
	netParams := &chaincfg.MainNetParams
	if isTestnet {
		netParams = &chaincfg.TestNet3Params
	}
	masterKey, err := hdkeychain.NewMaster(seedBytes, netParams)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'masterKey' from seed (%v)", err)
	}

	// We follow BIP44 to generate the addresses. Recall it follows the following
	// semantic hierarchy:
	// * purpose' / coin_type' / account' / change / address_index
	// For the derivation path we use: m/44'/0'/0'/0/0. Recall that 0' means we're
	// computing a "hardened" key, which means the private key is present, and
	// that 0 (no apostrophe) means we're computing an "unhardened" key which means
	// the private key is not present.
	//
	// m/44'/0'/0'/0/0 also maps to the first
	// address you'd get if you put the user's seed into most standard
	// Bitcoin wallets (Mycelium, Electrum, Ledger, iancoleman, etc...).
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 44)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'purpose' from seed (%v)", err)
	}
	coinTypeKey, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'coinType' from seed (%v)", err)
	}
	accountKey, err := coinTypeKey.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'accountKey' from seed (%v)", err)
	}
	changeKey, err := accountKey.Derive(0)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'changeKey' from seed (%v)", err)
	}
	addressKey, err := changeKey.Derive(index)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'addressKey' from seed (%v)", err)
	}

	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'pubKey' from seed (%v)", err)
	}
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'privKey' from seed (%v)", err)
	}
	addressObj, err := addressKey.Address(netParams)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'addressObj' from seed (%v)", err)
	}
	btcDepositAddress := addressObj.EncodeAddress()

	return pubKey, privKey, btcDepositAddress, nil
}

func GetNumDigits(val *big.Int) int {
	quotient := big.NewInt(0).Set(val)
	zero := big.NewInt(0)
	ten := big.NewInt(10)
	numDigits := 0
	for quotient.Cmp(zero) != 0 {
		numDigits += 1
		quotient.Div(quotient, ten)
	}
	return numDigits
}

// Given a value v that is a scaled uint256 with the provided scaling factor, this prints the decimal representation
// of v as a string
// Ex: if v = 12345 and scalingFactor = 100, then this outputs 123.45
func FormatScaledUint256AsDecimalString(v *big.Int, scalingFactor *big.Int) string {
	wholeNumber := big.NewInt(0).Div(v, scalingFactor)
	decimalPart := big.NewInt(0).Mod(v, scalingFactor)

	decimalPartIsZero := decimalPart.Cmp(big.NewInt(0)) == 0

	scalingFactorDigits := GetNumDigits(scalingFactor)
	decimalPartAsString := fmt.Sprintf("%d", decimalPart)

	// Left pad the decimal part with zeros
	if !decimalPartIsZero && len(decimalPartAsString) != scalingFactorDigits {
		decimalLeadingZeros := strings.Repeat("0", scalingFactorDigits-len(decimalPartAsString)-1)
		decimalPartAsString = fmt.Sprintf("%v%v", decimalLeadingZeros, decimalPartAsString)
	}

	// Trim trailing zeros
	if !decimalPartIsZero {
		decimalPartAsString = strings.TrimRight(decimalPartAsString, "0")
	}
	return fmt.Sprintf("%d.%v", wholeNumber, decimalPartAsString)
}

// SafeMakeSliceWithLength catches a panic in the make function and returns and
// error if the make function panics. Note that we typically do not allow named return
// value in function signatures. However, in this case, we must use a named return value
// for the error, so we can properly return an error if make panics.
func SafeMakeSliceWithLength[T any](length uint64) (_ []T, outputError error) {
	defer SafeMakeRecover(&outputError)
	return make([]T, length), outputError
}

// SafeMakeSliceWithLengthAndCapacity catches a panic in the make function and returns and
// error if the make function panics. Note that we typically do not allow named return
// value in function signatures. However, in this case, we must use a named return value
// for the error, so we can properly return an error if make panics.
func SafeMakeSliceWithLengthAndCapacity[T any](length uint64, capacity uint64) (_ []T, outputError error) {
	defer SafeMakeRecover(&outputError)
	return make([]T, length, capacity), outputError
}

// SafeMakeMapWithCapacity catches a panic in the make function and returns and
// error if the make function panics. Note that we typically do not allow named return
// value in function signatures. However, in this case, we must use a named return value
// for the error, so we can properly return an error if make panics.
func SafeMakeMapWithCapacity[K comparable, V any](length uint64) (_ map[K]V, outputError error) {
	defer SafeMakeRecover(&outputError)
	return make(map[K]V, length), outputError
}

// SafeMakeRecover recovers from a panic and sets the value of error parameter.
// This function should be called with defer so it ALWAYS runs after the execution of a function.
// This way if a function execution ends with a panic, SafeMakeRecover will "recover" the panic
// and set the error appropriately. We set the value of the pointer to the output error such
// that the calling function will return an error instead of a nil value. Unfortunately,
// there is no way to overwrite the return value of the calling function with a deferred function
// without the usage of named return values.
func SafeMakeRecover(outputError *error) {
	if err := recover(); err != nil {
		*outputError = errors.New(fmt.Sprintf("Error in make: %v", err))
	}
}

func EncodeBlockhashToHexString(blockHash *BlockHash) string {
	if blockHash == nil {
		return ""
	}
	return EncodeHexToStringIfNotNull(blockHash[:])
}

func EncodeHexToStringIfNotNull(hexBytes []byte) string {
	if hexBytes == nil {
		return ""
	}
	return hex.EncodeToString(hexBytes)
}

func MapKeysToNonDeterministicPointerSlice[K comparable, V any](inputMap map[K]V) []*K {
	outputSlice := []*K{}
	for k := range inputMap {
		kCopy := k
		outputSlice = append(outputSlice, &kCopy)
	}
	return outputSlice
}

// IsInterfaceValueNil returns true if the interface is nil or if the interface is a pointer and the pointer is nil.
// This is useful for checking if an interface value's (e.g. DeSoEncoder) underlying struct is nil.
func isInterfaceValueNil(i interface{}) bool {
	if i == nil {
		return true
	}

	value := reflect.ValueOf(i)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

// Encode a map[string]uint64 to bytes. The encoding is deterministic. This is useful for performing encodes for deso encoders.
func EncodeStringUint64MapToBytes(mapToEncode map[string]uint64) []byte {
	var data []byte

	// Encode the number of keys in the map.
	data = append(data, UintToBuf(uint64(len(mapToEncode)))...)
	// Get sorted keys of map. We do this to ensure that the encoding is deterministic.
	var sortedKeys []string
	for key := range mapToEncode {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)
	for _, key := range sortedKeys {
		data = append(data, EncodeByteArray([]byte(key))...)
		data = append(data, UintToBuf(mapToEncode[key])...)
	}
	return data
}

// Decode a map[string]uint64 from bytes. The decoding is deterministic. This is useful for performing decodes for deso decoders.
func DecodeStringUint64MapFromBytes(rr *bytes.Reader) (map[string]uint64, error) {
	// Decode the number of keys in the map.
	numKeys, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeStringUint64MapFromBytes: Problem reading numKeys")
	}
	// Decode the keys and values.
	mapToReturn := make(map[string]uint64)
	for ii := uint64(0); ii < numKeys; ii++ {
		key, err := DecodeByteArray(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeStringUint64MapFromBytes: Problem reading key")
		}
		value, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeStringUint64MapFromBytes: Problem reading value")
		}
		mapToReturn[string(key)] = value
	}
	return mapToReturn, nil
}

// SaveBoolToFile saves a boolean value to a file.
func SaveBoolToFile(filename string, value bool) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	_, err = writer.WriteString(fmt.Sprintf("%v", value))
	if err != nil {
		return err
	}

	return writer.Flush()
}

// ReadBool reads a boolean value from a file.
// Returns an error if the file exists but can't be read properly.
func ReadBoolFromFile(filename string) (bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return false, err // Return an error if there's a problem opening the file
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Scan the contents of the file, if there's anything to read.
	// Interpret the contents as a boolean value.
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text()) == "true", nil
	}

	if err := scanner.Err(); err != nil {
		return false, err // Return an error if there's a problem reading the file
	}

	return false, nil // Return false if there's no content to read
}

// hashUint64ToUint64 hashes a uint64 to a uint64 using SHA3-256. It's a useful pseudorandom
// function that can be used to deterministically map a uint64 to another uint64.
func hashUint64ToUint64(value uint64) uint64 {
	// Convert the input value to binary using big-endian encoding.
	binaryValue := EncodeUint64(value)

	// Hash the binary value using SHA3-256.
	hash := sha3.Sum256(binaryValue)

	// Convert the lowest eight bytes of the hash to a uint64.
	return DecodeUint64(hash[:])
}
