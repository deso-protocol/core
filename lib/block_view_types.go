package lib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type UtxoType uint8

const (
	// UTXOs can come from different sources. We document all of those sources
	// in the UTXOEntry using these types.
	UtxoTypeOutput      UtxoType = 0
	UtxoTypeBlockReward UtxoType = 1
	UtxoTypeBitcoinBurn UtxoType = 2
	// TODO(DELETEME): Remove the StakeReward txn type
	UtxoTypeStakeReward              UtxoType = 3
	UtxoTypeCreatorCoinSale          UtxoType = 4
	UtxoTypeCreatorCoinFounderReward UtxoType = 5
	UtxoTypeNFTSeller                UtxoType = 6
	UtxoTypeNFTBidderChange          UtxoType = 7
	UtxoTypeNFTCreatorRoyalty        UtxoType = 8
	UtxoTypeNFTAdditionalDESORoyalty UtxoType = 9
	UtxoTypeDAOCoinLimitOrderPayout  UtxoType = 10

	// NEXT_TAG = 11
)

func (mm UtxoType) String() string {
	switch mm {
	case UtxoTypeOutput:
		return "UtxoTypeOutput"
	case UtxoTypeBlockReward:
		return "UtxoTypeBlockReward"
	case UtxoTypeBitcoinBurn:
		return "UtxoTypeBitcoinBurn"
	case UtxoTypeStakeReward:
		return "UtxoTypeStakeReward"
	case UtxoTypeCreatorCoinSale:
		return "UtxoTypeCreatorCoinSale"
	case UtxoTypeCreatorCoinFounderReward:
		return "UtxoTypeCreatorCoinFounderReward"
	case UtxoTypeNFTSeller:
		return "UtxoTypeNFTSeller"
	case UtxoTypeNFTBidderChange:
		return "UtxoTypeNFTBidderChange"
	case UtxoTypeNFTCreatorRoyalty:
		return "UtxoTypeNFTCreatorRoyalty"
	case UtxoTypeNFTAdditionalDESORoyalty:
		return "UtxoTypeNFTAdditionalDESORoyalty"
	default:
		return "UtxoTypeUnknown"
	}
}

type EncoderType uint32

// Block view encoder types. These types to different structs implementing the DeSoEncoder interface.
const (
	EncoderTypeUtxoEntry                         EncoderType = 0
	EncoderTypeUtxoOperation                     EncoderType = 1
	EncoderTypeUtxoOperationBundle               EncoderType = 2
	EncoderTypeMessageEntry                      EncoderType = 3
	EncoderTypeGroupKeyName                      EncoderType = 4
	EncoderTypeMessagingGroupEntry               EncoderType = 5
	EncoderTypeMessagingGroupMember              EncoderType = 6
	EncoderTypeForbiddenPubKeyEntry              EncoderType = 7
	EncoderTypeLikeEntry                         EncoderType = 8
	EncoderTypeNFTEntry                          EncoderType = 9
	EncoderTypeNFTBidEntry                       EncoderType = 10
	EncoderTypeNFTBidEntryBundle                 EncoderType = 11
	EncoderTypeDerivedKeyEntry                   EncoderType = 12
	EncoderTypeDiamondEntry                      EncoderType = 13
	EncoderTypeRepostEntry                       EncoderType = 14
	EncoderTypeGlobalParamsEntry                 EncoderType = 15
	EncoderTypePostEntry                         EncoderType = 16
	EncoderTypeBalanceEntry                      EncoderType = 17
	EncoderTypeCoinEntry                         EncoderType = 18
	EncoderTypePublicKeyRoyaltyPair              EncoderType = 19
	EncoderTypePKIDEntry                         EncoderType = 20
	EncoderTypeProfileEntry                      EncoderType = 21
	EncoderTypeAffectedPublicKey                 EncoderType = 22
	EncoderTypeUtxoKey                           EncoderType = 23
	EncoderTypeDeSoOutput                        EncoderType = 24
	EncoderTypePKID                              EncoderType = 25
	EncoderTypePublicKey                         EncoderType = 26
	EncoderTypeBlockHash                         EncoderType = 27
	EncoderTypeDAOCoinLimitOrderEntry            EncoderType = 28
	EncoderTypeFilledDAOCoinLimitOrder           EncoderType = 29
	EncoderTypeUserAssociationEntry              EncoderType = 30
	EncoderTypePostAssociationEntry              EncoderType = 31
	EncoderTypeAccessGroupEntry                  EncoderType = 32
	EncoderTypeAccessGroupMemberEntry            EncoderType = 33
	EncoderTypeGroupMembershipKey                EncoderType = 34
	EncoderTypeNewMessageEntry                   EncoderType = 35
	EncoderTypeAccessGroupMemberEnumerationEntry EncoderType = 36
	EncoderTypeDmThreadEntry                     EncoderType = 37
	EncoderTypeDeSoNonce                         EncoderType = 38
	EncoderTypeTransactorNonceEntry              EncoderType = 39

	// EncoderTypeStateChangeEntry represents a state change to a DeSo encoder entry.
	EncoderTypeStateChangeEntry EncoderType = 40
	// EncoderTypeFollowEntry represents a follow relationship between two pkids.
	EncoderTypeFollowEntry EncoderType = 41
	// EncoderTypeDeSoBalanceEntry represents a balance of DeSo for a particular public key.
	EncoderTypeDeSoBalanceEntry EncoderType = 42
	// EncoderTypeBlock represents a block in the blockchain, including all transactions in said block.
	EncoderTypeBlock EncoderType = 43
	// EncoderTypeTxn represents a transaction in the blockchain.
	EncoderTypeTxn EncoderType = 44

	EncoderTypeValidatorEntry        EncoderType = 45
	EncoderTypeStakeEntry            EncoderType = 46
	EncoderTypeLockedStakeEntry      EncoderType = 47
	EncoderTypeEpochEntry            EncoderType = 48
	EncoderTypeLockedBalanceEntry    EncoderType = 49
	EncoderTypeLockupYieldCurvePoint EncoderType = 50

	// EncoderTypeBLSPublicKeyPKIDPairEntry represents a BLS public key <> PKID mapping.
	EncoderTypeBLSPublicKeyPKIDPairEntry EncoderType = 51

	// EncoderTypeEndBlockView encoder type should be at the end and is used for automated tests.
	EncoderTypeEndBlockView EncoderType = 52
)

// Txindex encoder types.
const (
	EncoderTypeTransactionMetadata                   EncoderType = 1000000
	EncoderTypeBasicTransferTxindexMetadata          EncoderType = 1000001
	EncoderTypeBitcoinExchangeTxindexMetadata        EncoderType = 1000002
	EncoderTypeCreatorCoinTxindexMetadata            EncoderType = 1000003
	EncoderTypeCreatorCoinTransferTxindexMetadata    EncoderType = 1000004
	EncoderTypeDAOCoinTransferTxindexMetadata        EncoderType = 1000005
	EncoderTypeFilledDAOCoinLimitOrderMetadata       EncoderType = 1000006
	EncoderTypeDAOCoinLimitOrderTxindexMetadata      EncoderType = 1000007
	EncoderTypeUpdateProfileTxindexMetadata          EncoderType = 1000008
	EncoderTypeSubmitPostTxindexMetadata             EncoderType = 1000009
	EncoderTypeLikeTxindexMetadata                   EncoderType = 1000010
	EncoderTypeFollowTxindexMetadata                 EncoderType = 1000011
	EncoderTypePrivateMessageTxindexMetadata         EncoderType = 1000012
	EncoderTypeSwapIdentityTxindexMetadata           EncoderType = 1000013
	EncoderTypeNFTRoyaltiesMetadata                  EncoderType = 1000014
	EncoderTypeNFTBidTxindexMetadata                 EncoderType = 1000015
	EncoderTypeAcceptNFTBidTxindexMetadata           EncoderType = 1000016
	EncoderTypeNFTTransferTxindexMetadata            EncoderType = 1000017
	EncoderTypeAcceptNFTTransferTxindexMetadata      EncoderType = 1000018
	EncoderTypeBurnNFTTxindexMetadata                EncoderType = 1000019
	EncoderTypeDAOCoinTxindexMetadata                EncoderType = 1000020
	EncoderTypeCreateNFTTxindexMetadata              EncoderType = 1000021
	EncoderTypeUpdateNFTTxindexMetadata              EncoderType = 1000022
	EncoderTypeCreateUserAssociationTxindexMetadata  EncoderType = 1000023
	EncoderTypeDeleteUserAssociationTxindexMetadata  EncoderType = 1000024
	EncoderTypeCreatePostAssociationTxindexMetadata  EncoderType = 1000025
	EncoderTypeDeletePostAssociationTxindexMetadata  EncoderType = 1000026
	EncoderTypeAccessGroupTxindexMetadata            EncoderType = 1000027
	EncoderTypeAccessGroupMembersTxindexMetadata     EncoderType = 1000028
	EncoderTypeNewMessageTxindexMetadata             EncoderType = 1000029
	EncoderTypeRegisterAsValidatorTxindexMetadata    EncoderType = 1000030
	EncoderTypeUnregisterAsValidatorTxindexMetadata  EncoderType = 1000031
	EncoderTypeStakeTxindexMetadata                  EncoderType = 1000032
	EncoderTypeUnstakeTxindexMetadata                EncoderType = 1000033
	EncoderTypeUnlockStakeTxindexMetadata            EncoderType = 1000034
	EncoderTypeUnjailValidatorTxindexMetadata        EncoderType = 1000035
	EncoderTypeCoinLockupTxindexMetadata             EncoderType = 1000036
	EncoderTypeUpdateCoinLockupParamsTxindexMetadata EncoderType = 1000037
	EncoderTypeCoinLockupTransferTxindexMetadata     EncoderType = 1000038
	EncoderTypeCoinUnlockTxindexMetadata             EncoderType = 1000039

	// EncoderTypeEndTxIndex encoder type should be at the end and is used for automated tests.
	EncoderTypeEndTxIndex EncoderType = 1000036
)

// This function translates the EncoderType into an empty DeSoEncoder struct.
func (encoderType EncoderType) New() DeSoEncoder {
	// Block view encoder types
	switch encoderType {
	case EncoderTypeUtxoEntry:
		return &UtxoEntry{}
	case EncoderTypeUtxoOperation:
		return &UtxoOperation{}
	case EncoderTypeUtxoOperationBundle:
		return &UtxoOperationBundle{}
	case EncoderTypeMessageEntry:
		return &MessageEntry{}
	case EncoderTypeGroupKeyName:
		return &GroupKeyName{}
	case EncoderTypeMessagingGroupEntry:
		return &MessagingGroupEntry{}
	case EncoderTypeMessagingGroupMember:
		return &MessagingGroupMember{}
	case EncoderTypeForbiddenPubKeyEntry:
		return &ForbiddenPubKeyEntry{}
	case EncoderTypeLikeEntry:
		return &LikeEntry{}
	case EncoderTypeNFTEntry:
		return &NFTEntry{}
	case EncoderTypeNFTBidEntry:
		return &NFTBidEntry{}
	case EncoderTypeNFTBidEntryBundle:
		return &NFTBidEntryBundle{}
	case EncoderTypeDerivedKeyEntry:
		return &DerivedKeyEntry{}
	case EncoderTypeDiamondEntry:
		return &DiamondEntry{}
	case EncoderTypeRepostEntry:
		return &RepostEntry{}
	case EncoderTypeGlobalParamsEntry:
		return &GlobalParamsEntry{}
	case EncoderTypePostEntry:
		return &PostEntry{}
	case EncoderTypeBalanceEntry:
		return &BalanceEntry{}
	case EncoderTypeCoinEntry:
		return &CoinEntry{}
	case EncoderTypePublicKeyRoyaltyPair:
		return &PublicKeyRoyaltyPair{}
	case EncoderTypePKIDEntry:
		return &PKIDEntry{}
	case EncoderTypeProfileEntry:
		return &ProfileEntry{}
	case EncoderTypeAffectedPublicKey:
		return &AffectedPublicKey{}
	case EncoderTypeUtxoKey:
		return &UtxoKey{}
	case EncoderTypeDeSoOutput:
		return &DeSoOutput{}
	case EncoderTypePKID:
		return &PKID{}
	case EncoderTypePublicKey:
		return &PublicKey{}
	case EncoderTypeBlockHash:
		return &BlockHash{}
	case EncoderTypeDAOCoinLimitOrderEntry:
		return &DAOCoinLimitOrderEntry{}
	case EncoderTypeFilledDAOCoinLimitOrder:
		return &FilledDAOCoinLimitOrder{}
	case EncoderTypeUserAssociationEntry:
		return &UserAssociationEntry{}
	case EncoderTypePostAssociationEntry:
		return &PostAssociationEntry{}
	case EncoderTypeAccessGroupEntry:
		return &AccessGroupEntry{}
	case EncoderTypeAccessGroupMemberEntry:
		return &AccessGroupMemberEntry{}
	case EncoderTypeGroupMembershipKey:
		return &AccessGroupMembershipKey{}
	case EncoderTypeNewMessageEntry:
		return &NewMessageEntry{}
	case EncoderTypeAccessGroupMemberEnumerationEntry:
		return &AccessGroupMemberEnumerationEntry{}
	case EncoderTypeDmThreadEntry:
		return &DmThreadEntry{}
	case EncoderTypeDeSoNonce:
		return &DeSoNonce{}
	case EncoderTypeTransactorNonceEntry:
		return &TransactorNonceEntry{}
	case EncoderTypeFollowEntry:
		return &FollowEntry{}
	case EncoderTypeStateChangeEntry:
		return &StateChangeEntry{}
	case EncoderTypeDeSoBalanceEntry:
		return &DeSoBalanceEntry{}
	case EncoderTypeBlock:
		return &MsgDeSoBlock{}
	case EncoderTypeTxn:
		return &MsgDeSoTxn{}
	case EncoderTypeValidatorEntry:
		return &ValidatorEntry{}
	case EncoderTypeStakeEntry:
		return &StakeEntry{}
	case EncoderTypeLockedStakeEntry:
		return &LockedStakeEntry{}
	case EncoderTypeEpochEntry:
		return &EpochEntry{}
	case EncoderTypeLockedBalanceEntry:
		return &LockedBalanceEntry{}
	case EncoderTypeLockupYieldCurvePoint:
		return &LockupYieldCurvePoint{}
	case EncoderTypeBLSPublicKeyPKIDPairEntry:
		return &BLSPublicKeyPKIDPairEntry{}
	}

	// Txindex encoder types
	switch encoderType {
	case EncoderTypeTransactionMetadata:
		return &TransactionMetadata{}
	case EncoderTypeBasicTransferTxindexMetadata:
		return &BasicTransferTxindexMetadata{}
	case EncoderTypeBitcoinExchangeTxindexMetadata:
		return &BitcoinExchangeTxindexMetadata{}
	case EncoderTypeCreatorCoinTxindexMetadata:
		return &CreatorCoinTxindexMetadata{}
	case EncoderTypeCreatorCoinTransferTxindexMetadata:
		return &CreatorCoinTransferTxindexMetadata{}
	case EncoderTypeDAOCoinTransferTxindexMetadata:
		return &DAOCoinTransferTxindexMetadata{}
	case EncoderTypeFilledDAOCoinLimitOrderMetadata:
		return &FilledDAOCoinLimitOrderMetadata{}
	case EncoderTypeDAOCoinLimitOrderTxindexMetadata:
		return &DAOCoinLimitOrderTxindexMetadata{}
	case EncoderTypeUpdateProfileTxindexMetadata:
		return &UpdateProfileTxindexMetadata{}
	case EncoderTypeSubmitPostTxindexMetadata:
		return &SubmitPostTxindexMetadata{}
	case EncoderTypeLikeTxindexMetadata:
		return &LikeTxindexMetadata{}
	case EncoderTypeFollowTxindexMetadata:
		return &FollowTxindexMetadata{}
	case EncoderTypePrivateMessageTxindexMetadata:
		return &PrivateMessageTxindexMetadata{}
	case EncoderTypeSwapIdentityTxindexMetadata:
		return &SwapIdentityTxindexMetadata{}
	case EncoderTypeNFTRoyaltiesMetadata:
		return &NFTRoyaltiesMetadata{}
	case EncoderTypeNFTBidTxindexMetadata:
		return &NFTBidTxindexMetadata{}
	case EncoderTypeAcceptNFTBidTxindexMetadata:
		return &AcceptNFTBidTxindexMetadata{}
	case EncoderTypeNFTTransferTxindexMetadata:
		return &NFTTransferTxindexMetadata{}
	case EncoderTypeAcceptNFTTransferTxindexMetadata:
		return &AcceptNFTTransferTxindexMetadata{}
	case EncoderTypeBurnNFTTxindexMetadata:
		return &BurnNFTTxindexMetadata{}
	case EncoderTypeDAOCoinTxindexMetadata:
		return &DAOCoinTxindexMetadata{}
	case EncoderTypeCreateNFTTxindexMetadata:
		return &CreateNFTTxindexMetadata{}
	case EncoderTypeUpdateNFTTxindexMetadata:
		return &UpdateNFTTxindexMetadata{}
	case EncoderTypeCreateUserAssociationTxindexMetadata:
		return &CreateUserAssociationTxindexMetadata{}
	case EncoderTypeDeleteUserAssociationTxindexMetadata:
		return &DeleteUserAssociationTxindexMetadata{}
	case EncoderTypeCreatePostAssociationTxindexMetadata:
		return &CreatePostAssociationTxindexMetadata{}
	case EncoderTypeDeletePostAssociationTxindexMetadata:
		return &DeletePostAssociationTxindexMetadata{}
	case EncoderTypeAccessGroupTxindexMetadata:
		return &AccessGroupTxindexMetadata{}
	case EncoderTypeAccessGroupMembersTxindexMetadata:
		return &AccessGroupMembersTxindexMetadata{}
	case EncoderTypeNewMessageTxindexMetadata:
		return &NewMessageTxindexMetadata{}
	case EncoderTypeRegisterAsValidatorTxindexMetadata:
		return &RegisterAsValidatorTxindexMetadata{}
	case EncoderTypeUnregisterAsValidatorTxindexMetadata:
		return &UnregisterAsValidatorTxindexMetadata{}
	case EncoderTypeStakeTxindexMetadata:
		return &StakeTxindexMetadata{}
	case EncoderTypeUnstakeTxindexMetadata:
		return &UnstakeTxindexMetadata{}
	case EncoderTypeUnlockStakeTxindexMetadata:
		return &UnlockStakeTxindexMetadata{}
	case EncoderTypeUnjailValidatorTxindexMetadata:
		return &UnjailValidatorTxindexMetadata{}
	case EncoderTypeCoinLockupTxindexMetadata:
		return &CoinLockupTxindexMetadata{}
	case EncoderTypeUpdateCoinLockupParamsTxindexMetadata:
		return &UpdateCoinLockupParamsTxindexMetadata{}
	case EncoderTypeCoinLockupTransferTxindexMetadata:
		return &CoinLockupTransferTxindexMetadata{}
	case EncoderTypeCoinUnlockTxindexMetadata:
		return &CoinUnlockTxindexMetadata{}
	default:
		return nil
	}
}

// DeSoEncoder is an interface handling our custom, deterministic byte encodings.
type DeSoEncoder interface {
	// RawEncodeWithoutMetadata and RawDecodeWithoutMetadata methods should encode/decode a DeSoEncoder struct into a
	// byte array. The encoding must always be deterministic, and readable by the corresponding RawDecodeWithoutMetadata.
	// We decided to call these methods with terms like: "RawEncode" and "WithoutMetadata" so that these functions sound
	// scary enough to not be directly called. They shouldn't be! EncodeToBytes and DecodeFromBytes wrappers should be
	// used instead. In particular, the implementation shouldn't worry about the DeSoEncoder being nil, nor about encoding
	// the blockHeight. All of this is handled by the wrappers. The blockHeights are passed to the encoder methods to support
	// encoder migrations, which allow upgrading existing badgerDB entries without requiring a resync. Lookup EncoderMigrationHeights
	// for more information on how this works. skipMetadata shouldn't be used directly by the methods; however, it must
	// always be passed if we're nesting EncodeToBytes in the method implementation.
	RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte
	RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error

	// GetVersionByte should return the version of the DeSoEncoder as a function of EncoderMigrationHeights and blockHeight.
	// For instance, if we added a new migration at height H and version byte V, we should implement the GetVersionByte
	// method so that V is returned whenever blockHeight >= H.
	GetVersionByte(blockHeight uint64) byte

	// GetEncoderType should return the EncoderType corresponding to the DeSoEncoder.
	GetEncoderType() EncoderType
}

type EncodeToBytesFunc func(blockHeight uint64, encoder DeSoEncoder, skipMetadata ...bool) []byte

var EncodeToBytesImpl EncodeToBytesFunc = encodeToBytes

// EncodeToBytes encodes a DeSoEncoder type to bytes, including encoder metadata such as existence byte, the encoder
// type, and the current blockHeight. The skipMetadata parameter should be always passed if we're nesting DeSoEncoders,
// but in general it shouldn't be passed. This parameter is only used when we're computing the state checksum.
func EncodeToBytes(blockHeight uint64, encoder DeSoEncoder, skipMetadata ...bool) []byte {
	return EncodeToBytesImpl(blockHeight, encoder, skipMetadata...)
}

func encodeToBytes(blockHeight uint64, encoder DeSoEncoder, skipMetadata ...bool) []byte {
	var data []byte

	// Encoding without metadata is used in the checksum computation. We do this because metadata is kind of arbitrary.
	shouldSkipMetadata := false
	if len(skipMetadata) > 0 {
		shouldSkipMetadata = skipMetadata[0]
	}

	// We will encode the DeSoEncoder type with some additional metadata. This metadata consists of:
	// 	<existenceByte [1]byte> <encoderType [4]byte> <encoderVersion [1]byte> <encodedBytes []byte>
	//
	// existenceByte  - is a boolean that tells us if the encoder entry was initialized (true) or if it was nil (false)
	// encoderType    - is a uint32 that encodes information of DeSoEncoder's type.
	// encoderVersion - is a byte that says which migration was used by the encoder. Migrations increment encoder's version.
	// encodedBytes   - encoder's bytes

	if encoder != nil && !reflect.ValueOf(encoder).IsNil() {
		data = append(data, BoolToByte(true))
		// Encode metadata
		if !shouldSkipMetadata {
			data = append(data, UintToBuf(uint64(encoder.GetEncoderType()))...)
			data = append(data, UintToBuf(uint64(encoder.GetVersionByte(blockHeight)))...)
		}
		data = append(data, encoder.RawEncodeWithoutMetadata(blockHeight, skipMetadata...)...)
	} else {
		data = append(data, BoolToByte(false))
	}

	return data
}

type DecodeFromByteFunc func(encoder DeSoEncoder, rr *bytes.Reader) (_existenceByte bool, _error error)

var DecodeFromBytesImpl = decodeFromBytes

// DecodeFromBytes decodes a DeSoEncoder type from bytes. We check
// for the existence byte, which tells us whether actual data was encoded, or a nil pointer.
func DecodeFromBytes(encoder DeSoEncoder, rr *bytes.Reader) (_existenceByte bool, _error error) {
	return DecodeFromBytesImpl(encoder, rr)
}

func decodeFromBytes(encoder DeSoEncoder, rr *bytes.Reader) (_existenceByte bool, _error error) {
	if existenceByte, err := ReadBoolByte(rr); existenceByte && err == nil {

		encoderType, err := ReadUvarint(rr)
		if err != nil {
			return false, errors.Wrapf(err, "DecodeFromBytes: Problem decoding encoder type")
		}
		if encoderType > math.MaxUint32 {
			return false, errors.Wrapf(err, "DecodeFromBytes: Encoder type "+
				"value exceeds max uint32: %v", encoderType)
		}

		// Because encoder is provided as a parameter, we just verify that the entry type matches the encoder type.
		if !reflect.DeepEqual(EncoderType(encoderType), encoder.GetEncoderType()) {
			return false, fmt.Errorf("DecodeFromBytes: encoder type (%v) doesn't match the "+
				"entry type (%v)", encoderType, encoder.GetEncoderType())
		}

		versionByte, err := ReadUvarint(rr)
		if err != nil {
			return false, errors.Wrapf(err, "DecodeFromBytes: Problem decoding version bytes")
		}
		if versionByte > math.MaxUint8 {
			return false, errors.Wrapf(err, "DecodeFromBytes: versionByte "+
				"value exceeds max uint8: %v", versionByte)
		}
		// TODO: We should pass DeSoParams to this function instead of using GlobalParams.
		// We don't do this for now because it's a massive refactor.
		blockHeight := VersionByteToMigrationHeight(uint8(versionByte), &GlobalDeSoParams)

		err = encoder.RawDecodeWithoutMetadata(blockHeight, rr)
		if err != nil {
			return false, errors.Wrapf(err, "DecodeFromBytes: Problem reading encoder")
		}
		return true, nil
	} else if err != nil {
		return false, errors.Wrapf(err, "DecodeFromBytes: Problem reading existence byte")
	}
	return false, nil
}

// MigrationTriggered is a suggested conditional check to be called within RawEncodeWithoutMetadata and
// RawDecodeWithoutMetadata when defining the encoding migrations for DeSoEncoders. Consult constants.go for more info.
func MigrationTriggered(blockHeight uint64, migrationName MigrationName) bool {
	for _, migration := range GlobalDeSoParams.EncoderMigrationHeightsList {
		if migration.Name == migrationName {
			return blockHeight >= migration.Height
		}
	}

	panic(any(fmt.Sprintf("Problem finding a migration corresponding to migrationName (%v) "+
		"check your code!", migrationName)))
}

// GetMigrationVersion can be returned in GetVersionByte when implementing DeSoEncoders. The way to do it is simply
// calling `return GetMigrationVersion(blockHeight, [Migration Names])` where migration names are all EncoderMigrationHeights
// that were used in RawEncodeWithoutMetadata and RawDecodeWithoutMetadata. [Migration Names] can be simply a list of
// MigrationName strings corresponding to these EncodeMigrationHeights.
func GetMigrationVersion(blockHeight uint64, appliedMigrationNames ...MigrationName) byte {
	maxMigrationVersion := byte(0)
	for _, migration := range GlobalDeSoParams.EncoderMigrationHeightsList {
		for _, appliedMigration := range appliedMigrationNames {
			// Select the applied migrations.
			if migration.Name == appliedMigration {

				// Make sure the migration is satisfied by the current blockHeight.
				if migration.Height <= blockHeight {

					// Find the migration with the greatest version.
					if migration.Version > maxMigrationVersion {
						maxMigrationVersion = migration.Version
					}
				}
			}
		}
	}
	return maxMigrationVersion
}

// UtxoEntry identifies the data associated with a UTXO.
type UtxoEntry struct {
	AmountNanos uint64
	PublicKey   []byte
	BlockHeight uint32
	UtxoType    UtxoType

	// The fields below aren't serialized or hashed. They are only kept
	// around for in-memory bookkeeping purposes.

	// Whether or not the UTXO is spent. This is not used by the database,
	// (in fact it's not even stored in the db) it's used
	// only by the in-memory data structure. The database is simple: A UTXO
	// is unspent if and only if it exists in the db. However, for the view,
	// a UTXO is unspent if it (exists in memory and is unspent) OR (it does not
	// exist in memory at all but does exist in the database).
	//
	// Note that we are relying on the code that serializes the entry to the
	// db to ignore private fields, which is why this variable is lowerCamelCase
	// rather than UpperCamelCase. We are also relying on it defaulting to
	// false when newly-read from the database.
	isSpent bool

	// A back-reference to the utxo key associated with this entry.
	UtxoKey *UtxoKey
}

func (utxoEntry *UtxoEntry) String() string {
	return fmt.Sprintf("< OwnerPublicKey: %v, BlockHeight: %d, AmountNanos: %d, UtxoType: %v, "+
		"isSpent: %v, utxoKey: %v>", PkToStringMainnet(utxoEntry.PublicKey),
		utxoEntry.BlockHeight, utxoEntry.AmountNanos,
		utxoEntry.UtxoType, utxoEntry.isSpent, utxoEntry.UtxoKey)
}

func (utxo *UtxoEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, UintToBuf(utxo.AmountNanos)...)
	data = append(data, EncodeByteArray(utxo.PublicKey)...)
	data = append(data, UintToBuf(uint64(utxo.BlockHeight))...)
	data = append(data, byte(utxo.UtxoType))
	data = append(data, EncodeToBytes(blockHeight, utxo.UtxoKey, skipMetadata...)...)

	return data
}

func (utxo *UtxoEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	utxo.AmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoEntry.Decode: Problem reading AmountNanos")
	}
	utxo.PublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoEntry.Decode: Problem reading PublicKey")
	}

	utxoBlockHeight, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoEntry.Decode: Problem reading blockHeight")
	}
	utxo.BlockHeight = uint32(utxoBlockHeight)

	utxoType, err := rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "UtxoEntry.Decode: Problem reading UtxoType")
	}
	utxo.UtxoType = UtxoType(utxoType)

	utxoKey := &UtxoKey{}
	if exist, err := DecodeFromBytes(utxoKey, rr); exist && err == nil {
		utxo.UtxoKey = utxoKey
	} else if err != nil {
		return errors.Wrapf(err, "UtxoEntry.Decode: Problem reading UtxoKey")
	}

	return nil
}

func (utxo *UtxoEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (utxo *UtxoEntry) GetEncoderType() EncoderType {
	return EncoderTypeUtxoEntry
}

type OperationType uint

const (
	// Every operation has a type that we document here. This information is
	// used when rolling back a txn to determine what kind of operations need
	// to be performed. For example, rolling back a BitcoinExchange may require
	// rolling back an AddUtxo operation.
	OperationTypeAddUtxo                       OperationType = 0
	OperationTypeSpendUtxo                     OperationType = 1
	OperationTypeBitcoinExchange               OperationType = 2
	OperationTypePrivateMessage                OperationType = 3
	OperationTypeSubmitPost                    OperationType = 4
	OperationTypeUpdateProfile                 OperationType = 5
	OperationTypeDeletePost                    OperationType = 7
	OperationTypeUpdateBitcoinUSDExchangeRate  OperationType = 8
	OperationTypeFollow                        OperationType = 9
	OperationTypeLike                          OperationType = 10
	OperationTypeCreatorCoin                   OperationType = 11
	OperationTypeSwapIdentity                  OperationType = 12
	OperationTypeUpdateGlobalParams            OperationType = 13
	OperationTypeCreatorCoinTransfer           OperationType = 14
	OperationTypeCreateNFT                     OperationType = 15
	OperationTypeUpdateNFT                     OperationType = 16
	OperationTypeAcceptNFTBid                  OperationType = 17
	OperationTypeNFTBid                        OperationType = 18
	OperationTypeDeSoDiamond                   OperationType = 19
	OperationTypeNFTTransfer                   OperationType = 20
	OperationTypeAcceptNFTTransfer             OperationType = 21
	OperationTypeBurnNFT                       OperationType = 22
	OperationTypeAuthorizeDerivedKey           OperationType = 23
	OperationTypeMessagingKey                  OperationType = 24
	OperationTypeDAOCoin                       OperationType = 25
	OperationTypeDAOCoinTransfer               OperationType = 26
	OperationTypeSpendingLimitAccounting       OperationType = 27
	OperationTypeDAOCoinLimitOrder             OperationType = 28
	OperationTypeCreateUserAssociation         OperationType = 29
	OperationTypeDeleteUserAssociation         OperationType = 30
	OperationTypeCreatePostAssociation         OperationType = 31
	OperationTypeDeletePostAssociation         OperationType = 32
	OperationTypeAccessGroup                   OperationType = 33
	OperationTypeAccessGroupMembers            OperationType = 34
	OperationTypeNewMessage                    OperationType = 35
	OperationTypeAddBalance                    OperationType = 36
	OperationTypeSpendBalance                  OperationType = 37
	OperationTypeDeleteExpiredNonces           OperationType = 38
	OperationTypeRegisterAsValidator           OperationType = 39
	OperationTypeUnregisterAsValidator         OperationType = 40
	OperationTypeStake                         OperationType = 41
	OperationTypeUnstake                       OperationType = 42
	OperationTypeUnlockStake                   OperationType = 43
	OperationTypeUnjailValidator               OperationType = 44
	OperationTypeCoinLockup                    OperationType = 45
	OperationTypeCoinLockupTransfer            OperationType = 46
	OperationTypeCoinUnlock                    OperationType = 47
	OperationTypeUpdateCoinLockupParams        OperationType = 48
	OperationTypeStakeDistributionRestake      OperationType = 49
	OperationTypeStakeDistributionPayToBalance OperationType = 50
	OperationTypeSetValidatorLastActiveAtEpoch OperationType = 51
	OperationTypeFailingTxn                    OperationType = 52
	// NEXT_TAG = 53
)

func (op OperationType) String() string {
	switch op {
	case OperationTypeAddUtxo:
		return "OperationTypeAddUtxo"
	case OperationTypeSpendUtxo:
		return "OperationTypeSpendUtxo"
	case OperationTypeBitcoinExchange:
		return "OperationTypeBitcoinExchange"
	case OperationTypePrivateMessage:
		return "OperationTypePrivateMessage"
	case OperationTypeSubmitPost:
		return "OperationTypeSubmitPost"
	case OperationTypeUpdateProfile:
		return "OperationTypeUpdateProfile"
	case OperationTypeDeletePost:
		return "OperationTypeDeletePost"
	case OperationTypeUpdateBitcoinUSDExchangeRate:
		return "OperationTypeUpdateBitcoinUSDExchangeRate"
	case OperationTypeFollow:
		return "OperationTypeFollow"
	case OperationTypeLike:
		return "OperationTypeLike"
	case OperationTypeCreatorCoin:
		return "OperationTypeCreatorCoin"
	case OperationTypeSwapIdentity:
		return "OperationTypeSwapIdentity"
	case OperationTypeUpdateGlobalParams:
		return "OperationTypeUpdateGlobalParams"
	case OperationTypeCreatorCoinTransfer:
		return "OperationTypeCreatorCoinTransfer"
	case OperationTypeCreateNFT:
		return "OperationTypeCreateNFT"
	case OperationTypeUpdateNFT:
		return "OperationTypeUpdateNFT"
	case OperationTypeAcceptNFTBid:
		return "OperationTypeAcceptNFTBid"
	case OperationTypeNFTBid:
		return "OperationTypeNFTBid"
	case OperationTypeDeSoDiamond:
		return "OperationTypeDeSoDiamond"
	case OperationTypeNFTTransfer:
		return "OperationTypeNFTTransfer"
	case OperationTypeAcceptNFTTransfer:
		return "OperationTypeAcceptNFTTransfer"
	case OperationTypeBurnNFT:
		return "OperationTypeBurnNFT"
	case OperationTypeAuthorizeDerivedKey:
		return "OperationTypeAuthorizeDerivedKey"
	case OperationTypeMessagingKey:
		return "OperationTypeMessagingKey"
	case OperationTypeDAOCoin:
		return "OperationTypeDAOCoin"
	case OperationTypeDAOCoinTransfer:
		return "OperationTypeDAOCoinTransfer"
	case OperationTypeSpendingLimitAccounting:
		return "OperationTypeSpendingLimitAccounting"
	case OperationTypeDAOCoinLimitOrder:
		return "OperationTypeDAOCoinLimitOrder"
	case OperationTypeCreateUserAssociation:
		return "OperationTypeCreateUserAssociation"
	case OperationTypeDeleteUserAssociation:
		return "OperationTypeDeleteUserAssociation"
	case OperationTypeCreatePostAssociation:
		return "OperationTypeCreatePostAssociation"
	case OperationTypeDeletePostAssociation:
		return "OperationTypeDeletePostAssociation"
	case OperationTypeAccessGroup:
		return "OperationTypeAccessGroup"
	case OperationTypeAccessGroupMembers:
		return "OperationTypeAccessGroupMembers"
	case OperationTypeNewMessage:
		return "OperationTypeNewMessage"
	case OperationTypeAddBalance:
		return "OperationTypeAddBalance"
	case OperationTypeSpendBalance:
		return "OperationTypeSpendBalance"
	case OperationTypeDeleteExpiredNonces:
		return "OperationTypeDeleteExpiredNonces"
	case OperationTypeRegisterAsValidator:
		return "OperationTypeRegisterAsValidator"
	case OperationTypeUnregisterAsValidator:
		return "OperationTypeUnregisterAsValidator"
	case OperationTypeStake:
		return "OperationTypeStake"
	case OperationTypeUnstake:
		return "OperationTypeUnstake"
	case OperationTypeUnlockStake:
		return "OperationTypeUnlockStake"
	case OperationTypeUnjailValidator:
		return "OperationTypeUnjailValidator"
	case OperationTypeCoinLockup:
		return "OperationTypeCoinLockup"
	case OperationTypeUpdateCoinLockupParams:
		return "OperationTypeUpdateCoinLockupParams"
	case OperationTypeCoinLockupTransfer:
		return "OperationTypeCoinLockupTransfer"
	case OperationTypeCoinUnlock:
		return "OperationTypeCoinUnlock"
	case OperationTypeStakeDistributionRestake:
		return "OperationTypeStakeDistributionRestake"
	case OperationTypeSetValidatorLastActiveAtEpoch:
		return "OperationTypeSetValidatorLastActiveAtEpoch"
	case OperationTypeStakeDistributionPayToBalance:
		return "OperationTypeStakeDistributionPayToBalance"
	}
	return "OperationTypeUNKNOWN"
}

type UtxoOperation struct {
	Type OperationType

	// Only set for OperationTypeSpendUtxo
	//
	// When we SPEND a UTXO entry we delete it from the utxo set but we still
	// store its info in case we want to reverse
	// it in the future. This information is not needed for ADD since
	// reversing an ADD just means deleting an entry from the end of our list.
	//
	// SPEND works by swapping the UTXO we want to spend with the UTXO at
	// the end of the list and then deleting from the end of the list. Obviously
	// this is more efficient than deleting the element in-place and then shifting
	// over everything after it. In order to be able to undo this operation,
	// however, we need to store the original index of the item we are
	// spending/deleting. Reversing the operation then amounts to adding a utxo entry
	// at the end of the list and swapping with this index. Given this, the entry
	// we store here has its position set to the position it was at right before the
	// SPEND operation was performed.
	Entry *UtxoEntry

	// Only set for OperationTypeSpendUtxo
	//
	// Store the UtxoKey as well. This isn't necessary but it helps
	// with error-checking during a roll-back so we just keep it.
	//
	// TODO: We can probably delete this at some point and save some space. UTXOs
	// are probably our biggest disk hog so getting rid of this should materially
	// improve disk usage.
	Key *UtxoKey

	// Used to revert BitcoinExchange transaction.
	PrevNanosPurchased uint64
	// Used to revert UpdateBitcoinUSDExchangeRate transaction.
	PrevUSDCentsPerBitcoin uint64

	// Save the previous post entry when making an update to a post.
	PrevPostEntry            *PostEntry
	PrevParentPostEntry      *PostEntry
	PrevGrandparentPostEntry *PostEntry
	PrevRepostedPostEntry    *PostEntry

	// Save the previous profile entry when making an update.
	PrevProfileEntry *ProfileEntry

	// Save the previous like entry and like count when making an update.
	PrevLikeEntry *LikeEntry
	PrevLikeCount uint64

	// For disconnecting diamonds.
	PrevDiamondEntry *DiamondEntry

	// For disconnecting NFTs.
	PrevNFTEntry              *NFTEntry
	PrevNFTBidEntry           *NFTBidEntry
	DeletedNFTBidEntries      []*NFTBidEntry
	NFTPaymentUtxoKeys        []*UtxoKey
	NFTSpentUtxoEntries       []*UtxoEntry
	PrevAcceptedNFTBidEntries *[]*NFTBidEntry

	// For disconnecting AuthorizeDerivedKey transactions.
	PrevDerivedKeyEntry *DerivedKeyEntry

	// For disconnecting MessagingGroupKey transactions.
	PrevMessagingKeyEntry *MessagingGroupEntry

	// Save the previous repost entry and repost count when making an update.
	PrevRepostEntry *RepostEntry
	PrevRepostCount uint64

	// Save the state of a creator coin prior to updating it due to a
	// buy/sell/add transaction.
	PrevCoinEntry *CoinEntry

	// Save the state of coin entries associated with a PKID prior to updating
	// it due to an additional coin royalty when an NFT is sold.
	PrevCoinRoyaltyCoinEntries map[PKID]CoinEntry

	// Save the creator coin balance of both the transactor and the creator.
	// We modify the transactor's balances when they buys/sell a creator coin
	// and we modify the creator's balance when we pay them a founder reward.
	PrevTransactorBalanceEntry *BalanceEntry
	PrevCreatorBalanceEntry    *BalanceEntry
	// We use this to revert founder's reward UTXOs created by creator coin buys.
	FounderRewardUtxoKey *UtxoKey

	// Save balance entries for the sender and receiver when creator coins are transferred.
	PrevSenderBalanceEntry   *BalanceEntry
	PrevReceiverBalanceEntry *BalanceEntry

	// Save the global params when making an update.
	PrevGlobalParamsEntry    *GlobalParamsEntry
	PrevForbiddenPubKeyEntry *ForbiddenPubKeyEntry

	// This value is used by Rosetta to adjust for a bug whereby a ParamUpdater
	// CoinEntry could get clobbered if updating a profile on someone else's
	// behalf. This is super confusing.
	ClobberedProfileBugDESOLockedNanos uint64

	// This value is used by Rosetta to return the amount of DESO that was added
	// or removed from a profile during a CreatorCoin transaction. It's needed
	// in order to avoid having to reconnect all transactions.
	CreatorCoinDESOLockedNanosDiff int64

	// This value is used by Rosetta to create a proper input/output when we
	// encounter a SwapIdentity txn. This makes it so that we don't have to
	// reconnect all txns in order to get these values.
	SwapIdentityFromDESOLockedNanos uint64
	SwapIdentityToDESOLockedNanos   uint64

	// These values are used by Rosetta in order to create input and output
	// operations. They make it so that we don't have to reconnect all txns
	// in order to get these values.
	AcceptNFTBidCreatorPublicKey        []byte
	AcceptNFTBidBidderPublicKey         []byte
	AcceptNFTBidCreatorRoyaltyNanos     uint64
	AcceptNFTBidCreatorDESORoyaltyNanos uint64
	AcceptNFTBidAdditionalCoinRoyalties []*PublicKeyRoyaltyPair
	AcceptNFTBidAdditionalDESORoyalties []*PublicKeyRoyaltyPair

	// These values are used by Rosetta in order to create input and output
	// operations. They make it so that we don't have to reconnect all txns
	// in order to get these values for NFT bid transactions on Buy Now NFTs.
	NFTBidCreatorPublicKey        []byte
	NFTBidBidderPublicKey         []byte
	NFTBidCreatorRoyaltyNanos     uint64
	NFTBidCreatorDESORoyaltyNanos uint64
	NFTBidAdditionalCoinRoyalties []*PublicKeyRoyaltyPair
	NFTBidAdditionalDESORoyalties []*PublicKeyRoyaltyPair

	// DAO coin limit order
	// PrevTransactorDAOCoinLimitOrderEntry is the previous version of the
	// transactor's DAO Coin Limit Order before this transaction was connected.
	// Note: This is only set if the transactor is cancelling an existing order.
	PrevTransactorDAOCoinLimitOrderEntry *DAOCoinLimitOrderEntry

	// PrevBalanceEntries is a map of User PKID, Creator PKID to DAO Coin Balance
	// Entry. When disconnecting a DAO Coin Limit Order, we will revert to these
	// BalanceEntries.
	PrevBalanceEntries map[PKID]map[PKID]*BalanceEntry

	// PrevMatchingOrder is a slice of DAOCoinLimitOrderEntries that were deleted
	// in the DAO Coin Limit Order Transaction. In order to revert the state in
	// the event of a disconnect, we restore all the deleted Order Entries
	PrevMatchingOrders []*DAOCoinLimitOrderEntry

	// FilledDAOCoinLimitOrder is a slice of FilledDAOCoinLimitOrder structs
	// that represent all orders fulfilled by the DAO Coin Limit Order transaction.
	// These are used to construct notifications for order fulfillment.
	FilledDAOCoinLimitOrders []*FilledDAOCoinLimitOrder

	// Save the state of any deleted associations, in case we need
	// to disconnect/revert and re-instate the prev association.
	PrevUserAssociationEntry *UserAssociationEntry
	PrevPostAssociationEntry *PostAssociationEntry

	//
	// Access Group Fork fields
	//

	// PrevAccessGroupEntry is the previous access group entry. It is used in
	// access group transactions to revert the access group after an update operation.
	PrevAccessGroupEntry *AccessGroupEntry

	// PrevAccessGroupMembersList is a list of previous access group member entries.
	// It is used in operations that modify existing access group members, such as
	// AccessGroupMemberOperationTypeRemove or AccessGroupMemberOperationTypeUpdate.
	PrevAccessGroupMembersList []*AccessGroupMemberEntry

	// PrevNewMessageEntry is the previous message entry, used for disconnecting NewMessage transactions.
	PrevNewMessageEntry *NewMessageEntry
	// PrevDmThreadEntry is used for disconnecting DM message threads.
	PrevDmThreadEntry *DmThreadEntry

	// When we add to or spend balance, we keep track of the public key and amount.
	BalancePublicKey   []byte
	BalanceAmountNanos uint64

	// When we connect a block, we delete expired nonce entries.
	PrevNonceEntries []*TransactorNonceEntry

	// Metadata related to the state change that this operation represents.
	StateChangeMetadata DeSoEncoder

	// PrevValidatorEntry is the previous ValidatorEntry prior to a
	// register, unregister, stake, or unstake txn.
	PrevValidatorEntry *ValidatorEntry

	// PrevStakeEntries is a slice of StakeEntries prior to
	// a register, unregister, stake, or unstake txn.
	PrevStakeEntries []*StakeEntry

	// PrevLockedStakeEntries is a slice of LockedStakeEntries
	// prior to a unstake or unlock stake txn.
	PrevLockedStakeEntries []*LockedStakeEntry

	//
	// Coin Lockup fields
	//

	// PrevLockedBalanceEntry is the previous LockedBalanceEntry prior
	// to a DAO coin lockup. PrevCoinEntry defined above stores the
	// CoinsInCirculation and NumberOfHolders prior to a lockup transaction.
	//
	// Vested lockups are a bit more confusing as we delete then set numerous locked balance entries.
	// To revert this we must know what locked balance entries were set as well as what locked
	// balance entries were deleted. We use PrevLockedBalanceEntries below and SetLockedBalanceEntries to convey
	// these two pieces of state change for disconnects.
	PrevLockedBalanceEntry  *LockedBalanceEntry
	SetLockedBalanceEntries []*LockedBalanceEntry

	// PrevLockupYieldCurvePoint and PrevLockupTransferRestriction are
	// the previous yield curve and transfer restrictions associated
	// with an UpdateCoinLockupParams transaction.
	PrevLockupYieldCurvePoint     *LockupYieldCurvePoint
	PrevLockupTransferRestriction TransferRestrictionStatus

	// PrevSenderLockedBalanceEntry and PrevReceiverLockedBalanceEntry are the previous LockedBalanceEntry
	// for both the sender and receiver in the coin lockup transfer operation.
	PrevSenderLockedBalanceEntry   *LockedBalanceEntry
	PrevReceiverLockedBalanceEntry *LockedBalanceEntry

	// PrevLockedBalanceEntries is a slice of LockedBalanceEntry prior to a coin unlock.
	// ModifiedLockedBalanceEntry is required due to the dynamic nature of the LockedBalanceEntryKey
	// in the coin unlock transaction. Essentially we need to know what LockedBalanceEntryKey
	// did not exist prior to the coin unlock to ensure it is properly deleted during a disconnect.
	// There is at most one modified locked balance entry per unlock (a vested locked balance entry
	// that has not fully expired yet).
	PrevLockedBalanceEntries   []*LockedBalanceEntry
	ModifiedLockedBalanceEntry *LockedBalanceEntry

	// StakeAmountNanosDiff is used by Rosetta to return the amount of DESO that was added
	// to a StakeEntry during the end-of-epoch hook. It's needed
	// in order to avoid having to re-run the end of epoch hook.
	StakeAmountNanosDiff uint64

	// LockedAtEpochNumber is used by Rosetta to uniquely identify a subaccount representing
	// a locked stake entry that is created during an Unlock transaction. Without this, we
	// would need to consolidate many LockedStakeEntries into a single subaccount which would
	// make it difficult to track the history of a particular stake entry and generally lead
	// to more complexity in rosetta which is undesirable. Another alternative would be to
	// require Rosetta to be able to compute epoch's based on block height, but this would
	// require a more structural change to rosetta's codebase so that transaction parsing
	// would be aware of the block height. This is also undesirable. Although adding a new
	// field to theUtxoOperation struct is not ideal, the tradeoff is worth it for the
	// simplicity it provides in rosetta. TODO: When refactoring UtxoOperations in the future,
	// consider how we can maintain support for rosetta and situations like this where the
	// transaction metadata itself doesn't specify the information we need to return to
	// rosetta.
	LockedAtEpochNumber uint64
}

// FIXME: This hackIsRunningStateSyncer() call is a hack to get around the fact that
// we don't have a way to not require a resync while introducing the state change
// metadata to the utxo operation struct. We don't want to use a block height to gate
// this because we want to be able to get state change metadata for ALL transactions.
// We should replace this with a more elegant solution, a better hack, or bundle it
// in with a release that requires a resync anyway. We should remove this function
// when we have a better solution in place.
func hackIsRunningStateSyncer() bool {
	return viper.GetString("state-change-dir") != ""
}

func (op *UtxoOperation) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	// Type
	data = append(data, UintToBuf(uint64(op.Type))...)

	// Entry
	data = append(data, EncodeToBytes(blockHeight, op.Entry, skipMetadata...)...)

	// Key
	data = append(data, EncodeToBytes(blockHeight, op.Key, skipMetadata...)...)

	// PrevNanosPurchased
	data = append(data, UintToBuf(op.PrevNanosPurchased)...)

	// PrevUSDCentsPerBitcoin
	data = append(data, UintToBuf(op.PrevUSDCentsPerBitcoin)...)

	// PrevPostEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevPostEntry, skipMetadata...)...)

	// PrevParentPostEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevParentPostEntry, skipMetadata...)...)

	// PrevGrandparentPostEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevGrandparentPostEntry, skipMetadata...)...)

	// PrevRepostedPostEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevRepostedPostEntry, skipMetadata...)...)

	// PrevProfileEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevProfileEntry, skipMetadata...)...)

	// PrevLikeEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevLikeEntry, skipMetadata...)...)

	// PrevLikeCount
	data = append(data, UintToBuf(op.PrevLikeCount)...)

	// PrevDiamondEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevDiamondEntry, skipMetadata...)...)

	// PrevNFTEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevNFTEntry, skipMetadata...)...)

	// PrevNFTBidEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevNFTBidEntry, skipMetadata...)...)

	// DeletedNFTBidEntries
	data = append(data, UintToBuf(uint64(len(op.DeletedNFTBidEntries)))...)
	for _, bidEntry := range op.DeletedNFTBidEntries {
		data = append(data, EncodeToBytes(blockHeight, bidEntry, skipMetadata...)...)
	}

	// NFTPaymentUtxoKeys
	data = append(data, UintToBuf(uint64(len(op.NFTPaymentUtxoKeys)))...)
	for _, utxoKey := range op.NFTPaymentUtxoKeys {
		data = append(data, EncodeToBytes(blockHeight, utxoKey, skipMetadata...)...)
	}

	// NFTSpentUtxoEntries
	data = append(data, UintToBuf(uint64(len(op.NFTSpentUtxoEntries)))...)
	for _, utxoEntry := range op.NFTSpentUtxoEntries {
		data = append(data, EncodeToBytes(blockHeight, utxoEntry, skipMetadata...)...)
	}

	// PrevAcceptedNFTBidEntries
	// Similarly to op.Entry, we encode an existence flag for the PrevAcceptedNFTBidEntries.
	if op.PrevAcceptedNFTBidEntries != nil {
		data = append(data, BoolToByte(true))
		data = append(data, UintToBuf(uint64(len(*op.PrevAcceptedNFTBidEntries)))...)
		for _, bidEntry := range *op.PrevAcceptedNFTBidEntries {
			data = append(data, EncodeToBytes(blockHeight, bidEntry, skipMetadata...)...)
		}
	} else {
		data = append(data, BoolToByte(false))
	}

	// PrevDerivedKeyEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevDerivedKeyEntry, skipMetadata...)...)

	// PrevMessagingKeyEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevMessagingKeyEntry, skipMetadata...)...)

	// PrevRepostEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevRepostEntry, skipMetadata...)...)

	// PrevRepostCount
	data = append(data, UintToBuf(op.PrevRepostCount)...)

	// PrevCoinEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevCoinEntry, skipMetadata...)...)

	// Encode the PrevCoinRoyaltyCoinEntries map. We define a helper struct to store the <PKID, CoinEntry>
	// objects as byte arrays. For coin entry, we first encode the struct, and then encode it as byte array.
	type royaltyEntry struct {
		pkid      []byte
		coinEntry []byte
	}
	encodeRoyaltyEntry := func(entry *royaltyEntry) []byte {
		var data []byte
		data = append(data, EncodeByteArray(entry.pkid)...)
		data = append(data, EncodeByteArray(entry.coinEntry)...)
		return data
	}
	var royaltyCoinEntries []*royaltyEntry
	if op.PrevCoinRoyaltyCoinEntries != nil {
		data = append(data, BoolToByte(true))
		data = append(data, UintToBuf(uint64(len(op.PrevCoinRoyaltyCoinEntries)))...)
		for pkid, coinEntry := range op.PrevCoinRoyaltyCoinEntries {
			newPKID := pkid
			newCoin := coinEntry
			royaltyCoinEntries = append(royaltyCoinEntries, &royaltyEntry{
				pkid:      newPKID.ToBytes(),
				coinEntry: EncodeToBytes(blockHeight, &newCoin, skipMetadata...),
			})
		}
		sort.Slice(royaltyCoinEntries, func(i int, j int) bool {
			switch bytes.Compare(royaltyCoinEntries[i].pkid, royaltyCoinEntries[j].pkid) {
			case 0:
				return true
			case -1:
				return true
			case 1:
				return false
			}
			return false
		})
		for _, entry := range royaltyCoinEntries {
			data = append(data, encodeRoyaltyEntry(entry)...)
		}
	} else {
		data = append(data, BoolToByte(false))
	}

	// PrevTransactorBalanceEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevTransactorBalanceEntry, skipMetadata...)...)

	// PrevCreatorBalanceEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevCreatorBalanceEntry, skipMetadata...)...)

	// FounderRewardUtxoKey
	data = append(data, EncodeToBytes(blockHeight, op.FounderRewardUtxoKey, skipMetadata...)...)

	// PrevSenderBalanceEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevSenderBalanceEntry, skipMetadata...)...)

	// PrevReceiverBalanceEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevReceiverBalanceEntry, skipMetadata...)...)

	// PrevGlobalParamsEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevGlobalParamsEntry, skipMetadata...)...)

	// PrevForbiddenPubKeyEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevForbiddenPubKeyEntry, skipMetadata...)...)

	// ClobberedProfileBugDESOLockedNanos
	data = append(data, UintToBuf(op.ClobberedProfileBugDESOLockedNanos)...)

	// CreatorCoinDESOLockedNanosDiff
	// Note that int64 is encoded identically to uint64, the sign bit is just interpreted differently.
	data = append(data, UintToBuf(uint64(op.CreatorCoinDESOLockedNanosDiff))...)

	// SwapIdentityFromDESOLockedNanos
	data = append(data, UintToBuf(op.SwapIdentityFromDESOLockedNanos)...)

	// SwapIdentityToDESOLockedNanos
	data = append(data, UintToBuf(op.SwapIdentityToDESOLockedNanos)...)

	// AcceptNFTBidCreatorPublicKey
	data = append(data, EncodeByteArray(op.AcceptNFTBidCreatorPublicKey)...)

	// AcceptNFTBidBidderPublicKey
	data = append(data, EncodeByteArray(op.AcceptNFTBidBidderPublicKey)...)

	// AcceptNFTBidCreatorRoyaltyNanos
	data = append(data, UintToBuf(op.AcceptNFTBidCreatorRoyaltyNanos)...)

	// AcceptNFTBidCreatorDESORoyaltyNanos
	data = append(data, UintToBuf(op.AcceptNFTBidCreatorDESORoyaltyNanos)...)

	// AcceptNFTBidAdditionalCoinRoyalties
	data = append(data, UintToBuf(uint64(len(op.AcceptNFTBidAdditionalCoinRoyalties)))...)
	for _, pair := range op.AcceptNFTBidAdditionalCoinRoyalties {
		data = append(data, EncodeToBytes(blockHeight, pair, skipMetadata...)...)
	}

	// AcceptNFTBidAdditionalDESORoyalties
	data = append(data, UintToBuf(uint64(len(op.AcceptNFTBidAdditionalDESORoyalties)))...)
	for _, pair := range op.AcceptNFTBidAdditionalDESORoyalties {
		data = append(data, EncodeToBytes(blockHeight, pair, skipMetadata...)...)
	}

	// NFTBidCreatorPublicKey
	data = append(data, EncodeByteArray(op.NFTBidCreatorPublicKey)...)

	// NFTBidBidderPublicKey
	data = append(data, EncodeByteArray(op.NFTBidBidderPublicKey)...)

	// NFTBidCreatorRoyaltyNanos
	data = append(data, UintToBuf(op.NFTBidCreatorRoyaltyNanos)...)

	// NFTBidCreatorDESORoyaltyNanos
	data = append(data, UintToBuf(op.NFTBidCreatorDESORoyaltyNanos)...)

	// NFTBidAdditionalCoinRoyalties
	data = append(data, UintToBuf(uint64(len(op.NFTBidAdditionalCoinRoyalties)))...)
	for _, pair := range op.NFTBidAdditionalCoinRoyalties {
		data = append(data, EncodeToBytes(blockHeight, pair, skipMetadata...)...)
	}

	// NFTBidAdditionalDESORoyalties
	data = append(data, UintToBuf(uint64(len(op.NFTBidAdditionalDESORoyalties)))...)
	for _, pair := range op.NFTBidAdditionalDESORoyalties {
		data = append(data, EncodeToBytes(blockHeight, pair, skipMetadata...)...)
	}

	// PrevTransactorDAOCoinLimitOrderEntry
	data = append(data, EncodeToBytes(blockHeight, op.PrevTransactorDAOCoinLimitOrderEntry, skipMetadata...)...)

	// PrevBalanceEntries. We translate the map[PKID]map[PKID]*BalanceEntry to a tuple <PKID, PKID, BalanceEntry>.
	// Then we sort the bytes to make the ordering deterministic.
	type prevBalance struct {
		primaryPKID   []byte
		secondaryPKID []byte
		balanceBytes  []byte
	}
	encodePrevBalance := func(entry *prevBalance) []byte {
		var data []byte
		data = append(data, EncodeByteArray(entry.primaryPKID)...)
		data = append(data, EncodeByteArray(entry.secondaryPKID)...)
		data = append(data, EncodeByteArray(entry.balanceBytes)...)
		return data
	}
	var prevBalanceEntries []*prevBalance
	if op.PrevBalanceEntries != nil {
		data = append(data, BoolToByte(true))
		for primaryPkidIter, secondaryMap := range op.PrevBalanceEntries {
			primaryPkid := primaryPkidIter
			for secondaryPkidIter, balanceEntry := range secondaryMap {
				secondaryPkid := secondaryPkidIter
				newBalance := *balanceEntry
				prevBalanceEntries = append(prevBalanceEntries, &prevBalance{
					primaryPKID:   primaryPkid.ToBytes(),
					secondaryPKID: secondaryPkid.ToBytes(),
					balanceBytes:  EncodeToBytes(blockHeight, &newBalance, skipMetadata...),
				})
			}
		}
		sort.Slice(prevBalanceEntries, func(i int, j int) bool {
			// We compare primaryPKID || secondaryPKID byte arrays so that we don't have to consider the edge-case where
			// primaryPKID[i] == secondaryPKID[j].
			switch bytes.Compare(append(prevBalanceEntries[i].primaryPKID, prevBalanceEntries[i].secondaryPKID...),
				append(prevBalanceEntries[j].primaryPKID, prevBalanceEntries[j].secondaryPKID...)) {
			case 0:
				return true
			case -1:
				return true
			case 1:
				return false
			}
			return false
		})
		data = append(data, UintToBuf(uint64(len(prevBalanceEntries)))...)
		for _, entry := range prevBalanceEntries {
			data = append(data, encodePrevBalance(entry)...)
		}
	} else {
		data = append(data, BoolToByte(false))
	}

	// PrevMatchingOrders
	data = append(data, UintToBuf(uint64(len(op.PrevMatchingOrders)))...)
	for _, entry := range op.PrevMatchingOrders {
		data = append(data, EncodeToBytes(blockHeight, entry, skipMetadata...)...)
	}

	// FilledDAOCoinLimitOrders
	data = append(data, UintToBuf(uint64(len(op.FilledDAOCoinLimitOrders)))...)
	for _, entry := range op.FilledDAOCoinLimitOrders {
		data = append(data, EncodeToBytes(blockHeight, entry, skipMetadata...)...)
	}

	if MigrationTriggered(blockHeight, AssociationsAndAccessGroupsMigration) {
		// PrevUserAssociationEntry
		data = append(data, EncodeToBytes(blockHeight, op.PrevUserAssociationEntry, skipMetadata...)...)

		// PrevPostAssociationEntry
		data = append(data, EncodeToBytes(blockHeight, op.PrevPostAssociationEntry, skipMetadata...)...)

		// PrevAccessGroupEntry
		data = append(data, EncodeToBytes(blockHeight, op.PrevAccessGroupEntry, skipMetadata...)...)

		// PrevAccessGroupMembersList
		data = append(data, UintToBuf(uint64(len(op.PrevAccessGroupMembersList)))...)
		for _, entry := range op.PrevAccessGroupMembersList {
			data = append(data, EncodeToBytes(blockHeight, entry, skipMetadata...)...)
		}

		// PrevNewMessageEntry
		data = append(data, EncodeToBytes(blockHeight, op.PrevNewMessageEntry, skipMetadata...)...)

		// PrevDmThreadEntry
		data = append(data, EncodeToBytes(blockHeight, op.PrevDmThreadEntry, skipMetadata...)...)
	}

	if MigrationTriggered(blockHeight, BalanceModelMigration) {
		data = append(data, EncodeByteArray(op.BalancePublicKey)...)
		data = append(data, UintToBuf(op.BalanceAmountNanos)...)

		data = append(data, UintToBuf(uint64(len(op.PrevNonceEntries)))...)
		for _, entry := range op.PrevNonceEntries {
			data = append(data, EncodeToBytes(blockHeight, entry, skipMetadata...)...)
		}
	}

	// StateChangeMetadata
	// FIXME: This hackIsRunningStateSyncer() call is a hack to get around the fact that
	// we don't have a way to not require a resync while introducing the state change
	// metadata to the utxo operation struct. We don't want to use a block height to gate
	// this because we want to be able to get state change metadata for ALL transactions.
	// We should replace this with a more elegant solution, a better hack, or bundle it
	// in with a release that requires a resync anyway.
	if hackIsRunningStateSyncer() && op.StateChangeMetadata != nil {
		data = append(data, EncodeToBytes(blockHeight, op.StateChangeMetadata, skipMetadata...)...)
	}

	if MigrationTriggered(blockHeight, ProofOfStake1StateSetupMigration) {
		// PrevValidatorEntry
		data = append(data, EncodeToBytes(blockHeight, op.PrevValidatorEntry, skipMetadata...)...)

		// PrevStakeEntries
		data = append(data, EncodeDeSoEncoderSlice(op.PrevStakeEntries, blockHeight, skipMetadata...)...)

		// PrevLockedStakeEntries
		data = append(data, EncodeDeSoEncoderSlice(op.PrevLockedStakeEntries, blockHeight, skipMetadata...)...)

		// Lockup Fields

		// PrevLockedBalanceEntry, SetLockedBalanceEntries
		data = append(data, EncodeToBytes(blockHeight, op.PrevLockedBalanceEntry, skipMetadata...)...)
		data = append(data, EncodeDeSoEncoderSlice(op.SetLockedBalanceEntries, blockHeight, skipMetadata...)...)

		// PrevLockupYieldCurvePoint, PrevLockupTransferRestrictions
		data = append(data, EncodeToBytes(blockHeight, op.PrevLockupYieldCurvePoint, skipMetadata...)...)
		data = append(data, byte(op.PrevLockupTransferRestriction))

		// PrevSenderLockedBalanceEntry, PrevReceiverLockedBalanceEntry
		data = append(data, EncodeToBytes(blockHeight, op.PrevSenderLockedBalanceEntry, skipMetadata...)...)
		data = append(data, EncodeToBytes(blockHeight, op.PrevReceiverLockedBalanceEntry, skipMetadata...)...)

		// PrevLockedBalanceEntries, ModifiedLockedBalanceEntry
		data = append(data, EncodeDeSoEncoderSlice(op.PrevLockedBalanceEntries, blockHeight, skipMetadata...)...)
		data = append(data, EncodeToBytes(blockHeight, op.ModifiedLockedBalanceEntry, skipMetadata...)...)

		// StakeAmountNanosDiff
		data = append(data, UintToBuf(op.StakeAmountNanosDiff)...)

		// LockedAtEpochNumber
		data = append(data, UintToBuf(op.LockedAtEpochNumber)...)
	}

	return data
}

func (op *UtxoOperation) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {

	// Type
	typeUint64, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading type")
	}
	op.Type = OperationType(uint(typeUint64))

	// Entry
	entry := &UtxoEntry{}
	if exist, err := DecodeFromBytes(entry, rr); exist && err == nil {
		op.Entry = entry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading Entry")
	}

	// Key
	key := &UtxoKey{}
	if exist, err := DecodeFromBytes(key, rr); exist && err == nil {
		op.Key = key
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading Key")
	}

	// PrevNanosPurchased
	op.PrevNanosPurchased, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevNanosPurchased")
	}

	// PrevUSDCentsPerBitcoin
	op.PrevUSDCentsPerBitcoin, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevUSDCentsPerBitcoin")
	}

	// PrevPostEntry
	prevPostEntry := &PostEntry{}
	if exist, err := DecodeFromBytes(prevPostEntry, rr); exist && err == nil {
		op.PrevPostEntry = prevPostEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevPostEntry")
	}

	// PrevParentPostEntry
	prevParentPostEntry := &PostEntry{}
	if exist, err := DecodeFromBytes(prevParentPostEntry, rr); exist && err == nil {
		op.PrevParentPostEntry = prevParentPostEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevParentPostEntry")
	}

	// PrevGrandparentPostEntry
	prevGrandparentPostEntry := &PostEntry{}
	if exist, err := DecodeFromBytes(prevGrandparentPostEntry, rr); exist && err == nil {
		op.PrevGrandparentPostEntry = prevGrandparentPostEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevGrandparentPostEntry")
	}

	// PrevRepostedPostEntry
	prevRepostedPostEntry := &PostEntry{}
	if exist, err := DecodeFromBytes(prevRepostedPostEntry, rr); exist && err == nil {
		op.PrevRepostedPostEntry = prevRepostedPostEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevRepostedPostEntry")
	}

	// PrevProfileEntry
	prevProfileEntry := &ProfileEntry{}
	if exist, err := DecodeFromBytes(prevProfileEntry, rr); exist && err == nil {
		op.PrevProfileEntry = prevProfileEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevProfileEntry")
	}

	// PrevLikeEntry
	prevLikeEntry := &LikeEntry{}
	if exist, err := DecodeFromBytes(prevLikeEntry, rr); exist && err == nil {
		op.PrevLikeEntry = prevLikeEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevLikeEntry")
	}

	// PrevLikeCount
	op.PrevLikeCount, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevLikeCount")
	}

	// PrevDiamondEntry
	prevDiamondEntry := &DiamondEntry{}
	if exist, err := DecodeFromBytes(prevDiamondEntry, rr); exist && err == nil {
		op.PrevDiamondEntry = prevDiamondEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevDiamondEntry")
	}

	// PrevNFTEntry
	prevNFTEntry := &NFTEntry{}
	if exist, err := DecodeFromBytes(prevNFTEntry, rr); exist && err == nil {
		op.PrevNFTEntry = prevNFTEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevNFTEntry")
	}

	// PrevNFTBidEntry
	prevNFTBidEntry := &NFTBidEntry{}
	if exist, err := DecodeFromBytes(prevNFTBidEntry, rr); exist && err == nil {
		op.PrevNFTBidEntry = prevNFTBidEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevNFTBidEntry")
	}

	// DeletedNFTBidEntries
	lenDeletedNFTBidEntries, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading len of DeletedNFTBidEntries")
	}
	for ; lenDeletedNFTBidEntries > 0; lenDeletedNFTBidEntries-- {
		deletedNFTBidEntry := &NFTBidEntry{}
		if exist, err := DecodeFromBytes(deletedNFTBidEntry, rr); exist && err == nil {
			op.DeletedNFTBidEntries = append(op.DeletedNFTBidEntries, deletedNFTBidEntry)
		} else {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading deletedNFTBidEntry")
		}
	}

	// NFTPaymentUtxoKeys
	lenNFTPaymentUtxoKeys, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading len of NFTPaymentUtxoKeys")
	}
	for ; lenNFTPaymentUtxoKeys > 0; lenNFTPaymentUtxoKeys-- {
		NFTPaymentUtxoKey := &UtxoKey{}
		if exist, err := DecodeFromBytes(NFTPaymentUtxoKey, rr); exist && err == nil {
			op.NFTPaymentUtxoKeys = append(op.NFTPaymentUtxoKeys, NFTPaymentUtxoKey)
		} else {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading NFTPaymentUtxoKey")
		}
	}

	// NFTSpentUtxoEntries
	lenNFTSpentUtxoEntries, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading len of NFTSpentUtxoEntries")
	}
	for ; lenNFTSpentUtxoEntries > 0; lenNFTSpentUtxoEntries-- {
		NFTSpentUtxoEntry := &UtxoEntry{}
		if exist, err := DecodeFromBytes(NFTSpentUtxoEntry, rr); exist && err == nil {
			op.NFTSpentUtxoEntries = append(op.NFTSpentUtxoEntries, NFTSpentUtxoEntry)
		} else {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading NFTSpentUtxoEntry")
		}
	}

	// PrevAcceptedNFTBidEntries
	if existByte, err := ReadBoolByte(rr); existByte && err == nil {
		lenPrevAcceptedNFTBidEntries, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading len of PrevAcceptedNFTBidEntries")
		}
		var prevAcceptedNFTBidEntries []*NFTBidEntry
		for ; lenPrevAcceptedNFTBidEntries > 0; lenPrevAcceptedNFTBidEntries-- {
			PrevAcceptedNFTBidEntry := &NFTBidEntry{}
			if exist, err := DecodeFromBytes(PrevAcceptedNFTBidEntry, rr); exist && err == nil {
				prevAcceptedNFTBidEntries = append(prevAcceptedNFTBidEntries, PrevAcceptedNFTBidEntry)
			} else if err != nil {
				return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevAcceptedNFTBidEntry")
			} else {
				prevAcceptedNFTBidEntries = append(prevAcceptedNFTBidEntries, &NFTBidEntry{})
			}
		}
		op.PrevAcceptedNFTBidEntries = &prevAcceptedNFTBidEntries
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevAcceptedNFTBidEntries")
	}

	// PrevDerivedKeyEntry
	prevDerivedKeyEntry := &DerivedKeyEntry{}
	if exist, err := DecodeFromBytes(prevDerivedKeyEntry, rr); exist && err == nil {
		op.PrevDerivedKeyEntry = prevDerivedKeyEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevDerivedKeyEntry")
	}

	// PrevMessagingKeyEntry
	prevMessagingKeyEntry := &MessagingGroupEntry{}
	if exist, err := DecodeFromBytes(prevMessagingKeyEntry, rr); exist && err == nil {
		op.PrevMessagingKeyEntry = prevMessagingKeyEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevMessagingKeyEntry")
	}

	// PrevRepostEntry
	prevRepostEntry := &RepostEntry{}
	if exist, err := DecodeFromBytes(prevRepostEntry, rr); exist && err == nil {
		op.PrevRepostEntry = prevRepostEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevRepostEntry")
	}

	// PrevRepostCount
	op.PrevRepostCount, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevRepostCount")
	}

	// PrevCoinEntry
	prevCoinEntry := &CoinEntry{}
	if exist, err := DecodeFromBytes(prevCoinEntry, rr); exist && err == nil {
		op.PrevCoinEntry = prevCoinEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevCoinEntry")
	}

	// PrevCoinRoyaltyCoinEntries
	type royaltyEntry struct {
		pkid      []byte
		coinEntry []byte
	}
	decodeRoyaltyEntry := func(rr *bytes.Reader) (*royaltyEntry, error) {
		entry := &royaltyEntry{}
		entry.pkid, err = DecodeByteArray(rr)
		if err != nil {
			return nil, err
		}
		entry.coinEntry, err = DecodeByteArray(rr)
		if err != nil {
			return nil, err
		}
		return entry, nil
	}
	if existByte, err := ReadBoolByte(rr); existByte && err == nil {
		op.PrevCoinRoyaltyCoinEntries = make(map[PKID]CoinEntry)
		lenPrevCoinRoyaltyCoinEntries, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevCoinRoyaltyCoinEntries")
		}
		for ; lenPrevCoinRoyaltyCoinEntries > 0; lenPrevCoinRoyaltyCoinEntries-- {
			// Decode the byte arrays for <pkid, coinEntry> pairs.
			entry, err := decodeRoyaltyEntry(rr)
			if err != nil {
				return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevCoinRoyaltyCoinEntries")
			}
			// We've already read the byte array of encoded coinEntry bytes. Now decode them.
			coinEntry := CoinEntry{}
			coinEntryReader := bytes.NewReader(entry.coinEntry)
			if exists, err := DecodeFromBytes(&coinEntry, coinEntryReader); !exists || err != nil {
				return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevCoinRoyaltyCoinEntries")
			}
			op.PrevCoinRoyaltyCoinEntries[*NewPKID(entry.pkid)] = coinEntry
		}
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevCoinRoyaltyCoinEntries")
	}

	// PrevTransactorBalanceEntry
	prevTransactorBalanceEntry := &BalanceEntry{}
	if exist, err := DecodeFromBytes(prevTransactorBalanceEntry, rr); exist && err == nil {
		op.PrevTransactorBalanceEntry = prevTransactorBalanceEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevTransactorBalanceEntry")
	}

	// PrevCreatorBalanceEntry
	prevCreatorBalanceEntry := &BalanceEntry{}
	if exist, err := DecodeFromBytes(prevCreatorBalanceEntry, rr); exist && err == nil {
		op.PrevCreatorBalanceEntry = prevCreatorBalanceEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevCreatorBalanceEntry")
	}

	// FounderRewardUtxoKey
	founderRewardUtxoKey := &UtxoKey{}
	if exist, err := DecodeFromBytes(founderRewardUtxoKey, rr); exist && err == nil {
		op.FounderRewardUtxoKey = founderRewardUtxoKey
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading FounderRewardUtxoKey")
	}

	// PrevSenderBalanceEntry
	prevSenderBalanceEntry := &BalanceEntry{}
	if exist, err := DecodeFromBytes(prevSenderBalanceEntry, rr); exist && err == nil {
		op.PrevSenderBalanceEntry = prevSenderBalanceEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevSenderBalanceEntry")
	}

	// PrevReceiverBalanceEntry
	prevReceiverBalanceEntry := &BalanceEntry{}
	if exist, err := DecodeFromBytes(prevReceiverBalanceEntry, rr); exist && err == nil {
		op.PrevReceiverBalanceEntry = prevReceiverBalanceEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevReceiverBalanceEntry")
	}

	// PrevGlobalParamsEntry
	prevGlobalParamsEntry := &GlobalParamsEntry{}
	if exist, err := DecodeFromBytes(prevGlobalParamsEntry, rr); exist && err == nil {
		op.PrevGlobalParamsEntry = prevGlobalParamsEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevGlobalParamsEntry")
	}

	// PrevForbiddenPubKeyEntry
	prevForbiddenPubKeyEntry := &ForbiddenPubKeyEntry{}
	if exist, err := DecodeFromBytes(prevForbiddenPubKeyEntry, rr); exist && err == nil {
		op.PrevForbiddenPubKeyEntry = prevForbiddenPubKeyEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevForbiddenPubKeyEntry")
	}

	// ClobberedProfileBugDESOLockedNanos
	op.ClobberedProfileBugDESOLockedNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading ClobberedProfileBugDESOLockedNanos")
	}

	// CreatorCoinDESOLockedNanosDiff
	uint64CreatorCoinDESOLockedNanosDiff, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading CreatorCoinDESOLockedNanosDiff")
	}
	op.CreatorCoinDESOLockedNanosDiff = int64(uint64CreatorCoinDESOLockedNanosDiff)

	// SwapIdentityFromDESOLockedNanos
	op.SwapIdentityFromDESOLockedNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading SwapIdentityFromDESOLockedNanos")
	}

	// SwapIdentityToDESOLockedNanos
	op.SwapIdentityToDESOLockedNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading SwapIdentityToDESOLockedNanos")
	}

	// AcceptNFTBidCreatorPublicKey
	op.AcceptNFTBidCreatorPublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading AcceptNFTBidCreatorPublicKey")
	}

	// AcceptNFTBidBidderPublicKey
	op.AcceptNFTBidBidderPublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading AcceptNFTBidBidderPublicKey")
	}

	// AcceptNFTBidCreatorRoyaltyNanos
	op.AcceptNFTBidCreatorRoyaltyNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading AcceptNFTBidCreatorRoyaltyNanos")
	}

	// AcceptNFTBidCreatorDESORoyaltyNanos
	op.AcceptNFTBidCreatorDESORoyaltyNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading AcceptNFTBidCreatorDESORoyaltyNanos")
	}

	// AcceptNFTBidAdditionalCoinRoyalties
	lenAcceptNFTBidAdditionalCoinRoyalties, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading AcceptNFTBidAdditionalCoinRoyalties")
	}
	for ; lenAcceptNFTBidAdditionalCoinRoyalties > 0; lenAcceptNFTBidAdditionalCoinRoyalties-- {
		pair := &PublicKeyRoyaltyPair{}
		if exist, err := DecodeFromBytes(pair, rr); exist && err == nil {
			op.AcceptNFTBidAdditionalCoinRoyalties = append(op.AcceptNFTBidAdditionalCoinRoyalties, pair)
		} else {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading AcceptNFTBidAdditionalCoinRoyalties")
		}
	}

	// AcceptNFTBidAdditionalDESORoyalties
	lenAcceptNFTBidAdditionalDESORoyalties, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading AcceptNFTBidAdditionalDESORoyalties")
	}
	for ; lenAcceptNFTBidAdditionalDESORoyalties > 0; lenAcceptNFTBidAdditionalDESORoyalties-- {
		pair := &PublicKeyRoyaltyPair{}
		if exist, err := DecodeFromBytes(pair, rr); exist && err == nil {
			op.AcceptNFTBidAdditionalDESORoyalties = append(op.AcceptNFTBidAdditionalDESORoyalties, pair)
		} else {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading AcceptNFTBidAdditionalDESORoyalties")
		}
	}

	// NFTBidCreatorPublicKey
	op.NFTBidCreatorPublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading NFTBidCreatorPublicKey")
	}

	// NFTBidBidderPublicKey
	op.NFTBidBidderPublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading NFTBidBidderPublicKey")
	}

	// NFTBidCreatorRoyaltyNanos
	op.NFTBidCreatorRoyaltyNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading NFTBidCreatorRoyaltyNanos")
	}

	// NFTBidCreatorDESORoyaltyNanos
	op.NFTBidCreatorDESORoyaltyNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading NFTBidCreatorDESORoyaltyNanos")
	}

	// NFTBidAdditionalCoinRoyalties
	lenNFTBidAdditionalCoinRoyalties, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading NFTBidAdditionalCoinRoyalties")
	}
	for ; lenNFTBidAdditionalCoinRoyalties > 0; lenNFTBidAdditionalCoinRoyalties-- {
		pair := &PublicKeyRoyaltyPair{}
		if exist, err := DecodeFromBytes(pair, rr); exist && err == nil {
			op.NFTBidAdditionalCoinRoyalties = append(op.NFTBidAdditionalCoinRoyalties, pair)
		} else {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading NFTBidAdditionalCoinRoyalties")
		}

	}

	// NFTBidAdditionalDESORoyalties
	lenNFTBidAdditionalDESORoyalties, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading NFTBidAdditionalDESORoyalties")
	}
	for ; lenNFTBidAdditionalDESORoyalties > 0; lenNFTBidAdditionalDESORoyalties-- {
		pair := &PublicKeyRoyaltyPair{}
		if exist, err := DecodeFromBytes(pair, rr); exist && err == nil {
			op.NFTBidAdditionalDESORoyalties = append(op.NFTBidAdditionalDESORoyalties, pair)
		} else {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading NFTBidAdditionalDESORoyalties")
		}
	}

	// PrevTransactorDAOCoinLimitOrderEntry
	prevTransactorDAOCoinLimitOrderEntry := &DAOCoinLimitOrderEntry{}
	if exist, err := DecodeFromBytes(prevTransactorDAOCoinLimitOrderEntry, rr); exist && err == nil {
		op.PrevTransactorDAOCoinLimitOrderEntry = prevTransactorDAOCoinLimitOrderEntry
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevTransactorDAOCoinLimitOrderEntry")
	}

	// PrevBalanceEntries
	type prevBalance struct {
		primaryPKID   []byte
		secondaryPKID []byte
		balanceBytes  []byte
	}
	decodePrevBalance := func(rr *bytes.Reader) (*prevBalance, error) {
		entry := &prevBalance{}
		entry.primaryPKID, err = DecodeByteArray(rr)
		if err != nil {
			return nil, err
		}
		entry.secondaryPKID, err = DecodeByteArray(rr)
		if err != nil {
			return nil, err
		}
		entry.balanceBytes, err = DecodeByteArray(rr)
		if err != nil {
			return nil, err
		}
		return entry, nil
	}
	if exist, err := ReadBoolByte(rr); exist && err == nil {
		op.PrevBalanceEntries = make(map[PKID]map[PKID]*BalanceEntry)
		lenPrevBalanceEntries, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevBalanceEntries")
		}
		for ; lenPrevBalanceEntries > 0; lenPrevBalanceEntries-- {
			// decode the <pkid, pkid, BalanceEntry> tuples.
			entry, err := decodePrevBalance(rr)
			if err != nil {
				return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevBalanceEntries")
			}

			primaryPKID := *NewPKID(entry.primaryPKID)
			secondaryPKID := *NewPKID(entry.secondaryPKID)
			balanceEntry := &BalanceEntry{}
			rrBalance := bytes.NewReader(entry.balanceBytes)
			if exist, err := DecodeFromBytes(balanceEntry, rrBalance); !exist || err != nil {
				return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevBalanceEntries")
			}
			if _, exist := op.PrevBalanceEntries[primaryPKID]; !exist {
				op.PrevBalanceEntries[primaryPKID] = make(map[PKID]*BalanceEntry)
			}
			op.PrevBalanceEntries[primaryPKID][secondaryPKID] = balanceEntry
		}
	} else if err != nil {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevBalanceEntries")
	}

	// PrevMatchingOrders
	if lenPrevMatchingOrders, err := ReadUvarint(rr); err == nil {
		for ; lenPrevMatchingOrders > 0; lenPrevMatchingOrders-- {
			prevOrder := &DAOCoinLimitOrderEntry{}
			if exist, err := DecodeFromBytes(prevOrder, rr); exist && err == nil {
				op.PrevMatchingOrders = append(op.PrevMatchingOrders, prevOrder)
			} else {
				return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevMatchingOrders")
			}
		}
	} else {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevMatchingOrders")
	}

	// FilledDAOCoinLimitOrders
	if lenFilledDAOCoinLimitOrders, err := ReadUvarint(rr); err == nil {
		for ; lenFilledDAOCoinLimitOrders > 0; lenFilledDAOCoinLimitOrders-- {
			filledDAOCoinLimitOrder := &FilledDAOCoinLimitOrder{}
			if exist, err := DecodeFromBytes(filledDAOCoinLimitOrder, rr); exist && err == nil {
				op.FilledDAOCoinLimitOrders = append(op.FilledDAOCoinLimitOrders, filledDAOCoinLimitOrder)
			} else {
				return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading FilledDAOCoinLimitOrder")
			}
		}
	} else {
		return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading FilledDAOCoinLimitOrder")
	}

	if MigrationTriggered(blockHeight, AssociationsAndAccessGroupsMigration) {
		// PrevUserAssociationEntry
		prevUserAssociationEntry := &UserAssociationEntry{}
		if exist, err := DecodeFromBytes(prevUserAssociationEntry, rr); exist && err == nil {
			op.PrevUserAssociationEntry = prevUserAssociationEntry
		} else if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevUserAssociationEntry")
		}

		// PrevPostAssociationEntry
		prevPostAssociationEntry := &PostAssociationEntry{}
		if exist, err := DecodeFromBytes(prevPostAssociationEntry, rr); exist && err == nil {
			op.PrevPostAssociationEntry = prevPostAssociationEntry
		} else if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevPostAssociationEntry")
		}

		// PrevAccessGroupEntry
		accessGroupEntry := &AccessGroupEntry{}
		if exist, err := DecodeFromBytes(accessGroupEntry, rr); exist && err == nil {
			op.PrevAccessGroupEntry = accessGroupEntry
		} else if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevAccessGroupEntry")
		}

		// PrevAccessGroupMembersList
		if lenPrevAccessGroupMembersList, err := ReadUvarint(rr); err == nil {
			for ; lenPrevAccessGroupMembersList > 0; lenPrevAccessGroupMembersList-- {
				accessGroupMemberEntry := &AccessGroupMemberEntry{}
				if exist, err := DecodeFromBytes(accessGroupMemberEntry, rr); exist && err == nil {
					op.PrevAccessGroupMembersList = append(op.PrevAccessGroupMembersList, accessGroupMemberEntry)
				} else {
					return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevAccessGroupMembersList")
				}
			}
		} else {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevAccessGroupMembersList")
		}

		// PrevNewMessageEntry
		newMessageEntry := &NewMessageEntry{}
		if exist, err := DecodeFromBytes(newMessageEntry, rr); exist && err == nil {
			op.PrevNewMessageEntry = newMessageEntry
		} else if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevNewMessageEntry")
		}

		// PrevDmThreadEntry
		dmThreadExistence := &DmThreadEntry{}
		if exist, err := DecodeFromBytes(dmThreadExistence, rr); exist && err == nil {
			op.PrevDmThreadEntry = dmThreadExistence
		} else if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevDmThreadEntry")
		}
	}

	if MigrationTriggered(blockHeight, BalanceModelMigration) {
		op.BalancePublicKey, err = DecodeByteArray(rr)
		if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PublicKeyBytes")
		}
		op.BalanceAmountNanos, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading BalanceAmountNanos")
		}

		var numPrevNonceEntries uint64
		numPrevNonceEntries, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading numPrevNonceEntries")
		}

		for ; numPrevNonceEntries > 0; numPrevNonceEntries-- {
			prevNonceEntry := &TransactorNonceEntry{}
			if _, err = DecodeFromBytes(prevNonceEntry, rr); err != nil {
				return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading prevNonceEntry")
			}
			op.PrevNonceEntries = append(op.PrevNonceEntries, prevNonceEntry)
		}
	}

	// DeSoEncoder
	stateChangeMetadata := GetStateChangeMetadataFromOpType(op.Type)
	// FIXME: This hackIsRunningStateSyncer() call is a hack to get around the fact that
	// we don't have a way to not require a resync while introducing the state change
	// metadata to the utxo operation struct. We don't want to use a block height to gate
	// this because we want to be able to get state change metadata for ALL transactions.
	// We should replace this with a more elegant solution, a better hack, or bundle it
	// in with a release that requires a resync anyway.
	if hackIsRunningStateSyncer() && stateChangeMetadata != nil {
		if exist, err := DecodeFromBytes(stateChangeMetadata, rr); exist && err == nil {
			op.StateChangeMetadata = stateChangeMetadata
		} else if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading DeSoEncoder")
		}
	}

	if MigrationTriggered(blockHeight, ProofOfStake1StateSetupMigration) {
		// PrevValidatorEntry
		if op.PrevValidatorEntry, err = DecodeDeSoEncoder(&ValidatorEntry{}, rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevValidatorEntry: ")
		}

		// PrevStakeEntries
		if op.PrevStakeEntries, err = DecodeDeSoEncoderSlice[*StakeEntry](rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevStakeEntries: ")
		}

		// PrevLockedStakeEntries
		if op.PrevLockedStakeEntries, err = DecodeDeSoEncoderSlice[*LockedStakeEntry](rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevLockedStakeEntries: ")
		}

		// Lockup Fields

		// PrevLockedBalanceEntry, SetLockedBalanceEntries
		if op.PrevLockedBalanceEntry, err = DecodeDeSoEncoder(&LockedBalanceEntry{}, rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevLockedBalanceEntry: ")
		}
		if op.SetLockedBalanceEntries, err = DecodeDeSoEncoderSlice[*LockedBalanceEntry](rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading SetLockedBalanceEntries: ")
		}

		// PrevLockupYieldCurvePoint, PrevLockupTransferRestriction
		if op.PrevLockupYieldCurvePoint, err = DecodeDeSoEncoder(&LockupYieldCurvePoint{}, rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevLockupYieldCurvePoint: ")
		}
		lockupTransferRestriction, err := rr.ReadByte()
		if err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevLockupTransferRestriction: ")
		}
		op.PrevLockupTransferRestriction = TransferRestrictionStatus(lockupTransferRestriction)

		// PrevSenderLockedBalanceEntry, PrevReceiverLockedBalanceEntry
		if op.PrevSenderLockedBalanceEntry, err = DecodeDeSoEncoder(&LockedBalanceEntry{}, rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevSenderLockedBalanceEntry: ")
		}
		if op.PrevReceiverLockedBalanceEntry, err = DecodeDeSoEncoder(&LockedBalanceEntry{}, rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem Reading PrevReceiverLockedBalanceEntry: ")
		}

		// PrevLockedBalanceEntries
		if op.PrevLockedBalanceEntries, err = DecodeDeSoEncoderSlice[*LockedBalanceEntry](rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading PrevLockedBalanceEntry: ")
		}
		// ModifiedLockedBalanceEntry
		if op.ModifiedLockedBalanceEntry, err = DecodeDeSoEncoder(&LockedBalanceEntry{}, rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem Reading ModifiedLockedBalanceEntry: ")
		}

		// StakeAmountNanosDiff
		if op.StakeAmountNanosDiff, err = ReadUvarint(rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading StakeAmountNanosDiff: ")
		}

		// LockedAtEpochNumber
		if op.LockedAtEpochNumber, err = ReadUvarint(rr); err != nil {
			return errors.Wrapf(err, "UtxoOperation.Decode: Problem reading LockedAtEpochNumber: ")
		}
	}

	return nil
}

func (op *UtxoOperation) GetVersionByte(blockHeight uint64) byte {
	return GetMigrationVersion(
		blockHeight,
		AssociationsAndAccessGroupsMigration,
		BalanceModelMigration,
		ProofOfStake1StateSetupMigration,
	)
}

func (op *UtxoOperation) GetEncoderType() EncoderType {
	return EncoderTypeUtxoOperation
}

type UtxoOperationBundle struct {
	UtxoOpBundle [][]*UtxoOperation
}

func (opBundle *UtxoOperationBundle) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, UintToBuf(uint64(len(opBundle.UtxoOpBundle)))...)
	for _, opList := range opBundle.UtxoOpBundle {
		data = append(data, UintToBuf(uint64(len(opList)))...)
		for _, op := range opList {
			data = append(data, EncodeToBytes(blockHeight, op, skipMetadata...)...)
		}
	}
	return data
}

func (opBundle *UtxoOperationBundle) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	opBundle.UtxoOpBundle = make([][]*UtxoOperation, 0)
	opListLen, err := ReadUvarint(rr)
	if err != nil {
		return err
	}

	for ; opListLen > 0; opListLen-- {
		opLen, err := ReadUvarint(rr)
		if err != nil {
			return err
		}

		var opList []*UtxoOperation
		for ; opLen > 0; opLen-- {
			op := &UtxoOperation{}
			if exists, err := DecodeFromBytes(op, rr); !exists || err != nil {
				return err
			}
			opList = append(opList, op)
		}
		opBundle.UtxoOpBundle = append(opBundle.UtxoOpBundle, opList)
	}

	return nil
}

func (opBundle *UtxoOperationBundle) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (opBundle *UtxoOperationBundle) GetEncoderType() EncoderType {
	return EncoderTypeUtxoOperationBundle
}

// Have to define these because Go doesn't let you use raw byte slices as map keys.
// This needs to be in-sync with DeSoMainnetParams.MaxUsernameLengthBytes
type UsernameMapKey [MaxUsernameLengthBytes]byte

func MakeUsernameMapKey(nonLowercaseUsername []byte) UsernameMapKey {
	// Always lowercase the username when we use it as a key in our map. This allows
	// us to check uniqueness in a case-insensitive way.
	lowercaseUsername := []byte(strings.ToLower(string(nonLowercaseUsername)))
	usernameMapKey := UsernameMapKey{}
	copy(usernameMapKey[:], lowercaseUsername)
	return usernameMapKey
}

// DEPRECATED: Replace all instances with lib.PublicKey
type PkMapKey [btcec.PubKeyBytesLenCompressed]byte

func (mm PkMapKey) String() string {
	return PkToStringBoth(mm[:])
}

func MakePkMapKey(pk []byte) PkMapKey {
	pkMapKey := PkMapKey{}
	copy(pkMapKey[:], pk)
	return pkMapKey
}

func MakeMessageKey(pk []byte, tstampNanos uint64) MessageKey {
	return MessageKey{
		PublicKey:   *NewPublicKey(pk),
		TstampNanos: tstampNanos,
	}
}

type MessageKey struct {
	PublicKey   PublicKey
	BlockHeight uint32
	TstampNanos uint64
}

func (mm *MessageKey) String() string {
	return fmt.Sprintf("<Public Key: %s, TstampNanos: %d>",
		PkToStringMainnet(mm.PublicKey[:]), mm.TstampNanos)
}

// StringKey is useful for creating maps that need to be serialized to JSON.
func (mm *MessageKey) StringKey(params *DeSoParams) string {
	return PkToString(mm.PublicKey[:], params) + "_" + fmt.Sprint(mm.TstampNanos)
}

// MessageEntry stores the essential content of a message transaction.
type MessageEntry struct {
	SenderPublicKey    *PublicKey
	RecipientPublicKey *PublicKey
	EncryptedText      []byte
	// TODO: Right now a sender can fake the timestamp and make it appear to
	// the recipient that she sent messages much earlier than she actually did.
	// This isn't a big deal because there is generally not much to gain from
	// faking a timestamp, and it's still impossible for a user to impersonate
	// another user, which is the important thing. Moreover, it is easy to fix
	// the timestamp spoofing issue: You just need to make it so that the nodes
	// index messages based on block height in addition to on the tstamp. The
	// reason I didn't do it yet is because it adds some complexity around
	// detecting duplicates, particularly if a transaction is allowed to have
	// zero inputs/outputs, which is advantageous for various reasons.
	TstampNanos uint64

	isDeleted bool

	// Indicates message encryption method
	// Version = 3 : message encrypted using rotating keys and group chats.
	// Version = 2 : message encrypted using shared secrets
	// Version = 1 : message encrypted using public key
	Version uint8

	// DeSo V3 Messages fields

	// SenderMessagingPublicKey is the sender's messaging public key that was used
	// to encrypt the corresponding message.
	SenderMessagingPublicKey *PublicKey

	// SenderMessagingGroupKeyName is the sender's key name of SenderMessagingPublicKey
	SenderMessagingGroupKeyName *GroupKeyName

	// RecipientMessagingPublicKey is the recipient's messaging public key that was
	// used to encrypt the corresponding message.
	RecipientMessagingPublicKey *PublicKey

	// RecipientMessagingGroupKeyName is the recipient's key name of RecipientMessagingPublicKey
	RecipientMessagingGroupKeyName *GroupKeyName

	// Extra data
	ExtraData map[string][]byte
}

func (message *MessageEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeToBytes(blockHeight, message.SenderPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, message.RecipientPublicKey, skipMetadata...)...)
	data = append(data, EncodeByteArray(message.EncryptedText)...)
	data = append(data, UintToBuf(message.TstampNanos)...)
	data = append(data, UintToBuf(uint64(message.Version))...)
	data = append(data, EncodeToBytes(blockHeight, message.SenderMessagingPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, message.SenderMessagingGroupKeyName, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, message.RecipientMessagingPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, message.RecipientMessagingGroupKeyName, skipMetadata...)...)
	data = append(data, EncodeExtraData(message.ExtraData)...)
	return data
}

func (message *MessageEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	senderPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(senderPublicKey, rr); exist && err == nil {
		message.SenderPublicKey = senderPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: Problem reading SenderPublicKey")
	}

	recipientPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(recipientPublicKey, rr); exist && err == nil {
		message.RecipientPublicKey = recipientPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding recipient public key")
	}

	message.EncryptedText, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding encrypted bytes")
	}

	message.TstampNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding timestamp")
	}

	versionBytes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding version")
	}
	message.Version = uint8(versionBytes)

	senderMessagingPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(senderMessagingPublicKey, rr); exist && err == nil {
		message.SenderMessagingPublicKey = senderMessagingPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding sender messaging public key")
	}

	senderMessagingKeyName := &GroupKeyName{}
	if exist, err := DecodeFromBytes(senderMessagingKeyName, rr); exist && err == nil {
		message.SenderMessagingGroupKeyName = senderMessagingKeyName
	} else if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding sender messaging key name")
	}

	recipientMessagingPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(recipientMessagingPublicKey, rr); exist && err == nil {
		message.RecipientMessagingPublicKey = recipientMessagingPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding sender messaging key name")
	}

	recipientMessagingKeyName := &GroupKeyName{}
	if exist, err := DecodeFromBytes(recipientMessagingKeyName, rr); exist && err == nil {
		message.RecipientMessagingGroupKeyName = recipientMessagingKeyName
	} else if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding sender messaging key name")
	}
	message.RecipientMessagingGroupKeyName = recipientMessagingKeyName

	message.ExtraData, err = DecodeExtraData(rr)
	if err != nil && strings.Contains(err.Error(), "EOF") {
		// To preserve backwards-compatibility, we set an empty map and return if we
		// encounter an EOF error decoding ExtraData.
		glog.Warning(err, "MesssageEntry.Decode: problem decoding extra data. "+
			"Please resync your node to upgrade your datadir before the next hard fork.")
		return nil
	} else if err != nil {
		return errors.Wrapf(err, "MesssageEntry.Decode: problem decoding extra data")
	}

	return nil
}

func (message *MessageEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (message *MessageEntry) GetEncoderType() EncoderType {
	return EncoderTypeMessageEntry
}

//
// New Message
//

// NewMessageEntry stores the essential content of a message transaction.
type NewMessageEntry struct {

	// Sender
	// SenderAccessGroupOwnerPublicKey is the owner public key of the sender's access group.
	// Messages are sent between two access groups: the sender, and the recipient.
	SenderAccessGroupOwnerPublicKey *PublicKey

	// SenderAccessGroupKeyName is the sender's access group key name
	SenderAccessGroupKeyName *GroupKeyName

	// SenderAccessGroupPublicKey is the sender's access public key that was used
	// to encrypt the corresponding message.
	SenderAccessGroupPublicKey *PublicKey

	// Recipient
	// RecipientAccessGroupOwnerPublicKey is the owner public key of the recipient's access group.
	RecipientAccessGroupOwnerPublicKey *PublicKey

	// RecipientAccessGroupKeyName is the recipient's access group key name
	RecipientAccessGroupKeyName *GroupKeyName

	// RecipientAccessGroupPublicKey is the recipient's access public key that was
	// used to encrypt the corresponding message.
	RecipientAccessGroupPublicKey *PublicKey

	EncryptedText []byte

	// Right now a sender can fake the timestamp and make it appear to
	// the recipient that she sent messages much earlier than she actually did.
	// This isn't a big deal because there is generally not much to gain from
	// faking a timestamp. Messaging apps can just display messages with timestamps
	// smaller than the current time.
	TimestampNanos uint64

	// Extra data
	ExtraData map[string][]byte

	isDeleted bool
}

func (message *NewMessageEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeToBytes(blockHeight, message.SenderAccessGroupOwnerPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, message.SenderAccessGroupKeyName, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, message.SenderAccessGroupPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, message.RecipientAccessGroupOwnerPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, message.RecipientAccessGroupKeyName, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, message.RecipientAccessGroupPublicKey, skipMetadata...)...)
	data = append(data, EncodeByteArray(message.EncryptedText)...)
	data = append(data, UintToBuf(message.TimestampNanos)...)
	data = append(data, EncodeExtraData(message.ExtraData)...)
	return data
}

func (message *NewMessageEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	senderAccessGroupOwnerPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(senderAccessGroupOwnerPublicKey, rr); exist && err == nil {
		message.SenderAccessGroupOwnerPublicKey = senderAccessGroupOwnerPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "NewMessageEntry.Decode: Problem reading SenderAccessGroupOwnerPublicKey")
	}

	senderAccessGroupKeyName := &GroupKeyName{}
	if exist, err := DecodeFromBytes(senderAccessGroupKeyName, rr); exist && err == nil {
		message.SenderAccessGroupKeyName = senderAccessGroupKeyName
	} else if err != nil {
		return errors.Wrapf(err, "NewMessageEntry.Decode: problem decoding SenderAccessGroupKeyName")
	}

	senderAccessPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(senderAccessPublicKey, rr); exist && err == nil {
		message.SenderAccessGroupPublicKey = senderAccessPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "NewMessageEntry.Decode: problem decoding SenderAccessGroupPublicKey")
	}

	recipientAccessGroupOwnerPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(recipientAccessGroupOwnerPublicKey, rr); exist && err == nil {
		message.RecipientAccessGroupOwnerPublicKey = recipientAccessGroupOwnerPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "NewMessageEntry.Decode: problem decoding RecipientAccessGroupOwnerPublicKey")
	}

	recipientAccessGroupKeyName := &GroupKeyName{}
	if exist, err := DecodeFromBytes(recipientAccessGroupKeyName, rr); exist && err == nil {
		message.RecipientAccessGroupKeyName = recipientAccessGroupKeyName
	} else if err != nil {
		return errors.Wrapf(err, "NewMessageEntry.Decode: problem decoding RecipientAccessGroupKeyName")
	}

	recipientAccessPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(recipientAccessPublicKey, rr); exist && err == nil {
		message.RecipientAccessGroupPublicKey = recipientAccessPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "NewMessageEntry.Decode: problem decoding RecipientAccessGroupPublicKey")
	}

	message.EncryptedText, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageEntry.Decode: problem decoding encrypted bytes")
	}

	message.TimestampNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageEntry.Decode: problem decoding timestamp")
	}

	message.ExtraData, err = DecodeExtraData(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageEntry.Decode: problem decoding extra data")
	}

	return nil
}

func (message *NewMessageEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (message *NewMessageEntry) GetEncoderType() EncoderType {
	return EncoderTypeNewMessageEntry
}

type GroupChatMessageKey struct {
	AccessGroupOwnerPublicKey PublicKey
	AccessGroupKeyName        GroupKeyName
	TimestampNanos            uint64
}

func MakeGroupChatMessageKey(groupOwnerPublicKey PublicKey, groupKeyName GroupKeyName, tstampNanos uint64) GroupChatMessageKey {
	return GroupChatMessageKey{
		AccessGroupOwnerPublicKey: groupOwnerPublicKey,
		AccessGroupKeyName:        groupKeyName,
		TimestampNanos:            tstampNanos,
	}
}

type DmMessageKey struct {
	MinorAccessGroupOwnerPublicKey PublicKey
	MinorAccessGroupKeyName        GroupKeyName
	MajorAccessGroupOwnerPublicKey PublicKey
	MajorAccessGroupKeyName        GroupKeyName
	TimestampNanos                 uint64
}

func MakeDmMessageKey(xGroupOwnerPublicKey PublicKey, xGroupKeyName GroupKeyName,
	yGroupOwnerPublicKey PublicKey, yGroupKeyName GroupKeyName, tstampNanos uint64) DmMessageKey {

	minorGroupOwnerPublicKey := xGroupOwnerPublicKey
	minorGroupKeyName := xGroupKeyName
	majorGroupOwnerPublicKey := yGroupOwnerPublicKey
	majorGroupKeyName := yGroupKeyName
	switch bytes.Compare(xGroupOwnerPublicKey.ToBytes(), yGroupOwnerPublicKey.ToBytes()) {
	case 1:
		minorGroupOwnerPublicKey = yGroupOwnerPublicKey
		minorGroupKeyName = yGroupKeyName
		majorGroupOwnerPublicKey = xGroupOwnerPublicKey
		majorGroupKeyName = xGroupKeyName
	case 0:
		// If there is a tie on public keys, then we compare group key names.
		switch bytes.Compare(xGroupKeyName.ToBytes(), yGroupKeyName.ToBytes()) {
		case 1:
			minorGroupOwnerPublicKey = yGroupOwnerPublicKey
			minorGroupKeyName = yGroupKeyName
			majorGroupOwnerPublicKey = xGroupOwnerPublicKey
			majorGroupKeyName = xGroupKeyName
		}
	}

	return DmMessageKey{
		MinorAccessGroupOwnerPublicKey: minorGroupOwnerPublicKey,
		MinorAccessGroupKeyName:        minorGroupKeyName,
		MajorAccessGroupOwnerPublicKey: majorGroupOwnerPublicKey,
		MajorAccessGroupKeyName:        majorGroupKeyName,
		TimestampNanos:                 tstampNanos,
	}
}

func MakeDmMessageKeyFromDmThreadKey(dmThreadKey DmThreadKey) DmMessageKey {
	return MakeDmMessageKeyForSenderRecipient(dmThreadKey.UserAccessGroupOwnerPublicKey, dmThreadKey.UserAccessGroupKeyName,
		dmThreadKey.PartyAccessGroupOwnerPublicKey, dmThreadKey.PartyAccessGroupKeyName, 0)
}

func MakeDmMessageKeyForSenderRecipient(senderAccessGroupOwnerPublicKey PublicKey, senderAccessGroupKeyName GroupKeyName,
	recipientAccessGroupOwnerPublicKey PublicKey, recipientAccessGroupKeyName GroupKeyName, tstampNanos uint64) DmMessageKey {

	return MakeDmMessageKey(
		senderAccessGroupOwnerPublicKey, senderAccessGroupKeyName,
		recipientAccessGroupOwnerPublicKey, recipientAccessGroupKeyName,
		tstampNanos)
}

type DmThreadKey struct {
	UserAccessGroupOwnerPublicKey  PublicKey
	UserAccessGroupKeyName         GroupKeyName
	PartyAccessGroupOwnerPublicKey PublicKey
	PartyAccessGroupKeyName        GroupKeyName
}

func MakeDmThreadKey(userGroupOwnerPublicKey PublicKey, userGroupKeyName GroupKeyName,
	partyGroupOwnerPublicKey PublicKey, partyGroupKeyName GroupKeyName) DmThreadKey {
	return DmThreadKey{
		UserAccessGroupOwnerPublicKey:  userGroupOwnerPublicKey,
		UserAccessGroupKeyName:         userGroupKeyName,
		PartyAccessGroupOwnerPublicKey: partyGroupOwnerPublicKey,
		PartyAccessGroupKeyName:        partyGroupKeyName,
	}
}

func MakeDmThreadKeyFromMessageEntry(messageEntry *NewMessageEntry, shouldUseRecipientUser bool) (DmThreadKey, error) {
	if messageEntry == nil {
		return DmThreadKey{}, fmt.Errorf("MakeDmThreadKeyFromMessageEntry: messageEntry is nil")
	}
	if messageEntry.RecipientAccessGroupOwnerPublicKey == nil || messageEntry.RecipientAccessGroupKeyName == nil ||
		messageEntry.SenderAccessGroupOwnerPublicKey == nil || messageEntry.SenderAccessGroupKeyName == nil {
		return DmThreadKey{}, fmt.Errorf("MakeDmThreadKeyFromMessageEntry: messageEntry is missing fields")
	}
	if shouldUseRecipientUser {
		return MakeDmThreadKey(
			*messageEntry.RecipientAccessGroupOwnerPublicKey, *messageEntry.RecipientAccessGroupKeyName,
			*messageEntry.SenderAccessGroupOwnerPublicKey, *messageEntry.SenderAccessGroupKeyName), nil
	} else {
		return MakeDmThreadKey(
			*messageEntry.SenderAccessGroupOwnerPublicKey, *messageEntry.SenderAccessGroupKeyName,
			*messageEntry.RecipientAccessGroupOwnerPublicKey, *messageEntry.RecipientAccessGroupKeyName), nil
	}
}

// AccessGroupMemberEnumerationEntry
type AccessGroupMemberEnumerationEntry struct {
	isDeleted bool
}

func MakeAccessGroupMemberEnumerationEntry() AccessGroupMemberEnumerationEntry {
	return AccessGroupMemberEnumerationEntry{
		isDeleted: false,
	}
}

func (entry *AccessGroupMemberEnumerationEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	return []byte{}
}

func (entry *AccessGroupMemberEnumerationEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	return nil
}

func (entry *AccessGroupMemberEnumerationEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (entry *AccessGroupMemberEnumerationEntry) GetEncoderType() EncoderType {
	return EncoderTypeAccessGroupMemberEnumerationEntry
}

// DmThreadEntry
type DmThreadEntry struct {
	isDeleted bool
}

func MakeDmThreadEntry() DmThreadEntry {
	return DmThreadEntry{
		isDeleted: false,
	}
}

func (entry *DmThreadEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	return data
}

func (entry *DmThreadEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	return nil
}

func (entry *DmThreadEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (entry *DmThreadEntry) GetEncoderType() EncoderType {
	return EncoderTypeDmThreadEntry
}

// GroupKeyName helps with handling key names in AccessGroups
type GroupKeyName [MaxAccessGroupKeyNameCharacters]byte

func (name *GroupKeyName) ToBytes() []byte {
	return name[:]
}

func (name *GroupKeyName) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	return EncodeByteArray(name[:])
}

func (name *GroupKeyName) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	nameBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupKeyName.Decode: Problem reading name")
	}
	copy(name[:], nameBytes)
	return nil
}

func (name *GroupKeyName) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (name *GroupKeyName) GetEncoderType() EncoderType {
	return EncoderTypeGroupKeyName
}

// Encode message key from varying length to a MaxAccessKeyNameCharacters.
// We fill the length of the access key to make sure there are no weird
// prefix overlaps in DB.
func NewGroupKeyName(groupKeyName []byte) *GroupKeyName {
	name := GroupKeyName{}

	// Fill with 0s to the MaxAccessKeyNameCharacters.
	for {
		if len(groupKeyName) < MaxAccessGroupKeyNameCharacters {
			groupKeyName = append(groupKeyName, []byte{0}...)
		} else {
			copy(name[:], groupKeyName)
			return &name
		}
	}
}

// Decode filled message key of length MaxMessagingKeyNameCharacters array.
func MessagingKeyNameDecode(name *GroupKeyName) []byte {

	bytes := make([]byte, MaxMessagingKeyNameCharacters)
	copy(bytes, name[:])

	// Return empty byte array if we have a non-existent key.
	if reflect.DeepEqual(bytes, (*NewGroupKeyName([]byte{}))[:]) {
		return []byte{}
	}

	// Remove trailing 0s from the encoded message key.
	for {
		if len(bytes) > MinMessagingKeyNameCharacters && bytes[len(bytes)-1] == byte(0) {
			bytes = bytes[:len(bytes)-1]
		} else {
			return bytes
		}
	}
}

// Decode filled message key of length MaxAccessKeyNameCharacters array.
func AccessKeyNameDecode(name *GroupKeyName) []byte {

	bytes := make([]byte, MaxAccessGroupKeyNameCharacters)
	copy(bytes, name[:])

	// Return empty byte array if we have a non-existent key.
	if reflect.DeepEqual(bytes, (*NewGroupKeyName([]byte{}))[:]) {
		return []byte{}
	}

	// Remove trailing 0s from the encoded message key.
	for {
		if len(bytes) > MinAccessGroupKeyNameCharacters && bytes[len(bytes)-1] == byte(0) {
			bytes = bytes[:len(bytes)-1]
		} else {
			return bytes
		}
	}
}

func EqualGroupKeyName(a, b *GroupKeyName) bool {
	return reflect.DeepEqual(a.ToBytes(), b.ToBytes())
}

func BaseGroupKeyName() *GroupKeyName {
	return NewGroupKeyName([]byte{})
}

func DefaultGroupKeyName() *GroupKeyName {
	return NewGroupKeyName([]byte("default-key"))
}

// MessagingGroupKey is similar to the MessageKey, and is used to index messaging keys for a user.
type MessagingGroupKey struct {
	OwnerPublicKey PublicKey
	GroupKeyName   GroupKeyName
}

func NewMessagingGroupKey(ownerPublicKey *PublicKey, groupKeyName []byte) *MessagingGroupKey {
	return &MessagingGroupKey{
		OwnerPublicKey: *ownerPublicKey,
		GroupKeyName:   *NewGroupKeyName(groupKeyName),
	}
}

func (key *MessagingGroupKey) String() string {
	return fmt.Sprintf("<OwnerPublicKey: %v, AccessGroupKeyName: %v",
		key.OwnerPublicKey, key.GroupKeyName)
}

type AccessGroupId struct {
	AccessGroupOwnerPublicKey PublicKey
	AccessGroupKeyName        GroupKeyName
}

func NewAccessGroupId(ownerPublicKey *PublicKey, groupKeyName []byte) *AccessGroupId {
	if ownerPublicKey == nil {
		return nil
	}
	return &AccessGroupId{
		AccessGroupOwnerPublicKey: *ownerPublicKey,
		AccessGroupKeyName:        *NewGroupKeyName(groupKeyName),
	}
}

func (key *AccessGroupId) String() string {
	return fmt.Sprintf("<AccessGroupOwnerPublicKey: %v, AccessGroupKeyName: %v",
		key.AccessGroupOwnerPublicKey, key.AccessGroupKeyName)
}

func (key *AccessGroupId) ToBytes() []byte {
	var data []byte
	data = append(data, EncodeByteArray(key.AccessGroupOwnerPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(key.AccessGroupKeyName.ToBytes())...)
	return data
}

func (key *AccessGroupId) FromBytes(rr *bytes.Reader) error {
	accessGroupOwnerPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading AccessGroupOwnerPublicKey")
	}
	key.AccessGroupOwnerPublicKey = *NewPublicKey(accessGroupOwnerPublicKeyBytes)

	accessGroupKeyNameBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading AccessGroupKeyName")
	}
	key.AccessGroupKeyName = *NewGroupKeyName(accessGroupKeyNameBytes)

	return nil
}

// AccessGroupMembershipKey is used to index group memberships for a user.
type AccessGroupMembershipKey struct {
	AccessGroupMemberPublicKey PublicKey
	AccessGroupOwnerPublicKey  PublicKey
	AccessGroupKeyName         GroupKeyName
}

func (key *AccessGroupMembershipKey) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, key.AccessGroupMemberPublicKey[:]...)
	data = append(data, key.AccessGroupOwnerPublicKey[:]...)
	data = append(data, key.AccessGroupKeyName[:]...)
	return data
}

func (key *AccessGroupMembershipKey) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {

	groupMemberPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(groupMemberPublicKey, rr); exist && err == nil {
		key.AccessGroupMemberPublicKey = *groupMemberPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupMembershipKey.Decode: Problem reading "+
			"AccessGroupMemberPublicKey")
	}

	groupOwnerPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(groupOwnerPublicKey, rr); exist && err == nil {
		key.AccessGroupOwnerPublicKey = *groupOwnerPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupMembershipKey.Decode: Problem reading "+
			"AccessGroupOwnerPublicKey")
	}

	groupKeyName := &GroupKeyName{}
	if exist, err := DecodeFromBytes(groupKeyName, rr); exist && err == nil {
		key.AccessGroupKeyName = *groupKeyName
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupMembershipKey.Decode: Problem reading "+
			"AccessGroupKeyName")
	}

	return nil
}

func (key *AccessGroupMembershipKey) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (key *AccessGroupMembershipKey) GetEncoderType() EncoderType {
	return EncoderTypeGroupMembershipKey
}

func NewGroupMembershipKey(groupMemberPublicKey PublicKey, groupOwnerPublicKey PublicKey, groupKeyName GroupKeyName) *AccessGroupMembershipKey {
	return &AccessGroupMembershipKey{
		AccessGroupMemberPublicKey: groupMemberPublicKey,
		AccessGroupOwnerPublicKey:  groupOwnerPublicKey,
		AccessGroupKeyName:         groupKeyName,
	}
}

func (key *AccessGroupMembershipKey) String() string {
	return fmt.Sprintf("<AccessGroupMemberPublicKey: %v, AccessGroupOwnerPublicKey: %v, AccessGroupKeyName: %v>",
		key.AccessGroupMemberPublicKey, key.AccessGroupOwnerPublicKey, key.AccessGroupKeyName)
}

type AccessGroupEntry struct {
	AccessGroupOwnerPublicKey *PublicKey
	AccessGroupKeyName        *GroupKeyName
	AccessGroupPublicKey      *PublicKey

	ExtraData map[string][]byte
	isDeleted bool
}

func (entry *AccessGroupEntry) String() string {
	return fmt.Sprintf("<AccessGroupOwnerPublicKey: %v, AccessGroupKeyName: %v, AccessGroupPublicKey: %v, ExtraData: %v, isDeleted: %v>",
		entry.AccessGroupOwnerPublicKey, entry.AccessGroupKeyName, entry.AccessGroupPublicKey, entry.ExtraData, entry.isDeleted)
}

func (entry *AccessGroupEntry) IsDeleted() bool {
	return entry.isDeleted
}

func (entry *AccessGroupEntry) GetAccessGroupId() AccessGroupId {
	return AccessGroupId{
		AccessGroupOwnerPublicKey: *entry.AccessGroupOwnerPublicKey,
		AccessGroupKeyName:        *entry.AccessGroupKeyName,
	}
}

func (entry *AccessGroupEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeToBytes(blockHeight, entry.AccessGroupOwnerPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, entry.AccessGroupKeyName, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, entry.AccessGroupPublicKey, skipMetadata...)...)
	data = append(data, EncodeExtraData(entry.ExtraData)...)
	return data
}

func (entry *AccessGroupEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	accessGroupOwnerPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(accessGroupOwnerPublicKey, rr); exist && err == nil {
		entry.AccessGroupOwnerPublicKey = accessGroupOwnerPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupEntry.Decode: Problem reading "+
			"AccessGroupOwnerPublicKey")
	}

	accessGroupKeyName := &GroupKeyName{}
	if exist, err := DecodeFromBytes(accessGroupKeyName, rr); exist && err == nil {
		entry.AccessGroupKeyName = accessGroupKeyName
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupEntry.Decode: Problem reading "+
			"AccessGroupKeyName")
	}

	accessGroupPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(accessGroupPublicKey, rr); exist && err == nil {
		entry.AccessGroupPublicKey = accessGroupPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupEntry.Decode: Problem reading "+
			"AccessGroupPublicKey")
	}

	extraData, err := DecodeExtraData(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupEntry.Decode: Problem reading "+
			"ExtraData")
	}
	entry.ExtraData = extraData

	return nil
}

func (entry *AccessGroupEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (entry *AccessGroupEntry) GetEncoderType() EncoderType {
	return EncoderTypeAccessGroupEntry
}

// AccessGroupEntry is used to update access keys for a user, this was added in
// the DeSo V3 Messages protocol.
type MessagingGroupEntry struct {
	// GroupOwnerPublicKey represents the owner public key of the user who created
	// this group. This key is what is used to index the group metadata in the db.
	GroupOwnerPublicKey *PublicKey

	// MessagingPublicKey is the key others will use to encrypt messages. The
	// GroupOwnerPublicKey is used for indexing, but the MessagingPublicKey is the
	// actual key used to encrypt/decrypt messages.
	MessagingPublicKey *PublicKey

	// MessagingGroupKeyName is the name of the messaging key. This is used to identify
	// the message public key. You can pass any 8-32 character string (byte array).
	// The standard Messages V3 key is named "default-key"
	MessagingGroupKeyName *GroupKeyName

	// MessagingGroupMembers is a list of recipients in a group chat. Messaging keys can have
	// multiple recipients, where the encrypted private key of the messaging public key
	// is given to all group members.
	MessagingGroupMembers []*MessagingGroupMember

	// ExtraData is an arbitrary key value map
	ExtraData map[string][]byte

	// Whether this entry should be deleted when the view is flushed
	// to the db. This is initially set to false, but can become true if
	// we disconnect the messaging key from UtxoView
	isDeleted bool
}

func (entry *MessagingGroupEntry) String() string {
	return fmt.Sprintf("<MessagingGroupEntry: %v | MessagingPublicKey : %v | MessagingGroupKey : %v | isDeleted : %v >",
		entry.GroupOwnerPublicKey, entry.MessagingPublicKey, entry.MessagingGroupKeyName, entry.isDeleted)
}

func (entry *MessagingGroupEntry) IsDeleted() bool {
	return entry.isDeleted
}

func sortMessagingGroupMembers(membersArg []*MessagingGroupMember) []*MessagingGroupMember {
	// Make a deep copy of the members to avoid messing up the slice the caller
	// used. Not doing this could cause downstream effects, mainly in tests where
	// the same slice is re-used in txns and in expectations later on.
	// TODO: use safe make here? will introduce an error
	members := make([]*MessagingGroupMember, len(membersArg))
	copy(members, membersArg)
	sort.Slice(members, func(ii, jj int) bool {
		iiStr := PkToStringMainnet(members[ii].GroupMemberPublicKey[:]) + string(members[ii].GroupMemberKeyName[:]) + string(members[ii].EncryptedKey)
		jjStr := PkToStringMainnet(members[jj].GroupMemberPublicKey[:]) + string(members[jj].GroupMemberKeyName[:]) + string(members[jj].EncryptedKey)
		return iiStr < jjStr
	})
	return members
}

func (entry *MessagingGroupEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var entryBytes []byte

	entryBytes = append(entryBytes, EncodeToBytes(blockHeight, entry.GroupOwnerPublicKey, skipMetadata...)...)
	entryBytes = append(entryBytes, EncodeToBytes(blockHeight, entry.MessagingPublicKey, skipMetadata...)...)
	entryBytes = append(entryBytes, EncodeToBytes(blockHeight, entry.MessagingGroupKeyName, skipMetadata...)...)
	entryBytes = append(entryBytes, UintToBuf(uint64(len(entry.MessagingGroupMembers)))...)
	// We sort the MessagingGroupMembers because they can be added while iterating over
	// a map, which could lead to inconsistent orderings across nodes when encoding.
	members := sortMessagingGroupMembers(entry.MessagingGroupMembers)
	for ii := 0; ii < len(members); ii++ {
		entryBytes = append(entryBytes, EncodeToBytes(blockHeight, members[ii], skipMetadata...)...)
	}
	entryBytes = append(entryBytes, EncodeExtraData(entry.ExtraData)...)
	return entryBytes
}

func (entry *MessagingGroupEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	groupOwnerPublicKeyBytes := &PublicKey{}
	if exist, err := DecodeFromBytes(groupOwnerPublicKeyBytes, rr); exist && err == nil {
		entry.GroupOwnerPublicKey = groupOwnerPublicKeyBytes
	} else if err != nil {
		return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding groupOwnerPublicKeyBytes")
	}

	messagingPublicKeyBytes := &PublicKey{}
	if exist, err := DecodeFromBytes(messagingPublicKeyBytes, rr); exist && err == nil {
		entry.MessagingPublicKey = messagingPublicKeyBytes
	} else if err != nil {
		return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding messagingPublicKey")
	}

	messagingKeyNameBytes := &GroupKeyName{}
	if exist, err := DecodeFromBytes(messagingKeyNameBytes, rr); exist && err == nil {
		entry.MessagingGroupKeyName = messagingKeyNameBytes
	} else if err != nil {
		return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding messagingKeyName")
	}

	recipientsLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding recipients length")
	}
	for ; recipientsLen > 0; recipientsLen-- {
		recipient := &MessagingGroupMember{}
		if exist, err := DecodeFromBytes(recipient, rr); exist && err == nil {
			entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, recipient)
		} else if err != nil {
			return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding recipient")
		}
	}

	entry.ExtraData, err = DecodeExtraData(rr)
	if err != nil && strings.Contains(err.Error(), "EOF") {
		// To preserve backwards-compatibility, we set an empty map and return if we
		// encounter an EOF error decoding ExtraData.
		glog.Warning(err, "MessagingGroupEntry.Decode: problem decoding extra data. "+
			"Please resync your node to upgrade your datadir before the next hard fork.")
		return nil
	} else if err != nil {
		return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding extra data")
	}

	return nil
}

func (entry *MessagingGroupEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (entry *MessagingGroupEntry) GetEncoderType() EncoderType {
	return EncoderTypeMessagingGroupEntry
}

type AccessGroupMemberEntry struct {
	// AccessGroupMemberPublicKey is the *owner* public key of the user in the access group
	AccessGroupMemberPublicKey *PublicKey

	// AccessGroupMemberKeyName is the key name of the user in the access group
	// Most of the time, we will be using a user's "default-key" key name
	AccessGroupMemberKeyName *GroupKeyName

	// EncryptedKey is the encrypted private key of the access group public key
	// If the access group's private key were GroupPriv, and the member's public
	// key were MemberPub, then we would have EncrypetdKey would be GroupPriv
	// encrypted with MemberPub.
	EncryptedKey []byte

	// ExtraData is an arbitrary key value map
	ExtraData map[string][]byte

	// Whether this entry should be deleted when the view is flushed to the db.
	// This is initially set to false, but can become true if the entry is disconnected.
	isDeleted bool
}

func (entry *AccessGroupMemberEntry) String() string {
	return fmt.Sprintf("<AccessGroupMemberEntry: %v | AccessGroupMemberKeyName : %v | EncryptedKey : %v | "+
		"ExtraData : %v | isDeleted : %v >", entry.AccessGroupMemberPublicKey, entry.AccessGroupMemberKeyName,
		entry.EncryptedKey, entry.ExtraData, entry.isDeleted)
}

func (entry *AccessGroupMemberEntry) IsDeleted() bool {
	return entry.isDeleted
}

func (entry *AccessGroupMemberEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var entryBytes []byte

	entryBytes = append(entryBytes, EncodeToBytes(blockHeight, entry.AccessGroupMemberPublicKey, skipMetadata...)...)
	entryBytes = append(entryBytes, EncodeToBytes(blockHeight, entry.AccessGroupMemberKeyName, skipMetadata...)...)
	entryBytes = append(entryBytes, EncodeByteArray(entry.EncryptedKey)...)
	entryBytes = append(entryBytes, EncodeExtraData(entry.ExtraData)...)
	return entryBytes
}

func (entry *AccessGroupMemberEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	accessGroupMemberPublicKeyBytes := &PublicKey{}
	if exist, err := DecodeFromBytes(accessGroupMemberPublicKeyBytes, rr); exist && err == nil {
		entry.AccessGroupMemberPublicKey = accessGroupMemberPublicKeyBytes
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupMemberEntry.Decode: Problem decoding accessGroupMemberPublicKeyBytes")
	}

	accessGroupMemberKeyNameBytes := &GroupKeyName{}
	if exist, err := DecodeFromBytes(accessGroupMemberKeyNameBytes, rr); exist && err == nil {
		entry.AccessGroupMemberKeyName = accessGroupMemberKeyNameBytes
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupMemberEntry.Decode: Problem decoding accessGroupMemberKeyNameBytes")
	}

	encryptedKey, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMemberEntry.Decode: Problem decoding encryptedKey")
	}
	entry.EncryptedKey = encryptedKey

	entry.ExtraData, err = DecodeExtraData(rr)
	if err != nil && strings.Contains(err.Error(), "EOF") {
		// To preserve backwards-compatibility, we set an empty map and return if we
		// encounter an EOF error decoding ExtraData.
		glog.Warning(err, "AccessGroupMemberEntry.Decode: problem decoding extra data. "+
			"Please resync your node to upgrade your datadir before the next hard fork.")
		return nil
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupMemberEntry.Decode: Problem decoding extra data")
	}

	return nil
}

func (entry *AccessGroupMemberEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (entry *AccessGroupMemberEntry) GetEncoderType() EncoderType {
	return EncoderTypeAccessGroupMemberEntry
}

// MessagingGroupMember is used to store information about a group chat member.
type MessagingGroupMember struct {
	// GroupMemberPublicKey is the main public key of the group chat member.
	// Importantly, it isn't a messaging public key.
	GroupMemberPublicKey *PublicKey

	// GroupMemberKeyName determines the key of the recipient that the
	// encrypted key is addressed to. We allow adding recipients by their
	// messaging keys. It suffices to specify the recipient's main public key
	// and recipient's messaging key name for the consensus to know how to
	// index the recipient. That's why we don't actually store the messaging
	// public key in the MessagingGroupMember entry.
	GroupMemberKeyName *GroupKeyName

	// EncryptedKey is the encrypted messaging public key, addressed to the recipient.
	EncryptedKey []byte
}

func (rec *MessagingGroupMember) ToBytes() []byte {
	var data []byte

	data = append(data, EncodeByteArray(rec.GroupMemberPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(rec.GroupMemberKeyName.ToBytes())...)
	data = append(data, EncodeByteArray(rec.EncryptedKey)...)

	return data
}

func (rec *MessagingGroupMember) FromBytes(rr *bytes.Reader) error {
	var err error

	pkBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupMember.FromBytes: Problem reading GroupMemberPublicKey")
	}
	rec.GroupMemberPublicKey = NewPublicKey(pkBytes)

	keyNameBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupMember.FromBytes: Problem reading GroupMemberKeyName")
	}
	rec.GroupMemberKeyName = NewGroupKeyName(keyNameBytes)

	rec.EncryptedKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupMember.FromBytes: Problem reading EncryptedKey")
	}
	return nil
}

func (rec *MessagingGroupMember) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	data := []byte{}

	data = append(data, EncodeToBytes(blockHeight, rec.GroupMemberPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, rec.GroupMemberKeyName, skipMetadata...)...)
	data = append(data, EncodeByteArray(rec.EncryptedKey)...)

	return data
}

func (rec *MessagingGroupMember) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	groupMemberPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(groupMemberPublicKey, rr); exist && err == nil {
		rec.GroupMemberPublicKey = groupMemberPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "MessagingGroupMember.Decode: Problem reading "+
			"GroupMemberPublicKey")
	}

	groupMemberKeyName := &GroupKeyName{}
	if exist, err := DecodeFromBytes(groupMemberKeyName, rr); exist && err == nil {
		rec.GroupMemberKeyName = groupMemberKeyName
	} else if err != nil {
		return errors.Wrapf(err, "MessagingGroupMember.Decode: Problem reading "+
			"GroupMemberKeyName")
	}

	rec.EncryptedKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupMember.Decode: Problem reading "+
			"EncryptedKey")
	}
	return nil
}

func (rec *MessagingGroupMember) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (rec *MessagingGroupMember) GetEncoderType() EncoderType {
	return EncoderTypeMessagingGroupMember
}

// Entry for a public key forbidden from signing blocks.
type ForbiddenPubKeyEntry struct {
	PubKey []byte

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (entry *ForbiddenPubKeyEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray(entry.PubKey)...)
	return data
}

func (entry *ForbiddenPubKeyEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	entry.PubKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "ForbiddenPubKeyEntry.Decode: Problem decoding PubKey")
	}
	return nil
}

func (entry *ForbiddenPubKeyEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (entry *ForbiddenPubKeyEntry) GetEncoderType() EncoderType {
	return EncoderTypeForbiddenPubKeyEntry
}

func MakeLikeKey(userPk []byte, LikedPostHash BlockHash) LikeKey {
	return LikeKey{
		LikerPubKey:   MakePkMapKey(userPk),
		LikedPostHash: LikedPostHash,
	}
}

type LikeKey struct {
	LikerPubKey   PkMapKey
	LikedPostHash BlockHash
}

// LikeEntry stores the content of a like transaction.
type LikeEntry struct {
	LikerPubKey   []byte
	LikedPostHash *BlockHash

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (likeEntry *LikeEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray(likeEntry.LikerPubKey)...)
	data = append(data, EncodeToBytes(blockHeight, likeEntry.LikedPostHash, skipMetadata...)...)
	return data
}

func (likeEntry *LikeEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	likeEntry.LikerPubKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "LikeEntry.Decode: problem reading LikerPubKey")
	}
	likedPostHash := &BlockHash{}
	if exist, err := DecodeFromBytes(likedPostHash, rr); exist && err == nil {
		likeEntry.LikedPostHash = likedPostHash
	} else if err != nil {
		return errors.Wrapf(err, "LikeEntry.Decode: problem reading LikedPostHash")
	}
	return nil
}

func (likeEntry *LikeEntry) DecodeLikeEntryFromLikerPubKeyToLikedPostHashKey(key []byte) error {
	if len(key) < HashSizeBytes+btcec.PubKeyBytesLenCompressed+1 {
		return fmt.Errorf("LikeEntry.RawDecodeWithoutMetadataFromKey: key is too short: %v", len(key))
	}
	likeEntry.LikerPubKey = key[1 : btcec.PubKeyBytesLenCompressed+1]
	likeEntry.LikedPostHash = &BlockHash{}
	copy(likeEntry.LikedPostHash[:], key[btcec.PubKeyBytesLenCompressed+1:])
	return nil
}

func (likeEntry *LikeEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (likeEntry *LikeEntry) GetEncoderType() EncoderType {
	return EncoderTypeLikeEntry
}

func MakeNFTKey(nftPostHash *BlockHash, serialNumber uint64) NFTKey {
	return NFTKey{
		NFTPostHash:  *nftPostHash,
		SerialNumber: serialNumber,
	}
}

type NFTKey struct {
	NFTPostHash  BlockHash
	SerialNumber uint64
}

// This struct defines an individual NFT owned by a PKID. An NFT entry  maps to a single
// postEntry, but a single postEntry can map to multiple NFT entries. Each NFT copy is
// defined by a serial number, which denotes it's place in the set (ie. #1 of 100).
type NFTEntry struct {
	LastOwnerPKID              *PKID // This is needed to decrypt unlockable text.
	OwnerPKID                  *PKID
	NFTPostHash                *BlockHash
	SerialNumber               uint64
	IsForSale                  bool
	MinBidAmountNanos          uint64
	UnlockableText             []byte
	LastAcceptedBidAmountNanos uint64

	// If this NFT was transferred to the current owner, it will be pending until accepted.
	IsPending bool

	// If an NFT does not have unlockable content, it can be sold instantly at BuyNowPriceNanos.
	IsBuyNow bool

	// If an NFT is a Buy Now NFT, it can be purchased for this price.
	BuyNowPriceNanos uint64

	ExtraData map[string][]byte

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (nft *NFTEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeToBytes(blockHeight, nft.LastOwnerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, nft.OwnerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, nft.NFTPostHash, skipMetadata...)...)
	data = append(data, UintToBuf(nft.SerialNumber)...)
	data = append(data, BoolToByte(nft.IsForSale))
	data = append(data, UintToBuf(nft.MinBidAmountNanos)...)
	data = append(data, EncodeByteArray(nft.UnlockableText)...)
	data = append(data, UintToBuf(nft.LastAcceptedBidAmountNanos)...)
	data = append(data, BoolToByte(nft.IsPending))
	data = append(data, BoolToByte(nft.IsBuyNow))
	data = append(data, UintToBuf(nft.BuyNowPriceNanos)...)
	data = append(data, EncodeExtraData(nft.ExtraData)...)
	return data
}

func (nft *NFTEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	lastOwnerPKID := &PKID{}
	if exist, err := DecodeFromBytes(lastOwnerPKID, rr); exist && err == nil {
		nft.LastOwnerPKID = lastOwnerPKID
	} else if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem reading LastOwnerPKID")
	}

	ownerPKID := &PKID{}
	if exist, err := DecodeFromBytes(ownerPKID, rr); exist && err == nil {
		nft.OwnerPKID = ownerPKID
	} else if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem reading OwnerPKID")
	}

	NFTPostHash := &BlockHash{}
	if exist, err := DecodeFromBytes(NFTPostHash, rr); exist && err == nil {
		nft.NFTPostHash = NFTPostHash
	} else if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem reading NFTPostHash")
	}
	nft.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem reading SerialNumber")
	}
	nft.IsForSale, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem reading IsForSale")
	}
	nft.MinBidAmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem reading MinBidAmountNanos")
	}

	nft.UnlockableText, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem reading UnlockableText")
	}

	nft.LastAcceptedBidAmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem reading LastAcceptedBidAmountNanos")
	}
	nft.IsPending, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem reading IsPending")
	}
	nft.IsBuyNow, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem reading IsBuyNow")
	}
	nft.BuyNowPriceNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem reading BuyNowPriceNanos")
	}

	nft.ExtraData, err = DecodeExtraData(rr)
	if err != nil && strings.Contains(err.Error(), "EOF") {
		// To preserve backwards-compatibility, we set an empty map and return if we
		// encounter an EOF error decoding ExtraData.
		glog.Warning(err, "NFTEntry.Decode: problem decoding extra data. "+
			"Please resync your node to upgrade your datadir before the next hard fork.")
		return nil
	} else if err != nil {
		return errors.Wrapf(err, "NFTEntry.Decode: Problem decoding extra data")
	}

	return nil
}

func (nft *NFTEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (nft *NFTEntry) GetEncoderType() EncoderType {
	return EncoderTypeNFTEntry
}

func MakeNFTBidKey(bidderPKID *PKID, nftPostHash *BlockHash, serialNumber uint64) NFTBidKey {
	return NFTBidKey{
		BidderPKID:   *bidderPKID,
		NFTPostHash:  *nftPostHash,
		SerialNumber: serialNumber,
	}
}

type NFTBidKey struct {
	BidderPKID   PKID
	NFTPostHash  BlockHash
	SerialNumber uint64
}

// This struct defines a single bid on an NFT.
type NFTBidEntry struct {
	BidderPKID     *PKID
	NFTPostHash    *BlockHash
	SerialNumber   uint64
	BidAmountNanos uint64

	AcceptedBlockHeight *uint32

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (be *NFTBidEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeToBytes(blockHeight, be.BidderPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, be.NFTPostHash, skipMetadata...)...)
	data = append(data, UintToBuf(be.SerialNumber)...)
	data = append(data, UintToBuf(be.BidAmountNanos)...)

	if be.AcceptedBlockHeight != nil {
		data = append(data, BoolToByte(true))
		data = append(data, UintToBuf(uint64(*be.AcceptedBlockHeight))...)
	} else {
		data = append(data, BoolToByte(false))
	}
	return data
}

func (be *NFTBidEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	bidderPKID := &PKID{}
	if exist, err := DecodeFromBytes(bidderPKID, rr); exist && err == nil {
		be.BidderPKID = bidderPKID
	} else if err != nil {
		return errors.Wrapf(err, "NFTBidEntry.Decode: Problem reading BidderPKID")
	}
	NFTPostHash := &BlockHash{}
	if exist, err := DecodeFromBytes(NFTPostHash, rr); exist && err == nil {
		be.NFTPostHash = NFTPostHash
	} else if err != nil {
		return errors.Wrapf(err, "NFTBidEntry.Decode: Problem reading NFTPostHash")
	}
	be.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTBidEntry.Decode: Problem reading SerialNubmer")
	}
	be.BidAmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTBidEntry.Decode: Problem reading BidAmountNanos")
	}

	if existByte, err := ReadBoolByte(rr); existByte && err == nil {
		acceptedBlockHeight, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "NFTBidEntry.Decode: Problem reading AcceptedBlockHeight")
		}
		acceptedBlockHeight32 := uint32(acceptedBlockHeight)
		be.AcceptedBlockHeight = &acceptedBlockHeight32
	}
	return nil
}

func (be *NFTBidEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (be *NFTBidEntry) GetEncoderType() EncoderType {
	return EncoderTypeNFTBidEntry
}

func (nftBidEntry *NFTBidEntry) Copy() *NFTBidEntry {
	if nftBidEntry == nil {
		return nil
	}
	newEntry := *nftBidEntry
	newEntry.BidderPKID = nftBidEntry.BidderPKID.NewPKID()
	newEntry.NFTPostHash = nftBidEntry.NFTPostHash.NewBlockHash()
	if nftBidEntry.AcceptedBlockHeight != nil {
		*newEntry.AcceptedBlockHeight = *nftBidEntry.AcceptedBlockHeight
	}
	return &newEntry
}

type NFTBidEntryBundle struct {
	nftBidEntryBundle []*NFTBidEntry
}

func (bundle *NFTBidEntryBundle) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	if bundle.nftBidEntryBundle != nil {
		numEntries := uint64(len(bundle.nftBidEntryBundle))
		data = append(data, UintToBuf(numEntries)...)

		for _, entry := range bundle.nftBidEntryBundle {
			data = append(data, EncodeToBytes(blockHeight, entry, skipMetadata...)...)
		}
	} else {
		data = append(data, UintToBuf(0)...)
	}

	return data
}

func (bundle *NFTBidEntryBundle) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {

	numEntries, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTBidEntryBundle.RawDecodeWithoutMetadata: Problem decoding number of nft bids")
	}
	bundle.nftBidEntryBundle, err = SafeMakeSliceWithLength[*NFTBidEntry](numEntries)
	if err != nil {
		return errors.Wrapf(err, "NFTBidEntryBundle.RawDecodeWithoutMetadata: Problem creating slice for nftBidEntryBundle")
	}
	for ii := uint64(0); ii < numEntries; ii++ {
		bidEntry := &NFTBidEntry{}
		if exists, err := DecodeFromBytes(bidEntry, rr); !exists || err != nil {
			return errors.Wrapf(err, "NFTBidEntryBundle.RawDecodeWithoutMetadata: Problem decoding nft bids at index ii: %v", ii)
		}
		bundle.nftBidEntryBundle = append(bundle.nftBidEntryBundle, bidEntry)
	}

	return nil
}

func (bundle *NFTBidEntryBundle) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (bundle *NFTBidEntryBundle) GetEncoderType() EncoderType {
	return EncoderTypeNFTBidEntryBundle
}

type DerivedKeyEntry struct {
	// Owner public key
	OwnerPublicKey PublicKey

	// Derived public key
	DerivedPublicKey PublicKey

	// Expiration Block
	ExpirationBlock uint64

	// Operation type determines if the derived key is
	// authorized or de-authorized.
	OperationType AuthorizeDerivedKeyOperationType

	ExtraData map[string][]byte

	// Transaction Spending limit Tracker
	TransactionSpendingLimitTracker *TransactionSpendingLimit

	// Memo that tells you what this derived key is for. Should
	// include the name or domain of the app that asked for these
	// permissions so the user can manage it from a centralized UI.
	Memo []byte

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (key *DerivedKeyEntry) IsDeleted() bool {
	return key.isDeleted
}

func (key *DerivedKeyEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray(key.OwnerPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(key.DerivedPublicKey.ToBytes())...)
	data = append(data, UintToBuf(key.ExpirationBlock)...)
	data = append(data, byte(key.OperationType))
	data = append(data, EncodeExtraData(key.ExtraData)...)
	if key.TransactionSpendingLimitTracker != nil {
		data = append(data, BoolToByte(true))
		// TODO: we need to catch the error here or not raise an error in spending limits .ToBytes
		tslBytes, _ := key.TransactionSpendingLimitTracker.ToBytes(blockHeight)
		data = append(data, tslBytes...)
	} else {
		data = append(data, BoolToByte(false))
	}
	data = append(data, EncodeByteArray(key.Memo)...)

	return data
}

func (key *DerivedKeyEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	ownerPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DerivedKeyEntry.Decode: Problem reading OwnerPublicKey")
	}
	key.OwnerPublicKey = *NewPublicKey(ownerPublicKeyBytes)
	derivedPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DerivedKeyEntry.Decode: Problem reading DerivedPublicKey")
	}
	key.DerivedPublicKey = *NewPublicKey(derivedPublicKeyBytes)

	key.ExpirationBlock, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DerivedKeyEntry.Decode: Problem reading ExpirationBlock")
	}

	operationType, err := rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "DerivedKeyEntry.Decode: Problem reading OperationType")
	}
	key.OperationType = AuthorizeDerivedKeyOperationType(operationType)

	key.ExtraData, err = DecodeExtraData(rr)
	if err != nil && strings.Contains(err.Error(), "EOF") {
		// To preserve backwards-compatibility, we set an empty map and return if we
		// encounter an EOF error decoding ExtraData.
		glog.Warning(err, "DerivedKeyEntry.Decode: problem decoding extra data. "+
			"Please resync your node to upgrade your datadir before the next hard fork.")
		return nil
	} else if err != nil {
		return errors.Wrapf(err, "DerivedKeyEntry.Decode: Problem decoding extra data")
	}

	if exists, err := ReadBoolByte(rr); exists && err == nil {
		key.TransactionSpendingLimitTracker = &TransactionSpendingLimit{}
		err := key.TransactionSpendingLimitTracker.FromBytes(blockHeight, rr)
		if err != nil {
			return errors.Wrapf(err, "DerivedKeyEntry.Decode: Problem decoding TransactionSpendingLimitTracker")
		}
	} else if err != nil {
		return errors.Wrapf(err, "DerivedKeyEntry.Decode: Problem decoding TransactionSpendingLimitTracker existence byte")
	}

	key.Memo, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DerivedKeyEntry.Decode: Problem decoding Memo")
	}

	return nil
}

func (key *DerivedKeyEntry) GetVersionByte(blockHeight uint64) byte {
	// Remember to update this every time there an encoder migration that impacts
	// the TransactionSpendingLimit struct.
	return GetMigrationVersion(blockHeight, UnlimitedDerivedKeysMigration, AssociationsAndAccessGroupsMigration,
		BalanceModelMigration, ProofOfStake1StateSetupMigration)
}

func (key *DerivedKeyEntry) GetEncoderType() EncoderType {
	return EncoderTypeDerivedKeyEntry
}

func (dk *DerivedKeyEntry) Copy() *DerivedKeyEntry {
	if dk == nil {
		return nil
	}
	newEntry := *dk
	if dk.TransactionSpendingLimitTracker != nil {
		newEntry.TransactionSpendingLimitTracker = dk.TransactionSpendingLimitTracker.Copy()
	}
	return &newEntry
}

type DerivedKeyMapKey struct {
	// Owner public key
	OwnerPublicKey PublicKey

	// Derived public key
	DerivedPublicKey PublicKey
}

func MakeDerivedKeyMapKey(ownerPublicKey PublicKey, derivedPublicKey PublicKey) DerivedKeyMapKey {
	return DerivedKeyMapKey{
		OwnerPublicKey:   ownerPublicKey,
		DerivedPublicKey: derivedPublicKey,
	}
}

func MakeFollowKey(followerPKID *PKID, followedPKID *PKID) FollowKey {
	return FollowKey{
		FollowerPKID: *followerPKID,
		FollowedPKID: *followedPKID,
	}
}

type FollowKey struct {
	FollowerPKID PKID
	FollowedPKID PKID
}

// FollowEntry stores the content of a follow transaction.
type FollowEntry struct {
	// Note: It's a little redundant to have these in the entry because they're
	// already used as the key in the DB but it doesn't hurt for now.
	FollowerPKID *PKID
	FollowedPKID *PKID

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (fe *FollowEntry) IsDeleted() bool {
	return fe.isDeleted
}

func (fe *FollowEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, fe.FollowerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, fe.FollowedPKID, skipMetadata...)...)
	return data
}

func (fe *FollowEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	followerPKID := &PKID{}
	if exist, err := DecodeFromBytes(followerPKID, rr); exist && err == nil {
		fe.FollowerPKID = followerPKID
	} else if err != nil {
		return errors.Wrapf(err, "FollowEntry.Decode: Problem reading FollowerPKID")
	}

	// FollowedPKID
	followedPKID := &PKID{}
	if exist, err := DecodeFromBytes(followedPKID, rr); exist && err == nil {
		fe.FollowedPKID = followedPKID
	} else if err != nil {
		return errors.Wrapf(err, "FollowEntry.Decode: Problem reading FollowedPKID")
	}

	return nil
}

func (fe *FollowEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (fe *FollowEntry) GetEncoderType() EncoderType {
	return EncoderTypeFollowEntry
}

// DeSoBalanceEntry stores the user's pkid and their corresponding DeSo balance nanos.
type DeSoBalanceEntry struct {
	PublicKey    []byte
	BalanceNanos uint64

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (desoBalanceEntry *DeSoBalanceEntry) IsDeleted() bool {
	return desoBalanceEntry.isDeleted
}

func (desoBalanceEntry *DeSoBalanceEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray(desoBalanceEntry.PublicKey)...)
	data = append(data, UintToBuf(desoBalanceEntry.BalanceNanos)...)
	return data
}

func (desoBalanceEntry *DeSoBalanceEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	desoBalanceEntry.PublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DesoBalanceEntry.Decode: Problem reading PublicKey")
	}

	balanceNanos, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DesoBalanceEntry.Decode: Problem reading BalanceNanos")
	}
	desoBalanceEntry.BalanceNanos = balanceNanos
	return nil
}

func (desoBalanceEntry *DeSoBalanceEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (desoBalanceEntry *DeSoBalanceEntry) GetEncoderType() EncoderType {
	return EncoderTypeDeSoBalanceEntry
}

type DiamondKey struct {
	SenderPKID      PKID
	ReceiverPKID    PKID
	DiamondPostHash BlockHash
}

func MakeDiamondKey(senderPKID *PKID, receiverPKID *PKID, diamondPostHash *BlockHash) DiamondKey {
	return DiamondKey{
		SenderPKID:      *senderPKID,
		ReceiverPKID:    *receiverPKID,
		DiamondPostHash: *diamondPostHash,
	}
}

func (mm *DiamondKey) String() string {
	return fmt.Sprintf("<SenderPKID: %v, ReceiverPKID: %v, DiamondPostHash: %v>",
		PkToStringMainnet(mm.SenderPKID[:]), PkToStringMainnet(mm.ReceiverPKID[:]),
		hex.EncodeToString(mm.DiamondPostHash[:]))
}

// DiamondEntry stores the number of diamonds given by a sender to a post.
type DiamondEntry struct {
	SenderPKID      *PKID
	ReceiverPKID    *PKID
	DiamondPostHash *BlockHash
	DiamondLevel    int64

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (de *DiamondEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeToBytes(blockHeight, de.SenderPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, de.ReceiverPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, de.DiamondPostHash, skipMetadata...)...)
	// Encoding as uint64 as it's encoded identically to int64.
	data = append(data, UintToBuf(uint64(de.DiamondLevel))...)

	return data
}

func (de *DiamondEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	senderPKID := &PKID{}
	if exist, err := DecodeFromBytes(senderPKID, rr); exist && err == nil {
		de.SenderPKID = senderPKID
	} else if err != nil {
		return errors.Wrapf(err, "DiamondEntry.Decode: Problem reading SenderPKID")
	}

	// ReceiverPKID
	receiverPKID := &PKID{}
	if exist, err := DecodeFromBytes(receiverPKID, rr); exist && err == nil {
		de.ReceiverPKID = receiverPKID
	} else if err != nil {
		return errors.Wrapf(err, "DiamondEntry.Decode: Problem reading ReceiverPKID")
	}

	diamondPostHash := &BlockHash{}
	if exist, err := DecodeFromBytes(diamondPostHash, rr); exist && err == nil {
		de.DiamondPostHash = diamondPostHash
	} else if err != nil {
		return errors.Wrapf(err, "DiamondEntry.Decode: Problem reading DiamondPostHash")
	}

	diamondLevel, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DiamondEntry.Decode: Problem reading DiamondLevel")
	}
	de.DiamondLevel = int64(diamondLevel)

	return nil
}

func (de *DiamondEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (de *DiamondEntry) GetEncoderType() EncoderType {
	return EncoderTypeDiamondEntry
}

func MakeRepostKey(userPk []byte, RepostedPostHash BlockHash) RepostKey {
	return RepostKey{
		ReposterPubKey:   MakePkMapKey(userPk),
		RepostedPostHash: RepostedPostHash,
	}
}

type RepostKey struct {
	ReposterPubKey PkMapKey
	// Post Hash of post that was reposted
	RepostedPostHash BlockHash
}

// RepostEntry stores the content of a Repost transaction.
type RepostEntry struct {
	ReposterPubKey []byte

	// BlockHash of the repost
	RepostPostHash *BlockHash

	// Post Hash of post that was reposted
	RepostedPostHash *BlockHash

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (re *RepostEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray(re.ReposterPubKey)...)
	data = append(data, EncodeToBytes(blockHeight, re.RepostPostHash, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, re.RepostedPostHash, skipMetadata...)...)

	return data
}

func (re *RepostEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	re.ReposterPubKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "RepostEntry.Decode: Problem reading ReposterPubKey")
	}

	repostPostHash := &BlockHash{}
	if exist, err := DecodeFromBytes(repostPostHash, rr); exist && err == nil {
		re.RepostPostHash = repostPostHash
	} else if err != nil {
		return errors.Wrapf(err, "RepostEntry.Decode: Problem reading RepostPostHash")
	}

	repostedPostHash := &BlockHash{}
	if exist, err := DecodeFromBytes(repostedPostHash, rr); exist && err == nil {
		re.RepostedPostHash = repostedPostHash
	} else if err != nil {
		return errors.Wrapf(err, "RepostEntry.Decode: Problem reading RepostedPostHash")
	}

	return nil
}

func (re *RepostEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (re *RepostEntry) GetEncoderType() EncoderType {
	return EncoderTypeRepostEntry
}

type GlobalParamsEntry struct {
	// The new exchange rate to set.
	USDCentsPerBitcoin uint64

	// The new create profile fee
	CreateProfileFeeNanos uint64

	// The fee to create a single NFT (NFTs with n copies incur n of these fees).
	CreateNFTFeeNanos uint64

	// The maximum number of NFT copies that are allowed to be minted.
	MaxCopiesPerNFT uint64

	// MinimumNetworkFeeNanosPerKB is the minimal fee rate in DeSo nanos per KB a transaction can have.
	// If a transaction has a lower fee than MinimumNetworkFeeNanosPerKB, it will be
	// rejected by the node's mempool.
	MinimumNetworkFeeNanosPerKB uint64

	// MaxNonceExpirationBlockHeightOffset is maximum value nodes will
	// tolerate for the difference between the current block height
	// and the expiration block height specified in the nonce for a
	// transaction.
	MaxNonceExpirationBlockHeightOffset uint64

	// StakeLockupEpochDuration is the number of epochs that a
	// user must wait before unlocking their unstaked stake.
	StakeLockupEpochDuration uint64

	// ValidatorJailEpochDuration is the number of epochs that a validator must
	// wait after being jailed before submitting an UnjailValidator txn.
	ValidatorJailEpochDuration uint64

	// LeaderScheduleMaxNumValidators is the maximum number of validators that
	// are included when generating a new Proof-of-Stake leader schedule.
	LeaderScheduleMaxNumValidators uint64

	// ValidatorSetMaxNumValidators is the maximum number of validators that
	// are included in the active validator set every epoch in the Proof-of-Stake
	// consensus.
	ValidatorSetMaxNumValidators uint64

	// StakingRewardsMaxNumStakes is the maximum number of stake entries that are
	// eligible to receive block rewards every epoch in the Proof-of-Stake
	// consensus.
	StakingRewardsMaxNumStakes uint64

	// StakingRewardsAPYBasisPoints determines the annual interest rate that stakers
	// receive on their stake in the Proof-of-Stake consensus. Stake rewards are paid
	// out at the end of every epoch based on the APY. The APY is configured as basis
	// points. Example:
	// - An APY of 5% corresponds to a value of 0.05 * 10000 = 500 basis points
	StakingRewardsAPYBasisPoints uint64

	// EpochDurationNumBlocks is the number of blocks included in one epoch.
	EpochDurationNumBlocks uint64

	// JailInactiveValidatorGracePeriodEpochs is the number of epochs we
	// allow a validator to be inactive for (neither voting nor proposing
	// blocks) before they are jailed.
	JailInactiveValidatorGracePeriodEpochs uint64

	// MaximumVestedIntersectionsPerLockupTransaction is used to limit the computational complexity of
	// vested lockup transactions. Essentially, vested lockups may overlap in time creating either
	// significant complexity on the lockup transaction or the unlock transaction. As a simple example,
	// consider a user having the following five vested lockups:
	//
	//		January 1st 2024 -> January 1st 2025; Amount: 1 DESO
	//		February 1st 2024 -> February 1st 2025; Amount: 1 DESO
	//		March 1st 2024 -> March 1st 2025; Amount: 1 DESO
	//		April 1st 2024 -> April 1st 2025; Amount: 1 DESO
	//		May 1st 2024 -> May 1st 2025; Amount: 1 DESO
	//
	// Notice that between May 1st 2024 and January 1st 2025 anytime the user wants to perform an unlock
	// on these vested locked balance entries they must read five distinct entries, update them,
	// possible consolidate them with other existing entries in the db, and write them back to disk. Worse,
	// this would happen on the unlock transaction which can be triggered every time. To get around this issue,
	// we consolidate these transactions on the lockup instead. For example, what SHOULD be stored in the database
	// for these five vested lockups is:
	//
	//		January 1st 2024 -> February 1st 2024; Amount: 1 DESO
	//		February 1st 2024 -> March 1st 2024; Amount: 2 DESO
	//		March 1st 2024 -> April 1st 2024; Amount: 3 DESO
	//		April 1st 2024 -> May 1st 2024; Amount: 4 DESO
	//		May 1st 2024 -> January 1st 2025; Amount: 5 DESO
	//		January 1st 2025 -> February 1st 2025; Amount: 4 DESO
	//		February 1st 2025 -> March 1st 2025; Amount: 3 DESO
	//		March 1st 2025 -> April 1st 2025; Amount: 2 DESO
	//		April 1st 2025 -> May 1st 2025; Amount: 1 DESO
	//
	// Notice that this is functionally identical but at any given point in time we hit exactly one vested
	// locked balance entry. This consolidation on the lockup transaction operation could be computationally expensive.
	// Hence, we limit this complexity with the MaximumVestedIntersectionsPerLockupTransactions (default: 1000).
	// When connecting a lockup transaction we check to see how many existing vested locked balance entries
	// we would intersect with. If we exceed the MaximumVestedIntersectionsPerLockupTransaction, we reject
	// the transaction. A user must split their single transaction into multiple disjoint time intervals which
	// satisfies the limit.
	MaximumVestedIntersectionsPerLockupTransaction int

	// FeeBucketGrowthRateBasisPoints is the rate of growth of the fee bucket ranges. This is part of the new
	// PoS Mempool. The multiplier is given as basis points. For example a value of 1000 means that the fee bucket
	// ranges will grow by 10% each time. If, let's say, we start with MinimumNetworkFeeNanosPerKB of 1000 nanos,
	// then the first bucket will be [1000, 1099], the second bucket will be [1100, 1209], the third bucket will
	// be [1210, 1330], etc.
	FeeBucketGrowthRateBasisPoints uint64

	// FailingTransactionBMFMultiplierBasisPoints is the factor of the transaction fee that is used for the computation
	// BMF. The value is expressed in basis points. For example a value of 2500 means that 25% of the fee will be
	// failing transaction fee will be used in the BMF algorithm.
	FailingTransactionBMFMultiplierBasisPoints uint64

	// BlockTimestampDriftNanoSecs is the maximum number of nanoseconds from the current timestamp that
	// we will allow a PoS block to be submitted.
	BlockTimestampDriftNanoSecs int64

	// MempoolMaxSizeBytes is the maximum size of the mempool in bytes.
	MempoolMaxSizeBytes uint64

	// MempoolFeeEstimatorNumMempoolBlocks is the number of possible future blocks to a txn may be placed
	// into when consider when estimating the fee for a new txn.
	MempoolFeeEstimatorNumMempoolBlocks uint64

	// MempoolFeeEstimatorNumPastBlocks is the number of past blocks to reference txn fees from when estimating
	// the fee for a new txn.
	MempoolFeeEstimatorNumPastBlocks uint64
}

func (gp *GlobalParamsEntry) Copy() *GlobalParamsEntry {
	return &GlobalParamsEntry{
		USDCentsPerBitcoin:                             gp.USDCentsPerBitcoin,
		CreateProfileFeeNanos:                          gp.CreateProfileFeeNanos,
		CreateNFTFeeNanos:                              gp.CreateNFTFeeNanos,
		MaxCopiesPerNFT:                                gp.MaxCopiesPerNFT,
		MinimumNetworkFeeNanosPerKB:                    gp.MinimumNetworkFeeNanosPerKB,
		MaxNonceExpirationBlockHeightOffset:            gp.MaxNonceExpirationBlockHeightOffset,
		StakeLockupEpochDuration:                       gp.StakeLockupEpochDuration,
		ValidatorJailEpochDuration:                     gp.ValidatorJailEpochDuration,
		LeaderScheduleMaxNumValidators:                 gp.LeaderScheduleMaxNumValidators,
		ValidatorSetMaxNumValidators:                   gp.ValidatorSetMaxNumValidators,
		StakingRewardsMaxNumStakes:                     gp.StakingRewardsMaxNumStakes,
		StakingRewardsAPYBasisPoints:                   gp.StakingRewardsAPYBasisPoints,
		EpochDurationNumBlocks:                         gp.EpochDurationNumBlocks,
		JailInactiveValidatorGracePeriodEpochs:         gp.JailInactiveValidatorGracePeriodEpochs,
		MaximumVestedIntersectionsPerLockupTransaction: gp.MaximumVestedIntersectionsPerLockupTransaction,
		FeeBucketGrowthRateBasisPoints:                 gp.FeeBucketGrowthRateBasisPoints,
		FailingTransactionBMFMultiplierBasisPoints:     gp.FailingTransactionBMFMultiplierBasisPoints,
		BlockTimestampDriftNanoSecs:                    gp.BlockTimestampDriftNanoSecs,
		MempoolMaxSizeBytes:                            gp.MempoolMaxSizeBytes,
		MempoolFeeEstimatorNumMempoolBlocks:            gp.MempoolFeeEstimatorNumMempoolBlocks,
		MempoolFeeEstimatorNumPastBlocks:               gp.MempoolFeeEstimatorNumPastBlocks,
	}
}

func (gp *GlobalParamsEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, UintToBuf(gp.USDCentsPerBitcoin)...)
	data = append(data, UintToBuf(gp.CreateProfileFeeNanos)...)
	data = append(data, UintToBuf(gp.CreateNFTFeeNanos)...)
	data = append(data, UintToBuf(gp.MaxCopiesPerNFT)...)
	data = append(data, UintToBuf(gp.MinimumNetworkFeeNanosPerKB)...)
	if MigrationTriggered(blockHeight, BalanceModelMigration) {
		data = append(data, UintToBuf(gp.MaxNonceExpirationBlockHeightOffset)...)
	}
	if MigrationTriggered(blockHeight, ProofOfStake1StateSetupMigration) {
		data = append(data, UintToBuf(gp.StakeLockupEpochDuration)...)
		data = append(data, UintToBuf(gp.ValidatorJailEpochDuration)...)
		data = append(data, UintToBuf(gp.LeaderScheduleMaxNumValidators)...)
		data = append(data, UintToBuf(gp.ValidatorSetMaxNumValidators)...)
		data = append(data, UintToBuf(gp.StakingRewardsMaxNumStakes)...)
		data = append(data, UintToBuf(gp.StakingRewardsAPYBasisPoints)...)
		data = append(data, UintToBuf(gp.EpochDurationNumBlocks)...)
		data = append(data, UintToBuf(gp.JailInactiveValidatorGracePeriodEpochs)...)
		data = append(data, IntToBuf(int64(gp.MaximumVestedIntersectionsPerLockupTransaction))...)
		data = append(data, UintToBuf(gp.FeeBucketGrowthRateBasisPoints)...)
		data = append(data, UintToBuf(gp.FailingTransactionBMFMultiplierBasisPoints)...)
		data = append(data, IntToBuf(gp.BlockTimestampDriftNanoSecs)...)
		data = append(data, UintToBuf(gp.MempoolMaxSizeBytes)...)
		data = append(data, UintToBuf(gp.MempoolFeeEstimatorNumMempoolBlocks)...)
		data = append(data, UintToBuf(gp.MempoolFeeEstimatorNumPastBlocks)...)
	}
	return data
}

func (gp *GlobalParamsEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	gp.USDCentsPerBitcoin, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading USDCentsPerBitcoin")
	}
	gp.CreateProfileFeeNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading CreateProfileFeeNanos")
	}
	gp.CreateNFTFeeNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading CreateNFTFeeNanos")
	}
	gp.MaxCopiesPerNFT, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading MaxCopiesPerNFT")
	}
	gp.MinimumNetworkFeeNanosPerKB, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading MinimumNetworkFeeNanosPerKB")
	}
	if MigrationTriggered(blockHeight, BalanceModelMigration) {
		gp.MaxNonceExpirationBlockHeightOffset, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading MaxNonceExpirationBlockHeightOffset")
		}
	}
	if MigrationTriggered(blockHeight, ProofOfStake1StateSetupMigration) {
		gp.StakeLockupEpochDuration, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading StakeLockupEpochDuration: ")
		}
		gp.ValidatorJailEpochDuration, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading ValidatorJailEpochDuration: ")
		}
		gp.LeaderScheduleMaxNumValidators, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading LeaderScheduleMaxNumValidators: ")
		}
		gp.ValidatorSetMaxNumValidators, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading ValidatorSetMaxNumValidators: ")
		}
		gp.StakingRewardsMaxNumStakes, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading StakingRewardsMaxNumStakes: ")
		}
		gp.StakingRewardsAPYBasisPoints, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading StakingRewardsAPYBasisPoints: ")
		}
		gp.EpochDurationNumBlocks, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading EpochDurationNumBlocks: ")
		}
		gp.JailInactiveValidatorGracePeriodEpochs, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading JailInactiveValidatorGracePeriodEpochs: ")
		}
		maximumVestedIntersectionsPerLockupTransaction, err := ReadVarint(rr)
		if err != nil {
			return errors.Wrapf(err,
				"GlobalParamsEntry.Decode: Problem reading MaximumVestedIntersectionsPerLockupTransaction")
		}
		gp.MaximumVestedIntersectionsPerLockupTransaction = int(maximumVestedIntersectionsPerLockupTransaction)
		gp.FeeBucketGrowthRateBasisPoints, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading FeeBucketGrowthRateBasisPoints")
		}
		gp.FailingTransactionBMFMultiplierBasisPoints, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading FailingTransactionBMFMultiplierBasisPoints")
		}
		gp.BlockTimestampDriftNanoSecs, err = ReadVarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading BlockTimestampDriftNanoSecs")
		}
		gp.MempoolMaxSizeBytes, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading MempoolMaxSizeBytes")
		}
		gp.MempoolFeeEstimatorNumMempoolBlocks, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading MempoolFeeEstimatorNumMempoolBlocks")
		}
		gp.MempoolFeeEstimatorNumPastBlocks, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "GlobalParamsEntry.Decode: Problem reading MempoolFeeEstimatorNumPastBlocks")
		}
	}
	return nil
}

func (gp *GlobalParamsEntry) GetVersionByte(blockHeight uint64) byte {
	return GetMigrationVersion(blockHeight, BalanceModelMigration, ProofOfStake1StateSetupMigration)
}

func (gp *GlobalParamsEntry) GetEncoderType() EncoderType {
	return EncoderTypeGlobalParamsEntry
}

// ComputeFeeTimeBucketMinimumFeeAndMultiplier takes the MinimumNetworkFeeNanosPerKB and FeeBucketGrowthRateBasisPoints for
// the GlobalParamsEntry, and returns them as big.Floats.
func (gp *GlobalParamsEntry) ComputeFeeTimeBucketMinimumFeeAndMultiplier() (
	_minimumRate *big.Float, _bucketMultiplier *big.Float) {

	minimumNetworkFeeNanosPerKB := NewFloat().SetUint64(gp.MinimumNetworkFeeNanosPerKB)
	feeBucketMultiplier := NewFloat().SetUint64(10000 + gp.FeeBucketGrowthRateBasisPoints)
	feeBucketMultiplier.Quo(feeBucketMultiplier, NewFloat().SetUint64(10000))
	return minimumNetworkFeeNanosPerKB, feeBucketMultiplier
}

// This struct holds info on a readers interactions (e.g. likes) with a post.
// It is added to a post entry response in the frontend server api.
type PostEntryReaderState struct {
	// This is true if the reader has liked the associated post.
	LikedByReader bool

	// The number of diamonds that the reader has given this post.
	DiamondLevelBestowed int64

	// This is true if the reader has reposted the associated post.
	RepostedByReader bool

	// This is the post hash hex of the repost
	RepostPostHashHex string
}

type PostEntry struct {
	// The hash of this post entry. Used as the ID for the entry.
	PostHash *BlockHash

	// The public key of the user who made the post.
	PosterPublicKey []byte

	// The parent post. This is used for comments.
	ParentStakeID []byte

	// The body of this post.
	Body []byte

	// The PostHash of the post this post reposts
	RepostedPostHash *BlockHash

	// Indicator if this PostEntry is a quoted repost or not
	IsQuotedRepost bool

	// The amount the creator of the post gets when someone stakes
	// to the post.
	CreatorBasisPoints uint64

	// The multiple of the payout when a user stakes to a post.
	// 2x multiple = 200% = 20,000bps
	StakeMultipleBasisPoints uint64

	// The block height when the post was confirmed.
	ConfirmationBlockHeight uint32

	// A timestamp used for ordering messages when displaying them to
	// users. The timestamp must be unique. Note that we use a nanosecond
	// timestamp because it makes it easier to deal with the uniqueness
	// constraint technically (e.g. If one second spacing is required
	// as would be the case with a standard Unix timestamp then any code
	// that generates these transactions will need to potentially wait
	// or else risk a timestamp collision. This complexity is avoided
	// by just using a nanosecond timestamp). Note that the timestamp is
	// an unsigned int as opposed to a signed int, which means times
	// before the zero time are not represented which doesn't matter
	// for our purposes. Restricting the timestamp in this way makes
	// lexicographic sorting based on bytes easier in our database which
	// is one of the reasons we do it.
	TimestampNanos uint64

	// Users can "delete" posts, but right now we just implement this as
	// setting a flag on the post to hide it rather than actually deleting
	// it. This simplifies the implementation and makes it easier to "undelete"
	// posts in certain situations.
	IsHidden bool

	// Counter of users that have liked this post.
	LikeCount uint64

	// Counter of users that have reposted this post.
	RepostCount uint64

	// Counter of quote reposts for this post.
	QuoteRepostCount uint64

	// Counter of diamonds that the post has received.
	DiamondCount uint64

	// The private fields below aren't serialized or hashed. They are only kept
	// around for in-memory bookkeeping purposes.

	// Whether or not this entry is deleted in the view.
	isDeleted bool

	// How many comments this post has
	CommentCount uint64

	// Indicator if a post is pinned or not.
	IsPinned bool

	// NFT info.
	IsNFT                          bool
	NumNFTCopies                   uint64
	NumNFTCopiesForSale            uint64
	NumNFTCopiesBurned             uint64
	HasUnlockable                  bool
	NFTRoyaltyToCreatorBasisPoints uint64
	NFTRoyaltyToCoinBasisPoints    uint64

	// AdditionalNFTRoyaltiesToCreatorsBasisPoints is a map where keys are PKIDs and values are uint64s representing
	// basis points. The user with the PKID specified should receive the basis points specified by the value as a
	// royalty anytime this NFT is sold. This map must not contain the post creator.
	AdditionalNFTRoyaltiesToCreatorsBasisPoints map[PKID]uint64
	// AdditionalNFTRoyaltiesToCoinsBasisPoints is a map where keys are PKIDs and values are uint64s representing
	// basis points. The user with the PKID specified should have the basis points specified as by the value added to
	// the DESO locked in their profile anytime this NFT is sold. This map must not contain the post creator.
	AdditionalNFTRoyaltiesToCoinsBasisPoints map[PKID]uint64

	// ExtraData map to hold arbitrary attributes of a post. Holds non-consensus related information about a post.
	// TODO: Change to just ExtraData. Will be easy to do once we have hypersync
	// encoders/decoders, but for now doing so would mess up GOB encoding so we'll
	// wait.
	PostExtraData map[string][]byte

	// If a PostEntry is frozen then it can no longer be updated.
	// That includes unfreezing the post.
	IsFrozen bool
}

func (pe *PostEntry) IsDeleted() bool {
	return pe.isDeleted
}

func IsQuotedRepost(postEntry *PostEntry) bool {
	return postEntry.IsQuotedRepost && postEntry.RepostedPostHash != nil
}

func (pe *PostEntry) HasMedia() bool {
	bodyJSONObj := DeSoBodySchema{}
	err := json.Unmarshal(pe.Body, &bodyJSONObj)
	//Return true if body json can be parsed and ImageURLs or VideoURLs is not nil/non-empty or EmbedVideoUrl is not nil/non-empty
	if (err == nil && len(bodyJSONObj.ImageURLs) > 0 || len(bodyJSONObj.VideoURLs) > 0) || len(pe.PostExtraData["EmbedVideoURL"]) > 0 {
		return true
	}
	return false
}

// Return true if postEntry is a vanilla repost.  A vanilla repost is a post that reposts another post,
// but does not have a body.
func IsVanillaRepost(postEntry *PostEntry) bool {
	return !postEntry.IsQuotedRepost && postEntry.RepostedPostHash != nil
}

func (pe *PostEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeToBytes(blockHeight, pe.PostHash, skipMetadata...)...)
	data = append(data, EncodeByteArray(pe.PosterPublicKey)...)
	data = append(data, EncodeByteArray(pe.ParentStakeID)...)
	data = append(data, EncodeByteArray(pe.Body)...)
	data = append(data, EncodeToBytes(blockHeight, pe.RepostedPostHash, skipMetadata...)...)
	data = append(data, BoolToByte(pe.IsQuotedRepost))
	data = append(data, UintToBuf(pe.CreatorBasisPoints)...)
	data = append(data, UintToBuf(pe.StakeMultipleBasisPoints)...)
	data = append(data, UintToBuf(uint64(pe.ConfirmationBlockHeight))...)
	data = append(data, UintToBuf(pe.TimestampNanos)...)
	data = append(data, BoolToByte(pe.IsHidden))
	data = append(data, UintToBuf(pe.LikeCount)...)
	data = append(data, UintToBuf(pe.RepostCount)...)
	data = append(data, UintToBuf(pe.QuoteRepostCount)...)
	data = append(data, UintToBuf(pe.DiamondCount)...)
	data = append(data, UintToBuf(pe.CommentCount)...)
	data = append(data, BoolToByte(pe.IsPinned))
	data = append(data, BoolToByte(pe.IsNFT))
	data = append(data, UintToBuf(pe.NumNFTCopies)...)
	data = append(data, UintToBuf(pe.NumNFTCopiesForSale)...)
	data = append(data, UintToBuf(pe.NumNFTCopiesBurned)...)
	data = append(data, BoolToByte(pe.HasUnlockable))
	data = append(data, UintToBuf(pe.NFTRoyaltyToCreatorBasisPoints)...)
	data = append(data, UintToBuf(pe.NFTRoyaltyToCoinBasisPoints)...)
	data = append(data, EncodePKIDuint64Map(pe.AdditionalNFTRoyaltiesToCreatorsBasisPoints)...)
	data = append(data, EncodePKIDuint64Map(pe.AdditionalNFTRoyaltiesToCoinsBasisPoints)...)
	data = append(data, EncodeExtraData(pe.PostExtraData)...)

	if MigrationTriggered(blockHeight, AssociationsAndAccessGroupsMigration) {
		data = append(data, BoolToByte(pe.IsFrozen))
	}

	return data
}

func (pe *PostEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	postHash := &BlockHash{}
	if exist, err := DecodeFromBytes(postHash, rr); exist && err == nil {
		pe.PostHash = postHash
	} else if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading PostHash")
	}
	pe.PosterPublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading PosterPublicKey")
	}
	pe.ParentStakeID, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading ParentStakeID")
	}
	pe.Body, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading Body")
	}

	repostedPostHash := &BlockHash{}
	if exist, err := DecodeFromBytes(repostedPostHash, rr); exist && err == nil {
		pe.RepostedPostHash = repostedPostHash
	} else if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading RepostedPostHash")
	}

	pe.IsQuotedRepost, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading IsQuotedRepost")
	}
	pe.CreatorBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading CreatorBasisPoints")
	}
	pe.StakeMultipleBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading StakeMultipleBasisPoints")
	}

	confirmationBlockHeight, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading ConfirmationBlockHeight")
	}
	pe.ConfirmationBlockHeight = uint32(confirmationBlockHeight)

	pe.TimestampNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading TimestampNanos")
	}
	pe.IsHidden, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading IsHidden")
	}
	pe.LikeCount, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading LikeCount")
	}
	pe.RepostCount, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading RepostCount")
	}
	pe.QuoteRepostCount, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading QuoteRepostCount")
	}
	pe.DiamondCount, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading DiamondCount")
	}
	pe.CommentCount, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading CommentCount")
	}
	pe.IsPinned, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading IsPinned")
	}
	pe.IsNFT, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading IsNFT")
	}
	pe.NumNFTCopies, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading NumNFTCopies")
	}
	pe.NumNFTCopiesForSale, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading NumNFTCopiesForSale")
	}
	pe.NumNFTCopiesBurned, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading NumNFTCopiesBurned")
	}
	pe.HasUnlockable, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading HasUnlockable")
	}
	pe.NFTRoyaltyToCreatorBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading NFTRoyaltyToCreatorBasisPoints")
	}
	pe.NFTRoyaltyToCoinBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading NFTRoyaltyToCoinBasisPoints")
	}
	pe.AdditionalNFTRoyaltiesToCreatorsBasisPoints, err = DecodePKIDuint64Map(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading AdditionalNFTRoyaltiesToCreatorsBasisPoints")
	}
	pe.AdditionalNFTRoyaltiesToCoinsBasisPoints, err = DecodePKIDuint64Map(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading AdditionalNFTRoyaltiesToCoinsBasisPoints")
	}
	pe.PostExtraData, err = DecodeExtraData(rr)
	if err != nil {
		return errors.Wrapf(err, "PostEntry.Decode: Problem reading PostExtraData")
	}

	if MigrationTriggered(blockHeight, AssociationsAndAccessGroupsMigration) {
		pe.IsFrozen, err = ReadBoolByte(rr)
		if err != nil {
			return errors.Wrap(err, "PostEntry.Decode: Problem reading IsFrozen")
		}
	}

	return nil
}

func (pe *PostEntry) GetVersionByte(blockHeight uint64) byte {
	return GetMigrationVersion(blockHeight, AssociationsAndAccessGroupsMigration)
}

func (pe *PostEntry) GetEncoderType() EncoderType {
	return EncoderTypePostEntry
}

type BalanceEntryMapKey struct {
	HODLerPKID  PKID
	CreatorPKID PKID
}

func MakeBalanceEntryKey(hodlerPKID *PKID, creatorPKID *PKID) BalanceEntryMapKey {
	return BalanceEntryMapKey{
		HODLerPKID:  *hodlerPKID,
		CreatorPKID: *creatorPKID,
	}
}

func (mm BalanceEntryMapKey) String() string {
	return fmt.Sprintf("BalanceEntryMapKey: <HODLer Pub Key: %v, Creator Pub Key: %v>",
		PkToStringBoth(mm.HODLerPKID[:]), PkToStringBoth(mm.CreatorPKID[:]))
}

// This struct is mainly used to track a user's balance of a particular
// creator coin. In the database, we store it as the value in a mapping
// that looks as follows:
// <HodlerPKID, CreatorPKID> -> HODLerEntry
type BalanceEntry struct {
	// The PKID of the HODLer. This should never change after it's set initially.
	HODLerPKID *PKID
	// The PKID of the creator. This should never change after it's set initially.
	CreatorPKID *PKID

	// How much this HODLer owns of a particular creator coin.
	BalanceNanos uint256.Int

	// Has the hodler purchased any amount of this user's coin
	HasPurchased bool

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (be *BalanceEntry) IsDeleted() bool {
	return be.isDeleted
}

func (be *BalanceEntry) Copy() *BalanceEntry {
	return &BalanceEntry{
		HODLerPKID:   be.HODLerPKID.NewPKID(),
		CreatorPKID:  be.CreatorPKID.NewPKID(),
		BalanceNanos: *be.BalanceNanos.Clone(),
		HasPurchased: be.HasPurchased,
		isDeleted:    be.isDeleted,
	}
}

func (be *BalanceEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeToBytes(blockHeight, be.HODLerPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, be.CreatorPKID, skipMetadata...)...)
	data = append(data, VariableEncodeUint256(&be.BalanceNanos)...)
	data = append(data, BoolToByte(be.HasPurchased))

	return data
}

func (be *BalanceEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {

	HODLerPKID := &PKID{}
	if exist, err := DecodeFromBytes(HODLerPKID, rr); exist && err == nil {
		be.HODLerPKID = HODLerPKID
	} else if err != nil {
		return errors.Wrapf(err, "BalanceEntry.Decode: Problem decoding HODLerPKID")
	}

	creatorPKID := &PKID{}
	if exist, err := DecodeFromBytes(creatorPKID, rr); exist && err == nil {
		be.CreatorPKID = creatorPKID
	} else if err != nil {
		return errors.Wrapf(err, "BalanceEntry.Decode: Problem decoding CreatorPKID")
	}

	balanceNanos, err := VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "BalanceEntry.Decode: Problem reading BalanceNanos")
	}
	be.BalanceNanos = *balanceNanos
	be.HasPurchased, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "BalanceEntry.Decode: Problem reading HasPurchased")
	}

	return nil
}

func (be *BalanceEntry) GetVersionByte(blockHeight uint64) byte {
	return byte(0)
}

func (be *BalanceEntry) GetEncoderType() EncoderType {
	return EncoderTypeBalanceEntry
}

type TransferRestrictionStatus uint8

const (
	TransferRestrictionStatusUnrestricted            TransferRestrictionStatus = 0
	TransferRestrictionStatusProfileOwnerOnly        TransferRestrictionStatus = 1
	TransferRestrictionStatusDAOMembersOnly          TransferRestrictionStatus = 2
	TransferRestrictionStatusPermanentlyUnrestricted TransferRestrictionStatus = 3
)

func (transferRestrictionStatus TransferRestrictionStatus) IsUnrestricted() bool {
	if transferRestrictionStatus == TransferRestrictionStatusUnrestricted ||
		transferRestrictionStatus == TransferRestrictionStatusPermanentlyUnrestricted {
		return true
	}
	return false
}

func (transferRestrictionStatus TransferRestrictionStatus) String() string {
	switch transferRestrictionStatus {
	case TransferRestrictionStatusUnrestricted:
		return "Unrestricted"
	case TransferRestrictionStatusProfileOwnerOnly:
		return "Profile Owner Only"
	case TransferRestrictionStatusDAOMembersOnly:
		return "DAO Members Only"
	case TransferRestrictionStatusPermanentlyUnrestricted:
		return "Permanently Unrestricted"
	default:
		return "INVALID TRANSFER RESTRICTION STATUS"
	}
}

// This struct contains all the information required to support coin
// buy/sell transactions on profiles.
type CoinEntry struct {
	// The amount the owner of this profile receives when there is a
	// "net new" purchase of their coin.
	CreatorBasisPoints uint64

	// The amount of DeSo backing the coin. Whenever a user buys a coin
	// from the protocol this amount increases, and whenever a user sells a
	// coin to the protocol this decreases.
	DeSoLockedNanos uint64

	// The number of public keys who have holdings in this creator coin.
	// Due to floating point truncation, it can be difficult to simultaneously
	// reset CoinsInCirculationNanos and DeSoLockedNanos to zero after
	// everyone has sold all their creator coins. Initially NumberOfHolders
	// is set to zero. Once it returns to zero after a series of buys & sells
	// we reset the DeSoLockedNanos and CoinsInCirculationNanos to prevent
	// abnormal bancor curve behavior.
	NumberOfHolders uint64

	// The number of coins currently in circulation. Whenever a user buys a
	// coin from the protocol this increases, and whenever a user sells a
	// coin to the protocol this decreases.
	//
	// It's OK to have a pointer here as long as we *NEVER* manipulate the
	// bigint in place. Instead, we must always do computations of the form:
	//
	// CoinsInCirculationNanos = uint256.NewInt(0).Add(CoinsInCirculationNanos, <other uint256>)
	//
	// This will guarantee that modifying a copy of this struct will not break
	// the original, which is needed for disconnects to work.
	CoinsInCirculationNanos uint256.Int

	// This field keeps track of the highest number of coins that has ever
	// been in circulation. It is used to determine when a creator should
	// receive a "founder reward." In particular, whenever the number of
	// coins being minted would push the number of coins in circulation
	// beyond the watermark, we allocate a percentage of the coins being
	// minted to the creator as a "founder reward."
	//
	// Note that this field doesn't need to be uint256 because it's only
	// relevant for CreatorCoins, which can't exceed math.MaxUint64 in total
	// supply.
	CoinWatermarkNanos uint64

	// If true, DAO coins can no longer be minted.
	MintingDisabled bool

	TransferRestrictionStatus TransferRestrictionStatus

	// ===== ENCODER MIGRATION ProofOfStake1StateSetupMigration =====
	// LockupTransferRestrictionStatus specifies transfer restrictions
	// for only those DAO coins actively locked up.
	LockupTransferRestrictionStatus TransferRestrictionStatus
}

func (ce *CoinEntry) Copy() *CoinEntry {
	return &CoinEntry{
		CreatorBasisPoints:              ce.CreatorBasisPoints,
		DeSoLockedNanos:                 ce.DeSoLockedNanos,
		NumberOfHolders:                 ce.NumberOfHolders,
		CoinsInCirculationNanos:         *uint256.NewInt().Set(&ce.CoinsInCirculationNanos),
		CoinWatermarkNanos:              ce.CoinWatermarkNanos,
		MintingDisabled:                 ce.MintingDisabled,
		TransferRestrictionStatus:       ce.TransferRestrictionStatus,
		LockupTransferRestrictionStatus: ce.LockupTransferRestrictionStatus,
	}
}

func (ce *CoinEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	// CoinEntry
	data = append(data, UintToBuf(ce.CreatorBasisPoints)...)
	data = append(data, UintToBuf(ce.DeSoLockedNanos)...)
	data = append(data, UintToBuf(ce.NumberOfHolders)...)
	data = append(data, VariableEncodeUint256(&ce.CoinsInCirculationNanos)...)
	data = append(data, UintToBuf(ce.CoinWatermarkNanos)...)
	data = append(data, BoolToByte(ce.MintingDisabled))
	data = append(data, byte(ce.TransferRestrictionStatus))

	if MigrationTriggered(blockHeight, ProofOfStake1StateSetupMigration) {
		data = append(data, byte(ce.LockupTransferRestrictionStatus))
	}

	return data
}

func (ce *CoinEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// CoinEntry
	ce.CreatorBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinEntry.Decode: Problem reading CreatorBasisPoints")
	}
	ce.DeSoLockedNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinEntry.Decode: Problem reading DeSoLockedNanos")
	}
	ce.NumberOfHolders, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinEntry.Decode: Problem reading NumberOfHolders")
	}
	coinsInCirculationNanos, err := VariableDecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinEntry.Decode: Problem reading NumberOfHolders")
	}
	ce.CoinsInCirculationNanos = *coinsInCirculationNanos

	ce.CoinWatermarkNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinEntry.Decode: Problem reading CoinWatermarkNanos")
	}

	ce.MintingDisabled, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "CoinEntry.Decode: Problem reading MintingDisabled")
	}

	statusByte, err := rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "CoinEntry.Decode: Problem reading TransferRestrictionStatus")
	}
	ce.TransferRestrictionStatus = TransferRestrictionStatus(statusByte)

	if MigrationTriggered(blockHeight, ProofOfStake1StateSetupMigration) {
		lockedStatusByte, err := rr.ReadByte()
		if err != nil {
			return errors.Wrapf(err, "CoinEntry.Decode: Problem reading LockupTransferRestrictionStatus")
		}
		ce.LockupTransferRestrictionStatus = TransferRestrictionStatus(lockedStatusByte)
	}

	return nil
}

func (ce *CoinEntry) GetVersionByte(blockHeight uint64) byte {
	return GetMigrationVersion(
		blockHeight,
		ProofOfStake1StateSetupMigration,
	)
}

func (ce *CoinEntry) GetEncoderType() EncoderType {
	return EncoderTypeCoinEntry
}

type PublicKeyRoyaltyPair struct {
	PublicKey          []byte
	RoyaltyAmountNanos uint64
}

func (pair *PublicKeyRoyaltyPair) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray(pair.PublicKey)...)
	data = append(data, UintToBuf(pair.RoyaltyAmountNanos)...)
	return data
}

func (pair *PublicKeyRoyaltyPair) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	pair.PublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "PublicKeyRoyaltyPair.Decode: problem decoding public key")
	}

	pair.RoyaltyAmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PublicKeyRoyaltyPair.Decode: problem decoding royalty amount")
	}
	return nil
}

func (pair *PublicKeyRoyaltyPair) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (pair *PublicKeyRoyaltyPair) GetEncoderType() EncoderType {
	return EncoderTypePublicKeyRoyaltyPair
}

type PKIDEntry struct {
	PKID *PKID
	// We add the public key only so we can reuse this struct to store the reverse
	// mapping of pkid -> public key.
	PublicKey []byte

	isDeleted bool
}

func (pkid *PKIDEntry) String() string {
	return fmt.Sprintf("< PKID: %s, OwnerPublicKey: %s >", PkToStringMainnet(pkid.PKID[:]), PkToStringMainnet(pkid.PublicKey))
}

func (pkid *PKIDEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeToBytes(blockHeight, pkid.PKID, skipMetadata...)...)
	data = append(data, EncodeByteArray(pkid.PublicKey)...)

	return data
}

func (pkid *PKIDEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	pkidCopy := &PKID{}
	if exist, err := DecodeFromBytes(pkidCopy, rr); exist && err == nil {
		pkid.PKID = pkidCopy
	} else if err != nil {
		return errors.Wrapf(err, "PKIDEntry.Decode: Problem decoding PKID")
	}

	pkid.PublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "PKIDEntry.Decode: Problem reading Public Key")
	}

	return nil
}

func (pkid *PKIDEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (pkid *PKIDEntry) GetEncoderType() EncoderType {
	return EncoderTypePKIDEntry
}

type ProfileEntry struct {
	// PublicKey is the key used by the user to sign for things and generally
	// verify her identity.
	PublicKey []byte

	// Username is a unique human-readable identifier associated with a profile.
	Username []byte

	// Some text describing the profile.
	Description []byte

	// The profile pic string encoded as a link e.g.
	// data:image/png;base64,<data in base64>
	ProfilePic []byte

	// Users can "delete" profiles, but right now we just implement this as
	// setting a flag on the post to hide it rather than actually deleting
	// it. This simplifies the implementation and makes it easier to "undelete"
	// profiles in certain situations.
	IsHidden bool

	// CreatorCoinEntry tracks the information required to buy/sell creator coins on a user's
	// profile. We "embed" it here for convenience so we can access the fields
	// directly on the ProfileEntry object. Embedding also makes it so that we
	// don't need to initialize it explicitly.
	CreatorCoinEntry CoinEntry

	// DAOCoinEntry tracks the information around the DAO coins issued on a user's profile.
	// Note: the following fields are basically ignored for the DAOCoinEntry
	// 1. CreatorBasisPoints
	// 2. DeSoLockedNanos
	// 3. CoinWaterMarkNanos
	DAOCoinEntry CoinEntry

	// ExtraData map to hold arbitrary attributes of a profile. Holds
	// non-consensus related information about a profile.
	ExtraData map[string][]byte

	// Whether or not this entry should be deleted when the view is flushed
	// to the db. This is initially set to false, but can become true if for
	// example we update a user entry and need to delete the data associated
	// with the old entry.
	isDeleted bool
}

func (pe *ProfileEntry) IsDeleted() bool {
	return pe.isDeleted
}

func (pe *ProfileEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray(pe.PublicKey)...)
	data = append(data, EncodeByteArray(pe.Username)...)
	data = append(data, EncodeByteArray(pe.Description)...)
	data = append(data, EncodeByteArray(pe.ProfilePic)...)
	data = append(data, BoolToByte(pe.IsHidden))

	// CoinEntry
	data = append(data, EncodeToBytes(blockHeight, &pe.CreatorCoinEntry, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, &pe.DAOCoinEntry, skipMetadata...)...)

	data = append(data, EncodeExtraData(pe.ExtraData)...)

	return data
}

func (pe *ProfileEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	pe.PublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "ProfileEntry.Decode: Problem reading PublicKey")
	}
	pe.Username, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "ProfileEntry.Decode: Problem reading Username")
	}
	pe.Description, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "ProfileEntry.Decode: Problem reading Description")
	}
	pe.ProfilePic, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "ProfileEntry.Decode: Problem reading ProfilePic")
	}
	pe.IsHidden, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "ProfileEntry.Decode: Problem reading IsHidden")
	}
	pe.CreatorCoinEntry = CoinEntry{}
	if exists, err := DecodeFromBytes(&pe.CreatorCoinEntry, rr); !exists || err != nil {
		return errors.Wrapf(err, "ProfileEntry.Decode: Problem reading CreatorCoinEntry")
	}

	pe.DAOCoinEntry = CoinEntry{}
	if exists, err := DecodeFromBytes(&pe.DAOCoinEntry, rr); !exists || err != nil {
		return errors.Wrapf(err, "ProfileEntry.Decode: Problem reading DAOCoinEntry")
	}

	pe.ExtraData, err = DecodeExtraData(rr)
	if err != nil && strings.Contains(err.Error(), "EOF") {
		// To preserve backwards-compatibility, we set an empty map and return if we
		// encounter an EOF error decoding ExtraData.
		glog.Warning(err, "ProfileEntry.Decode: problem decoding extra data. "+
			"Please resync your node to upgrade your datadir before the next hard fork.")
		return nil
	} else if err != nil {
		return errors.Wrapf(err, "ProfileEntry.Decode: problem decoding extra data")
	}

	return nil
}

func (pe *ProfileEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (pe *ProfileEntry) GetEncoderType() EncoderType {
	return EncoderTypeProfileEntry
}

func EncodeByteArray(bytes []byte) []byte {
	var data []byte

	data = append(data, UintToBuf(uint64(len(bytes)))...)
	data = append(data, bytes...)

	return data
}

func DecodeByteArray(reader io.Reader) ([]byte, error) {
	pkLen, err := ReadUvarint(reader)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeByteArray: Problem when ReadUvarint")
	}

	if pkLen > 0 {
		var result []byte
		result, err = SafeMakeSliceWithLength[byte](pkLen)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeByteArray: Problem creating slice")
		}

		_, err = io.ReadFull(reader, result)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeByteArray: Problem when ReadFull")
		}

		return result, nil
	} else {
		return nil, nil
	}
}

func EncodeUint64Array(uint64s []uint64) []byte {
	var data []byte

	data = append(data, UintToBuf(uint64(len(uint64s)))...)
	for _, uint64 := range uint64s {
		data = append(data, UintToBuf(uint64)...)
	}

	return data
}

func DecodeUint64Array(reader io.Reader) ([]uint64, error) {
	arrLen, err := ReadUvarint(reader)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeUint64Array: Problem reading array length")
	}

	if arrLen == 0 {
		return nil, nil
	}

	var result []uint64
	result, err = SafeMakeSliceWithLength[uint64](arrLen)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeUint64Array: Problem creating slice")
	}

	for ii := uint64(0); ii < arrLen; ii++ {
		result[ii], err = ReadUvarint(reader)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeUint64Array: Problem reading uint64")
		}
	}

	return result, nil
}

func EncodePKIDuint64Map(pkidMap map[PKID]uint64) []byte {
	var data []byte

	mapLength := uint64(len(pkidMap))
	data = append(data, UintToBuf(mapLength)...)
	if mapLength > 0 {
		// TODO: do we want to use safe make here and introduce an error?
		keys := make([][33]byte, 0, len(pkidMap))
		for pkid := range pkidMap {
			pkidBytes := [33]byte{}
			copy(pkidBytes[:], pkid[:])
			keys = append(keys, pkidBytes)
		}
		sort.SliceStable(keys, func(i, j int) bool {
			switch bytes.Compare(keys[i][:], keys[j][:]) {
			case 0:
				return true
			case -1:
				return true
			case 1:
				return false
			}
			return false
		})

		for _, key := range keys {
			pkid := NewPKID(key[:])
			data = append(data, UintToBuf(uint64(len(key)))...)
			data = append(data, key[:]...)

			data = append(data, UintToBuf(pkidMap[*pkid])...)
		}
	}
	return data
}

func DecodePKIDuint64Map(rr io.Reader) (map[PKID]uint64, error) {
	mapLength, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodePKIDuint64Map: Problem reading map length")
	}

	if mapLength > 0 {
		pkidMap, err := SafeMakeMapWithCapacity[PKID, uint64](mapLength)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodePKIDuint64Map: Problem making map for pkidMap")
		}

		for ii := uint64(0); ii < mapLength; ii++ {
			pkidLen, err := ReadUvarint(rr)
			if err != nil {
				return nil, errors.Wrapf(err, "DecodePKIDuint64Map: Problem reading pkid length at ii: (%v)", ii)
			}
			pkidBytes, err := SafeMakeSliceWithLength[byte](pkidLen)
			if err != nil {
				return nil, errors.Wrapf(err, "DecodePKIDuint64Map: Problem making slice for pkidBytes")
			}
			_, err = io.ReadFull(rr, pkidBytes)
			if err != nil {
				return nil, errors.Wrapf(err, "DecodePKIDuint64Map: Problem reading pkid bytes at ii: (%v)", ii)
			}
			pkid := NewPKID(pkidBytes)
			value, err := ReadUvarint(rr)
			if err != nil {
				return nil, errors.Wrapf(err, "DecodePKIDuint64Map: Problem reading value at ii (%v)", ii)
			}
			pkidMap[*pkid] = value
		}
		return pkidMap, nil
	}
	return nil, nil
}

// EncodeExtraData is used in consensus so don't change it
func EncodeExtraData(extraData map[string][]byte) []byte {
	var data []byte

	extraDataLength := uint64(len(extraData))
	data = append(data, UintToBuf(extraDataLength)...)
	if extraDataLength > 0 {
		// Sort the keys of the map
		// TODO: do we want to use safe make here and introduce an error?
		keys := make([]string, 0, len(extraData))
		for key := range extraData {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		// Encode the length of the key, the key itself
		// then the length of the value, then the value itself.
		for _, key := range keys {
			data = append(data, UintToBuf(uint64(len(key)))...)
			data = append(data, []byte(key)...)
			value := extraData[key]
			data = append(data, UintToBuf(uint64(len(value)))...)
			data = append(data, value...)
		}
	}

	return data
}

// DecodeExtraData is used in consensus so don't change it
func DecodeExtraData(rr io.Reader) (map[string][]byte, error) {
	extraDataLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeExtraData: Problem reading")
	}

	if extraDataLen > MaxMessagePayload {
		return nil, fmt.Errorf("DecodeExtraData: extraDataLen length %d longer than max %d", extraDataLen, MaxMessagePayload)
	}

	// Initialize an map of strings to byte slices of size extraDataLen -- extraDataLen is the number of keys.
	if extraDataLen != 0 {
		var extraData map[string][]byte
		extraData, err = SafeMakeMapWithCapacity[string, []byte](extraDataLen)
		if err != nil {
			return nil, fmt.Errorf("DecodeExtraData: Problem creating map with length %d", extraDataLen)
		}

		// Loop over each key
		for ii := uint64(0); ii < extraDataLen; ii++ {
			// De-serialize the length of the key
			var keyLen uint64
			keyLen, err = ReadUvarint(rr)
			if err != nil {
				return nil, fmt.Errorf("DecodeExtraData: Problem reading len(DeSoTxn.ExtraData.Keys[#{ii}]")
			}

			// De-serialize the key
			var keyBytes []byte
			keyBytes, err = SafeMakeSliceWithLength[byte](keyLen)
			if err != nil {
				return nil, fmt.Errorf("DecodeExtraData: Problem creating slice for key #{ii} with length #{keyLen}")
			}
			_, err = io.ReadFull(rr, keyBytes)
			if err != nil {
				return nil, fmt.Errorf("DecodeExtraData: Problem reading key #{ii}")
			}

			// Convert the key to a string and check if it already exists in the map.
			// If it already exists in the map, this is an error as a map cannot have duplicate keys.
			key := string(keyBytes)
			if _, keyExists := extraData[key]; keyExists {
				return nil, fmt.Errorf("DecodeExtraData: Key [#{ii}] ({key}) already exists in ExtraData")
			}

			// De-serialize the length of the value
			var valueLen uint64
			valueLen, err = ReadUvarint(rr)
			if err != nil {
				return nil, fmt.Errorf("DecodeExtraData: Problem reading len(DeSoTxn.ExtraData.Value[#{ii}]")
			}

			// De-serialize the value
			var value []byte
			value, err = SafeMakeSliceWithLength[byte](valueLen)
			if err != nil {
				return nil, fmt.Errorf("DecodeExtraData: Problem creating slice for value #{ii} with length #{valueLen}")
			}
			_, err = io.ReadFull(rr, value)
			if err != nil {
				return nil, fmt.Errorf("DecodeExtraData: Problem read value #{ii}")
			}

			// Map the key to the value
			extraData[key] = value
		}

		return extraData, nil
	}

	return nil, nil
}

func EncodeMapStringUint64(mapStruct map[string]uint64) []byte {
	var data []byte

	extraDataLength := uint64(len(mapStruct))
	data = append(data, UintToBuf(extraDataLength)...)
	if extraDataLength > 0 {
		// Sort the keys of the map
		keys, err := SafeMakeSliceWithLengthAndCapacity[string](0, extraDataLength)
		if err != nil {
			// TODO: do we really want to introduce an error here?
		}
		for key := range mapStruct {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		// Encode the length of the key, the key itself
		// then the length of the value, then the value itself.
		for _, key := range keys {
			data = append(data, UintToBuf(uint64(len(key)))...)
			data = append(data, []byte(key)...)
			value := mapStruct[key]
			data = append(data, UintToBuf(value)...)
		}
	}

	return data
}

func DecodeMapStringUint64(rr *bytes.Reader) (map[string]uint64, error) {
	extraDataLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeExtraData: Problem reading")
	}

	// Initialize an map of strings to byte slices of size extraDataLen -- extraDataLen is the number of keys.
	if extraDataLen != 0 {
		var extraData map[string]uint64
		extraData, err = SafeMakeMapWithCapacity[string, uint64](extraDataLen)
		if err != nil {
			return nil, fmt.Errorf("DecodeExtraData: Problem creating extra map with length #{extraDataLen}")
		}

		// Loop over each key
		for ii := uint64(0); ii < extraDataLen; ii++ {
			// De-serialize the length of the key
			var keyLen uint64
			keyLen, err = ReadUvarint(rr)
			if err != nil {
				return nil, fmt.Errorf("DecodeExtraData: Problem reading len(DeSoTxn.ExtraData.Keys[#{ii}]")
			}

			// De-serialize the key
			var keyBytes []byte
			keyBytes, err = SafeMakeSliceWithLength[byte](keyLen)
			if err != nil {
				return nil, fmt.Errorf("DecodeExtraData: Problem creating slice of length #{keyLen} for key #{ii}")
			}
			_, err = io.ReadFull(rr, keyBytes)
			if err != nil {
				return nil, fmt.Errorf("DecodeExtraData: Problem reading key #{ii}")
			}

			// Convert the key to a string and check if it already exists in the map.
			// If it already exists in the map, this is an error as a map cannot have duplicate keys.
			key := string(keyBytes)
			if _, keyExists := extraData[key]; keyExists {
				return nil, fmt.Errorf("DecodeExtraData: Key [#{ii}] ({key}) already exists in ExtraData")
			}

			// De-serialize the length of the value
			var value uint64
			value, err = ReadUvarint(rr)
			if err != nil {
				return nil, fmt.Errorf("DecodeExtraData: Problem reading value")
			}

			// Map the key to the value
			extraData[key] = value
		}

		return extraData, nil
	}

	return nil, nil
}

// VariableEncodeUint256 is useful for space-efficient encoding of uint256s.
// It does not guarantee fixed-width encoding, so should not be used
// in BadgerDB keys. Use FixedWidthEncodeUint256 instead, which does
// guarantee fixed-width encoding. Both VariableEncodeUint256 and
// FixedWidthEncodeUint256 can handle nil inputs.
func VariableEncodeUint256(number *uint256.Int) []byte {
	var data []byte
	if number != nil {
		data = append(data, BoolToByte(true))
		numberBytes := number.Bytes()
		data = append(data, EncodeByteArray(numberBytes)...)
	} else {
		data = append(data, BoolToByte(false))
	}
	return data
}

func VariableDecodeUint256(rr *bytes.Reader) (*uint256.Int, error) {
	if existenceByte, err := ReadBoolByte(rr); existenceByte && err == nil {
		maxUint256BytesLen := len(MaxUint256.Bytes())
		intLen, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeUint256: Problem reading length")
		}
		if intLen > uint64(maxUint256BytesLen) {
			return nil, fmt.Errorf("DecodeUint256: Length (%v) exceeds max (%v) length",
				intLen, maxUint256BytesLen)
		}

		numberBytes, err := SafeMakeSliceWithLength[byte](intLen)
		if err != nil {
			return nil, fmt.Errorf("DecodeUint256: Problem making slice of length %v", intLen)
		}
		_, err = io.ReadFull(rr, numberBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeUint256: Error reading uint256")
		}
		return uint256.NewInt().SetBytes(numberBytes), nil
	} else if err != nil {
		return nil, errors.Wrapf(err, "DecodeUint256: Error reading uint256")
	} else {
		return nil, nil
	}
}

// -----------------------------------
// DAO coin limit order
// -----------------------------------

type DAOCoinLimitOrderEntry struct {
	// OrderID is the txn hash (unique identifier) for this order.
	OrderID *BlockHash
	// TransactorPKID is the PKID of the user who created this order.
	TransactorPKID *PKID
	// The PKID of the coin that we're going to buy
	BuyingDAOCoinCreatorPKID *PKID
	// The PKID of the coin that we're going to sell
	SellingDAOCoinCreatorPKID *PKID
	// ScaledExchangeRateCoinsToSellPerCoinToBuy specifies how many of the coins
	// associated with SellingDAOCoinCreatorPKID we need to convert in order
	// to get one BuyingDAOCoinCreatorPKID. For example, if this value was
	// 2, then we would need to convert 2 SellingDAOCoinCreatorPKID
	// coins to get 1 BuyingDAOCoinCreatorPKID. Note, however, that to represent
	// 2, we would actually have to set ScaledExchangeRateCoinsToSellPerCoinToBuy to
	// be equal to 2*1e38 because of the representation format we describe
	// below.
	//
	// The exchange rate is represented as a fixed-point value, which works
	// as follows:
	// - Whenever we reference an exchange rate, call it Y, we pass it
	//   around as a uint256 BUT we consider it to be implicitly divided
	//   by 1e38.
	// - For example, to represent a decimal number like 123456789.987654321,
	//   call it X, we would pass around Y = X*1e38 = 1234567899876543210000000000000000000000000000
	//   as a uint256.
	//   Then, to do operations with Y, we would make sure to always divide by
	//   1e38 before returning a final quantity.
	// - We will refer to Y as "scaled." The value of ScaledExchangeRateCoinsToSellPerCoinToBuy
	//   will always be scaled, meaning it is a uint256 that we implicitly
	//   assume represents a number that is divided by 1e38.
	//
	// This scheme is also referred to as "fixed point," and a similar scheme
	// is utilized by Uniswap. You can learn more about how this works here:
	// - https://en.wikipedia.org/wiki/Q_(number_format)
	// - https://ethereum.org/de/developers/tutorials/uniswap-v2-annotated-code/#FixedPoint
	// - https://uniswap.org/whitepaper.pdf
	ScaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int
	// QuantityBaseUnits expresses how many "base units" of the coin this order is
	// buying. Note that we could have called this QuantityToBuyNanos, and in the
	// case where we're buying DESO, the base unit is a "nano." However, we call it
	// "base unit" rather than nano because other DAO coins might decide to use a
	// different scheme than nanos for their base unit. In particular, we expect 1e18
	// base units to equal 1 DAO coin, rather than using nanos.
	QuantityToFillInBaseUnits *uint256.Int
	// This is one of ASK or BID. If the operation type is an ASK, then the quantity
	// column applies to the selling coin. I.e. the order is considered fulfilled
	// once the selling coin quantity to fill is zero. If the operation type is a BID,
	// then quantity column applies to the buying coin. I.e. the order is considered
	// fulfilled once the buying coin quantity to fill is zero.
	OperationType DAOCoinLimitOrderOperationType
	// This is one of GoodTillCancelled, ImmediateOrCancel, or FillOrKill.
	// See the DAOCoinLimitOrderFillType struct for more details.
	FillType DAOCoinLimitOrderFillType
	// This is the block height at which the order was placed. We use the block height
	// to break ties between orders. If there are two orders that could be filled, we
	// pick the one that was submitted earlier.
	BlockHeight uint32

	isDeleted bool
}

type DAOCoinLimitOrderOperationType uint8

const (
	// We intentionally skip zero as otherwise that would be the default value.
	DAOCoinLimitOrderOperationTypeASK DAOCoinLimitOrderOperationType = 1
	DAOCoinLimitOrderOperationTypeBID DAOCoinLimitOrderOperationType = 2
)

func (tp DAOCoinLimitOrderOperationType) String() string {
	if tp == DAOCoinLimitOrderOperationTypeASK {
		return "ASK"
	} else if tp == DAOCoinLimitOrderOperationTypeBID {
		return "BID"
	} else {
		return "UNKNOWN"
	}
}

type DAOCoinLimitOrderFillType uint8

const (
	// GoodTillCancelled: fulfill whatever you can immediately then
	// store whatever is remaining of this order in the database.
	DAOCoinLimitOrderFillTypeGoodTillCancelled DAOCoinLimitOrderFillType = 1
	// ImmediateOrCancel: fulfill whatever you can immediately then
	// cancel whatever is remaining of this order.
	DAOCoinLimitOrderFillTypeImmediateOrCancel DAOCoinLimitOrderFillType = 2
	// FillOrKill: fulfill whatever you can immediately then cancel
	// the entire order if it is unable to be completely fulfilled.
	DAOCoinLimitOrderFillTypeFillOrKill DAOCoinLimitOrderFillType = 3
)

// FilledDAOCoinLimitOrder only exists to support understanding what orders were
// fulfilled when connecting a DAO Coin Limit Order Txn
type FilledDAOCoinLimitOrder struct {
	OrderID                       *BlockHash
	TransactorPKID                *PKID
	BuyingDAOCoinCreatorPKID      *PKID
	SellingDAOCoinCreatorPKID     *PKID
	CoinQuantityInBaseUnitsBought *uint256.Int
	CoinQuantityInBaseUnitsSold   *uint256.Int
	IsFulfilled                   bool
}

func (order *DAOCoinLimitOrderEntry) Copy() *DAOCoinLimitOrderEntry {
	return &DAOCoinLimitOrderEntry{
		OrderID:                   order.OrderID.NewBlockHash(),
		TransactorPKID:            order.TransactorPKID.NewPKID(),
		BuyingDAOCoinCreatorPKID:  order.BuyingDAOCoinCreatorPKID.NewPKID(),
		SellingDAOCoinCreatorPKID: order.SellingDAOCoinCreatorPKID.NewPKID(),
		ScaledExchangeRateCoinsToSellPerCoinToBuy: order.ScaledExchangeRateCoinsToSellPerCoinToBuy.Clone(),
		QuantityToFillInBaseUnits:                 order.QuantityToFillInBaseUnits.Clone(),
		OperationType:                             order.OperationType,
		FillType:                                  order.FillType,
		BlockHeight:                               order.BlockHeight,
		isDeleted:                                 order.isDeleted,
	}
}

func (order *DAOCoinLimitOrderEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeToBytes(blockHeight, order.OrderID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, order.TransactorPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, order.BuyingDAOCoinCreatorPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, order.SellingDAOCoinCreatorPKID, skipMetadata...)...)
	data = append(data, VariableEncodeUint256(order.ScaledExchangeRateCoinsToSellPerCoinToBuy)...)
	data = append(data, VariableEncodeUint256(order.QuantityToFillInBaseUnits)...)
	data = append(data, UintToBuf(uint64(order.OperationType))...)
	data = append(data, UintToBuf(uint64(order.FillType))...)
	data = append(data, UintToBuf(uint64(order.BlockHeight))...)

	return data
}

func (order *DAOCoinLimitOrderEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	orderID := &BlockHash{}
	if exist, err := DecodeFromBytes(orderID, rr); exist && err == nil {
		order.OrderID = orderID
	} else if err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderEntry.Decode: Problem decoding OrderID")
	}

	// TransactorPKID
	transactorPKID := &PKID{}
	if exist, err := DecodeFromBytes(transactorPKID, rr); exist && err == nil {
		order.TransactorPKID = transactorPKID
	} else if err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderEntry.Decode: Problem reading TransactorPKID")
	}

	// BuyingDAOCoinCreatorPKID
	buyingDAOCoinCreatorPKID := &PKID{}
	if exist, err := DecodeFromBytes(buyingDAOCoinCreatorPKID, rr); exist && err == nil {
		order.BuyingDAOCoinCreatorPKID = buyingDAOCoinCreatorPKID
	} else if err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderEntry.Decode: Problem reading BuyingDAOCoinCreatorPKID")
	}

	// SellingDAOCoinCreatorPKID
	sellingDAOCoinCreatorPKID := &PKID{}
	if exist, err := DecodeFromBytes(sellingDAOCoinCreatorPKID, rr); exist && err == nil {
		order.SellingDAOCoinCreatorPKID = sellingDAOCoinCreatorPKID
	} else if err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderEntry.Decode: Problem reading SellingDAOCoinCreatorPKID")
	}

	// ScaledExchangeRateCoinsToSellPerCoinToBuy
	if order.ScaledExchangeRateCoinsToSellPerCoinToBuy, err = VariableDecodeUint256(rr); err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderEntry.Decode: Problem reading ScaledExchangeRateCoinsToSellPerCoinToBuy")
	}

	// QuantityToFillInBaseUnits
	if order.QuantityToFillInBaseUnits, err = VariableDecodeUint256(rr); err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderEntry.Decode: Problem reading QuantityToFillInBaseUnits")
	}

	// OperationType
	operationType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderEntry.Decode: Error reading OperationType")
	}
	if operationType > math.MaxUint8 {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: OperationType exceeds "+
			"uint8 max: %v vs %v", operationType, math.MaxUint8)
	}
	order.OperationType = DAOCoinLimitOrderOperationType(operationType)

	// Parse FillType
	fillType, err := ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: Error reading FillType: %v", err)
	}
	if fillType > math.MaxUint8 {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: FillType exceeds "+
			"uint8 max: %v vs %v", fillType, math.MaxUint8)
	}
	order.FillType = DAOCoinLimitOrderFillType(fillType)

	// Parse BlockHeight
	daoBlockHeight, err := ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderEntry.Decode: Error reading BlockHeight: %v", err)
	}
	if daoBlockHeight > uint64(math.MaxUint32) {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: Invalid block height %d: Greater than max uint32", daoBlockHeight)
	}
	order.BlockHeight = uint32(daoBlockHeight)

	return nil
}

func (order *DAOCoinLimitOrderEntry) GetVersionByte(blockHeight uint64) byte {
	return byte(0)
}

func (order *DAOCoinLimitOrderEntry) GetEncoderType() EncoderType {
	return EncoderTypeDAOCoinLimitOrderEntry
}

func (order *DAOCoinLimitOrderEntry) IsMarketOrder() bool {
	// For ImmediateOrCancel and FillOrKill orders, the exchange
	// rate can be zero, in which case it is ignored and the order
	// functions as a market order accepting the best price available
	// in the order book for the specified buying + selling coin pair.
	return (order.FillType == DAOCoinLimitOrderFillTypeImmediateOrCancel ||
		order.FillType == DAOCoinLimitOrderFillTypeFillOrKill) &&
		order.ScaledExchangeRateCoinsToSellPerCoinToBuy.IsZero()
}

func (order *DAOCoinLimitOrderEntry) IsBetterMatchingOrderThan(other *DAOCoinLimitOrderEntry) bool {
	// We prefer the order with the higher exchange rate. This would result
	// in more of their selling DAO coin being offered to the transactor
	// for each of the corresponding buying DAO coin.
	if !order.ScaledExchangeRateCoinsToSellPerCoinToBuy.Eq(
		other.ScaledExchangeRateCoinsToSellPerCoinToBuy) {

		// order.ScaledPrice > other.ScaledPrice
		return order.ScaledExchangeRateCoinsToSellPerCoinToBuy.Gt(
			other.ScaledExchangeRateCoinsToSellPerCoinToBuy)
	}

	// FIFO, prefer older orders first, i.e. lower block height.
	if order.BlockHeight != other.BlockHeight {
		return order.BlockHeight < other.BlockHeight
	}

	// To break a tie and guarantee idempotency in sorting,
	// prefer higher OrderIDs. This matches the BadgerDB
	// ordering where we SEEK descending.
	return bytes.Compare(order.OrderID.ToBytes(), other.OrderID.ToBytes()) > 0
}

func (order *DAOCoinLimitOrderEntry) BaseUnitsToBuyUint256() (*uint256.Int, error) {
	if order.OperationType == DAOCoinLimitOrderOperationTypeASK {
		// In this case, the quantity specified in the order is the amount to sell,
		// so needs to be converted.
		return ComputeBaseUnitsToBuyUint256(
			order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			order.QuantityToFillInBaseUnits)
	} else if order.OperationType == DAOCoinLimitOrderOperationTypeBID {
		// In this case, the quantity specified in the order is the amount to buy,
		// so can be returned as-is.
		return order.QuantityToFillInBaseUnits, nil
	} else {
		return nil, fmt.Errorf("Invalid OperationType %v", order.OperationType)
	}
}

func ComputeBaseUnitsToBuyUint256(
	scaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int,
	quantityToSellBaseUnits *uint256.Int) (*uint256.Int, error) {
	// Converts quantity to sell to quantity to buy according to the given exchange rate.
	// Quantity to buy
	//	 = Scaling factor * Quantity to sell / Scaled exchange rate coins to sell per coin to buy
	//	 = Scaling factor * Quantity to sell / (Scaling factor * Quantity to sell / Quantity to Buy)
	//	 = 1 / (1 / Quantity to buy)
	//	 = Quantity to buy

	// Perform a few validations.
	if scaledExchangeRateCoinsToSellPerCoinToBuy == nil ||
		scaledExchangeRateCoinsToSellPerCoinToBuy.IsZero() {
		// This should never happen.
		return nil, fmt.Errorf("ComputeBaseUnitsToBuyUint256: passed invalid exchange rate")
	}

	if quantityToSellBaseUnits == nil {
		// This should never happen.
		return nil, fmt.Errorf("ComputeBaseUnitsToBuyUint256: passed invalid quantity to sell")
	}

	// If the quantity to sell is zero then return zero (selling
	// zero means you should buy zero)
	if quantityToSellBaseUnits.IsZero() {
		return uint256.NewInt(), nil
	}

	// Perform calculation.
	scaledQuantityToSellBigInt := big.NewInt(0).Mul(
		OneE38.ToBig(), quantityToSellBaseUnits.ToBig())

	quantityToBuyBigInt := big.NewInt(0).Div(
		scaledQuantityToSellBigInt, scaledExchangeRateCoinsToSellPerCoinToBuy.ToBig())

	// Check for overflow.
	if quantityToBuyBigInt.Cmp(MaxUint256.ToBig()) > 0 {
		return nil, errors.Wrapf(
			RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint256,
			"ComputeBaseUnitsToBuyUint256: scaledExchangeRateCoinsToSellPerCoinToBuy: %v, "+
				"quantityToSellBaseUnits: %v",
			scaledExchangeRateCoinsToSellPerCoinToBuy.Hex(),
			quantityToSellBaseUnits.Hex())
	}

	// We don't trust the overflow checker in uint256. It's too risky because
	// it could cause a money printer bug if there's a problem with it. We
	// manually check for overflow above.
	quantityToBuyUint256, _ := uint256.FromBig(quantityToBuyBigInt)

	return quantityToBuyUint256, nil
}

func (order *DAOCoinLimitOrderEntry) BaseUnitsToSellUint256() (*uint256.Int, error) {
	if order.OperationType == DAOCoinLimitOrderOperationTypeBID {
		// In this case, the quantity specified in the order is the amount to buy,
		// so needs to be converted.
		return ComputeBaseUnitsToSellUint256(
			order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			order.QuantityToFillInBaseUnits)
	} else if order.OperationType == DAOCoinLimitOrderOperationTypeASK {
		// In this case, the quantity specified in the order is the amount to sell,
		// so can be returned as-is.
		return order.QuantityToFillInBaseUnits, nil
	} else {
		return nil, fmt.Errorf("Invalid OperationType %v", order.OperationType)
	}
}

func ComputeBaseUnitsToSellUint256(
	scaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int,
	quantityToBuyBaseUnits *uint256.Int) (*uint256.Int, error) {
	// Converts quantity to buy to quantity to sell according to the given exchange rate.
	// Quantity to sell
	//   = Scaled exchange rate coins to sell per coin to buy * Quantity to buy / Scaling factor
	//   = (Scaling factor * Quantity to sell / Quantity to buy) * Quantity to buy / Scaling factor
	//   = Quantity to sell

	if scaledExchangeRateCoinsToSellPerCoinToBuy == nil ||
		scaledExchangeRateCoinsToSellPerCoinToBuy.IsZero() {
		// This should never happen.
		return nil, fmt.Errorf("ComputeBaseUnitsToBuyUint256: passed invalid exchange rate")
	}

	if quantityToBuyBaseUnits == nil {
		// This should never happen.
		return nil, fmt.Errorf("ComputeBaseUnitsToBuyUint256: passed invalid quantity to buy")
	}

	// If the quantity to buy is zero then return zero (buying
	// zero means you should sell zero)
	if quantityToBuyBaseUnits.IsZero() {
		return uint256.NewInt(), nil
	}

	// Perform calculation.
	// Note that we account for overflow here. Not doing this could result
	// in a money printer bug. You need to check the following:
	// scaledExchangeRateCoinsToSellPerCoinToBuy * quantityToBuyBaseUnits < uint256max
	// -> scaledExchangeRateCoinsToSellPerCoinToBuy < uint256max / quantitybaseunits
	//
	// The division afterward is inherently safe so no need to check it.

	// Returns the total cost of the inputted price x quantity as a uint256.
	scaledQuantityToSellBigint := big.NewInt(0).Mul(
		scaledExchangeRateCoinsToSellPerCoinToBuy.ToBig(),
		quantityToBuyBaseUnits.ToBig())

	// Check for overflow.
	if scaledQuantityToSellBigint.Cmp(MaxUint256.ToBig()) > 0 {
		return nil, errors.Wrapf(
			RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint256,
			"ComputeBaseUnitsToSellUint256: scaledExchangeRateCoinsToSellPerCoinToBuy: %v, "+
				"quantityToBuyBaseUnits: %v",
			scaledExchangeRateCoinsToSellPerCoinToBuy.Hex(),
			quantityToBuyBaseUnits.Hex())
	}

	// We don't trust the overflow checker in uint256. It's too risky because
	// it could cause a money printer bug if there's a problem with it. We
	// manually check for overflow above.
	scaledQuantityToSellUint256, _ := uint256.FromBig(scaledQuantityToSellBigint)
	quantityToSellUint256, err := SafeUint256().Div(scaledQuantityToSellUint256, OneE38)
	if err != nil {
		// This should never happen as we're dividing by a known constant.
		return nil, errors.Wrapf(err, "ComputeBaseUnitsToSellUint256: ")
	}

	return quantityToSellUint256, nil
}

type DAOCoinLimitOrderMapKey struct {
	// An OrderID uniquely identifies an order
	OrderID BlockHash
}

func (order *DAOCoinLimitOrderEntry) ToMapKey() DAOCoinLimitOrderMapKey {
	return DAOCoinLimitOrderMapKey{
		OrderID: *order.OrderID.NewBlockHash(),
	}
}

func (order *FilledDAOCoinLimitOrder) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeToBytes(blockHeight, order.OrderID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, order.TransactorPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, order.BuyingDAOCoinCreatorPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, order.SellingDAOCoinCreatorPKID, skipMetadata...)...)
	data = append(data, VariableEncodeUint256(order.CoinQuantityInBaseUnitsBought)...)
	data = append(data, VariableEncodeUint256(order.CoinQuantityInBaseUnitsSold)...)
	data = append(data, BoolToByte(order.IsFulfilled))

	return data
}

func (order *FilledDAOCoinLimitOrder) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// OrderID
	orderID := &BlockHash{}
	if exist, err := DecodeFromBytes(orderID, rr); exist && err == nil {
		order.OrderID = orderID
	} else if err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimitOrder.Decode: Problem reading OrderID")
	}

	// TransactorPKID
	transactorPKID := &PKID{}
	if exist, err := DecodeFromBytes(transactorPKID, rr); exist && err == nil {
		order.TransactorPKID = transactorPKID
	} else if err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimiteOrder.Decode: Problem reading TransactorPKID")
	}

	// BuyingDAOCoinCreatorPKID
	buyingDAOCoinCreatorPKID := &PKID{}
	if exist, err := DecodeFromBytes(buyingDAOCoinCreatorPKID, rr); exist && err == nil {
		order.BuyingDAOCoinCreatorPKID = buyingDAOCoinCreatorPKID
	} else if err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimiteOrder.Decode: Problem reading BuyingDAOCoinCreatorPKID")
	}

	// SellingDAOCoinCreatorPKID
	sellingDAOCoinCreatorPKID := &PKID{}
	if exist, err := DecodeFromBytes(sellingDAOCoinCreatorPKID, rr); exist && err == nil {
		order.SellingDAOCoinCreatorPKID = sellingDAOCoinCreatorPKID
	} else if err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimiteOrder.Decode: Problem reading SellingDAOCoinCreatorPKID")
	}

	// CoinQuantityInBaseUnitsBought
	if order.CoinQuantityInBaseUnitsBought, err = VariableDecodeUint256(rr); err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimiteOrder.Decode: Problem reading CoinQuantityInBaseUnitsBought")
	}

	// CoinQuantityInBaseUnitsSold
	if order.CoinQuantityInBaseUnitsSold, err = VariableDecodeUint256(rr); err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimiteOrder.Decode: Problem reading CoinQuantityInBaseUnitsSold")
	}

	// IsFulfilled
	if order.IsFulfilled, err = ReadBoolByte(rr); err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimiteOrder.Decode: Problem reading IsFulfilled")
	}

	return nil
}

func (order *FilledDAOCoinLimitOrder) GetVersionByte(blockHeight uint64) byte {
	return byte(0)
}

func (order *FilledDAOCoinLimitOrder) GetEncoderType() EncoderType {
	return EncoderTypeFilledDAOCoinLimitOrder
}

// -----------------------------------
// Associations
// -----------------------------------

type UserAssociationEntry struct {
	AssociationID    *BlockHash
	TransactorPKID   *PKID
	TargetUserPKID   *PKID
	AppPKID          *PKID
	AssociationType  []byte
	AssociationValue []byte
	ExtraData        map[string][]byte
	BlockHeight      uint32
	isDeleted        bool
}

type PostAssociationEntry struct {
	AssociationID    *BlockHash
	TransactorPKID   *PKID
	PostHash         *BlockHash
	AppPKID          *PKID
	AssociationType  []byte
	AssociationValue []byte
	ExtraData        map[string][]byte
	BlockHeight      uint32
	isDeleted        bool
}

func (associationEntry *UserAssociationEntry) Copy() *UserAssociationEntry {
	// Copy ExtraData.
	extraDataCopy := make(map[string][]byte)
	for key, value := range associationEntry.ExtraData {
		extraDataCopy[key] = value
	}

	// Return new AssociationEntry.
	return &UserAssociationEntry{
		AssociationID:    associationEntry.AssociationID.NewBlockHash(),
		TransactorPKID:   associationEntry.TransactorPKID.NewPKID(),
		TargetUserPKID:   associationEntry.TargetUserPKID.NewPKID(),
		AppPKID:          associationEntry.AppPKID.NewPKID(),
		AssociationType:  append([]byte{}, associationEntry.AssociationType...),  // Makes a copy.
		AssociationValue: append([]byte{}, associationEntry.AssociationValue...), // Makes a copy.
		ExtraData:        extraDataCopy,
		BlockHeight:      associationEntry.BlockHeight,
		isDeleted:        associationEntry.isDeleted,
	}
}

func (associationEntry *PostAssociationEntry) Copy() *PostAssociationEntry {
	// Copy ExtraData.
	extraDataCopy := make(map[string][]byte)
	for key, value := range associationEntry.ExtraData {
		extraDataCopy[key] = value
	}

	// Return new AssociationEntry.
	return &PostAssociationEntry{
		AssociationID:    associationEntry.AssociationID.NewBlockHash(),
		TransactorPKID:   associationEntry.TransactorPKID.NewPKID(),
		PostHash:         associationEntry.PostHash.NewBlockHash(),
		AppPKID:          associationEntry.AppPKID.NewPKID(),
		AssociationType:  append([]byte{}, associationEntry.AssociationType...),  // Makes a copy.
		AssociationValue: append([]byte{}, associationEntry.AssociationValue...), // Makes a copy.
		ExtraData:        extraDataCopy,
		BlockHeight:      associationEntry.BlockHeight,
		isDeleted:        associationEntry.isDeleted,
	}
}

func (associationEntry *UserAssociationEntry) ToMapKey() AssociationMapKey {
	return AssociationMapKey{
		AssociationID: *associationEntry.AssociationID,
	}
}

func (associationEntry *PostAssociationEntry) ToMapKey() AssociationMapKey {
	return AssociationMapKey{
		AssociationID: *associationEntry.AssociationID,
	}
}

func (associationEntry *UserAssociationEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, associationEntry.AssociationID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, associationEntry.TransactorPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, associationEntry.TargetUserPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, associationEntry.AppPKID, skipMetadata...)...)
	data = append(data, EncodeByteArray(associationEntry.AssociationType)...)
	data = append(data, EncodeByteArray(associationEntry.AssociationValue)...)
	data = append(data, EncodeExtraData(associationEntry.ExtraData)...)
	data = append(data, UintToBuf(uint64(associationEntry.BlockHeight))...)
	return data
}

func (associationEntry *PostAssociationEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, associationEntry.AssociationID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, associationEntry.TransactorPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, associationEntry.PostHash, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, associationEntry.AppPKID, skipMetadata...)...)
	data = append(data, EncodeByteArray(associationEntry.AssociationType)...)
	data = append(data, EncodeByteArray(associationEntry.AssociationValue)...)
	data = append(data, EncodeExtraData(associationEntry.ExtraData)...)
	data = append(data, UintToBuf(uint64(associationEntry.BlockHeight))...)
	return data
}

func (associationEntry *UserAssociationEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// AssociationID
	associationID := &BlockHash{}
	if exist, err := DecodeFromBytes(associationID, rr); exist && err == nil {
		associationEntry.AssociationID = associationID
	} else if err != nil {
		return errors.Wrapf(err, "UserAssociationEntry.Decode: Problem reading AssociationID: ")
	}

	// TransactorPKID
	transactorPKID := &PKID{}
	if exist, err := DecodeFromBytes(transactorPKID, rr); exist && err == nil {
		associationEntry.TransactorPKID = transactorPKID
	} else if err != nil {
		return errors.Wrapf(err, "UserAssociationEntry.Decode: Problem reading TransactorPKID: ")
	}

	// TargetUserPKID
	targetUserPKID := &PKID{}
	if exist, err := DecodeFromBytes(targetUserPKID, rr); exist && err == nil {
		associationEntry.TargetUserPKID = targetUserPKID
	} else if err != nil {
		return errors.Wrapf(err, "UserAssociationEntry.Decode: Problem reading TargetUserPKID: ")
	}

	// AppPKID
	appPKID := &PKID{}
	if exist, err := DecodeFromBytes(appPKID, rr); exist && err == nil {
		associationEntry.AppPKID = appPKID
	} else if err != nil {
		return errors.Wrapf(err, "UserAssociationEntry.Decode: Problem reading AppPKID: ")
	}

	// AssociationType
	associationEntry.AssociationType, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UserAssociationEntry.Decode: Problem reading AssociationType: ")
	}

	// AssociationValue
	associationEntry.AssociationValue, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UserAssociationEntry.Decode: Problem reading AssociationValue: ")
	}

	// ExtraData
	extraData, err := DecodeExtraData(rr)
	if err != nil {
		return errors.Wrapf(err, "UserAssociationEntry.Decode: Problem reading ExtraData: ")
	}
	associationEntry.ExtraData = extraData

	// BlockHeight
	entryBlockHeight, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UserAssociationEntry.Decode: Problem reading BlockHeight: ")
	}
	if blockHeight > uint64(math.MaxUint32) {
		return fmt.Errorf("UserAssociationEntry.Decode: invalid block height %d: greater than max uint32", entryBlockHeight)
	}
	associationEntry.BlockHeight = uint32(entryBlockHeight)

	return nil
}

func (associationEntry *PostAssociationEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	// AssociationID
	associationID := &BlockHash{}
	if exist, err := DecodeFromBytes(associationID, rr); exist && err == nil {
		associationEntry.AssociationID = associationID
	} else if err != nil {
		return errors.Wrapf(err, "PostAssociationEntry.Decode: Problem reading AssociationID: ")
	}

	// TransactorPKID
	transactorPKID := &PKID{}
	if exist, err := DecodeFromBytes(transactorPKID, rr); exist && err == nil {
		associationEntry.TransactorPKID = transactorPKID
	} else if err != nil {
		return errors.Wrapf(err, "PostAssociationEntry.Decode: Problem reading TransactorPKID: ")
	}

	// PostHash
	postHash := &BlockHash{}
	if exist, err := DecodeFromBytes(postHash, rr); exist && err == nil {
		associationEntry.PostHash = postHash
	} else if err != nil {
		return errors.Wrapf(err, "PostAssociationEntry.Decode: Problem reading PostHash: ")
	}

	// AppPKID
	appPKID := &PKID{}
	if exist, err := DecodeFromBytes(appPKID, rr); exist && err == nil {
		associationEntry.AppPKID = appPKID
	} else if err != nil {
		return errors.Wrapf(err, "PostAssociationEntry.Decode: Problem reading AppPKID: ")
	}

	// AssociationType
	associationEntry.AssociationType, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "PostAssociationEntry.Decode: Problem reading AssociationType: ")
	}

	// AssociationValue
	associationEntry.AssociationValue, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "PostAssociationEntry.Decode: Problem reading AssociationValue: ")
	}

	// ExtraData
	extraData, err := DecodeExtraData(rr)
	if err != nil {
		return errors.Wrapf(err, "PostAssociationEntry.Decode: Problem reading ExtraData: ")
	}
	associationEntry.ExtraData = extraData

	// BlockHeight
	entryBlockHeight, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PostAssociationEntry.Decode: Problem reading BlockHeight: ")
	}
	if blockHeight > uint64(math.MaxUint32) {
		return fmt.Errorf("PostAssociationEntry.Decode: invalid block height %d: greater than max uint32", entryBlockHeight)
	}
	associationEntry.BlockHeight = uint32(entryBlockHeight)

	return nil
}

func (associationEntry *UserAssociationEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (associationEntry *PostAssociationEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (associationEntry *UserAssociationEntry) GetEncoderType() EncoderType {
	return EncoderTypeUserAssociationEntry
}

func (associationEntry *PostAssociationEntry) GetEncoderType() EncoderType {
	return EncoderTypePostAssociationEntry
}

type AssociationMapKey struct {
	AssociationID BlockHash
}

func (associationEntry *UserAssociationEntry) Eq(other *UserAssociationEntry) bool {
	// Compare if two user association entries are equal. Note that their ExtraData and
	// BlockHeights can differ, and we would still consider them equal. Also note that
	// AssociationType is case-insensitive while AssociationValue is case-sensitive.
	// Basically all of these nil checks can never happen. But they're safety checks.
	if other == nil {
		return false
	}
	return associationEntry.TransactorPKID != nil &&
		associationEntry.TransactorPKID.Eq(other.TransactorPKID) &&
		associationEntry.TargetUserPKID != nil &&
		associationEntry.TargetUserPKID.Eq(other.TargetUserPKID) &&
		associationEntry.AppPKID != nil &&
		associationEntry.AppPKID.Eq(other.AppPKID) &&
		_isMatchingAssociationType(associationEntry.AssociationType, other.AssociationType) &&
		bytes.Equal(associationEntry.AssociationValue, other.AssociationValue)
}

func (associationEntry *PostAssociationEntry) Eq(other *PostAssociationEntry) bool {
	// Compare if two post association entries are equal. Note that their ExtraData and
	// BlockHeights can differ, and we would still consider them equal. Also note that
	// AssociationType is case-insensitive while AssociationValue is case-sensitive.
	// Basically all of these nil checks can never happen. But they're safety checks.
	if other == nil {
		return false
	}
	return associationEntry.TransactorPKID != nil &&
		associationEntry.TransactorPKID.Eq(other.TransactorPKID) &&
		associationEntry.PostHash != nil &&
		associationEntry.PostHash.IsEqual(other.PostHash) &&
		associationEntry.AppPKID != nil &&
		associationEntry.AppPKID.Eq(other.AppPKID) &&
		_isMatchingAssociationType(associationEntry.AssociationType, other.AssociationType) &&
		bytes.Equal(associationEntry.AssociationValue, other.AssociationValue)
}

type CreateUserAssociationTxindexMetadata struct {
	TargetUserPublicKeyBase58Check string
	AppPublicKeyBase58Check        string
	AssociationType                string
	AssociationValue               string
}

type DeleteUserAssociationTxindexMetadata struct {
	AssociationIDHex               string
	TargetUserPublicKeyBase58Check string
	AppPublicKeyBase58Check        string
	AssociationType                string
	AssociationValue               string
}

type CreatePostAssociationTxindexMetadata struct {
	PostHashHex             string
	AppPublicKeyBase58Check string
	AssociationType         string
	AssociationValue        string
}

type DeletePostAssociationTxindexMetadata struct {
	AssociationIDHex        string
	PostHashHex             string
	AppPublicKeyBase58Check string
	AssociationType         string
	AssociationValue        string
}

func (associationTxindexMeta *CreateUserAssociationTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.TargetUserPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AppPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AssociationType))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AssociationValue))...)
	return data
}

func (associationTxindexMeta *DeleteUserAssociationTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AssociationIDHex))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.TargetUserPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AppPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AssociationType))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AssociationValue))...)
	return data
}

func (associationTxindexMeta *CreatePostAssociationTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.PostHashHex))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AppPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AssociationType))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AssociationValue))...)
	return data
}

func (associationTxindexMeta *DeletePostAssociationTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AssociationIDHex))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.PostHashHex))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AppPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AssociationType))...)
	data = append(data, EncodeByteArray([]byte(associationTxindexMeta.AssociationValue))...)
	return data
}

func (associationTxindexMeta *CreateUserAssociationTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	// TargetUserPublicKeyBase58Check
	targetUserPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateUserAssociationTxindexMetadata.Decode: Problem reading TargetUserPublicKeyBase58Check: ")
	}
	associationTxindexMeta.TargetUserPublicKeyBase58Check = string(targetUserPublicKeyBase58CheckBytes)

	// AppPublicKeyBase58Check
	appPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateUserAssociationTxindexMetadata.Decode: Problem reading AppPublicKeyBase58Check: ")
	}
	associationTxindexMeta.AppPublicKeyBase58Check = string(appPublicKeyBase58CheckBytes)

	// AssociationType
	associationTypeBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateUserAssociationTxindexMetadata.Decode: Problem reading AssociationType: ")
	}
	associationTxindexMeta.AssociationType = string(associationTypeBytes)

	// AssociationValue
	associationValueBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateUserAssociationTxindexMetadata.Decode: Problem reading AssociationValue: ")
	}
	associationTxindexMeta.AssociationValue = string(associationValueBytes)

	return nil
}

func (associationTxindexMeta *DeleteUserAssociationTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	// AssociationIDHex
	associationIDHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeleteUserAssociationTxindexMetadata.Decode: Problem reading AssociationIDHex: ")
	}
	associationTxindexMeta.AssociationIDHex = string(associationIDHexBytes)

	// TargetUserPublicKeyBase58Check
	targetUserPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeleteUserAssociationTxindexMetadata.Decode: Problem reading TargetUserPublicKeyBase58Check: ")
	}
	associationTxindexMeta.TargetUserPublicKeyBase58Check = string(targetUserPublicKeyBase58CheckBytes)

	// AppPublicKeyBase58Check
	appPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeleteUserAssociationTxindexMetadata.Decode: Problem reading AppPublicKeyBase58Check: ")
	}
	associationTxindexMeta.AppPublicKeyBase58Check = string(appPublicKeyBase58CheckBytes)

	// AssociationType
	associationTypeBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeleteUserAssociationTxindexMetadata.Decode: Problem reading AssociationType: ")
	}
	associationTxindexMeta.AssociationType = string(associationTypeBytes)

	// AssociationValue
	associationValueBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeleteUserAssociationTxindexMetadata.Decode: Problem reading AssociationValue: ")
	}
	associationTxindexMeta.AssociationValue = string(associationValueBytes)

	return nil
}

func (associationTxindexMeta *CreatePostAssociationTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	// PostHashHex
	postHashHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatePostAssociationTxindexMetadata.Decode: Problem reading PostHashHex: ")
	}
	associationTxindexMeta.PostHashHex = string(postHashHexBytes)

	// AppPublicKeyBase58Check
	appPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatePostAssociationTxindexMetadata.Decode: Problem reading AppPublicKeyBase58Check: ")
	}
	associationTxindexMeta.AppPublicKeyBase58Check = string(appPublicKeyBase58CheckBytes)

	// AssociationType
	associationTypeBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatePostAssociationTxindexMetadata.Decode: Problem reading AssociationType: ")
	}
	associationTxindexMeta.AssociationType = string(associationTypeBytes)

	// AssociationValue
	associationValueBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatePostAssociationTxindexMetadata.Decode: Problem reading AssociationValue: ")
	}
	associationTxindexMeta.AssociationValue = string(associationValueBytes)

	return nil
}

func (associationTxindexMeta *DeletePostAssociationTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	// AssociationIDHex
	associationIDHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeletePostAssociationTxindexMetadata.Decode: Problem reading AssociationIDHex: ")
	}
	associationTxindexMeta.AssociationIDHex = string(associationIDHexBytes)

	// PostHashHex
	postHashHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeletePostAssociationTxindexMetadata.Decode: Problem reading PostHashHex: ")
	}
	associationTxindexMeta.PostHashHex = string(postHashHexBytes)

	// AppPublicKeyBase58Check
	appPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeletePostAssociationTxindexMetadata.Decode: Problem reading AppPublicKeyBase58Check: ")
	}
	associationTxindexMeta.AppPublicKeyBase58Check = string(appPublicKeyBase58CheckBytes)

	// AssociationType
	associationTypeBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeletePostAssociationTxindexMetadata.Decode: Problem reading AssociationType: ")
	}
	associationTxindexMeta.AssociationType = string(associationTypeBytes)

	// AssociationValue
	associationValueBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeletePostAssociationTxindexMetadata.Decode: Problem reading AssociationValue: ")
	}
	associationTxindexMeta.AssociationValue = string(associationValueBytes)

	return nil
}

func (associationTxindexMeta *CreateUserAssociationTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (associationTxindexMeta *DeleteUserAssociationTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (associationTxindexMeta *CreatePostAssociationTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (associationTxindexMeta *DeletePostAssociationTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (associationTxindexMeta *CreateUserAssociationTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCreateUserAssociationTxindexMetadata
}

func (associationTxindexMeta *DeleteUserAssociationTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeDeleteUserAssociationTxindexMetadata
}

func (associationTxindexMeta *CreatePostAssociationTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCreatePostAssociationTxindexMetadata
}

func (associationTxindexMeta *DeletePostAssociationTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeDeletePostAssociationTxindexMetadata
}

type AccessGroupTxindexMetadata struct {
	AccessGroupOwnerPublicKey PublicKey
	AccessGroupPublicKey      PublicKey
	AccessGroupKeyName        GroupKeyName
	AccessGroupOperationType
}

func (accessGroupTxindexMetadata *AccessGroupTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, &accessGroupTxindexMetadata.AccessGroupOwnerPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, &accessGroupTxindexMetadata.AccessGroupPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, &accessGroupTxindexMetadata.AccessGroupKeyName, skipMetadata...)...)
	data = append(data, UintToBuf(uint64(accessGroupTxindexMetadata.AccessGroupOperationType))...)
	return data
}

func (accessGroupTxindexMetadata *AccessGroupTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {

	// AccessGroupOwnerPublicKey
	accessGroupOwnerPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(accessGroupOwnerPublicKey, rr); exist && err == nil {
		accessGroupTxindexMetadata.AccessGroupOwnerPublicKey = *accessGroupOwnerPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupTxindexMetadata.Decode: Problem reading AccessGroupOwnerPublicKey: ")
	}

	// AccessGroupPublicKey
	accessGroupPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(accessGroupPublicKey, rr); exist && err == nil {
		accessGroupTxindexMetadata.AccessGroupPublicKey = *accessGroupPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupTxindexMetadata.Decode: Problem reading AccessGroupPublicKey: ")
	}

	// AccessGroupKeyName
	accessGroupKeyName := &GroupKeyName{}
	if exist, err := DecodeFromBytes(accessGroupKeyName, rr); exist && err == nil {
		accessGroupTxindexMetadata.AccessGroupKeyName = *accessGroupKeyName
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupTxindexMetadata.Decode: Problem reading AccessGroupKeyName: ")
	}

	// AccessGroupOperationType
	accessGroupOperationType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupTxindexMetadata.Decode: Problem reading AccessGroupOperationType: ")
	}
	accessGroupTxindexMetadata.AccessGroupOperationType = AccessGroupOperationType(accessGroupOperationType)

	return nil
}

func (accessGroupTxindexMetadata *AccessGroupTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (accessGroupTxindexMetadata *AccessGroupTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeAccessGroupTxindexMetadata
}

type AccessGroupMembersTxindexMetadata struct {
	AccessGroupOwnerPublicKey PublicKey
	AccessGroupKeyName        GroupKeyName
	AccessGroupMembersList    []*AccessGroupMember
	AccessGroupMemberOperationType
}

func (accessGroupMembersTxindexMetadata *AccessGroupMembersTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, &accessGroupMembersTxindexMetadata.AccessGroupOwnerPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, &accessGroupMembersTxindexMetadata.AccessGroupKeyName, skipMetadata...)...)
	data = append(data, encodeAccessGroupMembersList(accessGroupMembersTxindexMetadata.AccessGroupMembersList)...)
	data = append(data, UintToBuf(uint64(accessGroupMembersTxindexMetadata.AccessGroupMemberOperationType))...)
	return data
}

func (accessGroupMembersTxindexMetadata *AccessGroupMembersTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {

	// AccessGroupOwnerPublicKey
	accessGroupOwnerPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(accessGroupOwnerPublicKey, rr); exist && err == nil {
		accessGroupMembersTxindexMetadata.AccessGroupOwnerPublicKey = *accessGroupOwnerPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupMembersTxindexMetadata.Decode: Problem reading AccessGroupOwnerPublicKey: ")
	}

	// AccessGroupKeyName
	accessGroupKeyName := &GroupKeyName{}
	if exist, err := DecodeFromBytes(accessGroupKeyName, rr); exist && err == nil {
		accessGroupMembersTxindexMetadata.AccessGroupKeyName = *accessGroupKeyName
	} else if err != nil {
		return errors.Wrapf(err, "AccessGroupMembersTxindexMetadata.Decode: Problem reading AccessGroupKeyName: ")
	}

	// AccessGroupMembersList
	accessGroupMembersList, err := decodeAccessGroupMembersList(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMembersTxindexMetadata.Decode: Problem reading AccessGroupMembersList: ")
	}
	accessGroupMembersTxindexMetadata.AccessGroupMembersList = accessGroupMembersList

	// AccessGroupMemberOperationType
	accessGroupMemberOperationType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMembersTxindexMetadata.Decode: Problem reading AccessGroupMemberOperationType: ")
	}
	accessGroupMembersTxindexMetadata.AccessGroupMemberOperationType = AccessGroupMemberOperationType(accessGroupMemberOperationType)

	return nil
}

func (accessGroupMembersTxindexMetadata *AccessGroupMembersTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (accessGroupMembersTxindexMetadata *AccessGroupMembersTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeAccessGroupMembersTxindexMetadata
}

type NewMessageTxindexMetadata struct {
	SenderAccessGroupOwnerPublicKey    PublicKey
	SenderAccessGroupKeyName           GroupKeyName
	RecipientAccessGroupOwnerPublicKey PublicKey
	RecipientAccessGroupKeyName        GroupKeyName
	TimestampNanos                     uint64
	NewMessageType
	NewMessageOperation
}

func (newMessageTxindexMetadata *NewMessageTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, &newMessageTxindexMetadata.SenderAccessGroupOwnerPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, &newMessageTxindexMetadata.SenderAccessGroupKeyName, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, &newMessageTxindexMetadata.RecipientAccessGroupOwnerPublicKey, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, &newMessageTxindexMetadata.RecipientAccessGroupKeyName, skipMetadata...)...)
	data = append(data, UintToBuf(newMessageTxindexMetadata.TimestampNanos)...)
	data = append(data, UintToBuf(uint64(newMessageTxindexMetadata.NewMessageType))...)
	data = append(data, UintToBuf(uint64(newMessageTxindexMetadata.NewMessageOperation))...)
	return data
}

func (newMessageTxindexMetadata *NewMessageTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {

	// SenderAccessGroupOwnerPublicKey
	senderAccessGroupOwnerPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(senderAccessGroupOwnerPublicKey, rr); exist && err == nil {
		newMessageTxindexMetadata.SenderAccessGroupOwnerPublicKey = *senderAccessGroupOwnerPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "NewMessageTxindexMetadata.Decode: Problem reading SenderAccessGroupOwnerPublicKey: ")
	}

	// SenderAccessGroupKeyName
	senderAccessGroupKeyName := &GroupKeyName{}
	if exist, err := DecodeFromBytes(senderAccessGroupKeyName, rr); exist && err == nil {
		newMessageTxindexMetadata.SenderAccessGroupKeyName = *senderAccessGroupKeyName
	} else if err != nil {
		return errors.Wrapf(err, "NewMessageTxindexMetadata.Decode: Problem reading SenderAccessGroupKeyName: ")
	}

	// RecipientAccessGroupOwnerPublicKey
	recipientAccessGroupOwnerPublicKey := &PublicKey{}
	if exist, err := DecodeFromBytes(recipientAccessGroupOwnerPublicKey, rr); exist && err == nil {
		newMessageTxindexMetadata.RecipientAccessGroupOwnerPublicKey = *recipientAccessGroupOwnerPublicKey
	} else if err != nil {
		return errors.Wrapf(err, "NewMessageTxindexMetadata.Decode: Problem reading RecipientAccessGroupOwnerPublicKey: ")
	}

	// RecipientAccessGroupKeyName
	recipientAccessGroupKeyName := &GroupKeyName{}
	if exist, err := DecodeFromBytes(recipientAccessGroupKeyName, rr); exist && err == nil {
		newMessageTxindexMetadata.RecipientAccessGroupKeyName = *recipientAccessGroupKeyName
	} else if err != nil {
		return errors.Wrapf(err, "NewMessageTxindexMetadata.Decode: Problem reading RecipientAccessGroupKeyName: ")
	}

	// TimestampNanos
	timestampNanos, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageTxindexMetadata.Decode: Problem reading TimestampNanos: ")
	}
	newMessageTxindexMetadata.TimestampNanos = timestampNanos

	// NewMessageType
	newMessageType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageTxindexMetadata.Decode: Problem reading NewMessageType: ")
	}
	newMessageTxindexMetadata.NewMessageType = NewMessageType(newMessageType)

	// NewMessageOperation
	newMessageOperation, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageTxindexMetadata.Decode: Problem reading NewMessageOperation: ")
	}
	newMessageTxindexMetadata.NewMessageOperation = NewMessageOperation(newMessageOperation)

	return nil
}

func (newMessageTxindexMetadata *NewMessageTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (newMessageTxindexMetadata *NewMessageTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeNewMessageTxindexMetadata
}

type TransactorNonceEntry struct {
	Nonce          *DeSoNonce
	TransactorPKID *PKID
	isDeleted      bool
}

func (tne *TransactorNonceEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, tne.Nonce, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, tne.TransactorPKID, skipMetadata...)...)
	return data
}

func (tne *TransactorNonceEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	nonce := &DeSoNonce{}
	if exists, err := DecodeFromBytes(nonce, rr); exists && err == nil {
		tne.Nonce = nonce
	} else if err != nil {
		return err
	}

	transactorPKID := &PKID{}
	if exists, err := DecodeFromBytes(transactorPKID, rr); exists && err == nil {
		tne.TransactorPKID = transactorPKID
	} else if err != nil {
		return err
	}
	return nil
}

func (tne *TransactorNonceEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (tne *TransactorNonceEntry) GetEncoderType() EncoderType {
	return EncoderTypeTransactorNonceEntry
}

func (tne *TransactorNonceEntry) ToMapKey() TransactorNonceMapKey {
	return TransactorNonceMapKey{
		Nonce:          *tne.Nonce,
		TransactorPKID: *tne.TransactorPKID,
	}
}

func (tne *TransactorNonceEntry) Copy() *TransactorNonceEntry {
	copiedNonce := *tne.Nonce
	return &TransactorNonceEntry{
		Nonce:          &copiedNonce,
		TransactorPKID: tne.TransactorPKID.NewPKID(),
		isDeleted:      tne.isDeleted,
	}
}

type TransactorNonceMapKey struct {
	Nonce          DeSoNonce
	TransactorPKID PKID
}
