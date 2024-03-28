package lib

import (
	"bytes"
	"github.com/pkg/errors"
)

const (
	EncoderTypeCreatorCoinStateChangeMetadata           EncoderType = 2000000
	EncoderTypeCCTransferStateChangeMetadata            EncoderType = 2000001
	EncoderTypeSubmitPostStateChangeMetadata            EncoderType = 2000002
	EncoderTypeLikeStateChangeMetadata                  EncoderType = 2000003
	EncoderTypeSwapIdentityStateChangeMetadata          EncoderType = 2000004
	EncoderTypeNFTBidStateChangeMetadata                EncoderType = 2000005
	EncoderTypeAcceptNFTBidStateChangeMetadata          EncoderType = 2000006
	EncoderTypeCreateNFTStateChangeMetadata             EncoderType = 2000007
	EncoderTypeUpdateNFTStateChangeMetadata             EncoderType = 2000008
	EncoderTypeDAOCoinStateChangeMetadata               EncoderType = 2000009
	EncoderTypeDAOCoinTransferStateChangeMetadata       EncoderType = 2000010
	EncoderTypeDAOCoinLimitOrderStateChangeMetadata     EncoderType = 2000011
	EncoderTypeDeleteUserAssociationStateChangeMetadata EncoderType = 2000012
	EncoderTypeCreatePostAssociationStateChangeMetadata EncoderType = 2000013
	EncoderTypeDeletePostAssociationStateChangeMetadata EncoderType = 2000014
	EncoderTypeStakeRewardStateChangeMetadata           EncoderType = 2000015
	EncoderTypeUnjailValidatorStateChangeMetadata       EncoderType = 2000016
)

func GetStateChangeMetadataFromOpType(opType OperationType) DeSoEncoder {
	switch opType {
	case OperationTypeCreatorCoin:
		return &CreatorCoinStateChangeMetadata{}
	case OperationTypeCreatorCoinTransfer:
		return &CCTransferStateChangeMetadata{}
	case OperationTypeSubmitPost:
		return &SubmitPostStateChangeMetadata{}
	case OperationTypeLike:
		return &LikeStateChangeMetadata{}
	case OperationTypeSwapIdentity:
		return &SwapIdentityStateChangeMetadata{}
	case OperationTypeNFTBid:
		return &NFTBidStateChangeMetadata{}
	case OperationTypeAcceptNFTBid:
		return &AcceptNFTBidStateChangeMetadata{}
	case OperationTypeCreateNFT:
		return &CreateNFTStateChangeMetadata{}
	case OperationTypeUpdateNFT:
		return &UpdateNFTStateChangeMetadata{}
	case OperationTypeDAOCoin:
		return &DAOCoinStateChangeMetadata{}
	case OperationTypeDAOCoinTransfer:
		return &DAOCoinTransferStateChangeMetadata{}
	case OperationTypeDAOCoinLimitOrder:
		return &DAOCoinLimitOrderStateChangeMetadata{}
	case OperationTypeDeleteUserAssociation:
		return &DeleteUserAssociationStateChangeMetadata{}
	case OperationTypeCreatePostAssociation:
		return &CreatePostAssociationStateChangeMetadata{}
	case OperationTypeDeletePostAssociation:
		return &DeletePostAssociationStateChangeMetadata{}
	case OperationTypeStakeDistributionRestake, OperationTypeStakeDistributionPayToBalance:
		return &StakeRewardStateChangeMetadata{}
	case OperationTypeUnjailValidator:
		return &UnjailValidatorStateChangeMetadata{}
	default:
		return nil
	}
}

type CreatorCoinStateChangeMetadata struct {
	ProfileDeSoLockedNanos uint64
}

func (creatorCoinSCM *CreatorCoinStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, UintToBuf(creatorCoinSCM.ProfileDeSoLockedNanos)...)
	return data
}

func (creatorCoinSCM *CreatorCoinStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	creatorCoinSCM.ProfileDeSoLockedNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatorCoinStateChangeMetadata.Decode: Problem reading ProfileDeSoLockedNanos")
	}

	return nil
}

func (creatorCoinSCM *CreatorCoinStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (creatorCoinSCM *CreatorCoinStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCreatorCoinStateChangeMetadata
}

type CCTransferStateChangeMetadata struct {
	CreatorProfileEntry *ProfileEntry
}

func (ccTransferSCM *CCTransferStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, ccTransferSCM.CreatorProfileEntry, skipMetadata...)...)
	return data
}

func (ccTransferSCM *CCTransferStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	if ccTransferSCM.CreatorProfileEntry, err = DecodeDeSoEncoder(&ProfileEntry{}, rr); err != nil {
		return errors.Wrapf(err, "CCTransferStateChangeMetadata.Decode: Problem reading ProfileEntry")
	}
	return nil
}

func (ccTransferSCM *CCTransferStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (ccTransferSCM *CCTransferStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCCTransferStateChangeMetadata
}

type SubmitPostStateChangeMetadata struct {
	PostEntry         *PostEntry
	ProfilesMentioned []*ProfileEntry
	RepostPostEntry   *PostEntry
}

func (submitPostSCM *SubmitPostStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, submitPostSCM.PostEntry, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, submitPostSCM.RepostPostEntry, skipMetadata...)...)

	data = append(data, EncodeDeSoEncoderSlice(submitPostSCM.ProfilesMentioned, blockHeight, skipMetadata...)...)

	return data
}

func (submitPostSCM *SubmitPostStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	if submitPostSCM.PostEntry, err = DecodeDeSoEncoder(&PostEntry{}, rr); err != nil {
		return errors.Wrapf(err, "SubmitPostStateChangeMetadata.Decode: Problem reading PostEntry")
	}

	if submitPostSCM.RepostPostEntry, err = DecodeDeSoEncoder(&PostEntry{}, rr); err != nil {
		return errors.Wrapf(err, "SubmitPostStateChangeMetadata.Decode: Problem reading RepostPostEntry")
	}

	if submitPostSCM.ProfilesMentioned, err = DecodeDeSoEncoderSlice[*ProfileEntry](rr); err != nil {
		return errors.Wrapf(err, "SubmitPostStateChangeMetadata.Decode: Problem reading ProfileMention")
	}

	return nil
}

func (submitPostSCM *SubmitPostStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (submitPostSCM *SubmitPostStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeSubmitPostStateChangeMetadata
}

type LikeStateChangeMetadata struct {
	LikedPostEntry *PostEntry
}

func (likeSCM *LikeStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, likeSCM.LikedPostEntry, skipMetadata...)...)
	return data
}

func (likeSCM *LikeStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	if likeSCM.LikedPostEntry, err = DecodeDeSoEncoder(&PostEntry{}, rr); err != nil {
		return errors.Wrapf(err, "LikeStateChangeMetadata.Decode: Problem reading LikedPostEntry")
	}

	return nil
}

func (likeSCM *LikeStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (likeSCM *LikeStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeLikeStateChangeMetadata
}

type SwapIdentityStateChangeMetadata struct {
	FromProfile *ProfileEntry
	ToProfile   *ProfileEntry
}

func (swapIdSCM *SwapIdentityStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, swapIdSCM.FromProfile, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, swapIdSCM.ToProfile, skipMetadata...)...)
	return data
}

func (swapIdSCM *SwapIdentityStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	if swapIdSCM.FromProfile, err = DecodeDeSoEncoder(&ProfileEntry{}, rr); err != nil {
		return errors.Wrapf(err, "SwapIdentityStateChangeMetadata.Decode: Problem reading FromProfile")
	}

	if swapIdSCM.ToProfile, err = DecodeDeSoEncoder(&ProfileEntry{}, rr); err != nil {
		return errors.Wrapf(err, "SwapIdentityStateChangeMetadata.Decode: Problem reading ToProfile")
	}

	return nil
}

func (swapIdSCM *SwapIdentityStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (swapIdSCM *SwapIdentityStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeSwapIdentityStateChangeMetadata
}

type NFTBidStateChangeMetadata struct {
	PostEntry                 *PostEntry
	OwnerPublicKeyBase58Check string
}

func (nftBidSCM *NFTBidStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, nftBidSCM.PostEntry, skipMetadata...)...)
	data = append(data, EncodeByteArray([]byte(nftBidSCM.OwnerPublicKeyBase58Check))...)
	return data
}

func (nftBidSCM *NFTBidStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	if nftBidSCM.PostEntry, err = DecodeDeSoEncoder(&PostEntry{}, rr); err != nil {
		return errors.Wrapf(err, "NFTBidStateChangeMetadata.Decode: Problem reading PostEntry")
	}

	ownerPublicKeyBase58Check, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTBidStateChangeMetadata.Decode: Problem reading OwnerPublicKeyBase58Check")
	}
	nftBidSCM.OwnerPublicKeyBase58Check = string(ownerPublicKeyBase58Check)

	return nil
}

func (nftBidSCM *NFTBidStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (nftBidSCM *NFTBidStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeNFTBidStateChangeMetadata
}

type AcceptNFTBidStateChangeMetadata struct {
	BidderPublicKeyBase58Check string
}

func (acceptNFTBidSCM *AcceptNFTBidStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(acceptNFTBidSCM.BidderPublicKeyBase58Check))...)
	return data
}

func (acceptNFTBidSCM *AcceptNFTBidStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	bidderPublicKeyBase58Check, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AcceptNFTBidStateChangeMetadata.Decode: Problem reading BidderPublicKeyBase58Check")
	}
	acceptNFTBidSCM.BidderPublicKeyBase58Check = string(bidderPublicKeyBase58Check)
	return nil
}

func (acceptNFTBidSCM *AcceptNFTBidStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (acceptNFTBidSCM *AcceptNFTBidStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeAcceptNFTBidStateChangeMetadata
}

type CreateNFTStateChangeMetadata struct {
	AdditionalDESORoyaltiesMap map[string]uint64
	AdditionalCoinRoyaltiesMap map[string]uint64
}

func (createNFTSCM *CreateNFTStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	// Encode the additional DESO royalties map.
	data = append(data, EncodeStringUint64MapToBytes(createNFTSCM.AdditionalDESORoyaltiesMap)...)
	// Encode the additional coin royalties map.
	data = append(data, EncodeStringUint64MapToBytes(createNFTSCM.AdditionalCoinRoyaltiesMap)...)
	return data
}

func (createNFTSCM *CreateNFTStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	additionalDESORoyaltiesMap, err := DecodeStringUint64MapFromBytes(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateNFTStateChangeMetadata.Decode: Problem reading AdditionalDESORoyaltiesMap")
	}
	createNFTSCM.AdditionalDESORoyaltiesMap = additionalDESORoyaltiesMap

	additionalCoinRoyaltiesMap, err := DecodeStringUint64MapFromBytes(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateNFTStateChangeMetadata.Decode: Problem reading AdditionalCoinRoyaltiesMap")
	}
	createNFTSCM.AdditionalCoinRoyaltiesMap = additionalCoinRoyaltiesMap

	return nil
}

func (createNFTSCM *CreateNFTStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (createNFTSCM *CreateNFTStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCreateNFTStateChangeMetadata
}

type UpdateNFTStateChangeMetadata struct {
	NFTPostEntry               *PostEntry
	AdditionalDESORoyaltiesMap map[string]uint64
	AdditionalCoinRoyaltiesMap map[string]uint64
}

func (updateNFTSCM *UpdateNFTStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, updateNFTSCM.NFTPostEntry, skipMetadata...)...)
	// Encode the additional DESO royalties map.
	data = append(data, EncodeStringUint64MapToBytes(updateNFTSCM.AdditionalDESORoyaltiesMap)...)
	// Encode the additional coin royalties map.
	data = append(data, EncodeStringUint64MapToBytes(updateNFTSCM.AdditionalCoinRoyaltiesMap)...)
	return data
}

func (updateNFTSCM *UpdateNFTStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	if updateNFTSCM.NFTPostEntry, err = DecodeDeSoEncoder(&PostEntry{}, rr); err != nil {
		return errors.Wrapf(err, "UpdateNFTStateChangeMetadata.Decode: Problem reading PostEntry")
	}

	additionalDESORoyaltiesMap, err := DecodeStringUint64MapFromBytes(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateNFTStateChangeMetadata.Decode: Problem reading AdditionalDESORoyaltiesMap")
	}
	updateNFTSCM.AdditionalDESORoyaltiesMap = additionalDESORoyaltiesMap

	additionalCoinRoyaltiesMap, err := DecodeStringUint64MapFromBytes(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateNFTStateChangeMetadata.Decode: Problem reading AdditionalCoinRoyaltiesMap")
	}
	updateNFTSCM.AdditionalCoinRoyaltiesMap = additionalCoinRoyaltiesMap

	return nil
}

func (updateNFTSCM *UpdateNFTStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (updateNFTSCM *UpdateNFTStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeUpdateNFTStateChangeMetadata
}

type DAOCoinStateChangeMetadata struct {
	CreatorProfileEntry *ProfileEntry
}

func (daoCoinSCM *DAOCoinStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, daoCoinSCM.CreatorProfileEntry, skipMetadata...)...)
	return data
}

func (daoCoinSCM *DAOCoinStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	if daoCoinSCM.CreatorProfileEntry, err = DecodeDeSoEncoder(&ProfileEntry{}, rr); err != nil {
		return errors.Wrapf(err, "DAOCoinStateChangeMetadata.Decode: Problem reading ProfileEntry")
	}

	return nil
}

func (daoCoinSCM *DAOCoinStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (daoCoinSCM *DAOCoinStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeDAOCoinStateChangeMetadata
}

type DAOCoinTransferStateChangeMetadata struct {
	CreatorProfileEntry *ProfileEntry
}

func (daoCoinTransferSCM *DAOCoinTransferStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, daoCoinTransferSCM.CreatorProfileEntry, skipMetadata...)...)
	return data
}

func (daoCoinTransferSCM *DAOCoinTransferStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	if daoCoinTransferSCM.CreatorProfileEntry, err = DecodeDeSoEncoder(&ProfileEntry{}, rr); err != nil {
		return errors.Wrapf(err, "DAOCoinTransferStateChangeMetadata.Decode: Problem reading ProfileEntry")
	}

	return nil
}

func (daoCoinTransferSCM *DAOCoinTransferStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (daoCoinTransferSCM *DAOCoinTransferStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeDAOCoinTransferStateChangeMetadata
}

type DAOCoinLimitOrderStateChangeMetadata struct {
	FilledDAOCoinLimitOrdersMetadata []*FilledDAOCoinLimitOrderMetadata
}

func (daoCoinLimitOrderSCM *DAOCoinLimitOrderStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	// Encode the number of filled DAO coin limit orders.
	data = append(data, UintToBuf(uint64(len(daoCoinLimitOrderSCM.FilledDAOCoinLimitOrdersMetadata)))...)
	// Encode each filled DAO coin limit order.
	for _, filledDAOCoinLimitOrderMetadata := range daoCoinLimitOrderSCM.FilledDAOCoinLimitOrdersMetadata {
		data = append(data, EncodeToBytes(blockHeight, filledDAOCoinLimitOrderMetadata, skipMetadata...)...)
	}
	return data
}

func (daoCoinLimitOrderSCM *DAOCoinLimitOrderStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	if daoCoinLimitOrderSCM.FilledDAOCoinLimitOrdersMetadata, err = DecodeDeSoEncoderSlice[*FilledDAOCoinLimitOrderMetadata](rr); err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderStateChangeMetadata.Decode: Problem reading FilledDAOCoinLimitOrderMetadata")
	}

	return nil
}

func (daoCoinLimitOrderSCM *DAOCoinLimitOrderStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (daoCoinLimitOrderSCM *DAOCoinLimitOrderStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeDAOCoinLimitOrderStateChangeMetadata
}

type DeleteUserAssociationStateChangeMetadata struct {
	TargetUserPublicKeyBase58Check string
	AppPublicKeyBase58Check        string
}

func (deleteUserAssociationSCM *DeleteUserAssociationStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(deleteUserAssociationSCM.TargetUserPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(deleteUserAssociationSCM.AppPublicKeyBase58Check))...)
	return data
}

func (deleteUserAssociationSCM *DeleteUserAssociationStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	targetUserPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeleteUserAssociationStateChangeMetadata.Decode: Problem reading TargetUserPublicKeyBase58Check")
	}
	deleteUserAssociationSCM.TargetUserPublicKeyBase58Check = string(targetUserPublicKeyBytes)
	appPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeleteUserAssociationStateChangeMetadata.Decode: Problem reading AppPublicKeyBase58Check")
	}
	deleteUserAssociationSCM.AppPublicKeyBase58Check = string(appPublicKeyBytes)
	return nil
}

func (deleteUserAssociationSCM *DeleteUserAssociationStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (deleteUserAssociationSCM *DeleteUserAssociationStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeDeleteUserAssociationStateChangeMetadata
}

type CreatePostAssociationStateChangeMetadata struct {
	PostEntry *PostEntry
}

func (createPostAssociationSCM *CreatePostAssociationStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, createPostAssociationSCM.PostEntry)...)
	return data
}

func (createPostAssociationSCM *CreatePostAssociationStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	if createPostAssociationSCM.PostEntry, err = DecodeDeSoEncoder(&PostEntry{}, rr); err != nil {
		return errors.Wrapf(err, "CreatePostAssociationStateChangeMetadata.Decode: Problem reading PostEntry")
	}

	return nil
}

func (createPostAssociationSCM *CreatePostAssociationStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (createPostAssociationSCM *CreatePostAssociationStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCreatePostAssociationStateChangeMetadata
}

type DeletePostAssociationStateChangeMetadata struct {
	AppPublicKeyBase58Check string
	PostEntry               *PostEntry
}

func (deletePostAssociationSCM *DeletePostAssociationStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeByteArray([]byte(deletePostAssociationSCM.AppPublicKeyBase58Check))...)
	data = append(data, EncodeToBytes(blockHeight, deletePostAssociationSCM.PostEntry)...)
	return data
}

func (deletePostAssociationSCM *DeletePostAssociationStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	appPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeletePostAssociationStateChangeMetadata.Decode: Problem reading AppPublicKeyBase58Check")
	}
	deletePostAssociationSCM.AppPublicKeyBase58Check = string(appPublicKeyBytes)

	if deletePostAssociationSCM.PostEntry, err = DecodeDeSoEncoder(&PostEntry{}, rr); err != nil {
		return errors.Wrapf(err, "DeletePostAssociationStateChangeMetadata.Decode: Problem reading PostEntry")
	}

	return nil
}

func (deletePostAssociationSCM *DeletePostAssociationStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (deletePostAssociationSCM *DeletePostAssociationStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeDeletePostAssociationStateChangeMetadata
}

type StakeRewardStateChangeMetadata struct {
	ValidatorPKID         *PKID
	StakerPKID            *PKID
	RewardNanos           uint64
	StakingRewardMethod   StakingRewardMethod
	IsValidatorCommission bool
}

func (stakeRewardSCM *StakeRewardStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, stakeRewardSCM.ValidatorPKID, skipMetadata...)...)
	data = append(data, EncodeToBytes(blockHeight, stakeRewardSCM.StakerPKID, skipMetadata...)...)
	data = append(data, UintToBuf(stakeRewardSCM.RewardNanos)...)
	data = append(data, UintToBuf(uint64(stakeRewardSCM.StakingRewardMethod))...)
	data = append(data, BoolToByte(stakeRewardSCM.IsValidatorCommission))
	return data
}

func (stakeRewardSCM *StakeRewardStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	if stakeRewardSCM.ValidatorPKID, err = DecodeDeSoEncoder(&PKID{}, rr); err != nil {
		return errors.Wrapf(err, "StakeRewardStateChangeMetadata.Decode: Problem reading ValidatorPKID")
	}
	if stakeRewardSCM.StakerPKID, err = DecodeDeSoEncoder(&PKID{}, rr); err != nil {
		return errors.Wrapf(err, "StakeRewardStateChangeMetadata.Decode: Problem reading StakerPKID")
	}
	stakeRewardSCM.RewardNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "StakeRewardStateChangeMetadata.Decode: Problem reading RewardNanos")
	}
	stakingRewardMethod, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "StakeRewardStateChangeMetadata.Decode: Problem reading StakingRewardMethod")
	}
	stakeRewardSCM.StakingRewardMethod = StakingRewardMethod(stakingRewardMethod)
	stakeRewardSCM.IsValidatorCommission, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "StakeRewardStateChangeMetadata.Decode: Problem reading IsValidatorCommission")
	}
	return nil
}

func (stakeRewardSCM *StakeRewardStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (stakeRewardSCM *StakeRewardStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeStakeRewardStateChangeMetadata
}

type UnjailValidatorStateChangeMetadata struct {
	ValidatorPKID         *PKID
	JailedAtEpochNumber   uint64
	UnjailedAtEpochNumber uint64
}

func (metadata *UnjailValidatorStateChangeMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, EncodeToBytes(blockHeight, metadata.ValidatorPKID, skipMetadata...)...)
	data = append(data, UintToBuf(metadata.JailedAtEpochNumber)...)
	data = append(data, UintToBuf(metadata.UnjailedAtEpochNumber)...)
	return data
}

func (metadata *UnjailValidatorStateChangeMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	if metadata.ValidatorPKID, err = DecodeDeSoEncoder(&PKID{}, rr); err != nil {
		return errors.Wrapf(err, "UnjailValidatorStateChangeMetadata.Decode: Problem reading ValidatorPKID")
	}
	metadata.JailedAtEpochNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UnjailValidatorStateChangeMetadata.Decode: Problem reading JailedAtEpochNumber")
	}
	metadata.UnjailedAtEpochNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UnjailValidatorStateChangeMetadata.Decode: Problem reading UnjailedAtEpochNumber")
	}
	return nil
}

func (metadata *UnjailValidatorStateChangeMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (metadata *UnjailValidatorStateChangeMetadata) GetEncoderType() EncoderType {
	return EncoderTypeUnjailValidatorStateChangeMetadata
}
