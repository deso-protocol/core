// json_adapters_extended.go
package lib

import (
	"encoding/hex"
	"sort"
)

// --------------------------------------------------------------------
// UtxoEntry adapter
// --------------------------------------------------------------------

// UtxoEntryJSON is a JSON-friendly view of UtxoEntry.
type UtxoEntryJSON struct {
	AmountNanos uint64 `json:"amount_nanos"`
	PublicKey   string `json:"public_key"`
	BlockHeight uint32 `json:"block_height"`
	UtxoType    string `json:"utxo_type"`
}

// ToJSON converts a UtxoEntry to its JSON view.
func (ue *UtxoEntry) ToJSON() UtxoEntryJSON {
	return UtxoEntryJSON{
		AmountNanos: ue.AmountNanos,
		// Here we encode the public key as hex. (You might choose base58 or another encoding.)
		PublicKey:   hex.EncodeToString(ue.PublicKey),
		BlockHeight: ue.BlockHeight,
		UtxoType:    ue.UtxoType.String(),
	}
}

// =====================================================================
// ProfileEntry Adapter
// =====================================================================

// ProfileEntryJSON is a JSON‐friendly view of a ProfileEntry.
type ProfileEntryJSON struct {
	PublicKey        string            `json:"public_key"`
	Username         string            `json:"username"`
	Description      string            `json:"description"`
	ProfilePic       string            `json:"profile_pic"`
	IsHidden         bool              `json:"is_hidden"`
	CreatorCoinEntry *CoinEntryJSON    `json:"creator_coin_entry"`
	DAOCoinEntry     *CoinEntryJSON    `json:"dao_coin_entry"`
	ExtraData        map[string]string `json:"extra_data"`
}

// ToJSON converts a ProfileEntry to its JSON view.
func (pe *ProfileEntry) ToJSON() ProfileEntryJSON {
	// Convert extra data values (which are []byte) to hex strings.
	extra := make(map[string]string)
	keys := make([]string, 0, len(pe.ExtraData))
	for k := range pe.ExtraData {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		extra[k] = hex.EncodeToString(pe.ExtraData[k])
	}

	return ProfileEntryJSON{
		// Here we encode the public key as hex. You might choose to use a different encoding if desired.
		PublicKey:   hex.EncodeToString(pe.PublicKey),
		Username:    string(pe.Username),    // assumes UTF-8 encoding
		Description: string(pe.Description), // assumes UTF-8 encoding
		//ProfilePic:       string(pe.ProfilePic),  // could be a data URL
		IsHidden: pe.IsHidden,
		// CreatorCoinEntry: pe.CreatorCoinEntry.ToJSON(),
		// DAOCoinEntry:     pe.DAOCoinEntry.ToJSON(),
		ExtraData: extra,
	}
}

// =====================================================================
// NFTEntry Adapter
// =====================================================================

// NFTEntryJSON is a JSON-friendly view of an NFTEntry.
type NFTEntryJSON struct {
	LastOwnerPKID              string            `json:"last_owner_pkid"`
	OwnerPKID                  string            `json:"owner_pkid"`
	NFTPostHash                string            `json:"nft_post_hash"`
	SerialNumber               uint64            `json:"serial_number"`
	IsForSale                  bool              `json:"is_for_sale"`
	MinBidAmountNanos          uint64            `json:"min_bid_amount_nanos"`
	UnlockableText             string            `json:"unlockable_text"`
	LastAcceptedBidAmountNanos uint64            `json:"last_accepted_bid_amount_nanos"`
	IsPending                  bool              `json:"is_pending"`
	IsBuyNow                   bool              `json:"is_buy_now"`
	BuyNowPriceNanos           uint64            `json:"buy_now_price_nanos"`
	ExtraData                  map[string]string `json:"extra_data"`
}

// ToJSON converts an NFTEntry to its JSON view.
func (nft *NFTEntry) ToJSON() NFTEntryJSON {
	extra := make(map[string]string)
	// For each extra data key, encode the value as hex.
	for k, v := range nft.ExtraData {
		extra[k] = hex.EncodeToString(v)
	}
	var postHashStr string
	if nft.NFTPostHash != nil {
		postHashStr = hex.EncodeToString((*nft.NFTPostHash)[:])
	} else {
		postHashStr = ""
	}

	var lastOwnerPKID string
	if nft.LastOwnerPKID != nil {
		lastOwnerPKID = nft.LastOwnerPKID.ToString()
	}
	var ownerPKID string
	if nft.OwnerPKID != nil {
		ownerPKID = nft.OwnerPKID.ToString()
	}

	return NFTEntryJSON{
		LastOwnerPKID:              lastOwnerPKID, // Assumes PKID has a String() method.
		OwnerPKID:                  ownerPKID,
		NFTPostHash:                postHashStr,
		SerialNumber:               nft.SerialNumber,
		IsForSale:                  nft.IsForSale,
		MinBidAmountNanos:          nft.MinBidAmountNanos,
		UnlockableText:             string(nft.UnlockableText),
		LastAcceptedBidAmountNanos: nft.LastAcceptedBidAmountNanos,
		IsPending:                  nft.IsPending,
		IsBuyNow:                   nft.IsBuyNow,
		BuyNowPriceNanos:           nft.BuyNowPriceNanos,
		ExtraData:                  extra,
	}
}

// =====================================================================
// NFTBidEntry Adapter
// =====================================================================

// NFTBidEntryJSON is a JSON-friendly view of an NFTBidEntry.
type NFTBidEntryJSON struct {
	BidderPKID          string  `json:"bidder_pkid"`
	NFTPostHash         string  `json:"nft_post_hash"`
	SerialNumber        uint64  `json:"serial_number"`
	BidAmountNanos      uint64  `json:"bid_amount_nanos"`
	AcceptedBlockHeight *uint32 `json:"accepted_block_height,omitempty"`
}

// ToJSON converts an NFTBidEntry to its JSON view.
func (bid *NFTBidEntry) ToJSON() NFTBidEntryJSON {

	var bidderPKID string
	if bid.BidderPKID != nil {
		bidderPKID = bid.BidderPKID.ToString()
	}
	var nftPostHash string
	if bid.NFTPostHash != nil {
		nftPostHash = hex.EncodeToString((*bid.NFTPostHash)[:])
	}

	return NFTBidEntryJSON{
		BidderPKID:          bidderPKID,
		NFTPostHash:         nftPostHash,
		SerialNumber:        bid.SerialNumber,
		BidAmountNanos:      bid.BidAmountNanos,
		AcceptedBlockHeight: bid.AcceptedBlockHeight,
	}
}

// =====================================================================
// PostEntry Adapter
// =====================================================================

// PostEntryJSON is a JSON-friendly view of a PostEntry.
type PostEntryJSON struct {
	PostHash                         string            `json:"post_hash"`
	PosterPublicKey                  string            `json:"poster_public_key"`
	ParentStakeID                    string            `json:"parent_stake_id,omitempty"`
	Body                             string            `json:"body"`
	RepostedPostHash                 string            `json:"reposted_post_hash,omitempty"`
	IsQuotedRepost                   bool              `json:"is_quoted_repost"`
	CreatorBasisPoints               uint64            `json:"creator_basis_points"`
	StakeMultipleBasisPoints         uint64            `json:"stake_multiple_basis_points"`
	ConfirmationBlockHeight          uint32            `json:"confirmation_block_height"`
	TimestampNanos                   uint64            `json:"timestamp_nanos"`
	IsHidden                         bool              `json:"is_hidden"`
	LikeCount                        uint64            `json:"like_count"`
	RepostCount                      uint64            `json:"repost_count"`
	QuoteRepostCount                 uint64            `json:"quote_repost_count"`
	DiamondCount                     uint64            `json:"diamond_count"`
	CommentCount                     uint64            `json:"comment_count"`
	IsPinned                         bool              `json:"is_pinned"`
	IsNFT                            bool              `json:"is_nft"`
	NumNFTCopies                     uint64            `json:"num_nft_copies"`
	NumNFTCopiesForSale              uint64            `json:"num_nft_copies_for_sale"`
	NumNFTCopiesBurned               uint64            `json:"num_nft_copies_burned"`
	HasUnlockable                    bool              `json:"has_unlockable"`
	NFTRoyaltyToCreatorBasisPoints   uint64            `json:"nft_royalty_to_creator_basis_points"`
	NFTRoyaltyToCoinBasisPoints      uint64            `json:"nft_royalty_to_coin_basis_points"`
	AdditionalNFTRoyaltiesToCreators map[string]uint64 `json:"additional_nft_royalties_to_creators_basis_points"`
	AdditionalNFTRoyaltiesToCoins    map[string]uint64 `json:"additional_nft_royalties_to_coins_basis_points"`
	PostExtraData                    map[string]string `json:"post_extra_data"`
	IsFrozen                         bool              `json:"is_frozen"`
}

// ToJSON converts a PostEntry to its JSON view.
func (pe *PostEntry) ToJSON() PostEntryJSON {
	extra := make(map[string]string)
	// Sort keys to have deterministic JSON.
	keys := make([]string, 0, len(pe.PostExtraData))
	for k := range pe.PostExtraData {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		extra[k] = hex.EncodeToString(pe.PostExtraData[k])
	}

	creators := make(map[string]uint64)
	for pkid, val := range pe.AdditionalNFTRoyaltiesToCreatorsBasisPoints {
		creators[pkid.ToString()] = val
	}
	coins := make(map[string]uint64)
	for pkid, val := range pe.AdditionalNFTRoyaltiesToCoinsBasisPoints {
		coins[pkid.ToString()] = val
	}
	var repostHash string
	if pe.RepostedPostHash != nil {
		repostHash = hex.EncodeToString((*pe.RepostedPostHash)[:])
	}
	var parentStake string
	if len(pe.ParentStakeID) > 0 {
		parentStake = hex.EncodeToString(pe.ParentStakeID)
	}
	var postHashStr string
	if pe.PostHash != nil {
		postHashStr = hex.EncodeToString((*pe.PostHash)[:])
	} else {
		postHashStr = ""
	}
	return PostEntryJSON{
		PostHash:                         postHashStr,
		PosterPublicKey:                  hex.EncodeToString(pe.PosterPublicKey),
		ParentStakeID:                    parentStake,
		Body:                             string(pe.Body),
		RepostedPostHash:                 repostHash,
		IsQuotedRepost:                   pe.IsQuotedRepost,
		CreatorBasisPoints:               pe.CreatorBasisPoints,
		StakeMultipleBasisPoints:         pe.StakeMultipleBasisPoints,
		ConfirmationBlockHeight:          pe.ConfirmationBlockHeight,
		TimestampNanos:                   pe.TimestampNanos,
		IsHidden:                         pe.IsHidden,
		LikeCount:                        pe.LikeCount,
		RepostCount:                      pe.RepostCount,
		QuoteRepostCount:                 pe.QuoteRepostCount,
		DiamondCount:                     pe.DiamondCount,
		CommentCount:                     pe.CommentCount,
		IsPinned:                         pe.IsPinned,
		IsNFT:                            pe.IsNFT,
		NumNFTCopies:                     pe.NumNFTCopies,
		NumNFTCopiesForSale:              pe.NumNFTCopiesForSale,
		NumNFTCopiesBurned:               pe.NumNFTCopiesBurned,
		HasUnlockable:                    pe.HasUnlockable,
		NFTRoyaltyToCreatorBasisPoints:   pe.NFTRoyaltyToCreatorBasisPoints,
		NFTRoyaltyToCoinBasisPoints:      pe.NFTRoyaltyToCoinBasisPoints,
		AdditionalNFTRoyaltiesToCreators: creators,
		AdditionalNFTRoyaltiesToCoins:    coins,
		PostExtraData:                    extra,
		IsFrozen:                         pe.IsFrozen,
	}
}

// =====================================================================
// DAO Operations Adapter: DAOCoinLimitOrderEntry
// =====================================================================

// DAOCoinLimitOrderEntryJSON is a JSON view of a DAO coin limit order.
type DAOCoinLimitOrderEntryJSON struct {
	OrderID                              string `json:"order_id"`
	TransactorPKID                       string `json:"transactor_pkid"`
	BuyingDAOCoinCreatorPKID             string `json:"buying_dao_coin_creator_pkid"`
	SellingDAOCoinCreatorPKID            string `json:"selling_dao_coin_creator_pkid"`
	ScaledExchangeRateCoinsToSellPerCoin string `json:"scaled_exchange_rate_coins_to_sell_per_coin_to_buy"`
	QuantityToFillInBaseUnits            string `json:"quantity_to_fill_in_base_units"`
	OperationType                        string `json:"operation_type"`
	FillType                             string `json:"fill_type"`
	BlockHeight                          uint32 `json:"block_height"`
}

// ToJSON converts a DAOCoinLimitOrderEntry to its JSON view.
func (order *DAOCoinLimitOrderEntry) ToJSON() DAOCoinLimitOrderEntryJSON {
	opType := ""
	switch order.OperationType {
	case DAOCoinLimitOrderOperationTypeASK:
		opType = "ASK"
	case DAOCoinLimitOrderOperationTypeBID:
		opType = "BID"
	default:
		opType = "UNKNOWN"
	}
	fillType := ""
	switch order.FillType {
	case DAOCoinLimitOrderFillTypeGoodTillCancelled:
		fillType = "GoodTillCancelled"
	case DAOCoinLimitOrderFillTypeImmediateOrCancel:
		fillType = "ImmediateOrCancel"
	case DAOCoinLimitOrderFillTypeFillOrKill:
		fillType = "FillOrKill"
	default:
		fillType = "UNKNOWN"
	}
	var scaledRate, quantity string
	if order.ScaledExchangeRateCoinsToSellPerCoinToBuy != nil {
		scaledRate = order.ScaledExchangeRateCoinsToSellPerCoinToBuy.String()
	}
	if order.QuantityToFillInBaseUnits != nil {
		quantity = order.QuantityToFillInBaseUnits.String()
	}
	orderIDStr := ""
	if order.OrderID != nil {
		orderIDStr = order.OrderID.String()
	}

	transactorPKID := ""
	if order.TransactorPKID != nil {
		transactorPKID = order.TransactorPKID.ToString()
	}
	sellingDAOCoinCreatorPKID := ""
	if order.SellingDAOCoinCreatorPKID != nil {
		sellingDAOCoinCreatorPKID = order.SellingDAOCoinCreatorPKID.ToString()
	}
	buyingDAOCoinCreatorPKID := ""
	if order.BuyingDAOCoinCreatorPKID != nil {
		buyingDAOCoinCreatorPKID = order.BuyingDAOCoinCreatorPKID.ToString()
	}
	return DAOCoinLimitOrderEntryJSON{
		OrderID:                              orderIDStr,
		TransactorPKID:                       transactorPKID,
		BuyingDAOCoinCreatorPKID:             buyingDAOCoinCreatorPKID,
		SellingDAOCoinCreatorPKID:            sellingDAOCoinCreatorPKID,
		ScaledExchangeRateCoinsToSellPerCoin: scaledRate,
		QuantityToFillInBaseUnits:            quantity,
		OperationType:                        opType,
		FillType:                             fillType,
		BlockHeight:                          order.BlockHeight,
	}
}

// =====================================================================
// DAO Operations Adapter: FilledDAOCoinLimitOrder
// =====================================================================

// FilledDAOCoinLimitOrderJSON is a JSON view of a filled DAO coin limit order.
type FilledDAOCoinLimitOrderJSON struct {
	OrderID                       string `json:"order_id"`
	TransactorPKID                string `json:"transactor_pkid"`
	BuyingDAOCoinCreatorPKID      string `json:"buying_dao_coin_creator_pkid"`
	SellingDAOCoinCreatorPKID     string `json:"selling_dao_coin_creator_pkid"`
	CoinQuantityInBaseUnitsBought string `json:"coin_quantity_in_base_units_bought"`
	CoinQuantityInBaseUnitsSold   string `json:"coin_quantity_in_base_units_sold"`
	IsFulfilled                   bool   `json:"is_fulfilled"`
}

// ToJSON converts a FilledDAOCoinLimitOrder to its JSON view.
func (filledOrder *FilledDAOCoinLimitOrder) ToJSON() FilledDAOCoinLimitOrderJSON {
	var qtyBought, qtySold string
	if filledOrder.CoinQuantityInBaseUnitsBought != nil {
		qtyBought = filledOrder.CoinQuantityInBaseUnitsBought.String()
	}
	if filledOrder.CoinQuantityInBaseUnitsSold != nil {
		qtySold = filledOrder.CoinQuantityInBaseUnitsSold.String()
	}
	orderIDStr := ""
	if filledOrder.OrderID != nil {
		orderIDStr = filledOrder.OrderID.String()
	}
	transactorPKID := ""
	if filledOrder.TransactorPKID != nil {
		transactorPKID = filledOrder.TransactorPKID.ToString()
	}
	sellingDAOCoinCreatorPKID := ""
	if filledOrder.SellingDAOCoinCreatorPKID != nil {
		sellingDAOCoinCreatorPKID = filledOrder.SellingDAOCoinCreatorPKID.ToString()
	}
	buyingDAOCoinCreatorPKID := ""
	if filledOrder.BuyingDAOCoinCreatorPKID != nil {
		buyingDAOCoinCreatorPKID = filledOrder.BuyingDAOCoinCreatorPKID.ToString()
	}
	return FilledDAOCoinLimitOrderJSON{
		OrderID:                       orderIDStr,
		TransactorPKID:                transactorPKID,
		BuyingDAOCoinCreatorPKID:      buyingDAOCoinCreatorPKID,
		SellingDAOCoinCreatorPKID:     sellingDAOCoinCreatorPKID,
		CoinQuantityInBaseUnitsBought: qtyBought,
		CoinQuantityInBaseUnitsSold:   qtySold,
		IsFulfilled:                   filledOrder.IsFulfilled,
	}
}

// =====================================================================
// DESO Operations Adapter: CoinEntry
// =====================================================================

// CoinEntryJSON is a JSON-friendly view of a CoinEntry.
type CoinEntryJSON struct {
	CreatorBasisPoints              uint64 `json:"creator_basis_points"`
	DeSoLockedNanos                 uint64 `json:"deso_locked_nanos"`
	NumberOfHolders                 uint64 `json:"number_of_holders"`
	CoinsInCirculationNanos         string `json:"coins_in_circulation_nanos"`
	CoinWatermarkNanos              uint64 `json:"coin_watermark_nanos"`
	MintingDisabled                 bool   `json:"minting_disabled"`
	TransferRestrictionStatus       string `json:"transfer_restriction_status"`
	LockupTransferRestrictionStatus string `json:"lockup_transfer_restriction_status,omitempty"`
}

// ToJSON converts a CoinEntry to its JSON view.
func (ce *CoinEntry) ToJSON() CoinEntryJSON {
	var transStatus string
	switch ce.TransferRestrictionStatus {
	case TransferRestrictionStatusUnrestricted:
		transStatus = "Unrestricted"
	case TransferRestrictionStatusProfileOwnerOnly:
		transStatus = "ProfileOwnerOnly"
	case TransferRestrictionStatusDAOMembersOnly:
		transStatus = "DAOMembersOnly"
	case TransferRestrictionStatusPermanentlyUnrestricted:
		transStatus = "PermanentlyUnrestricted"
	default:
		transStatus = "Unknown"
	}
	var lockupStatus string
	switch ce.LockupTransferRestrictionStatus {
	case TransferRestrictionStatusUnrestricted:
		lockupStatus = "Unrestricted"
	case TransferRestrictionStatusProfileOwnerOnly:
		lockupStatus = "ProfileOwnerOnly"
	case TransferRestrictionStatusDAOMembersOnly:
		lockupStatus = "DAOMembersOnly"
	case TransferRestrictionStatusPermanentlyUnrestricted:
		lockupStatus = "PermanentlyUnrestricted"
	default:
		lockupStatus = ""
	}
	return CoinEntryJSON{
		CreatorBasisPoints:              ce.CreatorBasisPoints,
		DeSoLockedNanos:                 ce.DeSoLockedNanos,
		NumberOfHolders:                 ce.NumberOfHolders,
		CoinsInCirculationNanos:         ce.CoinsInCirculationNanos.String(),
		CoinWatermarkNanos:              ce.CoinWatermarkNanos,
		MintingDisabled:                 ce.MintingDisabled,
		TransferRestrictionStatus:       transStatus,
		LockupTransferRestrictionStatus: lockupStatus,
	}
}

// =====================================================================
// DESO Operations Adapter: DeSoBalanceEntry
// =====================================================================

// DeSoBalanceEntryJSON is a JSON view of a DeSoBalanceEntry.
type DeSoBalanceEntryJSON struct {
	PublicKey    string `json:"public_key"`
	BalanceNanos uint64 `json:"balance_nanos"`
}

// ToJSON converts a DeSoBalanceEntry to its JSON view.
func (de *DeSoBalanceEntry) ToJSON() DeSoBalanceEntryJSON {
	return DeSoBalanceEntryJSON{
		PublicKey:    hex.EncodeToString(de.PublicKey),
		BalanceNanos: de.BalanceNanos,
	}
}

// =====================================================================
// (Optional) Custom JSON Marshaling Example
// =====================================================================

// You can have the types themselves implement json.Marshaler so that they marshal automatically.
// For instance:
//
// func (nft *NFTEntry) MarshalJSON() ([]byte, error) {
//     return json.Marshal(nft.ToJSON())
// }
//
// And similarly for the other types.
//
// =====================================================================
// Example Usage:
//
// func main() {
//     // For example, converting an NFTEntry to JSON.
//     nft := &NFTEntry{
//         // … initialize fields …
//     }
//     jsonData, err := json.MarshalIndent(nft.ToJSON(), "", "  ")
//     if err != nil {
//         panic(err)
//     }
//     fmt.Println(string(jsonData))
// }
//
