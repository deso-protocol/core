package lib

import (
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/db"
	"github.com/deso-protocol/core/network"
	"github.com/deso-protocol/core/types"
	"github.com/dgraph-io/badger/v3"
	"github.com/gernest/mention"
	"github.com/go-pg/pg/v10"
	"reflect"
	"strings"
	"time"

	"github.com/golang/glog"
)

type Notifier struct {
	coreChain *Blockchain
	postgres  *types.Postgres

	// Shortcut to postgres.db
	db *pg.DB

	// Shortcut to coreChain.db
	badger *badger.DB
}

func NewNotifier(coreChain *Blockchain, postgres *types.Postgres) *Notifier {
	return &Notifier{
		coreChain: coreChain,
		postgres:  postgres,
		db:        postgres.db,
		badger:    coreChain.db,
	}
}

func (notifier *Notifier) Update() error {
	// Fetch all the blocks we haven't processed notifications for in groups of 10,000
	var blocks []*types.PGBlock
	err := notifier.db.Model(&blocks).Where("notified = false").Limit(10_000).Select()
	if err != nil {
		return err
	}

	for _, block := range blocks {
		var notifications []*types.PGNotification
		var transactions []*types.PGTransaction
		err = notifier.db.Model(&transactions).Where("block_hash = ?", block.Hash).
			Relation("Outputs").Relation("PGMetadataLike").Relation("PGMetadataFollow").
			Relation("PGMetadataCreatorCoin").Relation("PGMetadataCreatorCoinTransfer").
			Relation("PGMetadataSubmitPost").Select()
		// TODO: Add NFTs
		if err != nil {
			return err
		}

		glog.Infof("Notifier: Found %d transactions in block %v at height %d", len(transactions), block.Hash, block.Height)

		for _, transaction := range transactions {
			if transaction.Type == network.TxnTypeBasicTransfer {
				extraData := transaction.ExtraData
				for _, output := range transaction.Outputs {
					if !reflect.DeepEqual(output.PublicKey, transaction.PublicKey) {
						notification := &types.PGNotification{
							TransactionHash: transaction.Hash,
							Mined:           true,
							ToUser:          output.PublicKey,
							FromUser:        transaction.PublicKey,
							Type:            types.NotificationSendDESO,
							Amount:          output.AmountNanos,
							Timestamp:       block.Timestamp,
						}
						diamondLevelBytes, hasDiamondLevel := extraData[types.DiamondLevelKey]
						diamondPostBytes, hasDiamondPost := extraData[types.DiamondPostHashKey]
						if hasDiamondLevel && hasDiamondPost {
							diamondLevel, bytesRead := network.Varint(diamondLevelBytes)
							if bytesRead > 0 {
								notification.Type = types.NotificationDESODiamond
								notification.Amount = uint64(diamondLevel)
								notification.PostHash = &types.BlockHash{}
								copy(notification.PostHash[:], diamondPostBytes)
							}
						}
						notifications = append(notifications, notification)
					}
				}
			} else if transaction.Type == network.TxnTypeLike {
				postHash := transaction.MetadataLike.LikedPostHash
				post := db.DBGetPostEntryByPostHash(notifier.badger, postHash)
				if post != nil {
					notifications = append(notifications, &types.PGNotification{
						TransactionHash: transaction.Hash,
						Mined:           true,
						ToUser:          post.PosterPublicKey,
						FromUser:        transaction.PublicKey,
						Type:            types.NotificationLike,
						PostHash:        postHash,
						Timestamp:       block.Timestamp,
					})
				}
			} else if transaction.Type == network.TxnTypeFollow {
				if !transaction.MetadataFollow.IsUnfollow {
					notifications = append(notifications, &types.PGNotification{
						TransactionHash: transaction.Hash,
						Mined:           true,
						ToUser:          transaction.MetadataFollow.FollowedPublicKey,
						FromUser:        transaction.PublicKey,
						Type:            types.NotificationFollow,
						Timestamp:       block.Timestamp,
					})
				}
			} else if transaction.Type == network.TxnTypeCreatorCoin {
				meta := transaction.MetadataCreatorCoin
				if meta.OperationType == network.CreatorCoinOperationTypeBuy {
					notifications = append(notifications, &types.PGNotification{
						TransactionHash: transaction.Hash,
						Mined:           true,
						ToUser:          meta.ProfilePublicKey,
						FromUser:        transaction.PublicKey,
						Type:            types.NotificationCoinPurchase,
						Amount:          meta.DeSoToSellNanos,
						Timestamp:       block.Timestamp,
					})
				}
			} else if transaction.Type == network.TxnTypeCreatorCoinTransfer {
				meta := transaction.MetadataCreatorCoinTransfer
				extraData := transaction.ExtraData
				notification := &types.PGNotification{
					TransactionHash: transaction.Hash,
					Mined:           true,
					ToUser:          meta.ReceiverPublicKey,
					FromUser:        transaction.PublicKey,
					OtherUser:       meta.ProfilePublicKey,
					Timestamp:       block.Timestamp,
				}

				diamondLevelBytes, hasDiamondLevel := extraData[types.DiamondLevelKey]
				diamondPostBytes, hasDiamondPost := extraData[types.DiamondPostHashKey]
				if hasDiamondLevel && hasDiamondPost {
					diamondLevel, bytesRead := network.Varint(diamondLevelBytes)
					if bytesRead > 0 {
						notification.Type = types.NotificationCoinDiamond
						notification.Amount = uint64(diamondLevel)
						notification.PostHash = &types.BlockHash{}
						copy(notification.PostHash[:], diamondPostBytes)
					}
				}

				// If we failed to extract diamond metadata record it as a normal transfer
				if notification.Type == types.NotificationUnknown {
					notification.Type = types.NotificationCoinTransfer
					notification.Amount = meta.CreatorCoinToTransferNanos
				}

				notifications = append(notifications, notification)
			} else if transaction.Type == network.TxnTypeSubmitPost {
				meta := transaction.MetadataSubmitPost

				// Process replies
				if len(meta.ParentStakeID) == types.HashSizeBytes {
					postEntry := db.DBGetPostEntryByPostHash(notifier.badger, meta.ParentStakeID)
					if postEntry != nil {
						notifications = append(notifications, &types.PGNotification{
							TransactionHash: transaction.Hash,
							Mined:           true,
							ToUser:          postEntry.PosterPublicKey,
							FromUser:        transaction.PublicKey,
							Type:            types.NotificationPostReply,
							PostHash:        meta.ParentStakeID,
							Timestamp:       block.Timestamp,
						})
					}
				}

				// Process mentions
				bodyObj := &network.DeSoBodySchema{}
				if err := json.Unmarshal(meta.Body, &bodyObj); err == nil {
					terminators := []rune(" ,.\n&*()-+~'\"[]{}")
					dollarTagsFound := mention.GetTagsAsUniqueStrings('$', string(bodyObj.Body), terminators...)
					atTagsFound := mention.GetTagsAsUniqueStrings('@', string(bodyObj.Body), terminators...)

					tagsFound := append(dollarTagsFound, atTagsFound...)
					for _, tag := range tagsFound {

						profileFound := db.DBGetProfileEntryForUsername(notifier.badger, []byte(strings.ToLower(strings.Trim(tag, ",.\n&*()-+~'\"[]{}!?^%#"))))
						// Don't worry about tags that don't line up to a profile.
						if profileFound == nil {
							continue
						}

						notifications = append(notifications, &types.PGNotification{
							TransactionHash: transaction.Hash,
							Mined:           true,
							ToUser:          profileFound.PublicKey,
							FromUser:        transaction.PublicKey,
							Type:            types.NotificationPostMention,
							PostHash:        meta.PostHashToModify,
							Timestamp:       block.Timestamp,
						})
					}
				}

				// Process reposts
				if postBytes, isRepost := transaction.ExtraData[types.RepostedPostHash]; isRepost {
					postHash := &types.BlockHash{}
					copy(postHash[:], postBytes)
					post := db.DBGetPostEntryByPostHash(notifier.badger, postHash)
					if post != nil {
						notifications = append(notifications, &types.PGNotification{
							TransactionHash: transaction.Hash,
							Mined:           true,
							ToUser:          post.PosterPublicKey,
							FromUser:        transaction.PublicKey,
							Type:            types.NotificationPostRepost,
							PostHash:        postHash,
							Timestamp:       block.Timestamp,
						})
					}
				}
			}
		}

		// Insert the new notifications if we created any
		if len(notifications) > 0 {
			_, err = notifier.db.Model(&notifications).OnConflict("DO NOTHING").Returning("NULL").Insert()
			if err != nil {
				return err
			}
		}

		// Mark the block as notified
		block.Notified = true
		_, err = notifier.db.Model(block).WherePK().Column("notified").Returning("NULL").Update()
		if err != nil {
			return err
		}
	}

	return nil
}

func (notifier *Notifier) notifyBasicTransfers() {

}

func (notifier *Notifier) Start() {
	glog.Info("Notifier: Starting update thread")

	// Run a loop to continuously process notifications
	go func() {
		for {
			//if notifier.coreChain.ChainState() == SyncStateFullyCurrent {
			//	// If the node is fully synced, then try an update.
			//	err := notifier.Update()
			//	if err != nil {
			//		glog.Error(fmt.Errorf("Notifier: Problem running update: %v", err))
			//	}
			//} else {
			//	glog.Debugf("Notifier: Waiting for node to sync before updating")
			//}

			err := notifier.Update()
			if err != nil {
				glog.Error(fmt.Errorf("Notifier: Problem running update: %v", err))
			}
			time.Sleep(1 * time.Second)
		}
	}()

}
