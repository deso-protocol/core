package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/gernest/mention"
	"github.com/uptrace/bun"
	"reflect"
	"strings"
	"time"

	"github.com/golang/glog"
)

type Notifier struct {
	coreChain *Blockchain
	postgres  *Postgres

	// Shortcut to postgres
	db  *bun.DB
	ctx context.Context

	// Shortcut to coreChain.db
	badger *badger.DB
}

func NewNotifier(coreChain *Blockchain, postgres *Postgres) *Notifier {
	return &Notifier{
		coreChain: coreChain,
		postgres:  postgres,
		db:        postgres.db,
		ctx:       postgres.ctx,
		badger:    coreChain.db,
	}
}

func (notifier *Notifier) Update() error {
	// Fetch all the blocks we haven't processed notifications for in groups of 10,000
	var blocks []*PGBlock
	_, err := notifier.db.NewSelect().Model(&blocks).Where("notified = false").Limit(10_000).Exec(notifier.ctx)
	if err != nil {
		return err
	}

	for _, block := range blocks {
		var notifications []*PGNotification
		var transactions []*PGTransaction
		_, err = notifier.db.NewSelect().Model(&transactions).Where("block_hash = ?", block.Hash).
			Relation("Outputs").Relation("PGMetadataLike").Relation("PGMetadataFollow").
			Relation("PGMetadataCreatorCoin").Relation("PGMetadataCreatorCoinTransfer").
			Relation("PGMetadataSubmitPost").Exec(notifier.ctx)
		// TODO: Add NFTs
		if err != nil {
			return err
		}

		glog.Infof("Notifier: Found %d transactions in block %v at height %d", len(transactions), block.Hash, block.Height)

		for _, transaction := range transactions {
			if transaction.Type == TxnTypeBasicTransfer {
				extraData := transaction.ExtraData
				for _, output := range transaction.Outputs {
					if !reflect.DeepEqual(output.PublicKey, transaction.PublicKey) {
						notification := &PGNotification{
							TransactionHash: transaction.Hash,
							Mined:           true,
							ToUser:          output.PublicKey,
							FromUser:        transaction.PublicKey,
							Type:            NotificationSendDESO,
							Amount:          output.AmountNanos,
							Timestamp:       block.Timestamp,
						}
						diamondLevelBytes, hasDiamondLevel := extraData[DiamondLevelKey]
						diamondPostBytes, hasDiamondPost := extraData[DiamondPostHashKey]
						if hasDiamondLevel && hasDiamondPost {
							diamondLevel, bytesRead := Varint(diamondLevelBytes)
							if bytesRead > 0 {
								notification.Type = NotificationDESODiamond
								notification.Amount = uint64(diamondLevel)
								notification.PostHash = &BlockHash{}
								copy(notification.PostHash[:], diamondPostBytes)
							}
						}
						notifications = append(notifications, notification)
					}
				}
			} else if transaction.Type == TxnTypeLike {
				postHash := transaction.MetadataLike.LikedPostHash
				post := DBGetPostEntryByPostHash(notifier.badger, postHash)
				if post != nil {
					notifications = append(notifications, &PGNotification{
						TransactionHash: transaction.Hash,
						Mined:           true,
						ToUser:          post.PosterPublicKey,
						FromUser:        transaction.PublicKey,
						Type:            NotificationLike,
						PostHash:        postHash,
						Timestamp:       block.Timestamp,
					})
				}
			} else if transaction.Type == TxnTypeFollow {
				if !transaction.MetadataFollow.IsUnfollow {
					notifications = append(notifications, &PGNotification{
						TransactionHash: transaction.Hash,
						Mined:           true,
						ToUser:          transaction.MetadataFollow.FollowedPublicKey,
						FromUser:        transaction.PublicKey,
						Type:            NotificationFollow,
						Timestamp:       block.Timestamp,
					})
				}
			} else if transaction.Type == TxnTypeCreatorCoin {
				meta := transaction.MetadataCreatorCoin
				if meta.OperationType == CreatorCoinOperationTypeBuy {
					notifications = append(notifications, &PGNotification{
						TransactionHash: transaction.Hash,
						Mined:           true,
						ToUser:          meta.ProfilePublicKey,
						FromUser:        transaction.PublicKey,
						Type:            NotificationCoinPurchase,
						Amount:          meta.DESOToSellNanos,
						Timestamp:       block.Timestamp,
					})
				}
			} else if transaction.Type == TxnTypeCreatorCoinTransfer {
				meta := transaction.MetadataCreatorCoinTransfer
				extraData := transaction.ExtraData
				notification := &PGNotification{
					TransactionHash: transaction.Hash,
					Mined:           true,
					ToUser:          meta.ReceiverPublicKey,
					FromUser:        transaction.PublicKey,
					OtherUser:       meta.ProfilePublicKey,
					Timestamp:       block.Timestamp,
				}

				diamondLevelBytes, hasDiamondLevel := extraData[DiamondLevelKey]
				diamondPostBytes, hasDiamondPost := extraData[DiamondPostHashKey]
				if hasDiamondLevel && hasDiamondPost {
					diamondLevel, bytesRead := Varint(diamondLevelBytes)
					if bytesRead > 0 {
						notification.Type = NotificationCoinDiamond
						notification.Amount = uint64(diamondLevel)
						notification.PostHash = &BlockHash{}
						copy(notification.PostHash[:], diamondPostBytes)
					}
				}

				// If we failed to extract diamond metadata record it as a normal transfer
				if notification.Type == NotificationUnknown {
					notification.Type = NotificationCoinTransfer
					notification.Amount = meta.CreatorCoinToTransferNanos
				}

				notifications = append(notifications, notification)
			} else if transaction.Type == TxnTypeSubmitPost {
				meta := transaction.MetadataSubmitPost

				// Process replies
				if len(meta.ParentStakeID) == HashSizeBytes {
					postEntry := DBGetPostEntryByPostHash(notifier.badger, meta.ParentStakeID)
					if postEntry != nil {
						notifications = append(notifications, &PGNotification{
							TransactionHash: transaction.Hash,
							Mined:           true,
							ToUser:          postEntry.PosterPublicKey,
							FromUser:        transaction.PublicKey,
							Type:            NotificationPostReply,
							PostHash:        meta.ParentStakeID,
							Timestamp:       block.Timestamp,
						})
					}
				}

				// Process mentions
				bodyObj := &DeSoBodySchema{}
				if err := json.Unmarshal([]byte(meta.Body), &bodyObj); err == nil {
					terminators := []rune(" ,.\n&*()-+~'\"[]{}")
					dollarTagsFound := mention.GetTagsAsUniqueStrings('$', string(bodyObj.Body), terminators...)
					atTagsFound := mention.GetTagsAsUniqueStrings('@', string(bodyObj.Body), terminators...)
					tagsFound := append(dollarTagsFound, atTagsFound...)
					for _, tag := range tagsFound {

						profileFound := DBGetProfileEntryForUsername(notifier.badger, []byte(strings.ToLower(strings.Trim(tag, ",.\n&*()-+~'\"[]{}!?^%#"))))
						// Don't worry about tags that don't line up to a profile.
						if profileFound == nil {
							continue
						}

						notifications = append(notifications, &PGNotification{
							TransactionHash: transaction.Hash,
							Mined:           true,
							ToUser:          profileFound.PublicKey,
							FromUser:        transaction.PublicKey,
							Type:            NotificationPostMention,
							PostHash:        meta.PostHashToModify,
							Timestamp:       block.Timestamp,
						})
					}
				}

				// Process reposts
				if postBytes, isRepost := transaction.ExtraData[RepostedPostHash]; isRepost {
					postHash := &BlockHash{}
					copy(postHash[:], postBytes)
					post := DBGetPostEntryByPostHash(notifier.badger, postHash)
					if post != nil {
						notifications = append(notifications, &PGNotification{
							TransactionHash: transaction.Hash,
							Mined:           true,
							ToUser:          post.PosterPublicKey,
							FromUser:        transaction.PublicKey,
							Type:            NotificationPostRepost,
							PostHash:        postHash,
							Timestamp:       block.Timestamp,
						})
					}
				}
			}
		}

		// Insert the new notifications if we created any
		if len(notifications) > 0 {
			_, err = notifier.db.NewInsert().Model(&notifications).On("CONFLICT DO NOTHING").
				Returning("NULL").Exec(notifier.ctx)
			if err != nil {
				return err
			}
		}

		// Mark the block as notified
		block.Notified = true
		_, err = notifier.db.NewUpdate().Model(block).WherePK().Column("notified").
			Returning("NULL").Exec(notifier.ctx)
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
