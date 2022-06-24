package lib

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/davecgh/go-spew/spew"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"math"
	"reflect"
	"sort"
)

func (bav *UtxoView) _getRepostEntryForRepostKey(repostKey *RepostKey) *RepostEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.RepostKeyToRepostEntry[*repostKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	repostEntry := DbReposterPubKeyRepostedPostHashToRepostEntry(bav.Handle, bav.Snapshot,
		repostKey.ReposterPubKey[:], repostKey.RepostedPostHash)
	if repostEntry != nil {
		bav._setRepostEntryMappings(repostEntry)
	}
	return repostEntry
}

func (bav *UtxoView) _setRepostEntryMappings(repostEntry *RepostEntry) {
	// This function shouldn't be called with nil.
	if repostEntry == nil {
		glog.Errorf("_setRepostEntryMappings: Called with nil RepostEntry; " +
			"this should never happen.")
		return
	}

	repostKey := MakeRepostKey(repostEntry.ReposterPubKey, *repostEntry.RepostedPostHash)
	bav.RepostKeyToRepostEntry[repostKey] = repostEntry
}

func (bav *UtxoView) _deleteRepostEntryMappings(repostEntry *RepostEntry) {

	if repostEntry == nil {
		glog.Errorf("_deleteRepostEntryMappings: called with nil RepostEntry; " +
			"this should never happen")
		return
	}
	// Create a tombstone entry.
	tombstoneRepostEntry := *repostEntry
	tombstoneRepostEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setRepostEntryMappings(&tombstoneRepostEntry)
}

func (bav *UtxoView) _setDiamondEntryMappings(diamondEntry *DiamondEntry) {
	// This function shouldn't be called with nil.
	if diamondEntry == nil {
		glog.Errorf("_setDiamondEntryMappings: Called with nil DiamondEntry; " +
			"this should never happen.")
		return
	}

	diamondKey := MakeDiamondKey(
		diamondEntry.SenderPKID, diamondEntry.ReceiverPKID, diamondEntry.DiamondPostHash)
	bav.DiamondKeyToDiamondEntry[diamondKey] = diamondEntry
}

func (bav *UtxoView) _deleteDiamondEntryMappings(diamondEntry *DiamondEntry) {

	// Create a tombstone entry.
	tombstoneDiamondEntry := *diamondEntry
	tombstoneDiamondEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setDiamondEntryMappings(&tombstoneDiamondEntry)
}

func (bav *UtxoView) GetDiamondEntryForDiamondKey(diamondKey *DiamondKey) *DiamondEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	bavDiamondEntry, existsMapValue := bav.DiamondKeyToDiamondEntry[*diamondKey]
	if existsMapValue {
		return bavDiamondEntry
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	var diamondEntry *DiamondEntry
	if bav.Postgres != nil {
		diamond := bav.Postgres.GetDiamond(&diamondKey.SenderPKID, &diamondKey.ReceiverPKID, &diamondKey.DiamondPostHash)
		if diamond != nil {
			diamondEntry = &DiamondEntry{
				SenderPKID:      diamond.SenderPKID,
				ReceiverPKID:    diamond.ReceiverPKID,
				DiamondPostHash: diamond.DiamondPostHash,
				DiamondLevel:    int64(diamond.DiamondLevel),
			}
		}
	} else {
		diamondEntry = DbGetDiamondMappings(bav.Handle, bav.Snapshot,
			&diamondKey.ReceiverPKID, &diamondKey.SenderPKID, &diamondKey.DiamondPostHash)
	}

	if diamondEntry != nil {
		bav._setDiamondEntryMappings(diamondEntry)
	}

	return diamondEntry
}

func (bav *UtxoView) GetPostEntryForPostHash(postHash *BlockHash) *PostEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.PostHashToPostEntry[*postHash]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	if bav.Postgres != nil {
		post := bav.Postgres.GetPost(postHash)
		if post != nil {
			return bav.setPostMappings(post)
		}
		return nil
	} else {
		dbPostEntry := DBGetPostEntryByPostHash(bav.Handle, bav.Snapshot, postHash)
		if dbPostEntry != nil {
			bav._setPostEntryMappings(dbPostEntry)
		}
		return dbPostEntry
	}
}

func (bav *UtxoView) GetDiamondEntryMapForPublicKey(publicKey []byte, fetchYouDiamonded bool,
) (_pkidToDiamondsMap map[PKID][]*DiamondEntry, _err error) {
	pkidEntry := bav.GetPKIDForPublicKey(publicKey)

	dbPKIDToDiamondsMap, err := DbGetPKIDsThatDiamondedYouMap(bav.Handle, pkidEntry.PKID, fetchYouDiamonded)
	if err != nil {
		return nil, errors.Wrapf(err, "GetDiamondEntryMapForPublicKey: Error Getting "+
			"PKIDs that diamonded you map from the DB.")
	}

	// Load all of the diamondEntries into the view.
	for _, diamondEntryList := range dbPKIDToDiamondsMap {
		for _, diamondEntry := range diamondEntryList {
			diamondKey := &DiamondKey{
				SenderPKID:      *diamondEntry.SenderPKID,
				ReceiverPKID:    *diamondEntry.ReceiverPKID,
				DiamondPostHash: *diamondEntry.DiamondPostHash,
			}
			// If the diamond key is not in the view, add it to the view.
			if _, ok := bav.DiamondKeyToDiamondEntry[*diamondKey]; !ok {
				bav._setDiamondEntryMappings(diamondEntry)
			}
		}
	}

	// Iterate over all the diamondEntries in the view and build the final map.
	pkidToDiamondsMap := make(map[PKID][]*DiamondEntry)
	for _, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		if diamondEntry.isDeleted {
			continue
		}
		// Make sure the diamondEntry we are looking at is for the correct receiver public key.
		if !fetchYouDiamonded && reflect.DeepEqual(diamondEntry.ReceiverPKID, pkidEntry.PKID) {
			pkidToDiamondsMap[*diamondEntry.SenderPKID] = append(
				pkidToDiamondsMap[*diamondEntry.SenderPKID], diamondEntry)
		}

		// Make sure the diamondEntry we are looking at is for the correct sender public key.
		if fetchYouDiamonded && reflect.DeepEqual(diamondEntry.SenderPKID, pkidEntry.PKID) {
			pkidToDiamondsMap[*diamondEntry.ReceiverPKID] = append(
				pkidToDiamondsMap[*diamondEntry.ReceiverPKID], diamondEntry)
		}
	}

	return pkidToDiamondsMap, nil
}

func (bav *UtxoView) GetDiamondEntriesForSenderToReceiver(receiverPublicKey []byte, senderPublicKey []byte,
) (_diamondEntries []*DiamondEntry, _err error) {

	receiverPKIDEntry := bav.GetPKIDForPublicKey(receiverPublicKey)
	senderPKIDEntry := bav.GetPKIDForPublicKey(senderPublicKey)
	dbDiamondEntries, err := DbGetDiamondEntriesForSenderToReceiver(bav.Handle, receiverPKIDEntry.PKID, senderPKIDEntry.PKID)
	if err != nil {
		return nil, errors.Wrapf(err, "GetDiamondEntriesForGiverToReceiver: Error getting diamond entries from DB.")
	}

	// Load all of the diamondEntries into the view
	for _, diamondEntry := range dbDiamondEntries {
		diamondKey := &DiamondKey{
			SenderPKID:      *diamondEntry.SenderPKID,
			ReceiverPKID:    *diamondEntry.ReceiverPKID,
			DiamondPostHash: *diamondEntry.DiamondPostHash,
		}
		// If the diamond key is not in the view, add it to the view.
		if _, ok := bav.DiamondKeyToDiamondEntry[*diamondKey]; !ok {
			bav._setDiamondEntryMappings(diamondEntry)
		}
	}

	var diamondEntries []*DiamondEntry
	for _, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		if diamondEntry.isDeleted {
			continue
		}

		// Make sure the diamondEntry we are looking at is for the correct sender and receiver pair
		if reflect.DeepEqual(diamondEntry.ReceiverPKID, receiverPKIDEntry.PKID) &&
			reflect.DeepEqual(diamondEntry.SenderPKID, senderPKIDEntry.PKID) {
			diamondEntries = append(diamondEntries, diamondEntry)
		}
	}

	return diamondEntries, nil
}

func (bav *UtxoView) _setPostEntryMappings(postEntry *PostEntry) {
	// This function shouldn't be called with nil.
	if postEntry == nil {
		glog.Errorf("_setPostEntryMappings: Called with nil PostEntry; this should never happen.")
		return
	}

	// Add a mapping for the post.
	bav.PostHashToPostEntry[*postEntry.PostHash] = postEntry
}

func (bav *UtxoView) _deletePostEntryMappings(postEntry *PostEntry) {

	// Create a tombstone entry.
	tombstonePostEntry := *postEntry
	tombstonePostEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setPostEntryMappings(&tombstonePostEntry)
}

func (bav *UtxoView) setPostMappings(post *PGPost) *PostEntry {
	postEntry := post.NewPostEntry()

	// Add a mapping for the post.
	bav.PostHashToPostEntry[*post.PostHash] = postEntry

	return postEntry
}

func (bav *UtxoView) GetPostEntryReaderState(
	readerPK []byte, postEntry *PostEntry) *PostEntryReaderState {
	postEntryReaderState := &PostEntryReaderState{}

	// Get like state.
	postEntryReaderState.LikedByReader = bav.GetLikedByReader(readerPK, postEntry.PostHash)

	// Get repost state.
	postEntryReaderState.RepostPostHashHex, postEntryReaderState.RepostedByReader = bav.GetRepostPostEntryStateForReader(readerPK, postEntry.PostHash)

	// Get diamond state.
	senderPKID := bav.GetPKIDForPublicKey(readerPK)
	receiverPKID := bav.GetPKIDForPublicKey(postEntry.PosterPublicKey)
	if senderPKID == nil || receiverPKID == nil {
		glog.V(1).Infof(
			"GetPostEntryReaderState: Could not find PKID for reader PK: %s or poster PK: %s",
			PkToString(readerPK, bav.Params), PkToString(postEntry.PosterPublicKey, bav.Params))
	} else {
		diamondKey := MakeDiamondKey(senderPKID.PKID, receiverPKID.PKID, postEntry.PostHash)
		diamondEntry := bav.GetDiamondEntryForDiamondKey(&diamondKey)
		if diamondEntry != nil {
			postEntryReaderState.DiamondLevelBestowed = diamondEntry.DiamondLevel
		}
	}

	return postEntryReaderState
}

func (bav *UtxoView) GetRepostPostEntryStateForReader(readerPK []byte, postHash *BlockHash) (string, bool) {
	repostKey := MakeRepostKey(readerPK, *postHash)
	repostEntry := bav._getRepostEntryForRepostKey(&repostKey)
	if repostEntry == nil {
		return "", false
	}
	repostPostEntry := bav.GetPostEntryForPostHash(repostEntry.RepostPostHash)
	if repostPostEntry == nil {
		glog.Errorf("Could not find repost post entry from post hash: %v", repostEntry.RepostedPostHash)
		return "", false
	}
	// We include the PostHashHex of this user's post that reposts the current post to
	// handle undo-ing (AKA hiding) a repost.
	// If the user's repost of this post is hidden, we set RepostedByReader to false.
	return hex.EncodeToString(repostEntry.RepostPostHash[:]), !repostPostEntry.IsHidden
}

func (bav *UtxoView) GetCommentEntriesForParentStakeID(parentStakeID []byte) ([]*PostEntry, error) {
	if bav.Postgres != nil {
		posts := bav.Postgres.GetComments(NewBlockHash(parentStakeID))
		for _, post := range posts {
			bav.setPostMappings(post)
		}
	} else {
		_, dbCommentHashes, _, err := DBGetCommentPostHashesForParentStakeID(
			bav.Handle, bav.Snapshot, parentStakeID, false)
		if err != nil {
			return nil, errors.Wrapf(err, "GetCommentEntriesForParentStakeID: Problem fetching comments: %v", err)
		}

		// Load comment hashes into the view.
		for _, commentHash := range dbCommentHashes {
			bav.GetPostEntryForPostHash(commentHash)
		}
	}

	commentEntries := []*PostEntry{}
	for _, postEntry := range bav.PostHashToPostEntry {
		// Ignore deleted or rolled-back posts.
		if postEntry.isDeleted {
			continue
		}

		if len(postEntry.ParentStakeID) == 0 || !reflect.DeepEqual(postEntry.ParentStakeID, parentStakeID) {
			continue // Skip posts that are not comments on the given parentStakeID.
		} else {
			// Add the comment to our map.
			commentEntries = append(commentEntries, postEntry)
		}
	}

	return commentEntries, nil
}

// Accepts a postEntry and returns as many parent posts as it can find up to maxDepth.
// This function never returns an error, only an empty list if it hits a non-post parentStakeID.
// If "rootFirst" is passed, the root of the tree will be returned first, not the 1st parent.
// _truncatedTree is a flag that is true when the root post was not reached before the maxDepth was hit.
func (bav *UtxoView) GetParentPostEntriesForPostEntry(postEntry *PostEntry, maxDepth uint32, rootFirst bool,
) (_parentPostEntries []*PostEntry, _truncatedTree bool) {

	parentStakeID := postEntry.ParentStakeID
	parentPostEntries := []*PostEntry{}

	// If the post passed has no parent or isn't a post, we return the empty list.
	if len(parentStakeID) != HashSizeBytes {
		return parentPostEntries, false
	}

	iterations := uint32(0)
	for len(parentStakeID) == HashSizeBytes && iterations < maxDepth {
		parentPostHash := &BlockHash{}
		copy(parentPostHash[:], parentStakeID)

		parentPostEntry := bav.GetPostEntryForPostHash(parentPostHash)
		if postEntry == nil {
			break
		}
		if rootFirst {
			parentPostEntries = append([]*PostEntry{parentPostEntry}, parentPostEntries...)
		} else {
			parentPostEntries = append(parentPostEntries, parentPostEntry)
		}

		// Set up the next iteration of the loop.
		parentStakeID = parentPostEntry.ParentStakeID
		iterations += 1
	}

	return parentPostEntries, iterations >= maxDepth
}

// Just fetch all the posts from the db and join them with all the posts
// in the mempool. Then sort them by their timestamp. This can be called
// on an empty view or a view that already has a lot of transactions
// applied to it.
func (bav *UtxoView) GetAllPosts() (_corePosts []*PostEntry, _commentsByPostHash map[BlockHash][]*PostEntry, _err error) {
	// Start by fetching all the posts we have in the db.
	//
	// TODO(performance): This currently fetches all posts. We should implement
	// some kind of pagination instead though.
	_, _, dbPostEntries, err := DBGetAllPostsByTstamp(bav.Handle, bav.Snapshot, true)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetAllPosts: Problem fetching PostEntry's from db: ")
	}

	// Iterate through the entries found in the db and force the view to load them.
	// This fills in any gaps in the view so that, after this, the view should contain
	// the union of what it had before plus what was in the db.
	for _, dbPostEntry := range dbPostEntries {
		bav.GetPostEntryForPostHash(dbPostEntry.PostHash)
	}

	// Do one more pass to load all the comments from the DB.
	for _, postEntry := range bav.PostHashToPostEntry {
		// Ignore deleted or rolled-back posts.
		if postEntry.isDeleted {
			continue
		}

		// If we have a post in the view and if that post is not a comment
		// then fetch its attached comments from the db. We need to do this
		// because the tstamp index above only fetches "core" posts not
		// comments.

		if len(postEntry.ParentStakeID) == 0 {
			_, dbCommentHashes, _, err := DBGetCommentPostHashesForParentStakeID(
				bav.Handle, bav.Snapshot, postEntry.ParentStakeID, false)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "GetAllPosts: Problem fetching comment PostEntry's from db: ")
			}
			for _, commentHash := range dbCommentHashes {
				bav.GetPostEntryForPostHash(commentHash)
			}
		}
	}

	allCorePosts := []*PostEntry{}
	commentsByPostHash := make(map[BlockHash][]*PostEntry)
	for _, postEntry := range bav.PostHashToPostEntry {
		// Ignore deleted or rolled-back posts.
		if postEntry.isDeleted {
			continue
		}

		// Every post is either a core post or a comment. If it has a stake ID
		// its a comment, and if it doesn't then it's a core post.
		if len(postEntry.ParentStakeID) == 0 {
			allCorePosts = append(allCorePosts, postEntry)
		} else {
			// Add the comment to our map.
			commentsForPost := commentsByPostHash[*NewBlockHash(postEntry.ParentStakeID)]
			commentsForPost = append(commentsForPost, postEntry)
			commentsByPostHash[*NewBlockHash(postEntry.ParentStakeID)] = commentsForPost
		}
	}
	// Sort all the comment lists as well. Here we put the latest comment at the
	// end.
	for _, commentList := range commentsByPostHash {
		sort.Slice(commentList, func(ii, jj int) bool {
			return commentList[ii].TimestampNanos < commentList[jj].TimestampNanos
		})
	}

	return allCorePosts, commentsByPostHash, nil
}

func (bav *UtxoView) GetPostsPaginatedForPublicKeyOrderedByTimestamp(publicKey []byte, startPostHash *BlockHash, limit uint64, mediaRequired bool, nftRequired bool) (_posts []*PostEntry, _err error) {
	if bav.Postgres != nil {
		var startTime uint64 = math.MaxUint64
		if startPostHash != nil {
			startPostEntry := bav.GetPostEntryForPostHash(startPostHash)
			startTime = startPostEntry.TimestampNanos
		}
		posts := bav.Postgres.GetPostsForPublicKey(publicKey, startTime, limit)
		for _, post := range posts {
			// TODO: Normalize this field so we get the correct number of results from the DB
			if mediaRequired && !post.HasMedia() {
				continue
			}
			// nftRequired set to determine if we only want posts that are NFTs
			if nftRequired && !post.NFT {
				continue
			}
			bav.setPostMappings(post)
		}
	} else {
		handle := bav.Handle
		// FIXME: Db operation like this shouldn't happen in utxoview.
		dbPrefix := append([]byte{}, Prefixes.PrefixPosterPublicKeyTimestampPostHash...)
		dbPrefix = append(dbPrefix, publicKey...)
		var prefix []byte
		if startPostHash != nil {
			startPostEntry := bav.GetPostEntryForPostHash(startPostHash)
			if startPostEntry == nil {
				return nil, fmt.Errorf("GetPostsPaginatedForPublicKeyOrderedByTimestamp: Invalid start post hash")
			}
			prefix = append(dbPrefix, EncodeUint64(startPostEntry.TimestampNanos)...)
			prefix = append(prefix, startPostEntry.PostHash[:]...)
		} else {
			maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
			prefix = append(dbPrefix, maxBigEndianUint64Bytes...)
		}
		timestampSizeBytes := 8
		var posts []*PostEntry
		err := handle.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions

			opts.PrefetchValues = false

			// Go in reverse order
			opts.Reverse = true

			it := txn.NewIterator(opts)
			defer it.Close()
			it.Seek(prefix)
			if startPostHash != nil {
				// Skip the first post if we have a startPostHash.
				it.Next()
			}
			for ; it.ValidForPrefix(dbPrefix) && uint64(len(posts)) < limit; it.Next() {
				rawKey := it.Item().Key()

				keyWithoutPrefix := rawKey[1:]
				//posterPublicKey := keyWithoutPrefix[:HashSizeBytes]
				publicKeySizeBytes := HashSizeBytes + 1
				//tstampNanos := DecodeUint64(keyWithoutPrefix[publicKeySizeBytes:(publicKeySizeBytes + timestampSizeBytes)])

				postHash := &BlockHash{}
				copy(postHash[:], keyWithoutPrefix[(publicKeySizeBytes+timestampSizeBytes):])
				postEntry := bav.GetPostEntryForPostHash(postHash)
				if postEntry == nil {
					return fmt.Errorf("Missing post entry")
				}
				if postEntry.isDeleted || postEntry.ParentStakeID != nil || postEntry.IsHidden {
					continue
				}

				// mediaRequired set to determine if we only want posts that include media and ignore posts without
				if mediaRequired && !postEntry.HasMedia() {
					continue
				}

				// nftRequired set to determine if we only want posts that are NFTs
				if nftRequired && !postEntry.IsNFT {
					continue
				}

				posts = append(posts, postEntry)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	var postEntries []*PostEntry
	// Iterate over the view. Put all posts authored by the public key into our mempool posts slice
	for _, postEntry := range bav.PostHashToPostEntry {
		// Ignore deleted or hidden posts and any comments.
		if postEntry.isDeleted || postEntry.IsHidden || len(postEntry.ParentStakeID) != 0 {
			continue
		}

		// mediaRequired set to determine if we only want posts that include media and ignore posts without
		if mediaRequired && !postEntry.HasMedia() {
			continue
		}

		// nftRequired set to determine if we only want posts that are NFTs
		if nftRequired && !postEntry.IsNFT {
			continue
		}

		if reflect.DeepEqual(postEntry.PosterPublicKey, publicKey) {
			postEntries = append(postEntries, postEntry)
		}
	}

	return postEntries, nil
}

func (bav *UtxoView) GetDiamondSendersForPostHash(postHash *BlockHash) (_pkidToDiamondLevel map[PKID]int64, _err error) {
	handle := bav.Handle
	// FIXME: Db operation like this shouldn't happen in utxoview.
	dbPrefix := append([]byte{}, Prefixes.PrefixDiamondedPostHashDiamonderPKIDDiamondLevel...)
	dbPrefix = append(dbPrefix, postHash[:]...)
	keysFound, _ := EnumerateKeysForPrefix(handle, dbPrefix)

	diamondPostEntry := bav.GetPostEntryForPostHash(postHash)
	receiverPKIDEntry := bav.GetPKIDForPublicKey(diamondPostEntry.PosterPublicKey)

	// Iterate over all the db keys & values and load them into the view.
	expectedKeyLength := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed + 8
	for _, key := range keysFound {
		// Sanity check that this is a reasonable key.
		if len(key) != expectedKeyLength {
			return nil, fmt.Errorf("UtxoView.GetDiamondsForPostHash: Invalid key length found: %d", len(key))
		}

		senderPKID := &PKID{}
		copy(senderPKID[:], key[1+HashSizeBytes:])

		diamondKey := &DiamondKey{
			SenderPKID:      *senderPKID,
			ReceiverPKID:    *receiverPKIDEntry.PKID,
			DiamondPostHash: *postHash,
		}

		bav.GetDiamondEntryForDiamondKey(diamondKey)
	}

	// Iterate over the view and create the final map to return.
	pkidToDiamondLevel := make(map[PKID]int64)
	for _, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		if !diamondEntry.isDeleted && reflect.DeepEqual(diamondEntry.DiamondPostHash[:], postHash[:]) {
			pkidToDiamondLevel[*diamondEntry.SenderPKID] = diamondEntry.DiamondLevel
		}
	}

	return pkidToDiamondLevel, nil
}

func (bav *UtxoView) GetRepostsForPostHash(postHash *BlockHash) (_reposterPubKeys [][]byte, _err error) {
	handle := bav.Handle
	// FIXME: Db operation like this shouldn't happen in utxoview.
	dbPrefix := append([]byte{}, Prefixes.PrefixRepostedPostHashReposterPubKey...)
	dbPrefix = append(dbPrefix, postHash[:]...)
	keysFound, _ := EnumerateKeysForPrefix(handle, dbPrefix)

	// Iterate over all the db keys & values and load them into the view.
	expectedKeyLength := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed
	for _, key := range keysFound {
		// Sanity check that this is a reasonable key.
		if len(key) != expectedKeyLength {
			return nil, fmt.Errorf("UtxoView.GetRepostersForPostHash: Invalid key length found: %d", len(key))
		}

		reposterPubKey := key[1+HashSizeBytes:]

		repostKey := &RepostKey{
			ReposterPubKey:   MakePkMapKey(reposterPubKey),
			RepostedPostHash: *postHash,
		}

		bav._getRepostEntryForRepostKey(repostKey)
	}

	// Iterate over the view and create the final list to return.
	reposterPubKeys := [][]byte{}
	for _, repostEntry := range bav.RepostKeyToRepostEntry {
		if !repostEntry.isDeleted && reflect.DeepEqual(repostEntry.RepostedPostHash[:], postHash[:]) {
			reposterPubKeys = append(reposterPubKeys, repostEntry.ReposterPubKey)
		}
	}

	return reposterPubKeys, nil
}

func (bav *UtxoView) GetQuoteRepostsForPostHash(postHash *BlockHash,
) (_quoteReposterPubKeys [][]byte, _quoteReposterPubKeyToPosts map[PkMapKey][]*PostEntry, _err error) {
	handle := bav.Handle
	// FIXME: Db operation like this shouldn't happen in utxoview.
	dbPrefix := append([]byte{}, Prefixes.PrefixRepostedPostHashReposterPubKeyRepostPostHash...)
	dbPrefix = append(dbPrefix, postHash[:]...)
	keysFound, _ := EnumerateKeysForPrefix(handle, dbPrefix)

	// Iterate over all the db keys & values and load them into the view.
	expectedKeyLength := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed + HashSizeBytes

	repostPostHashIdx := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed
	for _, key := range keysFound {
		// Sanity check that this is a reasonable key.
		if len(key) != expectedKeyLength {
			return nil, nil, fmt.Errorf("UtxoView.GetQuoteRepostsForPostHash: Invalid key length found: %d", len(key))
		}

		repostPostHash := &BlockHash{}
		copy(repostPostHash[:], key[repostPostHashIdx:])

		bav.GetPostEntryForPostHash(repostPostHash)
	}

	// Iterate over the view and create the final map to return.
	quoteReposterPubKeys := [][]byte{}
	quoteReposterPubKeyToPosts := make(map[PkMapKey][]*PostEntry)

	for _, postEntry := range bav.PostHashToPostEntry {
		if !postEntry.isDeleted && postEntry.IsQuotedRepost && reflect.DeepEqual(postEntry.RepostedPostHash[:], postHash[:]) {
			quoteReposterPubKeys = append(quoteReposterPubKeys, postEntry.PosterPublicKey)

			quoteRepostPosts, _ := quoteReposterPubKeyToPosts[MakePkMapKey(postEntry.PosterPublicKey)]
			quoteRepostPosts = append(quoteRepostPosts, postEntry)
			quoteReposterPubKeyToPosts[MakePkMapKey(postEntry.PosterPublicKey)] = quoteRepostPosts
		}
	}

	return quoteReposterPubKeys, quoteReposterPubKeyToPosts, nil
}

func (bav *UtxoView) _connectSubmitPost(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32,
	verifySignatures bool, ignoreUtxos bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeSubmitPost {
		return 0, 0, nil, fmt.Errorf("_connectSubmitPost: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*SubmitPostMetadata)

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	//
	// The ignoreUtxos flag is used to connect "seed" transactions when initializing
	// the blockchain. It allows us to "seed" the database with posts and profiles
	// when we do a hard fork, without having the transactions rejected due to their
	// not being spendable.
	var totalInput, totalOutput uint64
	var utxoOpsForTxn = []*UtxoOperation{}
	var err error
	if !ignoreUtxos {
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectBasicTransfer(
			txn, txHash, blockHeight, verifySignatures)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectSubmitPost: ")
		}

		// Force the input to be non-zero so that we can prevent replay attacks.
		if totalInput == 0 {
			return 0, 0, nil, RuleErrorSubmitPostRequiresNonZeroInput
		}
	}

	// Transaction extra data contains both consensus-related, such as repost info, and additional information about a post,
	// whereas PostExtraData is an attribute of a PostEntry that contains only non-consensus related
	// information about a post, such as a link to a video that is embedded.
	extraData := make(map[string][]byte)
	for k, v := range txn.ExtraData {
		extraData[k] = v
	}
	// Set the IsQuotedRepost attribute of postEntry based on extra data
	isQuotedRepost := false
	if quotedRepost, hasQuotedRepost := extraData[IsQuotedRepostKey]; hasQuotedRepost {
		if reflect.DeepEqual(quotedRepost, QuotedRepostVal) {
			isQuotedRepost = true
		}
		// Delete key since it is not needed in the PostExtraData map as IsQuotedRepost is involved in consensus code.
		delete(extraData, IsQuotedRepostKey)
	}
	var repostedPostHash *BlockHash
	if repostedPostHashBytes, isRepost := extraData[RepostedPostHash]; isRepost {
		repostedPostHash = &BlockHash{}
		copy(repostedPostHash[:], repostedPostHashBytes)
		delete(extraData, RepostedPostHash)
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// If the metadata has a PostHashToModify then treat it as modifying an
	// existing post rather than creating a new post.
	var prevPostEntry *PostEntry
	var prevParentPostEntry *PostEntry
	var prevGrandparentPostEntry *PostEntry
	var prevRepostedPostEntry *PostEntry
	var prevRepostEntry *RepostEntry

	var newPostEntry *PostEntry
	var newParentPostEntry *PostEntry
	var newGrandparentPostEntry *PostEntry
	var newRepostedPostEntry *PostEntry
	var newRepostEntry *RepostEntry
	if len(txMeta.PostHashToModify) != 0 {
		// Make sure the post hash is valid
		if len(txMeta.PostHashToModify) != HashSizeBytes {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostInvalidPostHashToModify,
				"_connectSubmitPost: Bad post hash: %#v", txMeta.PostHashToModify)
		}

		// Get the existing post entry, which must exist and be undeleted.
		postHash := &BlockHash{}
		copy(postHash[:], txMeta.PostHashToModify[:])
		existingPostEntryy := bav.GetPostEntryForPostHash(postHash)
		if existingPostEntryy == nil || existingPostEntryy.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostModifyingNonexistentPost,
				"_connectSubmitPost: Post hash: %v", postHash)
		}

		// Post modification is only allowed by the original poster.
		if !reflect.DeepEqual(txn.PublicKey, existingPostEntryy.PosterPublicKey) {

			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostPostModificationNotAuthorized,
				"_connectSubmitPost: Post hash: %v, poster public key: %v, "+
					"txn public key: %v, paramUpdater: %v", postHash,
				PkToStringBoth(existingPostEntryy.PosterPublicKey),
				PkToStringBoth(txn.PublicKey), spew.Sdump(GetParamUpdaterPublicKeys(blockHeight, bav.Params)))
		}

		// Modification of an NFT is not allowed.
		if existingPostEntryy.IsNFT {
			return 0, 0, nil, errors.Wrapf(RuleErrorSubmitPostCannotUpdateNFT, "_connectSubmitPost: ")
		}

		// It's an error if we are updating the value of RepostedPostHash. A post can only ever repost a single post.
		if !reflect.DeepEqual(repostedPostHash, existingPostEntryy.RepostedPostHash) {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostUpdateRepostHash,
				"_connectSubmitPost: cannot update reposted post hash when updating a post")
		}

		// It's an error if we are updating the value of IsQuotedRepost.
		if isQuotedRepost != existingPostEntryy.IsQuotedRepost {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostUpdateIsQuotedRepost,
				"_connectSubmitPost: cannot update isQuotedRepost attribute of post when updating a post")
		}

		// Save the data from the post. Note that we don't make a deep copy
		// because all the fields that we modify are non-pointer fields.
		prevPostEntry = &PostEntry{}
		*prevPostEntry = *existingPostEntryy

		// Set the newPostEntry pointer to the existing entry
		newPostEntry = existingPostEntryy

		// The field values should have already been validated so set
		// them.
		if len(txMeta.Body) != 0 {
			newPostEntry.Body = txMeta.Body
		}

		// Merge the remaining attributes of the transaction's ExtraData into the postEntry's PostExtraData map.
		if len(extraData) > 0 {
			newPostExtraData := make(map[string][]byte)
			for k, v := range existingPostEntryy.PostExtraData {
				newPostExtraData[k] = v
			}
			for k, v := range extraData {
				// If we're given a value with length greater than 0, add it to the map.
				if len(v) > 0 {
					newPostExtraData[k] = v
				} else {
					// If the value we're given has a length of 0, this indicates that we should delete it if it exists.
					delete(newPostExtraData, k)
				}
			}
			newPostEntry.PostExtraData = newPostExtraData
		}
		// TODO: Right now a post can be undeleted by the owner of the post,
		// which seems like undesired behavior if a paramUpdater is trying to reduce
		// spam
		newPostEntry.IsHidden = txMeta.IsHidden

		// Obtain the parent posts
		newParentPostEntry, newGrandparentPostEntry, err = bav._getParentAndGrandparentPostEntry(newPostEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectSubmitPost: error with _getParentAndGrandparentPostEntry: %v", postHash)
		}

		if newPostEntry.RepostedPostHash != nil {
			newRepostedPostEntry = bav.GetPostEntryForPostHash(newPostEntry.RepostedPostHash)
		}

		// Figure out how much we need to change the parent / grandparent's comment count by
		var commentCountUpdateAmount int
		repostCountUpdateAmount := 0
		quoteRepostCountUpdateAmount := 0
		hidingPostEntry := !prevPostEntry.IsHidden && newPostEntry.IsHidden
		if hidingPostEntry {
			// If we're hiding a post then we need to decrement the comment count of the parent
			// and grandparent posts.
			commentCountUpdateAmount = -1 * int(1+prevPostEntry.CommentCount)

			// If we're hiding a post that is a vanilla repost of another post, we decrement the repost count of the
			// post that was reposted.
			if IsVanillaRepost(newPostEntry) {
				repostCountUpdateAmount = -1
			} else if isQuotedRepost {
				quoteRepostCountUpdateAmount = -1
			}
		}

		unhidingPostEntry := prevPostEntry.IsHidden && !newPostEntry.IsHidden
		if unhidingPostEntry {
			// If we're unhiding a post then we need to increment the comment count of the parent
			// and grandparent posts.
			commentCountUpdateAmount = int(1 + prevPostEntry.CommentCount)
			// If we are unhiding a post that is a vanilla repost of another post, we increment the repost count of
			// the post that was reposted.
			if IsVanillaRepost(newPostEntry) {
				repostCountUpdateAmount = 1
			} else if isQuotedRepost {
				quoteRepostCountUpdateAmount = 1
			}
		}

		// Save the data from the parent post. Note that we don't make a deep copy
		// because all the fields that we modify are non-pointer fields.
		if newParentPostEntry != nil {
			prevParentPostEntry = &PostEntry{}
			*prevParentPostEntry = *newParentPostEntry
			bav._updateParentCommentCountForPost(newPostEntry, newParentPostEntry, commentCountUpdateAmount)
		}

		// Save the data from the grandparent post. Note that we don't make a deep copy
		// because all the fields that we modify are non-pointer fields.
		if newGrandparentPostEntry != nil {
			prevGrandparentPostEntry = &PostEntry{}
			*prevGrandparentPostEntry = *newGrandparentPostEntry
			bav._updateParentCommentCountForPost(newPostEntry, newGrandparentPostEntry, commentCountUpdateAmount)
		}
		if newRepostedPostEntry != nil {
			prevRepostedPostEntry = &PostEntry{}
			*prevRepostedPostEntry = *newRepostedPostEntry
			// If the previous post entry is a vanilla repost, we can set the prevRepostEntry.
			if IsVanillaRepost(prevPostEntry) {
				prevRepostKey := MakeRepostKey(prevPostEntry.PosterPublicKey, *prevPostEntry.RepostedPostHash)
				prevRepostEntry = bav._getRepostEntryForRepostKey(&prevRepostKey)
				if prevRepostEntry == nil {
					return 0, 0, nil, fmt.Errorf("prevRepostEntry not found for prevPostEntry")
				}
				// Generally prevRepostEntry is identical to newRepostEntry. Currently, we enforce a check that
				// the RepostedPostHash does not get modified when attempting to connect a submitPost transaction
				newRepostEntry = &RepostEntry{
					ReposterPubKey:   newPostEntry.PosterPublicKey,
					RepostedPostHash: newPostEntry.RepostedPostHash,
					RepostPostHash:   newPostEntry.PostHash,
				}

				// Update the repost count if it has changed.
				bav._updateRepostCount(newRepostedPostEntry, repostCountUpdateAmount)
			} else {
				// Update the quote repost count if it has changed.
				bav._updateQuoteRepostCount(newRepostedPostEntry, quoteRepostCountUpdateAmount)
			}
		}
	} else {
		// In this case we are creating a post from scratch so validate
		// all the fields.

		// StakeMultipleBasisPoints > 0 < max
		// Between 1x = 100% and 10x = 10,000%
		if txMeta.StakeMultipleBasisPoints < 100*100 ||
			txMeta.StakeMultipleBasisPoints > bav.Params.MaxStakeMultipleBasisPoints {

			return 0, 0, nil, errors.Wrapf(RuleErrorSubmitPostStakeMultipleSize,
				"_connectSubmitPost: Invalid StakeMultipleSize: %d",
				txMeta.StakeMultipleBasisPoints)
		}
		// CreatorBasisPoints > 0 < max
		if txMeta.CreatorBasisPoints < 0 ||
			txMeta.CreatorBasisPoints > bav.Params.MaxCreatorBasisPoints {

			return 0, 0, nil, errors.Wrapf(RuleErrorSubmitPostCreatorPercentageSize,
				"_connectSubmitPost: Invalid CreatorPercentageSize: %d",
				txMeta.CreatorBasisPoints)
		}
		// TstampNanos != 0
		if txMeta.TimestampNanos == 0 {
			return 0, 0, nil, errors.Wrapf(RuleErrorSubmitPostTimestampIsZero,
				"_connectSubmitPost: Invalid Timestamp: %d",
				txMeta.TimestampNanos)
		}
		// The parent stake id should be a block hash or profile public key if it's set.
		if len(txMeta.ParentStakeID) != 0 && len(txMeta.ParentStakeID) != HashSizeBytes &&
			len(txMeta.ParentStakeID) != btcec.PubKeyBytesLenCompressed {
			return 0, 0, nil, errors.Wrapf(RuleErrorSubmitPostInvalidParentStakeIDLength,
				"_connectSubmitPost: Parent stake ID length %v must be either 0 or %v or %v",
				len(txMeta.ParentStakeID), HashSizeBytes, btcec.PubKeyBytesLenCompressed)
		}

		// The PostHash is just the transaction hash.
		postHash := txHash
		existingPostEntry := bav.GetPostEntryForPostHash(postHash)
		if existingPostEntry != nil && !existingPostEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPostAlreadyExists,
				"_connectSubmitPost: Post hash: %v", postHash)
		}

		if repostedPostHash != nil {
			newRepostedPostEntry = bav.GetPostEntryForPostHash(repostedPostHash)
			// It is an error if a post entry attempts to repost a post that does not exist.
			if newRepostedPostEntry == nil {
				return 0, 0, nil, RuleErrorSubmitPostRepostPostNotFound
			}
			// It is an error if a post is trying to repost a vanilla repost.
			if IsVanillaRepost(newRepostedPostEntry) {
				return 0, 0, nil, RuleErrorSubmitPostRepostOfRepost
			}
		}

		// Set the post entry pointer to a brand new post.
		newPostEntry = &PostEntry{
			PostHash:                 postHash,
			PosterPublicKey:          txn.PublicKey,
			ParentStakeID:            txMeta.ParentStakeID,
			Body:                     txMeta.Body,
			RepostedPostHash:         repostedPostHash,
			IsQuotedRepost:           isQuotedRepost,
			CreatorBasisPoints:       txMeta.CreatorBasisPoints,
			StakeMultipleBasisPoints: txMeta.StakeMultipleBasisPoints,
			TimestampNanos:           txMeta.TimestampNanos,
			ConfirmationBlockHeight:  blockHeight,
			PostExtraData:            extraData,
			// Don't set IsHidden on new posts.
		}

		// Obtain the parent posts
		newParentPostEntry, newGrandparentPostEntry, err = bav._getParentAndGrandparentPostEntry(newPostEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectSubmitPost: error with _getParentAndGrandparentPostEntry: %v", postHash)
		}

		// Save the data from the parent posts. Note that we don't make a deep copy
		// because all the fields that we modify are non-pointer fields.
		if newParentPostEntry != nil {
			prevParentPostEntry = &PostEntry{}
			*prevParentPostEntry = *newParentPostEntry
			bav._updateParentCommentCountForPost(newPostEntry, newParentPostEntry, 1 /*amountToChangeParentBy*/)
		}

		if newGrandparentPostEntry != nil {
			prevGrandparentPostEntry = &PostEntry{}
			*prevGrandparentPostEntry = *newGrandparentPostEntry
			bav._updateParentCommentCountForPost(newPostEntry, newGrandparentPostEntry, 1 /*amountToChangeParentBy*/)
		}

		// Save the data from the reposted post.
		if newRepostedPostEntry != nil {
			prevRepostedPostEntry = &PostEntry{}
			*prevRepostedPostEntry = *newRepostedPostEntry

			// We only set repost entry mappings and increment counts for vanilla reposts.
			if !isQuotedRepost {
				// Increment the repost count of the post that was reposted by 1 as we are creating a new
				// vanilla repost.
				bav._updateRepostCount(newRepostedPostEntry, 1)
				// Create the new repostEntry
				newRepostEntry = &RepostEntry{
					ReposterPubKey:   newPostEntry.PosterPublicKey,
					RepostedPostHash: newPostEntry.RepostedPostHash,
					RepostPostHash:   newPostEntry.PostHash,
				}
			} else {
				// If it is a quote repost, we need to increment the corresponding count.
				bav._updateQuoteRepostCount(newRepostedPostEntry, 1)
			}
		}
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// Set the mappings for the entry regardless of whether we modified it or
	// created it from scratch.
	bav._setPostEntryMappings(newPostEntry)
	if newParentPostEntry != nil {
		bav._setPostEntryMappings(newParentPostEntry)
	}
	if newGrandparentPostEntry != nil {
		bav._setPostEntryMappings(newGrandparentPostEntry)
	}
	if newRepostedPostEntry != nil {
		bav._setPostEntryMappings(newRepostedPostEntry)
	}

	if newRepostEntry != nil {
		bav._setRepostEntryMappings(newRepostEntry)
	}

	// Add an operation to the list at the end indicating we've added a post.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		// PrevPostEntry should generally be nil when we created a new post from
		// scratch, but non-nil if we modified an existing post.
		PrevPostEntry:            prevPostEntry,
		PrevParentPostEntry:      prevParentPostEntry,
		PrevGrandparentPostEntry: prevGrandparentPostEntry,
		PrevRepostedPostEntry:    prevRepostedPostEntry,
		PrevRepostEntry:          prevRepostEntry,
		Type:                     OperationTypeSubmitPost,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _getParentAndGrandparentPostEntry(postEntry *PostEntry) (
	_parentPostEntry *PostEntry, _grandparentPostEntry *PostEntry, _err error) {
	var parentPostEntry *PostEntry
	var grandparentPostEntry *PostEntry

	// This length check ensures that the parent is a post (and not something else, like a profile)
	//
	// If we ever allow commenting on something else such that the parent is not a post, but where
	// ParentStakeID is also HashSizeBytes, then this logic would likely need to be changed.
	if len(postEntry.ParentStakeID) == HashSizeBytes {
		parentPostEntry = bav.GetPostEntryForPostHash(NewBlockHash(postEntry.ParentStakeID))
		if parentPostEntry == nil {
			return nil, nil, errors.Wrapf(
				RuleErrorSubmitPostParentNotFound,
				"_getParentAndGrandparentPostEntry: failed to find parent post for post hash: %v, parentStakeId: %v",
				postEntry.PostHash, hex.EncodeToString(postEntry.ParentStakeID),
			)
		}
	}

	if parentPostEntry != nil && len(parentPostEntry.ParentStakeID) == HashSizeBytes {
		grandparentPostEntry = bav.GetPostEntryForPostHash(NewBlockHash(parentPostEntry.ParentStakeID))
		if grandparentPostEntry == nil {
			return nil, nil, errors.Wrapf(
				RuleErrorSubmitPostParentNotFound,
				"_getParentAndGrandparentPostEntry: failed to find grandparent post for post hash: %v, parentStakeId: %v, grandparentStakeId: %v",
				postEntry.PostHash, postEntry.ParentStakeID, parentPostEntry.ParentStakeID,
			)
		}
	}

	return parentPostEntry, grandparentPostEntry, nil
}

// Adds amount to the repost count of the post at repostPostHash
func (bav *UtxoView) _updateRepostCount(repostedPost *PostEntry, amount int) {
	result := int(repostedPost.RepostCount) + amount

	// Repost count should never be below 0.
	if result < 0 {
		glog.Errorf("_updateRepostCountForPost: RepostCount < 0 for result %v, repost post hash: %v, amount : %v",
			result, repostedPost, amount)
		result = 0
	}
	repostedPost.RepostCount = uint64(result)

}

// Adds amount to the quote repost count of the post at repostPostHash
func (bav *UtxoView) _updateQuoteRepostCount(repostedPost *PostEntry, amount int) {
	result := int(repostedPost.QuoteRepostCount) + amount

	// Repost count should never be below 0.
	if result < 0 {
		glog.Errorf("_updateQuoteRepostCountForPost: QuoteRepostCount < 0 for result %v, repost post hash: %v, amount : %v",
			result, repostedPost, amount)
		result = 0
	}
	repostedPost.QuoteRepostCount = uint64(result)

}

func (bav *UtxoView) _updateParentCommentCountForPost(postEntry *PostEntry, parentPostEntry *PostEntry, amountToChangeParentBy int) {
	result := int(parentPostEntry.CommentCount) + amountToChangeParentBy
	if result < 0 {
		glog.Errorf("_updateParentCommentCountForPost: CommentCount < 0 for result %v, postEntry hash: %v, parentPostEntry hash: %v, amountToChangeParentBy: %v",
			result, postEntry.PostHash, parentPostEntry.PostHash, amountToChangeParentBy)
		result = 0
	}

	parentPostEntry.CommentCount = uint64(result)
}

func (bav *UtxoView) _disconnectSubmitPost(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a SubmitPost operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectSubmitPost: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	currentOperation := utxoOpsForTxn[operationIndex]
	if currentOperation.Type != OperationTypeSubmitPost {
		return fmt.Errorf("_disconnectSubmitPost: Trying to revert "+
			"OperationTypeSubmitPost but found type %v",
			currentOperation.Type)
	}

	// Now we know the txMeta is SubmitPost
	txMeta := currentTxn.TxnMeta.(*SubmitPostMetadata)

	// The post hash is either the transaction hash or the hash set
	// in the metadata.
	postHashModified := txnHash
	if len(txMeta.PostHashToModify) != 0 {
		postHashModified = &BlockHash{}
		copy(postHashModified[:], txMeta.PostHashToModify[:])
	}

	// Get the PostEntry. If we don't find
	// it or if it has isDeleted=true that's an error.
	postEntry := bav.GetPostEntryForPostHash(postHashModified)
	if postEntry == nil || postEntry.isDeleted {
		return fmt.Errorf("_disconnectSubmitPost: PostEntry for "+
			"Post Hash %v was found to be nil or deleted: %v",
			&txnHash, postEntry)
	}

	// Delete repost mappings if they exist. They will be added back later if there is a previous version of this
	// postEntry
	if IsVanillaRepost(postEntry) {
		repostKey := MakeRepostKey(postEntry.PosterPublicKey, *postEntry.RepostedPostHash)
		repostEntry := bav._getRepostEntryForRepostKey(&repostKey)
		if repostEntry == nil {
			return fmt.Errorf("_disconnectSubmitPost: RepostEntry for "+
				"Post Has %v could not be found: %v", &txnHash, postEntry)
		}
		bav._deleteRepostEntryMappings(repostEntry)
	}

	// Now that we are confident the PostEntry lines up with the transaction we're
	// rolling back, use the entry to delete the mappings for this post.
	//
	// Note: We don't need to delete the existing PostEntry mappings for parent and grandparent
	// before setting the prev mappings because the only thing that could have changed is the
	// comment count, which isn't indexed.
	bav._deletePostEntryMappings(postEntry)

	// If we have a non-nil previous post entry then set the mappings for
	// that.
	if currentOperation.PrevPostEntry != nil {
		bav._setPostEntryMappings(currentOperation.PrevPostEntry)
	}
	if currentOperation.PrevParentPostEntry != nil {
		bav._setPostEntryMappings(currentOperation.PrevParentPostEntry)
	}
	if currentOperation.PrevGrandparentPostEntry != nil {
		bav._setPostEntryMappings(currentOperation.PrevGrandparentPostEntry)
	}
	if currentOperation.PrevRepostedPostEntry != nil {
		bav._setPostEntryMappings(currentOperation.PrevRepostedPostEntry)
	}
	if currentOperation.PrevRepostEntry != nil {
		bav._setRepostEntryMappings(currentOperation.PrevRepostEntry)
	}

	// Now revert the basic transfer with the remaining operations. Cut off
	// the SubmitPost operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
