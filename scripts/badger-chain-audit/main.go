package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/deso-protocol/core/consensus"
	"github.com/deso-protocol/core/lib"
	"github.com/dgraph-io/badger/v3"
)

func emit(x any) {
	if err := json.NewEncoder(os.Stdout).Encode(x); err != nil {
		panic(err)
	}
}
func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	data := flag.String("data-dir", "", "offline cloned node data directory")
	scan := flag.Bool("scan", false, "optional expensive scan of stored PoS headers")
	testnet := flag.Bool("testnet", false, "testnet parameters")
	flag.Parse()
	if *data == "" {
		panic("data-dir is required")
	}
	if _, err := os.Stat(filepath.Join(lib.GetBadgerDbPath(*data), "MANIFEST")); err != nil {
		panic("existing offline Badger MANIFEST required")
	}
	params := lib.DeSoMainnetParams
	if *testnet {
		params = lib.DeSoTestnetParams
	}
	lib.GlobalDeSoParams = params
	opts := lib.PerformanceBadgerOptions(lib.GetBadgerDbPath(*data)).WithReadOnly(true).WithLogger(nil).WithBlockCacheSize(128 << 20).WithIndexCacheSize(128 << 20)
	db, err := badger.Open(opts)
	check(err)
	defer db.Close()
	view := lib.NewUtxoView(db, &params, nil, nil, nil)
	stateHeight, err := lib.GetHeightForHash(db, nil, view.TipHash)
	check(err)
	stateNode := lib.GetHeightHashToNodeInfo(db, nil, uint32(stateHeight), view.TipHash, false)
	if stateNode == nil {
		panic("state tip header not found")
	}
	emit(map[string]any{"type": "state_tip", "height": stateHeight, "hash": view.TipHash.String(), "committed": stateNode.IsCommitted()})
	epoch, err := view.GetCurrentEpochEntry()
	check(err)
	currentSnapshot, err := view.GetCurrentSnapshotEpochNumber()
	check(err)
	emit(map[string]any{"type": "epoch", "epoch": epoch, "snapshot": currentSnapshot, "at": time.Now().UTC(), "readOnly": true})
	for n := currentSnapshot; n < epoch.EpochNumber; n++ {
		vals, err := view.GetAllSnapshotValidatorSetEntriesByStakeAtEpochNumber(n)
		check(err)
		for _, v := range vals {
			domains := []string{}
			for _, d := range v.Domains {
				domains = append(domains, string(d))
			}
			emit(map[string]any{"type": "snapshot_validator", "snapshotEpoch": n, "pkid": fmt.Sprintf("%x", v.ValidatorPKID.ToBytes()), "publicKey": lib.Base58CheckEncode(view.GetPublicKeyForPKID(v.ValidatorPKID), false, &params), "votingKey": v.VotingPublicKey.ToString(), "stakeNanos": v.TotalStakeAmountNanos.ToBig().String(), "domains": domains, "lastActiveEpoch": v.LastActiveAtEpochNumber, "jailedEpoch": v.JailedAtEpochNumber})
		}
	}
	// Use ordinary committed headers to prove recent voting participation. Stay
	// inside the current epoch so every signer index uses this exact snapshot.
	validators, err := view.GetAllSnapshotValidatorSetEntriesByStakeAtEpochNumber(currentSnapshot)
	check(err)
	counts := map[string]int{}
	latest := map[string]uint64{}
	recentNode := stateNode
	sampled := 0
	for sampled < 128 && recentNode != nil && recentNode.Header.Height > epoch.InitialBlockHeight {
		h := recentNode.Header
		if !recentNode.IsCommitted() {
			panic("recent canonical header is not committed")
		}
		qc := h.GetQC()
		if !consensus.IsValidSuperMajorityQuorumCertificate(qc, lib.ValidatorEntriesToConsensusInterface(validators)) {
			panic("recent committed QC does not verify against current consensus snapshot")
		}
		if h.PrevBlockHash == nil || !h.PrevBlockHash.IsEqual(lib.BlockHashFromConsensusInterface(qc.GetBlockHash())) {
			panic("recent committed QC parent mismatch")
		}
		bits := qc.GetAggregatedSignature().GetSignersList()
		for i, v := range validators {
			if bits.Get(i) {
				key := v.VotingPublicKey.ToString()
				counts[key]++
				if latest[key] == 0 {
					latest[key] = h.Height - 1
				}
			}
		}
		sampled++
		recentNode = lib.GetHeightHashToNodeInfo(db, nil, uint32(h.Height-1), h.PrevBlockHash, false)
	}
	emit(map[string]any{"type": "recent_consensus_votes", "snapshotEpoch": currentSnapshot, "epoch": epoch.EpochNumber, "verifiedQCs": sampled, "tipHeight": stateHeight, "tipTimestampSecs": stateNode.Header.GetTstampSecs(), "qcCountsByVotingKey": counts, "lastCertifiedHeightByVotingKey": latest})
	if !*scan {
		return
	}
	var count, pos, committed, mismatch, committedMismatch, first, last, lastCommitted, votes, timeouts uint64
	var lastHash string
	start := time.Now()
	err = db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = lib.Prefixes.PrefixHeightHashToNodeInfo
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			b, err := it.Item().ValueCopy(nil)
			if err != nil {
				return err
			}
			node, err := lib.DeserializeBlockNode(b)
			if err != nil {
				return err
			}
			count++
			h := node.Header
			if h.Version != 2 {
				continue
			}
			pos++
			if first == 0 {
				first = h.Height
			}
			if h.Height > last {
				last = h.Height
			}
			if node.IsCommitted() {
				committed++
				if h.Height > lastCommitted {
					lastCommitted = h.Height
					lastHash = node.Hash.String()
				}
			}
			bad := false
			if h.ValidatorsVoteQC != nil && h.ValidatorsVoteQC.BlockHash != nil {
				votes++
				bad = h.PrevBlockHash == nil || !h.PrevBlockHash.IsEqual(h.ValidatorsVoteQC.BlockHash)
			}
			if h.ValidatorsTimeoutAggregateQC != nil && h.ValidatorsTimeoutAggregateQC.ValidatorsHighQC != nil && h.ValidatorsTimeoutAggregateQC.ValidatorsHighQC.BlockHash != nil {
				timeouts++
				bad = bad || h.PrevBlockHash == nil || !h.PrevBlockHash.IsEqual(h.ValidatorsTimeoutAggregateQC.ValidatorsHighQC.BlockHash)
			}
			if bad {
				mismatch++
				if node.IsCommitted() {
					committedMismatch++
				}
				if mismatch <= 20 {
					emit(map[string]any{"type": "mismatch", "height": h.Height, "hash": node.Hash.String(), "committed": node.IsCommitted(), "validated": node.IsValidated()})
				}
			}
			if pos%250000 == 0 {
				emit(map[string]any{"type": "progress", "headers": count, "pos": pos, "height": last, "committedMismatch": committedMismatch, "elapsedSeconds": time.Since(start).Seconds()})
			}
		}
		return nil
	})
	check(err)
	emit(map[string]any{"type": "history_result", "headers": count, "pos": pos, "firstPoSHeight": first, "lastPoSHeight": last, "committed": committed, "lastCommittedHeight": lastCommitted, "lastCommittedHash": lastHash, "mismatches": mismatch, "committedMismatches": committedMismatch, "voteHeaders": votes, "timeoutHeaders": timeouts, "elapsedSeconds": time.Since(start).Seconds()})
	if committedMismatch > 0 {
		os.Exit(2)
	}
}
