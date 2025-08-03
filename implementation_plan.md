# State Change Syncer Refactor – Implementation Plan

## Overview (High-Level Goals)
This refactor replaces the *event-per-write* state-change logging mechanism with a **diff-based streaming model** built on Badger's `DB.Stream()` API.

Runtime behaviour changes:
• **Per-block diffs** – On block commit the node emits `state_changes_<height>.bin` containing all key/value pairs that changed since the previous block (cursor tracked via Badger timestamp).
• **Mempool rolling diffs** – The mempool routine continually writes `mempool_<last_height>_<ts>.bin`. Files older than two blocks are deleted.
• **Hypersync checkpoints** – Snapshot chunks write `state_changes_hypersync_<ts>.bin` so a consumer can bootstrap quickly.
• **Consumers** ingest these binary diff artifacts, convert them to `StateChangeEntry`s with existing helpers, and apply or revert them to downstream stores (Postgres, Kafka, etc.).

Migration strategy:
A feature flag toggles *legacy* vs *diff* mode. New nodes will enable diff mode from genesis; existing nodes may resync from scratch.

Key objectives:
1. Reduce overhead of emitting every single state change via callbacks.
2. Provide deterministic, append-only artifact per block that third-party systems can mirror or replay.
3. Simplify consumer logic by eliminating byte-offset index files.
4. Keep mempool visibility and hypersync performance comparable to current implementation.

---

> NOTE: All steps assume the new design goals described in the user brief (per–block Badger diff files via DB.Stream, consumer rework, revamped mempool routine, future hypersync changes).

---

## Step 1 – Requirements & Architecture Confirmation  ✅ (Completed)

**Objective:** Finalise high-level design choices and eliminate unknowns before touching code.

### Sub-tasks
1. Capture and circulate design diagram (sequence of events for block flush, mempool flush, consumer loop).
2. Confirm file naming convention (FINAL):
   • `state_changes_<height>.bin` – per committed block
   • `state_changes_hypersync_<ts>.bin` – snapshot chunk / hypersync
   • `mempool_<last_height>_<ts>.bin` – rolling mempool diff (delete when >2 blocks old)
3. Decide whether `since` value is stored in:
   • dedicated Badger key (e.g. `syncer-last-since`)
   • or per-block meta table.
4. Define concurrency model and mutex strategy (see "Concurrency Decisions" below).
5. Migration decision: no live migration; feature flag chooses legacy vs diff mode and fresh resync is required when enabling diff mode.

### Acceptance Criteria
- Document shared & approved by core team.
- Conventions above (file names, cursor key, retention, migration) captured.
- Concurrency design below acknowledged by reviewers.

### File / Function References
- `core/lib/state_change_syncer.go` (new entry points).
- `core/lib/pos_blockchain.go` (commit flow).

### Testing
- N/A (planning).

### Concurrency Decisions (Final)
1. **Single cursor writer** – Only block-commit path updates the `syncer-since` key; mempool & snapshot code read-only.
2. **diffGenerationMu** – A new mutex inside `StateChangeSyncer` guards:
   • Calling `BackupDatabase` / `DB.Stream`.
   • Writing/renaming the resulting *.bin file.
   • Deleting expired mempool diff files.
3. **Block path ordering** – Execution occurs while `ChainLock` is still held after DB flush, ensuring a consistent snapshot.
4. **Mempool isolation** – Mempool flushes operate in a detached Badger txn and also take `diffGenerationMu` only during file write, so can overlap with snapshot streaming.
5. **Snapshot chunks** – `SetSnapshotChunk` uses same mutex to serialise its diff emission with other producers.
6. **Retention deletion** – Block-commit handler deletes mempool files older than two blocks after writing its own diff while holding `diffGenerationMu`.

No outstanding open questions at this stage.

---

## Step 2 – Persist & Retrieve `since` Cursor ✅ (Completed)

**Objective:** Introduce helpers to read/write the last Badger timestamp used for backup streaming.

### Sub-tasks
1. Add constants for key names (e.g. `PrefixSyncerSince = []byte("syncer-since")`).
2. Implement `func (s *StateChangeSyncer) getLastSince(db *badger.DB) (uint64, error)`.
3. Implement `func (s *StateChangeSyncer) setLastSince(db *badger.DB, ts uint64) error`.
4. Provide unit tests with in-memory Badger.

### Acceptance Criteria
- Helpers round-trip the timestamp value.
- Tests cover initial (key absent) path & update path.

### File / Function References
- NEW `core/lib/state_change_syncer_cursor.go`.

### Testing Steps
```
1. Init empty Badger.
2. Call getLastSince – expect 0.
3. Call setLastSince(123).
4. Call getLastSince – expect 123.
```

### Open Questions
- Should we version the key for future format changes?

---

## Step 3 – Generate Per-Block Diff Files on Commit ✅ (Completed)

**Objective:** On successful block commit, stream Badger diff since previous commit and write to `state_changes_<height>.bin`.

### Sub-tasks
1. Hook into `Blockchain.commitBlockPoS` **after** DB flush & before stateSyncer flush.
2. Fetch `since` via helper from Step 2.
3. Call existing `BackupDatabase(db, since)`.
4. Write returned bytes to `filepath.Join(stateChangeDir, fmt.Sprintf("state_changes_%d.bin", height))`.
5. Update stored `since` with returned `nextSince`.
6. Hold `diffGenerationMu` around diff generation + write + `since` key update.
7. Ensure file write is atomic (tmp file + rename).
8. Remove now-unused event-driven committed entry code path (flag-guarded to ease migration).

### Acceptance Criteria
- New file appears per block on disk during unit/integration tests.
- Old state_change.bin writing disabled behind feature flag (`UseEventSyncer` false).

### File / Function References
- `core/lib/pos_blockchain.go` (`commitBlockPoS`).
- `core/lib/state_change_syncer.go` (expose BackupDatabase).

### Testing Steps
```
1. Spin up blockchain test harness.
2. Mine two blocks.
3. Check filesystem: state_changes_<h1>.bin, state_changes_<h2>.bin exist and non-empty.
4. Ensure since cursor advanced (value increases).
```

### Open Questions
- Where to place stateChangeDir for mainnet vs tests?

---

## Step 3.5 – Robust Integration & Unit Tests for Diff Generation

**Objective:** Validate end-to-end behaviour of the new diff pipeline in a realistic blockchain scenario with committed blocks, mempool activity, and consumer-style parsing.

### Sub-tasks
1. Spin-up a regtest chain inside tests using helpers (`NewLowDifficultyBlockchain`, `NewTestMiner`).
2. Enhance `StateChangeSyncer` during tests by wiring its `GenerateCommittedBlockDiff` call inside `commitBlockPoS` via a test hook or direct invocation.
3. Craft transactional workloads (multiple blocks + mempool) to exercise edge-cases:
   • **Block 1 (pure inserts)** ✅ (Completed) – mine a block containing:
     – `SubmitPost` – creates a new `PostEntry` (core-state).  
     – `UpdateGlobalParams` (core-state single-key upsert).  
     – `CreateUserAssociation` – inserts a `UserAssociationEntry` (core-state, key-encoded value).

   • **Block 2 (updates & deletes in same block)** – include:  
     – *Update* the previous post via `SubmitPost` modifying body to test overwrite diff.  
     – *Delete* the same post via `DeletePost` (tests `DbOperationTypeDelete`).  
     – *Delete* the association via `DeleteUserAssociation`.  
     – *Create* a new `PostAssociation` to introduce a second encoder type.

   • **Block 3 (multi-update same key)** – two transactions targeting identical `PostEntry` (body edit and extra data edit) within single block to ensure only final revision shows up once in diff.

   • **Block 4 (non-core-state noise)** – craft `AuthorizeDerivedKey` txn which touches non-core prefixes; confirm diff excludes them.

   • **Mempool phase** – prior to mining Block 4, queue several new posts & associations; run `SyncMempoolToStateSyncer` to generate mempool diff and verify:  
     – Correct entries appear.  
     – Cursor is *not* advanced.  
     – After Block 4 commit, mempool diff is cleaned according to retention rule.

   • Validate each diff’s `StateChangeEntry` slice for: operation type, key bytes, encoder type, and (for deletes) empty value.

5. Verify cursor progression and file atomicity (temp file absent, final file exists).
6. Ensure retention: generate ≥3 blocks, assert mempool diff files older than 2 blocks are deleted.
7. Provide helper to create temp diff dir for each test (`os.MkdirTemp`).

### Acceptance Criteria
• Tests compile & pass with `go test ./core/...` on CI.  
• At least 4 blocks mined with assorted txns; diff files contain correct upsert/delete entries for keys touched.  
• Cursor monotonicity validated (`getLastSince` increases strictly).  
• Retention rule (keep 2) enforced.  
• Mempool diff file created, then removed after subsequent block commit.  
• No race detector failures (`go test -race`).

### File / Function References
• `core/lib/state_change_syncer.go` → `GenerateCommittedBlockDiff`, `getLastSince`, `ExtractStateChangesFromBackup`.  
• `core/lib/pos_blockchain.go` → `commitBlockPoS` (hook site).  
• Test helpers: `NewLowDifficultyBlockchain`, `NewTestMiner`, `SubmitPostMetadata` etc.  
• Existing blueprint tests: `block_view_association_test.go`, `block_view_dao_coin_limit_order_test.go`.

### Test Implementation Steps
1. **Setup**  
   a. `db, chain, params := NewLowDifficultyBlockchain(...)`  
   b. Create temp dir; initialise `StateChangeSyncer` with it; inject into `chain.eventManager` handlers or call manually after `MineAndProcessSingleBlock`.
2. **Workload Creation**  
   a. Mine initial funding blocks.  
   b. Submit at least: SubmitPost, UpdateProfile, DeleteProfile.  
   c. In block N+1 include conflicting update to same Post to test overwrite diff.
3. **Commit & Diff Generation**  
   a. After miner processes block, invoke `syncer.GenerateCommittedBlockDiff(db, height)`.  
   b. Assert file exists; parse via `ExtractStateChangesFromBackup`.
4. **Assertions**  
   – Verify number of entries equals transactions impact.  
   – For each expected key prefix, assert presence and correct `OperationType`.
5. **Mempool**  
   a. Trigger `SyncMempoolToStateSyncer`; assert mempool diff file exists.  
   b. Mine new block; ensure old mempool file deleted.
6. **Retention**  
   a. Mine 3rd and 4th block.  
   b. Assert diff file for block height 1 has been removed while 3 & 4 exist.

### Questions to Resolve Before Coding
• Preferred hook: modify `commitBlockPoS` under build tag `diff_test` or manually call generator in tests?  (Default: manual call in test to avoid prod changes.)

---

## Step 4 – Consumer Refactor (Committed Blocks)

**Objective:** Replace sequential file reader with per-block diff ingestion loop.

### Sub-tasks
1. Add directory watcher / polling loop in `StateSyncerConsumer`.
2. Determine highest processed height on startup (look at processed files or progress file).
3. On new file detection:
   a. Read raw bytes.
   b. Call `ExtractStateChangesFromBackup` (existing helper) to -> []*StateChangeEntry.
   c. Process entries via existing batching logic (reuse `SyncCommittedEntry`).
4. Delete/arch archive diff file after successful processing (configurable).
5. Remove now-unused continuous index file reading logic.

### Acceptance Criteria
- Consumer correctly imports state when new diff file drops in E2E test.
- Legacy path still works behind feature flag.

### File / Function References
- `state-consumer/consumer/consumer.go` (new `watchDiffDir()` func).

### Testing Steps
```
1. Produce synthetic diff file with two PostEntry upserts.
2. Start consumer pointing at dir – expect two inserts in mock handler.
3. Produce second diff – ensure only new diff consumed.
```

### Open Questions
- Should consumer handle gaps (missing heights) by failing or warning?

---

## Step 5 – Mempool Diff Generation & Cleanup

**Objective:** Continue separate mempool routine but output diff files analogous to committed path.

### Sub-tasks
1. After each `SyncMempoolToStateSyncer` success, create `mempool_<height>_<uuid>.bin` with queued bytes instead of encoded SCEs.
2. Establish deletion policy: keep mempool files only for the **two most recent blocks**, deleting older ones while holding `diffGenerationMu`.
3. Adjust `ExtractStateChangesFromBackup` to accept optional flag treating all keys as mempool (flushId = mempool uuid).

### Acceptance Criteria
- Continuous mempool files appear with diffs while mempool contains txns.
- Consumer applies & reverts correctly across mempool flushes (existing logic reused).

### File / Function References
- `core/lib/state_change_syncer.go` (mempool routine modifications).

### Testing Steps
```
1. Craft mempool with 3 txns.
2. Ensure mempool diff written.
3. Remove one txn -> new diff; consumer reverts first diff and applies second.
```

### Open Questions
- Should mempool diffs include ancestral records or rely on rollback markers?

---

## Step 6 – Consumer Refactor (Mempool)

**Objective:** Consume new mempool diff files and integrate with existing revert/apply flow.

### Sub-tasks
1. Mirror watcher loop for `mempool_*.bin` files.
2. Maintain ordered list of applied mempool flush ids to allow rollback.
3. On new mempool diff arrival:
   • If diff flushId differs from last applied, revert previous mempool entries then apply new ones.
4. Handle automatic cleanup when committed block processed.

### Acceptance Criteria
- Integration test passes with mined block after mempool flushes.

### File / Function References
- `state-consumer/consumer/consumer.go` (`SyncMempoolEntry`, `RevertMempoolEntries`).

### Testing Steps
As in Step 5 but from consumer perspective.

### Open Questions
- Best signalling mechanism from chain side that mempool flush is invalidated (currently BlockSyncFlushId logic – can keep).

---

## Step 7 – Hypersync Rewrite (Checkpoint Model)

**Objective:** Replace previous parallel chunk state dump with serial diff-based sync using BackupDatabase.

### Sub-tasks
1. During hypersync, after each snapshot chunk flush, persist diff file named `state_changes_hypersync_<ts>.bin` while holding `diffGenerationMu`.
2. Consumer: treat snapshot chunk files exactly like block diffs.
3. Evaluate performance vs old Parallel; optimise batch size if needed.

### Acceptance Criteria
- Full hypersync of new node completes and consumer DB matches checksum of reference state.

### File / Function References
- `core/lib/snapshot.go` (SetSnapshotChunk paths).

### Testing Steps
```
Run hypersync integration: node + consumer from scratch until fully current.
Compare consumer DB row counts vs expected.
```

### Open Questions
- Keep previous chunk parallelism but derive diff inside each goroutine?

---

## Step 8 – Remove Obsolete Event-Based Commit Path

**Objective:** Delete legacy state change file writer once new system proves stable.

### Sub-tasks
1. Feature flag `UseEventSyncer` defaults to false; run soak tests.
2. After validation, delete dead code paths and associated tests.

### Acceptance Criteria
- Build passes with flag removed.

### File / Function References
- Many inside `state_change_syncer.go` & `db_utils.go`.

### Testing
Regression suite only.

### Open Questions
- Timeframe for removal.

---

## Step 9 – Documentation & Example Consumers

**Objective:** Provide docs + sample Postgres & Kafka consumer code using new diff files.

### Sub-tasks
1. Update README in `state-consumer/` with new architecture and CLI flags.
2. Sample Go script to read diff dir and print metric counts.
3. Sample Python kafka publisher.

### Acceptance Criteria
- Docs reviewed by devrel.

---

## Step 10 – CI/CD & Backward Compatibility Gates

**Objective:** Ensure automated tests cover both old and new flows during transition.

### Sub-tasks
1. Add GitHub actions job running integration test with diff flow.
2. Keep legacy path behind flag until Step 8.

### Acceptance Criteria
- All CI jobs green.

---

## Step 5B – Sequential Mempool Diff Files (Refined Approach)

**Objective:** Generate sequential diff files where each file contains only changes since the last mempool sync, allowing stateless consumer processing.

### Consumer Flow (As Specified)
1. Determine most recent committed block synced
2. Look for first `mempool_<block+1>_<timestamp>.bin` file  
3. Apply all changes from that file sequentially
4. Continue applying subsequent mempool files for same block in timestamp order
5. When new block commits, revert all mempool changes using ancestral records in reverse order
6. Start fresh with next block's mempool files

### Node-Side Implementation

```go
type MempoolSyncState struct {
    // Track what was written in the last mempool sync for this block height
    lastSyncState map[string][]byte  // key -> value from last sync
    currentBlockHeight uint64
    lastSyncTimestamp int64
}

func (stateChangeSyncer *StateChangeSyncer) SyncMempoolToStateSyncer(server *Server) (bool, error) {
    // ... existing setup code until FlushToDbWithTxn ...
    
    err = mempoolTxUtxoView.FlushToDbWithTxn(txn, uint64(server.blockchain.BlockTip().Height))
    if err != nil {
        // ... existing error handling ...
    }
    
    // NEW: Generate sequential diff from transaction
    err = stateChangeSyncer.generateSequentialMempoolDiff(txn, mempoolEventManager.lastCommittedViewTxn, blockHeight)
    if err != nil {
        glog.Errorf("Failed to generate mempool diff: %v", err)
        // Continue with existing flow
    }
    
    // ... rest of existing logic ...
}

func (stateChangeSyncer *StateChangeSyncer) generateSequentialMempoolDiff(
    mempoolTxn *badger.Txn,
    baseTxn *badger.Txn, 
    blockHeight uint64,
) error {
    stateChangeSyncer.DiffGenerationMutex.Lock()
    defer stateChangeSyncer.DiffGenerationMutex.Unlock()
    
    // Initialize or reset state tracking for new block height
    if stateChangeSyncer.mempoolSyncState == nil || 
       stateChangeSyncer.mempoolSyncState.currentBlockHeight != blockHeight {
        stateChangeSyncer.mempoolSyncState = &MempoolSyncState{
            lastSyncState:      make(map[string][]byte),
            currentBlockHeight: blockHeight,
            lastSyncTimestamp:  0,
        }
    }
    
    // 1. Extract current mempool state from transaction
    currentMempoolState := stateChangeSyncer.extractStateFromTransaction(mempoolTxn)
    
    // 2. Compare with last sync to find changes
    changes, ancestralRecords := stateChangeSyncer.computeMempoolDiff(
        stateChangeSyncer.mempoolSyncState.lastSyncState, 
        currentMempoolState,
        baseTxn,
    )
    
    // Skip if no changes
    if len(changes) == 0 {
        return nil
    }
    
    // 3. Generate file names
    timestamp := time.Now().UnixNano()
    diffFile := fmt.Sprintf("mempool_%d_%d.bin", blockHeight, timestamp)
    ancestralFile := fmt.Sprintf("mempool_ancestral_%d_%d.bin", blockHeight, timestamp)
    
    // 4. Write diff file (only changes since last sync)
    diffBytes := stateChangeSyncer.encodeMempoolChanges(changes)
    err := stateChangeSyncer.writeAtomicFile(diffFile, diffBytes)
    if err != nil {
        return err
    }
    
    // 5. Write ancestral records for this diff
    if len(ancestralRecords) > 0 {
        ancestralBytes := stateChangeSyncer.encodeAncestralRecords(ancestralRecords)
        err = stateChangeSyncer.writeAtomicFile(ancestralFile, ancestralBytes)
        if err != nil {
            return err
        }
    }
    
    // 6. Update state tracking for next diff
    stateChangeSyncer.mempoolSyncState.lastSyncState = currentMempoolState
    stateChangeSyncer.mempoolSyncState.lastSyncTimestamp = timestamp
    
    // 7. Clean up old files (different block heights)
    return stateChangeSyncer.cleanupOldMempoolFiles(int32(blockHeight))
}

func (stateChangeSyncer *StateChangeSyncer) extractStateFromTransaction(txn *badger.Txn) map[string][]byte {
    state := make(map[string][]byte)
    
    opts := badger.DefaultIteratorOptions
    opts.PrefetchValues = true
    
    it := txn.NewIterator(opts)
    defer it.Close()
    
    for it.Rewind(); it.Valid(); it.Next() {
        item := it.Item()
        key := item.Key()
        
        if !isCoreStateKey(key) {
            continue
        }
        
        value, err := item.ValueCopy(nil)
        if err != nil {
            continue
        }
        
        state[string(key)] = value
    }
    
    return state
}

func (stateChangeSyncer *StateChangeSyncer) computeMempoolDiff(
    lastState map[string][]byte,
    currentState map[string][]byte, 
    baseTxn *badger.Txn,
) (changes map[string][]byte, ancestralRecords []AncestralRecord) {
    
    changes = make(map[string][]byte)
    
    // Find new and modified entries
    for key, currentValue := range currentState {
        lastValue, existed := lastState[key]
        
        if !existed {
            // New entry
            changes[key] = currentValue
            
            // Get original value from committed state for ancestral record
            var originalValue []byte
            if item, err := baseTxn.Get([]byte(key)); err == nil {
                originalValue, _ = item.ValueCopy(nil)
            }
            
            ancestralRecords = append(ancestralRecords, AncestralRecord{
                Key:           []byte(key),
                PreviousValue: originalValue,
                Operation:     AncestralOperationInsert,
            })
            
        } else if !bytes.Equal(lastValue, currentValue) {
            // Modified entry  
            changes[key] = currentValue
            
            ancestralRecords = append(ancestralRecords, AncestralRecord{
                Key:           []byte(key),
                PreviousValue: lastValue,
                Operation:     AncestralOperationUpdate,
            })
        }
    }
    
    // Find deleted entries (in last state but not current)
    for key, lastValue := range lastState {
        if _, exists := currentState[key]; !exists {
            // Entry was deleted/ejected
            changes[key] = nil // nil value indicates deletion
            
            ancestralRecords = append(ancestralRecords, AncestralRecord{
                Key:           []byte(key),
                PreviousValue: lastValue,
                Operation:     AncestralOperationDelete,
            })
        }
    }
    
    return changes, ancestralRecords
}

func (stateChangeSyncer *StateChangeSyncer) encodeMempoolChanges(changes map[string][]byte) []byte {
    var buffer bytes.Buffer
    
    for key, value := range changes {
        // Create KV entry (reuse badger backup format)
        kv := &pb.KV{
            Key:   []byte(key),
            Value: value, // nil for deletions
        }
        
        kvList := &pb.KVList{Kv: []*pb.KV{kv}}
        kvBytes, err := proto.Marshal(kvList)
        if err != nil {
            continue
        }
        
        // Write in badger backup format
        binary.Write(&buffer, binary.LittleEndian, uint32(len(kvBytes)))
        binary.Write(&buffer, binary.LittleEndian, uint32(0)) // CRC placeholder  
        buffer.Write(kvBytes)
    }
    
    return buffer.Bytes()
}
```

### Block Commit Integration

When a new block commits, clean up mempool state:

```go
func (stateChangeSyncer *StateChangeSyncer) onBlockCommit(blockHeight uint64) {
    stateChangeSyncer.DiffGenerationMutex.Lock()
    defer stateChangeSyncer.DiffGenerationMutex.Unlock()
    
    // Reset mempool sync state for the new block height
    stateChangeSyncer.mempoolSyncState = nil
    
    // Clean up old mempool files (keep only current block height files)
    stateChangeSyncer.cleanupOldMempoolFiles(int32(blockHeight))
}
```

### Consumer Implementation

```go
// In state-consumer/consumer/consumer.go
func (consumer *Consumer) processMempoolForBlock(blockHeight uint64) error {
    // 1. Find all mempool files for this block height
    pattern := fmt.Sprintf("mempool_%d_*.bin", blockHeight)
    files, err := filepath.Glob(filepath.Join(consumer.stateDir, pattern))
    if err != nil {
        return err
    }
    
    // 2. Sort by timestamp
    sort.Strings(files) // timestamp ordering
    
    // 3. Apply each file sequentially
    var appliedFiles []string
    for _, file := range files {
        err := consumer.applyMempoolDiffFile(file)
        if err != nil {
            return err
        }
        appliedFiles = append(appliedFiles, file)
    }
    
    // 4. Store applied files for later revert
    consumer.currentMempoolFiles = appliedFiles
    return nil
}

func (consumer *Consumer) revertMempoolChanges() error {
    // Apply ancestral records in reverse order
    for i := len(consumer.currentMempoolFiles) - 1; i >= 0; i-- {
        file := consumer.currentMempoolFiles[i]
        ancestralFile := strings.Replace(file, "mempool_", "mempool_ancestral_", 1)
        
        err := consumer.applyAncestralRecords(ancestralFile)
        if err != nil {
            return err
        }
    }
    
    consumer.currentMempoolFiles = nil
    return nil
}
```

### Benefits of Sequential Approach

1. **Stateless Consumer**: Consumer doesn't need to track mempool state
2. **Clear Semantics**: Each file is a diff since the last file  
3. **Simple Revert**: Just apply ancestral records in reverse order
4. **Efficient**: Only transmits actual changes between syncs
5. **Deterministic**: Sequential processing ensures consistent state

### Implementation Effort

This approach requires:
- Simple state tracking on node side (map of last sync state)
- Diff computation logic (comparing two maps)
- Consumer updates for sequential processing
- Block commit integration to reset state

**Estimated effort: 1-2 weeks** - much simpler than the original complex approach while meeting all your requirements.

---

## Step 5C – Transaction Extraction Strategy (New Implementation Plan)

**Objective:** Separate transaction connection logic from state extraction to create a clean, modular architecture.

### Current Problem Analysis

The existing `SyncMempoolToStateSyncer` mixes two different types of state extraction:

1. **Flushed State Changes**: Extracted from badger transaction after `FlushToDbWithTxn` 
2. **Transaction/UtxoOp Entries**: Manually created by connecting transactions

These need to be separated because:
- Transaction entries are NOT part of the badger flush
- They must be recreated each sync due to transaction ordering
- They follow predictable patterns (Transaction + UtxoOps per block/transaction)
- Caching is problematic due to fee-timestamp ordering changes

### Proposed Architecture

```go
// Main orchestration function
func (stateChangeSyncer *StateChangeSyncer) generateSequentialMempoolDiff(
    mempoolTxn *badger.Txn,
    baseTxn *badger.Txn, 
    blockHeight uint64,
) error {
    // 1. Extract flushed state changes
    flushedState := stateChangeSyncer.extractStateFromTransaction(mempoolTxn)
    
    // 2. Extract transaction entries  
    transactionState, err := stateChangeSyncer.extractTransactionEntries(server, blockHeight)
    if err != nil {
        return err
    }
    
    // 3. Merge both states
    currentMempoolState := mergeMempoolStates(flushedState, transactionState)
    
    // 4. Continue with existing diff logic...
    changed, deleted, ancestralRecords := stateChangeSyncer.computeMempoolDiff(
        stateChangeSyncer.mempoolSyncState.lastSyncState, 
        currentMempoolState,
        baseTxn,
    )
    
    // ... rest of function
}
```

### New Functions to Implement

#### 1. `extractTransactionEntries`
```go
func (stateChangeSyncer *StateChangeSyncer) extractTransactionEntries(
    server *Server, 
    blockHeight uint64,
) (map[string][]byte, error)
```

**Responsibilities:**
- Connect uncommitted blocks and extract Block + UtxoOp entries
- Connect mempool transactions and extract Transaction + UtxoOp entries  
- Return consistent `map[string][]byte` format
- Handle all transaction ordering and connection logic

#### 2. `mergeMempoolStates`
```go
func mergeMempoolStates(
    flushedState map[string][]byte,
    transactionState map[string][]byte,
) map[string][]byte
```

**Responsibilities:**
- Merge flushed state and transaction state into single map
- Handle any key conflicts (transaction state should override)
- Return combined state for diff computation

### Implementation Strategy

#### Phase 1: Extract Transaction Logic
1. Create `extractTransactionEntries` function
2. Move uncommitted block connection logic
3. Move mempool transaction connection logic  
4. Return map format instead of using event handlers

#### Phase 2: Integration
1. Create `mergeMempoolStates` helper
2. Update `generateSequentialMempoolDiff` to use both functions
3. Add comprehensive tests

#### Phase 3: Optimization Notes (Future)
- **Transaction Caching**: Could cache `ConnectTransaction` results per transaction hash
- **Ordering Optimization**: Could track transaction order changes and incrementally update
- **Batch Processing**: Could batch similar transaction types
- **Validation Caching**: Could cache transaction validation results

⚠️ **Note**: Caching optimizations deferred due to complexity of fee-timestamp ordering changes

### Key Benefits

1. **Separation of Concerns**: Flushed state vs Transaction state clearly separated
2. **Testability**: Each function can be tested independently
3. **Maintainability**: Transaction logic isolated and easier to understand
4. **Reusability**: Transaction extraction could be used elsewhere
5. **Performance**: Clear bottlenecks identified for future optimization

### File Organization

- `extractStateFromTransaction` ✅ (Completed)
- `extractTransactionEntries` 🔄 (New - To Implement)  
- `mergeMempoolStates` 🔄 (New - To Implement)
- `generateSequentialMempoolDiff` 🔄 (Update - Integrate new functions)

### Testing Strategy

#### Unit Tests for `extractTransactionEntries`:
1. **Uncommitted Blocks**: Verify Block and UtxoOp entries created correctly
2. **Mempool Transactions**: Verify Transaction and UtxoOp entries created correctly
3. **Mixed Scenarios**: Both uncommitted blocks and mempool transactions
4. **Error Handling**: Transaction connection failures
5. **Empty Cases**: No uncommitted blocks, no mempool transactions

#### Integration Tests:
1. **End-to-End**: Full mempool diff with flushed + transaction state
2. **State Merging**: Verify flushed and transaction states merge correctly
3. **Performance**: Large mempool with many transactions

### Migration Path

1. Implement new functions alongside existing logic
2. Add feature flag to switch between old/new implementations
3. Comprehensive testing of new implementation
4. Gradual rollout and performance comparison
5. Remove old implementation once validated

This approach maintains the sequential diff functionality while creating a clean, maintainable architecture that separates the different types of state extraction.

## Implementation Summary & Next Steps

### Summary of Analysis
The mempool refactor represents a significant architectural shift from event-driven to stream-based state tracking. Based on analysis of the current implementation, the key challenges and solutions are:

#### Current System Complexity
- **Sophisticated Ejection Detection**: The existing system uses three maps (`MempoolSyncedKeyValueMap`, `MempoolFlushKeySet`, `MempoolNewlyFlushedTxns`) to track mempool state and detect ejected transactions
- **Event-Driven Architecture**: State changes are captured via event handlers and written to a single `mempool.bin` file
- **Complex Revert Logic**: Ancestral records are embedded in `StateChangeEntry` structures with `IsReverted` flags

#### New System Benefits
- **Incremental Files**: `mempool_<height>_<ts>.bin` format enables better tracking and cleanup
- **Separate Ancestral Records**: Cleaner separation of concerns with dedicated revert files
- **Stream-Based Detection**: Leverages proven badger streaming technology used for block commits
- **Better Performance**: Reduces event handler overhead and improves consumer processing

### Implementation Priority Matrix

| Component | Priority | Complexity | Dependencies |
|-----------|----------|------------|--------------|
| 5.1 - MempoolStateManager | **HIGH** | Medium | None |
| 5.11 - Change Detection Algorithm | **HIGH** | High | 5.1 |
| 5.4 - File Generation | **HIGH** | Medium | 5.1, 5.11 |
| 5.13 - Ancestral Record Format | **HIGH** | Medium | 5.11 |
| 5.12 - Performance Optimization | **MEDIUM** | High | 5.1, 5.11 |
| 5.14 - Consumer Integration | **MEDIUM** | Medium | 5.4, 5.13 |
| 5.17 - Error Recovery | **MEDIUM** | Medium | All core components |
| 5.15 - Metrics & Monitoring | **LOW** | Low | 5.11 |
| 5.18 - Comprehensive Testing | **LOW** | Medium | All components |

### Recommended Implementation Phases

#### Phase 1: Core Infrastructure (Weeks 1-2)
**Goal**: Establish the foundation for stream-based mempool syncing

**Tasks**:
1. Implement `MempoolStateManager` with in-memory state tracking (5.1)
2. Create basic change detection algorithm (5.11) 
3. Implement incremental file generation (5.4)
4. Design ancestral record format (5.13)

**Success Criteria**:
- Can generate mempool diff files from current mempool state
- Basic ejection detection works (new/modified/ejected entries)
- Files written atomically with proper naming convention

#### Phase 2: Integration & Optimization (Weeks 3-4)
**Goal**: Integrate with existing system and optimize performance

**Tasks**:
1. Replace existing `SyncMempoolToStateSyncer` implementation (5.7)
2. Implement performance optimizations (5.12)
3. Add error recovery mechanisms (5.17)
4. Update `StateChangeSyncer` structure (5.8)

**Success Criteria**:
- New system works alongside existing block commit diff generation
- Performance meets or exceeds current implementation
- Graceful error handling and recovery

#### Phase 3: Consumer & Testing (Weeks 5-6)
**Goal**: Complete end-to-end functionality and validation

**Tasks**:
1. Update consumer to handle new file formats (5.14)
2. Implement comprehensive test suite (5.18-5.19)
3. Add metrics and monitoring (5.15)
4. Perform migration testing with parallel implementations

**Success Criteria**:
- Consumer correctly processes incremental mempool files
- All existing mempool functionality preserved
- Performance metrics validate the improvements

### Implementation Checklist

#### Core Components
- [ ] `MempoolStateManager` struct with required fields
- [ ] In-memory badger DB or map-based state tracking  
- [ ] Change detection algorithm (new/modified/ejected)
- [ ] Incremental file generation with atomic writes
- [ ] Ancestral record file format and encoding
- [ ] File cleanup and retention policy
- [ ] Integration with existing `StateChangeSyncer`

#### Consumer Updates
- [ ] Parse new incremental file format
- [ ] Handle ancestral record files for reverts
- [ ] Update file watching logic for new naming convention
- [ ] Implement reset signal handling for error recovery

#### Testing & Validation
- [ ] Unit tests for `MempoolStateManager`
- [ ] Integration tests with live mempool
- [ ] Performance benchmarks vs current implementation
- [ ] Migration testing with parallel systems
- [ ] Error recovery and edge case testing

#### Documentation & Deployment
- [ ] Update README with new architecture
- [ ] Document consumer changes and migration process
- [ ] Feature flag for gradual rollout
- [ ] Monitoring and alerting for new metrics

### Risk Mitigation Strategies

#### Performance Risks
- **Risk**: State reconstruction overhead on each sync cycle
- **Mitigation**: Implement incremental updates and caching (5.12)
- **Fallback**: Adjust sync frequency if performance degrades

#### Data Consistency Risks  
- **Risk**: Race conditions between mempool changes and sync
- **Mitigation**: Use existing `DiffGenerationMutex` for synchronization
- **Fallback**: Implement reset mechanism for corrupted state (5.17)

#### Consumer Compatibility Risks
- **Risk**: Breaking changes for existing consumers
- **Mitigation**: Feature flag and parallel operation during migration
- **Fallback**: Keep legacy format as backup option

### Key Design Decisions

1. **Map-Based vs Badger DB**: Start with lightweight map-based state tracking, add badger DB if streaming benefits are significant
2. **File Format**: Use badger backup format for diff files to leverage existing parsing logic
3. **Ancestral Records**: Separate files with structured format for better revert handling
4. **Error Recovery**: Full reset strategy with consumer signaling for simplicity
5. **Performance**: Focus on incremental updates rather than full reconstruction

### Success Metrics

- **Performance**: Mempool sync time should be ≤ current implementation
- **Memory**: Memory usage should not exceed 2x current implementation
- **Reliability**: Error rate should be < 0.1% of sync operations
- **Compatibility**: 100% functional compatibility with existing consumer behavior
- **Maintainability**: Reduced complexity in state tracking logic

This implementation plan provides a clear roadmap for migrating from the event-driven mempool syncing to a stream-based approach that aligns with the overall state change syncer refactor goals while addressing the specific challenges of mempool state management.

---

### Implementation Status Update

#### ✅ COMPLETED: extractStateFromTransaction
- **Function**: `extractStateFromTransaction(txn *badger.Txn) map[string][]byte`
- **Location**: `core/lib/state_change_syncer.go` (lines 1382-1412)
- **Tests**: `core/lib/state_change_syncer_mempool_test.go`
  - ✅ Core state update test
  - ✅ Multiple update test (most recent value wins)
  - ✅ Integration test with submit post transaction
- **Status**: Fully implemented and tested

#### ✅ COMPLETED: Sequential Mempool Diff Functions (Phase 1)
- **Functions**: 
  - `computeMempoolDiff` (lines 1420-1487)
  - `generateSequentialMempoolDiff` (lines 1489-1548)
  - Supporting functions: `encodeMempoolChanges`, `encodeAncestralRecords`, `writeAtomicFile`, `cleanupOldMempoolFiles`
- **Types**: `AncestralOperation`, `AncestralRecord`, `MempoolSyncState`
- **Tests**: 
  - ✅ `TestComputeMempoolDiff_SingleTransaction`
  - ✅ `TestGenerateSequentialMempoolDiff_SingleTransaction`
- **Status**: Basic implementation complete, first test case passing

#### 🔄 IN PROGRESS: Comprehensive Test Coverage (Phase 2)

**Remaining Test Cases:**

##### Test Cases for `computeMempoolDiff`:
1. ✅ **Single Transaction**: One new entry in current state
2. **Multiple Same Key**: Multiple updates to same key in current state
3. **Cross-Scan Creation**: Entry in previous, different entry in current  
4. **Cross-Scan Update**: Same key, different value between scans
5. **Cross-Scan Delete-Recreate**: Entry exists → deleted → recreated with original value
6. **Mixed Operations**: Combination of creates, updates, deletes in single diff
7. **Empty States**: Both empty, only current empty, only previous empty
8. **Large State**: Performance test with many entries

##### Test Cases for `generateSequentialMempoolDiff`:
1. ✅ **Single Transaction File**: One mempool transaction generates correct file
2. **Multiple Same Key File**: Multiple updates generate single entry in file
3. **Sequential Files**: Multiple scans generate properly named sequential files
4. **Ancestral Records**: Verify ancestral record file generation and content
5. **File Cleanup**: Old files removed when block commits
6. **Timestamp Ordering**: Files generated in correct timestamp order
7. **Block Height Transition**: Proper file naming across block height changes
8. **Error Handling**: Failed writes, disk full scenarios

**Implementation Priority:**
- ✅ Phase 1: Implement both functions with basic logic
- ✅ Phase 2: Add first test case for each function  
- 🔄 Phase 3: Add remaining test cases incrementally
- Phase 4: Performance and error handling tests
