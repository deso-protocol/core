# State Change Syncer Refactor – Implementation Plan

## Overview (High-Level Goals)
This refactor replaces the *event-per-write* state-change logging mechanism with a **diff-based streaming model** built on Badger’s `DB.Stream()` API.

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
