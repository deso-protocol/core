# Cauterize Entry Count Mode - Quick Reference

## Two Cauterization Modes

### Mode 1: Cauterize by Entry Count (NEW!)
Remove a specific number of entries from the **tip** (end) of state-changes files.

```bash
./backend \
  --state-change-dir=/state-changes \
  --consumer-progress-dir=/consumer-progress \
  --cauterize-state-changes=true \
  --cauterize-entry-count=1000

# Or with environment variables
export STATE_CHANGE_DIR=/state-changes
export CONSUMER_PROGRESS_DIR=/consumer-progress
export CAUTERIZE_STATE_CHANGES=true
export CAUTERIZE_ENTRY_COUNT=1000
./backend
```

**✨ NEW: Consumer Progress Auto-Update**
- If `--consumer-progress-dir` is provided, consumer progress is **automatically updated** to match the truncated state
- No manual intervention needed!
- Consumer can resume immediately without errors

**When to Use:**
- ✅ You know corruption is at the tip (most recent entries)
- ✅ You want to remove a specific number of recent entries
- ✅ Consumer progress is ahead or unreliable
- ✅ You want automatic consumer progress management

### Mode 2: Cauterize to Consumer Progress (Original)
Truncate to where the consumer last successfully processed.

```bash
./backend \
  --state-change-dir=/state-changes \
  --consumer-progress-dir=/consumer-progress \
  --cauterize-state-changes=true

# Note: --cauterize-entry-count is NOT set (or set to 0)
```

**When to Use:**
- ✅ Consumer progress is accurate and behind corruption
- ✅ You want to preserve everything consumer processed
- ✅ Corruption is somewhere after consumer's position

---

## Mode Selection Logic

```
IF --cauterize-state-changes=true:
    IF --cauterize-entry-count > 0:
        → Use Mode 1: Remove N entries from tip
        → IF --consumer-progress-dir is provided:
            → Consumer progress automatically updated ✅
        → ELSE:
            → Warning: Manual consumer progress update needed ⚠️
    ELSE:
        → Use Mode 2: Truncate to consumer progress
        → --consumer-progress-dir IS required
        → Consumer progress remains unchanged (already correct)
```

---

## Example: Your Current Situation

**Problem:**
- Consumer progress: 1,266,870,209 entries
- Actual entries in files: 1,266,870,195 entries
- Consumer is **14 entries ahead** (inconsistent state)

**Solution with Auto-Update (RECOMMENDED):**

```bash
# Remove the last 1000 entries AND auto-update consumer progress
./backend \
  --state-change-dir=/state-changes \
  --consumer-progress-dir=/consumer-progress \
  --cauterize-state-changes=true \
  --cauterize-entry-count=1000
```

**What happens:**
```
Total entries: 1,266,870,195
Entries to remove: 1,000
Remaining entries: 1,266,869,195
✅ Consumer progress automatically set to: 1,266,869,195
✅ Consumer can resume immediately!
```

**Alternative: Without Auto-Update (NOT RECOMMENDED):**
```bash
# If you don't provide --consumer-progress-dir
./backend \
  --state-change-dir=/state-changes \
  --cauterize-state-changes=true \
  --cauterize-entry-count=1000

# You'll see warnings:
# ⚠️  Consumer progress directory not provided - consumer progress NOT updated
# ⚠️  You must manually set consumer progress to 1266869195 or the consumer will crash

# Then manually update:
python3 -c "import struct; open('/consumer-progress/consumer-progress.bin', 'wb').write(struct.pack('<Q', 1266869195))"
```

---

## Comparison

| Feature | Entry Count Mode | Consumer Progress Mode |
|---------|------------------|----------------------|
| **Requires consumer progress** | ❌ No (optional) | ✅ Yes (required) |
| **Auto-updates consumer progress** | ✅ Yes (if dir provided) | ➖ N/A (already correct) |
| **Fixed number of entries** | ✅ Yes | ❌ No (depends on progress) |
| **Good for tip corruption** | ✅ Yes | ❌ May miss it |
| **Good for known corruption** | ✅ Yes | ❌ Depends on progress |
| **Consumer ahead issue** | ✅ Handles it | ❌ Errors out |
| **Preserves consumer work** | ⚠️ Maybe | ✅ Yes |

---

## Output Examples

### Mode 1: Entry Count (With Consumer Progress Auto-Update)

```
I0122 15:42:10.123456  1 server.go:479] Cauterize mode enabled with entry count: 1000 entries from tip
I0122 15:42:10.123789  1 state_change_syncer.go:549] === CAUTERIZE BY ENTRY COUNT STARTED ===
I0122 15:42:10.123890  1 state_change_syncer.go:550] Entries to remove from tip: 1000
I0122 15:42:10.124012  1 state_change_syncer.go:567] Total entries in state-changes: 1266870195
I0122 15:42:10.124234  1 state_change_syncer.go:577] Target entry index after cauterization: 1266869195
I0122 15:42:10.124456  1 state_change_syncer.go:579] This will remove the last 1000 entries (indices 1266869195 through 1266870194)
W0122 15:42:10.124890  1 state_change_syncer.go:618] ⚠️  CAUTERIZE WILL REMOVE 1000 ENTRIES (50636915 BYTES OF DATA)
W0122 15:42:10.124991  1 state_change_syncer.go:619] ⚠️  This operation is DESTRUCTIVE and cannot be undone
W0122 15:42:10.125092  1 state_change_syncer.go:620] ⚠️  Proceeding in 5 seconds... (Ctrl+C to cancel)
I0122 15:42:15.125234  1 state_change_syncer.go:628] ✓ Truncated state-changes.bin to 781363084099 bytes
I0122 15:42:15.125456  1 state_change_syncer.go:635] ✓ Truncated state-changes-index.bin to 10134953560 bytes
I0122 15:42:15.125567  1 state_change_syncer.go:649] Updating consumer progress file at /consumer-progress/consumer-progress.bin
I0122 15:42:15.125678  1 state_change_syncer.go:664] ✓ Updated consumer-progress.bin to entry index: 1266869195
I0122 15:42:15.125789  1 state_change_syncer.go:678] ✓ Cleared mempool.bin
I0122 15:42:15.125890  1 state_change_syncer.go:685] ✓ Cleared mempool-index.bin
I0122 15:42:15.125991  1 state_change_syncer.go:690] === CAUTERIZE BY ENTRY COUNT COMPLETE ===
I0122 15:42:15.126092  1 state_change_syncer.go:692]   - Removed 1000 entries from the tip
I0122 15:42:15.126193  1 state_change_syncer.go:693]   - Removed 50636915 bytes from state-changes.bin
I0122 15:42:15.126294  1 state_change_syncer.go:694]   - Removed 8000 bytes from state-changes-index.bin
I0122 15:42:15.126395  1 state_change_syncer.go:695]   - Remaining entries: 1266869195 (indices 0 through 1266869194)
I0122 15:42:15.126496  1 state_change_syncer.go:697]   - Consumer progress updated to: 1266869195
I0122 15:42:15.126597  1 state_change_syncer.go:699]   - Node will now replay blocks to regenerate removed entries
```

### Mode 2: Consumer Progress

```
I0122 15:42:10.123456  1 server.go:489] Cauterize mode enabled, truncating state-changes to consumer progress...
I0122 15:42:10.123789  1 state_change_syncer.go:403] === CAUTERIZE OPERATION STARTED ===
I0122 15:42:10.123890  1 state_change_syncer.go:404] Consumer Progress Dir: /consumer-progress
I0122 15:42:10.124012  1 state_change_syncer.go:420] Last processed entry index: 1266869195
[... rest of output similar to original cauterize ...]
```

---

## Command-Line Flags Summary

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--cauterize-state-changes` | bool | false | Yes (to enable) | Enable cauterize operation |
| `--cauterize-entry-count` | uint64 | 0 | No | Number of entries to remove from tip |
| `--consumer-progress-dir` | string | "" | Only if entry-count=0 | Directory with consumer-progress.bin |
| `--state-change-dir` | string | "" | Yes | Directory with state-changes files |

---

## Quick Decision Tree

```
Do you know exactly how many entries to remove?
├─ YES → Use --cauterize-entry-count=N
│         (Don't need consumer progress)
│
└─ NO → Is consumer progress accurate?
    ├─ YES → Use consumer progress mode
    │         (Omit --cauterize-entry-count)
    │
    └─ NO → Either:
            1. Fix consumer progress first, then use it
            2. Estimate entry count and use entry count mode
            3. Full resync
```

---

## Safety Notes

⚠️ **Entry Count Mode:**
- Removes from the **tip** (most recent)
- Ignores consumer progress completely
- Consumer may need progress file updated afterward
- Good for known corruption at end

⚠️ **Consumer Progress Mode:**
- Removes everything **after** consumer's last processed entry
- Relies on accurate consumer progress
- Will error if consumer is ahead of files
- Good for preserving consumer's work

Both modes:
- 5-second warning before truncation
- Clear all mempool files
- Require node restart afterward
- Are DESTRUCTIVE (make backups!)

---

See [CAUTERIZE.md](./CAUTERIZE.md) for complete documentation.

