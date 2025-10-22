# State-Changes Cauterize Operation

## Overview

The **cauterize operation** is a surgical recovery mechanism that allows the DeSo core node to truncate corrupted state-changes data and replay from a clean snapshot. This is useful when corruption is detected downstream of the consumer's progress, avoiding the need for a full resync.

## What It Does

When enabled, the cauterize operation:
1. Reads the consumer's last successfully processed entry index from `consumer-progress.bin`
2. Calculates the corresponding byte position in `state-changes.bin` using the index file
3. Truncates both `state-changes.bin` and `state-changes-index.bin` to that position
4. Clears mempool files (they will be regenerated)
5. Allows the node to continue, replaying blocks to regenerate the removed entries

## Benefits

✅ **Surgical**: Only removes corrupted data, preserves good data
✅ **Fast**: No full resync needed for the consumer
✅ **Safe**: Upserts in the consumer handle duplicate entries gracefully
✅ **Flexible**: Can be run multiple times if needed
✅ **Diagnostic**: Clear logging shows exactly what was removed

## Usage

### Prerequisites

1. **Stop all services**:
   - Stop the core node
   - Stop the state consumer (e.g., postgres-data-handler)

2. **Identify corruption**:
   - Run diagnostics on the consumer to confirm corruption
   - Note the consumer's last successful entry index (automatically saved in `consumer-progress.bin`)

3. **(Optional) Revert core snapshot**:
   - If the core node is ahead of the corruption, revert to a snapshot before the corruption
   - This ensures the core can replay the blocks

### Command

```bash
./backend \
  --state-change-dir=/path/to/state-changes \
  --consumer-progress-dir=/path/to/consumer-progress \
  --cauterize-state-changes=true

# Or with environment variables
export STATE_CHANGE_DIR=/path/to/state-changes
export CONSUMER_PROGRESS_DIR=/path/to/consumer-progress
export CAUTERIZE_STATE_CHANGES=true
./backend
```

### Expected Output

```
I0122 15:42:10.123456  1 server.go:479] Cauterize mode enabled, truncating state-changes to consumer progress...
I0122 15:42:10.123789  1 state_change_syncer.go:403] === CAUTERIZE OPERATION STARTED ===
I0122 15:42:10.123890  1 state_change_syncer.go:404] Consumer Progress Dir: /path/to/consumer-progress
I0122 15:42:10.124012  1 state_change_syncer.go:420] Last processed entry index: 123456
I0122 15:42:10.124234  1 state_change_syncer.go:460] Byte position in state-changes.bin: 781363084099
I0122 15:42:10.124456  1 state_change_syncer.go:472] Current state-changes.bin size: 832000000000 bytes
I0122 15:42:10.124567  1 state_change_syncer.go:473] Current state-changes-index.bin size: 987648 bytes
I0122 15:42:10.124678  1 state_change_syncer.go:474] Will remove 50636915901 bytes from state-changes.bin
I0122 15:42:10.124789  1 state_change_syncer.go:475] Will remove 12352 bytes from state-changes-index.bin
W0122 15:42:10.124890  1 state_change_syncer.go:477] ⚠️  CAUTERIZE WILL REMOVE 50636915901 BYTES OF DATA
W0122 15:42:10.124991  1 state_change_syncer.go:478] ⚠️  This operation is DESTRUCTIVE and cannot be undone
W0122 15:42:10.125092  1 state_change_syncer.go:479] ⚠️  Proceeding in 5 seconds... (Ctrl+C to cancel)
I0122 15:42:15.125234  1 state_change_syncer.go:487] ✓ Truncated state-changes.bin to 781363084099 bytes
I0122 15:42:15.125456  1 state_change_syncer.go:494] ✓ Truncated state-changes-index.bin to 987648 bytes
I0122 15:42:15.125567  1 state_change_syncer.go:504] ✓ Cleared mempool.bin
I0122 15:42:15.125678  1 state_change_syncer.go:511] ✓ Cleared mempool-index.bin
I0122 15:42:15.125789  1 state_change_syncer.go:516] === CAUTERIZE OPERATION COMPLETE ===
I0122 15:42:15.125890  1 state_change_syncer.go:517] Summary:
I0122 15:42:15.125991  1 state_change_syncer.go:518]   - Removed 50636915901 bytes from state-changes.bin
I0122 15:42:15.126092  1 state_change_syncer.go:519]   - Removed 12352 bytes from state-changes-index.bin
I0122 15:42:15.126193  1 state_change_syncer.go:520]   - Consumer can resume from entry index 123456
I0122 15:42:15.126294  1 state_change_syncer.go:521]   - Node will now replay blocks to regenerate removed entries
```

### After Cauterize

1. **Stop the node** (the cauterize happens on startup, then the node continues normally)
   ```bash
   # Ctrl+C or kill the process
   ```

2. **Start the core node normally** (without cauterize flag)
   ```bash
   ./backend --state-change-dir=/path/to/state-changes
   ```

3. The node will:
   - Continue from where it left off
   - Replay blocks to regenerate the removed state-changes
   - Write new entries to the state-changes files

4. **Start the consumer**
   ```bash
   ./postgres-data-handler
   ```

5. The consumer will:
   - Resume from its last processed entry index
   - Process the regenerated state-changes
   - Upserts will handle any duplicate entries gracefully

## Configuration

### Environment Variables / Command-Line Flags

| Flag | Environment Variable | Required | Description |
|------|---------------------|----------|-------------|
| `--state-change-dir` | `STATE_CHANGE_DIR` | Yes | Directory containing state-changes files |
| `--consumer-progress-dir` | `CONSUMER_PROGRESS_DIR` | Yes (if cauterizing) | Directory containing `consumer-progress.bin` |
| `--cauterize-state-changes` | `CAUTERIZE_STATE_CHANGES` | No (default: false) | Enable cauterize operation on startup |

## Safety Features

### Built-in Validations

1. **Progress Check**: Ensures consumer progress > 0 (can't cauterize if nothing processed)
2. **Bounds Check**: Verifies entry index is within file bounds
3. **Position Check**: Confirms calculated byte position doesn't exceed file size
4. **5-Second Delay**: Gives you time to cancel (Ctrl+C) before truncation
5. **Warning Messages**: Clear warnings about destructive nature

### Error Handling

The operation will fail gracefully and return an error if:
- Consumer progress file doesn't exist
- Consumer progress file is corrupted or unreadable
- Entry index exceeds total entries in index file
- Calculated byte position is invalid
- File truncation fails

## Edge Cases

### Case 1: Consumer Never Ran
**Symptom**: `consumer-progress.bin` doesn't exist or entry index is 0
**Result**: Cauterize fails with error message
**Solution**: Not applicable - consumer needs to process at least one entry first

### Case 2: Consumer Ahead of Core
**Symptom**: Consumer progress indicates entries that don't exist yet
**Result**: Bounds check fails
**Solution**: This shouldn't happen; indicates serious state mismatch

### Case 3: Multiple Progress Files
**Symptom**: Multiple `*progress*` files in consumer progress directory
**Result**: Uses `consumer-progress.bin` specifically, logs warning
**Solution**: Clean up old progress files if needed

## Technical Details

### File Formats

#### consumer-progress.bin
- **Format**: Single `uint64` (8 bytes) in little-endian
- **Value**: Last successfully processed entry index
- **Location**: Consumer progress directory

#### state-changes-index.bin
- **Format**: Array of `uint64` (8 bytes each) in little-endian
- **Value**: Each uint64 is a byte offset into `state-changes.bin`
- **Index Calculation**: `entry_index * 8 = byte_offset_in_index_file`

#### state-changes.bin
- **Format**: Sequential state change entries
- **Position Lookup**: Read `state-changes-index.bin[entry_index]` to get byte position

### Calculation Flow

```
Consumer Progress: entry_index = 123456

1. Index File Offset:
   offset = entry_index * 8 = 123456 * 8 = 987648 bytes

2. Read Byte Position from Index:
   Seek to 987648 in state-changes-index.bin
   Read uint64 → byte_position = 781363084099

3. Truncate Files:
   state-changes.bin → Truncate to 781363084099 bytes
   state-changes-index.bin → Truncate to 987648 bytes
   mempool.bin → Truncate to 0 (clear)
   mempool-index.bin → Truncate to 0 (clear)
```

## Multi-Step Recovery Process

### Complete Recovery Flow

1. **Stop Everything**
   ```bash
   # Stop core node
   kill <core-pid>
   
   # Stop consumer
   kill <consumer-pid>
   ```

2. **Identify Corruption**
   ```bash
   # Run consumer diagnostics
   cd /path/to/state-consumer
   export ENABLE_MIGRATION_HEIGHT_DIAGNOSTIC=true
   export MAX_RECOVERY_LOOKBACK_BYTES=100000
   ./postgres-data-handler
   
   # Note: Consumer progress is automatically saved
   # Check last processed index
   hexdump -C /path/to/consumer-progress/consumer-progress.bin
   ```

3. **(Optional) Revert Core Snapshot**
   ```bash
   # Only if core is ahead of corruption
   cd /path/to/core/data
   # Backup current state
   cp -r badger badger.backup
   
   # Restore from earlier snapshot
   # (Implementation depends on your backup strategy)
   ```

4. **Run Cauterize**
   ```bash
   cd /path/to/core
   ./backend \
     --state-change-dir=/state-changes \
     --consumer-progress-dir=/consumer-progress \
     --cauterize-state-changes=true
   
   # Wait for operation to complete (5 seconds + truncation time)
   # Then stop the node (Ctrl+C)
   ```

5. **Restart Normal Operations**
   ```bash
   # Start core normally (without cauterize flag)
   ./backend --state-change-dir=/state-changes
   
   # In another terminal, start consumer
   cd /path/to/postgres-data-handler
   ./postgres-data-handler
   ```

6. **Monitor Progress**
   ```bash
   # Watch core logs
   tail -f /path/to/core/logs/node.log
   
   # Watch consumer logs
   tail -f /path/to/consumer/logs/consumer.log
   
   # Check consumer progress file periodically
   watch -n 5 'hexdump -C /consumer-progress/consumer-progress.bin'
   ```

## When to Use Cauterize

### Good Use Cases

✅ Corruption detected in state-changes files
✅ Consumer has processed significant data (don't want to resync everything)
✅ Corruption is localized and downstream of consumer progress
✅ You have backups (always recommended)
✅ Node can replay blocks from the corruption point

### Bad Use Cases

❌ Consumer never ran (no progress to cauterize to)
❌ Corruption is in committed state (BadgerDB) rather than state-changes files
❌ Unknown corruption location
❌ No backups exist
❌ Node cannot replay blocks (e.g., archival data missing)

## Advantages vs. Full Resync

| Aspect | Cauterize | Full Resync |
|--------|-----------|-------------|
| **Time** | Minutes to hours | Days to weeks |
| **Data Loss** | Only corrupted portion | All consumer data |
| **Consumer Downtime** | Minimal | Extended |
| **Core Replay** | From corruption point | From genesis |
| **Risk** | Medium (if backups exist) | Low (clean slate) |
| **Complexity** | Multi-step manual process | Single command |

## Troubleshooting

### Error: "Could not open consumer progress file"
**Cause**: Consumer progress file doesn't exist or wrong path
**Solution**: Verify `--consumer-progress-dir` points to correct directory containing `consumer-progress.bin`

### Error: "Consumer progress is 0, nothing to cauterize"
**Cause**: Consumer hasn't processed any entries yet
**Solution**: Run consumer first, or this operation isn't needed

### Error: "Entry index exceeds total entries"
**Cause**: Consumer progress indicates entries that don't exist in state-changes yet
**Solution**: This indicates a serious state mismatch; investigate consumer and core sync status

### Cauterize completes but consumer still errors
**Cause**: Corruption may be in multiple locations or core isn't replaying correctly
**Solution**: Run cauterize again with updated consumer progress, or consider full resync

### Node doesn't regenerate removed entries
**Cause**: Node may be missing blocks to replay, or not in correct sync state
**Solution**: Check node sync status, verify blockchain data integrity

## Implementation Details

### Files Modified

1. **cmd/config.go**: Added `ConsumerProgressDir` and `CauterizeStateChanges` config fields
2. **cmd/run.go**: Added `--consumer-progress-dir` and `--cauterize-state-changes` flags
3. **cmd/node.go**: Pass new parameters to `NewServer`
4. **lib/server.go**: 
   - Added parameters to `NewServer` function signature
   - Added cauterize logic after state change syncer initialization
5. **lib/state_change_syncer.go**: Implemented `CauterizeToConsumerProgress` method

### Code Size

- **New code**: ~150 lines in `CauterizeToConsumerProgress` method
- **Config changes**: ~10 lines
- **Integration code**: ~15 lines
- **Total**: ~175 lines of new code

## Future Enhancements

### Potential Improvements

1. **Dry Run Mode**: Add `--cauterize-dry-run` flag to simulate without truncating
2. **Automatic Backup**: Create backup of files before truncation
3. **Multiple Consumer Support**: Handle multiple consumers with different progress
4. **Progress Verification**: Verify consumer progress matches expected format
5. **Automated Recovery**: Integrate with diagnostics to auto-cauterize on detection

## Related Documentation

- [State Consumer README](https://github.com/deso-protocol/state-consumer/blob/main/README.md)
- [Postgres Data Handler README](https://github.com/deso-protocol/postgres-data-handler/blob/main/README.md)
- [Diagnostic Recovery Mode](https://github.com/deso-protocol/state-consumer/blob/main/DIAGNOSTIC_RECOVERY_MODE.md)

---

**Status**: ✅ **IMPLEMENTED AND READY TO USE**

The cauterize operation is now available in the core node and ready for production use. Always ensure you have backups before running destructive operations.

