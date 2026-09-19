# Recover a DeSo node slowed by obsolete Badger key versions

This runbook describes optional offline maintenance for a DeSo node whose
database lookups spend excessive time skipping obsolete Badger key versions.
All deployment details must be supplied by the operator. It is not a node
startup hook.

## What the maintenance does

Badger stores internal versions of keys when a value changes. Some versions can
remain in its on-disk tables until compaction merges the relevant tables. The
node already uses `NumVersionsToKeep=1`; that setting alone does not establish
that obsolete versions have been removed from existing tables. Confirm the
bottleneck with profiling and before/after measurements.

The maintenance tool uses **Badger v3.2103.5** and its stock `Flatten(1)`
operation on an isolated snapshot copy. It merges LSM tables and prunes obsolete
versions encountered during compaction. It does not delete blockchain history
or application key prefixes, and it does not guarantee that every bottom-level
table is rewritten. The tool does not run value-log garbage collection.

The procedure stops one node long enough to snapshot its detached disk, resumes
the original, and compacts a separate copy. Before switching to the copy, it
compares deterministic current-value samples and indexed height, audits the
committed tip and recent quorum certificates, and checks lookup performance.
Sampling is **not a full database digest**. Keep the original disk and snapshot
for rollback until live chain health and validator participation are verified.

The compactor uses 1 GiB memtables, 128 MiB value-log files,
`NumVersionsToKeep=1`, `NumCompactors=0`, a 100 MiB block cache and a 200 MiB
index cache. The GKE helper has a 12 GiB memory limit, an 8 GiB Go memory target,
`GOMAXPROCS=2`, and a 2-CPU limit. Check headroom for the actual database size.

## Scope and prerequisites

The supplied GKE driver supports **one single-replica, `OnDelete` StatefulSet**,
container `be`, with a whole-volume `/pd` mount on a **zonal ext4 GCP persistent
disk**, plus the normal local backend HTTP API on port 81. Full/API nodes can
use the same procedure if their layout matches. Regional disks, multiple
replicas sharing data, subPath mounts,
non-GKE hosts, different Badger versions, and nonstandard APIs need an experienced
operator to adapt the infrastructure steps first. The standalone Go compactor
can operate on another host's isolated offline copy with the same Badger version.

Before starting:

- Obtain authorization for the exact node. Do one validator at a time and check
  that enough healthy voting stake remains online during its downtime.
- Confirm this really is obsolete-version/iterator slowness. Compaction will
  not fix a bad RPC endpoint, network partition, corrupt database or consensus bug.
- Select an independent healthy reference node **on the same network**. It must
  serve the committed-tip and block-by-height APIs and use the configured
  container name. Never use the target as its own reference.
- Verify the deployed binary uses Badger **v3.2103.5** and matches the expected
  database format. A newer maintenance library is not an automatic upgrade path.
- Have `gcloud`, `kubectl`, Python 3 and Go installed locally. Authenticate an
  account authorized for the selected project and Kubernetes context.
- Allow an additional source-sized disk, snapshot quota, and temporary rewrite
  space. Ensure the helper's host has memory/CPU headroom. The helper requests
  8 GiB RAM and limits itself to 12 GiB/2 CPUs; a Pending helper is preferable
  to forcing it onto an overloaded node. Size resources for the database workload.
- Budget roughly an hour or more for snapshot, copy, compaction and validation;
  elapsed time depends on database size and storage throughput.

Do not print or check in the StatefulSet's full environment: it can contain a
validator seed. These tools save selected non-secret fields and spec hashes.
The maintenance pod gets a new command and **no validator environment or
credentials**, so the copy cannot start another signer. Never start the normal
node command on a clone while the original signer is running.

## 1. Build and test the tools

From the root of the core checkout:

```bash
BADGER_RUN="$HOME/.local/state/deso-badger-maintenance/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BADGER_RUN"
chmod 700 "$BADGER_RUN"
go test ./scripts/badger-maintenance -count=1
python3 -m unittest discover -s scripts -p test_gke_badger_maintenance.py
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BADGER_RUN/badger-maint" ./scripts/badger-maintenance
go build -o "$BADGER_RUN/chain-audit" ./scripts/badger-chain-audit
go version -m "$BADGER_RUN/badger-maint"
```

The audit build above assumes a Linux amd64 workstation. On another workstation,
use a compatible Linux amd64 builder for both binaries. Check their architecture
before copying them into the helper.
`go version -m` must show Badger v3.2103.5. No binaries need to go into Git.

## 2. Find the target's actual database path and fill the configuration

Replace the placeholders below with the authorized account, context and target.
Use the live cluster to discover resource details rather than relying on an
outdated infrastructure configuration. Read only the needed fields:

```bash
export CLOUDSDK_CORE_ACCOUNT=REPLACE_ACCOUNT
BADGER_CONTEXT=REPLACE_CONTEXT
BADGER_TARGET=REPLACE_TARGET
kubectl --context "$BADGER_CONTEXT" -n default get sts "$BADGER_TARGET" \
  -o 'jsonpath={.spec.replicas}{"\n"}{.spec.updateStrategy.type}{"\n"}'
kubectl --context "$BADGER_CONTEXT" -n default exec "$BADGER_TARGET-0" -c be -- \
  find /pd -maxdepth 5 -name MANIFEST -type f
kubectl --context "$BADGER_CONTEXT" top nodes
```

There may be several databases. Select the **chain database ending in
`v-00000/badgerdb`**, not mempool, txindex or global-state storage. Use the
parent of `MANIFEST` as `dbPath`. Do not assume two nodes use the same data
directory. Inspect the pod's current PVC and its free space (`df -h /pd`).

Create `$BADGER_RUN/config.json` with a text editor. Replace every example value
that differs for your target. `operation` must be a **new** lowercase resource
name, at most 39 characters; never reuse an old snapshot or disk name.

```json
{
  "account": "REPLACE_ACCOUNT",
  "context": "REPLACE_CONTEXT",
  "project": "REPLACE_PROJECT",
  "zone": "REPLACE_ZONE",
  "namespace": "default",
  "statefulset": "REPLACE_TARGET",
  "container": "be",
  "referencePod": "REPLACE_REFERENCE_POD",
  "operation": "badger-REPLACE_WITH_UNIQUE_LOWERCASE_NAME",
  "mountPath": "/pd",
  "dbPath": "/pd/REPLACE_WITH_ACTUAL_DIRECTORY/v-00000/badgerdb",
  "validatorKey": "REPLACE_WITH_PUBLIC_BC1_VALIDATOR_KEY",
  "testnet": false
}
```

`validatorKey` is the public validator account key, never a seed/private key.
Omit it for a non-validator. Use a testnet reference and `testnet: true` for
testnet. If the backend requires a virtual host, set `hostHeader` to the hostname
configured for that deployment; the reference must also accept that header.
Always choose a reference distinct from the target. Do not leave any `REPLACE`
placeholders.

```bash
BADGER_STATE="$BADGER_RUN/state.json"
python3 scripts/gke_badger_maintenance.py plan \
  --config "$BADGER_RUN/config.json" --state "$BADGER_STATE"
python3 scripts/gke_badger_maintenance.py status --state "$BADGER_STATE"
```

**Plan is read-only in GCP/Kubernetes.** Check account/project/context, target,
source disk/claim, image, DB path, baseline canonical hash, new snapshot/copy
names, and resource headroom. A failed plan requires a fresh state path after
fixing its cause; never manually set its stage to bypass a guard.

## 3. Snapshot a stopped node, create a copy, resume the original

```bash
python3 scripts/gke_badger_maintenance.py clone \
  --state "$BADGER_STATE" --confirm-target "$BADGER_TARGET"
```

The driver stops only the target, waits for its disk to detach, creates a
snapshot, waits for READY and verifies its source disk ID. It resumes the
original validator, then restores a separate disk of the same size/type. It
also attempts to resume the original if snapshot creation fails.

Check the original is running again and follows canonical history. If it
doesn't recover, resolve that before continuing. Save the state and receipts.

## 4. Compact and verify only the isolated copy

```bash
python3 scripts/gke_badger_maintenance.py compact \
  --state "$BADGER_STATE" --confirm-target "$BADGER_TARGET" \
  --binary "$BADGER_RUN/badger-maint" --audit-binary "$BADGER_RUN/chain-audit"
```

This creates a Retain PV/PVC and an isolated helper on the original node, copies
the tools and checks binary hashes, and runs the compactor with one worker.
The source validator stays online. Never open the source database with another
Badger process, even for diagnostics. Badger's file lock remains enabled.

The command writes `state.maintenance.jsonl` and `state.audit.jsonl` beside the
state file. Require a `validated` record, matching sample digests/counts,
unchanged highest indexed height, no increase in maxVersion, canonical offline
committed tip, and verified recent QCs. A decrease in maxVersion can be legitimate
when the highest transaction contains only tombstones/expired values; the local
regression test covers that case.

Also compare the `before`/`after` `bestHashVersions` and `heightLookupMillis`
fields. Confirm the expensive lookups actually improved. Matching values prove
the sampled data stayed the same; they do not by themselves prove this fixed
the performance problem. If the old versions or slow lookups remain, keep the
original running and investigate instead of activating an ineffective copy.

The audit uses current-epoch certificates; if fewer than three are available
in a snapshot taken at an epoch boundary, it stops instead of weakening the
gate. Ask an experienced operator to verify more history or take a fresh snapshot.

If your terminal disconnects **after the saved stage is `compacting`**, rerun
the same compact command: it resumes monitoring the existing process. Do not
start a second compactor. If the helper OOMs or compaction fails, the original
is still the active node. Inspect the receipt and helper status. Do not change
the receipt to claim success. Partial resource creation or activation errors
require inspecting the actual state before retrying.

## 5. Activate and validate the compacted copy

```bash
python3 scripts/gke_badger_maintenance.py activate \
  --state "$BADGER_STATE" --confirm-target "$BADGER_TARGET"
python3 scripts/gke_badger_maintenance.py validate \
  --state "$BADGER_STATE" --confirm-target "$BADGER_TARGET"
```

Activation removes the helper, waits for clone-disk detach, stops the original,
and changes only the data mount/volume. It preserves the original claim template
and data for rollback; the image, resources and identity stay unchanged.

Validation allows up to 20 minutes for catch-up, then requires three continuous
minutes of Ready, FULLY_CURRENT, canonical hashes, advancing height, at most
five blocks of sampling lag, and no restarts. On health timeout it restores
the original mount. If the validation process is interrupted, **it cannot
promise automatic rollback**; rerun validation or use the rollback command.

**Validator participation is a separate mandatory final check.** The driver
records `activityBefore` and deliberately labels `health-passed` as still
requiring participation verification. From the independent reference, query:

```bash
kubectl --context "$BADGER_CONTEXT" -n default exec REFERENCE_POD -c be -- \
  wget -qO- http://127.0.0.1:81/api/v0/validators/PUBLIC_VALIDATOR_KEY
kubectl --context "$BADGER_CONTEXT" -n default exec REFERENCE_POD -c be -- \
  wget -qO- http://127.0.0.1:81/api/v0/current-epoch-progress
```

Require Active, `JailedAtEpochNumber=0`, and a last-active epoch **greater than
the saved pre-switch value**, matching the new current epoch. If the old signer
was already active in the current epoch, wait for the next epoch; the unchanged
old value cannot prove the new process participated. Fresh local vote logs help
diagnosis but alone do not prove inclusion. A release involving consensus-rule
changes additionally needs its separate cryptographic voting-stake gate.
Do not proceed to another validator until this one passes, or roll it back.

Check other validators' pod UIDs/restart counters and chain health remained
unchanged. Keep the snapshot and source disk until an operator explicitly retires
rollback. Storage deletion is a separate operation, outside this procedure.

## Rollback

```bash
python3 scripts/gke_badger_maintenance.py rollback \
  --state "$BADGER_STATE" --confirm-target "$BADGER_TARGET"
```

It verifies the original disk ID still exists, stops only this target, removes
its helper if present, restores the original mounts/volumes and resumes it.
Then independently verify canonical catch-up and participation again. The
rollback tool refuses to overwrite unrelated StatefulSet edits. Neither the
maintenance nor rollback command deletes source disks, snapshots or copy data.

If the source disk or snapshot has already been retired, this rollback is not
available; recover from a separately verified backup instead. Never recreate
an empty disk under the old name and call that a rollback.

## Why this is not an every-startup optimization

The normal node already runs background compaction with one-version retention.
Full flattening can add tens of minutes of startup delay, consumes memory and
temporary disk capacity, and competes for I/O. An unconditional startup hook
could turn routine restarts into simultaneous validator outages. Use explicit
maintenance or a carefully designed one-time/threshold-triggered job. The
durable software follow-up is making the iterator skip obsolete versions
efficiently; this maintenance did not implement that iterator change.

## Files and validation status

- `scripts/badger-maintenance/`: tested offline compactor and preservation tests.
- `scripts/badger-chain-audit/`: read-only canonical-tip/recent-QC inspection.
- `scripts/gke_badger_maintenance.py`: generic, explicit-phase GKE driver.
- `scripts/test_gke_badger_maintenance.py`: verifies that switching a mount
  preserves every other field, rejects ambiguous/partial mounts, and rejects
  unrelated mount/volume edits before rollback stops a node.

Local tests cover logical-value preservation, deletion/expiry handling, and
selected infrastructure safety checks. They do not prove end-to-end support for
every deployment layout. Review the read-only plan for each node before running
any mutation phase, and independently validate the result before proceeding to
another node. Keep generated configuration, logs and operation receipts outside
the repository; they can contain deployment-specific identifiers.
