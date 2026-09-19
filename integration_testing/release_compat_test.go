package integration_testing

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
)

type releaseObservation struct {
	Height uint64
	Hash   string
}

// Runs only with throwaway regtest accounts on loopback, never production keys.
func TestReleaseLegacyNode(t *testing.T) {
	if os.Getenv("RELEASE_LEGACY_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	node := spawnFreezePosNode(t, 28102, "legacy-release-check", os.Getenv("RELEASE_TEST_SEED"), false)
	node.Config.ConnectIPs = []string{"127.0.0.1:28100"}
	node.Config.LogToStdErrOnly = true
	startNode(t, node)
	path := os.Getenv("RELEASE_OBSERVATION")
	for {
		if _, err := os.Stat(path + ".stop"); err == nil {
			return
		}
		tip, committed := node.Server.GetBlockchain().GetCommittedTip()
		if committed {
			b, err := json.Marshal(releaseObservation{uint64(tip.Height), tip.Hash.String()})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path+".tmp", b, 0600))
			require.NoError(t, os.Rename(path+".tmp", path))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestReleaseMixedVersionOrdinaryConsensus(t *testing.T) {
	binary := os.Getenv("RELEASE_LEGACY_BINARY")
	if binary == "" {
		t.Skip("requires legacy binary")
	}
	dir := t.TempDir()
	legacySeed := freezeRandomSeed(t)
	observationPath := filepath.Join(dir, "legacy.json")
	legacyLogPath := filepath.Join(dir, "legacy.log")
	if x := os.Getenv("RELEASE_LEGACY_LOG"); x != "" {
		legacyLogPath = x
	}
	legacyLog, err := os.Create(legacyLogPath)
	require.NoError(t, err)
	defer legacyLog.Close()
	node1 := spawnFreezePosNode(t, 28100, "patched-bootstrap", regtestParamUpdaterSeed, true)
	node1.Config.LogToStdErrOnly = true
	startNode(t, node1)
	node2Seed := freezeRandomSeed(t)
	node2 := spawnFreezePosNode(t, 28101, "patched-validator", node2Seed, false)
	node2.Config.LogToStdErrOnly = true
	node2.Config.ConnectIPs = []string{"127.0.0.1:28100"}
	startNode(t, node2)
	child := exec.Command(binary, "-test.run=^TestReleaseLegacyNode$", "-test.timeout=10m")
	child.Env = append(os.Environ(), "RELEASE_LEGACY_CHILD=1", "RELEASE_TEST_SEED="+legacySeed, "RELEASE_OBSERVATION="+observationPath)
	child.Stdout = legacyLog
	child.Stderr = legacyLog
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Signal(syscall.SIGCONT)
		_ = os.WriteFile(observationPath+".stop", []byte("stop"), 0600)
		done := make(chan error, 1)
		go func() { done <- child.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = child.Process.Kill()
			<-done
		}
		if t.Failed() {
			b, _ := os.ReadFile(legacyLogPath)
			if len(b) > 12000 {
				b = b[len(b)-12000:]
			}
			t.Logf("legacy log tail: %s", b)
		}
	})
	observe := func() releaseObservation {
		var o releaseObservation
		b, e := os.ReadFile(observationPath)
		if e == nil {
			_ = json.Unmarshal(b, &o)
		}
		return o
	}
	waitForFreezeConditionWithin(t, "all versions cross PoS cutover", 180*time.Second, func() bool {
		return node1.Server.GetBlockchain().BlockTip().Height > 32 && node2.Server.GetBlockchain().BlockTip().Height > 32 && observe().Height > 32
	})
	funder, key := freezeKeyPairFromSeed(t, regtestParamUpdaterSeed, node1.Params)
	// Keep normal honest validators from being jailed during accelerated startup.
	extra := map[string][]byte{
		lib.BlockProductionIntervalPoSKey:             lib.UintToBuf(1000),
		lib.TimeoutIntervalPoSKey:                     lib.UintToBuf(3000),
		lib.JailInactiveValidatorGracePeriodEpochsKey: lib.UintToBuf(1000),
	}
	paramTxn, _, _, _, err := node1.Server.GetBlockchain().CreateUpdateGlobalParamsTxn(key, -1, -1, -1, -1, 100, nil, -1, extra, freezeFeeRateNanosPerKB, node1.Server.GetMempool(), []*lib.DeSoOutput{})
	require.NoError(t, err)
	require.NoError(t, freezePosSignAndSubmit(t, node1, paramTxn, funder))
	for _, seed := range []string{node2Seed, legacySeed} {
		_, recipient := freezeKeyPairFromSeed(t, seed, node1.Params)
		require.NoError(t, freezePosSignAndSubmit(t, node1, freezeBasicTransferTxn(t, node1, key, recipient, 1e10), funder))
	}
	freezePosRegisterValidator(t, node1, node2Seed, "127.0.0.1:28101", freezePosNode2StakeNanos)
	freezePosRegisterValidator(t, node1, legacySeed, "127.0.0.1:28102", freezePosNode3StakeNanos)
	waitForFreezeConditionWithin(t, "three snapshot validators", 120*time.Second, func() bool { return len(freezePosSnapshotValidators(t, node1)) == 3 })
	for _, v := range freezePosSnapshotValidators(t, node1) {
		t.Logf("snapshot votingKey=%s stake=%s jailed=%d", v.VotingPublicKey.ToString(), v.TotalStakeAmountNanos.ToBig(), v.JailedAtEpochNumber)
	}
	start := uint64(node1.Server.GetBlockchain().BlockTip().Height) + 1
	keys := []*bls.PublicKey{freezePosVotingPublicKey(t, node2Seed), freezePosVotingPublicKey(t, legacySeed)}
	waitForFreezeConditionWithin(t, "old and patched proposers commit", 120*time.Second, func() bool {
		tip, ok := node1.Server.GetBlockchain().GetCommittedTip()
		if !ok || uint64(tip.Height) < start+20 {
			return false
		}
		counts := freezePosCountProposals(t, node1, keys, start, uint64(tip.Height))
		return counts[0] > 0 && counts[1] > 0
	})
	// Briefly pause the minority validator so honest leaders must recover via timeouts.
	require.NoError(t, child.Process.Signal(syscall.SIGSTOP))
	t.Cleanup(func() { _ = child.Process.Signal(syscall.SIGCONT) })
	timeoutStart := uint64(node1.Server.GetBlockchain().BlockTip().Height) + 1
	waitForFreezeConditionWithin(t, "honest timeout block commits", 120*time.Second, func() bool {
		tip, ok := node1.Server.GetBlockchain().GetCommittedTip()
		if !ok || uint64(tip.Height) < timeoutStart+5 {
			return false
		}
		for h := timeoutStart; h <= uint64(tip.Height); h++ {
			n, exists, e := node1.Server.GetBlockchain().GetBlockFromBestChainByHeight(h, false)
			if e == nil && exists && n.Header.ValidatorsTimeoutAggregateQC != nil {
				return true
			}
		}
		return false
	})
	require.NoError(t, child.Process.Signal(syscall.SIGCONT))
	waitForFreezeConditionWithin(t, "legacy catches up and agrees on committed hash", 120*time.Second, func() bool {
		o := observe()
		tip, ok := node1.Server.GetBlockchain().GetCommittedTip()
		if !ok || o.Height <= timeoutStart+5 || o.Height+8 < uint64(tip.Height) {
			return false
		}
		n, exists, e := node1.Server.GetBlockchain().GetBlockFromBestChainByHeight(o.Height, false)
		return e == nil && exists && n.Hash.String() == o.Hash
	})
	t.Logf("PASS mixed version: both versions propose, patched majority commits timeout blocks, legacy resumes on same chain; legacy committed=%d", observe().Height)
}
