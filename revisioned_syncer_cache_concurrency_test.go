// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package casbin

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/persist/cache"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
	"github.com/casbin/casbin/v3/persist/revisioned"
)

func TestRevisionedDecisionCacheInvalidatedOnlyAfterSwap(t *testing.T) {
	seed := loadSeedModel(t)
	store := revisioned.NewMemoryRevisionStore(seed)
	source := &gatedSnapshotSource{inner: store}
	adapter := &countingAdapter{
		Adapter: fileadapter.NewAdapter("examples/rbac_policy.csv"),
	}
	cachedEnforcer, err := NewSyncedCachedEnforcer(seed.Copy(), adapter)
	if err != nil {
		t.Fatalf("create cached enforcer: %v", err)
	}
	innerCache, err := cache.NewSyncCache()
	if err != nil {
		t.Fatalf("create sync cache: %v", err)
	}
	decisionCache := &countingCache{inner: innerCache}
	cachedEnforcer.SetCache(decisionCache)

	syncer := NewRevisionedSyncer(cachedEnforcer.SyncedEnforcer, source, 64).
		WithCacheInvalidator(cachedEnforcer.InvalidateCache)
	if err = syncer.Bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Bootstrap itself swaps in a snapshot, so prime the cache and measure all
	// deltas from the steady state before any revisioned event arrives.
	allowed, err := cachedEnforcer.Enforce("alice", "data1", "read")
	if err != nil || !allowed {
		t.Fatalf("prime decision cache, allowed=%v err=%v", allowed, err)
	}
	steadyClears := atomic.LoadInt32(&decisionCache.clearCalls)

	event, err := store.Commit("op-cache", []persist.PolicyOperation{
		addPolicyOp("p", "p", []string{"eve", "data1", "read"}),
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err = syncer.HandleEvent(event); err != nil {
		t.Fatalf("handle event: %v", err)
	}
	if atomic.LoadInt32(&decisionCache.clearCalls) != steadyClears+1 {
		t.Fatal("successful swap must invalidate the decision cache exactly once")
	}
	allowed, err = cachedEnforcer.Enforce("eve", "data1", "read")
	if err != nil || !allowed {
		t.Fatalf("new rule should be enforceable, allowed=%v err=%v", allowed, err)
	}
	// Enforce may lazily clear via the built-in version sync; re-baseline here so
	// the failing-batch assertion isolates the syncer-driven invalidation hook.
	afterGoodBatch := atomic.LoadInt32(&decisionCache.clearCalls)

	// Craft an event that is structurally valid but impossible at this revision,
	// since the commit source itself refuses to persist invalid batches.
	badEvent := event.Clone()
	badEvent.OperationID = "op-bad-cache"
	badEvent.FromRevision = event.ToRevision
	badEvent.ToRevision = event.ToRevision + 1
	badEvent.Mutations = []persist.PolicyOperation{
		removePolicyOp("p", "p", []string{"ghost", "data9", "read"}),
	}
	if err = syncer.HandleEvent(badEvent); err == nil {
		t.Fatal("invalid batch must be rejected")
	}
	if atomic.LoadInt32(&decisionCache.clearCalls) != afterGoodBatch {
		t.Fatal("failed candidate validation must not switch the cache generation")
	}
}

func TestRevisionedConcurrentReceiveRace(t *testing.T) {
	h := newSyncHarness(t, 8)
	const eventCount = 12
	events := make([]*revisioned.MutationEvent, eventCount)
	for i := 0; i < eventCount; i++ {
		rule := []string{fmt.Sprintf("user%d", i), "data1", "read"}
		events[i] = h.commit(t, fmt.Sprintf("op-%d", i),
			addPolicyOp("p", "p", rule))
	}

	var waitGroup sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			for i := range events {
				index := (i + worker) % len(events)
				_ = h.syncer.HandleEvent(events[index])
				_ = h.syncer.HandleEvent(events[index].Clone())
			}
		}(worker)
	}
	for reader := 0; reader < 2; reader++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for i := 0; i < 100; i++ {
				_, _ = h.se.Enforce("alice", "data1", "read")
				_, _ = h.syncer.Status()
				_ = h.syncer.IsReady()
			}
		}()
	}
	waitGroup.Wait()

	if err := h.syncer.RetryReload(); err != nil {
		t.Fatalf("final convergence reload: %v", err)
	}
	revision, ready := h.syncer.Status()
	if !ready || revision.Value != eventCount {
		t.Fatalf("receiver did not converge: %+v ready=%v", revision, ready)
	}
	h.assertMatchesAuthoritative(t, eventCount)
	h.assertNoFeedbackLoop(t)
}

func TestRevisionedMemoryBusEndToEnd(t *testing.T) {
	seed := loadSeedModel(t)
	store := revisioned.NewMemoryRevisionStore(seed)
	adapter := &countingAdapter{
		Adapter: fileadapter.NewAdapter("examples/rbac_policy.csv"),
	}
	se, err := NewSyncedEnforcer(seed.Copy(), adapter)
	if err != nil {
		t.Fatalf("create enforcer: %v", err)
	}
	syncer := NewRevisionedSyncer(se, store, 64)
	watcher := store.NewWatcher(32)
	defer watcher.Close()
	if err = syncer.BindWatcher(watcher); err != nil {
		t.Fatalf("bind watcher: %v", err)
	}
	if err = syncer.Bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	const eventCount = 6
	for i := 0; i < eventCount; i++ {
		_, err = store.Commit(fmt.Sprintf("bus-%d", i), []persist.PolicyOperation{
			addPolicyOp("p", "p", []string{fmt.Sprintf("bus-user-%d", i), "data1", "read"}),
		})
		if err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}
	store.WaitIdle()

	revision, ready := syncer.Status()
	if !ready || revision.Value != eventCount {
		t.Fatalf("bus receiver did not reach head: %+v ready=%v", revision, ready)
	}
	expected := replayAuthoritative(t, seed, store.CommitLog(), eventCount)
	if got, want := modelRuleSet(se.model), modelRuleSet(expected); !equalStrings(got, want) {
		t.Fatalf("bus receiver diverged: got %v want %v", got, want)
	}
	if calls := adapter.totalWriteCalls(); calls != 0 {
		t.Fatalf("receive path wrote the adapter %d times", calls)
	}
}

func TestRevisionedWatcherKeepsClassicWatcherContract(t *testing.T) {
	seed := loadSeedModel(t)
	store := revisioned.NewMemoryRevisionStore(seed)
	watcher := store.NewWatcher(8)
	defer watcher.Close()

	var callbackCount int32
	if err := watcher.SetUpdateCallback(func(string) {
		atomic.AddInt32(&callbackCount, 1)
	}); err != nil {
		t.Fatalf("set classic callback: %v", err)
	}
	if err := watcher.Update(); err != nil {
		t.Fatalf("classic update: %v", err)
	}
	if atomic.LoadInt32(&callbackCount) != 1 {
		t.Fatal("classic Watcher callback must remain supported")
	}

	se, err := NewSyncedEnforcer(seed.Copy(), &countingAdapter{
		Adapter: fileadapter.NewAdapter("examples/rbac_policy.csv"),
	})
	if err != nil {
		t.Fatalf("create enforcer: %v", err)
	}
	if err = se.SetWatcher(watcher); err != nil {
		t.Fatalf("revisioned watcher must plug into SetWatcher: %v", err)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
