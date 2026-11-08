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
	"sync/atomic"
	"testing"

	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/persist/revisioned"
)

func TestRevisionedInOrderApplyMatchesCommitLog(t *testing.T) {
	h := newSyncHarness(t, 64)

	events := []*revisioned.MutationEvent{
		h.commit(t, "op-add-eve", addPolicyOp("p", "p",
			[]string{"eve", "data1", "read"})),
		h.commit(t, "op-g-bob", addPolicyOp("g", "g",
			[]string{"bob", "data2_admin"})),
		h.commit(t, "op-remove-bob", removePolicyOp("p", "p",
			[]string{"bob", "data2", "write"})),
		h.commit(t, "op-update-alice", updatePolicyOp("p", "p",
			[][]string{{"alice", "data1", "read"}},
			[][]string{{"alice", "data1", "write"}})),
	}
	for _, event := range events {
		if err := h.syncer.HandleEvent(event); err != nil {
			t.Fatalf("handle %s: %v", event.OperationID, err)
		}
		revision, ready := h.syncer.Status()
		if !ready || revision.Epoch != 1 || revision.Value != event.ToRevision {
			t.Fatalf("unexpected status after %s: %+v ready=%v",
				event.OperationID, revision, ready)
		}
		h.assertMatchesAuthoritative(t, event.ToRevision)
	}

	// The grouping mutation must have rebuilt the role graph.
	allowed, err := h.se.Enforce("bob", "data2", "read")
	if err != nil || !allowed {
		t.Fatalf("bob should inherit data2_admin, allowed=%v err=%v", allowed, err)
	}
	allowed, err = h.se.Enforce("alice", "data1", "write")
	if err != nil || !allowed {
		t.Fatalf("updated alice rule should allow write, allowed=%v err=%v", allowed, err)
	}
	allowed, err = h.se.Enforce("alice", "data1", "read")
	if err != nil || allowed {
		t.Fatalf("old alice rule should be gone, allowed=%v err=%v", allowed, err)
	}

	stats := h.syncer.Stats()
	if stats.AppliedEvents != len(events) {
		t.Fatalf("applied=%d want %d", stats.AppliedEvents, len(events))
	}
	h.assertNoFeedbackLoop(t)
}

func TestRevisionedDuplicateIsNotReapplied(t *testing.T) {
	h := newSyncHarness(t, 64)
	event := h.commit(t, "op-dup", addPolicyOp("p", "p",
		[]string{"eve", "data1", "read"}))

	if err := h.syncer.HandleEvent(event); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	before := h.syncer.Stats()
	if err := h.syncer.HandleEvent(event.Clone()); err != nil {
		t.Fatalf("duplicate delivery: %v", err)
	}
	after := h.syncer.Stats()
	if after.AppliedEvents != before.AppliedEvents ||
		after.DuplicateEvents != before.DuplicateEvents+1 {
		t.Fatalf("duplicate changed counters: before=%+v after=%+v", before, after)
	}
	h.assertMatchesAuthoritative(t, event.ToRevision)
	h.assertNoFeedbackLoop(t)
}

func TestRevisionedSameOperationIDConflict(t *testing.T) {
	h := newSyncHarness(t, 64)
	event := h.commit(t, "op-conflict", addPolicyOp("p", "p",
		[]string{"eve", "data1", "read"}))
	if err := h.syncer.HandleEvent(event); err != nil {
		t.Fatalf("first delivery: %v", err)
	}

	conflicting := event.Clone()
	conflicting.Mutations = []persist.PolicyOperation{
		addPolicyOp("p", "p", []string{"mallory", "data9", "read"}),
	}
	err := h.syncer.HandleEvent(conflicting)
	if err != revisioned.ErrOperationIDConflict {
		t.Fatalf("expected ErrOperationIDConflict, got %v", err)
	}
	revision, ready := h.syncer.Status()
	if !ready || revision.Value != event.ToRevision {
		t.Fatalf("conflict must not move the revision: %+v ready=%v", revision, ready)
	}
	if h.syncer.Stats().ConflictEvents != 1 {
		t.Fatal("conflict counter not incremented")
	}
	has, _ := h.se.model.HasPolicy("p", "p", []string{"mallory", "data9", "read"})
	if has {
		t.Fatal("conflicting batch must never touch the model")
	}
}

func TestRevisionedGapReloadsSnapshotAndStaleEventRejected(t *testing.T) {
	h := newSyncHarness(t, 64)
	baseline := h.syncer.Stats()
	first := h.commit(t, "op-1", addPolicyOp("p", "p",
		[]string{"eve", "data1", "read"}))
	second := h.commit(t, "op-2", addPolicyOp("p", "p",
		[]string{"frank", "data4", "read"}))
	third := h.commit(t, "op-3", addPolicyOp("g", "g",
		[]string{"frank", "data2_admin"}))

	// Deliver the third event first: from-revision 2 is a gap for a receiver at 0.
	if err := h.syncer.HandleEvent(third); err != nil {
		t.Fatalf("gap event: %v", err)
	}
	revision, ready := h.syncer.Status()
	if !ready || revision.Value != third.ToRevision {
		t.Fatalf("snapshot should recover to head revision, got %+v ready=%v",
			revision, ready)
	}
	h.assertMatchesAuthoritative(t, third.ToRevision)
	stats := h.syncer.Stats()
	if stats.GapEvents != baseline.GapEvents+1 ||
		stats.ReloadCount != baseline.ReloadCount+1 ||
		stats.SnapshotLoads != baseline.SnapshotLoads+1 {
		t.Fatalf("unexpected stats after gap: %+v baseline=%+v", stats, baseline)
	}

	// The skipped first event is now fully covered by the snapshot.
	if err := h.syncer.HandleEvent(first); err != revisioned.ErrStaleEvent {
		t.Fatalf("expected ErrStaleEvent, got %v", err)
	}
	if err := h.syncer.HandleEvent(second); err != revisioned.ErrStaleEvent {
		t.Fatalf("covered event should be reported stale, got %v", err)
	}
	h.assertMatchesAuthoritative(t, third.ToRevision)
	h.assertNoFeedbackLoop(t)
}

func TestRevisionedOutOfOrderCatchesUp(t *testing.T) {
	h := newSyncHarness(t, 64)
	first := h.commit(t, "op-1", addPolicyOp("p", "p",
		[]string{"eve", "data1", "read"}))
	second := h.commit(t, "op-2", addPolicyOp("p", "p",
		[]string{"frank", "data4", "read"}))
	third := h.commit(t, "op-3", removePolicyOp("p", "p",
		[]string{"bob", "data2", "write"}))

	// Delivering the second event first opens a gap; the snapshot jumps to rev 3.
	if err := h.syncer.HandleEvent(second); err != nil {
		t.Fatalf("out-of-order delivery: %v", err)
	}
	if err := h.syncer.HandleEvent(third); err != revisioned.ErrStaleEvent {
		t.Fatalf("covered event should be reported stale, got %v", err)
	}
	if err := h.syncer.HandleEvent(first); err != revisioned.ErrStaleEvent {
		t.Fatalf("covered event should be reported stale, got %v", err)
	}
	fourth := h.commit(t, "op-4", addPolicyOp("g", "g",
		[]string{"eve", "data2_admin"}))
	if err := h.syncer.HandleEvent(fourth); err != nil {
		t.Fatalf("in-order event after catch-up: %v", err)
	}
	revision, ready := h.syncer.Status()
	if !ready || revision.Value != fourth.ToRevision {
		t.Fatalf("unexpected final revision: %+v ready=%v", revision, ready)
	}
	h.assertMatchesAuthoritative(t, fourth.ToRevision)
}

func TestRevisionedEpochResetTriggersRebootstrap(t *testing.T) {
	h := newSyncHarness(t, 64)
	oldEpochEvent := h.commit(t, "op-old", addPolicyOp("p", "p",
		[]string{"eve", "data1", "read"}))
	if err := h.syncer.HandleEvent(oldEpochEvent); err != nil {
		t.Fatalf("epoch one event: %v", err)
	}

	h.store.ResetEpoch(nil)
	newEpochEvent := h.commit(t, "op-new", addPolicyOp("p", "p",
		[]string{"carol", "data3", "read"}))
	if err := h.syncer.HandleEvent(newEpochEvent); err != nil {
		t.Fatalf("new epoch event: %v", err)
	}
	revision, ready := h.syncer.Status()
	if !ready || revision.Epoch != 2 || revision.Value != 1 {
		t.Fatalf("rebootstrap failed: %+v ready=%v", revision, ready)
	}
	// The reset lineage starts from an empty policy, not the retired seed.
	resetBase := h.seed.Copy()
	resetBase.ClearPolicy()
	expected := replayAuthoritative(t, resetBase, h.store.CommitLog(), 1)
	if got, want := modelRuleSet(h.se.model), modelRuleSet(expected); !equalStrings(got, want) {
		t.Fatalf("new epoch model mismatch: got %v want %v", got, want)
	}

	// An event from the retired lineage must be discarded, not applied.
	stale := oldEpochEvent.Clone()
	if err := h.syncer.HandleEvent(stale); err != nil {
		t.Fatalf("stale epoch event: %v", err)
	}
	revision, _ = h.syncer.Status()
	if revision.Epoch != 2 {
		t.Fatalf("retired epoch event changed lineage: %+v", revision)
	}
	if got, want := modelRuleSet(h.se.model), modelRuleSet(expected); !equalStrings(got, want) {
		t.Fatalf("stale epoch event mutated the model: got %v want %v", got, want)
	}
}

func TestRevisionedReloadFailureKeepsOldModelAndExposesNotReady(t *testing.T) {
	h := newSyncHarness(t, 64)
	first := h.commit(t, "op-1", addPolicyOp("p", "p",
		[]string{"eve", "data1", "read"}))
	second := h.commit(t, "op-2", addPolicyOp("p", "p",
		[]string{"frank", "data4", "read"}))

	h.source.SetFail(true)
	err := h.syncer.HandleEvent(second)
	if err == nil {
		t.Fatal("expected reload failure")
	}
	revision, ready := h.syncer.Status()
	if ready {
		t.Fatal("receiver must expose not-ready after reload failure")
	}
	if revision.Value != 0 {
		t.Fatalf("old model revision must stay unchanged, got %d", revision.Value)
	}
	// The previous complete model stays enforceable.
	allowed, enforceErr := h.se.Enforce("alice", "data1", "read")
	if enforceErr != nil || !allowed {
		t.Fatalf("old complete model should still serve, allowed=%v err=%v",
			allowed, enforceErr)
	}

	h.source.SetFail(false)
	if err = h.syncer.RetryReload(); err != nil {
		t.Fatalf("retry reload: %v", err)
	}
	revision, ready = h.syncer.Status()
	if !ready || revision.Value != second.ToRevision {
		t.Fatalf("retry should reach head revision: %+v ready=%v", revision, ready)
	}
	h.assertMatchesAuthoritative(t, first.ToRevision+1)
}

func TestRevisionedBoundedBufferOverflowRefetchesSnapshot(t *testing.T) {
	h := newSyncHarness(t, 2)
	first := h.commit(t, "op-1", addPolicyOp("p", "p",
		[]string{"eve", "data1", "read"}))
	second := h.commit(t, "op-2", addPolicyOp("p", "p",
		[]string{"frank", "data4", "read"}))
	third := h.commit(t, "op-3", addPolicyOp("g", "g",
		[]string{"frank", "data2_admin"}))
	fourth := h.commit(t, "op-4", removePolicyOp("p", "p",
		[]string{"bob", "data2", "write"}))
	fifth := h.commit(t, "op-5", addPolicyOp("p", "p",
		[]string{"zack", "data9", "delete"}))

	h.source.ArmBlock()
	done := make(chan error, 1)
	go func() { done <- h.syncer.HandleEvent(third) }()
	<-h.source.started

	// These arrivals are bounded-cached while the snapshot fetch is blocked.
	_ = h.syncer.HandleEvent(first)
	_ = h.syncer.HandleEvent(fourth)
	_ = h.syncer.HandleEvent(second)
	_ = h.syncer.HandleEvent(fifth)

	h.source.Release()
	if err := <-done; err != nil {
		t.Fatalf("reload completion: %v", err)
	}
	revision, ready := h.syncer.Status()
	if !ready || revision.Value != fifth.ToRevision {
		t.Fatalf("overflow recovery lost updates: %+v ready=%v", revision, ready)
	}
	if h.syncer.PendingCount() != 0 {
		t.Fatal("pending buffer must drain after reload")
	}
	if atomic.LoadInt32(&h.source.loads) < 2 {
		t.Fatal("overflow must trigger an additional snapshot fetch")
	}
	has, err := h.se.model.HasPolicy("p", "p", []string{"zack", "data9", "delete"})
	if err != nil || !has {
		t.Fatalf("last update before reload completion was lost, has=%v err=%v", has, err)
	}
	h.assertMatchesAuthoritative(t, fifth.ToRevision)
}

func TestRevisionedOverlappingIntervalRejected(t *testing.T) {
	h := newSyncHarness(t, 64)
	event := h.commit(t, "op-1", addPolicyOp("p", "p",
		[]string{"eve", "data1", "read"}))
	if err := h.syncer.HandleEvent(event); err != nil {
		t.Fatalf("first event: %v", err)
	}

	overlap := event.Clone()
	overlap.OperationID = "op-overlap"
	overlap.FromRevision = event.FromRevision
	overlap.ToRevision = event.ToRevision + 1
	err := h.syncer.HandleEvent(overlap)
	if err != revisioned.ErrRevisionOverlap {
		t.Fatalf("expected ErrRevisionOverlap, got %v", err)
	}
	revision, ready := h.syncer.Status()
	if !ready || revision.Value != event.ToRevision {
		t.Fatalf("overlap must not move the revision: %+v ready=%v", revision, ready)
	}
}

func TestRevisionedRoleGraphAndFailedBatchAtomicity(t *testing.T) {
	h := newSyncHarness(t, 64)
	addLink := h.commit(t, "op-g-add", addPolicyOp("g", "g",
		[]string{"bob", "data2_admin"}))
	if err := h.syncer.HandleEvent(addLink); err != nil {
		t.Fatalf("add link: %v", err)
	}
	allowed, err := h.se.Enforce("bob", "data2", "read")
	if err != nil || !allowed {
		t.Fatalf("role link should be effective, allowed=%v err=%v", allowed, err)
	}

	removeLink := h.commit(t, "op-g-remove", removePolicyOp("g", "g",
		[]string{"bob", "data2_admin"}))
	if err = h.syncer.HandleEvent(removeLink); err != nil {
		t.Fatalf("remove link: %v", err)
	}
	allowed, err = h.se.Enforce("bob", "data2", "read")
	if err != nil || allowed {
		t.Fatalf("role link should be gone, allowed=%v err=%v", allowed, err)
	}

	revisionBefore, _ := h.syncer.Status()
	// The commit source rejects invalid batches, so the receiver-side failure is
	// reproduced with a structurally valid event carrying an impossible mutation.
	badBatch := removeLink.Clone()
	badBatch.OperationID = "op-bad"
	badBatch.FromRevision = revisionBefore.Value
	badBatch.ToRevision = revisionBefore.Value + 1
	badBatch.Mutations = []persist.PolicyOperation{
		removePolicyOp("g", "g", []string{"ghost", "nowhere"}),
	}
	if err = h.syncer.HandleEvent(badBatch); err == nil {
		t.Fatal("invalid batch must be rejected")
	}
	revisionAfter, ready := h.syncer.Status()
	if !ready || revisionAfter.Value != revisionBefore.Value {
		t.Fatalf("failed batch must not switch revisions: %+v -> %+v",
			revisionBefore, revisionAfter)
	}
	allowed, err = h.se.Enforce("alice", "data1", "read")
	if err != nil || !allowed {
		t.Fatalf("old model must remain enforceable, allowed=%v err=%v", allowed, err)
	}
}
