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

package revisioned

import (
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

const rbacModelText = `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

func newTestModel(t *testing.T) model.Model {
	t.Helper()
	m, err := model.NewModelFromString(rbacModelText)
	if err != nil {
		t.Fatalf("create model: %v", err)
	}
	return m
}

func addPMutation(rules ...[]string) persist.PolicyOperation {
	return persist.PolicyOperation{
		Type:       persist.OperationAdd,
		Section:    "p",
		PolicyType: "p",
		Rules:      rules,
	}
}

func TestMemoryStoreAssignsContiguousRevisions(t *testing.T) {
	store := NewMemoryRevisionStore(newTestModel(t))

	if rev := store.CurrentRevision(); rev.Epoch != 1 || rev.Value != 0 {
		t.Fatalf("unexpected initial revision: %+v", rev)
	}

	first, err := store.Commit("op-1", []persist.PolicyOperation{
		addPMutation([]string{"alice", "data1", "read"}),
	})
	if err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if first.Epoch != 1 || first.FromRevision != 0 || first.ToRevision != 1 {
		t.Fatalf("unexpected first event: %+v", first)
	}

	second, err := store.Commit("op-2", []persist.PolicyOperation{
		addPMutation([]string{"bob", "data2", "write"}),
	})
	if err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if second.FromRevision != 1 || second.ToRevision != 2 {
		t.Fatalf("unexpected second event: %+v", second)
	}

	snapshot, err := store.LoadRevisionedSnapshot()
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if snapshot.Epoch != 1 || snapshot.Revision != 2 {
		t.Fatalf("unexpected snapshot revision: %+v", snapshot)
	}
	has, err := snapshot.Policy.HasPolicy("p", "p", []string{"alice", "data1", "read"})
	if err != nil || !has {
		t.Fatalf("snapshot missing first rule, has=%v err=%v", has, err)
	}
}

func TestMemoryStoreIdempotentCommitAndConflict(t *testing.T) {
	store := NewMemoryRevisionStore(newTestModel(t))
	mutations := []persist.PolicyOperation{addPMutation([]string{"alice", "data1", "read"})}

	first, err := store.Commit("op-dup", mutations)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	repeated, err := store.Commit("op-dup", mutations)
	if err != nil {
		t.Fatalf("idempotent recommit should succeed: %v", err)
	}
	if repeated.FromRevision != first.FromRevision ||
		repeated.ToRevision != first.ToRevision ||
		repeated.OperationID != first.OperationID {
		t.Fatalf("recommit returned different event: %+v vs %+v", repeated, first)
	}
	if len(store.CommitLog()) != 1 {
		t.Fatalf("idempotent commit must not extend the log")
	}

	conflicting := []persist.PolicyOperation{addPMutation([]string{"bob", "data2", "write"})}
	if _, err = store.Commit("op-dup", conflicting); err != ErrOperationIDConflict {
		t.Fatalf("expected ErrOperationIDConflict, got %v", err)
	}
}

func TestMemoryStoreSnapshotIsolation(t *testing.T) {
	store := NewMemoryRevisionStore(newTestModel(t))
	_, err := store.Commit("op-1", []persist.PolicyOperation{
		addPMutation([]string{"alice", "data1", "read"}),
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	snapshot, err := store.LoadRevisionedSnapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err = snapshot.Policy.AddPolicy("p", "p", []string{"mallory", "data9", "deny"}); err != nil {
		t.Fatalf("mutate snapshot copy: %v", err)
	}

	fresh, err := store.LoadRevisionedSnapshot()
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	has, err := fresh.Policy.HasPolicy("p", "p", []string{"mallory", "data9", "deny"})
	if err != nil {
		t.Fatalf("probe snapshot: %v", err)
	}
	if has {
		t.Fatal("snapshot mutation leaked into the authoritative store")
	}
}

func TestMemoryStoreResetEpoch(t *testing.T) {
	store := NewMemoryRevisionStore(newTestModel(t))
	_, err := store.Commit("op-1", []persist.PolicyOperation{
		addPMutation([]string{"alice", "data1", "read"}),
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	store.ResetEpoch(nil)
	if rev := store.CurrentRevision(); rev.Epoch != 2 || rev.Value != 0 {
		t.Fatalf("unexpected revision after reset: %+v", rev)
	}

	event, err := store.Commit("op-new-epoch", []persist.PolicyOperation{
		addPMutation([]string{"carol", "data3", "read"}),
	})
	if err != nil {
		t.Fatalf("post-reset commit: %v", err)
	}
	if event.Epoch != 2 || event.FromRevision != 0 || event.ToRevision != 1 {
		t.Fatalf("unexpected post-reset event: %+v", event)
	}
	if len(store.CommitLog()) != 1 {
		t.Fatal("epoch reset must truncate the commit log")
	}
}

func TestMemoryWatcherFanOutAndLocalPublish(t *testing.T) {
	store := NewMemoryRevisionStore(newTestModel(t))
	watcher := store.NewWatcher(8)
	defer watcher.Close()

	received := make(chan *MutationEvent, 4)
	if err := watcher.SetRevisionedCallback(func(event *MutationEvent) error {
		received <- event
		return nil
	}); err != nil {
		t.Fatalf("set callback: %v", err)
	}

	committed, err := store.Commit("op-1", []persist.PolicyOperation{
		addPMutation([]string{"alice", "data1", "read"}),
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	store.WaitIdle()

	select {
	case event := <-received:
		if event.OperationID != committed.OperationID || event.ToRevision != 1 {
			t.Fatalf("fan-out delivered wrong event: %+v", event)
		}
	default:
		t.Fatal("fan-out event was not delivered")
	}

	local := committed.Clone()
	local.OperationID = "local-only"
	if err = watcher.PublishRevisionedEvent(local); err != nil {
		t.Fatalf("local publish: %v", err)
	}
	store.WaitIdle()
	select {
	case event := <-received:
		if event.OperationID != "local-only" {
			t.Fatalf("unexpected local event: %+v", event)
		}
	default:
		t.Fatal("locally published event was not delivered")
	}
	if len(store.CommitLog()) != 1 {
		t.Fatal("local publish must not re-enter the commit store")
	}

	watcher.Close()
	if err = watcher.PublishRevisionedEvent(committed); err != ErrWatcherClosed {
		t.Fatalf("expected ErrWatcherClosed, got %v", err)
	}
}

func TestMutationEventValidate(t *testing.T) {
	valid := &MutationEvent{
		Epoch:        1,
		FromRevision: 0,
		ToRevision:   1,
		OperationID:  "op",
		Mutations:    []persist.PolicyOperation{addPMutation([]string{"a", "b", "c"})},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}

	cases := []*MutationEvent{
		nil,
		{FromRevision: 0, ToRevision: 1, Mutations: valid.Mutations},
		{OperationID: "op", FromRevision: 1, ToRevision: 1, Mutations: valid.Mutations},
		{OperationID: "op", FromRevision: 0, ToRevision: 1},
	}
	for i, event := range cases {
		if err := event.Validate(); err == nil {
			t.Fatalf("case %d should be invalid", i)
		}
	}
}
