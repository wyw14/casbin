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
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/persist/cache"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
	"github.com/casbin/casbin/v3/persist/revisioned"
)

const syncTestModelText = `
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

func addPolicyOp(sec, ptype string, rules ...[]string) persist.PolicyOperation {
	return persist.PolicyOperation{Type: persist.OperationAdd, Section: sec,
		PolicyType: ptype, Rules: rules}
}

func removePolicyOp(sec, ptype string, rules ...[]string) persist.PolicyOperation {
	return persist.PolicyOperation{Type: persist.OperationRemove, Section: sec,
		PolicyType: ptype, Rules: rules}
}

func updatePolicyOp(sec, ptype string, oldRules, newRules [][]string) persist.PolicyOperation {
	return persist.PolicyOperation{Type: persist.OperationUpdate, Section: sec,
		PolicyType: ptype, OldRules: oldRules, Rules: newRules}
}

// countingAdapter counts every persistence write so receive-side
// synchronization can be proven not to write the adapter again.
type countingAdapter struct {
	*fileadapter.Adapter
	addPolicyCalls        int64
	addPoliciesCalls      int64
	removePolicyCalls     int64
	removePoliciesCalls   int64
	removeFilteredCalls   int64
	updatePolicyCalls     int64
	updatePoliciesCalls   int64
	updateFilteredCalls   int64
	savePolicyCalls       int64
}

func (a *countingAdapter) AddPolicy(sec, ptype string, rule []string) error {
	atomic.AddInt64(&a.addPolicyCalls, 1)
	return nil
}

func (a *countingAdapter) AddPolicies(sec, ptype string, rules [][]string) error {
	atomic.AddInt64(&a.addPoliciesCalls, 1)
	return nil
}

func (a *countingAdapter) RemovePolicy(sec, ptype string, rule []string) error {
	atomic.AddInt64(&a.removePolicyCalls, 1)
	return nil
}

func (a *countingAdapter) RemovePolicies(sec, ptype string, rules [][]string) error {
	atomic.AddInt64(&a.removePoliciesCalls, 1)
	return nil
}

func (a *countingAdapter) RemoveFilteredPolicy(sec, ptype string,
	fieldIndex int, fieldValues ...string) error {
	atomic.AddInt64(&a.removeFilteredCalls, 1)
	return nil
}

func (a *countingAdapter) UpdatePolicy(sec, ptype string,
	oldRule, newRule []string) error {
	atomic.AddInt64(&a.updatePolicyCalls, 1)
	return nil
}

func (a *countingAdapter) UpdatePolicies(sec, ptype string,
	oldRules, newRules [][]string) error {
	atomic.AddInt64(&a.updatePoliciesCalls, 1)
	return nil
}

func (a *countingAdapter) UpdateFilteredPolicies(sec, ptype string,
	newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	atomic.AddInt64(&a.updateFilteredCalls, 1)
	return nil, nil
}

func (a *countingAdapter) SavePolicy(m model.Model) error {
	atomic.AddInt64(&a.savePolicyCalls, 1)
	return nil
}

func (a *countingAdapter) totalWriteCalls() int64 {
	return atomic.LoadInt64(&a.addPolicyCalls) + atomic.LoadInt64(&a.addPoliciesCalls) +
		atomic.LoadInt64(&a.removePolicyCalls) + atomic.LoadInt64(&a.removePoliciesCalls) +
		atomic.LoadInt64(&a.removeFilteredCalls) + atomic.LoadInt64(&a.updatePolicyCalls) +
		atomic.LoadInt64(&a.updatePoliciesCalls) + atomic.LoadInt64(&a.updateFilteredCalls) +
		atomic.LoadInt64(&a.savePolicyCalls)
}

// countingWatcher proves receive-side synchronization never broadcasts.
type countingWatcher struct {
	updateCalls int64
	callback    func(string)
}

func (w *countingWatcher) SetUpdateCallback(callback func(string)) error {
	w.callback = callback
	return nil
}

func (w *countingWatcher) Update() error {
	atomic.AddInt64(&w.updateCalls, 1)
	if w.callback != nil {
		w.callback("")
	}
	return nil
}

func (w *countingWatcher) Close() {}

// countingCache counts decision cache invalidations.
type countingCache struct {
	inner      cache.Cache
	clearCalls int32
}

func (c *countingCache) Set(key string, value bool, extra ...interface{}) error {
	return c.inner.Set(key, value, extra...)
}

func (c *countingCache) Get(key string) (bool, error) {
	return c.inner.Get(key)
}

func (c *countingCache) Delete(key string) error {
	return c.inner.Delete(key)
}

func (c *countingCache) Clear() error {
	atomic.AddInt32(&c.clearCalls, 1)
	return c.inner.Clear()
}

// gatedSnapshotSource makes snapshot fetch timing and failures controllable.
type gatedSnapshotSource struct {
	inner     revisioned.SnapshotSource
	mu        sync.Mutex
	gate      chan struct{}
	started   chan struct{}
	blockOnce *sync.Once
	block     int32
	fail      int32
	loads     int32
}

func (g *gatedSnapshotSource) ArmBlock() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gate = make(chan struct{})
	g.started = make(chan struct{})
	g.blockOnce = &sync.Once{}
	atomic.StoreInt32(&g.block, 1)
}

func (g *gatedSnapshotSource) Release() {
	g.mu.Lock()
	gate := g.gate
	g.mu.Unlock()
	atomic.StoreInt32(&g.block, 0)
	close(gate)
}

func (g *gatedSnapshotSource) SetFail(fail bool) {
	var value int32
	if fail {
		value = 1
	}
	atomic.StoreInt32(&g.fail, value)
}

func (g *gatedSnapshotSource) LoadRevisionedSnapshot() (*revisioned.Snapshot, error) {
	atomic.AddInt32(&g.loads, 1)
	if atomic.LoadInt32(&g.fail) != 0 {
		return nil, errors.New("snapshot source unavailable")
	}
	if atomic.LoadInt32(&g.block) != 0 {
		g.blockOnce.Do(func() { close(g.started) })
		<-g.gate
	}
	return g.inner.LoadRevisionedSnapshot()
}

type syncHarness struct {
	seed    model.Model
	store   *revisioned.MemoryRevisionStore
	source  *gatedSnapshotSource
	se      *SyncedEnforcer
	syncer  *RevisionedSyncer
	adapter *countingAdapter
	watcher *countingWatcher
}

func loadSeedModel(t *testing.T) model.Model {
	t.Helper()
	m, err := model.NewModelFromString(syncTestModelText)
	if err != nil {
		t.Fatalf("create model: %v", err)
	}
	fileAdapter := fileadapter.NewAdapter("examples/rbac_policy.csv")
	if err = fileAdapter.LoadPolicy(m); err != nil {
		t.Fatalf("load seed policy: %v", err)
	}
	return m
}

func newSyncHarness(t *testing.T, pendingCapacity int) *syncHarness {
	t.Helper()
	seed := loadSeedModel(t)
	store := revisioned.NewMemoryRevisionStore(seed)
	source := &gatedSnapshotSource{inner: store}
	adapter := &countingAdapter{
		Adapter: fileadapter.NewAdapter("examples/rbac_policy.csv"),
	}
	se, err := NewSyncedEnforcer(seed.Copy(), adapter)
	if err != nil {
		t.Fatalf("create synced enforcer: %v", err)
	}
	watcher := &countingWatcher{}
	if err = se.SetWatcher(watcher); err != nil {
		t.Fatalf("set watcher: %v", err)
	}
	syncer := NewRevisionedSyncer(se, source, pendingCapacity)
	if err = syncer.Bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	return &syncHarness{
		seed: seed, store: store, source: source, se: se,
		syncer: syncer, adapter: adapter, watcher: watcher,
	}
}

func (h *syncHarness) commit(t *testing.T, operationID string,
	mutations ...persist.PolicyOperation) *revisioned.MutationEvent {
	t.Helper()
	event, err := h.store.Commit(operationID, mutations)
	if err != nil {
		t.Fatalf("commit %s: %v", operationID, err)
	}
	return event
}

func modelRuleSet(m model.Model) []string {
	lines := make([]string, 0)
	for sec, assertionMap := range m {
		if sec != "p" && sec != "g" {
			continue
		}
		for ptype, assertion := range assertionMap {
			for _, rule := range assertion.Policy {
				lines = append(lines, ptype+","+strings.Join(rule, ","))
			}
		}
	}
	sort.Strings(lines)
	return lines
}

func replayAuthoritative(t *testing.T, base model.Model,
	log []*revisioned.MutationEvent, toRevision uint64) model.Model {
	t.Helper()
	// The seed policy is revision zero and stays part of every replay.
	replayed := base.Copy()
	for _, event := range log {
		if event.ToRevision > toRevision {
			break
		}
		if err := revisioned.ApplyMutationsToModel(replayed, event.Mutations); err != nil {
			t.Fatalf("replay event %s: %v", event.OperationID, err)
		}
	}
	return replayed
}

func (h *syncHarness) assertMatchesAuthoritative(t *testing.T, toRevision uint64) {
	t.Helper()
	expected := replayAuthoritative(t, h.seed, h.store.CommitLog(), toRevision)
	got := modelRuleSet(h.se.model)
	want := modelRuleSet(expected)
	if len(got) != len(want) {
		t.Fatalf("model mismatch at revision %d: got %v want %v", toRevision, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("model mismatch at revision %d: got %v want %v", toRevision, got, want)
		}
	}
}

func (h *syncHarness) assertNoFeedbackLoop(t *testing.T) {
	t.Helper()
	if calls := h.adapter.totalWriteCalls(); calls != 0 {
		t.Fatalf("receiver wrote the adapter %d times", calls)
	}
	if calls := atomic.LoadInt64(&h.watcher.updateCalls); calls != 0 {
		t.Fatalf("receiver broadcast to the watcher %d times", calls)
	}
}
