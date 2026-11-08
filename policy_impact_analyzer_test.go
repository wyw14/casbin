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
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
	"github.com/casbin/casbin/v3/rbac"
	defaultrolemanager "github.com/casbin/casbin/v3/rbac/default-role-manager"
	"github.com/casbin/casbin/v3/util"
	"github.com/casbin/govaluate"
)

// recordingAdapter counts every write-side adapter call while delegating loads.
type recordingAdapter struct {
	inner  persist.Adapter
	mu     sync.Mutex
	writes int
}

func (a *recordingAdapter) LoadPolicy(m model.Model) error {
	return a.inner.LoadPolicy(m)
}

func (a *recordingAdapter) SavePolicy(m model.Model) error {
	a.mu.Lock()
	a.writes++
	a.mu.Unlock()
	return nil
}

func (a *recordingAdapter) AddPolicy(sec, ptype string, rule []string) error {
	a.mu.Lock()
	a.writes++
	a.mu.Unlock()
	return nil
}

func (a *recordingAdapter) RemovePolicy(sec, ptype string, rule []string) error {
	a.mu.Lock()
	a.writes++
	a.mu.Unlock()
	return nil
}

func (a *recordingAdapter) RemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	a.mu.Lock()
	a.writes++
	a.mu.Unlock()
	return nil
}

func (a *recordingAdapter) writeCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.writes
}

// recordingWatcher counts watcher notifications without invoking callbacks.
type recordingWatcher struct {
	mu      sync.Mutex
	updates int
}

func (w *recordingWatcher) SetUpdateCallback(func(string)) error { return nil }

func (w *recordingWatcher) Update() error {
	w.mu.Lock()
	w.updates++
	w.mu.Unlock()
	return nil
}

func (w *recordingWatcher) Close() {}

func (w *recordingWatcher) updateCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.updates
}

func newRecordingEnforcer(t *testing.T, modelPath, policyPath string) (*Enforcer, *recordingAdapter, *recordingWatcher) {
	t.Helper()
	adapter := &recordingAdapter{inner: fileadapter.NewAdapter(policyPath)}
	e, err := NewEnforcer(modelPath, adapter)
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}
	watcher := &recordingWatcher{}
	if err = e.SetWatcher(watcher); err != nil {
		t.Fatalf("SetWatcher failed: %v", err)
	}
	return e, adapter, watcher
}

// applyPatchToIndependentEnforcer replays the patch through the public
// management API on a fully independent enforcer, without persisting anything.
func applyPatchToIndependentEnforcer(t *testing.T, e *Enforcer, patch PolicyPatch) {
	t.Helper()
	e.EnableAutoSave(false)
	for _, op := range patch.Operations {
		var ok bool
		var err error
		switch op.Sec {
		case "p":
			ok, err = applyPolicySideOp(e, op)
		case "g":
			ok, err = applyGroupingSideOp(e, op)
		default:
			t.Fatalf("unexpected section %q", op.Sec)
		}
		if err != nil || !ok {
			t.Fatalf("replaying %v on independent enforcer failed: ok=%v err=%v", op, ok, err)
		}
	}
}

func applyPolicySideOp(e *Enforcer, op PatchOperation) (bool, error) {
	switch op.Op {
	case PatchOpAdd:
		return e.AddNamedPolicy(op.PType, op.Rule)
	case PatchOpRemove:
		return e.RemoveNamedPolicy(op.PType, op.Rule)
	case PatchOpUpdate:
		return e.UpdateNamedPolicy(op.PType, op.OldRule, op.Rule)
	default:
		return false, fmt.Errorf("unknown op %q", op.Op)
	}
}

func applyGroupingSideOp(e *Enforcer, op PatchOperation) (bool, error) {
	switch op.Op {
	case PatchOpAdd:
		return e.AddNamedGroupingPolicy(op.PType, op.Rule)
	case PatchOpRemove:
		return e.RemoveNamedGroupingPolicy(op.PType, op.Rule)
	case PatchOpUpdate:
		return e.UpdateNamedGroupingPolicy(op.PType, op.OldRule, op.Rule)
	default:
		return false, fmt.Errorf("unknown op %q", op.Op)
	}
}

func checkReportAgainstIndependent(t *testing.T, report *ImpactReport,
	baseline, candidate *Enforcer, requests []AnalysisRequest) {
	t.Helper()
	if !report.Complete {
		t.Fatalf("report should be complete: analyzed=%d total=%d", report.AnalyzedCount, report.TotalCount)
	}
	if report.ScopeStatement != ImpactAnalysisScopeStatement {
		t.Fatalf("missing scope statement")
	}
	if len(report.Outcomes) != len(requests) {
		t.Fatalf("outcomes length %d != requests length %d", len(report.Outcomes), len(requests))
	}
	expectedCounts := newCategoryCounts()
	expectedWitnesses := map[OutcomeCategory]int{}
	for index, request := range requests {
		expectedBaseline := enforceRequest(baseline, request)
		expectedCandidate := enforceRequest(candidate, request)
		expectedCategory := classifyOutcome(expectedBaseline, expectedCandidate)
		expectedCounts[expectedCategory]++
		if _, ok := expectedWitnesses[expectedCategory]; !ok {
			expectedWitnesses[expectedCategory] = index
		}

		got := report.Outcomes[index]
		if got.Index != index || got.Category != expectedCategory {
			t.Fatalf("index %d category=%q, expected %q", index, got.Category, expectedCategory)
		}
		assertSideResult(t, fmt.Sprintf("index %d baseline", index), got.Baseline, expectedBaseline)
		assertSideResult(t, fmt.Sprintf("index %d candidate", index), got.Candidate, expectedCandidate)
	}
	for category, expected := range expectedCounts {
		if report.Counts[category] != expected {
			t.Fatalf("category %q count=%d, expected %d", category, report.Counts[category], expected)
		}
	}
	for category, expected := range expectedWitnesses {
		got, ok := report.Witness(category)
		if !ok || got != expected {
			t.Fatalf("category %q witness=%v ok=%v, expected %d", category, got, ok, expected)
		}
	}
	if len(report.Witnesses) != len(expectedWitnesses) {
		t.Fatalf("witness set size %d != expected %d", len(report.Witnesses), len(expectedWitnesses))
	}
}

func assertSideResult(t *testing.T, label string, got, expected SideResult) {
	t.Helper()
	if (got.Err == nil) != (expected.Err == nil) {
		t.Fatalf("%s error presence mismatch: got=%v expected=%v", label, got.Err, expected.Err)
	}
	if got.Err == nil && got.Allowed != expected.Allowed {
		t.Fatalf("%s decision mismatch: got=%v expected=%v", label, got.Allowed, expected.Allowed)
	}
}

func analysisRequests(args ...[]interface{}) []AnalysisRequest {
	requests := make([]AnalysisRequest, len(args))
	for i, arg := range args {
		requests[i] = NewAnalysisRequest(arg...)
	}
	return requests
}

func TestPolicyImpactAnalyzer_RBACInheritanceAndSideEffects(t *testing.T) {
	live, adapter, watcher := newRecordingEnforcer(t,
		"examples/rbac_model.conf", "examples/rbac_policy.csv")
	analyzer, err := NewPolicyImpactAnalyzer(live)
	if err != nil {
		t.Fatalf("NewPolicyImpactAnalyzer failed: %v", err)
	}

	requests := analysisRequests(
		[]interface{}{"alice", "data1", "read"},
		[]interface{}{"alice", "data2", "read"},
		[]interface{}{"alice", "data2", "write"},
		[]interface{}{"bob", "data2", "write"},
		[]interface{}{"bob", "data2", "read"},
		[]interface{}{"bob", "data1", "read"},
	)
	patch := NewPolicyPatch(
		NewRemovePatchOperation("g", "g", []string{"alice", "data2_admin"}),
		NewAddPatchOperation("g", "g", []string{"bob", "data2_admin"}),
	)

	report, err := analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{
		VerifyBaselineDecisions: true,
	})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	independentBaseline, err := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	independentCandidate, err := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	applyPatchToIndependentEnforcer(t, independentCandidate, patch)
	checkReportAgainstIndependent(t, report, independentBaseline, independentCandidate, requests)

	// alice data2 read is the first allow-to-deny witness; bob data2 read is deny-to-allow.
	allowToDeny, ok := report.Witness(CategoryAllowToDeny)
	if !ok || allowToDeny != 1 {
		t.Fatalf("allow_to_deny witness=%d ok=%v, expected 1", allowToDeny, ok)
	}
	denyToAllow, ok := report.Witness(CategoryDenyToAllow)
	if !ok || denyToAllow != 4 {
		t.Fatalf("deny_to_allow witness=%d ok=%v, expected 4", denyToAllow, ok)
	}
	if report.Counts[CategoryUnchanged] != 3 || report.Counts[CategoryEvalError] != 0 {
		t.Fatalf("unexpected counts: %v", report.Counts)
	}

	// The live enforcer must be untouched: removed grouping rule still present.
	hasGrouping, err := live.HasGroupingPolicy("alice", "data2_admin")
	if err != nil || !hasGrouping {
		t.Fatalf("live grouping policy changed: has=%v err=%v", hasGrouping, err)
	}
	testEnforce(t, live, "alice", "data2", "read", true)
	testEnforce(t, live, "bob", "data2", "read", false)
	if adapter.writeCount() != 0 || watcher.updateCount() != 0 {
		t.Fatalf("external side effects detected: adapterWrites=%d watcherUpdates=%d",
			adapter.writeCount(), watcher.updateCount())
	}
}

func TestPolicyImpactAnalyzer_DenyPatch(t *testing.T) {
	live, _, _ := newRecordingEnforcer(t,
		"examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv")
	analyzer, _ := NewPolicyImpactAnalyzer(live)

	requests := analysisRequests(
		[]interface{}{"alice", "data1", "read"},
		[]interface{}{"alice", "data2", "write"},
		[]interface{}{"bob", "data2", "write"},
	)
	// Add a fresh deny rule flips a previously allowed request; removing the
	// existing deny flips a denied request back to allow.
	patch := NewPolicyPatch(
		NewAddPatchOperation("p", "p", []string{"alice", "data1", "read", "deny"}),
		NewRemovePatchOperation("p", "p", []string{"alice", "data2", "write", "deny"}),
	)
	report, err := analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	baseline, _ := NewEnforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv")
	candidate, _ := NewEnforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv")
	applyPatchToIndependentEnforcer(t, candidate, patch)
	checkReportAgainstIndependent(t, report, baseline, candidate, requests)

	if witness, _ := report.Witness(CategoryAllowToDeny); witness != 0 {
		t.Fatalf("allow_to_deny witness=%d, expected 0", witness)
	}
	if witness, _ := report.Witness(CategoryDenyToAllow); witness != 1 {
		t.Fatalf("deny_to_allow witness=%d, expected 1", witness)
	}
	// A previously allowed request changed only because of a deny patch.
	outcome := report.Outcomes[0]
	if outcome.Baseline.Allowed != true || outcome.Candidate.Allowed != false {
		t.Fatalf("deny patch did not flip baseline allow: %+v", outcome)
	}
}

func TestPolicyImpactAnalyzer_PriorityReorder(t *testing.T) {
	live, _, _ := newRecordingEnforcer(t,
		"examples/priority_model_explicit.conf", "examples/priority_policy_explicit.csv")
	analyzer, _ := NewPolicyImpactAnalyzer(live)

	requests := analysisRequests(
		[]interface{}{"alice", "data1", "read"},
		[]interface{}{"bob", "data2", "read"},
		[]interface{}{"bob", "data2", "write"},
	)
	// The in-place update keeps policy order exactly like Enforcer.UpdateNamedPolicy,
	// while the inserted top-priority deny flips a decision through priority semantics.
	patch := NewPolicyPatch(
		NewUpdatePatchOperation("p", "p",
			[]string{"1", "alice", "data1", "read", "allow"},
			[]string{"20", "alice", "data1", "read", "allow"}),
		NewAddPatchOperation("p", "p", []string{"0", "bob", "data2", "write", "deny"}),
	)
	report, err := analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	baseline, _ := NewEnforcer("examples/priority_model_explicit.conf", "examples/priority_policy_explicit.csv")
	candidate, _ := NewEnforcer("examples/priority_model_explicit.conf", "examples/priority_policy_explicit.csv")
	applyPatchToIndependentEnforcer(t, candidate, patch)
	checkReportAgainstIndependent(t, report, baseline, candidate, requests)

	// The flip is a priority effect, not a mere policy-set membership change;
	// the in-place priority update preserves order and therefore the decision.
	if report.Counts[CategoryAllowToDeny] != 1 || report.Counts[CategoryUnchanged] != 2 {
		t.Fatalf("unexpected priority counts: %v", report.Counts)
	}
	if witness, _ := report.Witness(CategoryAllowToDeny); witness != 2 {
		t.Fatalf("priority allow_to_deny witness=%d, expected 2", witness)
	}
	if report.Outcomes[0].Category != CategoryUnchanged {
		t.Fatalf("in-place update must preserve order and decision: %+v", report.Outcomes[0])
	}
}

func TestPolicyImpactAnalyzer_NegativeCondition(t *testing.T) {
	modelText := `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act && !keyMatch(r.act, "forbid_*")
`
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatal(err)
	}
	live, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = live.AddPolicy("alice", "data1", "read"); err != nil {
		t.Fatal(err)
	}
	analyzer, _ := NewPolicyImpactAnalyzer(live)

	requests := analysisRequests(
		[]interface{}{"alice", "data1", "read"},
		[]interface{}{"alice", "data1", "forbid_x"},
		[]interface{}{"alice", "data2", "read"},
	)
	// The new rule textually matches request 1, but the negative condition must
	// keep it denied: decisions come from real Enforce, not policy-set diffing.
	patch := NewPolicyPatch(
		NewAddPatchOperation("p", "p", []string{"alice", "data1", "forbid_x"}),
		NewAddPatchOperation("p", "p", []string{"alice", "data2", "read"}),
	)
	report, err := analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	baseModel, _ := model.NewModelFromString(modelText)
	baseline, _ := NewEnforcer(baseModel)
	_, _ = baseline.AddPolicy("alice", "data1", "read")
	candidateModel, _ := model.NewModelFromString(modelText)
	candidate, _ := NewEnforcer(candidateModel)
	applyPatchToIndependentEnforcer(t, candidate, NewPolicyPatch(
		NewAddPatchOperation("p", "p", []string{"alice", "data1", "read"}),
		patch.Operations[0],
		patch.Operations[1],
	))
	checkReportAgainstIndependent(t, report, baseline, candidate, requests)

	if report.Outcomes[1].Category != CategoryUnchanged || report.Outcomes[1].Candidate.Allowed != false {
		t.Fatalf("negative condition violated: %+v", report.Outcomes[1])
	}
	if witness, _ := report.Witness(CategoryDenyToAllow); witness != 2 {
		t.Fatalf("deny_to_allow witness=%d, expected 2", witness)
	}
}

func erroringFunctionFactory(callCount *int32) govaluate.ExpressionFunction {
	return func(args ...interface{}) (interface{}, error) {
		atomic.AddInt32(callCount, 1)
		if len(args) == 1 && args[0] == "explode" {
			return nil, errors.New("forced evaluation error")
		}
		return true, nil
	}
}

func TestPolicyImpactAnalyzer_ErrorFunction(t *testing.T) {
	modelText := `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && check(r.obj) && r.obj == p.obj && r.act == p.act
`
	m, _ := model.NewModelFromString(modelText)
	live, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	var calls int32
	live.AddFunction("check", erroringFunctionFactory(&calls))
	if _, err = live.AddPolicy("alice", "data1", "read"); err != nil {
		t.Fatal(err)
	}
	if _, err = live.AddPolicy("bob", "data2", "read"); err != nil {
		t.Fatal(err)
	}
	analyzer, _ := NewPolicyImpactAnalyzer(live)

	requests := analysisRequests(
		[]interface{}{"alice", "data1", "read"},
		[]interface{}{"alice", "explode", "read"},
		[]interface{}{"carol", "explode", "read"},
		[]interface{}{"carol", "data3", "read"},
	)
	patch := NewPolicyPatch(
		NewRemovePatchOperation("p", "p", []string{"alice", "data1", "read"}),
		NewAddPatchOperation("p", "p", []string{"carol", "explode", "read"}),
	)

	// Without the purity contract the analyzer must refuse the run.
	if _, err = analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{}); err == nil ||
		!errors.Is(err, ErrImpactAnalysisContract) {
		t.Fatalf("expected contract error, got %v", err)
	}

	options := AnalysisOptions{PureFunctions: []PureFunction{{
		Name: "check",
		Func: erroringFunctionFactory(new(int32)),
	}}}
	report, err := analyzer.Analyze(context.Background(), patch, requests, options)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	baseModel, _ := model.NewModelFromString(modelText)
	baseline, _ := NewEnforcer(baseModel)
	baseline.AddFunction("check", erroringFunctionFactory(new(int32)))
	_, _ = baseline.AddPolicy("alice", "data1", "read")
	_, _ = baseline.AddPolicy("bob", "data2", "read")
	candidateModel, _ := model.NewModelFromString(modelText)
	candidate, _ := NewEnforcer(candidateModel)
	candidate.AddFunction("check", erroringFunctionFactory(new(int32)))
	_, _ = candidate.AddPolicy("bob", "data2", "read")
	_, _ = candidate.AddPolicy("carol", "explode", "read")
	checkReportAgainstIndependent(t, report, baseline, candidate, requests)

	if report.Counts[CategoryEvalError] != 2 {
		t.Fatalf("expected 2 eval errors, got %d (%v)", report.Counts[CategoryEvalError], report.Counts)
	}
	errorWitness, ok := report.Witness(CategoryEvalError)
	if !ok || errorWitness != 1 {
		t.Fatalf("eval_error witness=%d ok=%v, expected 1", errorWitness, ok)
	}
	// Index 1 errors only on the baseline; removing the alice rule makes the
	// candidate evaluate cleanly. Index 2 errors only on the candidate.
	if report.Outcomes[1].Baseline.Err == nil || report.Outcomes[1].Candidate.Err != nil {
		t.Fatalf("index 1 should error only on baseline: %+v", report.Outcomes[1])
	}
	if report.Outcomes[2].Baseline.Err != nil || report.Outcomes[2].Candidate.Err == nil {
		t.Fatalf("index 2 should error only on candidate: %+v", report.Outcomes[2])
	}
}

// stubRoleManager satisfies RoleManager for contract rejection tests; its
// methods are never expected to run successfully.
type stubRoleManager struct{}

func (stubRoleManager) Clear() error { return nil }
func (stubRoleManager) AddLink(string, string, ...string) error {
	return errors.New("stub")
}
func (stubRoleManager) BuildRelationship(string, string, ...string) error {
	return errors.New("stub")
}
func (stubRoleManager) DeleteLink(string, string, ...string) error {
	return errors.New("stub")
}
func (stubRoleManager) HasLink(string, string, ...string) (bool, error) {
	return false, errors.New("stub")
}
func (stubRoleManager) GetRoles(string, ...string) ([]string, error) { return nil, errors.New("stub") }
func (stubRoleManager) GetUsers(string, ...string) ([]string, error) { return nil, errors.New("stub") }
func (stubRoleManager) GetImplicitRoles(string, ...string) ([]string, error) {
	return nil, errors.New("stub")
}
func (stubRoleManager) GetImplicitUsers(string, ...string) ([]string, error) {
	return nil, errors.New("stub")
}
func (stubRoleManager) GetDomains(string) ([]string, error)             { return nil, errors.New("stub") }
func (stubRoleManager) GetAllDomains() ([]string, error)                { return nil, errors.New("stub") }
func (stubRoleManager) PrintRoles() error                               { return nil }
func (stubRoleManager) Match(string, string) bool                       { return false }
func (stubRoleManager) AddMatchingFunc(string, rbac.MatchingFunc)       {}
func (stubRoleManager) AddDomainMatchingFunc(string, rbac.MatchingFunc) {}
func (stubRoleManager) DeleteDomain(string) error                       { return errors.New("stub") }

// cloneableStubRoleManager returns an independent native manager when cloned.
type cloneableStubRoleManager struct {
	stubRoleManager
}

func (cloneableStubRoleManager) CloneForAnalysis() (rbac.RoleManager, error) {
	return defaultrolemanager.NewRoleManagerImpl(10), nil
}

// freezableStubRoleManager records the freeze and allows shared read-only use.
type freezableStubRoleManager struct {
	stubRoleManager
	frozen bool
}

func (f *freezableStubRoleManager) FreezeForAnalysis() error {
	f.frozen = true
	return nil
}

func TestPolicyImpactAnalyzer_RoleManagerContracts(t *testing.T) {
	live, err := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	live.SetRoleManager(stubRoleManager{})
	analyzer, _ := NewPolicyImpactAnalyzer(live)
	requests := analysisRequests([]interface{}{"alice", "data1", "read"})

	if _, err = analyzer.Analyze(context.Background(), PolicyPatch{}, requests, AnalysisOptions{}); err == nil ||
		!errors.Is(err, ErrImpactAnalysisContract) {
		t.Fatalf("expected rejection of unknown role manager, got %v", err)
	}

	// An explicit cloner contract satisfies the analyzer.
	report, err := analyzer.Analyze(context.Background(), PolicyPatch{}, requests, AnalysisOptions{
		RoleManagerCloner: func(string, rbac.RoleManager) (rbac.RoleManager, error) {
			return defaultrolemanager.NewRoleManagerImpl(10), nil
		},
	})
	if err != nil {
		t.Fatalf("cloner contract failed: %v", err)
	}
	if !report.Complete || report.AnalyzedCount != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}

	// CloneableRoleManager and FreezableRoleManager interfaces are honored.
	cloneableLive, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	cloneableLive.SetRoleManager(cloneableStubRoleManager{})
	cloneableAnalyzer, _ := NewPolicyImpactAnalyzer(cloneableLive)
	if _, err = cloneableAnalyzer.Analyze(context.Background(), PolicyPatch{}, requests, AnalysisOptions{}); err != nil {
		t.Fatalf("CloneableRoleManager rejected: %v", err)
	}

	freezableLive, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	freezable := &freezableStubRoleManager{}
	freezableLive.SetRoleManager(freezable)
	freezableAnalyzer, _ := NewPolicyImpactAnalyzer(freezableLive)
	if _, err = freezableAnalyzer.Analyze(context.Background(), PolicyPatch{}, requests, AnalysisOptions{}); err != nil {
		t.Fatalf("FreezableRoleManager rejected: %v", err)
	}
	if !freezable.frozen {
		t.Fatal("FreezeForAnalysis was not invoked")
	}

	// A cloner must give every isolated enforcer an independent manager, so a
	// grouping patch rebuilds the candidate graph without touching the live one.
	rbacLive, err := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	rbacLive.SetRoleManager(stubRoleManager{})
	rbacAnalyzer, _ := NewPolicyImpactAnalyzer(rbacLive)
	rbacRequests := analysisRequests(
		[]interface{}{"bob", "data2", "read"},
		[]interface{}{"alice", "data2", "read"},
	)
	rbacPatch := NewPolicyPatch(NewAddPatchOperation("g", "g", []string{"bob", "data2_admin"}))
	rbacReport, err := rbacAnalyzer.Analyze(context.Background(), rbacPatch, rbacRequests, AnalysisOptions{
		RoleManagerCloner: func(string, rbac.RoleManager) (rbac.RoleManager, error) {
			return defaultrolemanager.NewRoleManagerImpl(10), nil
		},
	})
	if err != nil {
		t.Fatalf("cloner with grouping patch failed: %v", err)
	}
	if witness, _ := rbacReport.Witness(CategoryDenyToAllow); witness != 0 {
		t.Fatalf("cloned candidate role graph wrong: witness=%d, expected 0", witness)
	}
	if has, _ := rbacLive.HasGroupingPolicy("bob", "data2_admin"); has {
		t.Fatal("grouping patch leaked into live model")
	}

	// A frozen shared manager cannot serve a grouping-patch analysis.
	frozenRBACLive, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	frozenRBAC := &freezableStubRoleManager{}
	frozenRBACLive.SetRoleManager(frozenRBAC)
	frozenAnalyzer, _ := NewPolicyImpactAnalyzer(frozenRBACLive)
	if _, err = frozenAnalyzer.Analyze(context.Background(), rbacPatch, rbacRequests, AnalysisOptions{}); err == nil ||
		!errors.Is(err, ErrImpactAnalysisContract) {
		t.Fatalf("grouping patch on frozen manager must be rejected, got %v", err)
	}
	// Policy-only patches remain valid on frozen managers.
	pOnlyPatch := NewPolicyPatch(NewAddPatchOperation("p", "p", []string{"bob", "data2", "read"}))
	if _, err = frozenAnalyzer.Analyze(context.Background(), pOnlyPatch, rbacRequests, AnalysisOptions{}); err != nil {
		t.Fatalf("policy-only patch on frozen manager should work: %v", err)
	}
}

func TestPolicyImpactAnalyzer_MatchingFuncContractAndBaselineVerify(t *testing.T) {
	live, err := NewEnforcer("examples/rbac_with_pattern_model.conf", "examples/rbac_with_pattern_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	live.AddNamedMatchingFunc("g2", "matchingFunc", util.KeyMatch2)
	analyzer, _ := NewPolicyImpactAnalyzer(live)
	requests := analysisRequests(
		[]interface{}{"alice", "/book/1", "GET"},
		[]interface{}{"bob", "/pen/1", "GET"},
	)
	patch := NewPolicyPatch(NewAddPatchOperation("p", "p", []string{"alice", "/book/1", "POST"}))

	// Without the matching function contract the isolated baseline diverges and
	// the optional verification rejects the run instead of returning a wrong report.
	_, err = analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{
		VerifyBaselineDecisions: true,
	})
	if err == nil || !errors.Is(err, ErrBaselineDivergence) {
		t.Fatalf("expected baseline divergence error, got %v", err)
	}

	// With the explicit pure matching function contract the verification passes.
	report, err := analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{
		VerifyBaselineDecisions: true,
		MatchingFuncs: []MatchingFuncContract{{
			PType: "g2",
			Name:  "matchingFunc",
			Func:  util.KeyMatch2,
		}},
	})
	if err != nil {
		t.Fatalf("contracted analysis failed: %v", err)
	}
	if !report.Complete || report.Generation != live.getPolicyVersion() {
		t.Fatalf("unexpected report: %+v", report)
	}

	// An unknown ptype in a matching contract is rejected up front.
	_, err = analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{
		MatchingFuncs: []MatchingFuncContract{{PType: "g9", Name: "x", Func: util.KeyMatch2}},
	})
	if err == nil || !errors.Is(err, ErrImpactAnalysisContract) {
		t.Fatalf("unknown matching ptype must be rejected, got %v", err)
	}
}

func TestPolicyImpactAnalyzer_NilEnforcer(t *testing.T) {
	if _, err := NewPolicyImpactAnalyzer(nil); err == nil {
		t.Fatal("nil enforcer must be rejected")
	}
}

func TestPolicyImpactAnalyzer_EnforceContextDomainAndEval(t *testing.T) {
	// Named EnforceContext with multiple policy definitions.
	contextLive, err := NewEnforcer(
		"examples/multiple_policy_definitions_model.conf",
		"examples/multiple_policy_definitions_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	contextAnalyzer, _ := NewPolicyImpactAnalyzer(contextLive)
	enforceContext := NewEnforceContext("2")
	enforceContext.EType = "e"
	requests := []AnalysisRequest{
		NewAnalysisRequest("alice", "data2", "read"),
		NewContextAnalysisRequest(enforceContext, struct{ Age int }{Age: 30}, "/data1", "read"),
		NewContextAnalysisRequest(enforceContext, struct{ Age int }{Age: 70}, "/data1", "read"),
		NewContextAnalysisRequest(enforceContext, struct{ Age int }{Age: 10}, "/data1", "read"),
	}
	patch := NewPolicyPatch(NewAddPatchOperation("p", "p2",
		[]string{"r2.sub.Age < 18", "/data1", "read", "allow"}))
	contextReport, err := contextAnalyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{})
	if err != nil {
		t.Fatalf("context Analyze failed: %v", err)
	}
	contextBaseline, _ := NewEnforcer(
		"examples/multiple_policy_definitions_model.conf",
		"examples/multiple_policy_definitions_policy.csv")
	contextCandidate, _ := NewEnforcer(
		"examples/multiple_policy_definitions_model.conf",
		"examples/multiple_policy_definitions_policy.csv")
	applyPatchToIndependentEnforcer(t, contextCandidate, patch)
	checkReportAgainstIndependent(t, contextReport, contextBaseline, contextCandidate, requests)
	if witness, _ := contextReport.Witness(CategoryDenyToAllow); witness != 3 {
		t.Fatalf("context deny_to_allow witness=%d, expected 3", witness)
	}

	// Domain-aware RBAC.
	domainLive, _ := NewEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
	domainAnalyzer, _ := NewPolicyImpactAnalyzer(domainLive)
	domainRequests := analysisRequests(
		[]interface{}{"alice", "domain1", "data1", "read"},
		[]interface{}{"alice", "domain2", "data2", "read"},
	)
	domainPatch := NewPolicyPatch(NewAddPatchOperation("g", "g",
		[]string{"alice", "admin", "domain2"}))
	domainReport, err := domainAnalyzer.Analyze(context.Background(), domainPatch, domainRequests, AnalysisOptions{})
	if err != nil {
		t.Fatalf("domain Analyze failed: %v", err)
	}
	domainBaseline, _ := NewEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
	domainCandidate, _ := NewEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
	applyPatchToIndependentEnforcer(t, domainCandidate, domainPatch)
	checkReportAgainstIndependent(t, domainReport, domainBaseline, domainCandidate, domainRequests)
	if witness, _ := domainReport.Witness(CategoryDenyToAllow); witness != 1 {
		t.Fatalf("domain deny_to_allow witness=%d, expected 1", witness)
	}

	// eval() semantics.
	evalLive, _ := NewEnforcer("examples/eval_operator_model.conf", "examples/eval_operator_policy.csv")
	evalAnalyzer, _ := NewPolicyImpactAnalyzer(evalLive)
	evalRequests := analysisRequests(
		[]interface{}{"admin", "users", "write"},
		[]interface{}{"root", "users", "write"},
	)
	evalPatch := NewPolicyPatch(NewUpdatePatchOperation("p", "p",
		[]string{"r.sub == 'admin' || false", "r.obj == 'users'", "write"},
		[]string{"r.sub == 'admin' || r.sub == 'root'", "r.obj == 'users'", "write"}))
	evalReport, err := evalAnalyzer.Analyze(context.Background(), evalPatch, evalRequests, AnalysisOptions{})
	if err != nil {
		t.Fatalf("eval Analyze failed: %v", err)
	}
	evalBaseline, _ := NewEnforcer("examples/eval_operator_model.conf", "examples/eval_operator_policy.csv")
	evalCandidate, _ := NewEnforcer("examples/eval_operator_model.conf", "examples/eval_operator_policy.csv")
	applyPatchToIndependentEnforcer(t, evalCandidate, evalPatch)
	checkReportAgainstIndependent(t, evalReport, evalBaseline, evalCandidate, evalRequests)
	if witness, _ := evalReport.Witness(CategoryDenyToAllow); witness != 1 {
		t.Fatalf("eval deny_to_allow witness=%d, expected 1", witness)
	}
}

func TestPolicyImpactAnalyzer_ContextCancellation(t *testing.T) {
	modelText := `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = heartbeat() && r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	buildLive := func() *Enforcer {
		m, _ := model.NewModelFromString(modelText)
		e, err := NewEnforcer(m)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = e.AddPolicy("alice", "data1", "read")
		return e
	}
	live := buildLive()
	var calls int32
	live.AddFunction("heartbeat", func(args ...interface{}) (interface{}, error) {
		atomic.AddInt32(&calls, 1)
		return true, nil
	})
	analyzer, _ := NewPolicyImpactAnalyzer(live)
	requests := make([]AnalysisRequest, 1000)
	for i := range requests {
		requests[i] = NewAnalysisRequest("alice", "data1", "read")
	}
	options := AnalysisOptions{
		BatchSize: 10,
		PureFunctions: []PureFunction{{
			Name: "heartbeat",
			Func: func(args ...interface{}) (interface{}, error) { return true, nil },
		}},
	}

	// Pre-cancelled context: nothing is analyzed and nothing is called unchanged.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	emptyReport, err := analyzer.Analyze(cancelledCtx, PolicyPatch{}, requests, options)
	if err != context.Canceled || emptyReport.Complete || emptyReport.AnalyzedCount != 0 {
		t.Fatalf("pre-cancelled run wrong: err=%v report=%+v", err, emptyReport)
	}
	if emptyReport.Counts[CategoryUnchanged] != 0 {
		t.Fatalf("unprocessed requests must not be counted as unchanged: %v", emptyReport.Counts)
	}

	// Cancellation mid-run returns the analyzed range only.
	live2 := buildLive()
	var calls2 int32
	ctx2, cancelMid := context.WithCancel(context.Background())
	live2.AddFunction("heartbeat", func(args ...interface{}) (interface{}, error) {
		if atomic.AddInt32(&calls2, 1) == 200 {
			cancelMid()
		}
		return true, nil
	})
	analyzer2, _ := NewPolicyImpactAnalyzer(live2)
	options2 := options
	options2.PureFunctions = []PureFunction{{
		Name: "heartbeat",
		Func: live2.fm.GetFunctions()["heartbeat"],
	}}
	partialReport, err := analyzer2.Analyze(ctx2, PolicyPatch{}, requests, options2)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if partialReport.Complete || partialReport.AnalyzedCount == 0 ||
		partialReport.AnalyzedCount >= len(requests) {
		t.Fatalf("unexpected partial report: %+v", partialReport)
	}
	total := 0
	for _, count := range partialReport.Counts {
		total += count
	}
	if total != partialReport.AnalyzedCount || len(partialReport.Outcomes) != partialReport.AnalyzedCount {
		t.Fatalf("partial counts do not bound the analyzed range: %+v", partialReport)
	}
	for category, witness := range partialReport.Witnesses {
		if witness >= partialReport.AnalyzedCount {
			t.Fatalf("witness %d for %q escapes analyzed range %d",
				witness, category, partialReport.AnalyzedCount)
		}
	}
}

func TestPolicyImpactAnalyzer_ConcurrentLiveUpdate(t *testing.T) {
	modelText := `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = barrier() && g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
	m, _ := model.NewModelFromString(modelText)
	synced, err := NewSyncedEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = synced.AddPolicy("data1_admin", "data1", "read")
	_, _ = synced.AddGroupingPolicy("alice", "data1_admin")

	started := make(chan struct{}, 1)
	barrier := func(args ...interface{}) (interface{}, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		return true, nil
	}
	synced.AddFunction("barrier", barrier)

	adapter := &recordingAdapter{inner: fileadapter.NewAdapter("examples/rbac_policy.csv")}
	synced.SetAdapter(adapter)
	watcher := &recordingWatcher{}
	_ = synced.SetWatcher(watcher)

	analyzer, _ := NewPolicyImpactAnalyzer(synced.Enforcer)
	requests := make([]AnalysisRequest, 300)
	for i := range requests {
		requests[i] = NewAnalysisRequest("alice", "data1", "read")
	}
	patch := NewPolicyPatch(NewAddPatchOperation("p", "p",
		[]string{"data1_admin", "data1", "write"}))
	options := AnalysisOptions{
		BatchSize:     16,
		Locker:        synced.GetLock(),
		PureFunctions: []PureFunction{{Name: "barrier", Func: barrier}},
	}

	// Independent snapshot enforcers are built from their own model copies
	// before any live mutation, so they cannot observe the live goroutine.
	noOpBarrier := func(args ...interface{}) (interface{}, error) { return true, nil }
	baselineModel, _ := model.NewModelFromString(modelText)
	independentBaseline, _ := NewEnforcer(baselineModel)
	independentBaseline.AddFunction("barrier", noOpBarrier)
	_, _ = independentBaseline.AddPolicy("data1_admin", "data1", "read")
	_, _ = independentBaseline.AddGroupingPolicy("alice", "data1_admin")
	candidateModel, _ := model.NewModelFromString(modelText)
	independentCandidate, _ := NewEnforcer(candidateModel)
	independentCandidate.AddFunction("barrier", noOpBarrier)
	_, _ = independentCandidate.AddPolicy("data1_admin", "data1", "read")
	_, _ = independentCandidate.AddGroupingPolicy("alice", "data1_admin")
	applyPatchToIndependentEnforcer(t, independentCandidate, patch)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-started
		_, _ = synced.AddPolicy("charlie", "data9", "read")
	}()

	report, err := analyzer.Analyze(context.Background(), patch, requests, options)
	wg.Wait()
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	checkReportAgainstIndependent(t, report, independentBaseline, independentCandidate, requests)

	// The live mutation landed and is visible after analysis; the report never saw it.
	allowed, err := synced.Enforce("charlie", "data9", "read")
	if err != nil || !allowed {
		t.Fatalf("live mutation not visible: allowed=%v err=%v", allowed, err)
	}
	if report.Generation >= synced.getPolicyVersion() {
		t.Fatalf("report generation %d should predate live generation %d",
			report.Generation, synced.getPolicyVersion())
	}
	if _, ok := report.Witness(CategoryDenyToAllow); ok {
		t.Fatalf("the concurrent live charlie rule must not appear in the report")
	}
	// The single write/notification belongs to the explicit live mutation only.
	if adapter.writeCount() != 1 || watcher.updateCount() != 1 {
		t.Fatalf("unexpected side effects: adapterWrites=%d watcherUpdates=%d",
			adapter.writeCount(), watcher.updateCount())
	}
}

func TestPolicyImpactAnalyzer_InputOwnership(t *testing.T) {
	live, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	analyzer, _ := NewPolicyImpactAnalyzer(live)
	requests := analysisRequests(
		[]interface{}{"alice", "data2", "read"},
		[]interface{}{"bob", "data1", "read"},
		[]interface{}{"bob", "data2", "read"},
	)
	patch := NewPolicyPatch(NewAddPatchOperation("g", "g", []string{"bob", "data2_admin"}))
	report, err := analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{})
	if err != nil {
		t.Fatal(err)
	}
	witnessIndex, _ := report.Witness(CategoryDenyToAllow)
	witnessBefore := report.Outcomes[witnessIndex]

	// Mutate every caller-owned slice after the run; owned report data must survive.
	requests[0].Args[0] = "mutated"
	requests[1].Args[0] = "mutated"
	patch.Operations[0].Rule[0] = "mutated"
	witnessAfter, ok := report.WitnessOutcome(CategoryDenyToAllow)
	if !ok || witnessAfter.Request.Args[0] != "bob" {
		t.Fatalf("witness request was corrupted: %+v", witnessAfter)
	}
	if witnessBefore.Request.Args[0] != "bob" {
		t.Fatalf("stored witness request must be an independent copy")
	}
}

func TestPolicyImpactAnalyzer_Grouping(t *testing.T) {
	modelText := `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	m, _ := model.NewModelFromString(modelText)
	live, _ := NewEnforcer(m)
	_, _ = live.AddPolicy("alice", "data1", "read")
	analyzer, _ := NewPolicyImpactAnalyzer(live)
	requests := []AnalysisRequest{
		NewAnalysisRequest("alice", "data1", "read"),
		NewAnalysisRequest("alice", "data2", "read"),
		NewAnalysisRequest("bob", "data1", "read"),
		NewAnalysisRequest(1, "data1", "read"),
	}
	patch := NewPolicyPatch(NewAddPatchOperation("p", "p", []string{"alice", "data2", "read"}))
	report, err := analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{GroupBy: []int{0, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Groups) != 3 {
		t.Fatalf("expected 3 boundary-safe groups, got %d: %+v", len(report.Groups), report.Groups)
	}
	for _, group := range report.Groups {
		fields := group.Key.Fields()
		if len(fields) != 2 || fields[0].Index != 0 || fields[1].Index != 2 {
			t.Fatalf("group key lost field boundaries: %+v", fields)
		}
		total := 0
		for _, count := range group.Counts {
			total += count
		}
		if total == 0 {
			t.Fatalf("empty group produced: %+v", group)
		}
	}
	// String "1" and int 1 must remain distinct typed keys.
	typedValueGroups := 0
	for _, group := range report.Groups {
		firstField := group.Key.Fields()[0]
		if firstField.Value == "1" {
			typedValueGroups++
			if firstField.Type != "int" {
				t.Fatalf("int request lost its type: %+v", firstField)
			}
		}
	}
	if typedValueGroups != 1 {
		t.Fatalf("expected exactly one int-typed group, got %d: %+v", typedValueGroups, report.Groups)
	}

	if _, err = analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{GroupBy: []int{-1}}); err == nil {
		t.Fatal("negative GroupBy index must be rejected")
	}
	if _, err = analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{GroupBy: []int{9}}); err == nil ||
		!errors.Is(err, ErrImpactAnalysisContract) {
		t.Fatalf("out-of-range GroupBy must raise contract error, got %v", err)
	}
}

func TestPolicyImpactAnalyzer_PatchValidation(t *testing.T) {
	live, _, _ := newRecordingEnforcer(t,
		"examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv")
	analyzer, _ := NewPolicyImpactAnalyzer(live)
	requests := analysisRequests([]interface{}{"alice", "data1", "read"})

	cases := []PolicyPatch{
		NewPolicyPatch(NewAddPatchOperation("p", "p", []string{"alice", "data1", "read", "allow"})),
		NewPolicyPatch(NewRemovePatchOperation("p", "p", []string{"nobody", "data9", "read", "deny"})),
		NewPolicyPatch(NewUpdatePatchOperation("p", "p",
			[]string{"nobody", "data9", "read", "deny"}, []string{"nobody", "data9", "read", "allow"})),
		NewPolicyPatch(NewAddPatchOperation("x", "x", []string{"alice"})),
		NewPolicyPatch(NewAddPatchOperation("p", "p", []string{"alice", "data1"})),
	}
	for i, patch := range cases {
		if _, err := analyzer.Analyze(context.Background(), patch, requests, AnalysisOptions{}); err == nil ||
			!errors.Is(err, ErrInvalidPolicyPatch) {
			t.Fatalf("case %d expected invalid patch error, got %v", i, err)
		}
	}

	// Rejected analysis must leave the live model and its decisions untouched.
	hasPolicy, err := live.HasPolicy("alice", "data2", "write", "deny")
	if err != nil || !hasPolicy {
		t.Fatalf("live policy changed after rejected patches: %v", err)
	}
	if !strings.HasPrefix(ErrInvalidPolicyPatch.Error(), "invalid") {
		t.Fatalf("error sentinel wording changed: %v", ErrInvalidPolicyPatch)
	}
}
