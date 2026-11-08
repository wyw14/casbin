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
	"time"

	"github.com/casbin/casbin/v3/model"
	persistcache "github.com/casbin/casbin/v3/persist/cache"
	"github.com/casbin/casbin/v3/rbac"
	defaultrolemanager "github.com/casbin/casbin/v3/rbac/default-role-manager"
	"github.com/casbin/govaluate"
)

func unlimitedBudget() Budget {
	return Budget{MaxPolicies: -1, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: -1}
}

func assertBudgetExceeded(t *testing.T, err error, stage string) *BudgetExceededError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a budget error, got nil")
	}
	var budgetErr *BudgetExceededError
	if !errors.As(err, &budgetErr) {
		t.Fatalf("expected *BudgetExceededError, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("budget error must wrap ErrBudgetExceeded, got %v", err)
	}
	if budgetErr.Stage != stage {
		t.Fatalf("expected stage %q, got %q (path %q)", stage, budgetErr.Stage, budgetErr.Path)
	}
	return budgetErr
}

func newCounterEnforcer(t *testing.T, policyCount int) (*Enforcer, *int64) {
	t.Helper()
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "countCall(r.sub) && r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	var calls int64
	e.AddFunction("countCall", func(args ...interface{}) (interface{}, error) {
		atomic.AddInt64(&calls, 1)
		return true, nil
	})
	for i := 0; i < policyCount; i++ {
		if _, err = e.AddPolicy(fmt.Sprintf("user%02d", i), "data", "read"); err != nil {
			t.Fatalf("AddPolicy: %v", err)
		}
	}
	return e, &calls
}

// TestEnforceBoundedPolicyLimit checks strict policy/function boundaries with a
// counting pure function, zero-quota semantics and equivalence on success.
func TestEnforceBoundedPolicyLimit(t *testing.T) {
	e, calls := newCounterEnforcer(t, 20)

	// Policy budget exhausted: the 6th policy is rejected before its matcher
	// runs, so exactly 5 counting functions have been executed.
	_, err := e.EnforceBounded(context.Background(), Budget{MaxPolicies: 5, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"alice", "data", "read")
	budgetErr := assertBudgetExceeded(t, err, BudgetStagePolicy)
	if budgetErr.Limit != 5 || budgetErr.Used != 6 || budgetErr.Path != "p[5]" {
		t.Fatalf("unexpected budget error fields: %+v", budgetErr)
	}
	if got := atomic.LoadInt64(calls); got != 5 {
		t.Fatalf("expected 5 matcher evaluations before the limit, got %d", got)
	}

	// Zero policy quota fails on the first chargeable policy, executing nothing.
	atomic.StoreInt64(calls, 0)
	_, err = e.EnforceBounded(context.Background(), Budget{MaxPolicies: 0, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"alice", "data", "read")
	budgetErr = assertBudgetExceeded(t, err, BudgetStagePolicy)
	if budgetErr.Used != 1 || budgetErr.Path != "p[0]" {
		t.Fatalf("unexpected zero-quota error: %+v", budgetErr)
	}
	if got := atomic.LoadInt64(calls); got != 0 {
		t.Fatalf("zero quota must not execute any matcher, got %d calls", got)
	}

	// Function budget: pre-call charging means the 8th call is rejected and the
	// wrapped function runs only 7 times.
	atomic.StoreInt64(calls, 0)
	_, err = e.EnforceBounded(context.Background(), Budget{MaxPolicies: -1, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: 7},
		"alice", "data", "read")
	budgetErr = assertBudgetExceeded(t, err, BudgetStageFunction)
	if budgetErr.Path != "countCall" || budgetErr.Used != 8 {
		t.Fatalf("unexpected function budget error: %+v", budgetErr)
	}
	if got := atomic.LoadInt64(calls); got != 7 {
		t.Fatalf("expected 7 executed function calls, got %d", got)
	}

	// Sufficient budget: decision identical to ordinary Enforce.
	want, wantErr := e.Enforce("alice", "data", "read")
	atomic.StoreInt64(calls, 0)
	got, gotErr := e.EnforceBounded(context.Background(), unlimitedBudget(), "alice", "data", "read")
	if got != want || (gotErr == nil) != (wantErr == nil) {
		t.Fatalf("bounded (%v,%v) != enforce (%v,%v)", got, gotErr, want, wantErr)
	}
	if atomic.LoadInt64(calls) != 20 {
		t.Fatalf("all 20 non-matching policies must be evaluated, got %d", atomic.LoadInt64(calls))
	}
}

// TestEnforceBoundedPolicyIndexSkips verifies rules skipped by an installed
// policy index are neither evaluated nor billed.
func TestEnforceBoundedPolicyIndexSkips(t *testing.T) {
	e, calls := newCounterEnforcer(t, 20)
	if err := e.SetPolicyIndexByToken("p", "r_sub", "p_sub"); err != nil {
		t.Fatalf("SetPolicyIndexByToken: %v", err)
	}

	// Request subject "alice" has no partition, so every rule is skipped. Even a
	// zero policy budget must then complete successfully with zero evaluations.
	got, err := e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: 0, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"alice", "data", "read")
	if err != nil || got {
		t.Fatalf("skipped rules must not be billed or allowed, got (%v,%v)", got, err)
	}
	if atomic.LoadInt64(calls) != 0 {
		t.Fatalf("index-skipped policies must not evaluate the matcher, got %d", *calls)
	}
}

func newRBACEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	return e
}

// TestEnforceBoundedRoleCycle verifies role cycles stay finite and hit the
// node budget instead of looping forever, while unlimited runs match Enforce.
func TestEnforceBoundedRoleCycle(t *testing.T) {
	e := newRBACEnforcer(t)
	for _, link := range [][2]string{{"alice", "r1"}, {"r1", "r2"}, {"r2", "alice"}} {
		if _, err := e.AddGroupingPolicy(link[0], link[1]); err != nil {
			t.Fatalf("AddGroupingPolicy: %v", err)
		}
	}
	if _, err := e.AddPolicy("ghost", "data", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	// Default maxHierarchyLevel is 10: the cycle alice->r1->r2->alice produces
	// 11 finite node inspections when the target does not exist.
	_, err := e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: 4, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"alice", "data", "read")
	budgetErr := assertBudgetExceeded(t, err, BudgetStageRole)
	if budgetErr.Used != 5 || !strings.Contains(budgetErr.Path, "g(alice, ghost)") ||
		!strings.Contains(budgetErr.Path, "@node(") {
		t.Fatalf("unexpected role budget error: %+v", budgetErr)
	}

	// Unlimited budget terminates normally and agrees with ordinary Enforce.
	want, wantErr := e.Enforce("alice", "data", "read")
	got, gotErr := e.EnforceBounded(context.Background(), unlimitedBudget(), "alice", "data", "read")
	if got != want || (gotErr == nil) != (wantErr == nil) {
		t.Fatalf("bounded (%v,%v) != enforce (%v,%v)", got, gotErr, want, wantErr)
	}
	if want || wantErr != nil {
		t.Fatalf("cycle lookup of missing role should be false/nil, got (%v,%v)", want, wantErr)
	}
}

// TestEnforceBoundedDeepRoleChain walks a long linear chain to prove node
// accounting follows traversal depth exactly.
func TestEnforceBoundedDeepRoleChain(t *testing.T) {
	e := newRBACEnforcer(t)
	rm := defaultrolemanager.NewRoleManagerImpl(100)
	// SetRoleManager updates rmMap; the matcher closure reads assertion.RM, so
	// install the bounded manager in both places.
	e.SetRoleManager(rm)
	e.model["g"]["g"].RM = rm

	const chainLen = 30
	if err := rm.AddLink("user", "r1"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < chainLen; i++ {
		if err := rm.AddLink(fmt.Sprintf("r%d", i), fmt.Sprintf("r%d", i+1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.AddPolicy(fmt.Sprintf("r%d", chainLen), "data", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	// A successful lookup inspects user + r1..r30 = 31 nodes.
	got, err := e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: 10, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"user", "data", "read")
	budgetErr := assertBudgetExceeded(t, err, BudgetStageRole)
	if budgetErr.Used != 11 {
		t.Fatalf("expected 11th node inspection to fail, got %+v", budgetErr)
	}
	if got {
		t.Fatal("budget failure must not report an allow")
	}

	got, err = e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: 31, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"user", "data", "read")
	if err != nil || !got {
		t.Fatalf("exact-node budget should succeed, got (%v,%v)", got, err)
	}

	want, wantErr := e.Enforce("user", "data", "read")
	if want != true || wantErr != nil {
		t.Fatalf("ordinary enforce mismatch: (%v,%v)", want, wantErr)
	}
}

// TestEnforceBoundedGCacheBilling pins the fixed g() memo rules: a cache hit
// costs one function unit but zero role nodes, and the memo never leaks across
// calls.
func TestEnforceBoundedGCacheBilling(t *testing.T) {
	e := newRBACEnforcer(t)
	if _, err := e.AddGroupingPolicy("alice", "admin"); err != nil {
		t.Fatal(err)
	}
	// Both rules evaluate g(alice, admin); objects never match the request.
	if _, err := e.AddPolicy("admin", "data1", "read"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("admin", "data2", "read"); err != nil {
		t.Fatal(err)
	}

	// A miss costs 2 nodes (alice, admin). The second g() is a memo hit: with a
	// 2-node budget the call still succeeds because hits bill zero nodes.
	got, err := e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: 2, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"alice", "dataX", "read")
	if err != nil || got {
		t.Fatalf("cache hit must not bill role nodes, got (%v,%v)", got, err)
	}

	// Every g() entry bills a function unit even when served from the memo.
	_, err = e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: 1},
		"alice", "dataX", "read")
	budgetErr := assertBudgetExceeded(t, err, BudgetStageFunction)
	if budgetErr.Path != "g" || budgetErr.Used != 2 {
		t.Fatalf("cache hit must still bill a function unit: %+v", budgetErr)
	}

	// The memo is per-call: two independent calls each pay the miss node cost.
	for i := 0; i < 2; i++ {
		_, err = e.EnforceBounded(context.Background(),
			Budget{MaxPolicies: -1, MaxRoleNodes: 1, MaxEvalDepth: -1, MaxFunctionCalls: -1},
			"alice", "dataX", "read")
		assertBudgetExceeded(t, err, BudgetStageRole)
	}
	got, err = e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: 2, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"alice", "dataX", "read")
	if err != nil || got {
		t.Fatalf("fresh calls must independently succeed at the miss cost, got (%v,%v)", got, err)
	}
}

func newEvalEnforcer(t *testing.T, nested bool) *Enforcer {
	t.Helper()
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj")
	if nested {
		m.AddDef("p", "p", "sub_rule, obj_rule, act_rule")
		m.AddDef("e", "e", "some(where (p.eft == allow))")
		m.AddDef("m", "m", "eval(p.sub_rule)")
	} else {
		m.AddDef("p", "p", "sub_rule, obj_rule")
		m.AddDef("e", "e", "some(where (p.eft == allow))")
		m.AddDef("m", "m", "eval(p.sub_rule) && eval(p.obj_rule)")
	}
	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	if nested {
		// eval#1 -> eval#2 -> eval#3 (leaf).
		if _, err = e.AddPolicy("eval(p.obj_rule)", "eval(p.act_rule)", "r.sub == 'alice'"); err != nil {
			t.Fatalf("AddPolicy: %v", err)
		}
	} else {
		if _, err = e.AddPolicy("r.sub == 'alice'", "r.obj == 'data1'"); err != nil {
			t.Fatalf("AddPolicy: %v", err)
		}
	}
	return e
}

// TestEnforceBoundedEvalNesting covers depth limits, sibling frame reset and
// nested eval chains.
func TestEnforceBoundedEvalNesting(t *testing.T) {
	e := newEvalEnforcer(t, false)

	_, err := e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: -1, MaxEvalDepth: 0, MaxFunctionCalls: -1},
		"alice", "data1")
	budgetErr := assertBudgetExceeded(t, err, BudgetStageEval)
	if budgetErr.Used != 1 {
		t.Fatalf("zero eval depth must fail on the first frame: %+v", budgetErr)
	}

	// Two sibling eval() calls each occupy depth 1 and succeed.
	got, err := e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: -1, MaxEvalDepth: 1, MaxFunctionCalls: -1},
		"alice", "data1")
	if err != nil || !got {
		t.Fatalf("sibling eval frames must reset depth, got (%v,%v)", got, err)
	}
	got, err = e.EnforceBounded(context.Background(), unlimitedBudget(), "bob", "data1")
	if err != nil || got {
		t.Fatalf("non-matching eval request should be false, got (%v,%v)", got, err)
	}

	nested := newEvalEnforcer(t, true)
	_, err = nested.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: -1, MaxEvalDepth: 2, MaxFunctionCalls: -1},
		"alice", "x")
	budgetErr = assertBudgetExceeded(t, err, BudgetStageEval)
	if budgetErr.Used != 3 || !strings.Contains(budgetErr.Path, "eval(") {
		t.Fatalf("nested eval chain should fail entering depth 3: %+v", budgetErr)
	}
	got, err = nested.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: -1, MaxEvalDepth: 3, MaxFunctionCalls: -1},
		"alice", "x")
	if err != nil || !got {
		t.Fatalf("depth 3 budget should allow the chain, got (%v,%v)", got, err)
	}
}

// TestEnforceBoundedDenyOverrideNoEarlyPublish ensures an allow matched before
// a necessary deny rule is never published when the budget runs out.
func TestEnforceBoundedDenyOverrideNoEarlyPublish(t *testing.T) {
	e, err := NewEnforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv")
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	want, wantErr := e.Enforce("alice", "data2", "write")
	if want || wantErr != nil {
		t.Fatalf("fixture should deny, got (%v,%v)", want, wantErr)
	}

	// 4 rules evaluated, the explicit deny rule at p[4] never runs: the partial
	// allow from p[3] must not be returned as a decision.
	got, err := e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: 4, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"alice", "data2", "write")
	budgetErr := assertBudgetExceeded(t, err, BudgetStagePolicy)
	if budgetErr.Path != "p[4]" {
		t.Fatalf("expected to stop before the deny rule, got %+v", budgetErr)
	}
	if got {
		t.Fatal("incomplete evaluation must never publish an allow")
	}

	// Full budget reproduces the deny decision exactly.
	got, err = e.EnforceBounded(context.Background(), unlimitedBudget(), "alice", "data2", "write")
	if err != nil || got != false {
		t.Fatalf("full budget should reproduce deny, got (%v,%v)", got, err)
	}
	// A genuinely allowed request stays allowed under bounded enforcement.
	got, err = e.EnforceBounded(context.Background(), unlimitedBudget(), "alice", "data2", "read")
	if err != nil || !got {
		t.Fatalf("allow request mismatch, got (%v,%v)", got, err)
	}
}

// TestEnforceBoundedConcurrent verifies per-call budget isolation under heavy
// concurrency (run with -race); no call may consume another call's quota.
func TestEnforceBoundedConcurrent(t *testing.T) {
	e, _ := newCounterEnforcer(t, 30)
	rbacE := newRBACEnforcer(t)
	_, _ = rbacE.AddGroupingPolicy("alice", "admin")
	_, _ = rbacE.AddPolicy("admin", "data", "read")

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				_, err := e.EnforceBounded(context.Background(),
					Budget{MaxPolicies: 5, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: -1},
					"alice", "data", "read")
				budgetErr := assertBudgetExceeded(t, err, BudgetStagePolicy)
				if budgetErr.Used != 6 {
					t.Errorf("quota leaked across calls: %+v", budgetErr)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				got, err := rbacE.EnforceBounded(context.Background(), unlimitedBudget(), "alice", "data", "read")
				if err != nil || !got {
					t.Errorf("unlimited concurrent call failed: (%v,%v)", got, err)
				}
			}
		}()
	}
	wg.Wait()
}

// TestEnforceBoundedCacheZeroPublication proves bounded enforcement neither
// reads nor writes the decision cache and never populates the matcher cache.
func TestEnforceBoundedCacheZeroPublication(t *testing.T) {
	ce, err := NewCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewCachedEnforcer: %v", err)
	}

	countMatcher := func() int {
		n := 0
		ce.matcherMap.Range(func(_, _ interface{}) bool { n++; return true })
		return n
	}
	cacheLen := func() int {
		dc, ok := ce.cache.(*persistcache.DefaultCache)
		if !ok {
			t.Fatalf("unexpected cache type %T", ce.cache)
		}
		return len(*dc)
	}

	if cacheLen() != 0 || countMatcher() != 0 {
		t.Fatal("fresh enforcer should hold no cached decisions/matchers")
	}

	// Failing bounded calls publish nothing.
	for i := 0; i < 3; i++ {
		_, err = ce.EnforceBounded(context.Background(),
			Budget{MaxPolicies: 0, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: -1},
			"alice", "data1", "read")
		assertBudgetExceeded(t, err, BudgetStagePolicy)
	}
	if cacheLen() != 0 || countMatcher() != 0 {
		t.Fatal("bounded failures must not populate the decision or matcher cache")
	}

	// Ordinary enforcement populates both caches once.
	got, err := ce.Enforce("alice", "data1", "read")
	if err != nil || !got {
		t.Fatalf("ordinary enforce failed: (%v,%v)", got, err)
	}
	if cacheLen() != 1 || countMatcher() == 0 {
		t.Fatalf("ordinary enforce should warm caches, got decision=%d matcher=%d", cacheLen(), countMatcher())
	}
	matcherBefore := countMatcher()

	// Bounded calls neither add decision entries nor touch matcher compilation.
	_, err = ce.EnforceBounded(context.Background(),
		Budget{MaxPolicies: 0, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"alice", "data1", "read")
	assertBudgetExceeded(t, err, BudgetStagePolicy)
	got, err = ce.EnforceBounded(context.Background(), unlimitedBudget(), "alice", "data1", "read")
	if err != nil || !got {
		t.Fatalf("successful bounded call mismatch: (%v,%v)", got, err)
	}
	if cacheLen() != 1 || countMatcher() != matcherBefore {
		t.Fatalf("bounded calls changed caches: decision=%d matcher=%d", cacheLen(), countMatcher())
	}
}

// TestEnforceBoundedEquivalence runs multiple shipped models and asserts that
// with an unlimited budget the decision and the original error are identical
// to ordinary Enforce.
func TestEnforceBoundedEquivalence(t *testing.T) {
	cases := []struct {
		model  string
		policy string
		rval   []interface{}
	}{
		{"examples/basic_model.conf", "examples/basic_policy.csv", []interface{}{"alice", "data1", "read"}},
		{"examples/basic_model.conf", "examples/basic_policy.csv", []interface{}{"alice", "data1", "write"}},
		{"examples/basic_model.conf", "examples/basic_policy.csv", []interface{}{"alice", "data2", "read"}},
		{"examples/rbac_model.conf", "examples/rbac_policy.csv", []interface{}{"alice", "data2", "write"}},
		{"examples/rbac_model.conf", "examples/rbac_policy.csv", []interface{}{"bob", "data2", "write"}},
		{"examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv", []interface{}{"alice", "data2", "write"}},
		{"examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv", []interface{}{"alice", "data2", "read"}},
		{"examples/eval_operator_model.conf", "examples/eval_operator_policy.csv", []interface{}{"admin", "users", "write"}},
		{"examples/eval_operator_model.conf", "examples/eval_operator_policy.csv", []interface{}{"bob", "users", "write"}},
		{"examples/keymatch_model.conf", "examples/keymatch_policy.csv", []interface{}{"alice", "/alice_data/resource1", "GET"}},
		{"examples/keymatch_model.conf", "examples/keymatch_policy.csv", []interface{}{"bob", "/alice_data/resource1", "GET"}},
		{"examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv", []interface{}{"alice", "domain1", "data1", "read"}},
	}
	for _, tc := range cases {
		e, err := NewEnforcer(tc.model, tc.policy)
		if err != nil {
			t.Fatalf("NewEnforcer(%s): %v", tc.model, err)
		}
		want, wantErr := e.Enforce(tc.rval...)
		got, gotErr := e.EnforceBounded(context.Background(), unlimitedBudget(), tc.rval...)
		if got != want || fmt.Sprint(wantErr) != fmt.Sprint(gotErr) {
			t.Fatalf("%s %v: bounded (%v,%v) != enforce (%v,%v)", tc.model, tc.rval, got, gotErr, want, wantErr)
		}
	}

	// Original errors must be reproduced verbatim.
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	want, wantErr := e.Enforce("wrong", "wrong")
	got, gotErr := e.EnforceBounded(context.Background(), unlimitedBudget(), "wrong", "wrong")
	if got != want || fmt.Sprint(wantErr) != fmt.Sprint(gotErr) {
		t.Fatalf("request-size error mismatch: (%v,%v) vs (%v,%v)", got, gotErr, want, wantErr)
	}

	e2, _ := NewEnforcer("examples/abac_rule_model.conf")
	want, wantErr = e2.Enforce("wang", "wang", "wang")
	got, gotErr = e2.EnforceBounded(context.Background(), unlimitedBudget(), "wang", "wang", "wang")
	if got != want || fmt.Sprint(wantErr) != fmt.Sprint(gotErr) {
		t.Fatalf("abac rule error mismatch: (%v,%v) vs (%v,%v)", got, gotErr, want, wantErr)
	}
}

// TestEnforceBoundedContextCancellation covers pre-canceled contexts,
// cancellation at a policy checkpoint and propagation from a blocking function.
func TestEnforceBoundedContextCancellation(t *testing.T) {
	e, _ := newCounterEnforcer(t, 20)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := e.EnforceBounded(ctx, unlimitedBudget(), "alice", "data", "read")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled context must return context.Canceled, got %v", err)
	}

	// Cancel between policy evaluations: the next checkpoint reports cancellation.
	ctx2, cancel2 := context.WithCancel(context.Background())
	var count int32
	m2 := model.NewModel()
	m2.AddDef("r", "r", "sub, obj, act")
	m2.AddDef("p", "p", "sub, obj, act")
	m2.AddDef("e", "e", "some(where (p.eft == allow))")
	m2.AddDef("m", "m", "cancelCall(r.sub) && r.sub == p.sub")
	e2, err := NewEnforcer(m2)
	if err != nil {
		t.Fatal(err)
	}
	e2.AddFunction("cancelCall", func(args ...interface{}) (interface{}, error) {
		if atomic.AddInt32(&count, 1) == 3 {
			cancel2()
		}
		return true, nil
	})
	for i := 0; i < 10; i++ {
		_, _ = e2.AddPolicy(fmt.Sprintf("u%02d", i), "o", "a")
	}
	_, err = e2.EnforceBounded(ctx2, unlimitedBudget(), "alice", "o", "a")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-loop cancellation must propagate, got %v", err)
	}
	if !strings.Contains(err.Error(), BudgetStagePolicy) {
		t.Fatalf("cancellation error should carry the policy stage, got %v", err)
	}

	// A user function blocking internally is not preempted but its returned
	// context error propagates; only the pre-call check is guaranteed.
	ctx3, cancel3 := context.WithCancel(context.Background())
	m3 := model.NewModel()
	m3.AddDef("r", "r", "sub")
	m3.AddDef("p", "p", "sub")
	m3.AddDef("e", "e", "some(where (p.eft == allow))")
	m3.AddDef("m", "m", "staller() && r.sub == p.sub")
	e3, err := NewEnforcer(m3)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = e3.AddPolicy("alice")
	e3.AddFunction("staller", func(args ...interface{}) (interface{}, error) {
		<-ctx3.Done()
		return nil, ctx3.Err()
	})
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel3()
	}()
	_, err = e3.EnforceBounded(ctx3, unlimitedBudget(), "alice")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("blocking function should propagate cancellation, got %v", err)
	}
}

// stubUnboundedRoleManager is a RoleManager without the bounded protocol.
type stubUnboundedRoleManager struct{}

func (s *stubUnboundedRoleManager) Clear() error                                  { return nil }
func (s *stubUnboundedRoleManager) AddLink(_ string, _ string, _ ...string) error { return nil }
func (s *stubUnboundedRoleManager) BuildRelationship(_ string, _ string, _ ...string) error {
	return nil
}
func (s *stubUnboundedRoleManager) DeleteLink(_ string, _ string, _ ...string) error { return nil }
func (s *stubUnboundedRoleManager) HasLink(_ string, _ string, _ ...string) (bool, error) {
	return false, nil
}
func (s *stubUnboundedRoleManager) GetRoles(_ string, _ ...string) ([]string, error) {
	return nil, nil
}
func (s *stubUnboundedRoleManager) GetUsers(_ string, _ ...string) ([]string, error) {
	return nil, nil
}
func (s *stubUnboundedRoleManager) GetImplicitRoles(_ string, _ ...string) ([]string, error) {
	return nil, nil
}
func (s *stubUnboundedRoleManager) GetImplicitUsers(_ string, _ ...string) ([]string, error) {
	return nil, nil
}
func (s *stubUnboundedRoleManager) GetDomains(_ string) ([]string, error)               { return nil, nil }
func (s *stubUnboundedRoleManager) GetAllDomains() ([]string, error)                    { return nil, nil }
func (s *stubUnboundedRoleManager) PrintRoles() error                                   { return nil }
func (s *stubUnboundedRoleManager) Match(_ string, _ string) bool                       { return false }
func (s *stubUnboundedRoleManager) AddMatchingFunc(_ string, _ rbac.MatchingFunc)       {}
func (s *stubUnboundedRoleManager) AddDomainMatchingFunc(_ string, _ rbac.MatchingFunc) {}
func (s *stubUnboundedRoleManager) DeleteDomain(_ string) error                         { return nil }

// TestEnforceBoundedRejectsUnknownRoleManager pins the explicit protocol
// requirement: unknown role managers reject bounded mode up-front.
func TestEnforceBoundedRejectsUnknownRoleManager(t *testing.T) {
	e := newRBACEnforcer(t)
	stub := &stubUnboundedRoleManager{}
	// The matcher closure and the bounded preflight both read assertion.RM.
	e.SetRoleManager(stub)
	e.model["g"]["g"].RM = stub
	_, _ = e.AddPolicy("admin", "data", "read")

	_, err := e.EnforceBounded(context.Background(), unlimitedBudget(), "alice", "data", "read")
	if !errors.Is(err, ErrBoundedModeUnsupported) {
		t.Fatalf("expected ErrBoundedModeUnsupported, got %v", err)
	}

	// Ordinary enforcement keeps working with the custom manager.
	got, err := e.Enforce("alice", "data", "read")
	if err != nil || got {
		t.Fatalf("ordinary enforce should stay compatible, got (%v,%v)", got, err)
	}
}

// TestEnforceBoundedFailedAttemptAndNoMutation checks failed-attempt billing
// and guarantees bounded errors never mutate policy, role links or registrations.
func TestEnforceBoundedFailedAttemptAndNoMutation(t *testing.T) {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "failFn() && r.sub == p.sub && g(r.sub, p.sub)")
	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = e.AddPolicy("alice", "data", "read")
	_, _ = e.AddGroupingPolicy("alice", "admin")

	var executions int32
	e.AddFunction("failFn", func(args ...interface{}) (interface{}, error) {
		atomic.AddInt32(&executions, 1)
		return nil, errors.New("boom")
	})

	// Zero function quota: pre-call rejection means the function never runs.
	_, err = e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: 0},
		"alice", "data", "read")
	assertBudgetExceeded(t, err, BudgetStageFunction)
	if atomic.LoadInt32(&executions) != 0 {
		t.Fatal("pre-call check must prevent execution of the user function")
	}

	// One unit: the function runs, fails and the attempt is still consumed; the
	// caller receives the function's own error, not a budget error.
	_, err = e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: 1},
		"alice", "data", "read")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected the function error to propagate, got %v", err)
	}
	if atomic.LoadInt32(&executions) != 1 {
		t.Fatalf("failed attempt should execute exactly once, got %d", executions)
	}

	// Snapshot state, run failing/canceled bounded calls, verify no mutation.
	policiesBefore, _ := e.GetPolicy()
	linksBefore, _ := e.GetGroupingPolicy()
	_, _ = e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: 0, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"alice", "data", "read")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = e.EnforceBounded(ctx, unlimitedBudget(), "alice", "data", "read")

	policiesAfter, _ := e.GetPolicy()
	linksAfter, _ := e.GetGroupingPolicy()
	if fmt.Sprint(policiesBefore) != fmt.Sprint(policiesAfter) ||
		fmt.Sprint(linksBefore) != fmt.Sprint(linksAfter) {
		t.Fatal("bounded errors/cancellation must not modify policy or role links")
	}
	link, linkErr := e.GetRoleManager().HasLink("alice", "admin")
	if linkErr != nil || !link {
		t.Fatalf("role link changed after bounded failure: %v %v", link, linkErr)
	}
	// The registered function remains available to ordinary enforcement.
	if _, err = e.Enforce("alice", "data", "read"); err == nil ||
		!strings.Contains(err.Error(), "boom") {
		t.Fatalf("function registration changed, expected boom error, got %v", err)
	}
}

// TestEnforceBoundedNamedContextSharedBudget verifies that one budget governs
// whichever named request/policy/matcher section the call selects; no quota is
// re-allocated per named section.
func TestEnforceBoundedNamedContextSharedBudget(t *testing.T) {
	e, err := NewEnforcer("examples/multiple_policy_definitions_model.conf",
		"examples/multiple_policy_definitions_policy.csv")
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	ctx2 := NewEnforceContext("2")
	ctx2.EType = "e"

	// Unlimited budget reproduces named-context decisions exactly.
	for age, want := range map[int]bool{30: true, 70: false} {
		got, err := e.EnforceBounded(context.Background(), unlimitedBudget(),
			ctx2, struct{ Age int }{Age: age}, "/data1", "read")
		if err != nil || got != want {
			t.Fatalf("age %d: bounded (%v,%v) != expected %v", age, got, err, want)
		}
	}

	// The named p2 section is evaluated under the same budget state: a zero
	// policy quota fails on p2[0], not on some per-section replenished budget.
	_, err = e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: 0, MaxRoleNodes: -1, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		ctx2, struct{ Age int }{Age: 30}, "/data1", "read")
	budgetErr := assertBudgetExceeded(t, err, BudgetStagePolicy)
	if budgetErr.Path != "p2[0]" {
		t.Fatalf("named policy must share the call budget, got path %q", budgetErr.Path)
	}

	// m2 evaluates eval(p2.sub_rule): zero eval depth must be enforced too.
	_, err = e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: -1, MaxEvalDepth: 0, MaxFunctionCalls: -1},
		ctx2, struct{ Age int }{Age: 30}, "/data1", "read")
	assertBudgetExceeded(t, err, BudgetStageEval)

	// Default named section uses g(): zero role nodes stops its traversal.
	_, err = e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: -1, MaxRoleNodes: 0, MaxEvalDepth: -1, MaxFunctionCalls: -1},
		"alice", "data2", "read")
	assertBudgetExceeded(t, err, BudgetStageRole)
}

// TestEnforceBoundedDisabled mirrors Enforce on a disabled enforcer and skips
// role-manager preflight entirely.
func TestEnforceBoundedDisabled(t *testing.T) {
	e := newRBACEnforcer(t)
	stub := &stubUnboundedRoleManager{}
	e.SetRoleManager(stub)
	e.model["g"]["g"].RM = stub
	e.EnableEnforce(false)

	got, err := e.EnforceBounded(context.Background(),
		Budget{MaxPolicies: 0, MaxRoleNodes: 0, MaxEvalDepth: 0, MaxFunctionCalls: 0},
		"alice", "data", "read")
	if err != nil || !got {
		t.Fatalf("disabled enforcer must allow without budget checks, got (%v,%v)", got, err)
	}
}

// TestEnforceBoundedBudgetStateRules unit-tests the fixed accounting rules
// directly, including context precedence and eval frame bookkeeping.
func TestEnforceBoundedBudgetStateRules(t *testing.T) {
	// Dimensions are independent: exhausting the policy quota does not consume
	// function quota, and rejected charges never move the counter.
	st := newBudgetState(context.Background(), Budget{MaxPolicies: 1, MaxRoleNodes: 1, MaxEvalDepth: 1, MaxFunctionCalls: 1})
	if err := st.chargePolicy("p[0]"); err != nil {
		t.Fatal(err)
	}
	if err := st.chargePolicy("p[1]"); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("second policy charge must fail, got %v", err)
	}
	if err := st.chargeFunction("f"); err != nil {
		t.Fatalf("first function charge must succeed, got %v", err)
	}
	if err := st.chargeFunction("f"); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("second function charge must fail, got %v", err)
	}
	if u := st.usage(); u.Policies != 1 || u.FunctionCalls != 1 {
		t.Fatalf("failed charges must not increment counters: %+v", u)
	}

	// Context cancellation takes precedence over budget exhaustion.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st2 := newBudgetState(ctx, Budget{MaxPolicies: 0, MaxRoleNodes: 0, MaxEvalDepth: 0, MaxFunctionCalls: 0})
	if err := st2.chargeFunction("f"); !errors.Is(err, context.Canceled) {
		t.Fatalf("context must take precedence, got %v", err)
	}

	// Eval depth decrements on leave, so sibling frames reuse the depth.
	st3 := newBudgetState(context.Background(), Budget{MaxPolicies: -1, MaxRoleNodes: -1, MaxEvalDepth: 1, MaxFunctionCalls: -1})
	leave, err := st3.enterEval("a")
	if err != nil {
		t.Fatal(err)
	}
	leave()
	leave, err = st3.enterEval("b")
	if err != nil {
		t.Fatalf("depth must reset after leave: %v", err)
	}
	defer leave()
	if _, err = st3.enterEval("c"); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("nested frame must exceed depth 1, got %v", err)
	}
}

// Compile-time guard: bounded closures use the govaluate function type.
var _ govaluate.ExpressionFunction = wrapBoundedFunction("x", func(args ...interface{}) (interface{}, error) {
	return true, nil
}, newBudgetState(context.Background(), unlimitedBudget()))
