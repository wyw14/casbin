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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/casbin/casbin/v3/matcher/celmatcher"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/util"
	"github.com/google/cel-go/cel"
)

func newCELBackend(t *testing.T, opts ...celmatcher.Option) *celmatcher.Backend {
	t.Helper()
	backend, err := celmatcher.NewBackend(opts...)
	if err != nil {
		t.Fatalf("celmatcher.NewBackend: %v", err)
	}
	return backend
}

func newCELEnforcer(t *testing.T, modelPath, policyPath string, backend *celmatcher.Backend) *Enforcer {
	t.Helper()
	e, err := NewEnforcer(modelPath, policyPath)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	e.SetMatcherBackend(backend)
	return e
}

func assertCELCategory(t *testing.T, err error, category celmatcher.Category) {
	t.Helper()
	var celErr *celmatcher.Error
	if !errors.As(err, &celErr) {
		t.Fatalf("expected *celmatcher.Error, got %T: %v", err, err)
	}
	if celErr.Category != category {
		t.Fatalf("category = %s, want %s (err: %v)", celErr.Category, category, err)
	}
}

func TestCELBackendDefaultsToGovaluate(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if e.GetMatcherBackend() != nil {
		t.Fatal("default matcher backend must be nil (govaluate)")
	}
	testEnforce(t, e, "alice", "data1", "read", true)
}

func TestCELBackendAllowAndDeny(t *testing.T) {
	e := newCELEnforcer(t, "examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv", newCELBackend(t))

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestCELBackendPriority(t *testing.T) {
	e := newCELEnforcer(t, "examples/priority_model.conf", "examples/priority_policy.csv", newCELBackend(t))

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", true)
	testEnforce(t, e, "bob", "data2", "write", false)
}

func TestCELBackendNamedEnforceContext(t *testing.T) {
	e := newCELEnforcer(t,
		"examples/priority_model_enforce_context.conf",
		"examples/priority_policy_enforce_context.csv",
		newCELBackend(t))

	// Default r/p/m context.
	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)

	// Named r2/m2 context with two request tokens.
	enforceContext := EnforceContext{RType: "r2", PType: "p", EType: "e", MType: "m2"}
	got, err := e.Enforce(enforceContext, "alice", "data1")
	if err != nil {
		t.Fatalf("Enforce with EnforceContext: %v", err)
	}
	if !got {
		t.Fatal("named EnforceContext decision should be true")
	}
	got, err = e.Enforce(enforceContext, "nobody", "data1")
	if err != nil {
		t.Fatalf("Enforce with EnforceContext: %v", err)
	}
	if got {
		t.Fatal("named EnforceContext decision should be false")
	}
}

func TestCELBackendABACMissingField(t *testing.T) {
	e := newCELEnforcer(t, "examples/abac_model.conf", "", newCELBackend(t))

	// Struct requests follow the r.obj.Owner convention.
	data1 := newTestResource("data1", "alice")
	testEnforce(t, e, "alice", data1, "read", true)
	testEnforce(t, e, "bob", data1, "read", false)

	// A map missing the selected field produces a categorized runtime error,
	// never a cached false.
	_, err := e.Enforce("alice", map[string]interface{}{"Name": "data1"}, "read")
	assertCELCategory(t, err, celmatcher.RuntimeError)

	// Repeating the same request fails again: runtime errors are not cached as false.
	_, err = e.Enforce("alice", map[string]interface{}{"Name": "data1"}, "read")
	assertCELCategory(t, err, celmatcher.RuntimeError)

	// Supplying the field makes the same matcher succeed.
	ok, err := e.Enforce("alice", map[string]interface{}{"Name": "data1", "Owner": "alice"}, "read")
	if err != nil || !ok {
		t.Fatalf("enforce with complete map = (%v, %v), want true", ok, err)
	}
}

func TestCELBackendRBACWithDomains(t *testing.T) {
	e := newCELEnforcer(t, "examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv", newCELBackend(t))

	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", true)
	testDomainEnforce(t, e, "alice", "domain1", "data1", "write", true)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "read", false)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "read", true)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "write", true)
	testDomainEnforce(t, e, "bob", "domain1", "data1", "read", false)
}

func TestCELBackendConditionalRoles(t *testing.T) {
	e := newCELEnforcer(t,
		"examples/rbac_with_temporal_roles_model.conf",
		"examples/rbac_with_temporal_roles_policy.csv",
		newCELBackend(t))

	for _, role := range []string{"data2_admin", "data3_admin", "data4_admin", "data5_admin", "data6_admin", "data7_admin", "data8_admin"} {
		e.AddNamedLinkConditionFunc("g", "alice", role, util.TimeMatchFunc)
	}

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data3", "read", true)
	testEnforce(t, e, "alice", "data4", "read", true)
	testEnforce(t, e, "alice", "data6", "read", false)
	testEnforce(t, e, "alice", "data7", "read", true)
	testEnforce(t, e, "alice", "data8", "read", false)
}

func TestCELBackendTypedFunctionRegistrationUpdate(t *testing.T) {
	backend := newCELBackend(t)
	e := newCELEnforcer(t, "examples/keymatch_custom_model.conf", "examples/keymatch2_policy.csv", backend)

	if err := backend.RegisterFunction(celmatcher.TypedFunction{
		Name:       "keyMatchCustom",
		ArgTypes:   []*cel.Type{cel.StringType, cel.StringType},
		ReturnType: cel.BoolType,
		Binding:    func(key1, key2 string) bool { return CustomFunction(key1, key2) },
	}); err != nil {
		t.Fatalf("RegisterFunction: %v", err)
	}

	testEnforce(t, e, "alice", "/alice_data2/myid", "GET", false)
	testEnforce(t, e, "alice", "/alice_data2/myid/using/res_id", "GET", true)

	// Replace the implementation: the updated generation must take effect.
	if err := backend.RegisterFunction(celmatcher.TypedFunction{
		Name:       "keyMatchCustom",
		ArgTypes:   []*cel.Type{cel.StringType, cel.StringType},
		ReturnType: cel.BoolType,
		Binding:    func(key1, key2 string) bool { return false },
	}); err != nil {
		t.Fatalf("RegisterFunction update: %v", err)
	}
	testEnforce(t, e, "alice", "/alice_data2/myid/using/res_id", "GET", false)
}

func TestCELBackendLegacyUntypedFunctionRejected(t *testing.T) {
	backend := newCELBackend(t)
	e := newCELEnforcer(t, "examples/keymatch_custom_model.conf", "examples/keymatch2_policy.csv", backend)

	// Legacy govaluate-style registration must not be silently wired as a
	// dynamically typed CEL function.
	e.AddFunction("keyMatchCustom", CustomFunctionWrapper)

	_, err := e.Enforce("alice", "/alice_data2/myid/using/res_id", "GET")
	assertCELCategory(t, err, celmatcher.CompilationError)
	if !strings.Contains(err.Error(), "keyMatchCustom") {
		t.Fatalf("error should name the undeclared function: %v", err)
	}
}

func TestCELBackendMatcherTypeErrors(t *testing.T) {
	e := newCELEnforcer(t, "examples/basic_model.conf", "examples/basic_policy.csv", newCELBackend(t))

	cases := []struct {
		name     string
		matcher  string
		category celmatcher.Category
	}{
		{"unknown variable", `r_unknown == "x"`, celmatcher.CompilationError},
		{"non-bool result", `1 + 1`, celmatcher.CompilationError},
		{"undeclared function", `notDeclared(r_sub)`, celmatcher.CompilationError},
		{"dynamic eval", `eval(p_sub)`, celmatcher.ValidationError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.EnforceWithMatcher(tc.matcher, "alice", "data1", "read")
			assertCELCategory(t, err, tc.category)
		})
	}
}

func TestCELBackendRejectsEvalModel(t *testing.T) {
	// Dynamic eval() sub-expressions are not supported by the CEL backend and
	// are rejected explicitly instead of being rewritten.
	e := newCELEnforcer(t, "examples/eval_operator_model.conf", "examples/eval_operator_policy.csv", newCELBackend(t))
	_, err := e.Enforce("alice", "data1", "read")
	assertCELCategory(t, err, celmatcher.ValidationError)
}

func TestCELBackendRejectsGovaluateOnlySyntax(t *testing.T) {
	// The govaluate tuple-style "in" syntax is not auto-converted into CEL:
	// compilation fails rather than silently changing matcher semantics.
	e := newCELEnforcer(t,
		"examples/rbac_model_matcher_using_in_op.conf",
		"examples/rbac_policy.csv",
		newCELBackend(t))
	_, err := e.Enforce("alice", "data2", "read")
	assertCELCategory(t, err, celmatcher.CompilationError)
}

func TestCELBackendCustomMatcherSuccess(t *testing.T) {
	e := newCELEnforcer(t, "examples/basic_model.conf", "examples/basic_policy.csv", newCELBackend(t))

	got, err := e.EnforceWithMatcher(`r_sub == "alice" && r_act in ["read", "write"]`, "alice", "data1", "read")
	if err != nil {
		t.Fatalf("EnforceWithMatcher: %v", err)
	}
	if !got {
		t.Fatal("custom CEL matcher should match")
	}
	got, err = e.EnforceWithMatcher(`r_sub == "alice" && r_act in ["read", "write"]`, "alice", "data1", "delete")
	if err != nil {
		t.Fatalf("EnforceWithMatcher: %v", err)
	}
	if got {
		t.Fatal("custom CEL matcher should not match delete")
	}
}

func TestCELBackendCachedEnforcerDoesNotCacheRuntimeErrors(t *testing.T) {
	// All-string requests are decision-cacheable, so a runtime error here truly
	// exercises the cache path instead of bypassing it.
	backend := newCELBackend(t)
	if err := backend.RegisterFunction(celmatcher.TypedFunction{
		Name:       "failIf",
		ArgTypes:   []*cel.Type{cel.StringType},
		ReturnType: cel.BoolType,
		Binding: func(sub string) (bool, error) {
			if sub == "boom" {
				return false, errors.New("boom input rejected by custom function")
			}
			return true, nil
		},
	}); err != nil {
		t.Fatalf("RegisterFunction: %v", err)
	}

	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = failIf(r_sub) && r_obj == p_obj && r_act == p_act
`)
	if err != nil {
		t.Fatal(err)
	}
	ce, err := NewCachedEnforcer()
	if err != nil {
		t.Fatal(err)
	}
	if err = ce.InitWithModelAndAdapter(m, nil); err != nil {
		t.Fatal(err)
	}
	ce.SetMatcherBackend(backend)
	if _, err = ce.AddPolicy("ok", "data1", "read"); err != nil {
		t.Fatal(err)
	}

	// The runtime error must never be stored as a false decision.
	if _, err = ce.Enforce("boom", "data1", "read"); err == nil {
		t.Fatal("expected runtime error")
	} else {
		assertCELCategory(t, err, celmatcher.RuntimeError)
	}
	if _, err = ce.Enforce("boom", "data1", "read"); err == nil {
		t.Fatal("runtime error must not be cached as a false decision")
	} else {
		assertCELCategory(t, err, celmatcher.RuntimeError)
	}

	// Successful decisions are cached normally.
	got, err := ce.Enforce("ok", "data1", "read")
	if err != nil || !got {
		t.Fatalf("ok request = (%v, %v), want true", got, err)
	}
	got, err = ce.Enforce("ok", "data1", "read")
	if err != nil || !got {
		t.Fatalf("cached ok request = (%v, %v), want true", got, err)
	}
}

func TestCELBackendNativeListSyntax(t *testing.T) {
	modelText := `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.act in ["read", "write"]
`
	// The CEL backend compiles authored CEL syntax; the loader's govaluate
	// tuple rewriting only affects the govaluate matcher value, not RawValue.
	celModel, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	if strings.Contains(celModel["m"]["m"].RawValue, "(") || !strings.Contains(celModel["m"]["m"].RawValue, "[") {
		t.Fatalf("RawValue must keep CEL list literals, got %q", celModel["m"]["m"].RawValue)
	}

	celEnforcer, err := NewEnforcer()
	if err != nil {
		t.Fatal(err)
	}
	if err = celEnforcer.InitWithModelAndAdapter(celModel, nil); err != nil {
		t.Fatal(err)
	}
	celEnforcer.SetMatcherBackend(newCELBackend(t))
	if _, err = celEnforcer.AddPolicy("alice", "data1", "read"); err != nil {
		t.Fatal(err)
	}
	testEnforce(t, celEnforcer, "alice", "data1", "read", true)
	testEnforce(t, celEnforcer, "alice", "data1", "delete", false)

	// The same model text remains executable by the default govaluate backend.
	govModel, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatal(err)
	}
	govEnforcer, err := NewEnforcer()
	if err != nil {
		t.Fatal(err)
	}
	if err = govEnforcer.InitWithModelAndAdapter(govModel, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = govEnforcer.AddPolicy("alice", "data1", "read"); err != nil {
		t.Fatal(err)
	}
	testEnforce(t, govEnforcer, "alice", "data1", "read", true)
	testEnforce(t, govEnforcer, "alice", "data1", "delete", false)
}

func TestCELBackendRoleGraphUpdateWithoutRecompile(t *testing.T) {
	backend := newCELBackend(t)
	e := newCELEnforcer(t, "examples/rbac_model.conf", "examples/rbac_policy.csv", backend)

	testEnforce(t, e, "alice", "data1", "read", true)
	entriesBefore := backend.CachedEntries()
	if entriesBefore == 0 {
		t.Fatal("expected compiled matcher to be cached")
	}

	// Mutating the role graph changes decisions but must not require
	// recompiling the pure matcher: the g binding reads the role manager live.
	if _, err := e.AddGroupingPolicy("alice", "data2_admin"); err != nil {
		t.Fatal(err)
	}
	testEnforce(t, e, "alice", "data2", "read", true)
	if _, err := e.RemoveGroupingPolicy("alice", "data2_admin"); err != nil {
		t.Fatal(err)
	}
	testEnforce(t, e, "alice", "data2", "read", false)

	if entries := backend.CachedEntries(); entries != entriesBefore {
		t.Fatalf("cache entries changed from %d to %d after role graph updates", entriesBefore, entries)
	}
}

func TestCELBackendConcurrentEnforce(t *testing.T) {
	backend := newCELBackend(t)
	e := newCELEnforcer(t, "examples/rbac_model.conf", "examples/rbac_policy.csv", backend)

	// Concurrent reuse: many goroutines evaluate the same compiled programs
	// with distinct request data. Programs must not capture request state.
	const goroutines = 32
	const iterations = 50
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				got, err := e.Enforce("alice", "data1", "read")
				if err != nil {
					errCh <- err
					return
				}
				if !got {
					errCh <- errors.New("expected true")
					return
				}
				if _, err = e.Enforce("nobody", "data1", "read"); err != nil {
					errCh <- err
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent enforce failed: %v", err)
	}
}

func TestCELBackendSyncedEnforceWithMutation(t *testing.T) {
	// Policy mutation concurrent with enforcement requires the synchronized
	// enforcer, exactly as with the govaluate backend.
	se, err := NewSyncedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	se.SetMatcherBackend(newCELBackend(t))

	const goroutines = 16
	const iterations = 30
	var evaluators sync.WaitGroup
	errCh := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		evaluators.Add(1)
		go func() {
			defer evaluators.Done()
			for j := 0; j < iterations; j++ {
				if _, err := se.Enforce("alice", "data1", "read"); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}

	stop := make(chan struct{})
	var mutator sync.WaitGroup
	mutator.Add(1)
	go func() {
		defer mutator.Done()
		for {
			_, _ = se.AddGroupingPolicy("concurrent_user", "data2_admin")
			_, _ = se.RemoveGroupingPolicy("concurrent_user", "data2_admin")
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()

	evaluators.Wait()
	close(stop)
	mutator.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("synced concurrent enforce failed: %v", err)
	}
}

func TestCELBackendCostLimit(t *testing.T) {
	backend := newCELBackend(t, celmatcher.WithCostLimit(1))
	e := newCELEnforcer(t, "examples/basic_model.conf", "examples/basic_policy.csv", backend)

	_, err := e.Enforce("alice", "data1", "read")
	assertCELCategory(t, err, celmatcher.RuntimeError)
	if !strings.Contains(err.Error(), "cost limit exceeded") {
		t.Fatalf("expected cost limit error, got: %v", err)
	}

	// The error is a runtime interruption, not a false decision: a backend
	// without the budget still evaluates the same request correctly.
	plain := newCELEnforcer(t, "examples/basic_model.conf", "examples/basic_policy.csv", newCELBackend(t))
	testEnforce(t, plain, "alice", "data1", "read", true)
}

// parityConformanceExclusions lists conformance cases whose matchers rely on
// govaluate-only dialect (dynamic eval or tuple-style in), which the CEL
// backend is intentionally not auto-compatible with.
var parityConformanceExclusions = []string{
	"eval_operator",
	"rbac_model_matcher_using_in_op",
}

func TestCELBackendGovaluateParity(t *testing.T) {
	files, err := filepath.Glob("conformance/cases/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		caseName := strings.TrimSuffix(filepath.Base(file), ".json")
		excluded := false
		for _, prefix := range parityConformanceExclusions {
			if strings.HasPrefix(caseName, prefix) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		t.Run(caseName, func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var c conformanceCase
			if err = json.Unmarshal(data, &c); err != nil {
				t.Fatal(err)
			}

			govEnforcer, err := NewEnforcer(
				filepath.Join("conformance/data", c.Model),
				filepath.Join("conformance/data", c.Policy))
			if err != nil {
				t.Fatal(err)
			}
			celEnforcer := newCELEnforcer(t,
				filepath.Join("conformance/data", c.Model),
				filepath.Join("conformance/data", c.Policy),
				newCELBackend(t))

			for _, tc := range c.Tests {
				rvals := make([]interface{}, len(tc.Request))
				for i, v := range tc.Request {
					rvals[i] = v
				}
				govResult, govErr := govEnforcer.Enforce(rvals...)
				celResult, celErr := celEnforcer.Enforce(rvals...)
				if govErr != nil {
					// Both backends should reject the same malformed inputs.
					if celErr == nil {
						t.Fatalf("%v: govaluate errored (%v) but CEL returned %v", tc.Request, govErr, celResult)
					}
					continue
				}
				if celErr != nil {
					t.Fatalf("%v: CEL error %v, govaluate result %v", tc.Request, celErr, govResult)
				}
				if govResult != celResult {
					t.Fatalf("%v: govaluate = %v, CEL = %v", tc.Request, govResult, celResult)
				}
			}
		})
	}
}
