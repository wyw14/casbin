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

package celmatcher

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/casbin/casbin/v3/matcher"
	"github.com/google/cel-go/cel"
)

func baseSpec(expression string) matcher.CompileSpec {
	return matcher.CompileSpec{
		Expression: expression,
		RTokens:    []string{"r_sub", "r_obj", "r_act"},
		PTokens:    []string{"p_sub", "p_obj", "p_act"},
	}
}

func TestCompileAndEvalBasic(t *testing.T) {
	backend, err := NewBackend()
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	if backend.Language() != matcher.LanguageCEL {
		t.Fatalf("language = %q, want %q", backend.Language(), matcher.LanguageCEL)
	}

	compiled, err := backend.Compile(baseSpec("r_sub == p_sub && r_act == p_act"))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	ok, err := compiled.Eval([]interface{}{"alice", "data1", "read"}, []string{"alice", "data1", "read"})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !ok {
		t.Fatal("expected matcher to be true")
	}

	ok, err = compiled.Eval([]interface{}{"alice", "data1", "read"}, []string{"bob", "data1", "read"})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if ok {
		t.Fatal("expected matcher to be false")
	}
}

func TestCompileRejections(t *testing.T) {
	backend, err := NewBackend()
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	cases := []struct {
		name       string
		expression string
		category   Category
	}{
		{"unknown variable", "r_unknown == 1", CompilationError},
		{"undeclared function", "unknownFunc(r_sub)", CompilationError},
		{"non-bool result", "1 + 1", CompilationError},
		{"string result", `p_sub + "x"`, CompilationError},
		{"dynamic eval", "eval(p_sub)", ValidationError},
		{"empty matcher", "   ", ValidationError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := backend.Compile(baseSpec(tc.expression))
			var celErr *Error
			if !errors.As(err, &celErr) {
				t.Fatalf("expected *celmatcher.Error, got %T: %v", err, err)
			}
			if celErr.Category != tc.category {
				t.Fatalf("category = %s, want %s (err: %v)", celErr.Category, tc.category, err)
			}
		})
	}
}

func TestRuntimeMissingMapField(t *testing.T) {
	backend, _ := NewBackend()
	compiled, err := backend.Compile(baseSpec(`r_obj.Owner == "alice"`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Map without the Owner field: CEL raises a runtime "no such key" error,
	// it is never silently treated as false.
	_, err = compiled.Eval(
		[]interface{}{"alice", map[string]interface{}{"Name": "data1"}, "read"},
		nil,
	)
	var celErr *Error
	if !errors.As(err, &celErr) || celErr.Category != RuntimeError {
		t.Fatalf("expected Runtime error, got %T: %v", err, err)
	}

	// Same expression succeeds once the field exists.
	ok, err := compiled.Eval(
		[]interface{}{"alice", map[string]interface{}{"Name": "data1", "Owner": "alice"}, "read"},
		nil,
	)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !ok {
		t.Fatal("expected true when field exists")
	}
}

func TestABACScalarListMapAndStruct(t *testing.T) {
	backend, _ := NewBackend()
	compiled, err := backend.Compile(baseSpec(`"moderator" in r_obj.Roles && r_obj.Enabled == true && r_obj.Age >= 21`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	mapRequest := map[string]interface{}{
		"Roles":   []interface{}{"user", "moderator"},
		"Enabled": true,
		"Age":     30,
	}
	ok, err := compiled.Eval([]interface{}{"x", mapRequest, "x"}, nil)
	if err != nil {
		t.Fatalf("map Eval: %v", err)
	}
	if !ok {
		t.Fatal("map request should match")
	}

	structRequest := struct {
		Roles   []interface{}
		Enabled bool
		Age     int
	}{
		Roles:   []interface{}{"user", "moderator"},
		Enabled: true,
		Age:     30,
	}
	ok, err = compiled.Eval([]interface{}{"x", structRequest, "x"}, nil)
	if err != nil {
		t.Fatalf("struct Eval: %v", err)
	}
	if !ok {
		t.Fatal("struct request should match after normalization")
	}
}

func TestRoleFunctionArityAndDomain(t *testing.T) {
	role := matcher.RoleFunction{
		Name:  "g",
		Arity: 3,
		Binding: func(args ...string) (bool, error) {
			if len(args) == 2 {
				return args[0] == "alice" && args[1] == "admin", nil
			}
			return args[0] == "alice" && args[1] == "admin" && args[2] == "domain1", nil
		},
	}
	backend, _ := NewBackend()

	twoArg, err := backend.Compile(matcher.CompileSpec{
		Expression: "g(r_sub, p_sub)",
		RTokens:    []string{"r_sub", "r_dom"},
		PTokens:    []string{"p_sub"},
		Roles:      []matcher.RoleFunction{role},
	})
	if err != nil {
		t.Fatalf("Compile 2-arg: %v", err)
	}
	ok, err := twoArg.Eval([]interface{}{"alice", "domain1"}, []string{"admin"})
	if err != nil || !ok {
		t.Fatalf("2-arg g = (%v, %v), want true", ok, err)
	}

	threeArg, err := backend.Compile(matcher.CompileSpec{
		Expression: "g(r_sub, p_sub, r_dom)",
		RTokens:    []string{"r_sub", "r_dom"},
		PTokens:    []string{"p_sub"},
		Roles:      []matcher.RoleFunction{role},
	})
	if err != nil {
		t.Fatalf("Compile 3-arg: %v", err)
	}
	ok, err = threeArg.Eval([]interface{}{"alice", "domain1"}, []string{"admin"})
	if err != nil || !ok {
		t.Fatalf("3-arg g = (%v, %v), want true", ok, err)
	}
	ok, err = threeArg.Eval([]interface{}{"alice", "domain2"}, []string{"admin"})
	if err != nil || ok {
		t.Fatalf("3-arg g wrong domain = (%v, %v), want false", ok, err)
	}

	// Unsupported arity is rejected at compile time, not dispatched dynamically.
	_, err = backend.Compile(matcher.CompileSpec{
		Expression: "g(r_sub, p_sub, r_dom, r_dom)",
		RTokens:    []string{"r_sub", "r_dom"},
		PTokens:    []string{"p_sub"},
		Roles:      []matcher.RoleFunction{role},
	})
	var celErr *Error
	if !errors.As(err, &celErr) || celErr.Category != CompilationError {
		t.Fatalf("expected Compilation error for 4-arg g, got %v", err)
	}
}

func TestTypedFunctionRegistrationAndUpdate(t *testing.T) {
	backend, _ := NewBackend()
	tf := TypedFunction{
		Name:       "startsWith",
		ArgTypes:   []*cel.Type{cel.StringType, cel.StringType},
		ReturnType: cel.BoolType,
		Binding:    func(a, b string) bool { return strings.HasPrefix(a, b) },
	}
	if err := backend.RegisterFunction(tf); err != nil {
		t.Fatalf("RegisterFunction: %v", err)
	}

	compiled, err := backend.Compile(baseSpec("startsWith(r_obj, p_obj)"))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ok, err := compiled.Eval([]interface{}{"alice", "/alice_data/x", "read"}, []string{"", "/alice_data", ""})
	if err != nil || !ok {
		t.Fatalf("custom fn = (%v, %v), want true", ok, err)
	}

	// Replace the implementation with the opposite behavior; the generation
	// bump must force recompilation on the next Compile call.
	genBefore := backend.Generation()
	if err := backend.RegisterFunction(TypedFunction{
		Name:       "startsWith",
		ArgTypes:   []*cel.Type{cel.StringType, cel.StringType},
		ReturnType: cel.BoolType,
		Binding:    func(a, b string) bool { return false },
	}); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if backend.Generation() != genBefore+1 {
		t.Fatalf("generation = %d, want %d", backend.Generation(), genBefore+1)
	}
	compiled2, err := backend.Compile(baseSpec("startsWith(r_obj, p_obj)"))
	if err != nil {
		t.Fatalf("Compile after update: %v", err)
	}
	ok, err = compiled2.Eval([]interface{}{"alice", "/alice_data/x", "read"}, []string{"", "/alice_data", ""})
	if err != nil || ok {
		t.Fatalf("updated custom fn = (%v, %v), want false", ok, err)
	}
}

func TestTypedFunctionRegistrationValidation(t *testing.T) {
	backend, _ := NewBackend()

	badCases := []TypedFunction{
		{Name: "f1", ArgTypes: []*cel.Type{cel.StringType, cel.StringType}, ReturnType: cel.BoolType, Binding: func(a string) bool { return true }},
		{Name: "f2", ArgTypes: []*cel.Type{cel.StringType}, ReturnType: cel.BoolType, Binding: "not a function"},
		{Name: "f3", ArgTypes: []*cel.Type{}, ReturnType: cel.BoolType, Binding: func() bool { return true }},
		{Name: "", ArgTypes: []*cel.Type{cel.StringType}, ReturnType: cel.BoolType, Binding: func(string) bool { return true }},
		{Name: "f4", ArgTypes: []*cel.Type{cel.StringType}, ReturnType: nil, Binding: func(string) bool { return true }},
		{Name: "f5", ArgTypes: []*cel.Type{cel.BoolType}, ReturnType: cel.BoolType, Binding: func(string) bool { return true }},
	}
	for i, tf := range badCases {
		if err := backend.RegisterFunction(tf); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		} else {
			var celErr *Error
			if !errors.As(err, &celErr) || celErr.Category != ValidationError {
				t.Fatalf("case %d: expected Validation error, got %v", i, err)
			}
		}
	}
}

func TestCompilationCacheIdentity(t *testing.T) {
	backend, _ := NewBackend()
	spec := baseSpec("r_sub == p_sub")

	first, err := backend.Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	second, err := backend.Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if first != second {
		t.Fatal("identical specs must reuse the cached program")
	}
	if backend.CachedEntries() != 1 {
		t.Fatalf("cache entries = %d, want 1", backend.CachedEntries())
	}

	// Different matcher text is a different identity.
	third, err := backend.Compile(baseSpec("r_act == p_act"))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if third == first {
		t.Fatal("different matcher text must not share a compiled object")
	}
	if backend.CachedEntries() != 2 {
		t.Fatalf("cache entries = %d, want 2", backend.CachedEntries())
	}

	// A second backend keeps an isolated cache even for identical text.
	otherBackend, _ := NewBackend()
	fourth, err := otherBackend.Compile(spec)
	if err != nil {
		t.Fatalf("Compile on other backend: %v", err)
	}
	if fourth == first {
		t.Fatal("backends must not share compiled objects for same-text matchers")
	}
	if otherBackend.CachedEntries() != 1 {
		t.Fatalf("other cache entries = %d, want 1", otherBackend.CachedEntries())
	}
}

func TestCostLimitInterruptsEvaluation(t *testing.T) {
	backend, err := NewBackend(WithCostLimit(1))
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	compiled, err := backend.Compile(baseSpec("r_sub == p_sub && r_act == p_act && r_obj == p_obj"))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	_, err = compiled.Eval([]interface{}{"a", "b", "c"}, []string{"a", "b", "c"})
	var celErr *Error
	if !errors.As(err, &celErr) || celErr.Category != RuntimeError {
		t.Fatalf("expected Runtime cost-limit error, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "cost limit exceeded") {
		t.Fatalf("error should mention cost limit: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	backend, _ := NewBackend()
	compiled, err := backend.Compile(baseSpec("r_sub == p_sub && r_act == p_act"))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ctxCompiled, ok := compiled.(matcher.ContextCompiled)
	if !ok {
		t.Fatalf("compiled matcher does not implement ContextCompiled")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ctxCompiled.EvalContext(ctx, []interface{}{"a", "b", "c"}, []string{"a", "b", "c"})
	var celErr *Error
	if !errors.As(err, &celErr) || celErr.Category != RuntimeError {
		t.Fatalf("expected Runtime cancellation error, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("error should mention cancellation: %v", err)
	}

	// The shared program remains usable with a live context afterwards.
	ok2, err := ctxCompiled.EvalContext(context.Background(), []interface{}{"a", "b", "c"}, []string{"a", "b", "c"})
	if err != nil || !ok2 {
		t.Fatalf("program not reusable after cancellation: (%v, %v)", ok2, err)
	}
}

func TestBuiltinFunctions(t *testing.T) {
	backend, _ := NewBackend()
	compiled, err := backend.Compile(baseSpec(`keyMatch(r_obj, p_obj) && ipMatch(r_sub, p_sub)`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ok, err := compiled.Eval(
		[]interface{}{"192.168.2.123", "/alice_data/resource1", "read"},
		[]string{"192.168.2.0/24", "/alice_data/*", "read"},
	)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !ok {
		t.Fatal("expected builtins to match")
	}
}

func TestEvalDoesNotCaptureRequestData(t *testing.T) {
	backend, _ := NewBackend()
	compiled, err := backend.Compile(baseSpec("r_sub == p_sub"))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// Reuse the same program concurrently with distinct request data.
	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func(i int) {
			sub := "user"
			want := i%2 == 0
			pSub := "other"
			if want {
				pSub = sub
			}
			got, err := compiled.Eval([]interface{}{sub, nil, nil}, []string{pSub, "", ""})
			if err != nil {
				done <- err
				return
			}
			if got != want {
				done <- context.Canceled
				return
			}
			done <- nil
		}(i)
	}
	for i := 0; i < 16; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent Eval: %v", err)
		}
	}
}
