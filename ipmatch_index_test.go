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
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/casbin/casbin/v3/model"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
	"github.com/casbin/govaluate"
)

// newIPMatchEnforcer builds an in-memory enforcer whose matcher is a positive
// conjunction of a counting gate, the built-in ipMatch and an equality check.
// The gate is the first conjunct, so every rule whose matcher is actually
// evaluated increments evalCount exactly once.
func newIPMatchEnforcer(t testing.TB, matcher, effect string, withEft bool, evalCount *int) *Enforcer {
	t.Helper()

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	if withEft {
		m.AddDef("p", "p", "sub, obj, act, eft")
	} else {
		m.AddDef("p", "p", "sub, obj, act")
	}
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", effect)
	m.AddDef("m", "m", matcher)

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	e.AddFunction("gate", func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return false, fmt.Errorf("gate: expected 2 arguments, got %d", len(args))
		}
		*evalCount++
		return args[0].(string) == args[1].(string), nil
	})
	return e
}

const ipMatchGateMatcher = "gate(r.act, p.act) && ipMatch(r.sub, p.sub) && r.obj == p.obj"

func ipMatchRules(t testing.TB, withEft bool, patterns [][2]string) [][]string {
	t.Helper()
	rules := make([][]string, 0, len(patterns))
	for i, pattern := range patterns {
		rule := []string{pattern[0], fmt.Sprintf("obj-%d", i), pattern[1]}
		if withEft {
			rule = append(rule, "allow")
		}
		rules = append(rules, rule)
	}
	return rules
}

// evalOrdinals decodes the unique "prefix-N" markers recorded by a counting
// function into the policy ordinals that were really evaluated.
func evalOrdinals(t testing.TB, evaluated map[string]bool) map[int]bool {
	t.Helper()
	ordinals := make(map[int]bool, len(evaluated))
	for obj := range evaluated {
		dash := strings.LastIndex(obj, "-")
		if dash < 0 {
			t.Fatalf("unexpected marker %q", obj)
		}
		var index int
		if _, err := fmt.Sscanf(obj[dash+1:], "%d", &index); err != nil {
			t.Fatal(err)
		}
		ordinals[index] = true
	}
	return ordinals
}

func TestIPMatchIndexAnalyzerMatrix(t *testing.T) {
	tests := []struct {
		name    string
		matcher string
		wantErr bool
	}{
		{name: "plain conjunction", matcher: "ipMatch(r.sub, p.sub) && r.obj == p.obj && r.act == p.act", wantErr: false},
		{name: "whole matcher is ipMatch", matcher: "ipMatch(r.sub, p.sub)", wantErr: false},
		{name: "parenthesized predicate", matcher: "(ipMatch(r.sub, p.sub)) && r.obj == p.obj", wantErr: false},
		{name: "double parentheses", matcher: "((ipMatch(r.sub, p.sub))) && r.obj == p.obj", wantErr: false},
		{name: "or in sibling term", matcher: "ipMatch(r.sub, p.sub) && (r.obj == p.obj || r.act == p.act)", wantErr: false},
		{name: "other function sibling", matcher: "ipMatch(r.sub, p.sub) && regexMatch(r.obj, p.obj)", wantErr: false},
		{name: "g function sibling", matcher: "g(r.sub, p.sub) && ipMatch(r.sub, p.sub) && r.act == p.act", wantErr: false},
		{name: "or around ipMatch left", matcher: "ipMatch(r.sub, p.sub) || r.act == p.act", wantErr: true},
		{name: "or around ipMatch right", matcher: "r.act == p.act || ipMatch(r.sub, p.sub)", wantErr: true},
		{name: "or in parenthesized ipMatch branch", matcher: "(ipMatch(r.sub, p.sub) || r.act == p.act) && r.obj == p.obj", wantErr: true},
		{name: "negated ipMatch", matcher: "!ipMatch(r.sub, p.sub) && r.obj == p.obj", wantErr: true},
		{name: "negated group containing ipMatch", matcher: "!(r.obj == p.obj && ipMatch(r.sub, p.sub))", wantErr: true},
		{name: "ipMatch in ternary branch", matcher: `r.act == "read" ? ipMatch(r.sub, p.sub) : false`, wantErr: true},
		{name: "ipMatch in ternary condition", matcher: "ipMatch(r.sub, p.sub) ? r.obj == p.obj : false", wantErr: true},
		{name: "ipMatch in coalesce", matcher: "ipMatch(r.sub, p.sub) ?? r.obj == p.obj", wantErr: true},
		{name: "ipMatch nested in function", matcher: "regexMatch(ipMatch(r.sub, p.sub), p.obj) && r.act == p.act", wantErr: true},
		{name: "ipMatch result compared", matcher: "ipMatch(r.sub, p.sub) == true && r.obj == p.obj", wantErr: true},
		{name: "reversed arguments", matcher: "ipMatch(p.sub, r.sub) && r.obj == p.obj", wantErr: true},
		{name: "literal request argument", matcher: `ipMatch("10.0.0.1", p.sub) && r.obj == p.obj`, wantErr: true},
		{name: "unknown request token", matcher: "ipMatch(r.missing, p.sub) && r.obj == p.obj", wantErr: true},
		{name: "unknown policy token", matcher: "ipMatch(r.sub, p.missing) && r.obj == p.obj", wantErr: true},
		{name: "three arguments", matcher: "ipMatch(r.sub, p.sub, r.obj) && r.act == p.act", wantErr: true},
		{name: "two ipMatch calls", matcher: "ipMatch(r.sub, p.sub) && ipMatch(r.obj, p.obj)", wantErr: true},
		{name: "eval in matcher", matcher: "ipMatch(r.sub, p.sub) && eval(p.act)", wantErr: true},
		{name: "no ipMatch", matcher: "r.sub == p.sub && r.obj == p.obj", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			count := 0
			e := newIPMatchEnforcer(t, test.matcher, "some(where (p.eft == allow))", false, &count)
			err := e.SetIPMatchIndex("p")
			if test.wantErr && err == nil {
				t.Fatalf("expected SetIPMatchIndex to reject matcher %q", test.matcher)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("expected SetIPMatchIndex to accept matcher %q, got %v", test.matcher, err)
			}
			if test.wantErr {
				if _, ok := e.policyIndexes.Load("p"); ok {
					t.Fatal("no index may be installed when analysis fails")
				}
				return
			}
			if _, err := e.AddPolicy("10.0.0.1", "obj-0", "read"); err != nil {
				t.Fatal(err)
			}
			if ok, err := e.Enforce("10.0.0.1", "obj-0", "read"); err != nil || !ok {
				t.Fatalf("accepted matcher must still enforce: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestIPMatchIndexAnalyzerRejectsUnknownFunctionIdentity(t *testing.T) {
	// When the function behind the ipMatch call site cannot be proven to be the
	// built-in (custom same-name function scenario), the analyzer treats the
	// call as an ordinary function and finds no indexable predicate.
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "ipMatch(r.sub, p.sub) && r.obj == p.obj")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	functions := e.fm.GetFunctions()
	expression, err := govaluate.NewEvaluableExpressionWithFunctions(e.model["m"]["m"].Value, functions)
	if err != nil {
		t.Fatal(err)
	}

	analyzer := &ipMatchAnalyzer{
		tokens:         expression.Tokens(),
		rTokenIndex:    tokenPositionMap(e.model["r"]["r"].Tokens),
		pTokenIndex:    tokenPositionMap(e.model["p"]["p"].Tokens),
		builtinIPMatch: 0, // intentionally impossible pointer
	}
	if _, _, err := analyzer.analyze(); err == nil {
		t.Fatal("expected fallback when ipMatch identity cannot be proven")
	}
}

// ipMatchPolicyFixture is the shared policy corpus: overlapping and nested
// CIDRs of both families, host routes, duplicate ranges, mapped v6 space and
// unparseable entries.
func ipMatchPolicyPatterns() [][2]string {
	return [][2]string{
		{"10.0.0.0/8", "read"},
		{"10.1.0.0/16", "read"},
		{"10.1.2.0/24", "read"},
		{"10.1.2.128/25", "read"},
		{"10.1.2.200", "read"},
		{"192.168.0.0/16", "read"},
		{"192.168.1.0/24", "read"},
		{"192.168.1.5", "read"},
		{"172.16.0.0/12", "read"},
		{"0.0.0.0/0", "read"},
		{"2001:db8::/32", "read"},
		{"2001:db8:1::/48", "read"},
		{"2001:db8:1:2::/64", "read"},
		{"2001:db8:1:2::1234", "read"},
		{"::/0", "read"},
		{"::ffff:0:0/96", "read"},
		{"::ffff:10.0.0.0/112", "read"},
		{"2001:dead::/32", "read"},
		{"fe80::1", "read"},
		{"not-an-ip", "read"},
		{"1.2.3.0/33", "read"},
		{"999.1.1.1", "read"},
		{"", "read"},
	}
}

func validIPMatchPatterns() [][2]string {
	all := ipMatchPolicyPatterns()
	valid := make([][2]string, 0, len(all))
	for _, pattern := range all {
		if _, _, err := net.ParseCIDR(pattern[0]); err == nil {
			valid = append(valid, pattern)
			continue
		}
		if net.ParseIP(pattern[0]) != nil {
			valid = append(valid, pattern)
		}
	}
	return valid
}

func randomIPMatchRequests(t *testing.T, n int) [][]interface{} {
	t.Helper()
	rng := rand.New(rand.NewSource(20261108))
	requests := make([][]interface{}, 0, n)
	objChoices := []string{"obj-0", "obj-4", "obj-10", "obj-13", "other-object", ""}
	actChoices := []string{"read", "write", "read", "read"}

	for i := 0; i < n; i++ {
		var sub string
		switch rng.Intn(8) {
		case 0:
			sub = fmt.Sprintf("10.1.2.%d", rng.Intn(256))
		case 1:
			sub = fmt.Sprintf("192.168.%d.%d", rng.Intn(4), rng.Intn(256))
		case 2:
			sub = fmt.Sprintf("172.%d.%d.%d", 16+rng.Intn(15), rng.Intn(256), rng.Intn(256))
		case 3:
			sub = fmt.Sprintf("8.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256))
		case 4:
			sub = fmt.Sprintf("2001:db8:%x::%x", rng.Intn(8), rng.Intn(65536))
		case 5:
			v4 := fmt.Sprintf("10.0.%d.%d", rng.Intn(256), rng.Intn(256))
			sub = "::ffff:" + v4
		case 6:
			sub = "not-an-ip"
		default:
			sub = "2001:dead:beef::1"
		}
		requests = append(requests, []interface{}{sub, objChoices[rng.Intn(len(objChoices))], actChoices[rng.Intn(len(actChoices))]})
	}
	return requests
}

func assertEnforceParity(t *testing.T, indexed, plain *Enforcer, requests [][]interface{}) {
	t.Helper()
	for i, request := range requests {
		indexedOK, indexedExplain, indexedErr := indexed.EnforceEx(request...)
		plainOK, plainExplain, plainErr := plain.EnforceEx(request...)

		if (indexedErr == nil) != (plainErr == nil) {
			t.Fatalf("request %d %v: error mismatch indexed=%v plain=%v", i, request, indexedErr, plainErr)
		}
		if indexedErr != nil && indexedErr.Error() != plainErr.Error() {
			t.Fatalf("request %d %v: error text mismatch\nindexed: %v\nplain:   %v", i, request, indexedErr, plainErr)
		}
		if indexedOK != plainOK {
			t.Fatalf("request %d %v: decision mismatch indexed=%v plain=%v", i, request, indexedOK, plainOK)
		}
		if !reflect.DeepEqual(indexedExplain, plainExplain) {
			t.Fatalf("request %d %v: explain mismatch indexed=%v plain=%v", i, request, indexedExplain, plainExplain)
		}
	}
}

func TestIPMatchIndexRandomParity(t *testing.T) {
	patterns := ipMatchPolicyPatterns()
	requests := randomIPMatchRequests(t, 400)

	for _, effect := range []string{
		"some(where (p.eft == allow))",
		"some(where (p.eft == allow)) && !some(where (p.eft == deny))",
	} {
		t.Run(effect, func(t *testing.T) {
			withEft := strings.Contains(effect, "p_eft")
			var indexedCount, plainCount int
			indexed := newIPMatchEnforcer(t, ipMatchGateMatcher, effect, withEft, &indexedCount)
			plain := newIPMatchEnforcer(t, ipMatchGateMatcher, effect, withEft, &plainCount)

			rules := ipMatchRules(t, withEft, patterns)
			if _, err := indexed.AddPolicies(rules); err != nil {
				t.Fatal(err)
			}
			if _, err := plain.AddPolicies(rules); err != nil {
				t.Fatal(err)
			}
			if err := indexed.SetIPMatchIndex("p"); err != nil {
				t.Fatal(err)
			}

			assertEnforceParity(t, indexed, plain, requests)
		})
	}
}

func TestIPMatchIndexPriorityParity(t *testing.T) {
	effect := "priority(p_eft) || deny"
	patterns := ipMatchPolicyPatterns()
	requests := randomIPMatchRequests(t, 200)

	var indexedCount, plainCount int
	indexed := newIPMatchEnforcer(t, ipMatchGateMatcher, effect, true, &indexedCount)
	plain := newIPMatchEnforcer(t, ipMatchGateMatcher, effect, true, &plainCount)

	rules := ipMatchRules(t, true, patterns)
	// Interleave deny rules at overlapping CIDRs; the priority effector relies
	// on policy ordinal, which the index must never reorder.
	denyRules := [][]string{
		{"10.1.2.0/24", "obj-2", "read", "deny"},
		{"2001:db8::/32", "obj-10", "read", "deny"},
		{"0.0.0.0/0", "obj-9", "read", "deny"},
		{"not-an-ip", "obj-18", "read", "deny"},
	}
	rules = append(rules, denyRules...)
	if _, err := indexed.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if err := indexed.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	assertEnforceParity(t, indexed, plain, requests)
}

func TestIPMatchIndexNarrowsResidualEvaluations(t *testing.T) {
	patterns := validIPMatchPatterns()
	rules := ipMatchRules(t, true, patterns)
	// A deny rule forces the allow-and-deny effector to scan every rule, so
	// short-circuit breaks do not obscure the candidate counts.
	rules = append(rules, []string{"203.0.113.0/24", "obj-deny", "read", "deny"})

	var indexedCount, plainCount int
	indexed := newIPMatchEnforcer(t, ipMatchGateMatcher,
		"some(where (p.eft == allow)) && !some(where (p.eft == deny))", true, &indexedCount)
	plain := newIPMatchEnforcer(t, ipMatchGateMatcher,
		"some(where (p.eft == allow)) && !some(where (p.eft == deny))", true, &plainCount)
	if _, err := indexed.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if err := indexed.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	request := []interface{}{"10.1.2.200", "no-such-object", "read"}

	plainCount = 0
	if _, err := plain.Enforce(request...); err != nil {
		t.Fatal(err)
	}
	if plainCount != len(rules) {
		t.Fatalf("plain enforcer evaluated %d rules, want all %d", plainCount, len(rules))
	}

	indexedCount = 0
	if _, err := indexed.Enforce(request...); err != nil {
		t.Fatal(err)
	}

	// Independent oracle: every CIDR/host containing the request, plus every
	// unparseable policy entry that must stay a universal error candidate.
	requestIP := net.ParseIP("10.1.2.200")
	expected := map[int]bool{}
	for ordinal, rule := range rules {
		pattern := rule[0]
		if _, cidr, err := net.ParseCIDR(pattern); err == nil {
			if cidr.Contains(requestIP) {
				expected[ordinal] = true
			}
			continue
		}
		if ip := net.ParseIP(pattern); ip != nil {
			if ip.Equal(requestIP) {
				expected[ordinal] = true
			}
			continue
		}
		expected[ordinal] = true
	}
	if indexedCount != len(expected) {
		t.Fatalf("indexed residual evaluations=%d, want %d oracle candidates", indexedCount, len(expected))
	}
	if indexedCount >= plainCount {
		t.Fatalf("index did not narrow candidates: indexed=%d plain=%d", indexedCount, plainCount)
	}
	t.Logf("policy=%d residual=%d reduction=%.1f%%", plainCount, indexedCount,
		100*(1-float64(indexedCount)/float64(plainCount)))
}

func TestIPMatchIndexCandidateOrdinals(t *testing.T) {
	// Verify exactly which ordinals survive, using unique per-rule obj markers.
	// A trailing unmatched deny rule keeps the allow-and-deny effector from
	// short-circuiting, so every candidate rule is really evaluated.
	recorded := map[string]bool{}
	var mu sync.Mutex
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act, eft")
	m.AddDef("e", "e", "some(where (p.eft == allow)) && !some(where (p.eft == deny))")
	m.AddDef("m", "m", "ipMatch(r.sub, p.sub) && recordGate(r.obj, p.obj)")
	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	e.AddFunction("recordGate", func(args ...interface{}) (interface{}, error) {
		mu.Lock()
		recorded[args[1].(string)] = true
		mu.Unlock()
		return true, nil
	})

	patterns := validIPMatchPatterns()
	rules := make([][]string, 0, len(patterns)+1)
	for i, pattern := range patterns {
		rules = append(rules, []string{pattern[0], fmt.Sprintf("mark-%d", i), "read", "allow"})
	}
	rules = append(rules, []string{"203.0.113.0/24", "mark-deny", "read", "deny"})
	if _, err := e.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if err := e.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	for _, requestIP := range []string{"10.1.2.200", "192.168.1.5", "8.8.8.8", "2001:db8:1:2::1234", "::ffff:10.1.2.200", "fe80::9"} {
		recorded = map[string]bool{}
		if _, err := e.Enforce(requestIP, "anything", "read"); err != nil {
			t.Fatalf("%s: %v", requestIP, err)
		}

		parsed := net.ParseIP(requestIP)
		want := map[int]bool{}
		for ordinal, rule := range rules {
			pattern := rule[0]
			if _, cidr, err := net.ParseCIDR(pattern); err == nil {
				if cidr.Contains(parsed) {
					want[ordinal] = true
				}
				continue
			}
			if ip := net.ParseIP(pattern); ip != nil {
				if ip.Equal(parsed) {
					want[ordinal] = true
				}
				continue
			}
			want[ordinal] = true
		}
		if got := evalOrdinals(t, recorded); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: candidate ordinals mismatch\ngot  %v\nwant %v", requestIP, sortedKeys(got), sortedKeys(want))
		}
	}
}

func sortedKeys(set map[int]bool) []int {
	keys := make([]int, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func TestIPMatchIndexInvalidRequestAndPolicyErrors(t *testing.T) {
	patterns := [][2]string{
		{"10.0.0.0/8", "read"},
		{"broken-policy-ip", "read"},
		{"192.168.0.0/16", "read"},
	}
	var indexedCount, plainCount int
	indexed := newIPMatchEnforcer(t, ipMatchGateMatcher, "some(where (p.eft == allow))", false, &indexedCount)
	plain := newIPMatchEnforcer(t, ipMatchGateMatcher, "some(where (p.eft == allow))", false, &plainCount)
	rules := ipMatchRules(t, false, patterns)
	if _, err := indexed.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if err := indexed.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	// Invalid request IP: the index falls back to the full scan so the exact
	// original ipMatch error is produced instead of a silent no-match.
	_, indexedErr := indexed.Enforce("not-an-ip", "obj-0", "read")
	_, plainErr := plain.Enforce("not-an-ip", "obj-0", "read")
	if indexedErr == nil || plainErr == nil {
		t.Fatal("expected ipMatch request errors on both enforcers")
	}
	if indexedErr.Error() != plainErr.Error() {
		t.Fatalf("request error mismatch: indexed=%v plain=%v", indexedErr, plainErr)
	}

	// Invalid policy IP remains a universal candidate: when reached, both
	// enforcers report the same policy-side error.
	_, indexedErr = indexed.Enforce("172.31.0.1", "obj-1", "read")
	_, plainErr = plain.Enforce("172.31.0.1", "obj-1", "read")
	if indexedErr == nil || plainErr == nil {
		t.Fatal("expected ipMatch policy errors on both enforcers")
	}
	if indexedErr.Error() != plainErr.Error() {
		t.Fatalf("policy error mismatch: indexed=%v plain=%v", indexedErr, plainErr)
	}

	// A request matching only the first rule and allowing there must not surface
	// the broken later rule, because the effector short-circuits first.
	indexedOK, indexedErr := indexed.Enforce("10.0.0.9", "obj-0", "read")
	plainOK, plainErr := plain.Enforce("10.0.0.9", "obj-0", "read")
	if indexedErr != nil || plainErr != nil || !indexedOK || !plainOK {
		t.Fatalf("short-circuit parity: indexed=(%v,%v) plain=(%v,%v)", indexedOK, indexedErr, plainOK, plainErr)
	}
}

func TestIPMatchIndexFallbackForCustomMatcherAndContext(t *testing.T) {
	var count int
	e := newIPMatchEnforcer(t, ipMatchGateMatcher, "some(where (p.eft == allow))", false, &count)
	rules := ipMatchRules(t, false, validIPMatchPatterns())
	if _, err := e.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if err := e.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	// Runtime custom matcher bypasses the proven index entirely. A request
	// that matches no rule forces a full scan, so the gate count can prove
	// the index was ignored.
	count = 0
	if ok, err := e.EnforceWithMatcher("gate(r.act, p.act) && ipMatch(r.sub, p.sub) && r.obj == p.obj",
		"10.1.2.200", "no-such-object", "read"); err != nil || ok {
		t.Fatalf("custom matcher enforce: ok=%v err=%v", ok, err)
	}
	if count != len(rules) {
		t.Fatalf("custom matcher must evaluate all rules, got %d of %d", count, len(rules))
	}

	// Default matcher still uses the index.
	count = 0
	if _, err := e.Enforce("10.1.2.200", "no-such-object", "read"); err != nil {
		t.Fatal(err)
	}
	if count == len(rules) {
		t.Fatal("default matcher should still narrow candidates")
	}
}

func TestIPMatchIndexRebuildsAfterPolicyChanges(t *testing.T) {
	var count int
	e := newIPMatchEnforcer(t, ipMatchGateMatcher, "some(where (p.eft == allow))", false, &count)
	if err := e.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	if _, err := e.AddPolicy("10.0.0.0/8", "obj-0", "read"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("192.168.0.0/16", "obj-1", "read"); err != nil {
		t.Fatal(err)
	}

	count = 0
	if ok, err := e.Enforce("10.0.0.1", "obj-0", "read"); err != nil || !ok {
		t.Fatalf("after add: ok=%v err=%v", ok, err)
	}
	if count != 1 {
		t.Fatalf("after add expected 1 residual evaluation, got %d", count)
	}

	if _, err := e.AddPolicy("10.0.0.0/16", "obj-2", "read"); err != nil {
		t.Fatal(err)
	}
	count = 0
	if _, err := e.Enforce("10.0.0.2", "obj-x", "read"); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("nested CIDR add expected 2 residuals, got %d", count)
	}

	if _, err := e.RemovePolicy("10.0.0.0/16", "obj-2", "read"); err != nil {
		t.Fatal(err)
	}
	count = 0
	if _, err := e.Enforce("10.0.0.2", "obj-x", "read"); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("after remove expected 1 residual, got %d", count)
	}

	if ok, err := e.UpdatePolicy(
		[]string{"192.168.0.0/16", "obj-1", "read"},
		[]string{"172.16.0.0/12", "obj-3", "read"}); err != nil || !ok {
		t.Fatalf("update failed: %v %v", ok, err)
	}
	count = 0
	if ok, err := e.Enforce("192.168.0.1", "obj-1", "read"); err != nil || ok {
		t.Fatalf("updated-away rule must no longer match: ok=%v err=%v", ok, err)
	}
	if ok, err := e.Enforce("172.16.0.1", "obj-3", "read"); err != nil || !ok {
		t.Fatalf("updated rule must match in new generation: ok=%v err=%v", ok, err)
	}

	e.ClearPolicy()
	count = 0
	if ok, err := e.Enforce("10.0.0.1", "obj-0", "read"); err != nil || ok {
		t.Fatalf("after clear: ok=%v err=%v", ok, err)
	}
	if _, err := e.AddPolicy("10.0.0.0/8", "obj-0", "read"); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.Enforce("10.0.0.1", "obj-0", "read"); err != nil || !ok {
		t.Fatalf("after clear+add: ok=%v err=%v", ok, err)
	}
}

func TestIPMatchIndexReloadsWithLoadPolicyAndModel(t *testing.T) {
	var count int
	e := newIPMatchEnforcer(t, ipMatchGateMatcher, "some(where (p.eft == allow))", false, &count)
	if _, err := e.AddPolicies(ipMatchRules(t, false, validIPMatchPatterns())); err != nil {
		t.Fatal(err)
	}
	if err := e.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	reference, err := NewEnforcer("examples/ipmatch_model.conf", "examples/ipmatch_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	requests := [][]interface{}{
		{"192.168.2.123", "data1", "read"},
		{"10.0.0.5", "data2", "write"},
		{"8.8.8.8", "data1", "read"},
		{"not-an-ip", "data1", "read"},
	}

	// LoadPolicy swaps in a fresh assertion generation; the old snapshot must
	// be dropped and rebuilt against the loaded rules.
	e.SetAdapter(fileadapter.NewAdapter("examples/ipmatch_policy.csv"))
	if err := e.LoadPolicy(); err != nil {
		t.Fatal(err)
	}
	assertEnforceParity(t, e, reference, requests)

	// LoadModel only works for a file-backed enforcer: it installs fresh
	// assertions and a fresh function map, so index generations must reset.
	fileEnforcer, err := NewEnforcer("examples/ipmatch_model.conf", "examples/ipmatch_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	if err := fileEnforcer.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}
	if ok, err := fileEnforcer.Enforce("192.168.2.123", "data1", "read"); err != nil || !ok {
		t.Fatalf("before LoadModel: ok=%v err=%v", ok, err)
	}
	if err := fileEnforcer.LoadModel(); err != nil {
		t.Fatal(err)
	}
	if err := fileEnforcer.LoadPolicy(); err != nil {
		t.Fatal(err)
	}
	assertEnforceParity(t, fileEnforcer, reference, requests)
}

func TestIPMatchIndexFunctionGeneration(t *testing.T) {
	var count int
	e := newIPMatchEnforcer(t, ipMatchGateMatcher, "some(where (p.eft == allow))", false, &count)
	if _, err := e.AddPolicies(ipMatchRules(t, false, validIPMatchPatterns())); err != nil {
		t.Fatal(err)
	}
	if err := e.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	before := e.getFunctionVersion()
	e.AddFunction("brandNewHelper", func(_ ...interface{}) (interface{}, error) {
		return true, nil
	})
	if e.getFunctionVersion() == before {
		t.Fatal("AddFunction must bump the function generation")
	}

	// Re-analysis succeeds because the built-in ipMatch is untouched; the
	// index must keep narrowing and returning identical decisions.
	count = 0
	if ok, err := e.Enforce("10.1.2.200", "no-such-object", "read"); err != nil || ok {
		t.Fatalf("after unrelated AddFunction: ok=%v err=%v", ok, err)
	}
	if count == 0 {
		t.Fatal("index should remain active after a compatible function change")
	}

	// A disabled generation must fall back to the full candidate set.
	entry, ok := e.policyIndexes.Load("p")
	if !ok {
		t.Fatal("index entry missing")
	}
	idx := entry.(*ipMatchPolicyIndex)
	idx.mu.Lock()
	idx.disabled = true
	idx.mu.Unlock()
	count = 0
	if _, err := e.Enforce("10.1.2.200", "no-such-object", "read"); err != nil {
		t.Fatal(err)
	}
	if count != len(e.model["p"]["p"].Policy) {
		t.Fatalf("disabled index must scan all rules, got %d", count)
	}
}

func TestIPMatchIndexRemoveRestoresFullScan(t *testing.T) {
	var count int
	e := newIPMatchEnforcer(t, ipMatchGateMatcher, "some(where (p.eft == allow))", false, &count)
	if _, err := e.AddPolicies(ipMatchRules(t, false, validIPMatchPatterns())); err != nil {
		t.Fatal(err)
	}
	if err := e.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}
	e.RemovePolicyIndex("p")

	count = 0
	if _, err := e.Enforce("10.1.2.200", "no-such-object", "read"); err != nil {
		t.Fatal(err)
	}
	if count != len(e.model["p"]["p"].Policy) {
		t.Fatalf("removed index must evaluate every rule, got %d", count)
	}
}

func TestIPMatchIndexConformanceCases(t *testing.T) {
	caseData, err := os.ReadFile(filepath.Join("conformance", "cases", "ipmatch.json"))
	if err != nil {
		t.Fatal(err)
	}
	var conformance struct {
		Tests []struct {
			Request []string `json:"request"`
			Allow   bool     `json:"allow"`
			Explain []string `json:"explain"`
		} `json:"tests"`
	}
	if err := json.Unmarshal(caseData, &conformance); err != nil {
		t.Fatal(err)
	}

	indexed, err := NewEnforcer(
		filepath.Join("conformance", "data", "ipmatch_model.conf"),
		filepath.Join("conformance", "data", "ipmatch_policy.csv"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := NewEnforcer(
		filepath.Join("conformance", "data", "ipmatch_model.conf"),
		filepath.Join("conformance", "data", "ipmatch_policy.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if err := indexed.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	requests := make([][]interface{}, 0, len(conformance.Tests))
	for _, testCase := range conformance.Tests {
		rvals := make([]interface{}, len(testCase.Request))
		for i, v := range testCase.Request {
			rvals[i] = v
		}
		requests = append(requests, rvals)
	}
	assertEnforceParity(t, indexed, plain, requests)
}

func TestIPMatchIndexConcurrentUpdatesAndEnforce(t *testing.T) {
	// Concurrent policy mutation is only supported by SyncedEnforcer; the
	// plain Enforcer explicitly documents a single-writer model.
	newSynced := func() *SyncedEnforcer {
		m := model.NewModel()
		m.AddDef("r", "r", "sub, obj, act")
		m.AddDef("p", "p", "sub, obj, act")
		m.AddDef("g", "g", "_, _")
		m.AddDef("e", "e", "some(where (p.eft == allow))")
		m.AddDef("m", "m", ipMatchGateMatcher)
		e, err := NewSyncedEnforcer(m)
		if err != nil {
			t.Fatal(err)
		}
		e.AddFunction("gate", func(args ...interface{}) (interface{}, error) {
			if len(args) != 2 {
				return false, fmt.Errorf("gate: expected 2 arguments, got %d", len(args))
			}
			return args[0].(string) == args[1].(string), nil
		})
		return e
	}

	baseRules := ipMatchRules(t, false, validIPMatchPatterns())
	indexed := newSynced()
	plain := newSynced()
	if _, err := indexed.AddPolicies(baseRules); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.AddPolicies(baseRules); err != nil {
		t.Fatal(err)
	}
	if err := indexed.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	requests := randomIPMatchRequests(t, 60)
	var wg sync.WaitGroup

	// Readers hammer the index while policy generations change underneath.
	for reader := 0; reader < 6; reader++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < 200; i++ {
				request := requests[rng.Intn(len(requests))]
				_, _ = indexed.Enforce(request...)
			}
		}(int64(reader) + 1)
	}

	// Mutators go through the synced locks; the same operations are applied
	// to both enforcers so their final states stay comparable.
	for mutator := 0; mutator < 3; mutator++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + 99))
			for i := 0; i < 40; i++ {
				rule := []interface{}{
					fmt.Sprintf("10.%d.%d.0/24", rng.Intn(255), rng.Intn(255)),
					fmt.Sprintf("concurrent-%d", i),
					"read",
				}
				_, _ = indexed.AddPolicy(rule...)
				_, _ = plain.AddPolicy(rule...)
				if i%5 == 0 {
					_, _ = indexed.RemovePolicy(rule...)
					_, _ = plain.RemovePolicy(rule...)
				}
			}
		}(int64(mutator) + 7)
	}
	wg.Wait()

	if len(indexed.model["p"]["p"].Policy) != len(plain.model["p"]["p"].Policy) {
		t.Fatalf("policy lengths diverged: indexed=%d plain=%d",
			len(indexed.model["p"]["p"].Policy), len(plain.model["p"]["p"].Policy))
	}
	assertEnforceParity(t, indexed.Enforcer, plain.Enforcer, requests)
}

func TestIPMatchIndexWholeMatcherAndNonStringRequest(t *testing.T) {
	// A matcher that is exactly the ipMatch predicate is still indexable.
	var count int
	e := newIPMatchEnforcer(t, "ipMatch(r.sub, p.sub)", "some(where (p.eft == allow))", false, &count)
	if _, err := e.AddPolicies(ipMatchRules(t, false, validIPMatchPatterns())); err != nil {
		t.Fatal(err)
	}
	if err := e.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.Enforce("10.1.2.200", "ignored", "ignored"); err != nil || !ok {
		t.Fatalf("whole-matcher ipMatch enforce: ok=%v err=%v", ok, err)
	}

	// A non-string request value must take the full-scan path and surface the
	// original IPMatchFunc type error, exactly like the unindexed enforcer.
	var plainCount int
	plain := newIPMatchEnforcer(t, "ipMatch(r.sub, p.sub)", "some(where (p.eft == allow))", false, &plainCount)
	if _, err := plain.AddPolicies(ipMatchRules(t, false, validIPMatchPatterns())); err != nil {
		t.Fatal(err)
	}
	_, indexedErr := e.Enforce(12345, "ignored", "ignored")
	_, plainErr := plain.Enforce(12345, "ignored", "ignored")
	if indexedErr == nil || plainErr == nil {
		t.Fatal("expected a type error from ipMatch on both enforcers")
	}
	if indexedErr.Error() != plainErr.Error() {
		t.Fatalf("non-string error mismatch: indexed=%v plain=%v", indexedErr, plainErr)
	}
}

func TestIPMatchIndexIgnoredForEnforceContext(t *testing.T) {
	// The index is proven for the default r/m definitions. An EnforceContext
	// with a different matcher must never consult it.
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "ipMatch(r.sub, p.sub) && r.obj == p.obj")
	m.AddDef("r", "r2", "sub, obj, act")
	m.AddDef("p", "p2", "sub, obj, act")
	m.AddDef("m", "m2", "r2.sub == p2.sub && r2.obj == p2.obj")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("10.0.0.0/8", "v4-object", "read"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddNamedPolicy("p2", "alice", "v4-object", "read"); err != nil {
		t.Fatal(err)
	}
	if err := e.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	// Under m2 the subject is a plain name comparison, which the CIDR index
	// (installed for p only) must not influence.
	ctx := NewEnforceContext("2")
	ctx.EType = "e"
	if ok, err := e.Enforce(ctx, "alice", "v4-object", "read"); err != nil || !ok {
		t.Fatalf("EnforceContext decision: ok=%v err=%v", ok, err)
	}
	if ok, err := e.Enforce(ctx, "10.0.0.1", "v4-object", "read"); err != nil || ok {
		t.Fatalf("EnforceContext must use m2 semantics, not the p CIDR index: ok=%v err=%v", ok, err)
	}
}
