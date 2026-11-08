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
	"testing"
)

const (
	ipBenchV4Groups = 200
	ipBenchPerGroup = 100
	ipBenchV6Groups = 50
)

// newLargeIPMatchEnforcer builds 20,000+ rules spread across many disjoint
// and overlapping CIDRs of both address families.
func newLargeIPMatchEnforcer(b testing.TB) *Enforcer {
	matcher := "ipMatch(r.sub, p.sub) && r.obj == p.obj && r.act == p.act"
	e := newIPMatchEnforcer(b, matcher, "some(where (p.eft == allow))", false, new(int))

	rules := make([][]string, 0, ipBenchV4Groups*ipBenchPerGroup+ipBenchV6Groups)
	for group := 0; group < ipBenchV4Groups; group++ {
		// 10.<group>.0.0/16 holds 100 /24 networks, so every request inside
		// one group still overlaps its containing /16 and the shared /8.
		for member := 0; member < ipBenchPerGroup; member++ {
			cidr := fmt.Sprintf("10.%d.%d.0/24", group, member)
			rules = append(rules, []string{cidr, fmt.Sprintf("obj-%d-%d", group, member), "read"})
		}
		rules = append(rules, []string{fmt.Sprintf("10.%d.0.0/16", group), fmt.Sprintf("net-%d", group), "read"})
	}
	for group := 0; group < ipBenchV6Groups; group++ {
		rules = append(rules, []string{
			fmt.Sprintf("2001:db8:%x::/48", group),
			fmt.Sprintf("v6-obj-%d", group),
			"read",
		})
	}
	if _, err := e.AddPolicies(rules); err != nil {
		b.Fatal(err)
	}
	return e
}

func BenchmarkIPMatchIndex(b *testing.B) {
	e := newLargeIPMatchEnforcer(b)
	// The object never matches, so the allow-override effector scans the full
	// policy in the unindexed case while the index only keeps CIDR candidates.
	request := []interface{}{"10.42.7.9", "no-such-object", "read"}

	b.Run("unindexed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if ok, err := e.Enforce(request...); err != nil || ok {
				b.Fatal(ok, err)
			}
		}
	})

	if err := e.SetIPMatchIndex("p"); err != nil {
		b.Fatal(err)
	}

	b.Run("indexed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if ok, err := e.Enforce(request...); err != nil || ok {
				b.Fatal(ok, err)
			}
		}
	})
}

// TestIPMatchIndexLargeScaleReduction proves on a large policy that the index
// shrinks the evaluated set instead of merely adding bookkeeping objects.
func TestIPMatchIndexLargeScaleReduction(t *testing.T) {
	var plainCount, indexedCount int
	matcher := "gate(r.act, p.act) && ipMatch(r.sub, p.sub) && r.obj == p.obj"
	plain := newIPMatchEnforcer(t, matcher, "some(where (p.eft == allow))", false, &plainCount)
	indexed := newIPMatchEnforcer(t, matcher, "some(where (p.eft == allow))", false, &indexedCount)

	rules := make([][]string, 0, ipBenchV4Groups*ipBenchPerGroup)
	for group := 0; group < ipBenchV4Groups; group++ {
		for member := 0; member < ipBenchPerGroup; member++ {
			rules = append(rules, []string{
				fmt.Sprintf("10.%d.%d.0/24", group, member),
				fmt.Sprintf("obj-%d-%d", group, member),
				"read",
			})
		}
	}
	if _, err := plain.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if _, err := indexed.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if err := indexed.SetIPMatchIndex("p"); err != nil {
		t.Fatal(err)
	}

	request := []interface{}{"10.42.7.9", "no-such-object", "read"}

	plainCount = 0
	if _, err := plain.Enforce(request...); err != nil {
		t.Fatal(err)
	}
	indexedCount = 0
	if _, err := indexed.Enforce(request...); err != nil {
		t.Fatal(err)
	}

	if plainCount != len(rules) {
		t.Fatalf("plain enforcer evaluated %d of %d rules", plainCount, len(rules))
	}
	if indexedCount != 1 {
		t.Fatalf("indexed enforcer evaluated %d rules, want exactly the single containing /24", indexedCount)
	}
	if indexedCount >= plainCount/100 {
		t.Fatalf("candidate reduction too small: indexed=%d plain=%d", indexedCount, plainCount)
	}
	t.Logf("large policy=%d residual evaluations: plain=%d indexed=%d (%.3f%%)",
		len(rules), plainCount, indexedCount, 100*float64(indexedCount)/float64(plainCount))
}
