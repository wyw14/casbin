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

package rbac

import "context"

// BoundedRoleManager is the optional budget-aware protocol of RoleManager.
//
// EnforceBounded only accepts role managers implementing this interface.
// A custom RoleManager that does not implement it is rejected up-front with
// ErrBoundedModeUnsupported instead of being traversed without accounting.
//
// HasLinkBounded has the same semantics as HasLink, plus two guarantees:
//
//  1. onVisit is invoked whenever a role graph node is inspected, including the
//     source node. Within one BFS level a node is reported at most once (the
//     level map deduplicates it); the same node may be reported again on a
//     later level when the graph contains cycles. Traversals stay finite
//     because the role manager still enforces its maxHierarchyLevel, while the
//     visitor budget provides an independent hard cap.
//  2. the traversal stops as soon as ctx is canceled or onVisit returns a
//     non-nil error; that error is propagated unchanged to the caller.
//
// The traversal itself never blocks beyond the role manager's own operations;
// ctx and onVisit are checked between node expansions, so a blocked expansion
// cannot be preempted from the outside.
type BoundedRoleManager interface {
	RoleManager

	// HasLinkBounded determines whether a link exists between two roles while
	// reporting every inspected role graph node and honoring cancellation.
	HasLinkBounded(ctx context.Context, name1 string, name2 string, onVisit func(node string) error, domain ...string) (bool, error)
}
