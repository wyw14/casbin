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
)

// Budget stages reported by BudgetExceededError.Stage.
const (
	// BudgetStagePolicy is charged per policy rule whose matcher expression is evaluated.
	BudgetStagePolicy = "policy"
	// BudgetStageRole is charged per role graph node inspected during a g() traversal.
	BudgetStageRole = "role"
	// BudgetStageEval is charged (as depth) when entering an eval() sub-expression.
	BudgetStageEval = "eval"
	// BudgetStageFunction is charged per invocation of a named expression function.
	BudgetStageFunction = "function"
)

// Sentinel errors. BudgetExceededError always wraps ErrBudgetExceeded so callers
// can use errors.Is(err, ErrBudgetExceeded) without inspecting concrete types.
var (
	// ErrBudgetExceeded marks decisions aborted because a Budget limit was reached.
	ErrBudgetExceeded = errors.New("enforce budget exceeded")
	// ErrBoundedModeUnsupported marks role managers that reject bounded mode
	// because they do not implement rbac.BoundedRoleManager.
	ErrBoundedModeUnsupported = errors.New("bounded enforce mode is not supported by this role manager")
)

// Budget limits the work a single EnforceBounded call may perform.
//
// One Budget becomes one private budgetState per EnforceBounded call. Every
// chargeable event of the whole call draws from the same state: the named
// request/policy/matcher selected via EnforceContext, every policy rule of
// that named policy, nested eval() sub-expressions and every g() invocation
// (including g2, g3, ...). Budgets are never re-allocated per policy rule or
// per role manager entry, and budgetState never escapes the call, so concurrent
// EnforceBounded calls cannot share or steal each other's quota.
//
// Fixed billing rules (identical for every model, do not depend on evaluation
// results):
//
//   - A negative limit means "unlimited" for that dimension. A zero limit is
//     strict: the very first chargeable event of that dimension fails with
//     ErrBudgetExceeded before any work it guards is performed.
//   - MaxPolicies: one unit is charged immediately before the matcher of a
//     policy rule is evaluated. Rules skipped by the policy index are not
//     evaluated and cost nothing. When the model has no policy rules, the single
//     matcher evaluation costs zero policy units.
//   - MaxFunctionCalls: one unit is charged before every named expression
//     function runs. This covers built-in functions (keyMatch, regexMatch, ...),
//     user-registered functions, g() and eval(). Charging happens before the
//     call, therefore a function that returns an error still consumes its unit
//     (failed attempts are billed). A g() result served from the per-call g
//     memo costs one function unit but zero role nodes.
//   - MaxRoleNodes: on a g() cache miss, one unit is charged per role graph
//     node inspection reported by the bounded role manager, starting with the
//     source node. A node is reported at most once per BFS level; nodes in a
//     role cycle may be reported again on later levels, while the traversal
//     remains finite through the role manager's maxHierarchyLevel. g() cache
//     hits and the name1 == name2 short-circuit cost zero role nodes.
//   - MaxEvalDepth: entering eval() increments the active depth; the outermost
//     eval frame is depth 1. Entry that would exceed the limit fails before the
//     sub-expression is compiled or evaluated. The depth decrements on return,
//     so sibling eval() calls do not accumulate.
//
// Context cancellation is checked at every charge point and takes precedence
// over budget exhaustion: a canceled context returns the wrapped context error
// instead of a BudgetExceededError.
type Budget struct {
	// MaxPolicies limits the number of policy rules whose matcher is evaluated.
	MaxPolicies int64
	// MaxRoleNodes limits the total role graph nodes inspected across all g()
	// traversals of the call.
	MaxRoleNodes int64
	// MaxEvalDepth limits the nesting depth of eval() sub-expressions.
	MaxEvalDepth int64
	// MaxFunctionCalls limits the total named expression function invocations,
	// including g(), eval(), built-in and user-registered functions.
	MaxFunctionCalls int64
}

// BudgetExceededError is returned when a Budget limit is reached. It never
// replaces a decision: EnforceBounded returns it together with result false,
// so callers cannot confuse an exhausted budget with a normal deny. It wraps
// ErrBudgetExceeded and carries the offending stage and a descriptive path.
type BudgetExceededError struct {
	// Stage is one of the BudgetStage* constants.
	Stage string
	// Path describes where inside the enforcement the limit was reached,
	// e.g. "p[3]", "keyMatch", "g(alice, admin)@node(bob)" or "eval(...) / eval(...)".
	Path string
	// Limit is the configured limit that was exceeded.
	Limit int64
	// Used is the counter value after the rejected charge (always Limit+1).
	Used int64
}

func (e *BudgetExceededError) Error() string {
	return fmt.Sprintf("%s: stage %s at %s, limit %d exceeded (used %d)",
		ErrBudgetExceeded.Error(), e.Stage, e.Path, e.Limit, e.Used)
}

// Unwrap allows errors.Is(err, ErrBudgetExceeded).
func (e *BudgetExceededError) Unwrap() error {
	return ErrBudgetExceeded
}

// BudgetUsage is a point-in-time snapshot of a call's budget counters.
type BudgetUsage struct {
	Policies      int64
	RoleNodes     int64
	FunctionCalls int64
	EvalDepth     int64
}

// budgetState is the per-call accounting state. It is created inside
// EnforceBounded, shared by every function closure compiled for that call and
// never stored on the Enforcer or in any shared cache.
type budgetState struct {
	ctx    context.Context
	budget Budget

	mu sync.Mutex

	policies      int64
	roleNodes     int64
	functionCalls int64
	evalDepth     int64
	evalPath      []string
}

func newBudgetState(ctx context.Context, budget Budget) *budgetState {
	return &budgetState{ctx: ctx, budget: budget}
}

// usage returns a consistent snapshot of all counters for tests and diagnostics.
func (s *budgetState) usage() BudgetUsage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return BudgetUsage{
		Policies:      s.policies,
		RoleNodes:     s.roleNodes,
		FunctionCalls: s.functionCalls,
		EvalDepth:     s.evalDepth,
	}
}

func (s *budgetState) canceledError(stage, path string) error {
	return fmt.Errorf("bounded enforce stopped at stage %q path %q: %w", stage, path, s.ctx.Err())
}

// checkContext returns a wrapped context error (errors.Is still matches the
// original) when the context is done, nil otherwise.
func (s *budgetState) checkContext(stage, path string) error {
	if err := s.ctx.Err(); err != nil {
		return s.canceledError(stage, path)
	}
	return nil
}

// charge implements the shared rule: context first, then strict-limit check.
// It must be called with s.mu held.
func (s *budgetState) charge(stage, path string, limit, current int64) (int64, error) {
	if err := s.ctx.Err(); err != nil {
		return current, s.canceledError(stage, path)
	}
	next := current + 1
	if limit >= 0 && next > limit {
		return current, &BudgetExceededError{Stage: stage, Path: path, Limit: limit, Used: next}
	}
	return next, nil
}

// chargePolicy bills one evaluated policy rule.
func (s *budgetState) chargePolicy(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := s.charge(BudgetStagePolicy, path, s.budget.MaxPolicies, s.policies)
	if err != nil {
		return err
	}
	s.policies = next
	return nil
}

// chargeFunction bills one named expression function invocation before the
// wrapped function runs, so failed attempts are billed as well.
func (s *budgetState) chargeFunction(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := s.charge(BudgetStageFunction, name, s.budget.MaxFunctionCalls, s.functionCalls)
	if err != nil {
		return err
	}
	s.functionCalls = next
	return nil
}

// chargeRoleNode bills one inspected role graph node during a g() traversal.
func (s *budgetState) chargeRoleNode(gName, name1, name2, node string) error {
	path := fmt.Sprintf("%s(%s, %s)@node(%s)", gName, name1, name2, node)
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := s.charge(BudgetStageRole, path, s.budget.MaxRoleNodes, s.roleNodes)
	if err != nil {
		return err
	}
	s.roleNodes = next
	return nil
}

// enterEval bills one eval() frame. The returned leave function restores the
// previous depth and must be called when the frame exits.
func (s *budgetState) enterEval(expression string) (func(), error) {
	entry := "eval(" + truncateForBudgetPath(expression, 64) + ")"
	path := s.evalPathWith(entry)
	if err := s.checkContext(BudgetStageEval, path); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.evalDepth + 1
	if s.budget.MaxEvalDepth >= 0 && next > s.budget.MaxEvalDepth {
		return nil, &BudgetExceededError{
			Stage: BudgetStageEval,
			Path:  path,
			Limit: s.budget.MaxEvalDepth,
			Used:  next,
		}
	}
	s.evalDepth = next
	s.evalPath = append(s.evalPath, entry)
	return func() {
		s.mu.Lock()
		s.evalDepth--
		if len(s.evalPath) > 0 {
			s.evalPath = s.evalPath[:len(s.evalPath)-1]
		}
		s.mu.Unlock()
	}, nil
}

// evalPathWith renders the current eval frame stack including the new entry.
func (s *budgetState) evalPathWith(entry string) string {
	if len(s.evalPath) == 0 {
		return entry
	}
	return strings.Join(s.evalPath, " / ") + " / " + entry
}

func truncateForBudgetPath(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
