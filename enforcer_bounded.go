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

	"github.com/casbin/casbin/v3/rbac"
	"github.com/casbin/casbin/v3/util"
	"github.com/casbin/govaluate"
)

// enforceSession carries per-call enforcement state. A nil session means the
// ordinary, fully backward-compatible enforcement path. Bounded sessions are
// created inside EnforceBounded and never shared between calls.
type enforceSession struct {
	budget *budgetState
}

// EnforceBounded decides whether a "subject" can access a "object" with the
// operation "action" under an explicit resource budget and a cancelable
// context; input parameters are usually: (sub, obj, act).
//
// The budget is scoped to this single call and shared by every chargeable
// event inside it: the named request/policy/matcher, all policy rules, nested
// eval() sub-expressions and all g() traversals. When a limit is reached the
// call returns (false, *BudgetExceededError) carrying the stage and path; it
// never returns a nil-error false that could be read as a normal deny, and it
// never publishes allow/deny results into any cache. A canceled or expired
// context is reported with the wrapped context error at the next checkpoint.
//
// Bounded enforcement does not modify policies, the adapter or function
// registrations. Matcher expressions are compiled through an independent
// per-call path so the shared matcher cache never holds closures capturing
// this budget or context; concurrent calls therefore cannot share quota.
//
// Role managers must implement rbac.BoundedRoleManager, otherwise the call is
// rejected up-front with ErrBoundedModeUnsupported. User-registered functions
// are only checked immediately before invocation; a function blocking
// internally cannot be preempted.
func (e *Enforcer) EnforceBounded(ctx context.Context, budget Budget, rvals ...interface{}) (bool, error) {
	// Mirror Enforce: a disabled enforcer allows everything without touching
	// role managers, caches or the budget.
	if !e.enabled {
		return true, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("bounded enforce rejected before evaluation: %w", err)
	}
	if err := e.checkBoundedRoleManagers(); err != nil {
		return false, err
	}

	state := newBudgetState(ctx, budget)
	return e.enforceInSession("", nil, &enforceSession{budget: state}, rvals...)
}

// checkBoundedRoleManagers rejects bounded mode when any role definition uses a
// role manager outside the explicit budget-aware protocol, instead of silently
// traversing an unknown graph without node accounting.
func (e *Enforcer) checkBoundedRoleManagers() error {
	gSection, ok := e.model["g"]
	if !ok {
		return nil
	}
	for key, ast := range gSection {
		var manager rbac.RoleManager
		if ast.RM != nil {
			manager = ast.RM
		} else if ast.CondRM != nil {
			manager = ast.CondRM
		}
		if manager == nil {
			continue
		}
		if _, supported := manager.(rbac.BoundedRoleManager); !supported {
			return fmt.Errorf("%w: role definition %q uses role manager %T, register an rbac.BoundedRoleManager implementation to run EnforceBounded",
				ErrBoundedModeUnsupported, key, manager)
		}
	}
	return nil
}

// buildDefaultFunctions reproduces the historical function map construction of
// the unbounded enforce path, including the g role-manager closures.
func (e *Enforcer) buildDefaultFunctions() map[string]govaluate.ExpressionFunction {
	functions := e.fm.GetFunctions()
	if _, ok := e.model["g"]; ok {
		for key, ast := range e.model["g"] {
			// g must be a normal role definition (ast.RM != nil)
			//   or a conditional role definition (ast.CondRM != nil)
			// ast.RM and ast.CondRM shouldn't be nil at the same time
			if ast.RM != nil {
				functions[key] = util.GenerateGFunction(ast.RM, e.gFunctionCache)
			}
			if ast.CondRM != nil {
				functions[key] = util.GenerateConditionalGFunction(ast.CondRM)
			}
		}
	}
	return functions
}

// buildBoundedFunctions creates the per-call function map. Every entry wraps
// the original function with a pre-call budget check; g and eval closures
// additionally share the same budgetState across nested invocations.
func (e *Enforcer) buildBoundedFunctions(state *budgetState) map[string]govaluate.ExpressionFunction {
	functions := e.fm.GetFunctions()
	for name, fn := range functions {
		functions[name] = wrapBoundedFunction(name, fn, state)
	}

	if gSection, ok := e.model["g"]; ok {
		for key, ast := range gSection {
			if ast.RM != nil {
				functions[key] = e.makeBoundedGFunction(key, ast.RM, state)
			}
			if ast.CondRM != nil {
				functions[key] = e.makeBoundedGFunction(key, ast.CondRM, state)
			}
		}
	}
	return functions
}

// wrapBoundedFunction charges one function unit before delegating to the
// original function. The charge happens before the call by contract, so a
// function returning an error still consumed its unit. Only the entry point is
// guarded; a blocked user function is not preempted.
func wrapBoundedFunction(name string, fn govaluate.ExpressionFunction, state *budgetState) govaluate.ExpressionFunction {
	return func(args ...interface{}) (interface{}, error) {
		if err := state.chargeFunction(name); err != nil {
			return nil, err
		}
		return fn(args...)
	}
}

// makeBoundedGFunction builds a budget-aware g() closure. The result memo is a
// fresh per-call map: a cache hit still costs one function unit but performs
// no graph traversal, so it costs zero role nodes; a cache miss traverses the
// role manager through rbac.BoundedRoleManager and bills every inspected node.
func (e *Enforcer) makeBoundedGFunction(gName string, manager rbac.RoleManager, state *budgetState) govaluate.ExpressionFunction {
	memorized := sync.Map{}
	return func(args ...interface{}) (interface{}, error) {
		if err := state.chargeFunction(gName); err != nil {
			return nil, err
		}

		if e.gFunctionCache {
			key := boundedGCacheKey(args)
			if cached, found := memorized.Load(key); found {
				return cached, nil
			}
			value, err := e.boundedGLink(gName, manager, state, args)
			if err != nil {
				return nil, err
			}
			memorized.Store(key, value)
			return value, nil
		}

		return e.boundedGLink(gName, manager, state, args)
	}
}

// boundedGLink resolves one g() call through the budget-aware protocol.
func (e *Enforcer) boundedGLink(gName string, manager rbac.RoleManager, state *budgetState, args []interface{}) (interface{}, error) {
	name1, name2 := args[0].(string), args[1].(string)
	if manager == nil {
		return name1 == name2, nil
	}

	bounded, ok := manager.(rbac.BoundedRoleManager)
	if !ok {
		// Defensive guard: checkBoundedRoleManagers rejects this before evaluation.
		return nil, fmt.Errorf("%w: role definition %q uses role manager %T", ErrBoundedModeUnsupported, gName, manager)
	}

	onVisit := func(node string) error {
		return state.chargeRoleNode(gName, name1, name2, node)
	}
	if len(args) == 2 {
		return bounded.HasLinkBounded(state.ctx, name1, name2, onVisit)
	}
	domain := args[2].(string)
	return bounded.HasLinkBounded(state.ctx, name1, name2, onVisit, domain)
}

// boundedGCacheKey reproduces the g() memo key layout used by
// util.GenerateGFunction so the billing behavior matches cache semantics.
func boundedGCacheKey(args []interface{}) string {
	total := len(args)
	for _, a := range args {
		total += len(a.(string))
	}
	builder := strings.Builder{}
	builder.Grow(total)
	for _, arg := range args {
		builder.WriteByte(0)
		builder.WriteString(arg.(string))
	}
	return builder.String()
}

// generateBoundedEvalFunction builds a budget-aware eval() closure. It shares
// the call's function map, so nested eval() and g() invocations draw from the
// same budget; depth is accounted before the sub-expression is compiled.
func generateBoundedEvalFunction(functions map[string]govaluate.ExpressionFunction, parameters *enforceParameters, state *budgetState) govaluate.ExpressionFunction {
	return func(args ...interface{}) (interface{}, error) {
		if err := state.chargeFunction("eval"); err != nil {
			return nil, err
		}
		if len(args) != 1 {
			return nil, fmt.Errorf("function eval(subrule string) expected %d arguments, but got %d", 1, len(args))
		}

		expression, ok := args[0].(string)
		if !ok {
			return nil, errors.New("argument of eval(subrule string) must be a string")
		}

		leave, err := state.enterEval(expression)
		if err != nil {
			return nil, err
		}
		defer leave()

		expression = util.EscapeAssertion(expression)
		expr, err := govaluate.NewEvaluableExpressionWithFunctions(expression, functions)
		if err != nil {
			return nil, fmt.Errorf("error while parsing eval parameter: %s, %s", expression, err.Error())
		}
		return expr.Eval(parameters)
	}
}
