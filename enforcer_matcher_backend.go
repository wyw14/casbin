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
	"fmt"

	"github.com/casbin/casbin/v3/matcher"
	"github.com/casbin/casbin/v3/util"
	"github.com/casbin/govaluate"
)

// compiledMatcherExpr is the enforcer-internal view of a compiled matcher.
// It always yields a bool; the bool is fed into the existing effector exactly
// like the govaluate matcher result.
type compiledMatcherExpr interface {
	Eval(parameters enforceParameters) (bool, error)
}

// govaluateMatcherExpr preserves the historical govaluate result convention:
// bool is used directly, a non-zero float is treated as true.
type govaluateMatcherExpr struct {
	expression *govaluate.EvaluableExpression
}

func (g govaluateMatcherExpr) Eval(parameters enforceParameters) (bool, error) {
	result, err := g.expression.Eval(parameters)
	if err != nil {
		return false, err
	}
	switch result := result.(type) {
	case bool:
		return result, nil
	case float64:
		return result != 0, nil
	default:
		return false, errors.New("matcher result should be bool, int or float")
	}
}

// backendMatcherExpr adapts a matcher.Backend compiled program to the enforcer
// evaluation loop. Request/policy values are passed per call and are never
// retained by the compiled program.
type backendMatcherExpr struct {
	compiled matcher.Compiled
}

func (b backendMatcherExpr) Eval(parameters enforceParameters) (bool, error) {
	return b.compiled.Eval(parameters.rVals, parameters.pVals)
}

// SetMatcherBackend installs an explicit matcher backend (e.g. the CEL
// backend). Passing nil restores the default govaluate backend. The adapter,
// policy format and effector are unaffected by this choice.
func (e *Enforcer) SetMatcherBackend(backend matcher.Backend) {
	e.matcherBackend = backend
	e.invalidateMatcherMap()
}

// GetMatcherBackend returns the active matcher backend, or nil when the
// default govaluate backend is in use.
func (e *Enforcer) GetMatcherBackend() matcher.Backend {
	return e.matcherBackend
}

// compileBackendMatcher type-checks and compiles the matcher through the
// configured non-govaluate backend. The backend owns the compilation cache,
// keyed by language, matcher text, token/function configuration and generation.
func (e *Enforcer) compileBackendMatcher(rType, pType, mType, customMatcher string) (compiledMatcherExpr, error) {
	var source string
	if customMatcher == "" {
		ast := e.model["m"][mType]
		// RawValue is the matcher text without govaluate-specific normalizations.
		// Models whose matcher was assigned directly still work via the fallback.
		source = ast.RawValue
		if source == "" {
			source = ast.Value
		}
	} else {
		// Runtime custom matchers only get comment removal and r./p. identifier
		// escaping; no govaluate dialect rewriting is applied.
		source = util.RemoveComments(util.EscapeAssertion(customMatcher))
	}

	spec := matcher.CompileSpec{
		Expression: source,
		RTokens:    append([]string(nil), e.model["r"][rType].Tokens...),
		PTokens:    append([]string(nil), e.model["p"][pType].Tokens...),
		Roles:      e.buildRoleFunctions(),
	}
	compiled, err := e.matcherBackend.Compile(spec)
	if err != nil {
		return nil, err
	}
	return backendMatcherExpr{compiled: compiled}, nil
}

// buildRoleFunctions creates the g-style role bindings for the matcher.
//
// Each binding resolves the role manager through the enforcer at evaluation
// time, so role graph updates are observed without recompiling pure
// expressions and every decision reads the current consistent model view.
// Arity (2 or 3, the latter carrying the domain) and conditional-role
// semantics are identical to the govaluate g functions.
func (e *Enforcer) buildRoleFunctions() []matcher.RoleFunction {
	gSection, ok := e.model["g"]
	if !ok {
		return nil
	}
	roles := make([]matcher.RoleFunction, 0, len(gSection))
	for name := range gSection {
		roleName := name
		roles = append(roles, matcher.RoleFunction{
			Name:  roleName,
			Arity: len(gSection[roleName].Tokens),
			Binding: func(args ...string) (bool, error) {
				if len(args) != 2 && len(args) != 3 {
					return false, fmt.Errorf("role function %s expects 2 or 3 arguments, got %d", roleName, len(args))
				}
				if rm := e.rmMap[roleName]; rm != nil {
					return roleManagerHasLink(rm, args)
				}
				if condRM := e.condRmMap[roleName]; condRM != nil {
					return roleManagerHasLink(condRM, args)
				}
				// No role manager: only identical names match, mirroring govaluate.
				return args[0] == args[1], nil
			},
		})
	}
	return roles
}

func roleManagerHasLink(rm interface {
	HasLink(name1 string, name2 string, domain ...string) (bool, error)
}, args []string) (bool, error) {
	if len(args) == 2 {
		return rm.HasLink(args[0], args[1])
	}
	return rm.HasLink(args[0], args[1], args[2])
}
