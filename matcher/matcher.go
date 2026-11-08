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

// Package matcher defines the pluggable matcher backend abstraction used by
// the enforcer. A backend owns one expression language (the default govaluate
// dialect or an explicit CEL dialect), compiles matchers against static
// request/policy declarations and returns concurrency-safe compiled programs.
//
// Compiled programs are reusable across enforcement calls and must never
// capture request data: request and policy values are supplied at Eval time.
package matcher

import "context"

// Matcher language identifiers. Every cache identity is scoped to one
// language, so matchers with identical text compiled by different backends
// never share a compiled object.
const (
	LanguageGovaluate = "govaluate"
	LanguageCEL       = "cel"
)

// RoleFunction binds a role-manager lookup (g, g2, ...) to a matcher.
//
// The binding is invoked at evaluation time against the current role-manager
// view, so role graph updates are observed without recompiling the matcher.
// Arity is the statically declared argument count: 2 for g(name1, name2) and
// 3 for the domain-aware g(name1, name2, domain) form.
type RoleFunction struct {
	Name    string
	Arity   int
	Binding func(args ...string) (bool, error)
}

// CompileSpec is the request-independent static input of a compilation.
//
// It carries the matcher text, the declared request/policy tokens, the
// role-function configuration and a configuration generation. It deliberately
// contains no request or policy values. Custom typed functions are managed by
// the backend itself through its registration protocol, so a backend swap or
// function re-registration changes the compilation identity automatically.
type CompileSpec struct {
	Expression string
	RTokens    []string
	PTokens    []string
	Roles      []RoleFunction
	Generation uint64
}

// Compiled is a concurrency-safe, reusable matcher program. Eval must not
// retain the supplied request/policy values after returning.
type Compiled interface {
	// Eval evaluates the matcher. rVals align positionally with the request
	// tokens and pVals with the policy tokens given at compile time.
	Eval(rVals []interface{}, pVals []string) (bool, error)
}

// ContextCompiled is optionally implemented by backends whose runtime supports
// cooperative context cancellation. The context affects a single evaluation
// only; the shared compiled program stays untouched.
type ContextCompiled interface {
	Compiled
	EvalContext(ctx context.Context, rVals []interface{}, pVals []string) (bool, error)
}

// Backend compiles matcher expressions of a single language.
// Implementations are expected to keep an internal compilation cache keyed by
// the language, token/function configuration and generation.
type Backend interface {
	// Language returns the matcher language identifier, e.g. LanguageCEL.
	Language() string
	// Compile type-checks and compiles the matcher described by spec.
	Compile(spec CompileSpec) (Compiled, error)
}
