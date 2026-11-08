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

// Package celmatcher implements an explicit CEL (Common Expression Language)
// matcher backend for Casbin.
//
// The backend builds static CEL declarations from the request/policy tokens,
// type-checks every matcher at compile time and rejects unknown variables,
// non-bool results, undeclared custom functions and dynamic eval()
// sub-expressions. It never rewrites govaluate syntax into CEL: matchers are
// compiled as authored in CEL.
//
// Custom functions must be registered through TypedFunction, which carries an
// explicit CEL type signature; the legacy untyped ExpressionFunction protocol
// is not implicitly accepted as a dynamically typed function.
//
// Compiled programs are cached per (language, matcher text, token/function
// configuration, generation), are safe for concurrent use and never capture
// request data. Cost limits and context cancellation use the CEL runtime's
// own interruption mechanisms.
package celmatcher

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v3/matcher"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
)

// defaultInterruptCheckFrequency is the number of comprehension iterations
// between native context cancellation checks.
const defaultInterruptCheckFrequency uint = 20

// evalCallPattern matches a dynamic eval(...) call. CEL has no dynamic
// expression evaluation, so the construct is rejected up front with a
// validation error instead of being silently misinterpreted.
var evalCallPattern = regexp.MustCompile(`\beval\s*\(`)

// TypedFunction is the registration protocol for custom matcher functions.
//
// ArgTypes and ReturnType are explicit CEL types; Binding must be a Go
// function whose parameter/result types match them, returning either a single
// result or (result, error). Dyn-typed arguments receive the native Go value.
type TypedFunction struct {
	Name       string
	ArgTypes   []*cel.Type
	ReturnType *cel.Type
	Binding    interface{}
}

// Option configures a CEL matcher backend at construction time.
type Option func(*Backend) error

// WithCostLimit enables the CEL runtime cost tracker and hard-limits each
// evaluation to limit cost units. Exceeding the limit aborts evaluation with a
// runtime error instead of returning a value.
func WithCostLimit(limit uint64) Option {
	return func(b *Backend) error {
		b.costLimit = &limit
		return nil
	}
}

// WithEvaluationContext sets the context used by plain Eval calls. EvalContext
// on a compiled matcher overrides it for a single evaluation. Defaults to
// context.Background().
func WithEvaluationContext(ctx context.Context) Option {
	return func(b *Backend) error {
		if ctx == nil {
			return validationError("evaluation context must not be nil", nil)
		}
		b.evalCtx = ctx
		return nil
	}
}

// WithInterruptCheckFrequency configures how often comprehension folds check
// for context cancellation.
func WithInterruptCheckFrequency(frequency uint) Option {
	return func(b *Backend) error {
		if frequency == 0 {
			return validationError("interrupt check frequency must be greater than zero", nil)
		}
		b.interruptFrequency = frequency
		return nil
	}
}

// Backend is the CEL implementation of matcher.Backend.
type Backend struct {
	mu                 sync.RWMutex
	functions          map[string]TypedFunction
	generation         uint64
	costLimit          *uint64
	evalCtx            context.Context
	interruptFrequency uint

	cache sync.Map // cacheKey -> *compiledMatcher
}

// NewBackend creates a CEL matcher backend with the built-in Casbin matching
// functions pre-declared and the supplied options applied.
func NewBackend(opts ...Option) (*Backend, error) {
	b := &Backend{
		functions:          make(map[string]TypedFunction),
		evalCtx:            context.Background(),
		interruptFrequency: defaultInterruptCheckFrequency,
	}
	for _, opt := range opts {
		if err := opt(b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// Language implements matcher.Backend.
func (b *Backend) Language() string {
	return matcher.LanguageCEL
}

// RegisterFunction adds or replaces a custom function with an explicit type
// signature. Replacing a function bumps the configuration generation, which
// invalidates previously compiled matchers referencing it.
func (b *Backend) RegisterFunction(tf TypedFunction) error {
	if err := validateTypedFunction(tf); err != nil {
		return err
	}
	b.mu.Lock()
	b.functions[tf.Name] = tf
	b.generation++
	b.mu.Unlock()
	return nil
}

// Generation returns the current typed-function configuration generation.
func (b *Backend) Generation() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.generation
}

// CachedEntries returns the number of distinct compiled matchers currently
// cached. It is intended for diagnostics and tests.
func (b *Backend) CachedEntries() int {
	count := 0
	b.cache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

func validateTypedFunction(tf TypedFunction) error {
	if tf.Name == "" {
		return validationError("typed function name must not be empty", nil)
	}
	if tf.ReturnType == nil {
		return validationError(fmt.Sprintf("typed function %s requires a return type", tf.Name), nil)
	}
	if len(tf.ArgTypes) == 0 {
		return validationError(fmt.Sprintf("typed function %s requires at least one argument", tf.Name), nil)
	}
	if tf.Binding == nil {
		return validationError(fmt.Sprintf("typed function %s requires a binding", tf.Name), nil)
	}
	fnType := reflect.TypeOf(tf.Binding)
	if fnType.Kind() != reflect.Func {
		return validationError(fmt.Sprintf("typed function %s binding must be a function, got %s", tf.Name, fnType), nil)
	}
	if fnType.NumIn() != len(tf.ArgTypes) {
		return validationError(fmt.Sprintf("typed function %s binding expects %d parameters, signature declares %d",
			tf.Name, fnType.NumIn(), len(tf.ArgTypes)), nil)
	}
	if fnType.NumOut() != 1 && !(fnType.NumOut() == 2 && fnType.Out(1) == reflect.TypeOf((*error)(nil)).Elem()) {
		return validationError(fmt.Sprintf("typed function %s binding must return %s or (%s, error)",
			tf.Name, tf.ReturnType.String(), tf.ReturnType.String()), nil)
	}
	for i, argType := range tf.ArgTypes {
		goType, ok := celGoType(argType)
		if !ok {
			return validationError(fmt.Sprintf("typed function %s argument %d uses unsupported CEL type %s",
				tf.Name, i, cel.FormatCELType(argType)), nil)
		}
		if !fnType.In(i).AssignableTo(goType) {
			return validationError(fmt.Sprintf("typed function %s binding parameter %d is %s, not assignable to CEL type %s",
				tf.Name, i, fnType.In(i), cel.FormatCELType(argType)), nil)
		}
	}
	returnGoType, ok := celGoType(tf.ReturnType)
	if !ok {
		return validationError(fmt.Sprintf("typed function %s uses unsupported return CEL type %s",
			tf.Name, cel.FormatCELType(tf.ReturnType)), nil)
	}
	if !fnType.Out(0).AssignableTo(returnGoType) {
		return validationError(fmt.Sprintf("typed function %s binding result is %s, not assignable to CEL type %s",
			tf.Name, fnType.Out(0), cel.FormatCELType(tf.ReturnType)), nil)
	}
	return nil
}

func celGoType(t *cel.Type) (reflect.Type, bool) {
	switch t {
	case cel.StringType:
		return reflect.TypeOf(""), true
	case cel.BoolType:
		return reflect.TypeOf(false), true
	case cel.IntType:
		return reflect.TypeOf(int64(0)), true
	case cel.UintType:
		return reflect.TypeOf(uint64(0)), true
	case cel.DoubleType:
		return reflect.TypeOf(float64(0)), true
	case cel.BytesType:
		return reflect.TypeOf([]byte(nil)), true
	case cel.DynType:
		return reflect.TypeOf((*interface{})(nil)).Elem(), true
	case cel.TimestampType:
		return reflect.TypeOf(time.Time{}), true
	case cel.DurationType:
		return reflect.TypeOf(time.Duration(0)), true
	}
	if t.Kind() == types.MapKind && t.Parameters()[0] == cel.StringType {
		return reflect.TypeOf(map[string]interface{}{}), true
	}
	if t.Kind() == types.ListKind {
		return reflect.TypeOf([]interface{}{}), true
	}
	return nil, false
}

// cacheKey is the full identity of a compilation. Request/policy values are
// intentionally absent; the key only describes static configuration.
type cacheKey struct {
	language   string
	expression string
	rTokens    string
	pTokens    string
	functions  string
	roles      string
	specGen    uint64
	regGen     uint64
}

// Compile implements matcher.Backend.
func (b *Backend) Compile(spec matcher.CompileSpec) (matcher.Compiled, error) {
	if strings.TrimSpace(spec.Expression) == "" {
		return nil, validationError("matcher expression must not be empty", nil)
	}
	if evalCallPattern.MatchString(spec.Expression) {
		return nil, validationError("dynamic eval() sub-expressions are not supported by the CEL matcher backend", nil)
	}

	b.mu.RLock()
	regGen := b.generation
	key := b.buildCacheKey(spec, regGen)
	b.mu.RUnlock()

	if cached, ok := b.cache.Load(key); ok {
		return cached.(*compiledMatcher), nil
	}

	compiled, err := b.compile(spec)
	if err != nil {
		return nil, err
	}
	// Another goroutine may have compiled the same spec concurrently; either
	// object is equivalent because the identity is identical.
	actual, _ := b.cache.LoadOrStore(key, compiled)
	return actual.(*compiledMatcher), nil
}

func (b *Backend) buildCacheKey(spec matcher.CompileSpec, regGen uint64) cacheKey {
	key := cacheKey{
		language:   matcher.LanguageCEL,
		expression: spec.Expression,
		rTokens:    strings.Join(spec.RTokens, ","),
		pTokens:    strings.Join(spec.PTokens, ","),
		specGen:    spec.Generation,
		regGen:     regGen,
	}

	functionSigs := make([]string, 0, len(b.functions))
	for name, tf := range b.functions {
		args := make([]string, len(tf.ArgTypes))
		for i, t := range tf.ArgTypes {
			args[i] = cel.FormatCELType(t)
		}
		functionSigs = append(functionSigs, name+"("+strings.Join(args, ",")+")->"+cel.FormatCELType(tf.ReturnType))
	}
	sort.Strings(functionSigs)
	key.functions = strings.Join(functionSigs, ";")

	roleSigs := make([]string, 0, len(spec.Roles))
	for _, role := range spec.Roles {
		roleSigs = append(roleSigs, fmt.Sprintf("%s/%d", role.Name, role.Arity))
	}
	sort.Strings(roleSigs)
	key.roles = strings.Join(roleSigs, ";")
	return key
}

func (b *Backend) compile(spec matcher.CompileSpec) (*compiledMatcher, error) {
	envOptions := []cel.EnvOption{cel.EagerlyValidateDeclarations(true)}

	// Request tokens hold arbitrary ABAC values (scalar/list/map/struct), so
	// they are declared as dyn. Policy tokens always hold strings.
	for _, token := range spec.RTokens {
		envOptions = append(envOptions, cel.Variable(token, cel.DynType))
	}
	for _, token := range spec.PTokens {
		envOptions = append(envOptions, cel.Variable(token, cel.StringType))
	}

	envOptions = append(envOptions, builtinDeclarations()...)

	b.mu.RLock()
	for _, tf := range b.functions {
		envOptions = append(envOptions, functionDecl(tf))
	}
	b.mu.RUnlock()

	for _, role := range spec.Roles {
		envOptions = append(envOptions, roleFunctionDecl(role))
	}

	env, err := cel.NewEnv(envOptions...)
	if err != nil {
		return nil, compilationError("failed to construct CEL environment", err)
	}

	ast, issues := env.Compile(spec.Expression)
	if issues != nil && issues.Err() != nil {
		return nil, compilationError("matcher failed CEL compilation: "+issues.String(), issues.Err())
	}
	if ast.OutputType() != cel.BoolType {
		return nil, compilationError(fmt.Sprintf("matcher must return bool, but the CEL result type is %s",
			cel.FormatCELType(ast.OutputType())), nil)
	}

	programOptions := []cel.ProgramOption{
		cel.InterruptCheckFrequency(b.interruptFrequency),
		// Track cost on every program so ActualCost is available; when a cost
		// limit is configured the tracker aborts evaluation on overflow.
		cel.EvalOptions(cel.OptTrackCost),
		cel.CustomDecorator(interruptDecorator()),
	}
	if b.costLimit != nil {
		programOptions = append(programOptions, cel.CostLimit(*b.costLimit))
	}

	prog, err := env.Program(ast, programOptions...)
	if err != nil {
		return nil, compilationError("failed to construct CEL program", err)
	}

	return &compiledMatcher{
		program: prog,
		rTokens: append([]string(nil), spec.RTokens...),
		pTokens: append([]string(nil), spec.PTokens...),
		evalCtx: b.evalCtx,
	}, nil
}

func functionDecl(tf TypedFunction) cel.EnvOption {
	op := nativeBinding(tf)
	overloadID := "casbin_user_" + tf.Name + "_" + fmt.Sprint(len(tf.ArgTypes))
	return cel.Function(tf.Name,
		cel.Overload(overloadID, tf.ArgTypes, tf.ReturnType, cel.FunctionBinding(op)),
	)
}

func nativeBinding(tf TypedFunction) functions.FunctionOp {
	fn := reflect.ValueOf(tf.Binding)
	hasError := fn.Type().NumOut() == 2
	return func(values ...ref.Val) ref.Val {
		args := make([]reflect.Value, len(values))
		for i, v := range values {
			args[i] = reflect.ValueOf(v.Value())
		}
		results := fn.Call(args)
		if hasError && !results[1].IsNil() {
			return types.NewErr("%s: %v", tf.Name, results[1].Interface().(error))
		}
		return types.DefaultTypeAdapter.NativeToValue(results[0].Interface())
	}
}

// compiledMatcher is a reusable CEL program bound to static token declarations.
type compiledMatcher struct {
	program cel.Program
	rTokens []string
	pTokens []string
	evalCtx context.Context
}

// Eval implements matcher.Compiled using the backend's default context.
func (c *compiledMatcher) Eval(rVals []interface{}, pVals []string) (bool, error) {
	return c.EvalContext(c.evalCtx, rVals, pVals)
}

// EvalContext implements matcher.ContextCompiled. The context governs this
// evaluation only; the shared program itself is not modified.
func (c *compiledMatcher) EvalContext(ctx context.Context, rVals []interface{}, pVals []string) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	vars := make(map[string]interface{}, len(c.rTokens)+len(c.pTokens))
	for i, token := range c.rTokens {
		if i < len(rVals) {
			vars[token] = normalizeValue(rVals[i])
		}
	}
	for i, token := range c.pTokens {
		if i < len(pVals) {
			vars[token] = pVals[i]
		}
	}

	baseActivation, actErr := cel.NewActivation(vars)
	if actErr != nil {
		return false, runtimeError("failed to build CEL activation", actErr)
	}
	activation := &contextActivation{parent: baseActivation, ctx: ctx}
	out, _, err := c.program.ContextEval(ctx, activation)
	if err != nil {
		var canceled interpreter.EvalCancelledError
		if errors.As(err, &canceled) {
			return false, runtimeError(canceled.Message, err)
		}
		return false, runtimeError("expression evaluation failed", err)
	}
	result, ok := out.Value().(bool)
	if !ok {
		return false, runtimeError(fmt.Sprintf("matcher returned non-bool result %v of type %T", out.Value(), out.Value()), nil)
	}
	return result, nil
}

// contextCarrier is implemented by the per-evaluation activation so the
// interrupt decorator can reach the evaluation context without storing any
// per-request state on the shared program.
type contextCarrier interface {
	CELContext() context.Context
}

type contextActivation struct {
	parent interpreter.Activation
	ctx    context.Context
}

func (a *contextActivation) ResolveName(name string) (interface{}, bool) {
	return a.parent.ResolveName(name)
}

func (a *contextActivation) Parent() interpreter.Activation {
	return a.parent
}

func (a *contextActivation) CELContext() context.Context {
	return a.ctx
}

// callInterrupt wraps CEL call nodes (operators and function invocations) and
// checks cancellation before each call. It complements the native fold-level
// interrupt checks performed by ContextEval.
type callInterrupt struct {
	interpreter.InterpretableCall
}

func (c *callInterrupt) Eval(activation interpreter.Activation) ref.Val {
	if err := carrierContext(activation).Err(); err != nil {
		panic(interpreter.EvalCancelledError{
			Cause:   interpreter.ContextCancelled,
			Message: "operation cancelled: " + err.Error(),
		})
	}
	return c.InterpretableCall.Eval(activation)
}

func carrierContext(activation interpreter.Activation) context.Context {
	for activation != nil {
		if carrier, ok := activation.(contextCarrier); ok {
			return carrier.CELContext()
		}
		activation = activation.Parent()
	}
	return context.Background()
}

func interruptDecorator() interpreter.InterpretableDecorator {
	return func(node interpreter.Interpretable) (interpreter.Interpretable, error) {
		if call, ok := node.(interpreter.InterpretableCall); ok {
			return &callInterrupt{InterpretableCall: call}, nil
		}
		return node, nil
	}
}
