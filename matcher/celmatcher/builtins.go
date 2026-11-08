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
	"fmt"

	"github.com/casbin/casbin/v3/matcher"
	"github.com/casbin/casbin/v3/util"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// govaluateStyleFunc adapts a Casbin util.*Func (the govaluate ExpressionFunction
// shape) to a CEL variadic binding. CEL overload resolution already guarantees
// argument count and types, so errors from the underlying implementation are
// surfaced as CEL runtime errors instead of being folded into a false result.
func govaluateStyleFunc(fn func(args ...interface{}) (interface{}, error)) functions.FunctionOp {
	return func(values ...ref.Val) ref.Val {
		args := make([]interface{}, len(values))
		for i, v := range values {
			args[i] = v.Value()
		}
		result, err := fn(args...)
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.DefaultTypeAdapter.NativeToValue(result)
	}
}

// binaryStringBool declares name(string, string) -> bool.
func binaryStringBool(name string, fn func(args ...interface{}) (interface{}, error)) cel.EnvOption {
	return cel.Function(name,
		cel.Overload("casbin_"+name+"_string_string_bool",
			[]*cel.Type{cel.StringType, cel.StringType},
			cel.BoolType,
			cel.FunctionBinding(govaluateStyleFunc(fn)),
		),
	)
}

// ternaryStringString declares name(string, string, string) -> string.
func ternaryStringString(name string, fn func(args ...interface{}) (interface{}, error)) cel.EnvOption {
	return cel.Function(name,
		cel.Overload("casbin_"+name+"_string_string_string_string",
			[]*cel.Type{cel.StringType, cel.StringType, cel.StringType},
			cel.StringType,
			cel.FunctionBinding(govaluateStyleFunc(fn)),
		),
	)
}

// builtinDeclarations returns the explicit, statically typed declarations of
// the Casbin built-in matching functions. Every overload has a concrete
// signature; there is no dynamically typed catch-all.
func builtinDeclarations() []cel.EnvOption {
	return []cel.EnvOption{
		binaryStringBool("keyMatch", util.KeyMatchFunc),
		binaryStringBool("keyMatch2", util.KeyMatch2Func),
		binaryStringBool("keyMatch3", util.KeyMatch3Func),
		binaryStringBool("keyMatch4", util.KeyMatch4Func),
		binaryStringBool("keyMatch5", util.KeyMatch5Func),
		binaryStringBool("regexMatch", util.RegexMatchFunc),
		binaryStringBool("ipMatch", util.IPMatchFunc),
		binaryStringBool("globMatch", util.GlobMatchFunc),

		binaryStringBool("keyGet", util.KeyGetFunc),
		ternaryStringString("keyGet2", util.KeyGet2Func),
		ternaryStringString("keyGet3", util.KeyGet3Func),
	}
}

// roleFunctionDecl declares a g-style role function with the two statically
// known arities (2 and 3, the latter carrying the domain). Both overloads
// delegate to the same live role-manager binding, preserving the arity,
// domain and conditional-role semantics of the govaluate g function.
func roleFunctionDecl(role matcher.RoleFunction) cel.EnvOption {
	binding := func(values ...ref.Val) ref.Val {
		args := make([]string, len(values))
		for i, v := range values {
			s, ok := v.Value().(string)
			if !ok {
				return types.NewErr("role function %s expects string arguments, got %T", role.Name, v.Value())
			}
			args[i] = s
		}
		matched, err := role.Binding(args...)
		if err != nil {
			return types.NewErr("%s: %v", role.Name, err)
		}
		return types.Bool(matched)
	}
	return cel.Function(role.Name,
		cel.Overload(fmt.Sprintf("casbin_%s_string_string_bool", role.Name),
			[]*cel.Type{cel.StringType, cel.StringType},
			cel.BoolType,
			cel.FunctionBinding(binding),
		),
		cel.Overload(fmt.Sprintf("casbin_%s_string_string_string_bool", role.Name),
			[]*cel.Type{cel.StringType, cel.StringType, cel.StringType},
			cel.BoolType,
			cel.FunctionBinding(binding),
		),
	)
}
