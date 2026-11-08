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

// Category classifies a matcher error by the phase in which it arose.
type Category int

const (
	// CompilationError covers parse and type-check failures: syntax errors,
	// unknown variables, undeclared functions, overload resolution failures
	// and matchers whose result type is not bool.
	CompilationError Category = iota + 1
	// ValidationError covers configuration that is rejected before the CEL
	// compiler runs, e.g. dynamic eval() sub-expressions or invalid typed
	// function registrations.
	ValidationError
	// RuntimeError covers failures while evaluating a successfully compiled
	// matcher: missing map fields, runtime type mismatches, function binding
	// errors, cost limit exhaustion and context cancellation.
	RuntimeError
)

// String returns the stable category name used in error messages.
func (c Category) String() string {
	switch c {
	case CompilationError:
		return "Compilation"
	case ValidationError:
		return "Validation"
	case RuntimeError:
		return "Runtime"
	default:
		return "Unknown"
	}
}

// Error is the categorized error type returned by the CEL matcher backend.
// Callers can use errors.As to inspect the Category while Unwrap preserves
// the underlying CEL error for detailed diagnosis.
type Error struct {
	Category Category
	Message  string
	Cause    error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return "cel matcher " + e.Category.String() + " error: " + e.Message + ": " + e.Cause.Error()
	}
	return "cel matcher " + e.Category.String() + " error: " + e.Message
}

func (e *Error) Unwrap() error {
	return e.Cause
}

func compilationError(message string, cause error) *Error {
	return &Error{Category: CompilationError, Message: message, Cause: cause}
}

func validationError(message string, cause error) *Error {
	return &Error{Category: ValidationError, Message: message, Cause: cause}
}

func runtimeError(message string, cause error) *Error {
	return &Error{Category: RuntimeError, Message: message, Cause: cause}
}
