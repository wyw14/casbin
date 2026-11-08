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
	"reflect"
	"time"
)

// maxNormalizeDepth bounds recursive ABAC value normalization so cyclic
// structures fail fast instead of overflowing the stack.
const maxNormalizeDepth = 32

// normalizeValue converts the conventional Casbin ABAC request values
// (scalars, lists, maps and plain Go structs) into the canonical Go shapes
// understood by the CEL runtime:
//
//   - scalars (string, bool, int*/uint*/float*, []byte, time.Time) pass through;
//   - slices and arrays become []interface{} with normalized elements;
//   - map[string]T becomes map[string]interface{} with normalized elements;
//   - plain structs (and pointers to them) become map[string]interface{} keyed
//     by exported field name, so field selection follows the same r_obj.Owner
//     convention as the govaluate backend.
//
// Selecting a missing key on a normalized map produces a genuine CEL runtime
// "no such key" error; the value is never silently coerced to false.
func normalizeValue(value interface{}) interface{} {
	return normalize(reflect.ValueOf(value), 0)
}

func normalize(v reflect.Value, depth int) interface{} {
	if !v.IsValid() {
		return nil
	}
	if depth > maxNormalizeDepth {
		return v.Interface()
	}

	// Unwrap pointers and interfaces.
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Struct:
		// time.Time is natively understood by CEL as a timestamp.
		if t, ok := v.Interface().(time.Time); ok {
			return t
		}
		return structToMap(v, depth)
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			// Keep []byte as CEL bytes rather than a list of integers.
			return v.Interface()
		}
		out := make([]interface{}, v.Len())
		for i := 0; i < v.Len(); i++ {
			out[i] = normalize(v.Index(i), depth+1)
		}
		return out
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			// Non-string-keyed maps are outside the Casbin ABAC convention;
			// leave them to CEL's dynamic map support.
			return v.Interface()
		}
		out := make(map[string]interface{}, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out[iter.Key().String()] = normalize(iter.Value(), depth+1)
		}
		return out
	default:
		return v.Interface()
	}
}

func structToMap(v reflect.Value, depth int) map[string]interface{} {
	t := v.Type()
	out := make(map[string]interface{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			// Unexported field, skip.
			continue
		}
		out[field.Name] = normalize(v.Field(i), depth+1)
	}
	return out
}
