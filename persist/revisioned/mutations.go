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

package revisioned

import (
	"fmt"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// ApplyMutationsToModel validates and applies an ordered mutation batch onto a
// candidate model.
//
// The candidate is the only state being touched, so a failed validation leaves
// the live model, role graph and decision caches untouched. Commit sources and
// receivers share this function to guarantee identical validation semantics.
func ApplyMutationsToModel(candidate model.Model, mutations []persist.PolicyOperation) error {
	for i := range mutations {
		if err := mutations[i].Validate(); err != nil {
			return err
		}
		var err error
		switch mutations[i].Type {
		case persist.OperationAdd:
			err = applyAddMutation(candidate, mutations[i])
		case persist.OperationRemove:
			err = applyRemoveMutation(candidate, mutations[i])
		case persist.OperationUpdate:
			err = applyUpdateMutation(candidate, mutations[i])
		default:
			return persist.ErrInvalidPolicyOperation
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func applyAddMutation(candidate model.Model, mutation persist.PolicyOperation) error {
	for _, rule := range mutation.Rules {
		hasPolicy, err := candidate.HasPolicyEx(mutation.Section, mutation.PolicyType, rule)
		if err != nil {
			return err
		}
		if hasPolicy {
			// Re-adding an existing rule is a no-op, mirroring model semantics.
			continue
		}
		if err := candidate.AddPolicy(mutation.Section, mutation.PolicyType, rule); err != nil {
			return err
		}
	}
	return nil
}

func applyRemoveMutation(candidate model.Model, mutation persist.PolicyOperation) error {
	for _, rule := range mutation.Rules {
		hasPolicy, err := candidate.HasPolicyEx(mutation.Section, mutation.PolicyType, rule)
		if err != nil {
			return err
		}
		if !hasPolicy {
			return fmt.Errorf("revisioned watcher: cannot remove missing rule %v from %s/%s",
				rule, mutation.Section, mutation.PolicyType)
		}
		if _, err := candidate.RemovePolicy(mutation.Section, mutation.PolicyType, rule); err != nil {
			return err
		}
	}
	return nil
}

func applyUpdateMutation(candidate model.Model, mutation persist.PolicyOperation) error {
	for _, newRule := range mutation.Rules {
		if _, err := candidate.HasPolicyEx(mutation.Section, mutation.PolicyType, newRule); err != nil {
			return err
		}
	}
	for _, oldRule := range mutation.OldRules {
		if _, err := candidate.HasPolicyEx(mutation.Section, mutation.PolicyType, oldRule); err != nil {
			return err
		}
	}
	updated, err := candidate.UpdatePolicies(mutation.Section, mutation.PolicyType,
		mutation.OldRules, mutation.Rules)
	if err != nil {
		return err
	}
	if !updated {
		return fmt.Errorf("revisioned watcher: cannot update missing rules in %s/%s",
			mutation.Section, mutation.PolicyType)
	}
	return nil
}
