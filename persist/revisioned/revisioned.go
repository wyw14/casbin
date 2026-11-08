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

// Package revisioned defines the revisioned watcher protocol.
//
// A revisioned watcher transports atomic policy mutation events that carry an
// epoch, a contiguous revision interval and an operation identifier together
// with the complete ordered mutation batch. Receivers apply a batch only when
// its from-revision matches the revision they currently hold, suppress
// duplicate deliveries, reject operation identifiers whose content conflicts
// with a previous delivery, rebootstrap on epoch changes and recover any gap by
// reloading an authoritative snapshot. Revisions are always produced by the
// commit source together with its persistence result; receiver processes never
// invent revisions from local counters.
//
// The package only defines the protocol and an in-process, testable memory
// implementation. No external message middleware is provided.
package revisioned

import (
	"errors"
	"strings"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// Sentinel errors shared by the revisioned watcher protocol.
var (
	// ErrInvalidEvent is returned when an event fails structural validation.
	ErrInvalidEvent = errors.New("revisioned watcher: invalid mutation event")
	// ErrOperationIDConflict is returned when the same operation ID is reused
	// with a different mutation batch.
	ErrOperationIDConflict = errors.New("revisioned watcher: operation ID reused with conflicting content")
	// ErrRevisionGap is returned when an event starts after the current revision.
	ErrRevisionGap = errors.New("revisioned watcher: revision gap detected")
	// ErrRevisionOverlap is returned when an event straddles the current revision.
	ErrRevisionOverlap = errors.New("revisioned watcher: revision interval overlaps current revision")
	// ErrStaleEvent is returned when an event is already covered by the model.
	ErrStaleEvent = errors.New("revisioned watcher: stale event already covered by the model")
	// ErrNotReady is returned when the receiver has no consistent model yet.
	ErrNotReady = errors.New("revisioned watcher: receiver model is not ready")
	// ErrBufferOverflow is returned when an in-memory delivery buffer is full.
	ErrBufferOverflow = errors.New("revisioned watcher: delivery buffer overflow")
	// ErrSnapshotUnavailable is returned when no authoritative snapshot exists.
	ErrSnapshotUnavailable = errors.New("revisioned watcher: authoritative snapshot is unavailable")
	// ErrWatcherClosed is returned when the watcher has been closed.
	ErrWatcherClosed = errors.New("revisioned watcher: watcher is closed")
)

// Revision points at one exact position of the authoritative commit history.
type Revision struct {
	// Epoch identifies the history lineage. It changes when the source reboots.
	Epoch uint64
	// Value is the contiguous revision number inside the epoch.
	Value uint64
}

// MutationEvent is an atomic policy change notification.
//
// The whole batch is the smallest apply unit: FromRevision must equal the
// receiver's current revision and ToRevision must be greater than
// FromRevision. Mutations stay ordered and must be applied in sequence.
type MutationEvent struct {
	// Epoch is the history lineage the event belongs to.
	Epoch uint64
	// FromRevision is the authoritative revision before this batch.
	FromRevision uint64
	// ToRevision is the authoritative revision after this batch.
	ToRevision uint64
	// OperationID uniquely identifies the committed batch for deduplication.
	OperationID string
	// Mutations is the complete, ordered batch of policy mutations.
	Mutations []persist.PolicyOperation
}

// Snapshot is the authoritative complete policy at a single revision.
type Snapshot struct {
	// Epoch is the history lineage the snapshot belongs to.
	Epoch uint64
	// Revision is the revision of the complete policy carried by the snapshot.
	Revision uint64
	// Policy is a fully populated model using the same revision system.
	Policy model.Model
}

// RevisionedWatcher strengthens Watcher with revisioned event delivery.
type RevisionedWatcher interface {
	persist.Watcher
	// SetRevisionedCallback registers the receiver-side event handler.
	SetRevisionedCallback(handler func(*MutationEvent) error) error
	// PublishRevisionedEvent delivers a committed, fully revisioned event.
	//
	// Implementations must never deliver the event back to its originator, so
	// receiver-side synchronization cannot trigger a broadcast loop.
	PublishRevisionedEvent(event *MutationEvent) error
}

// SnapshotSource provides authoritative snapshots for gap recovery and
// epoch rebootstrap.
type SnapshotSource interface {
	// LoadRevisionedSnapshot returns the complete policy at the latest revision.
	LoadRevisionedSnapshot() (*Snapshot, error)
}

// Validate checks the structural invariants of a mutation event.
func (event *MutationEvent) Validate() error {
	if event == nil {
		return ErrInvalidEvent
	}
	if event.OperationID == "" {
		return ErrInvalidEvent
	}
	if event.ToRevision <= event.FromRevision {
		return ErrInvalidEvent
	}
	if len(event.Mutations) == 0 {
		return ErrInvalidEvent
	}
	for i := range event.Mutations {
		if err := event.Mutations[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Clone returns a deep copy of the event so callers can retain it safely.
func (event *MutationEvent) Clone() *MutationEvent {
	if event == nil {
		return nil
	}
	cloned := &MutationEvent{
		Epoch:        event.Epoch,
		FromRevision: event.FromRevision,
		ToRevision:   event.ToRevision,
		OperationID:  event.OperationID,
		Mutations:    make([]persist.PolicyOperation, len(event.Mutations)),
	}
	for i, mutation := range event.Mutations {
		cloned.Mutations[i] = CloneMutation(mutation)
	}
	return cloned
}

// CloneMutation returns a deep copy of a single policy operation.
func CloneMutation(mutation persist.PolicyOperation) persist.PolicyOperation {
	return persist.PolicyOperation{
		Type:       mutation.Type,
		Section:    mutation.Section,
		PolicyType: mutation.PolicyType,
		Rules:      cloneRules(mutation.Rules),
		OldRules:   cloneRules(mutation.OldRules),
	}
}

func cloneRules(rules [][]string) [][]string {
	if rules == nil {
		return nil
	}
	cloned := make([][]string, len(rules))
	for i, rule := range rules {
		cloned[i] = append([]string(nil), rule...)
	}
	return cloned
}

// EventDigest builds a deterministic content fingerprint for an event.
//
// Two events with the same operation ID and the same digest are exact
// duplicates; the same ID with different digests is a protocol conflict.
func EventDigest(event *MutationEvent) string {
	var builder strings.Builder
	for _, mutation := range event.Mutations {
		builder.WriteString(encodeRules(mutation.OldRules))
		builder.WriteString(encodeRules(mutation.Rules))
		builder.WriteString("|")
		builder.WriteString(mutation.Section)
		builder.WriteString("/")
		builder.WriteString(mutation.PolicyType)
		builder.WriteString("/")
		builder.WriteByte(byte('0' + int(mutation.Type)))
		builder.WriteString(";")
	}
	return builder.String()
}

func encodeRules(rules [][]string) string {
	var builder strings.Builder
	for _, rule := range rules {
		builder.WriteString(strings.Join(rule, ","))
		builder.WriteString(";")
	}
	return builder.String()
}

// TouchesGrouping reports whether any mutation changes a grouping policy.
func TouchesGrouping(event *MutationEvent) bool {
	for i := range event.Mutations {
		if event.Mutations[i].Section == "g" {
			return true
		}
	}
	return false
}
