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
	"sync"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist/revisioned"
)

// defaultPendingCapacity is the default bound on events cached while a
// snapshot reload is in progress.
const defaultPendingCapacity = 64

// RevisionedSyncer drives an enforcer as a receiver of revisioned policy
// events.
//
// It recognizes duplicate, out-of-order and missing events, rebootstraps on
// epoch changes and recovers gaps through authoritative snapshot reloads.
// Synchronization only mutates the in-memory model, role graph and decision
// cache: it never writes the adapter again and never broadcasts to the
// watcher, so receive-side processing cannot form a feedback loop.
type RevisionedSyncer struct {
	enforcer *SyncedEnforcer
	source   revisioned.SnapshotSource

	mu           sync.Mutex
	ready        bool
	reloadActive bool
	overflowed   bool
	epoch        uint64
	revision     uint64
	seen         map[string]string
	pending      []*revisioned.MutationEvent
	pendingCap   int

	appliedEvents   int
	duplicateEvents int
	conflictEvents  int
	gapEvents       int
	reloadCount     int
	snapshotLoads   int

	cacheInvalidator func() error
}

// NewRevisionedSyncer creates a receiver bound to a synced enforcer and an
// authoritative snapshot source.
//
// A non-positive pending capacity falls back to defaultPendingCapacity.
func NewRevisionedSyncer(enforcer *SyncedEnforcer, source revisioned.SnapshotSource,
	pendingCapacity int) *RevisionedSyncer {
	if pendingCapacity <= 0 {
		pendingCapacity = defaultPendingCapacity
	}
	return &RevisionedSyncer{
		enforcer:   enforcer,
		source:     source,
		seen:       make(map[string]string),
		pending:    make([]*revisioned.MutationEvent, 0, pendingCapacity),
		pendingCap: pendingCapacity,
	}
}

// WithCacheInvalidator registers an explicit decision cache invalidation hook.
//
// The hook runs only after a batch or snapshot has been fully committed, never
// while a candidate model is still being validated.
func (s *RevisionedSyncer) WithCacheInvalidator(invalidator func() error) *RevisionedSyncer {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cacheInvalidator = invalidator
	return s
}

// BindWatcher registers the receiver callback on a revisioned watcher.
func (s *RevisionedSyncer) BindWatcher(watcher revisioned.RevisionedWatcher) error {
	return watcher.SetRevisionedCallback(s.HandleEvent)
}

// Bootstrap loads the first authoritative snapshot and marks the receiver ready.
func (s *RevisionedSyncer) Bootstrap() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runReloadLoop()
}

// RetryReload retries snapshot recovery after a previous reload failure.
func (s *RevisionedSyncer) RetryReload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reloadActive {
		return nil
	}
	return s.runReloadLoop()
}

// HandleEvent is the receiver-side entry point for revisioned events.
func (s *RevisionedSyncer) HandleEvent(event *revisioned.MutationEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.ready || s.reloadActive {
		s.bufferEvent(event)
		if !s.reloadActive {
			return s.runReloadLoop()
		}
		return nil
	}
	if event.Epoch != s.epoch {
		// A new history lineage requires rebootstrap before any event applies.
		s.bufferEvent(event)
		return s.runReloadLoop()
	}
	return s.handleSameEpochEvent(event)
}

func (s *RevisionedSyncer) handleSameEpochEvent(event *revisioned.MutationEvent) error {
	digest := revisioned.EventDigest(event)
	if existing, ok := s.seen[event.OperationID]; ok {
		if existing != digest {
			s.conflictEvents++
			return revisioned.ErrOperationIDConflict
		}
		// Exact duplicates are acknowledged but never applied twice.
		s.duplicateEvents++
		return nil
	}
	switch {
	case event.FromRevision == s.revision:
		return s.applyEvent(event, digest)
	case event.FromRevision > s.revision:
		s.gapEvents++
		s.bufferEvent(event)
		return s.runReloadLoop()
	case event.ToRevision <= s.revision:
		return revisioned.ErrStaleEvent
	default:
		return revisioned.ErrRevisionOverlap
	}
}

// IsReady reports whether a consistent model is currently installed.
func (s *RevisionedSyncer) IsReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready
}

// Status returns the installed revision and the readiness flag.
func (s *RevisionedSyncer) Status() (revisioned.Revision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return revisioned.Revision{Epoch: s.epoch, Value: s.revision}, s.ready
}

// PendingCount returns the number of events buffered for reload replay.
func (s *RevisionedSyncer) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// Stats returns counters describing receiver behavior since startup.
func (s *RevisionedSyncer) Stats() RevisionedSyncStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return RevisionedSyncStats{
		AppliedEvents:   s.appliedEvents,
		DuplicateEvents: s.duplicateEvents,
		ConflictEvents:  s.conflictEvents,
		GapEvents:       s.gapEvents,
		ReloadCount:     s.reloadCount,
		SnapshotLoads:   s.snapshotLoads,
	}
}

// RevisionedSyncStats exposes receiver counters for tests and observability.
type RevisionedSyncStats struct {
	AppliedEvents   int
	DuplicateEvents int
	ConflictEvents  int
	GapEvents       int
	ReloadCount     int
	SnapshotLoads   int
}

func (s *RevisionedSyncer) bufferEvent(event *revisioned.MutationEvent) {
	if len(s.pending) >= s.pendingCap {
		// Evict the oldest event and demand a fresher snapshot instead of
		// silently dropping the newest update.
		s.pending = append(s.pending[1:], event.Clone())
		s.overflowed = true
		return
	}
	s.pending = append(s.pending, event.Clone())
}

func (s *RevisionedSyncer) invalidateDecisionCache() error {
	if s.cacheInvalidator != nil {
		return s.cacheInvalidator()
	}
	return nil
}

// applyEvent validates the whole batch on a candidate model and swaps the
// enforcer state only after every mutation and the role graph succeed.
func (s *RevisionedSyncer) applyEvent(event *revisioned.MutationEvent, digest string) error {
	candidate := s.enforcer.model.Copy()
	if err := revisioned.ApplyMutationsToModel(candidate, event.Mutations); err != nil {
		return err
	}

	enforcerLock := s.enforcer.GetLock()
	enforcerLock.Lock()
	defer enforcerLock.Unlock()

	if err := s.prepareRoleGraph(candidate, event); err != nil {
		return err
	}
	s.enforcer.model = candidate
	s.enforcer.resetPolicyCaches()
	s.enforcer.invalidateMatcherMap()
	// The swap is already irreversible, so advance the revision before running
	// the optional cache hook. The policyVersion bump above already guarantees
	// stale decisions are flushed on the next Enforce even if the hook fails.
	s.revision = event.ToRevision
	s.seen[event.OperationID] = digest
	s.appliedEvents++
	return s.invalidateDecisionCache()
}

func (s *RevisionedSyncer) prepareRoleGraph(candidate model.Model,
	event *revisioned.MutationEvent) error {
	if !revisioned.TouchesGrouping(event) || !s.enforcer.autoBuildRoleLinks {
		return nil
	}
	if err := s.enforcer.rebuildRoleLinks(candidate); err != nil {
		_ = s.enforcer.rebuildRoleLinks(s.enforcer.model)
		return err
	}
	if err := s.enforcer.rebuildConditionalRoleLinks(candidate); err != nil {
		_ = s.enforcer.rebuildRoleLinks(s.enforcer.model)
		_ = s.enforcer.rebuildConditionalRoleLinks(s.enforcer.model)
		return err
	}
	return nil
}
