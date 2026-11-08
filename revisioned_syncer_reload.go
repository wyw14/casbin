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
	"github.com/casbin/casbin/v3/persist/revisioned"
)

// runReloadLoop recovers a consistent model from authoritative snapshots.
//
// The snapshot fetch happens without holding the receiver lock, so events that
// arrive during the fetch are bounded-cached by concurrent HandleEvent calls.
// On failure the previous complete model stays installed and the receiver is
// marked not ready; the old model is never advertised as the latest state.
func (s *RevisionedSyncer) runReloadLoop() error {
	s.reloadActive = true
	s.reloadCount++
	for {
		snapshot, err := s.fetchSnapshot()
		if err != nil {
			s.ready = false
			s.reloadActive = false
			return err
		}
		if err = s.installSnapshot(snapshot); err != nil {
			s.ready = false
			s.reloadActive = false
			return err
		}
		s.adoptSnapshotRevision(snapshot)

		if s.overflowed {
			// The buffer evicted events: a fresher snapshot must cover them.
			s.overflowed = false
			s.pending = s.pending[:0]
			continue
		}
		gapRemains, err := s.replayPending()
		if err != nil {
			s.reloadActive = false
			return err
		}
		if !gapRemains {
			s.ready = true
			s.reloadActive = false
			return nil
		}
	}
}

func (s *RevisionedSyncer) fetchSnapshot() (*revisioned.Snapshot, error) {
	s.mu.Unlock()
	defer s.mu.Lock()
	snapshot, err := s.source.LoadRevisionedSnapshot()
	s.snapshotLoads++
	return snapshot, err
}

func (s *RevisionedSyncer) adoptSnapshotRevision(snapshot *revisioned.Snapshot) {
	if snapshot.Epoch != s.epoch {
		// Identifiers from a previous lineage must not shadow new events.
		s.seen = make(map[string]string)
	}
	s.epoch = snapshot.Epoch
	s.revision = snapshot.Revision
}

func (s *RevisionedSyncer) installSnapshot(snapshot *revisioned.Snapshot) error {
	candidate := snapshot.Policy.Copy()
	enforcerLock := s.enforcer.GetLock()
	enforcerLock.Lock()
	defer enforcerLock.Unlock()

	if err := s.enforcer.applyModifiedModel(candidate); err != nil {
		return err
	}
	// Best-effort explicit invalidation: the policyVersion bump inside
	// applyModifiedModel is the authoritative path for flushing stale decisions.
	_ = s.invalidateDecisionCache()
	return nil
}

// replayPending applies buffered events at the snapshot cut point.
//
// Events already covered by the snapshot are deduplicated, events of a stale
// epoch are discarded and a remaining gap forces another snapshot fetch.
func (s *RevisionedSyncer) replayPending() (bool, error) {
	remaining := make([]*revisioned.MutationEvent, 0)
	for i, event := range s.pending {
		if event.Epoch != s.epoch {
			continue
		}
		digest := revisioned.EventDigest(event)
		if existing, ok := s.seen[event.OperationID]; ok {
			if existing != digest {
				s.conflictEvents++
				s.pending = remaining
				return false, revisioned.ErrOperationIDConflict
			}
			s.duplicateEvents++
			continue
		}
		if event.ToRevision <= s.revision {
			// The snapshot already contains this batch.
			s.seen[event.OperationID] = digest
			s.duplicateEvents++
			continue
		}
		if event.FromRevision != s.revision {
			remaining = append(remaining, s.pending[i:]...)
			s.pending = remaining
			return true, nil
		}
		if err := s.applyEvent(event, digest); err != nil {
			s.pending = remaining
			return false, err
		}
	}
	s.pending = s.pending[:0]
	return false, nil
}
