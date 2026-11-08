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
	"sync"
	"sync/atomic"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// DefaultWatcherBuffer is the default per-watcher delivery buffer capacity.
const DefaultWatcherBuffer = 128

// Compile-time protocol compliance checks.
var (
	_ SnapshotSource    = (*MemoryRevisionStore)(nil)
	_ RevisionedWatcher = (*MemoryWatcher)(nil)
	_ persist.Watcher   = (*MemoryWatcher)(nil)
)

// MemoryRevisionStore is an in-process authoritative commit source.
//
// It validates each committed batch against a candidate model, persists the
// result atomically together with the new revision, and only then fans the
// fully revisioned event out to subscribers. The revision is produced by this
// store as the commit source together with its persistence result; subscriber
// processes never generate revisions themselves.
type MemoryRevisionStore struct {
	mu       sync.Mutex
	epoch    uint64
	revision uint64
	schema   model.Model
	policy   model.Model
	log      []*MutationEvent
	watchers []*MemoryWatcher
	wg       sync.WaitGroup
}

// NewMemoryRevisionStore creates a store seeded with an initial model.
//
// The initial model is exposed as revision zero of epoch one.
func NewMemoryRevisionStore(initial model.Model) *MemoryRevisionStore {
	seed := initial.Copy()
	return &MemoryRevisionStore{
		epoch:    1,
		revision: 0,
		schema:   initial.Copy(),
		policy:   seed,
		log:      make([]*MutationEvent, 0),
		watchers: make([]*MemoryWatcher, 0),
	}
}

// CurrentRevision returns the authoritative epoch and revision.
func (store *MemoryRevisionStore) CurrentRevision() Revision {
	store.mu.Lock()
	defer store.mu.Unlock()
	return Revision{Epoch: store.epoch, Value: store.revision}
}

// Commit validates, persists and publishes one ordered mutation batch.
//
// Re-committing a known operation ID with identical content is idempotent and
// returns the original event. The same operation ID with different content is
// rejected with ErrOperationIDConflict.
func (store *MemoryRevisionStore) Commit(operationID string,
	mutations []persist.PolicyOperation) (*MutationEvent, error) {
	if operationID == "" || len(mutations) == 0 {
		return nil, ErrInvalidEvent
	}

	store.mu.Lock()
	if event, err := store.lookupOperation(operationID, mutations); err != nil || event != nil {
		store.mu.Unlock()
		return event, err
	}

	candidate := store.policy.Copy()
	if err := ApplyMutationsToModel(candidate, mutations); err != nil {
		store.mu.Unlock()
		return nil, err
	}

	fromRevision := store.revision
	store.revision++
	event := &MutationEvent{
		Epoch:        store.epoch,
		FromRevision: fromRevision,
		ToRevision:   store.revision,
		OperationID:  operationID,
		Mutations:    cloneMutationSlice(mutations),
	}
	// Persistence result and the new revision are installed together.
	store.policy = candidate
	store.log = append(store.log, event.Clone())
	watchers := append([]*MemoryWatcher(nil), store.watchers...)
	store.mu.Unlock()

	for _, watcher := range watchers {
		_ = watcher.deliver(event)
	}
	return event.Clone(), nil
}

func (store *MemoryRevisionStore) lookupOperation(operationID string,
	mutations []persist.PolicyOperation) (*MutationEvent, error) {
	for _, committed := range store.log {
		if committed.OperationID != operationID {
			continue
		}
		probe := &MutationEvent{Mutations: mutations}
		if EventDigest(committed) != EventDigest(probe) {
			return nil, ErrOperationIDConflict
		}
		return committed.Clone(), nil
	}
	return nil, nil
}

// LoadRevisionedSnapshot returns a deep copy of the complete current policy.
func (store *MemoryRevisionStore) LoadRevisionedSnapshot() (*Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return &Snapshot{
		Epoch:    store.epoch,
		Revision: store.revision,
		Policy:   store.policy.Copy(),
	}, nil
}

// CommitLog returns a deep copy of the committed event history.
func (store *MemoryRevisionStore) CommitLog() []*MutationEvent {
	store.mu.Lock()
	defer store.mu.Unlock()
	log := make([]*MutationEvent, len(store.log))
	for i, event := range store.log {
		log[i] = event.Clone()
	}
	return log
}

// ResetEpoch starts a new history lineage and resets the revision to zero.
//
// A nil initial policy reuses the stored schema with an empty policy.
func (store *MemoryRevisionStore) ResetEpoch(initial model.Model) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.epoch++
	store.revision = 0
	store.log = store.log[:0]
	if initial != nil {
		store.policy = initial.Copy()
		return
	}
	store.policy = store.schema.Copy()
	store.policy.ClearPolicy()
}

// NewWatcher attaches a buffered in-memory watcher to the store.
func (store *MemoryRevisionStore) NewWatcher(bufferCapacity int) *MemoryWatcher {
	if bufferCapacity <= 0 {
		bufferCapacity = DefaultWatcherBuffer
	}
	watcher := &MemoryWatcher{
		store: store,
		ch:    make(chan *MutationEvent, bufferCapacity),
	}
	store.mu.Lock()
	store.watchers = append(store.watchers, watcher)
	store.mu.Unlock()
	go watcher.pump()
	return watcher
}

func (store *MemoryRevisionStore) removeWatcher(target *MemoryWatcher) {
	store.mu.Lock()
	defer store.mu.Unlock()
	watchers := store.watchers[:0]
	for _, watcher := range store.watchers {
		if watcher != target {
			watchers = append(watchers, watcher)
		}
	}
	store.watchers = watchers
}

// WaitIdle blocks until every delivered event has been handled.
func (store *MemoryRevisionStore) WaitIdle() {
	store.wg.Wait()
}

func cloneMutationSlice(mutations []persist.PolicyOperation) []persist.PolicyOperation {
	cloned := make([]persist.PolicyOperation, len(mutations))
	for i, mutation := range mutations {
		cloned[i] = CloneMutation(mutation)
	}
	return cloned
}

// MemoryWatcher is an in-process RevisionedWatcher fed by a MemoryRevisionStore.
type MemoryWatcher struct {
	store     *MemoryRevisionStore
	ch        chan *MutationEvent
	mu        sync.Mutex
	callback  func(*MutationEvent) error
	genericCB func(string)
	closed    int32
	closeOnce sync.Once
}

// SetRevisionedCallback registers the receiver-side event handler.
func (watcher *MemoryWatcher) SetRevisionedCallback(
	handler func(*MutationEvent) error) error {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	watcher.callback = handler
	return nil
}

// SetUpdateCallback registers the classic Watcher compatibility callback.
func (watcher *MemoryWatcher) SetUpdateCallback(callback func(string)) error {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	watcher.genericCB = callback
	return nil
}

// PublishRevisionedEvent delivers an event to this local watcher only.
//
// It never re-enters the commit store and never fans out to peers, so a
// receiver cannot trigger a broadcast loop while synchronizing.
func (watcher *MemoryWatcher) PublishRevisionedEvent(event *MutationEvent) error {
	if event == nil {
		return ErrInvalidEvent
	}
	return watcher.deliver(event.Clone())
}

// Update invokes the classic Watcher compatibility callback.
func (watcher *MemoryWatcher) Update() error {
	watcher.mu.Lock()
	callback := watcher.genericCB
	watcher.mu.Unlock()
	if callback != nil {
		callback("")
	}
	return nil
}

// Close detaches the watcher and stops its delivery pump.
func (watcher *MemoryWatcher) Close() {
	watcher.closeOnce.Do(func() {
		atomic.StoreInt32(&watcher.closed, 1)
		watcher.store.removeWatcher(watcher)
		close(watcher.ch)
	})
}

func (watcher *MemoryWatcher) deliver(event *MutationEvent) error {
	if atomic.LoadInt32(&watcher.closed) != 0 {
		return ErrWatcherClosed
	}
	watcher.store.wg.Add(1)
	select {
	case watcher.ch <- event:
		return nil
	default:
		watcher.store.wg.Done()
		return ErrBufferOverflow
	}
}

func (watcher *MemoryWatcher) pump() {
	for event := range watcher.ch {
		watcher.mu.Lock()
		callback := watcher.callback
		watcher.mu.Unlock()
		if callback != nil {
			_ = callback(event)
		}
		watcher.store.wg.Done()
	}
}
