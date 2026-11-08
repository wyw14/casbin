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
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/casbin/casbin/v3/effector"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/rbac"
	defaultrolemanager "github.com/casbin/casbin/v3/rbac/default-role-manager"
	"github.com/casbin/govaluate"
)

const (
	// defaultImpactBatchSize bounds the number of corpus requests evaluated
	// between cancellation checks when the caller does not specify a batch size.
	defaultImpactBatchSize = 256

	// ImpactAnalysisScopeStatement is attached to every impact report. It makes
	// clear that the report is scoped to the finite, explicitly provided request
	// corpus: the analysis is not a transaction commit and is not a proof that
	// permissions stay unchanged or non-expanded for any other possible request.
	ImpactAnalysisScopeStatement = "PolicyImpactAnalyzer results describe only the " +
		"explicitly provided finite request corpus; they are not a proof that permissions " +
		"are unchanged or non-expanded for any other possible request, and they do not " +
		"commit any policy change."
)

var (
	// ErrImpactAnalysisContract is returned when the live enforcer uses custom
	// functions, role managers or effectors without an explicit pure, cloneable
	// or freezable analysis contract.
	ErrImpactAnalysisContract = errors.New("policy impact analysis contract error")

	// ErrInvalidPolicyPatch is returned when a candidate patch references
	// unknown sections or policy types, has malformed rules, or targets rules
	// that do not exist (remove/update) or already exist (add).
	ErrInvalidPolicyPatch = errors.New("invalid policy impact patch")

	// ErrBaselineDivergence is returned by the optional baseline verification
	// when an isolated baseline enforcer reaches a different decision than the
	// live enforcer, which indicates a missing analysis contract.
	ErrBaselineDivergence = errors.New("isolated baseline diverges from live enforcer")

	// ErrSnapshotChanged is returned when the live policy generation changes
	// while the optional baseline verification is still running.
	ErrSnapshotChanged = errors.New("live policy generation changed during analysis")
)

// PatchOpType identifies the kind of mutation carried by a PatchOperation.
type PatchOpType string

const (
	// PatchOpAdd adds a rule to a named p or g policy type.
	PatchOpAdd PatchOpType = "add"
	// PatchOpRemove removes a rule from a named p or g policy type.
	PatchOpRemove PatchOpType = "remove"
	// PatchOpUpdate replaces OldRule with Rule in a named p or g policy type.
	PatchOpUpdate PatchOpType = "update"
)

// PatchOperation is a single named policy mutation applied on the isolated
// candidate model only. Sec must be "p" for policy rules or "g" for grouping
// rules. OldRule is used only for PatchOpUpdate.
type PatchOperation struct {
	Op      PatchOpType
	Sec     string
	PType   string
	Rule    []string
	OldRule []string
}

// PolicyPatch is the ordered, immutable-by-convention candidate change set
// compared against the baseline. It is never committed: the analyzer owns a
// defensive copy and never mutates the caller's slices.
type PolicyPatch struct {
	Operations []PatchOperation
}

// NewPolicyPatch builds a patch from the given operations.
func NewPolicyPatch(operations ...PatchOperation) PolicyPatch {
	return PolicyPatch{Operations: operations}
}

// NewAddPatchOperation builds an add operation for a named p/g policy type.
func NewAddPatchOperation(sec, ptype string, rule []string) PatchOperation {
	return PatchOperation{Op: PatchOpAdd, Sec: sec, PType: ptype, Rule: rule}
}

// NewRemovePatchOperation builds a remove operation for a named p/g policy type.
func NewRemovePatchOperation(sec, ptype string, rule []string) PatchOperation {
	return PatchOperation{Op: PatchOpRemove, Sec: sec, PType: ptype, Rule: rule}
}

// NewUpdatePatchOperation builds an update operation for a named p/g policy type.
func NewUpdatePatchOperation(sec, ptype string, oldRule, newRule []string) PatchOperation {
	return PatchOperation{Op: PatchOpUpdate, Sec: sec, PType: ptype, Rule: newRule, OldRule: oldRule}
}

// OutcomeCategory classifies a single corpus request after comparing the real
// baseline and candidate Enforce decisions.
type OutcomeCategory string

const (
	// CategoryAllowToDeny means the request was allowed on the baseline and is
	// denied on the candidate, with neither evaluation returning an error.
	CategoryAllowToDeny OutcomeCategory = "allow_to_deny"
	// CategoryDenyToAllow means the request was denied on the baseline and is
	// allowed on the candidate, with neither evaluation returning an error.
	CategoryDenyToAllow OutcomeCategory = "deny_to_allow"
	// CategoryUnchanged means both sides evaluated successfully to the same
	// allow or deny decision.
	CategoryUnchanged OutcomeCategory = "unchanged"
	// CategoryEvalError means at least one side failed to evaluate the request;
	// the per-side errors are retained on the RequestOutcome.
	CategoryEvalError OutcomeCategory = "eval_error"
)

// AnalysisRequest is one caller-provided enforcement input. EnforceContext is
// optional: when non-nil it selects named r/p/e/m definitions exactly like the
// first argument of Enforcer.Enforce. Args must contain immutable values; the
// analyzer copies the slice but cannot deep-copy pointer arguments.
type AnalysisRequest struct {
	EnforceContext *EnforceContext
	Args           []interface{}
}

// NewAnalysisRequest builds a request using the default r/p/e/m definitions.
func NewAnalysisRequest(args ...interface{}) AnalysisRequest {
	return AnalysisRequest{Args: args}
}

// NewContextAnalysisRequest builds a request using a named EnforceContext.
func NewContextAnalysisRequest(enforceContext EnforceContext, args ...interface{}) AnalysisRequest {
	contextCopy := enforceContext
	return AnalysisRequest{EnforceContext: &contextCopy, Args: args}
}

// SideResult captures one Enforce outcome on one isolated enforcer.
type SideResult struct {
	Allowed bool
	Err     error
}

// GroupField is one typed field of a grouping key. Type preserves the Go type
// identity (for example a string "1" stays distinct from an int 1) and Value is
// a length-prefixed stable representation so field boundaries are never lost.
type GroupField struct {
	Index int
	Type  string
	Value string
}

// GroupKey is a boundary-safe, type-preserving key built from a finite set of
// request argument indexes.
type GroupKey struct {
	fields  []GroupField
	encoded string
}

// Fields returns a copy of the structured fields making up the key.
func (k GroupKey) Fields() []GroupField {
	return append([]GroupField(nil), k.fields...)
}

// String returns the deterministic encoded form of the key.
func (k GroupKey) String() string {
	return k.encoded
}

// RequestOutcome is the per-request comparison record owned by the report.
type RequestOutcome struct {
	Index     int
	Request   AnalysisRequest
	Baseline  SideResult
	Candidate SideResult
	Category  OutcomeCategory
	GroupKey  *GroupKey
}

// GroupSummary aggregates counts and the minimum-index witness per category
// inside one GroupKey.
type GroupSummary struct {
	Key       GroupKey
	Counts    map[OutcomeCategory]int
	Witnesses map[OutcomeCategory]int
}

// ImpactReport is the finite-corpus impact result. When Complete is false the
// context was cancelled: Outcomes cover exactly AnalyzedCount requests and
// unprocessed requests are never counted as unchanged.
type ImpactReport struct {
	Complete       bool
	Generation     uint64
	TotalCount     int
	AnalyzedCount  int
	Counts         map[OutcomeCategory]int
	Witnesses      map[OutcomeCategory]int
	Outcomes       []RequestOutcome
	Groups         []GroupSummary
	ScopeStatement string
}

// Witness returns the stable minimum corpus index exhibiting the category.
func (r *ImpactReport) Witness(category OutcomeCategory) (int, bool) {
	index, ok := r.Witnesses[category]
	return index, ok
}

// WitnessOutcome returns the full outcome at the category witness index.
func (r *ImpactReport) WitnessOutcome(category OutcomeCategory) (*RequestOutcome, bool) {
	index, ok := r.Witnesses[category]
	if !ok || index >= len(r.Outcomes) {
		return nil, false
	}
	outcome := r.Outcomes[index]
	return &outcome, true
}

// PureFunction attests that a govaluate expression function registered on the
// live enforcer is pure: deterministic, free of side effects and free of reads
// of mutable global state, so it may be shared with isolated enforcers.
type PureFunction struct {
	Name string
	Func govaluate.ExpressionFunction
}

// MatchingFuncContract attests a pure role-manager matching function that must
// be re-registered on isolated role managers. Domain selects AddDomainMatchingFunc.
type MatchingFuncContract struct {
	PType  string
	Name   string
	Func   rbac.MatchingFunc
	Domain bool
}

// RoleManagerCloneFunc builds an independent role manager for a named role
// definition (g, g2, ...). The source manager must be treated as read-only.
type RoleManagerCloneFunc func(ptype string, source rbac.RoleManager) (rbac.RoleManager, error)

// CloneableRoleManager is implemented by role managers that can create an
// independent copy for isolated what-if analysis.
type CloneableRoleManager interface {
	rbac.RoleManager
	CloneForAnalysis() (rbac.RoleManager, error)
}

// FreezableRoleManager is implemented by role managers that can forbid further
// mutation, after which sharing the instance for read-only analysis is safe.
type FreezableRoleManager interface {
	rbac.RoleManager
	FreezeForAnalysis() error
}

// AnalysisLocker optionally serializes snapshotting against concurrent live
// mutations. *SyncedEnforcer.GetLock satisfies this interface.
type AnalysisLocker interface {
	Lock()
	Unlock()
	RLock()
	RUnlock()
}

// AnalysisOptions configures one analysis run.
type AnalysisOptions struct {
	// BatchSize bounds requests processed between cancellation checks.
	BatchSize int
	// PureFunctions covers every custom expression function in use; analysis is
	// rejected when a custom function has no explicit purity attestation.
	PureFunctions []PureFunction
	// MatchingFuncs re-registers pure matching functions on isolated managers.
	MatchingFuncs []MatchingFuncContract
	// RoleManagerCloner provides independent copies of custom role managers.
	RoleManagerCloner RoleManagerCloneFunc
	// GroupBy selects request argument indexes for optional grouped summaries.
	GroupBy []int
	// Locker guards the snapshot when the enforcer is mutated concurrently.
	Locker AnalysisLocker
	// VerifyBaselineDecisions additionally cross-checks every baseline decision
	// against the live enforcer and rejects the run on divergence.
	VerifyBaselineDecisions bool
}

// PolicyImpactAnalyzer compares real Enforce decisions of a frozen baseline
// generation against an isolated candidate policy patch over a finite,
// caller-provided request corpus. It never writes through an adapter, never
// notifies watchers or dispatchers and never mutates the live model or caches.
type PolicyImpactAnalyzer struct {
	enforcer *Enforcer
}

// NewPolicyImpactAnalyzer creates an analyzer bound to a live enforcer. The
// enforcer itself is only read, and only while taking the frozen snapshot.
func NewPolicyImpactAnalyzer(e *Enforcer) (*PolicyImpactAnalyzer, error) {
	if e == nil {
		return nil, errors.New("PolicyImpactAnalyzer requires a non-nil enforcer")
	}
	return &PolicyImpactAnalyzer{enforcer: e}, nil
}

// rmHandle describes how one named role manager is materialized independently
// for every isolated enforcer. Exactly one of native, clone or frozen is set.
type rmHandle struct {
	native bool
	// clone builds a fresh independent manager; its link graph is afterwards
	// rebuilt from the isolated model's grouping policies.
	clone func() (rbac.RoleManager, error)
	// frozen is a read-only shared manager that must never be rebuilt. It is
	// only valid when the patch does not touch grouping policies.
	frozen rbac.RoleManager
}

// analysisSnapshot is the frozen generation used by both isolated enforcers.
type analysisSnapshot struct {
	generation      uint64
	model           model.Model
	customFunctions map[string]govaluate.ExpressionFunction
	rmHandles       map[string]rmHandle
	condRmHandles   map[string]rmHandle
	enabled         bool
	acceptJSON      bool
	gFunctionCache  bool
}

// Analyze runs the finite-corpus comparison and returns the impact report. On
// context cancellation it returns the incomplete report together with the
// context error; contract or patch violations return a nil report.
func (a *PolicyImpactAnalyzer) Analyze(ctx context.Context, patch PolicyPatch,
	requests []AnalysisRequest, opts AnalysisOptions) (*ImpactReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ownedRequests := cloneRequests(requests)
	ownedPatch := clonePatch(patch)
	if err := validateGroupBy(ownedRequests, opts.GroupBy); err != nil {
		return nil, err
	}

	snapshot, err := a.takeSnapshot(opts)
	if err != nil {
		return nil, err
	}
	if err = validateFrozenGroupingPatch(snapshot, ownedPatch); err != nil {
		return nil, err
	}
	baseline, err := a.buildIsolatedEnforcer(snapshot.model, snapshot, opts)
	if err != nil {
		return nil, err
	}
	candidateModel := snapshot.model.Copy()
	if err = applyPolicyPatch(candidateModel, ownedPatch); err != nil {
		return nil, err
	}
	candidate, err := a.buildIsolatedEnforcer(candidateModel, snapshot, opts)
	if err != nil {
		return nil, err
	}

	report := newImpactReport(snapshot.generation, len(ownedRequests))
	if opts.VerifyBaselineDecisions {
		if err = a.verifyBaseline(ctx, ownedRequests, baseline, snapshot, opts); err != nil {
			return nil, err
		}
	}

	groups := newGroupAccumulator(opts.GroupBy)
	batchSize := normalizedBatchSize(opts.BatchSize)
	for start := 0; start < len(ownedRequests); start += batchSize {
		if err = ctx.Err(); err != nil {
			finalizeGroups(report, groups)
			return report, err
		}
		end := start + batchSize
		if end > len(ownedRequests) {
			end = len(ownedRequests)
		}
		for index := start; index < end; index++ {
			outcome := evaluateRequest(baseline, candidate, ownedRequests[index], index, opts.GroupBy)
			recordOutcome(report, outcome, groups)
		}
	}

	report.Complete = true
	finalizeGroups(report, groups)
	return report, nil
}

func newImpactReport(generation uint64, total int) *ImpactReport {
	return &ImpactReport{
		Complete:       false,
		Generation:     generation,
		TotalCount:     total,
		AnalyzedCount:  0,
		Counts:         newCategoryCounts(),
		Witnesses:      map[OutcomeCategory]int{},
		Outcomes:       make([]RequestOutcome, 0, total),
		Groups:         nil,
		ScopeStatement: ImpactAnalysisScopeStatement,
	}
}

func newCategoryCounts() map[OutcomeCategory]int {
	return map[OutcomeCategory]int{
		CategoryAllowToDeny: 0,
		CategoryDenyToAllow: 0,
		CategoryUnchanged:   0,
		CategoryEvalError:   0,
	}
}

func normalizedBatchSize(size int) int {
	if size > 0 {
		return size
	}
	return defaultImpactBatchSize
}

func cloneRequests(requests []AnalysisRequest) []AnalysisRequest {
	cloned := make([]AnalysisRequest, len(requests))
	for i, request := range requests {
		cloned[i] = AnalysisRequest{
			Args: append([]interface{}(nil), request.Args...),
		}
		if request.EnforceContext != nil {
			contextCopy := *request.EnforceContext
			cloned[i].EnforceContext = &contextCopy
		}
	}
	return cloned
}

func clonePatch(patch PolicyPatch) PolicyPatch {
	operations := make([]PatchOperation, len(patch.Operations))
	for i, op := range patch.Operations {
		operations[i] = PatchOperation{
			Op:      op.Op,
			Sec:     op.Sec,
			PType:   op.PType,
			Rule:    append([]string(nil), op.Rule...),
			OldRule: append([]string(nil), op.OldRule...),
		}
	}
	return PolicyPatch{Operations: operations}
}

func validateGroupBy(requests []AnalysisRequest, groupBy []int) error {
	for _, index := range groupBy {
		if index < 0 {
			return fmt.Errorf("%w: GroupBy index %d must not be negative", ErrImpactAnalysisContract, index)
		}
		for _, request := range requests {
			if index >= len(request.Args) {
				return fmt.Errorf("%w: GroupBy index %d exceeds request argument count %d",
					ErrImpactAnalysisContract, index, len(request.Args))
			}
		}
	}
	return nil
}

func (a *PolicyImpactAnalyzer) takeSnapshot(opts AnalysisOptions) (*analysisSnapshot, error) {
	unlock := acquireReadLock(opts.Locker)
	defer unlock()

	e := a.enforcer
	if _, ok := e.eft.(*effector.DefaultEffector); !ok {
		return nil, fmt.Errorf("%w: custom effector %T is not supported", ErrImpactAnalysisContract, e.eft)
	}

	customFunctions, err := resolveCustomFunctions(e, opts)
	if err != nil {
		return nil, err
	}
	snapshot, err := resolveRoleManagers(e, opts)
	if err != nil {
		return nil, err
	}

	snapshot.generation = e.getPolicyVersion()
	snapshot.model = e.model.Copy()
	snapshot.customFunctions = customFunctions
	snapshot.enabled = e.enabled
	snapshot.acceptJSON = e.acceptJsonRequest
	snapshot.gFunctionCache = e.gFunctionCache
	return snapshot, nil
}

func acquireReadLock(locker AnalysisLocker) func() {
	if locker == nil {
		return func() {}
	}
	locker.RLock()
	return locker.RUnlock
}

func resolveCustomFunctions(e *Enforcer, opts AnalysisOptions) (map[string]govaluate.ExpressionFunction, error) {
	builtinFunctionMap := model.LoadFunctionMap()
	builtinNames := map[string]struct{}{}
	for name := range builtinFunctionMap.GetFunctions() {
		builtinNames[name] = struct{}{}
	}

	attested := map[string]govaluate.ExpressionFunction{}
	for _, pure := range opts.PureFunctions {
		if _, duplicated := attested[pure.Name]; duplicated {
			return nil, fmt.Errorf("%w: duplicate pure function attestation %q", ErrImpactAnalysisContract, pure.Name)
		}
		attested[pure.Name] = pure.Func
	}

	liveFunctions := e.fm.GetFunctions()
	custom := map[string]govaluate.ExpressionFunction{}
	for name := range liveFunctions {
		if _, builtin := builtinNames[name]; builtin {
			continue
		}
		pure, ok := attested[name]
		if !ok {
			return nil, fmt.Errorf("%w: custom function %q needs an explicit PureFunction attestation",
				ErrImpactAnalysisContract, name)
		}
		custom[name] = pure
	}
	for name := range attested {
		if _, present := e.fm.GetFunctions()[name]; !present {
			return nil, fmt.Errorf("%w: attested pure function %q is not registered on the enforcer",
				ErrImpactAnalysisContract, name)
		}
	}
	return custom, nil
}

func resolveRoleManagers(e *Enforcer, opts AnalysisOptions) (*analysisSnapshot, error) {
	snapshot := &analysisSnapshot{
		rmHandles:     map[string]rmHandle{},
		condRmHandles: map[string]rmHandle{},
	}

	for ptype, source := range e.rmMap {
		handle, err := resolveOneRoleManager(ptype, source, opts)
		if err != nil {
			return nil, err
		}
		snapshot.rmHandles[ptype] = handle
	}
	for ptype, source := range e.condRmMap {
		handle, err := resolveOneRoleManager(ptype, source, opts)
		if err != nil {
			return nil, err
		}
		if handle.native {
			snapshot.condRmHandles[ptype] = handle
			continue
		}
		// Validate once that the contract result is a conditional manager.
		manager, err := materializeRoleManager(handle)
		if err != nil {
			return nil, err
		}
		if _, ok := manager.(rbac.ConditionalRoleManager); !ok {
			return nil, fmt.Errorf("%w: cloned manager %q does not implement ConditionalRoleManager",
				ErrImpactAnalysisContract, ptype)
		}
		snapshot.condRmHandles[ptype] = handle
	}
	return snapshot, nil
}

func resolveOneRoleManager(ptype string, source rbac.RoleManager, opts AnalysisOptions) (rmHandle, error) {
	if opts.RoleManagerCloner != nil {
		clone := func() (rbac.RoleManager, error) {
			return opts.RoleManagerCloner(ptype, source)
		}
		return rmHandle{clone: clone}, nil
	}
	if cloner, ok := source.(CloneableRoleManager); ok {
		return rmHandle{clone: cloner.CloneForAnalysis}, nil
	}
	if isNativeRoleManager(source) {
		return rmHandle{native: true}, nil
	}
	if freezable, ok := source.(FreezableRoleManager); ok {
		if err := freezable.FreezeForAnalysis(); err != nil {
			return rmHandle{}, err
		}
		return rmHandle{frozen: source}, nil
	}
	return rmHandle{}, fmt.Errorf("%w: role manager %q of type %T needs a cloneable or freezable contract",
		ErrImpactAnalysisContract, ptype, source)
}

func materializeRoleManager(handle rmHandle) (rbac.RoleManager, error) {
	switch {
	case handle.clone != nil:
		return handle.clone()
	case handle.frozen != nil:
		return handle.frozen, nil
	default:
		return nil, fmt.Errorf("%w: role manager handle has no materialization contract",
			ErrImpactAnalysisContract)
	}
}

func validateFrozenGroupingPatch(snapshot *analysisSnapshot, patch PolicyPatch) error {
	frozen := 0
	for _, handle := range snapshot.rmHandles {
		if handle.frozen != nil {
			frozen++
		}
	}
	for _, handle := range snapshot.condRmHandles {
		if handle.frozen != nil {
			frozen++
		}
	}
	if frozen == 0 {
		return nil
	}
	for _, op := range patch.Operations {
		if op.Sec == "g" {
			return fmt.Errorf("%w: grouping patch %v cannot be applied to a frozen shared role manager; "+
				"provide a cloneable contract instead", ErrImpactAnalysisContract, op)
		}
	}
	return nil
}

func isNativeRoleManager(source rbac.RoleManager) bool {
	switch source.(type) {
	case *defaultrolemanager.RoleManagerImpl,
		*defaultrolemanager.RoleManager,
		*defaultrolemanager.ConditionalRoleManager,
		*defaultrolemanager.ConditionalDomainManager:
		return true
	default:
		return false
	}
}

func (a *PolicyImpactAnalyzer) buildIsolatedEnforcer(m model.Model, snapshot *analysisSnapshot,
	opts AnalysisOptions) (*Enforcer, error) {
	isolated := &Enforcer{}
	if err := isolated.InitWithModelAndAdapter(m, nil); err != nil {
		return nil, err
	}
	isolated.enabled = snapshot.enabled
	isolated.acceptJsonRequest = snapshot.acceptJSON
	isolated.gFunctionCache = snapshot.gFunctionCache

	for name, fn := range snapshot.customFunctions {
		isolated.fm.AddFunction(name, fn)
	}
	if err := materializeRoleManagers(isolated, snapshot); err != nil {
		return nil, err
	}
	if err := rebuildRoleLinks(m, isolated, snapshot); err != nil {
		return nil, err
	}
	if err := registerMatchingFuncs(isolated, opts.MatchingFuncs); err != nil {
		return nil, err
	}
	return isolated, nil
}

// materializeRoleManagers gives this enforcer its own independent manager for
// every named role definition. Native managers created by InitWithModelAndAdapter
// are kept; clone handles produce a fresh manager per enforcer, while frozen
// managers are shared because the patch is validated not to touch grouping rules.
func materializeRoleManagers(isolated *Enforcer, snapshot *analysisSnapshot) error {
	for ptype, handle := range snapshot.rmHandles {
		assertion, ok := isolated.model["g"][ptype]
		if !ok {
			// The model never references this manager, so it cannot affect Enforce.
			continue
		}
		if handle.native {
			continue
		}
		manager, err := materializeRoleManager(handle)
		if err != nil {
			return err
		}
		isolated.rmMap[ptype] = manager
		assertion.RM = manager
	}
	for ptype, handle := range snapshot.condRmHandles {
		assertion, ok := isolated.model["g"][ptype]
		if !ok {
			// The model never references this manager, so it cannot affect Enforce.
			continue
		}
		if handle.native {
			continue
		}
		manager, err := materializeRoleManager(handle)
		if err != nil {
			return err
		}
		conditional, ok := manager.(rbac.ConditionalRoleManager)
		if !ok {
			return fmt.Errorf("%w: manager %q does not implement ConditionalRoleManager",
				ErrImpactAnalysisContract, ptype)
		}
		isolated.condRmMap[ptype] = conditional
		assertion.CondRM = conditional
	}
	return nil
}

// rebuildRoleLinks reconstructs the role graph of every native or cloned manager
// from this enforcer's own grouping policies. Frozen shared managers are skipped.
func rebuildRoleLinks(m model.Model, isolated *Enforcer, snapshot *analysisSnapshot) error {
	rebuildableRm := map[string]rbac.RoleManager{}
	for ptype, handle := range snapshot.rmHandles {
		if handle.frozen != nil {
			continue
		}
		if manager := isolated.rmMap[ptype]; manager != nil {
			if handle.clone != nil {
				if err := manager.Clear(); err != nil {
					return err
				}
			}
			rebuildableRm[ptype] = manager
		}
	}
	if err := m.BuildRoleLinks(rebuildableRm); err != nil {
		return err
	}
	rebuildableCondRm := map[string]rbac.ConditionalRoleManager{}
	for ptype, handle := range snapshot.condRmHandles {
		if handle.frozen != nil {
			continue
		}
		if manager := isolated.condRmMap[ptype]; manager != nil {
			if handle.clone != nil {
				if err := manager.Clear(); err != nil {
					return err
				}
			}
			rebuildableCondRm[ptype] = manager
		}
	}
	return m.BuildConditionalRoleLinks(rebuildableCondRm)
}

func registerMatchingFuncs(isolated *Enforcer, contracts []MatchingFuncContract) error {
	seen := map[string]struct{}{}
	for _, contract := range contracts {
		key := contract.PType + ":" + contract.Name + ":" + strconv.FormatBool(contract.Domain)
		if _, duplicated := seen[key]; duplicated {
			return fmt.Errorf("%w: duplicate matching function contract %q", ErrImpactAnalysisContract, key)
		}
		seen[key] = struct{}{}

		var registered bool
		if contract.Domain {
			registered = isolated.AddNamedDomainMatchingFunc(contract.PType, contract.Name, contract.Func)
		} else {
			registered = isolated.AddNamedMatchingFunc(contract.PType, contract.Name, contract.Func)
		}
		if !registered {
			return fmt.Errorf("%w: role manager %q cannot accept matching function %q",
				ErrImpactAnalysisContract, contract.PType, contract.Name)
		}
	}
	return nil
}

func applyPolicyPatch(m model.Model, patch PolicyPatch) error {
	// The snapshot model already carries the enforcer's canonical policy order
	// (load-time sorting plus priority-aware insertion on AddPolicy). Replaying
	// the same model-level mutations therefore reproduces exactly the order a
	// live enforcer would reach through its management API; an extra re-sort
	// would invent decisions that the real operation sequence would not produce.
	for _, op := range patch.Operations {
		if err := validatePatchOperation(m, op); err != nil {
			return err
		}
		if err := applyPatchOperation(m, op); err != nil {
			return err
		}
	}
	return nil
}

func validatePatchOperation(m model.Model, op PatchOperation) error {
	if op.Sec != "p" && op.Sec != "g" {
		return fmt.Errorf("%w: section must be \"p\" or \"g\", got %q", ErrInvalidPolicyPatch, op.Sec)
	}
	assertion, err := m.GetAssertion(op.Sec, op.PType)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPolicyPatch, err)
	}
	if err := validateRuleSize(op.Sec, assertion.Tokens, op.Rule); err != nil {
		return err
	}

	exists, err := m.HasPolicy(op.Sec, op.PType, op.Rule)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPolicyPatch, err)
	}
	switch op.Op {
	case PatchOpAdd:
		if exists {
			return fmt.Errorf("%w: add target already exists: %v", ErrInvalidPolicyPatch, op.Rule)
		}
	case PatchOpRemove:
		if !exists {
			return fmt.Errorf("%w: remove target does not exist: %v", ErrInvalidPolicyPatch, op.Rule)
		}
	case PatchOpUpdate:
		if err := validateRuleSize(op.Sec, assertion.Tokens, op.OldRule); err != nil {
			return err
		}
		oldExists, oldErr := m.HasPolicy(op.Sec, op.PType, op.OldRule)
		if oldErr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidPolicyPatch, oldErr)
		}
		if !oldExists {
			return fmt.Errorf("%w: update source does not exist: %v", ErrInvalidPolicyPatch, op.OldRule)
		}
		if exists {
			return fmt.Errorf("%w: update target already exists: %v", ErrInvalidPolicyPatch, op.Rule)
		}
	default:
		return fmt.Errorf("%w: unknown operation %q", ErrInvalidPolicyPatch, op.Op)
	}
	return nil
}

func validateRuleSize(sec string, tokens, rule []string) error {
	if sec == "p" && len(rule) != len(tokens) {
		return fmt.Errorf("%w: expected %d fields, got %d: %v",
			ErrInvalidPolicyPatch, len(tokens), len(rule), rule)
	}
	if sec == "g" && len(rule) < len(tokens) {
		return fmt.Errorf("%w: expected at least %d fields, got %d: %v",
			ErrInvalidPolicyPatch, len(tokens), len(rule), rule)
	}
	return nil
}

func applyPatchOperation(m model.Model, op PatchOperation) error {
	switch op.Op {
	case PatchOpAdd:
		return m.AddPolicy(op.Sec, op.PType, op.Rule)
	case PatchOpRemove:
		_, err := m.RemovePolicy(op.Sec, op.PType, op.Rule)
		return err
	case PatchOpUpdate:
		// In-place replacement mirrors Enforcer.UpdateNamedPolicy: policy order,
		// including implicit priority ordering, is preserved.
		_, err := m.UpdatePolicy(op.Sec, op.PType, op.OldRule, op.Rule)
		return err
	default:
		return fmt.Errorf("%w: unknown operation %q", ErrInvalidPolicyPatch, op.Op)
	}
}

func (a *PolicyImpactAnalyzer) verifyBaseline(ctx context.Context, requests []AnalysisRequest,
	baseline *Enforcer, snapshot *analysisSnapshot, opts AnalysisOptions) error {
	for index, request := range requests {
		if err := ctx.Err(); err != nil {
			return err
		}
		expected := enforceRequest(baseline, request)
		actual := enforceRequestLive(a.enforcer, request, opts.Locker)
		if resultsDiverge(expected, actual) {
			return fmt.Errorf("%w: request index %d baseline=%v candidate-live=%v",
				ErrBaselineDivergence, index, expected, actual)
		}
	}
	unlock := acquireReadLock(opts.Locker)
	defer unlock()
	if current := a.enforcer.getPolicyVersion(); current != snapshot.generation {
		return fmt.Errorf("%w: generation %d changed to %d",
			ErrSnapshotChanged, snapshot.generation, current)
	}
	return nil
}

func resultsDiverge(expected, actual SideResult) bool {
	if (expected.Err == nil) != (actual.Err == nil) {
		return true
	}
	return expected.Err == nil && expected.Allowed != actual.Allowed
}

func enforceRequestLive(e *Enforcer, request AnalysisRequest, locker AnalysisLocker) SideResult {
	unlock := acquireReadLock(locker)
	defer unlock()
	return enforceRequest(e, request)
}

func enforceRequest(e *Enforcer, request AnalysisRequest) SideResult {
	rvals := append([]interface{}(nil), request.Args...)
	if request.EnforceContext != nil {
		rvals = append([]interface{}{*request.EnforceContext}, rvals...)
	}
	allowed, err := e.Enforce(rvals...)
	return SideResult{Allowed: allowed, Err: err}
}

func evaluateRequest(baseline, candidate *Enforcer, request AnalysisRequest,
	index int, groupBy []int) RequestOutcome {
	baselineResult := enforceRequest(baseline, request)
	candidateResult := enforceRequest(candidate, request)
	outcome := RequestOutcome{
		Index:     index,
		Request:   request,
		Baseline:  baselineResult,
		Candidate: candidateResult,
		Category:  classifyOutcome(baselineResult, candidateResult),
	}
	if len(groupBy) > 0 {
		key := buildGroupKey(request, groupBy)
		outcome.GroupKey = &key
	}
	return outcome
}

func classifyOutcome(baseline, candidate SideResult) OutcomeCategory {
	if baseline.Err != nil || candidate.Err != nil {
		return CategoryEvalError
	}
	if baseline.Allowed == candidate.Allowed {
		return CategoryUnchanged
	}
	if baseline.Allowed {
		return CategoryAllowToDeny
	}
	return CategoryDenyToAllow
}

func recordOutcome(report *ImpactReport, outcome RequestOutcome, groups *groupAccumulator) {
	report.Outcomes = append(report.Outcomes, outcome)
	report.AnalyzedCount++
	report.Counts[outcome.Category]++
	if _, exists := report.Witnesses[outcome.Category]; !exists {
		report.Witnesses[outcome.Category] = outcome.Index
	}
	groups.record(outcome)
}

func buildGroupKey(request AnalysisRequest, groupBy []int) GroupKey {
	fields := make([]GroupField, len(groupBy))
	var builder strings.Builder
	for i, index := range groupBy {
		value := request.Args[index]
		typeName := "<nil>"
		valueText := ""
		if value != nil {
			typeName = reflect.TypeOf(value).String()
			valueText = fmt.Sprintf("%v", value)
		}
		fields[i] = GroupField{Index: index, Type: typeName, Value: valueText}
		if i > 0 {
			builder.WriteByte(0x1f)
		}
		builder.WriteString(strconv.Itoa(index))
		builder.WriteByte(0x1e)
		builder.WriteString(typeName)
		builder.WriteByte(0x1e)
		builder.WriteString(strconv.Itoa(len(valueText)))
		builder.WriteByte(0x1e)
		builder.WriteString(valueText)
	}
	return GroupKey{fields: fields, encoded: builder.String()}
}

type groupAccumulator struct {
	groupBy []int
	entries map[string]*groupEntry
	order   []string
}

type groupEntry struct {
	key       GroupKey
	counts    map[OutcomeCategory]int
	witnesses map[OutcomeCategory]int
}

func newGroupAccumulator(groupBy []int) *groupAccumulator {
	return &groupAccumulator{
		groupBy: groupBy,
		entries: map[string]*groupEntry{},
		order:   nil,
	}
}

func (accumulator *groupAccumulator) record(outcome RequestOutcome) {
	if len(accumulator.groupBy) == 0 || outcome.GroupKey == nil {
		return
	}
	key := outcome.GroupKey.encoded
	entry, ok := accumulator.entries[key]
	if !ok {
		entry = &groupEntry{
			key:       *outcome.GroupKey,
			counts:    newCategoryCounts(),
			witnesses: map[OutcomeCategory]int{},
		}
		accumulator.entries[key] = entry
		accumulator.order = append(accumulator.order, key)
	}
	entry.counts[outcome.Category]++
	if _, exists := entry.witnesses[outcome.Category]; !exists {
		entry.witnesses[outcome.Category] = outcome.Index
	}
}

func finalizeGroups(report *ImpactReport, accumulator *groupAccumulator) {
	if len(accumulator.groupBy) == 0 {
		return
	}
	keys := append([]string(nil), accumulator.order...)
	sort.Strings(keys)
	report.Groups = make([]GroupSummary, 0, len(keys))
	for _, key := range keys {
		entry := accumulator.entries[key]
		report.Groups = append(report.Groups, GroupSummary{
			Key:       entry.key,
			Counts:    entry.counts,
			Witnesses: entry.witnesses,
		})
	}
}
