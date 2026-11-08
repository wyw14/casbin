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
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/util"
	"github.com/casbin/govaluate"
)

// SetIPMatchIndex installs the built-in CIDR candidate index for a positive
// top-level conjunction of the form ipMatch(r.<token>, p.<token>) in the
// default matcher "m".
//
// The index never decides a request by itself: it only narrows the set of
// policy rules handed to the unchanged govaluate matcher, which still
// evaluates every candidate rule. Decisions, errors, explain ordinals and
// effector priority are therefore identical to a full policy scan.
//
// Installation fails (and nothing is installed) when the matcher cannot be
// proven safe, in which case Enforce keeps evaluating every rule:
//   - the ipMatch call sits inside an OR, a negation, a ternary/coalesce
//     expression or another function call;
//   - the matcher uses eval(), whose predicate is only known at runtime;
//   - the registered "ipMatch" function is not the built-in util.IPMatchFunc;
//   - the two arguments are not exactly one request token and one policy
//     token, in that order, or more than one ipMatch call is present.
//
// Rules whose policy IP/CIDR is invalid are kept as universal candidates, so
// the original ipMatch error still fires when the rule is reached. A request
// whose IP is invalid likewise falls back to the full scan, preserving the
// original request-side error. The index is rebuilt from scratch on every
// policy generation and reset by LoadPolicy/LoadModel; replacing functions
// invalidates the analysis generation.
func (e *Enforcer) SetIPMatchIndex(ptype string) error {
	rIndex, pIndex, err := e.analyzeIPMatchIndex(ptype)
	if err != nil {
		return err
	}

	e.policyIndexes.Store(ptype, &ipMatchPolicyIndex{
		ptype:       ptype,
		rTokenIndex: rIndex,
		pTokenIndex: pIndex,
		funcVersion: e.getFunctionVersion(),
	})
	return nil
}

// analyzeIPMatchIndex verifies the matcher structure and resolves the
// request/policy token positions of the single indexable ipMatch predicate.
func (e *Enforcer) analyzeIPMatchIndex(ptype string) (int, int, error) {
	rAssertion, ok := e.model["r"]["r"]
	if !ok {
		return 0, 0, errors.New(`request type "r" does not exist`)
	}
	pAssertion, ok := e.model["p"][ptype]
	if !ok {
		return 0, 0, fmt.Errorf("policy type %q does not exist", ptype)
	}
	mAssertion, ok := e.model["m"]["m"]
	if !ok {
		return 0, 0, errors.New(`matcher "m" does not exist`)
	}

	// eval() builds its predicate from policy values at runtime, so no static
	// ipMatch predicate can be proven. Enforce uses the same HasEval check.
	if util.HasEval(mAssertion.Value) {
		return 0, 0, errors.New("matcher uses eval(); ipMatch indexing requires a static predicate")
	}

	functions := e.fm.GetFunctions()
	// Mirror enforce(): role functions are attached to the function map there.
	if _, ok := e.model["g"]; ok {
		for key, ast := range e.model["g"] {
			if ast.RM != nil {
				functions[key] = util.GenerateGFunction(ast.RM, e.gFunctionCache)
			}
			if ast.CondRM != nil {
				functions[key] = util.GenerateConditionalGFunction(ast.CondRM)
			}
		}
	}

	registeredIPMatch, ok := functions["ipMatch"]
	if !ok || reflect.ValueOf(registeredIPMatch).Pointer() != reflect.ValueOf(util.IPMatchFunc).Pointer() {
		return 0, 0, errors.New("ipMatch is replaced by a custom function; ipMatch indexing cannot prove its semantics")
	}

	expression, err := govaluate.NewEvaluableExpressionWithFunctions(mAssertion.Value, functions)
	if err != nil {
		return 0, 0, fmt.Errorf("matcher cannot be parsed for ipMatch indexing: %w", err)
	}

	analyzer := &ipMatchAnalyzer{
		tokens:         expression.Tokens(),
		rTokenIndex:    tokenPositionMap(rAssertion.Tokens),
		pTokenIndex:    tokenPositionMap(pAssertion.Tokens),
		builtinIPMatch: reflect.ValueOf(util.IPMatchFunc).Pointer(),
	}
	return analyzer.analyze()
}

func tokenPositionMap(tokens []string) map[string]int {
	positions := make(map[string]int, len(tokens))
	for i, token := range tokens {
		positions[token] = i
	}
	return positions
}

// ipMatchAnalyzer walks the infix govaluate token stream and accepts only a
// single ipMatch(requestToken, policyToken) call that is a standalone
// predicate of the top-level AND conjunction. Everything else is rejected so
// that the caller falls back to the full candidate set. The walk is a
// necessary-condition analysis: it never treats the ipMatch predicate as
// sufficient, because the residual matcher is still evaluated at runtime.
type ipMatchAnalyzer struct {
	tokens []govaluate.ExpressionToken
	pos    int

	rTokenIndex map[string]int
	pTokenIndex map[string]int

	builtinIPMatch uintptr
	// fnDepth counts the function calls whose argument list is currently
	// being parsed. An ipMatch found at depth > 0 is nested in another
	// function and cannot be treated as a top-level predicate.
	fnDepth int

	found bool
	// rIndex/pIndex are the positions of the validated request and policy
	// tokens of the accepted ipMatch predicate.
	rIndex int
	pIndex int
}

type ipMatchArgSpan struct {
	start int
	end   int
}

func (a *ipMatchAnalyzer) analyze() (int, int, error) {
	if _, err := a.parseTernary(); err != nil {
		return 0, 0, err
	}
	if a.pos != len(a.tokens) {
		return 0, 0, errors.New("malformed matcher expression: unexpected trailing tokens")
	}
	if !a.found {
		return 0, 0, errors.New(`matcher has no positive-conjunct "ipMatch(requestToken, policyToken)" predicate`)
	}
	return a.rIndex, a.pIndex, nil
}

func (a *ipMatchAnalyzer) current() *govaluate.ExpressionToken {
	if a.pos >= len(a.tokens) {
		return nil
	}
	token := a.tokens[a.pos]
	return &token
}

func (a *ipMatchAnalyzer) kindIs(kind govaluate.TokenKind) bool {
	token := a.current()
	return token != nil && token.Kind == kind
}

func (a *ipMatchAnalyzer) isLogical(symbol string) bool {
	token := a.current()
	return token != nil && token.Kind == govaluate.LOGICALOP && token.Value.(string) == symbol
}

// parseTernary handles `cond ? whenTrue : whenFalse` and `left ?? right`.
// ipMatch anywhere in such a conditional structure is not a proven predicate.
func (a *ipMatchAnalyzer) parseTernary() (bool, error) {
	cond, err := a.parseOr()
	if err != nil {
		return false, err
	}

	token := a.current()
	if token == nil || token.Kind != govaluate.TERNARY {
		return cond, nil
	}

	symbol := token.Value.(string)
	a.pos++

	if symbol == "??" {
		right, err := a.parseTernary()
		if err != nil {
			return false, err
		}
		if cond || right {
			return false, errors.New("ipMatch inside a coalescing expression is not provably a positive conjunction")
		}
		return false, nil
	}

	whenTrue, err := a.parseOr()
	if err != nil {
		return false, err
	}
	token = a.current()
	if token == nil || token.Kind != govaluate.TERNARY || token.Value.(string) != ":" {
		return false, errors.New("malformed ternary expression in matcher")
	}
	a.pos++
	whenFalse, err := a.parseTernary()
	if err != nil {
		return false, err
	}
	if cond || whenTrue || whenFalse {
		return false, errors.New("ipMatch inside a ternary expression is not provably a positive conjunction")
	}
	return false, nil
}

func (a *ipMatchAnalyzer) parseOr() (bool, error) {
	left, err := a.parseAnd()
	if err != nil {
		return false, err
	}

	for a.isLogical("||") {
		a.pos++
		right, err := a.parseAnd()
		if err != nil {
			return false, err
		}
		// A necessary condition on one OR branch does not bound the rules
		// that can match the whole expression, so ipMatch under OR is unsafe.
		if left || right {
			return false, errors.New("ipMatch inside an OR expression cannot be used as an index predicate")
		}
		left = false
	}
	return left, nil
}

func (a *ipMatchAnalyzer) parseAnd() (bool, error) {
	left, err := a.parseUnary()
	if err != nil {
		return false, err
	}

	for a.isLogical("&&") {
		a.pos++
		right, err := a.parseUnary()
		if err != nil {
			return false, err
		}
		left = left || right
	}
	return left, nil
}

func (a *ipMatchAnalyzer) parseUnary() (bool, error) {
	if a.kindIs(govaluate.PREFIX) {
		a.pos++
		operand, err := a.parseUnary()
		if err != nil {
			return false, err
		}
		if operand {
			return false, errors.New("ipMatch under a negation or prefix operator is not provably a positive conjunction")
		}
		return false, nil
	}
	return a.parsePrimary()
}

func (a *ipMatchAnalyzer) parsePrimary() (bool, error) {
	if a.kindIs(govaluate.CLAUSE) {
		a.pos++
		contains, err := a.parseTernary()
		if err != nil {
			return false, err
		}
		if !a.kindIs(govaluate.CLAUSE_CLOSE) {
			return false, errors.New("malformed parenthesized expression in matcher")
		}
		a.pos++
		return contains, nil
	}
	return a.parseAtom()
}

// parseAtom consumes one non-boolean expression unit: variables, literals,
// comparators, arithmetic and function calls up to the next boolean
// operator, clause close, ternary mark or argument separator.
func (a *ipMatchAnalyzer) parseAtom() (bool, error) {
	contains := false

	for {
		token := a.current()
		if token == nil {
			return contains, nil
		}

		switch token.Kind {
		case govaluate.LOGICALOP, govaluate.CLAUSE_CLOSE, govaluate.TERNARY, govaluate.SEPARATOR:
			return contains, nil
		case govaluate.CLAUSE:
			nested, err := a.parsePrimary()
			if err != nil {
				return false, err
			}
			contains = contains || nested
		case govaluate.FUNCTION:
			nested, err := a.parseFunction()
			if err != nil {
				return false, err
			}
			contains = contains || nested
		default:
			// The ipMatch predicate must stand alone inside its AND term.
			// Feeding its result into a comparison or arithmetic expression
			// changes its meaning, so such a shape is not indexable.
			if contains && (token.Kind == govaluate.COMPARATOR || token.Kind == govaluate.MODIFIER) {
				return false, errors.New("ipMatch must be a standalone predicate of the top-level AND conjunction")
			}
			a.pos++
		}
	}
}

func (a *ipMatchAnalyzer) parseFunction() (bool, error) {
	token := a.tokens[a.pos]
	fn := token.Value.(govaluate.ExpressionFunction)
	isBuiltinIPMatch := reflect.ValueOf(fn).Pointer() == a.builtinIPMatch
	a.pos++

	if !a.kindIs(govaluate.CLAUSE) {
		return false, errors.New("malformed function call in matcher")
	}
	a.pos++ // consume "("

	if isBuiltinIPMatch && a.fnDepth > 0 {
		return false, errors.New("ipMatch nested inside another function call cannot be used as an index predicate")
	}

	argSpans := make([]ipMatchArgSpan, 0, 2)
	argsContainIPMatch := false
	if !a.kindIs(govaluate.CLAUSE_CLOSE) {
		for {
			start := a.pos
			a.fnDepth++
			argContains, err := a.parseTernary()
			a.fnDepth--
			if err != nil {
				return false, err
			}
			argsContainIPMatch = argsContainIPMatch || argContains
			argSpans = append(argSpans, ipMatchArgSpan{start: start, end: a.pos})

			if a.kindIs(govaluate.SEPARATOR) {
				a.pos++
				continue
			}
			break
		}
	}

	if !a.kindIs(govaluate.CLAUSE_CLOSE) {
		return false, errors.New("malformed function call arguments in matcher")
	}
	a.pos++ // consume ")"

	if isBuiltinIPMatch {
		if err := a.acceptIPMatchCall(argSpans); err != nil {
			return false, err
		}
		return true, nil
	}

	if argsContainIPMatch {
		return false, errors.New("ipMatch nested inside another function call cannot be used as an index predicate")
	}
	return false, nil
}

func (a *ipMatchAnalyzer) acceptIPMatchCall(args []ipMatchArgSpan) error {
	if a.found {
		return errors.New("multiple ipMatch calls are not indexable; a single positive-conjunct predicate is required")
	}
	if len(args) != 2 {
		return fmt.Errorf("ipMatch expects 2 arguments, got %d", len(args))
	}

	requestName, err := a.bareVariableToken(args[0], "request")
	if err != nil {
		return err
	}
	policyName, err := a.bareVariableToken(args[1], "policy")
	if err != nil {
		return err
	}

	requestIndex, ok := a.rTokenIndex[requestName]
	if !ok {
		return fmt.Errorf("ipMatch first argument %q is not a token of the request definition", requestName)
	}
	policyIndex, ok := a.pTokenIndex[policyName]
	if !ok {
		return fmt.Errorf("ipMatch second argument %q is not a token of the policy definition", policyName)
	}

	a.found = true
	a.rIndex = requestIndex
	a.pIndex = policyIndex
	return nil
}

func (a *ipMatchAnalyzer) bareVariableToken(span ipMatchArgSpan, side string) (string, error) {
	tokens := a.tokens[span.start:span.end]
	if len(tokens) != 1 || tokens[0].Kind != govaluate.VARIABLE {
		return "", fmt.Errorf("the %s argument of ipMatch must be a single %s token", side, side)
	}
	return tokens[0].Value.(string), nil
}

// ipCidrTrieNode is one binary-prefix node. A CIDR terminates on the node
// reached after its prefix bits; all nodes on a request-IP walk therefore
// represent exactly the CIDRs (and host routes) that contain the request.
type ipCidrTrieNode struct {
	children [2]*ipCidrTrieNode
	ordinals []int
}

type ipCidrTrie struct {
	root *ipCidrTrieNode
}

func newIPCIDRTrie() *ipCidrTrie {
	return &ipCidrTrie{root: &ipCidrTrieNode{}}
}

func (t *ipCidrTrie) insert(ip net.IP, prefixBits int, ordinal int) {
	node := t.root
	for bitIndex := 0; bitIndex < prefixBits; bitIndex++ {
		bit := int(ip[bitIndex/8] >> (7 - uint(bitIndex%8)) & 1)
		if node.children[bit] == nil {
			node.children[bit] = &ipCidrTrieNode{}
		}
		node = node.children[bit]
	}
	node.ordinals = append(node.ordinals, ordinal)
}

// lookup marks every rule whose prefix contains ip on the candidate mask.
func (t *ipCidrTrie) lookup(mask []bool, ip net.IP) {
	node := t.root
	for _, ordinal := range node.ordinals {
		mask[ordinal] = true
	}
	for bitIndex := 0; bitIndex < len(ip)*8; bitIndex++ {
		bit := int(ip[bitIndex/8] >> (7 - uint(bitIndex%8)) & 1)
		node = node.children[bit]
		if node == nil {
			return
		}
		for _, ordinal := range node.ordinals {
			mask[ordinal] = true
		}
	}
}

// ipMatchSnapshot is one immutable index generation. It is built fully before
// being published, so concurrent Enforce calls never observe a half-built
// trie. Stale snapshots are replaced whole; no bucket is reused by string key.
type ipMatchSnapshot struct {
	policyVersion uint64
	policyLen     int

	v4 *ipCidrTrie
	v6 *ipCidrTrie

	// universal lists the ordinals that must always be evaluated because
	// their policy value is neither a valid IP nor a valid CIDR. Keeping
	// them reachable preserves the original ipMatch runtime error.
	universal []bool
}

// ipMatchPolicyIndex is the per-ptype built-in CIDR candidate index.
type ipMatchPolicyIndex struct {
	mu sync.Mutex

	ptype string

	rTokenIndex int
	pTokenIndex int

	// funcVersion is the enforcer function generation for which the
	// structural analysis is valid. Function replacement triggers a
	// re-analysis, which may disable the index.
	funcVersion uint64
	disabled    bool

	snapshot *ipMatchSnapshot
}

func (idx *ipMatchPolicyIndex) reset() {
	idx.mu.Lock()
	idx.snapshot = nil
	idx.mu.Unlock()
}

// reanalyzeLocked reruns the matcher analysis after a function generation
// change. The caller must hold idx.mu.
func (idx *ipMatchPolicyIndex) reanalyzeLocked(e *Enforcer) error {
	rIndex, pIndex, err := e.analyzeIPMatchIndex(idx.ptype)
	if err != nil {
		idx.disabled = true
		idx.funcVersion = e.getFunctionVersion()
		return err
	}
	idx.rTokenIndex = rIndex
	idx.pTokenIndex = pIndex
	idx.funcVersion = e.getFunctionVersion()
	idx.disabled = false
	return nil
}

func (idx *ipMatchPolicyIndex) ensureSnapshotLocked(ast *model.Assertion) *ipMatchSnapshot {
	if idx.snapshot != nil &&
		idx.snapshot.policyVersion == ast.PolicyVersion &&
		idx.snapshot.policyLen == len(ast.Policy) {
		return idx.snapshot
	}

	snapshot := &ipMatchSnapshot{
		policyVersion: ast.PolicyVersion,
		policyLen:     len(ast.Policy),
		v4:            newIPCIDRTrie(),
		v6:            newIPCIDRTrie(),
		universal:     make([]bool, len(ast.Policy)),
	}

	for ordinal, rule := range ast.Policy {
		if idx.pTokenIndex >= len(rule) || !snapshot.addPolicyPattern(rule[idx.pTokenIndex], ordinal) {
			// Out-of-range and unparseable entries stay universal so the
			// original size check or ipMatch runtime error is preserved.
			snapshot.universal[ordinal] = true
		}
	}

	// Publish the completed generation atomically.
	idx.snapshot = snapshot
	return snapshot
}

// addPolicyPattern indexes one policy IP/CIDR value. It returns false when the
// value is neither a CIDR nor a plain IP, so the caller keeps the rule as a
// universal candidate. Parsing follows util.ipMatch: CIDR first, plain IP
// second.
func (s *ipMatchSnapshot) addPolicyPattern(pattern string, ordinal int) bool {
	if _, cidr, err := net.ParseCIDR(pattern); err == nil {
		s.addCIDR(cidr, ordinal)
		return true
	}

	ip := net.ParseIP(pattern)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		s.v4.insert(v4, 32, ordinal)
		return true
	}
	s.v6.insert(ip, 128, ordinal)
	return true
}

// addCIDR inserts a parsed network into the right address-family trie,
// mirroring net.IPNet.Contains: a network with a 4-byte form (IPv4 literal or
// an IPv4-mapped IPv6 network) is tested against the request's 4-byte form,
// and a 16-byte mask keeps only its trailing 4 bytes, i.e. drops the first
// 96 bits.
func (s *ipMatchSnapshot) addCIDR(cidr *net.IPNet, ordinal int) {
	ones, _ := cidr.Mask.Size()
	if v4 := cidr.IP.To4(); v4 != nil {
		if len(cidr.Mask) == net.IPv6len {
			if ones > 96 {
				ones -= 96
			} else {
				ones = 0
			}
		}
		s.v4.insert(v4, ones, ordinal)
		return
	}
	s.v6.insert(cidr.IP, ones, ordinal)
}

// candidates returns a per-ordinal mask of rules whose ipMatch predicate may
// be true for this request. ok=false disables filtering for the request, so
// the caller evaluates the full policy exactly as without the index.
func (idx *ipMatchPolicyIndex) candidates(e *Enforcer, ast *model.Assertion, rvals []interface{}) (mask []bool, ok bool) {
	if ast == nil {
		return nil, false
	}

	idx.mu.Lock()
	if idx.funcVersion != e.getFunctionVersion() {
		_ = idx.reanalyzeLocked(e)
	}
	if idx.disabled {
		idx.mu.Unlock()
		return nil, false
	}
	snapshot := idx.ensureSnapshotLocked(ast)
	rTokenIndex := idx.rTokenIndex
	idx.mu.Unlock()

	if rTokenIndex >= len(rvals) {
		return nil, false
	}
	requestValue, isString := rvals[rTokenIndex].(string)
	if !isString {
		// The original matcher reports a type error for non-string arguments;
		// only the real evaluation may produce it.
		return nil, false
	}
	requestIP := net.ParseIP(requestValue)
	if requestIP == nil {
		// Preserve the original "not an IP address" error path.
		return nil, false
	}

	mask = make([]bool, snapshot.policyLen)
	copy(mask, snapshot.universal)

	// Mirror net.IPNet.Contains: a request with a 4-byte form is reduced to
	// it, so it can only match networks stored in the v4 trie (including
	// IPv4-mapped IPv6 CIDRs, which are inserted there). A pure IPv6 request
	// can only match pure IPv6 networks in the v6 trie.
	if v4 := requestIP.To4(); v4 != nil {
		snapshot.v4.lookup(mask, v4)
	} else {
		snapshot.v6.lookup(mask, requestIP)
	}
	return mask, true
}
