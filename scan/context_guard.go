package scan

import (
	"encoding/binary"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"
)

// keywordGuard is a necessary condition for a keyword hit to be part of a
// match. A rejected hit neither admits its rule nor creates a search window,
// so a guard must accept every hit that a regex match can begin from.
type keywordGuard interface {
	possible(raw string, start, end int) bool
}

// contextGuard runs a rule's own syntax on both sides of a keyword. Each
// top-level alternative of the regex contains a keyword element. The text
// before a hit must be able to end the syntax preceding that element, and
// the text after it must be able to continue the match.
//
// Search windows are measured from the first keyword in each alternative.
// Inference therefore requires the syntax before the keyword element to be
// unable to contain a keyword, so that both analyses use the same element.
type contextGuard struct {
	branches []contextBranch
}

type contextBranch struct {
	before, after *lazyGuardDFA // nil leaves that side unconstrained
}

func (g *contextGuard) possible(raw string, start, end int) bool {
	for _, branch := range g.branches {
		if branch.before.backward(raw, start) && branch.after.forward(raw, end) {
			return true
		}
	}
	return false
}

func inferContextGuard(re *syntax.Regexp, keywords []string) *contextGuard {
	if len(keywords) == 0 {
		return nil
	}
	words := make(map[string]bool, len(keywords))
	shortest := len(keywords[0])
	for _, keyword := range keywords {
		words[strings.ToLower(keyword)] = true
		shortest = min(shortest, len(keyword))
	}
	re = stripCaptures(re)
	// Prefer per-alternative contexts; fall back to the whole expression.
	if re.Op == syntax.OpConcat && len(re.Sub) > 0 {
		if first := stripCaptures(re.Sub[0]); first.Op == syntax.OpAlternate {
			if g := contextBranches(first.Sub, re.Sub[1:], words, shortest); g != nil {
				return g
			}
		}
	}
	if re.Op == syntax.OpAlternate {
		return contextBranches(re.Sub, nil, words, shortest)
	}
	return contextBranches([]*syntax.Regexp{re}, nil, words, shortest)
}

func contextBranches(alternatives, rest []*syntax.Regexp, words map[string]bool, shortest int) *contextGuard {
	g := &contextGuard{}
	constrained := false
	for _, alternative := range alternatives {
		elements := []*syntax.Regexp{alternative}
		if alternative = stripCaptures(alternative); alternative.Op == syntax.OpConcat {
			elements = alternative.Sub
		}
		before, after, ok := splitAtKeyword(elements, words, shortest)
		if !ok {
			return nil
		}
		branch := contextBranch{}
		// Reversal turns the prefix's leading optional syntax into trailing syntax.
		if prefix := withoutOptionalSuffix(reverseSyntax(concatOf(before))); !matchesEmpty(prefix) {
			branch.before = newLazyGuardDFA([]*syntax.Regexp{prefix})
		}
		var candidates []*syntax.Regexp
		if len(rest) > 0 {
			// The rest of the regex sharpens the condition when it stays small.
			candidates = append(candidates, withoutOptionalSuffix(concatOf(append(slices.Clone(after), rest...))))
		}
		if tail := withoutOptionalSuffix(concatOf(after)); !matchesEmpty(tail) {
			candidates = append(candidates, tail)
		}
		if len(candidates) > 0 && !matchesEmpty(candidates[0]) {
			branch.after = newLazyGuardDFA(candidates)
		}
		constrained = constrained || branch.before != nil || branch.after != nil
		g.branches = append(g.branches, branch)
	}
	if !constrained {
		return nil
	}
	return g
}

// splitAtKeyword returns the syntax on each side of the first keyword
// element. A literal may merge a keyword with adjacent text, as in "secret>";
// it is split only when it contains no other keyword, since search windows
// are measured from the first keyword found in it.
func splitAtKeyword(elements []*syntax.Regexp, words map[string]bool, shortest int) (before, after []*syntax.Regexp, ok bool) {
	for i, e := range elements {
		if isKeywordElement(e, words) {
			return elements[:i], elements[i+1:], true
		}
		if pre, post, found := splitKeywordLiteral(e, words); found {
			return append(slices.Clone(elements[:i]), pre...), append(post, elements[i+1:]...), true
		}
		if !keywordFree(e, shortest) {
			return nil, nil, false
		}
	}
	return nil, nil, false
}

func splitKeywordLiteral(re *syntax.Regexp, words map[string]bool) (pre, post []*syntax.Regexp, ok bool) {
	if re.Op != syntax.OpLiteral {
		return nil, nil, false
	}
	folded := make([]byte, len(re.Rune))
	for i, r := range re.Rune {
		b, ok := guardFoldASCII(r)
		if !ok {
			return nil, nil, false
		}
		folded[i] = b
	}
	text := string(folded)
	at, length := -1, 0
	for word := range words {
		for offset := 0; ; {
			i := strings.Index(text[offset:], word)
			if i < 0 {
				break
			}
			if at >= 0 {
				return nil, nil, false
			}
			at, length = offset+i, len(word)
			offset += i + 1
		}
	}
	if at < 0 {
		return nil, nil, false
	}
	part := func(runes []rune) []*syntax.Regexp {
		if len(runes) == 0 {
			return nil
		}
		return []*syntax.Regexp{{Op: syntax.OpLiteral, Flags: re.Flags, Rune: slices.Clone(runes)}}
	}
	return part(re.Rune[:at]), part(re.Rune[at+length:]), true
}

// withoutOptionalSuffix drops syntax a match may end without. The guard
// accepts once any match is reachable, so its decisions are unchanged.
func withoutOptionalSuffix(re *syntax.Regexp) *syntax.Regexp {
	switch re.Op {
	case syntax.OpCapture:
		return withoutOptionalSuffix(re.Sub[0])
	case syntax.OpQuest, syntax.OpStar:
		return &syntax.Regexp{Op: syntax.OpEmptyMatch}
	case syntax.OpRepeat:
		if re.Min == 0 {
			return &syntax.Regexp{Op: syntax.OpEmptyMatch}
		}
	case syntax.OpConcat:
		subs := slices.Clone(re.Sub)
		for len(subs) > 0 {
			last := withoutOptionalSuffix(subs[len(subs)-1])
			if last.Op != syntax.OpEmptyMatch {
				subs[len(subs)-1] = last
				break
			}
			subs = subs[:len(subs)-1]
		}
		if len(subs) == 0 {
			return &syntax.Regexp{Op: syntax.OpEmptyMatch}
		}
		return concatOf(subs)
	case syntax.OpAlternate:
		subs := make([]*syntax.Regexp, len(re.Sub))
		for i, sub := range re.Sub {
			if subs[i] = withoutOptionalSuffix(sub); subs[i].Op == syntax.OpEmptyMatch {
				return subs[i]
			}
		}
		return &syntax.Regexp{Op: syntax.OpAlternate, Sub: subs}
	}
	return re
}

// matchesEmpty reports syntax that imposes no condition after the dropping
// of optional suffixes, including zero-width assertions the guard ignores.
func matchesEmpty(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if !matchesEmpty(sub) {
				return false
			}
		}
		return true
	case syntax.OpCapture:
		return matchesEmpty(re.Sub[0])
	}
	return false
}

func stripCaptures(re *syntax.Regexp) *syntax.Regexp {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	return re
}

func concatOf(subs []*syntax.Regexp) *syntax.Regexp {
	if len(subs) == 1 {
		return subs[0]
	}
	return &syntax.Regexp{Op: syntax.OpConcat, Sub: subs}
}

// The keyword element matches exactly the keywords that report a hit.
func isKeywordElement(re *syntax.Regexp, words map[string]bool) bool {
	literals, ok := foldedLiterals(re)
	if !ok || len(literals) == 0 {
		return false
	}
	for _, literal := range literals {
		if !words[literal] {
			return false
		}
	}
	return true
}

// keywordFree reports syntax whose matches cannot contain a keyword literal.
func keywordFree(re *syntax.Regexp, shortest int) bool {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary,
		syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return true
	case syntax.OpLiteral:
		return len(re.Rune) < shortest
	case syntax.OpCapture:
		return keywordFree(re.Sub[0], shortest)
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		// A repeated single rune class can match keyword text, but regexspan
		// never anchors on repetition, so the keyword element stays first.
		sub := stripCaptures(re.Sub[0])
		return sub.Op == syntax.OpCharClass || sub.Op == syntax.OpAnyChar || sub.Op == syntax.OpAnyCharNotNL ||
			sub.Op == syntax.OpLiteral && len(sub.Rune) == 1
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !keywordFree(sub, shortest) {
				return false
			}
		}
		return true
	}
	return false
}

// reverseSyntax matches the reversed strings of re. Empty-width assertions
// are kept in place; the guard treats them as satisfied.
func reverseSyntax(re *syntax.Regexp) *syntax.Regexp {
	reversed := *re
	switch re.Op {
	case syntax.OpLiteral:
		reversed.Rune = slices.Clone(re.Rune)
		slices.Reverse(reversed.Rune)
	case syntax.OpConcat:
		reversed.Sub = make([]*syntax.Regexp, len(re.Sub))
		for i, sub := range re.Sub {
			reversed.Sub[len(re.Sub)-1-i] = reverseSyntax(sub)
		}
	default:
		if len(re.Sub) > 0 {
			reversed.Sub = make([]*syntax.Regexp, len(re.Sub))
			for i, sub := range re.Sub {
				reversed.Sub[i] = reverseSyntax(sub)
			}
		}
	}
	return &reversed
}

const (
	// Larger programs rarely fit the state limit; skip them before building.
	maxGuardInsts  = 1024
	maxGuardCount  = 8
	maxGuardStates = 512
	// maxGuardBytes bounds the work per hit. Longer contexts are left to the
	// regex, which still sees the complete window.
	maxGuardBytes = 512
	deadState     = 0
)

// guardDFA recognizes the strings that can begin (or, reversed, end) an
// expression. Empty-width assertions count as satisfied and non-ASCII input
// is accepted, so the DFA over-approximates the expression.
type guardDFA struct {
	classes [utf8.RuneSelf]uint8
	stride  int
	next    []uint16
	accept  []bool
	start   uint16
}

// lazyGuardDFA builds the first candidate expression whose DFA fits.
type lazyGuardDFA struct {
	once       sync.Once
	candidates []*syntax.Regexp
	dfa        *guardDFA
}

func newLazyGuardDFA(candidates []*syntax.Regexp) *lazyGuardDFA {
	return &lazyGuardDFA{candidates: candidates}
}

func (l *lazyGuardDFA) get() *guardDFA {
	l.once.Do(func() {
		for _, candidate := range l.candidates {
			if l.dfa = compileGuardDFA(candidate); l.dfa != nil {
				break
			}
		}
		l.candidates = nil
	})
	return l.dfa
}

func (l *lazyGuardDFA) forward(raw string, pos int) bool {
	if l == nil {
		return true
	}
	d := l.get()
	if d == nil {
		return true
	}
	state := d.start
	limit := min(len(raw), pos+maxGuardBytes)
	for ; ; pos++ {
		if d.accept[state] {
			return true
		}
		if pos == len(raw) {
			return false
		}
		if pos == limit || raw[pos] >= utf8.RuneSelf {
			return true
		}
		if state = d.next[int(state)*d.stride+int(d.classes[raw[pos]])]; state == deadState {
			return false
		}
	}
}

func (l *lazyGuardDFA) backward(raw string, pos int) bool {
	if l == nil {
		return true
	}
	d := l.get()
	if d == nil {
		return true
	}
	state := d.start
	limit := max(0, pos-maxGuardBytes)
	for ; ; pos-- {
		if d.accept[state] {
			return true
		}
		if pos == 0 {
			return false
		}
		if pos == limit || raw[pos-1] >= utf8.RuneSelf {
			return true
		}
		if state = d.next[int(state)*d.stride+int(d.classes[raw[pos-1]])]; state == deadState {
			return false
		}
	}
}

func compileGuardDFA(re *syntax.Regexp) *guardDFA {
	prog, err := syntax.Compile(relaxCounts(re).Simplify())
	if err != nil || len(prog.Inst) > maxGuardInsts {
		return nil
	}
	n := len(prog.Inst)
	words := (n + 63) / 64

	// consuming[b] is the set of instructions that consume ASCII byte b.
	consuming := make([][]uint64, utf8.RuneSelf)
	for b := range consuming {
		set := make([]uint64, words)
		for pc := range prog.Inst {
			inst := &prog.Inst[pc]
			var ok bool
			switch inst.Op {
			case syntax.InstRune:
				ok = inst.MatchRune(rune(b))
			case syntax.InstRune1:
				ok = rune(b) == inst.Rune[0]
			case syntax.InstRuneAny:
				ok = true
			case syntax.InstRuneAnyNotNL:
				ok = b != '\n'
			}
			if ok {
				set[pc/64] |= 1 << (pc % 64)
			}
		}
		consuming[b] = set
	}

	// Bytes consumed by the same instructions share a column.
	d := &guardDFA{}
	columns := map[string]uint8{}
	var representatives []byte
	for b := range utf8.RuneSelf {
		k := string(appendWords(nil, consuming[b]))
		class, ok := columns[k]
		if !ok {
			class = uint8(len(columns))
			columns[k] = class
			representatives = append(representatives, byte(b))
		}
		d.classes[b] = class
	}
	d.stride = len(representatives)

	// A state is the sorted set of consuming instructions, plus Match,
	// reachable by following every non-consuming instruction.
	visited := make([]bool, n)
	var stack, touched []uint32
	closure := func(pcs []uint32) []uint32 {
		var out []uint32
		stack = append(stack[:0], pcs...)
		for len(stack) > 0 {
			pc := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if visited[pc] {
				continue
			}
			visited[pc] = true
			touched = append(touched, pc)
			inst := &prog.Inst[pc]
			switch inst.Op {
			case syntax.InstAlt, syntax.InstAltMatch:
				stack = append(stack, inst.Arg, inst.Out)
			case syntax.InstCapture, syntax.InstNop, syntax.InstEmptyWidth:
				stack = append(stack, inst.Out)
			case syntax.InstMatch, syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
				out = append(out, pc)
			}
		}
		for _, pc := range touched {
			visited[pc] = false
		}
		touched = touched[:0]
		slices.Sort(out)
		return out
	}

	ids := map[string]uint16{}
	sets := [][]uint32{nil} // state 0 is dead
	d.accept = []bool{false}
	var keyBuf []byte
	add := func(pcs []uint32) (uint16, bool) {
		if len(pcs) == 0 {
			return deadState, true
		}
		keyBuf = keyBuf[:0]
		for _, pc := range pcs {
			keyBuf = binary.LittleEndian.AppendUint32(keyBuf, pc)
		}
		if id, ok := ids[string(keyBuf)]; ok {
			return id, true
		}
		if len(sets) >= maxGuardStates {
			return 0, false
		}
		id := uint16(len(sets))
		ids[string(keyBuf)] = id
		sets = append(sets, pcs)
		d.accept = append(d.accept, slices.ContainsFunc(pcs, func(pc uint32) bool { return prog.Inst[pc].Op == syntax.InstMatch }))
		return id, true
	}
	start, _ := add(closure([]uint32{uint32(prog.Start)}))
	d.start = start
	d.next = make([]uint16, d.stride) // the dead row
	var targets []uint32
	for id := 1; id < len(sets); id++ {
		for _, b := range representatives {
			set := consuming[b]
			targets = targets[:0]
			for _, pc := range sets[id] {
				if set[pc/64]&(1<<(pc%64)) != 0 {
					targets = append(targets, prog.Inst[pc].Out)
				}
			}
			next, ok := add(closure(targets))
			if !ok {
				return nil
			}
			d.next = append(d.next, next)
		}
	}
	return d
}

// relaxCounts opens long counted repetitions. The accepted language only
// grows, so the guard stays sound, and its DFA no longer counts. Precision
// barely changes: identifiers rarely exceed the counts that rules allow.
func relaxCounts(re *syntax.Regexp) *syntax.Regexp {
	relaxed := *re
	if len(re.Sub) > 0 {
		relaxed.Sub = make([]*syntax.Regexp, len(re.Sub))
		for i, sub := range re.Sub {
			relaxed.Sub[i] = relaxCounts(sub)
		}
	}
	if re.Op == syntax.OpRepeat && (re.Max < 0 || re.Max > maxGuardCount) {
		relaxed.Min = min(re.Min, maxGuardCount)
		relaxed.Max = -1
	}
	return &relaxed
}

func appendWords(dst []byte, words []uint64) []byte {
	for _, w := range words {
		dst = binary.LittleEndian.AppendUint64(dst, w)
	}
	return dst
}
