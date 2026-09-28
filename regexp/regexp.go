package regexp

import (
	"regexp/syntax"
	"sync"
)

// Engine compiles regular expressions. Implementations must support concurrent
// calls and must not change behavior while a scanner or runtime uses them.
type Engine interface {
	Compile(str string) (CompiledRegexp, error)
	Version() string
}

// Regexp wraps a regular expression. Compilation is deferred until first match.
type Regexp struct {
	pattern   string
	engine    Engine
	numSubexp int

	once sync.Once
	e    CompiledRegexp
	err  error
}

func (r *Regexp) MatchString(s string) bool {
	e, ok := r.compiled()
	return ok && e.MatchString(s)
}
func (r *Regexp) FindString(s string) string {
	if e, ok := r.compiled(); ok {
		return e.FindString(s)
	}
	return ""
}
func (r *Regexp) FindStringSubmatch(s string) []string {
	if e, ok := r.compiled(); ok {
		return e.FindStringSubmatch(s)
	}
	return nil
}
func (r *Regexp) FindAllStringIndex(s string, n int) [][]int {
	if e, ok := r.compiled(); ok {
		return e.FindAllStringIndex(s, n)
	}
	return nil
}
func (r *Regexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	if e, ok := r.compiled(); ok {
		return e.FindAllStringSubmatchIndex(s, n)
	}
	return nil
}

// AnchoredFinder is implemented by compiled regexes that can restrict a search
// to matches beginning at given offsets while keeping the whole text as
// context for ^, $ and \b.
type AnchoredFinder interface {
	FindAllStringIndexAt(s string, starts []int, n int) [][]int
	FindAllStringSubmatchIndexAt(s string, starts []int, n int) [][]int
}

// FindAllStringIndexAt is FindAllStringIndex restricted to matches that begin
// at one of starts (ascending byte offsets). The caller must know that every
// match of the expression in s begins at a candidate; see the leading-literal
// analysis in the scanner. The second result is false when the engine cannot
// anchor at an offset, in which case the caller uses FindAllStringIndex.
func (r *Regexp) FindAllStringIndexAt(s string, starts []int, n int) ([][]int, bool) {
	e, ok := r.compiled()
	if !ok {
		return nil, true
	}
	anchored, ok := e.(AnchoredFinder)
	if !ok {
		return nil, false
	}
	return anchored.FindAllStringIndexAt(s, starts, n), true
}

// FindAllStringSubmatchIndexAt is FindAllStringSubmatchIndex under the same
// contract as FindAllStringIndexAt.
func (r *Regexp) FindAllStringSubmatchIndexAt(s string, starts []int, n int) ([][]int, bool) {
	e, ok := r.compiled()
	if !ok {
		return nil, true
	}
	anchored, ok := e.(AnchoredFinder)
	if !ok {
		return nil, false
	}
	return anchored.FindAllStringSubmatchIndexAt(s, starts, n), true
}

// AnchoredEngine is implemented by engines whose compiled regexes implement
// AnchoredFinder. AnchoredSearch preserves lazy regex compilation.
type AnchoredEngine interface {
	AnchoredSearch() bool
}

// SupportsAnchoredSearch reports whether regexes compiled by engine implement
// AnchoredFinder.
func SupportsAnchoredSearch(engine Engine) bool {
	anchored, ok := engine.(AnchoredEngine)
	return ok && anchored.AnchoredSearch()
}
func (r *Regexp) ReplaceAllString(src, repl string) string {
	if e, ok := r.compiled(); ok {
		return e.ReplaceAllString(src, repl)
	}
	return src
}
func (r *Regexp) NumSubexp() int {
	return r.numSubexp
}
func (r *Regexp) SubexpNames() []string {
	if e, ok := r.compiled(); ok {
		return e.SubexpNames()
	}
	return nil
}
func (r *Regexp) String() string {
	return r.pattern
}
func (r *Regexp) Compile() error {
	r.compiled()
	return r.err
}

func (r *Regexp) compiled() (CompiledRegexp, bool) {
	r.once.Do(func() {
		r.e, r.err = r.engine.Compile(r.pattern)
	})
	return r.e, r.err == nil && r.e != nil
}

// Compile parses a regular expression using the standard-library engine.
// Backend compilation is deferred until first use.
func Compile(str string) (*Regexp, error) {
	return CompileWithEngine(str, Stdlib{})
}

// CompileWithEngine parses a regular expression and retains engine for deferred
// compilation. A nil engine selects the standard-library engine.
func CompileWithEngine(str string, engine Engine) (*Regexp, error) {
	if engine == nil {
		engine = Stdlib{}
	}
	parsed, err := syntax.Parse(str, syntax.Perl)
	if err != nil {
		return nil, err
	}
	return &Regexp{
		pattern:   str,
		engine:    engine,
		numSubexp: parsed.MaxCap(),
	}, nil
}

// CompileParsedWithEngine is CompileWithEngine for a pattern the caller has
// already parsed with syntax.Perl flags; parsed must be the parse of str.
func CompileParsedWithEngine(str string, parsed *syntax.Regexp, engine Engine) *Regexp {
	if engine == nil {
		engine = Stdlib{}
	}
	return &Regexp{
		pattern:   str,
		engine:    engine,
		numSubexp: parsed.MaxCap(),
	}
}

// MustCompile is like Compile but panics on invalid syntax.
func MustCompile(str string) *Regexp {
	r, err := Compile(str)
	if err != nil {
		panic(err)
	}
	return r
}
