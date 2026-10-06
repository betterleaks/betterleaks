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

// MustCompile is like Compile but panics on invalid syntax.
func MustCompile(str string) *Regexp {
	r, err := Compile(str)
	if err != nil {
		panic(err)
	}
	return r
}
