package regexp

import (
	"regexp/syntax"
	"sync"

	"github.com/betterleaks/betterleaks/regexp/internal"
)

type Engine interface {
	Compile(str string) (internal.CompiledRegexp, error)
	Version() string
}

// Regexp wraps a regular expression. Compilation is deferred until first match.
type Regexp struct {
	pattern   string
	engine    Engine
	numSubexp int

	once sync.Once
	e    internal.CompiledRegexp
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

func (r *Regexp) compiled() (internal.CompiledRegexp, bool) {
	r.once.Do(func() {
		r.e, r.err = r.engine.Compile(r.pattern)
	})
	return r.e, r.err == nil && r.e != nil
}

var currentEngine Engine = Stdlib{}

// Version returns the name of the active regex engine.
func Version() string { return currentEngine.Version() }

// SetEngine selects the regex engine used by subsequent MustCompile calls.
func SetEngine(engine Engine) {
	currentEngine = engine
}

// Compile parses a regular expression using the currently selected engine.
// If successful, returns a [Regexp] object that can be used to match against text.
func Compile(str string) (*Regexp, error) {
	parsed, err := syntax.Parse(str, syntax.Perl)
	if err != nil {
		return nil, err
	}
	return &Regexp{
		pattern:   str,
		engine:    currentEngine,
		numSubexp: parsed.MaxCap(),
	}, nil
}

// MustCompile compiles a regular expression using the currently selected engine.
func MustCompile(str string) *Regexp {
	r, err := Compile(str)
	if err != nil {
		panic(err)
	}
	return r
}
