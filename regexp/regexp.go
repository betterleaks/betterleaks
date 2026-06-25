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
	return r.compiled().MatchString(s)
}
func (r *Regexp) FindString(s string) string {
	return r.compiled().FindString(s)
}
func (r *Regexp) FindStringSubmatch(s string) []string {
	return r.compiled().FindStringSubmatch(s)
}
func (r *Regexp) FindAllStringIndex(s string, n int) [][]int {
	return r.compiled().FindAllStringIndex(s, n)
}
func (r *Regexp) ReplaceAllString(src, repl string) string {
	return r.compiled().ReplaceAllString(src, repl)
}
func (r *Regexp) NumSubexp() int {
	return r.numSubexp
}
func (r *Regexp) SubexpNames() []string {
	return r.compiled().SubexpNames()
}
func (r *Regexp) String() string {
	return r.pattern
}

func (r *Regexp) compiled() internal.CompiledRegexp {
	r.once.Do(func() {
		r.e, r.err = r.engine.Compile(r.pattern)
	})
	if r.err != nil {
		panic(r.err)
	}
	return r.e
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
