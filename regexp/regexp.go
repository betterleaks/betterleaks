package regexp

import "github.com/betterleaks/betterleaks/regexp/internal"

type Engine interface {
	Compile(str string) (internal.CompiledRegexp, error)
	Version() string
}

// Regexp wraps a compiled regular expression. It is a concrete struct
// so that *Regexp works as a normal pointer (not pointer-to-interface).
type Regexp struct{ e internal.CompiledRegexp }

func (r *Regexp) MatchString(s string) bool {
	return r.e.MatchString(s)
}
func (r *Regexp) FindString(s string) string {
	return r.e.FindString(s)
}
func (r *Regexp) FindStringSubmatch(s string) []string {
	return r.e.FindStringSubmatch(s)
}
func (r *Regexp) FindAllStringIndex(s string, n int) [][]int {
	return r.e.FindAllStringIndex(s, n)
}
func (r *Regexp) ReplaceAllString(src, repl string) string {
	return r.e.ReplaceAllString(src, repl)
}
func (r *Regexp) NumSubexp() int {
	return r.e.NumSubexp()
}
func (r *Regexp) SubexpNames() []string {
	return r.e.SubexpNames()
}
func (r *Regexp) String() string {
	return r.e.String()
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
	impl, err := currentEngine.Compile(str)
	if err != nil {
		return nil, err
	}
	return &Regexp{e: impl}, nil
}

// MustCompile compiles a regular expression using the currently selected engine.
func MustCompile(str string) *Regexp {
	r, err := Compile(str)
	if err != nil {
		panic(err)
	}
	return r
}
