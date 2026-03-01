package regexp

import (
	"os"
	stdlib "regexp"

	gore2 "github.com/wasilibs/go-re2"
)

func init() {
	if v := os.Getenv("BETTERLEAKS_REGEX_ENGINE"); v != "" {
		SetEngine(v)
	}
}

// engine is an internal interface satisfied by both *stdlib.Regexp and *gore2.Regexp.
type engine interface {
	MatchString(s string) bool
	FindString(s string) string
	FindStringSubmatch(s string) []string
	FindAllStringIndex(s string, n int) [][]int
	ReplaceAllString(src, repl string) string
	NumSubexp() int
	String() string
}

// Regexp wraps a compiled regular expression. It is a concrete struct
// so that *Regexp works as a normal pointer (not pointer-to-interface).
type Regexp struct{ e engine }

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
func (r *Regexp) String() string {
	return r.e.String()
}

var currentEngine = "re2"

// Version returns the name of the active regex engine.
func Version() string { return currentEngine }

// SetEngine selects the regex engine used by subsequent MustCompile calls.
func SetEngine(name string) {
	switch name {
	case "stdlib", "re2":
		currentEngine = name
	default:
		panic("regexp: unknown engine: " + name)
	}
}

// Compile parses a regular expression using the currently selected engine.
// If successful, returns a [Regexp] object that can be used to match against text.
func Compile(str string) (*Regexp, error) {
	var (
		impl engine
		err  error
	)
	if currentEngine == "re2" {
		impl, err = gore2.Compile(str)
	} else {
		impl, err = stdlib.Compile(str)
	}
	if err != nil {
		return nil, err
	}
	return &Regexp{e: impl}, nil
}

// MustCompile compiles a regular expression using the currently selected engine.
func MustCompile(str string) *Regexp {
	var impl engine
	if currentEngine == "re2" {
		impl = gore2.MustCompile(str)
	} else {
		impl = stdlib.MustCompile(str)
	}
	return &Regexp{e: impl}
}
