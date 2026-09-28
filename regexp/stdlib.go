package regexp

import "regexp"

// Stdlib is an Engine that uses the standard regexp package.
type Stdlib struct{}

func (Stdlib) Compile(str string) (CompiledRegexp, error) {
	return regexp.Compile(str)
}

func (Stdlib) Version() string {
	return "stdlib"
}
