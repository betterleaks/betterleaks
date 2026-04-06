package regexp

import (
	"regexp"

	"github.com/betterleaks/betterleaks/regexp/internal"
)

// Stdlib is an Engine that uses the standard regexp package.
type Stdlib struct{}

func (Stdlib) Compile(str string) (internal.CompiledRegexp, error) {
	return regexp.Compile(str)
}

func (Stdlib) Version() string {
	return "stdlib"
}
