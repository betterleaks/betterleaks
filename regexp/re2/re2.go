package re2

import (
	"github.com/betterleaks/betterleaks/regexp/internal"

	gore2 "github.com/wasilibs/go-re2"
)

// RE2 is an Engine that uses github.com/wasilibs/go-re2.
type RE2 struct{}

func (RE2) Compile(str string) (internal.CompiledRegexp, error) {
	return gore2.Compile(str)
}

func (RE2) Version() string {
	return "re2"
}
