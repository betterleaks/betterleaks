package regexp

import stdlib "regexp"

// Regexp wraps a compiled regular expression.
type Regexp = stdlib.Regexp

// Compile parses a regular expression and returns, if successful, a Regexp object.
func Compile(str string) (*Regexp, error) {
	return stdlib.Compile(str)
}

// MustCompile is like Compile but panics if the expression cannot be parsed.
func MustCompile(str string) *Regexp {
	return stdlib.MustCompile(str)
}
