package internal

// CompiledRegexp is an interface satisfied by both *stdlib.Regexp and *github.com/wasilibs/go-re2.Regexp.
type CompiledRegexp interface {
	MatchString(s string) bool
	FindString(s string) string
	FindStringSubmatch(s string) []string
	FindAllStringIndex(s string, n int) [][]int
	ReplaceAllString(src, repl string) string
	NumSubexp() int
	SubexpNames() []string
	String() string
}
