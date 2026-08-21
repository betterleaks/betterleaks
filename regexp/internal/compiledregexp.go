package internal

// CompiledRegexp is an interface satisfied by both *stdlib.Regexp and *github.com/betterleaks/go-re2.Regexp.
type CompiledRegexp interface {
	Match(b []byte) bool
	MatchString(s string) bool
	FindAllIndex(b []byte, n int) [][]int
	FindString(s string) string
	FindStringSubmatch(s string) []string
	FindAllStringIndex(s string, n int) [][]int
	ReplaceAllString(src, repl string) string
	NumSubexp() int
	SubexpNames() []string
	String() string
}
