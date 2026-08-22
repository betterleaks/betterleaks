package internal

// CompiledRegexp is an interface satisfied by both *stdlib.Regexp and *github.com/betterleaks/go-re2.Regexp.
type CompiledRegexp interface {
	Match(b []byte) bool
	MatchString(s string) bool
	FindSubmatchIndex(b []byte) []int
	FindAllIndex(b []byte, n int) [][]int
	FindAllSubmatchIndex(b []byte, n int) [][]int
	FindString(s string) string
	FindStringSubmatch(s string) []string
	FindStringSubmatchIndex(s string) []int
	FindAllStringIndex(s string, n int) [][]int
	FindAllStringSubmatchIndex(s string, n int) [][]int
	ReplaceAllString(src, repl string) string
	NumSubexp() int
	SubexpNames() []string
	String() string
}
