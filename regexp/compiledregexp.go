package regexp

// CompiledRegexp is the result of Engine.Compile. Its methods follow the
// standard library regexp.Regexp semantics and must support concurrent calls.
type CompiledRegexp interface {
	MatchString(s string) bool
	FindString(s string) string
	FindStringSubmatch(s string) []string
	FindAllStringIndex(s string, n int) [][]int
	FindAllStringSubmatchIndex(s string, n int) [][]int
	ReplaceAllString(src, repl string) string
	NumSubexp() int
	SubexpNames() []string
	String() string
}
