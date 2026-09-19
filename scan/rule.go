package scan

import (
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/contextwindow"
	"github.com/betterleaks/betterleaks/v2/internal/regexspan"
	"github.com/betterleaks/betterleaks/v2/regexp"
)

// compiledRule owns the runtime regexes for an immutable snapshot of a rule.
// Regex backends are initialized lazily, unless precompilation is requested.
type compiledRule struct {
	guard         *assignmentGuard
	span          *regexspan.Plan
	searchAnchors []string
	rule          config.Rule
	regex         *regexp.Regexp
	path          *regexp.Regexp
	pathSuffixes  []string
	filter        *lazyFilter
	components    []compiledComponent
}

type compiledComponent struct {
	ruleIndex int
	window    contextwindow.Spec
	optional  bool
}

// Shorter anchors can locate complete windows even when a keyword contains
// punctuation separated by optional whitespace in the regex. Compile proves
// their coverage; the original keywords still decide rule eligibility.
func compilePrefixWindows(pattern string, keywords []string) (*regexspan.Plan, []string) {
	prefixes := make([]string, len(keywords))
	changed := false
	for i, keyword := range keywords {
		prefixes[i] = strings.TrimRightFunc(keyword, func(r rune) bool {
			return r < 128 && !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
		})
		changed = changed || prefixes[i] != keyword
	}
	if !changed {
		return nil, nil
	}
	plan := regexspan.Compile(pattern, prefixes)
	if plan == nil {
		return nil, nil
	}
	return plan, prefixes
}
