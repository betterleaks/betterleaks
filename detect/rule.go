package detect

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
)

// compiledRule owns the runtime regexes for an immutable snapshot of a rule.
// Regex backends are initialized lazily, unless precompilation is requested.
type compiledRule struct {
	rule  config.Rule
	regex *regexp.Regexp
	path  *regexp.Regexp
}
