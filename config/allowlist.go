package config

import (
	"errors"
	"fmt"
	stdregexp "regexp"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/regexp"
	"golang.org/x/exp/maps"
)

// ResourceMatcher matches a resource metadata key against a regex pattern.
// Parsed from "source:key:pattern" strings, e.g.:
//   - "git:author_email:.*@noreply\.github\.com"
//   - "[git,file]:path:vendor/.*"
//   - "*:path:\.env"
type ResourceMatcher struct {
	Sources []string // nil means wildcard (match any source)
	Key     string
	Pattern *regexp.Regexp
}

// ParseResourceMatcher parses a resource matcher string into a ResourceMatcher.
// Supported formats:
//   - "source:key:pattern"             — single source
//   - "[source1,source2]:key:pattern"  — multiple sources
//   - "*:key:pattern"                  — all sources (wildcard)
func ParseResourceMatcher(s string) (*ResourceMatcher, error) {
	var sources []string
	var rest string

	if strings.HasPrefix(s, "[") {
		// Multi-source: "[source1,source2]:key:pattern"
		closeBracket := strings.Index(s, "]")
		if closeBracket < 0 {
			return nil, fmt.Errorf("invalid resource matcher %q: unclosed bracket", s)
		}
		inner := s[1:closeBracket]
		if inner == "" {
			return nil, fmt.Errorf("invalid resource matcher %q: empty source list", s)
		}
		for _, src := range strings.Split(inner, ",") {
			src = strings.TrimSpace(src)
			if src == "" {
				return nil, fmt.Errorf("invalid resource matcher %q: empty source in list", s)
			}
			sources = append(sources, src)
		}
		// Expect "]:key:pattern"
		if closeBracket+1 >= len(s) || s[closeBracket+1] != ':' {
			return nil, fmt.Errorf("invalid resource matcher %q: expected \":\" after \"]\"", s)
		}
		rest = s[closeBracket+2:]
	} else {
		// Single source or wildcard: "source:key:pattern" / "*:key:pattern"
		firstColon := strings.Index(s, ":")
		if firstColon <= 0 {
			return nil, fmt.Errorf("invalid resource matcher %q: expected \"source:key:pattern\"", s)
		}
		src := s[:firstColon]
		if src != "*" {
			sources = []string{src}
		}
		// sources remains nil for wildcard
		rest = s[firstColon+1:]
	}

	// rest is "key:pattern"
	colonIdx := strings.Index(rest, ":")
	if colonIdx <= 0 {
		return nil, fmt.Errorf("invalid resource matcher %q: expected \"source:key:pattern\"", s)
	}
	key := rest[:colonIdx]
	pattern := rest[colonIdx+1:]

	if pattern == "" {
		return nil, fmt.Errorf("invalid resource matcher %q: pattern cannot be empty", s)
	}

	re := regexp.MustCompile(pattern)
	return &ResourceMatcher{Sources: sources, Key: key, Pattern: re}, nil
}

type AllowlistMatchCondition int

const (
	AllowlistMatchOr AllowlistMatchCondition = iota
	AllowlistMatchAnd
)

func (a AllowlistMatchCondition) String() string {
	return [...]string{
		"OR",
		"AND",
	}[a]
}

// Allowlist allows a rule to be ignored for specific
// regexes, paths, and/or commits
type Allowlist struct {
	// Short human readable description of the allowlist.
	Description string

	// MatchCondition determines whether all criteria must match. Defaults to "OR".
	MatchCondition AllowlistMatchCondition

	// Commits is a slice of commit SHAs that are allowed to be ignored.
	Commits []string

	// Paths is a slice of path regular expressions that are allowed to be ignored.
	Paths []*regexp.Regexp

	// Can be `match` or `line`.
	//
	// If `match` the _Regexes_ will be tested against the match of the _Rule.Regex_.
	//
	// If `line` the _Regexes_ will be tested against the entire line.
	//
	// If RegexTarget is empty, it will be tested against the found secret.
	RegexTarget string

	// Regexes is slice of content regular expressions that are allowed to be ignored.
	Regexes []*regexp.Regexp

	// StopWords is a slice of stop words that are allowed to be ignored.
	// This targets the _secret_, not the content of the regex match like the
	// Regexes slice.
	StopWords []string

	// Resources is a slice of resource matchers in "source:key:pattern" format.
	// These match against Resource.Metadata values using OR logic. For example:
	//   "git:author_email:dependabot.*"
	//   "*:path:vendor/.*"
	Resources []*ResourceMatcher

	// validated is an internal flag to track whether `Validate()` has been called.
	validated bool

	regexPat     *regexp.Regexp
	stopwordTrie *ahocorasick.Trie
	// resourceMap is indexed by [source][key] and contains combined regex patterns.
	// The wildcard source "*" is stored as an empty string key.
	resourceMap map[string]map[string]*regexp.Regexp
}

func (a *Allowlist) Validate() error {
	if a.validated {
		return nil
	}

	// Disallow empty allowlists.
	if len(a.Commits) == 0 &&
		len(a.Paths) == 0 &&
		len(a.Regexes) == 0 &&
		len(a.StopWords) == 0 &&
		len(a.Resources) == 0 {
		return errors.New("must contain at least one check for: commits, paths, regexes, stopwords, or resources")
	}

	// Deduplicate commits and stopwords.
	var uniqueCommits map[string]struct{}
	if len(a.Commits) > 0 {
		uniqueCommits = make(map[string]struct{})
		for _, commit := range a.Commits {
			// Commits are case-insensitive.
			uniqueCommits[strings.TrimSpace(strings.ToLower(commit))] = struct{}{}
		}
		a.Commits = maps.Keys(uniqueCommits)
	}
	if len(a.StopWords) > 0 {
		uniqueStopwords := make(map[string]struct{})
		for _, stopWord := range a.StopWords {
			uniqueStopwords[strings.ToLower(stopWord)] = struct{}{}
		}

		values := maps.Keys(uniqueStopwords)
		a.StopWords = values
		a.stopwordTrie = ahocorasick.NewTrieBuilder().AddStrings(values).Build()
	}

	// Combine regex patterns into a single expression.
	if len(a.Regexes) > 0 {
		a.regexPat = joinRegexOr(a.Regexes)
	}

	// Convert Paths to ResourceMatchers (wildcard source, key="path").
	// This unifies path filtering through the resource matching path.
	if len(a.Paths) > 0 {
		pathPat := joinRegexOr(a.Paths)
		a.Resources = append(a.Resources, &ResourceMatcher{
			Sources: nil, // wildcard
			Key:     "path",
			Pattern: pathPat,
		})
	}

	// Convert Commits to ResourceMatchers (source="git", key="commit_sha").
	if len(a.Commits) > 0 {
		var commitPatterns []*regexp.Regexp
		for commit := range uniqueCommits {
			commitPatterns = append(commitPatterns, regexp.MustCompile(`(?i)^`+stdregexp.QuoteMeta(commit)+`$`))
		}
		a.Resources = append(a.Resources, &ResourceMatcher{
			Sources: nil, // wildcard — commits could come from any git-like source
			Key:     "commit_sha",
			Pattern: joinRegexOr(commitPatterns),
		})
	}

	// Build resourceMap for efficient lookup by [source][key].
	if len(a.Resources) > 0 {
		// Group patterns by source and key.
		type sourceKey struct {
			source string // empty string for wildcard
			key    string
		}
		grouped := make(map[sourceKey][]*regexp.Regexp)

		for _, rm := range a.Resources {
			if rm.Sources == nil {
				// Wildcard source - store with empty string key.
				sk := sourceKey{source: "", key: rm.Key}
				grouped[sk] = append(grouped[sk], rm.Pattern)
			} else {
				// Specific sources.
				for _, src := range rm.Sources {
					sk := sourceKey{source: src, key: rm.Key}
					grouped[sk] = append(grouped[sk], rm.Pattern)
				}
			}
		}

		// Combine patterns for each [source][key] combination.
		a.resourceMap = make(map[string]map[string]*regexp.Regexp)
		for sk, patterns := range grouped {
			if a.resourceMap[sk.source] == nil {
				a.resourceMap[sk.source] = make(map[string]*regexp.Regexp)
			}
			a.resourceMap[sk.source][sk.key] = joinRegexOr(patterns)
		}
	}

	a.validated = true
	return nil
}

// RegexAllowed returns true if the regex is allowed to be ignored.
func (a *Allowlist) RegexAllowed(secret string) bool {
	if a == nil || secret == "" {
		return false
	}
	if a.regexPat != nil {
		return a.regexPat.MatchString(secret)
	} else if len(a.Regexes) > 0 {
		return anyRegexMatch(secret, a.Regexes)
	}
	return false
}

// ResourceAllowed returns true if any resource matcher matches (OR logic).
func (a *Allowlist) ResourceAllowed(source string, metadata map[string]string) bool {
	if a == nil || len(a.Resources) == 0 || metadata == nil {
		return false
	}

	// Fast path: use the pre-compiled resourceMap if available.
	if a.resourceMap != nil {
		// Check wildcard patterns first (empty string key).
		if wildcardKeys := a.resourceMap[""]; wildcardKeys != nil {
			for key, pattern := range wildcardKeys {
				if val, ok := metadata[key]; ok && pattern.MatchString(val) {
					return true
				}
			}
		}

		// Check source-specific patterns.
		if sourceKeys := a.resourceMap[source]; sourceKeys != nil {
			for key, pattern := range sourceKeys {
				if val, ok := metadata[key]; ok && pattern.MatchString(val) {
					return true
				}
			}
		}

		return false
	}

	// Fallback: iterate through Resources (for unvalidated allowlists).
	for _, m := range a.Resources {
		if !m.matchesSource(source) {
			continue
		}
		val, ok := metadata[m.Key]
		if ok && m.Pattern.MatchString(val) {
			return true
		}
	}
	return false
}

// ResourceKeyAllowed returns true if any resource matcher matches the given
// source and single key/value pair. This is useful for early-exit checks
// during enumeration when full metadata is not yet available.
func (a *Allowlist) ResourceKeyAllowed(source, key, value string) bool {
	if a == nil || len(a.Resources) == 0 || value == "" {
		return false
	}

	// Fast path: use the pre-compiled resourceMap if available.
	if a.resourceMap != nil {
		// Check wildcard patterns first (empty string key).
		if wildcardKeys := a.resourceMap[""]; wildcardKeys != nil {
			if pattern, ok := wildcardKeys[key]; ok && pattern.MatchString(value) {
				return true
			}
		}

		// Check source-specific patterns.
		if sourceKeys := a.resourceMap[source]; sourceKeys != nil {
			if pattern, ok := sourceKeys[key]; ok && pattern.MatchString(value) {
				return true
			}
		}

		return false
	}

	// Fallback: iterate through Resources (for unvalidated allowlists).
	for _, m := range a.Resources {
		if !m.matchesSource(source) {
			continue
		}
		if m.Key == key && m.Pattern.MatchString(value) {
			return true
		}
	}
	return false
}

// matchesSource returns true if the given source matches this matcher.
// A nil Sources slice means wildcard (match any source).
func (m *ResourceMatcher) matchesSource(source string) bool {
	if m.Sources == nil {
		return true
	}
	for _, s := range m.Sources {
		if s == source {
			return true
		}
	}
	return false
}

// fragmentAllowed returns true if this allowlist matches the given resource context.
// Only evaluates resource-level checks since content is not available at fragment level.
// In AND mode, returns false if content-based checks (regexes/stopwords) are required.
func (a *Allowlist) fragmentAllowed(source string, metadata map[string]string) bool {
	if a == nil {
		return false
	}
	resourceAllowed := a.ResourceAllowed(source, metadata)

	if a.MatchCondition == AllowlistMatchAnd {
		// Can't satisfy AND if content checks are required but unavailable.
		if len(a.Regexes) > 0 || len(a.StopWords) > 0 {
			return false
		}
		return len(a.Resources) > 0 && resourceAllowed
	}
	return resourceAllowed
}

// findingAllowed returns true if this allowlist matches the given finding context.
// Evaluates all checks: resources, regexes, and stopwords.
// The regexTarget parameter is the resolved string to test regexes against
// (secret, match, or line depending on RegexTarget).
func (a *Allowlist) findingAllowed(regexTarget, secret, source string, metadata map[string]string) bool {
	if a == nil {
		return false
	}

	resourceAllowed := a.ResourceAllowed(source, metadata)
	regexAllowed := a.RegexAllowed(regexTarget)
	containsStopword, _ := a.ContainsStopWord(secret)

	if a.MatchCondition == AllowlistMatchAnd {
		var checks []bool
		if len(a.Regexes) > 0 {
			checks = append(checks, regexAllowed)
		}
		if len(a.StopWords) > 0 {
			checks = append(checks, containsStopword)
		}
		if len(a.Resources) > 0 {
			checks = append(checks, resourceAllowed)
		}
		for _, c := range checks {
			if !c {
				return false
			}
		}
		return len(checks) > 0
	}

	return regexAllowed || containsStopword || resourceAllowed
}

func (a *Allowlist) ContainsStopWord(s string) (bool, string) {
	if a == nil || s == "" {
		return false, ""
	}

	s = strings.ToLower(s)
	if a.stopwordTrie != nil {
		if m := a.stopwordTrie.MatchFirstString(s); m != nil {
			return true, m.MatchString()
		}
	} else if len(a.StopWords) > 0 {
		for _, stopWord := range a.StopWords {
			if strings.Contains(s, stopWord) {
				return true, stopWord
			}
		}
	}
	return false, ""
}

// FragmentAllowed returns true if the fragment should be scanned (not allowlisted).
// Returns false if the fragment matches any global allowlist.
func (c *Config) FragmentAllowed(fragment betterleaks.Fragment) bool {
	if fragment.Path != "" {
		if fragment.Path == c.Path {
			logging.Trace().Msg("skipping file: matches config or baseline path")
			return false
		}
	}

	var source string
	var metadata map[string]string
	if fragment.Resource != nil {
		source = fragment.Resource.Source
		metadata = fragment.Resource.Metadata
	}

	for _, a := range c.Allowlists {
		if a.fragmentAllowed(source, metadata) {
			return false
		}
	}
	return true
}

// FindingAllowed returns true if the finding should be reported (not allowlisted).
// It checks global allowlists and rule-level allowlists.
// Uses finding.DecodedLine for regex target resolution.
func (c *Config) FindingAllowed(finding betterleaks.Finding, rule Rule) bool {
	var source string
	var metadata map[string]string
	if finding.Fragment != nil && finding.Fragment.Resource != nil {
		source = finding.Fragment.Resource.Source
		metadata = finding.Fragment.Resource.Metadata
	}

	for _, a := range c.Allowlists {
		regexTarget := resolveRegexTarget(a.RegexTarget, finding)
		if a.findingAllowed(regexTarget, finding.Secret, source, metadata) {
			return false
		}
	}
	for _, a := range rule.Allowlists {
		regexTarget := resolveRegexTarget(a.RegexTarget, finding)
		if a.findingAllowed(regexTarget, finding.Secret, source, metadata) {
			return false
		}
	}

	return true
}

// resolveRegexTarget picks the string to test regexes against based on the allowlist's RegexTarget.
func resolveRegexTarget(target string, finding betterleaks.Finding) string {
	switch target {
	case "match":
		return finding.Match
	case "line":
		return finding.DecodedLine
	default:
		return finding.Secret
	}
}
