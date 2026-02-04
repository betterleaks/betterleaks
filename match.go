package betterleaks

// Match represents a potential secret match found in a fragment.
// It contains all the location based metadata needed for a finding.
type Match struct {
	RuleID          string
	MatchStart      int
	MatchEnd        int
	MatchString     string
	FullDecodedLine string

	// If the match has no pattern (e.g., path-only rules)
	NoPattern bool
	MetaTags  []string
}
