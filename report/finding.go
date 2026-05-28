package report

import (
	"fmt"
	"maps"
	"math"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/sources"
)

// Finding contains a whole bunch of information about a secret finding.
// Plenty of real estate in this bad boy so fillerup as needed.
type Finding struct {
	// Rule is the name of the rule that was matched
	RuleID      string
	Description string

	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	// Regex match that triggered the finding
	Match string

	// Captured secret
	Secret string

	// MatchContext contains surrounding lines around the match
	MatchContext string `json:",omitempty"`

	Line string `json:"-"`

	// CaptureGroups holds named regex capture groups from the match.
	CaptureGroups map[string]string `json:",omitempty"`

	// Fragment used for multi-part rule checking and CEL filtering
	Fragment *sources.Fragment `json:",omitempty"`

	// Attributes holds additional metadata about the finding.
	// Keys are defined in sources.Attr* constants (subject to change), but this is extensible for custom use cases.
	// Attributes are initially populated from the source's Fragment attributes and can be added to in the Detector or ValidationPool.
	// Deprecated "attribute" fields (File, Commit, etc.) are synced from Attributes for compatibility.
	Attributes map[string]string `json:",omitempty"`

	Tags []string

	// RequiredSets holds the Cartesian-product combinations of required findings.
	// Each set is one complete group of components that can be validated independently.
	RequiredSets []RequiredSet `json:",omitempty"`

	ValidationStatus string `json:",omitempty"`
	ValidationReason string `json:",omitempty"`
	// TODO maybe just use the Attribute map
	ValidationMeta map[string]any `json:",omitempty"`

	// unique identifier
	Fingerprint string

	// Hidden field to hold the context for CEL evaluation without bloating the report output.
	celContext string

	// Deprecated
	// File is the name of the file containing the finding
	// Deprecated
	File string
	// Deprecated
	SymlinkFile string
	// Deprecated
	Commit string
	// Deprecated
	Link string `json:",omitempty"`

	// Entropy is the shannon entropy of Value
	// Deprecated
	Entropy float32

	// Deprecated
	Author string
	// Deprecated
	Email string
	// Deprecated
	Date string
	// Deprecated
	Message string
}

// RequiredSet represents one combination of required findings (one element per
// required rule) from the Cartesian product. Each set can be validated
// independently and carries its own validation result.
type RequiredSet struct {
	Components       []*RequiredFinding `json:"components"`
	ValidationStatus string             `json:"validationStatus,omitempty"`
	ValidationReason string             `json:"validationReason,omitempty"`
}

type RequiredFinding struct {
	// contains a subset of the Finding fields
	// only used for reporting
	RuleID        string
	StartLine     int
	EndLine       int
	StartColumn   int
	EndColumn     int
	Line          string `json:"-"`
	Match         string
	Secret        string
	CaptureGroups map[string]string `json:",omitempty"`
}

// BuildRequiredSets generates the Cartesian product of the given required findings
// grouped by RuleID and populates f.RequiredSets. maxRequiredSets caps the total number of
// combos to prevent excessive memory use.
func (f *Finding) BuildRequiredSets(requiredFindings []*RequiredFinding, maxRequiredSets int) {
	if len(requiredFindings) == 0 {
		f.RequiredSets = nil
		return
	}

	// Group by RuleID, preserving first-occurrence order.
	var ruleOrder []string
	byRule := make(map[string][]*RequiredFinding)
	for _, rf := range requiredFindings {
		if _, exists := byRule[rf.RuleID]; !exists {
			ruleOrder = append(ruleOrder, rf.RuleID)
		}
		byRule[rf.RuleID] = append(byRule[rf.RuleID], rf)
	}

	products := cartesianFindings(ruleOrder, byRule, maxRequiredSets)
	f.RequiredSets = make([]RequiredSet, len(products))
	for i, components := range products {
		f.RequiredSets[i] = RequiredSet{Components: components}
	}
}

// cartesianFindings computes the Cartesian product over RequiredFinding slices
// keyed by ruleOrder. It stops early once maxRequiredSets is reached.
func cartesianFindings(ruleOrder []string, byRule map[string][]*RequiredFinding, maxRequiredSets int) [][]*RequiredFinding {
	if len(ruleOrder) == 0 {
		return [][]*RequiredFinding{{}}
	}

	head := ruleOrder[0]
	rest := cartesianFindings(ruleOrder[1:], byRule, maxRequiredSets)

	var result [][]*RequiredFinding
	for _, rf := range byRule[head] {
		for _, tail := range rest {
			row := make([]*RequiredFinding, 0, len(tail)+1)
			row = append(row, rf)
			row = append(row, tail...)
			result = append(result, row)
			if len(result) >= maxRequiredSets {
				return result
			}
		}
	}
	return result
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact(percent uint) {
	secret := MaskSecret(f.Secret, percent)
	if percent >= 100 {
		secret = "REDACTED"
	}
	f.Line = strings.ReplaceAll(f.Line, f.Secret, secret)
	f.Match = strings.ReplaceAll(f.Match, f.Secret, secret)
	f.MatchContext = strings.ReplaceAll(f.MatchContext, f.Secret, secret)
	f.Secret = secret

	seen := make(map[*RequiredFinding]struct{})
	for _, set := range f.RequiredSets {
		for _, comp := range set.Components {
			if _, ok := seen[comp]; ok {
				continue
			}
			seen[comp] = struct{}{}
			compSecret := MaskSecret(comp.Secret, percent)
			if percent >= 100 {
				compSecret = "REDACTED"
			}
			comp.Match = strings.ReplaceAll(comp.Match, comp.Secret, compSecret)
			comp.Secret = compSecret
		}
	}
}

// MaskSecret applies partial masking to a secret string based on the given percentage.
// At 100% the caller should use "REDACTED" instead.
func MaskSecret(secret string, percent uint) string {
	if percent > 100 {
		percent = 100
	}
	len := float64(len(secret))
	if len <= 0 {
		return secret
	}
	prc := float64(100 - percent)
	lth := int64(math.RoundToEven(len * prc / float64(100)))

	return secret[:lth] + "..."
}

func (f *Finding) SetCELContext(context string) {
	f.celContext = context
}

// Print writes a verbose finding using the pretty box format.
func (f Finding) Print(noColor bool, redact uint) {
	f.printPretty(noColor, redact)
}

// locateMatch returns the byte index of match within rawLine, using startCol
// (1-indexed byte offset) to disambiguate duplicate occurrences. When the
// exact position doesn't match, it searches forward then backward from the
// expected position before falling back to the first occurrence.
func locateMatch(rawLine, rawMatch string, startCol int) int {
	if rawLine == "" || rawMatch == "" {
		return -1
	}

	if startCol > 0 {
		idx := startCol - 1 // assumes StartColumn is a 1-based byte offset

		if idx >= 0 && idx+len(rawMatch) <= len(rawLine) &&
			rawLine[idx:idx+len(rawMatch)] == rawMatch {
			return idx
		}

		// Search near the expected position first, not from the start.
		if idx < 0 {
			idx = 0
		}
		if idx > len(rawLine) {
			idx = len(rawLine)
		}
		if rel := strings.Index(rawLine[idx:], rawMatch); rel >= 0 {
			return idx + rel
		}
		if prev := strings.LastIndex(rawLine[:idx], rawMatch); prev >= 0 {
			return prev
		}
	}

	// startCol <= 0 (no hint provided) or, redundantly, when the
	// forward+backward searches above already covered the full line.
	return strings.Index(rawLine, rawMatch)
}

func sortedMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (f *Finding) SetAttr(key, value string) {
	if f.Attributes == nil {
		f.Attributes = make(map[string]string)
	}
	f.Attributes[key] = value
}

func (f Finding) Attr(key string) string {
	if f.Attributes != nil {
		if value := f.Attributes[key]; value != "" {
			return value
		}
	}

	switch key {
	case sources.AttrPath:
		return f.File
	case sources.AttrFSSymlink:
		return f.SymlinkFile
	case sources.AttrGitSHA:
		return f.Commit
	case sources.AttrGitAuthorName:
		return f.Author
	case sources.AttrGitAuthorEmail:
		return f.Email
	case sources.AttrGitDate:
		return f.Date
	case sources.AttrGitMessage:
		return f.Message
	default:
		return ""
	}
}

// SetAttributes stores a copy of attrs and syncs deprecated source fields for compatibility.
func (f *Finding) SetAttributes(attrs map[string]string) {
	f.Attributes = maps.Clone(attrs)
	f.SyncDeprecatedSourceFields()
}

// Attribute is retained as a compatibility wrapper around Attr.
func (f Finding) Attribute(key string) string {
	return f.Attr(key)
}

// SyncDeprecatedSourceFields backfills deprecated fields from Attributes so
// legacy reporters, baselines, and templates continue to work.
func (f *Finding) SyncDeprecatedSourceFields() {
	f.File = f.Attr(sources.AttrPath)
	f.SymlinkFile = f.Attr(sources.AttrFSSymlink)
	f.Commit = f.Attr(sources.AttrGitSHA)
	f.Author = f.Attr(sources.AttrGitAuthorName)
	f.Email = f.Attr(sources.AttrGitAuthorEmail)
	f.Date = f.Attr(sources.AttrGitDate)
	f.Message = f.Attr(sources.AttrGitMessage)
}

func (f *Finding) SetFingerprint() {
	path := f.Attributes[sources.AttrPath]
	commit := f.Attributes[sources.AttrGitSHA]

	globalFingerprint := fmt.Sprintf("%s:%s:%d", path, f.RuleID, f.StartLine)
	if commit != "" {
		f.Fingerprint = fmt.Sprintf("%s:%s:%s:%d", commit, path, f.RuleID, f.StartLine)
	} else {
		f.Fingerprint = globalFingerprint
	}
}

// ToCELMap returns the fixed-shape map[string]string used as the `finding`
// variable in CEL filter and validation expressions.
func (f *Finding) ToCELMap() map[string]string {
	return map[string]string{
		"secret":      f.Secret,
		"match":       f.Match,
		"line":        f.Line,
		"rule_id":     f.RuleID,
		"description": f.Description,
		"context":     f.celContext,
	}
}
