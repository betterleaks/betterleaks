package report

import (
	"maps"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/sources"
)

// Finding describes one detected secret and the source metadata needed to
// report, validate, and baseline it.
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

	// Attributes holds source and detector metadata. Well-known keys are defined
	// by sources.Attr* constants; callers may add their own keys.
	Attributes map[string]string `json:",omitempty"`

	Tags []string

	RuleSpecificity int `json:"-"`

	// ComponentSets holds the Cartesian-product combinations of component findings.
	// Each set is one complete group of components that can be validated independently.
	ComponentSets []ComponentSet `json:",omitempty"`

	ValidationStatus ValidationStatus `json:",omitempty"`
	ValidationReason string           `json:",omitempty"`
	ValidationMeta   map[string]any   `json:",omitempty"`

	// Fingerprint is a stable source/rule/line identifier.
	Fingerprint string

	// Hidden field to hold expression context without bloating the report output.
	exprContext string
}

// ComponentSet represents one combination of component findings (one element per
// matched component rule) from the Cartesian product. Each set can be validated
// independently and carries its own validation result.
type ComponentSet struct {
	Components       []*ComponentFinding `json:"components"`
	ValidationStatus ValidationStatus    `json:"validationStatus,omitempty"`
	ValidationReason string              `json:"validationReason,omitempty"`
}

type ComponentFinding struct {
	// ComponentFinding contains the subset of Finding needed to report and
	// validate a composite rule component.
	RuleID      string
	Optional    bool
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Line        string `json:"-"`
	Match       string
	Secret      string
	// CaptureGroups holds named regex capture groups from the component match.
	CaptureGroups   map[string]string `json:",omitempty"`
	RuleSpecificity int               `json:"-"`
}

// BuildComponentSets generates the Cartesian product of the given component findings
// grouped by RuleID and populates f.ComponentSets. maxComponentSets caps the total number of
// combos to prevent excessive memory use.
func (f *Finding) BuildComponentSets(componentFindings []*ComponentFinding, maxComponentSets int) {
	if len(componentFindings) == 0 || maxComponentSets <= 0 {
		f.ComponentSets = nil
		return
	}

	// Group by RuleID, preserving first-occurrence order.
	var ruleOrder []string
	byRule := make(map[string][]*ComponentFinding)
	for _, rf := range componentFindings {
		if rf == nil {
			continue
		}
		if _, exists := byRule[rf.RuleID]; !exists {
			ruleOrder = append(ruleOrder, rf.RuleID)
		}
		byRule[rf.RuleID] = append(byRule[rf.RuleID], rf)
	}
	if len(ruleOrder) == 0 {
		f.ComponentSets = nil
		return
	}

	products := cartesianFindings(ruleOrder, byRule, maxComponentSets)
	f.ComponentSets = make([]ComponentSet, len(products))
	for i, components := range products {
		f.ComponentSets[i] = ComponentSet{Components: components}
	}
}

// cartesianFindings computes the Cartesian product over ComponentFinding slices
// keyed by ruleOrder. It stops early once maxComponentSets is reached.
func cartesianFindings(ruleOrder []string, byRule map[string][]*ComponentFinding, maxComponentSets int) [][]*ComponentFinding {
	if len(ruleOrder) == 0 {
		return [][]*ComponentFinding{{}}
	}

	head := ruleOrder[0]
	rest := cartesianFindings(ruleOrder[1:], byRule, maxComponentSets)

	var result [][]*ComponentFinding
	for _, rf := range byRule[head] {
		for _, tail := range rest {
			row := make([]*ComponentFinding, 0, len(tail)+1)
			row = append(row, rf)
			row = append(row, tail...)
			result = append(result, row)
			if len(result) >= maxComponentSets {
				return result
			}
		}
	}
	return result
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact(percent uint) {
	if f == nil || percent == 0 {
		return
	}
	if original := f.Secret; original != "" {
		secret := MaskSecret(original, percent)
		if percent >= 100 {
			secret = "REDACTED"
		}
		f.Line = strings.ReplaceAll(f.Line, original, secret)
		f.Match = strings.ReplaceAll(f.Match, original, secret)
		f.MatchContext = strings.ReplaceAll(f.MatchContext, original, secret)
		// Capture groups can contain the secret verbatim and are emitted in JSON,
		// JUnit, and template reports, so they must be redacted too.
		for key, value := range f.CaptureGroups {
			f.CaptureGroups[key] = strings.ReplaceAll(value, original, secret)
		}
		f.Secret = secret
	}

	var seen map[*ComponentFinding]struct{}
	for _, set := range f.ComponentSets {
		for _, comp := range set.Components {
			if comp == nil {
				continue
			}
			if seen == nil {
				seen = make(map[*ComponentFinding]struct{}, len(set.Components))
			}
			if _, ok := seen[comp]; ok {
				continue
			}
			seen[comp] = struct{}{}
			original := comp.Secret
			if original == "" {
				continue
			}
			compSecret := MaskSecret(original, percent)
			if percent >= 100 {
				compSecret = "REDACTED"
			}
			comp.Line = strings.ReplaceAll(comp.Line, original, compSecret)
			comp.Match = strings.ReplaceAll(comp.Match, original, compSecret)
			for key, value := range comp.CaptureGroups {
				comp.CaptureGroups[key] = strings.ReplaceAll(value, original, compSecret)
			}
			comp.Secret = compSecret
		}
	}
}

// MaskSecret applies partial masking to a secret string based on the given percentage.
// At 100% the caller should use "REDACTED" instead.
func MaskSecret(secret string, percent uint) string {
	if percent == 0 {
		return secret
	}
	if percent > 100 {
		percent = 100
	}
	// Operate on runes, not bytes: slicing a multi-byte UTF-8 secret by byte
	// offset can split a rune (producing invalid UTF-8) and skews the mask ratio.
	runes := []rune(secret)
	total := float64(len(runes))
	if total <= 0 {
		return secret
	}
	prc := float64(100 - percent)
	keep := int(math.RoundToEven(total * prc / float64(100)))

	return string(runes[:keep]) + "..."
}

func (f *Finding) SetExprContext(context string) {
	f.exprContext = context
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

func (f *Finding) Attr(key string) string {
	return f.Attributes[key]
}

// SetAttributes stores a copy of attrs.
func (f *Finding) SetAttributes(attrs map[string]string) {
	f.Attributes = maps.Clone(attrs)
}

func (f *Finding) SetFingerprint() {
	path := f.Attributes[sources.AttrPath]
	commit := f.Attributes[sources.AttrGitSHA]

	var digits [20]byte
	line := strconv.AppendInt(digits[:0], int64(f.StartLine), 10)
	capacity := len(path) + len(f.RuleID) + len(line) + 2
	if commit != "" {
		capacity += len(commit) + 1
	}
	var fingerprint strings.Builder
	fingerprint.Grow(capacity)
	if commit != "" {
		fingerprint.WriteString(commit)
		fingerprint.WriteByte(':')
	}
	fingerprint.WriteString(path)
	fingerprint.WriteByte(':')
	fingerprint.WriteString(f.RuleID)
	fingerprint.WriteByte(':')
	_, _ = fingerprint.Write(line)
	f.Fingerprint = fingerprint.String()
}

// ToExprMap returns the fixed-shape map[string]string used as the `finding`
// variable in filter and validation expressions.
func (f *Finding) ToExprMap() map[string]string {
	return map[string]string{
		"secret":      f.Secret,
		"match":       f.Match,
		"line":        f.Line,
		"rule_id":     f.RuleID,
		"description": f.Description,
		"context":     f.exprContext,
	}
}
