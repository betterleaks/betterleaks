package report

import (
	"encoding/json"
	"maps"
	"math"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/internal/confidence"
	"github.com/betterleaks/betterleaks/sources"
)

// Finding describes a secret found by a rule.
type Finding struct {
	RuleID      string `json:"ruleID"`
	Description string `json:"description"`
	Confidence  string `json:"confidence"`

	// Regex match that triggered the finding
	Match string `json:"match"`

	// Captured secret
	Secret string `json:"secret"`

	// MatchContext contains surrounding lines around the match
	MatchContext string `json:"matchContext,omitempty"`

	// CaptureGroups holds named regex capture groups from the match.
	CaptureGroups map[string]string `json:"captureGroups,omitempty"`

	// Attributes holds extensible source metadata. Well-known keys are defined
	// by the sources package.
	Attributes map[string]string `json:"attributes,omitempty"`

	Location   Location   `json:"location"`
	Validation Validation `json:"validation,omitzero"`
	Analysis   Analysis   `json:"analysis,omitzero"`

	// ComponentSets holds the Cartesian-product combinations of component findings.
	// Each set is one complete group of components that can be validated independently.
	ComponentSets []ComponentSet `json:"componentSets,omitempty"`

	Tags []string `json:"tags"`

	Line            string `json:"-"`
	RuleSpecificity int    `json:"-"`

	// Hidden field to hold expression context without bloating the report output.
	exprContext string
}

// MarshalJSON omits attributes that exist only to coordinate the scanning
// pipeline. They remain available on the in-memory finding for filters,
// validation, and analysis expressions, but are not part of the report schema.
func (f Finding) MarshalJSON() ([]byte, error) {
	type wireFinding Finding

	wire := wireFinding(f)
	wire.Attributes = reportAttributes(f.Attributes)
	return json.Marshal(wire)
}

func reportAttributes(attributes map[string]string) map[string]string {
	if _, internal := attributes[sources.AttrFSFirstFragment]; !internal {
		return attributes
	}

	visible := maps.Clone(attributes)
	delete(visible, sources.AttrFSFirstFragment)
	if len(visible) == 0 {
		return nil
	}
	return visible
}

// Location identifies a finding's position in its source.
type Location struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}

// Validation describes the result of validating a finding.
type Validation struct {
	Status   ValidationStatus `json:"status,omitempty"`
	Reason   string           `json:"reason,omitempty"`
	Metadata map[string]any   `json:"metadata,omitempty"`
}

func (v Validation) IsZero() bool {
	return v.Status == "" && v.Reason == "" && len(v.Metadata) == 0
}

// ComponentSet represents one combination of component findings (one element per
// matched component rule) from the Cartesian product. Each set can be validated
// independently and carries its own validation result.
type ComponentSet struct {
	Components []*ComponentFinding `json:"components"`
	Validation Validation          `json:"validation,omitzero"`
	Analysis   Analysis            `json:"analysis,omitzero"`
}

type ComponentFinding struct {
	// contains a subset of the Finding fields
	// only used for reporting
	RuleID   string `json:"ruleID"`
	Optional bool   `json:"optional,omitempty"`
	Line     string `json:"-"`
	Match    string `json:"match"`
	Secret   string `json:"secret"`
	// CaptureGroups holds named regex capture groups from the component match.
	CaptureGroups   map[string]string `json:"captureGroups,omitempty"`
	Location        Location          `json:"location"`
	RuleSpecificity int               `json:"-"`
}

// BuildComponentSets generates the Cartesian product of the given component findings
// grouped by RuleID and populates f.ComponentSets. maxComponentSets caps the total number of
// combos to prevent excessive memory use.
func (f *Finding) BuildComponentSets(componentFindings []*ComponentFinding, maxComponentSets int) {
	if len(componentFindings) == 0 {
		f.ComponentSets = nil
		return
	}

	// Group by RuleID, preserving first-occurrence order.
	var ruleOrder []string
	byRule := make(map[string][]*ComponentFinding)
	for _, rf := range componentFindings {
		if _, exists := byRule[rf.RuleID]; !exists {
			ruleOrder = append(ruleOrder, rf.RuleID)
		}
		byRule[rf.RuleID] = append(byRule[rf.RuleID], rf)
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
	analysisSecrets := []string{f.Secret}
	for _, set := range f.ComponentSets {
		for _, component := range set.Components {
			if component != nil {
				analysisSecrets = append(analysisSecrets, component.Secret)
			}
		}
	}

	secret := MaskSecret(f.Secret, percent)
	if percent >= 100 {
		secret = "REDACTED"
	}
	f.Line = strings.ReplaceAll(f.Line, f.Secret, secret)
	f.Match = strings.ReplaceAll(f.Match, f.Secret, secret)
	f.MatchContext = strings.ReplaceAll(f.MatchContext, f.Secret, secret)
	// Capture groups can contain the secret verbatim and are emitted in JSON,
	// JUnit, and template reports, so they must be redacted too. Done before
	// f.Secret is overwritten so the original value is still available to match.
	for k, v := range f.CaptureGroups {
		f.CaptureGroups[k] = strings.ReplaceAll(v, f.Secret, secret)
	}
	f.Secret = secret

	seen := make(map[*ComponentFinding]struct{})
	for _, set := range f.ComponentSets {
		for _, comp := range set.Components {
			if _, ok := seen[comp]; ok {
				continue
			}
			seen[comp] = struct{}{}
			compSecret := MaskSecret(comp.Secret, percent)
			if percent >= 100 {
				compSecret = "REDACTED"
			}
			comp.Line = strings.ReplaceAll(comp.Line, comp.Secret, compSecret)
			comp.Match = strings.ReplaceAll(comp.Match, comp.Secret, compSecret)
			for k, v := range comp.CaptureGroups {
				comp.CaptureGroups[k] = strings.ReplaceAll(v, comp.Secret, compSecret)
			}
			comp.Secret = compSecret
		}
	}

	f.Analysis = SanitizeAnalysis(f.Analysis, analysisSecrets)
	for i := range f.ComponentSets {
		f.ComponentSets[i].Analysis = SanitizeAnalysis(f.ComponentSets[i].Analysis, analysisSecrets)
	}
}

// RedactedCopy returns a redacted finding without modifying maps, component
// findings, or component sets shared with the original finding.
func (f Finding) RedactedCopy(percent uint) Finding {
	f.CaptureGroups = maps.Clone(f.CaptureGroups)

	if len(f.ComponentSets) > 0 {
		componentCopies := make(map[*ComponentFinding]*ComponentFinding)
		sets := make([]ComponentSet, len(f.ComponentSets))
		for i, set := range f.ComponentSets {
			sets[i] = set
			sets[i].Components = make([]*ComponentFinding, len(set.Components))
			for j, component := range set.Components {
				if component == nil {
					continue
				}
				componentCopy, ok := componentCopies[component]
				if !ok {
					copyValue := *component
					copyValue.CaptureGroups = maps.Clone(component.CaptureGroups)
					componentCopy = &copyValue
					componentCopies[component] = componentCopy
				}
				sets[i].Components[j] = componentCopy
			}
		}
		f.ComponentSets = sets
	}
	f.Redact(percent)
	return f
}

// MaskSecret applies partial masking to a secret string based on the given percentage.
// At 100% the caller should use "REDACTED" instead.
func MaskSecret(secret string, percent uint) string {
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
	if key == confidence.Attribute {
		f.Confidence = value
		delete(f.Attributes, key)
		return
	}
	if f.Attributes == nil {
		f.Attributes = make(map[string]string)
	}
	f.Attributes[key] = value
}

func (f Finding) Attr(key string) string {
	if key == confidence.Attribute {
		return f.Confidence
	}
	if f.Attributes != nil {
		return f.Attributes[key]
	}
	return ""
}

// SetAttributes stores a copy of attrs, promoting confidence into its typed
// Finding field.
func (f *Finding) SetAttributes(attrs map[string]string) {
	f.Attributes = maps.Clone(attrs)
	if value, ok := f.Attributes[confidence.Attribute]; ok {
		f.Confidence = value
		delete(f.Attributes, confidence.Attribute)
	}
}

// ToExprMap returns the fixed-shape map[string]string used as the `finding`
// variable in filter, validation, and analysis expressions.
func (f *Finding) ToExprMap() map[string]string {
	return map[string]string{
		"secret":      f.Secret,
		"match":       f.Match,
		"line":        f.Line,
		"rule_id":     f.RuleID,
		"description": f.Description,
		"confidence":  f.Confidence,
		"context":     f.exprContext,
	}
}
