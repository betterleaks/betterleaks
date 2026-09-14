package report

import (
	"encoding/json"
	"maps"
	"math"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/confidence"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// Finding describes what a rule matched, where it was found, and optional provider
// enrichment. Scanner owns discovery fields; Analyzer owns Analysis.
type Finding struct {
	RuleID      string `json:"ruleID"`
	Description string `json:"description"`
	Confidence  string `json:"confidence"`

	Match Match `json:"match"`

	// MatchContext is optional source context, also exposed as finding.context
	// to expressions. It is populated only when explicitly requested or supplied.
	MatchContext string `json:"matchContext,omitempty"`

	// Attributes holds extensible source metadata. Well-known keys are defined
	// by the sources package. Path is stored in Location; SetAttributes promotes
	// it when importing source metadata.
	Attributes map[string]string `json:"attributes,omitempty"`

	Location Location `json:"location"`
	Analysis Analysis `json:"analysis,omitzero"`

	// ComponentSets holds the Cartesian-product combinations of component findings.
	// Each set is one complete group of components that can be validated independently.
	ComponentSets []ComponentSet `json:"componentSets,omitempty"`

	Tags []string `json:"tags"`

	Line            string `json:"-"`
	RuleSpecificity int    `json:"-"`
}

// MarshalJSON omits internal attributes and limits Git message metadata to its
// first line. Full attributes remain available on the in-memory finding for
// filters, validation, and analysis expressions.
func (f Finding) MarshalJSON() ([]byte, error) {
	type wireFinding Finding

	wire := wireFinding(f)
	wire.Attributes = reportAttributes(f.Attributes)
	return json.Marshal(wire)
}

func reportAttributes(attributes map[string]string) map[string]string {
	_, internal := attributes[sources.AttrFSFirstFragment]
	_, path := attributes[sources.AttrPath]
	message := attributes[sources.AttrGitMessage]
	lineEnd := strings.IndexAny(message, "\r\n")
	if !internal && !path && lineEnd < 0 {
		return attributes
	}

	visible := maps.Clone(attributes)
	delete(visible, sources.AttrFSFirstFragment)
	delete(visible, sources.AttrPath)
	if lineEnd >= 0 {
		visible[sources.AttrGitMessage] = message[:lineEnd]
		if strings.TrimSpace(message[lineEnd:]) != "" {
			visible[sources.AttrGitMessage] += "..."
		}
	}
	if len(visible) == 0 {
		return nil
	}
	return visible
}

// Match groups matched text and the extracted value independently of its source.
// A component or path rule need not identify a secret.
type Match struct {
	Full     string            `json:"full"`
	Value    string            `json:"value"`
	Captures map[string]string `json:"captures,omitempty"`
}

// Location identifies a finding's position in its source. Path has source-defined
// semantics and is optional. Text coordinates use one-based lines and byte columns.
type Location struct {
	Path        string `json:"path,omitempty"`
	StartLine   int    `json:"startLine,omitempty"`
	EndLine     int    `json:"endLine,omitempty"`
	StartColumn int    `json:"startColumn,omitempty"`
	EndColumn   int    `json:"endColumn,omitempty"`
}

// ComponentSet represents one combination of component findings (one element per
// matched component rule) from the Cartesian product. Each set can be validated
// independently and carries its own Analysis result.
type ComponentSet struct {
	Components []*ComponentFinding `json:"components"`
	Analysis   Analysis            `json:"analysis,omitzero"`
}

// ComponentFinding is the discovery information for one companion match.
type ComponentFinding struct {
	RuleID          string   `json:"ruleID"`
	Optional        bool     `json:"optional,omitempty"`
	Match           Match    `json:"match"`
	Location        Location `json:"location"`
	Line            string   `json:"-"`
	RuleSpecificity int      `json:"-"`
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
	secrets := []string{f.Match.Value}
	for _, set := range f.ComponentSets {
		for _, component := range set.Components {
			if component != nil {
				secrets = append(secrets, component.Match.Value)
			}
		}
	}

	// Replace all primary and component values in each match and its surrounding
	// text. Longest values win when credentials overlap; replacements are applied
	// once so masking one value cannot expose or corrupt another.
	secrets = credentialSecretsForRedaction(secrets)
	pairs := make([]string, 0, len(secrets)*2)
	for _, secret := range secrets {
		masked := "REDACTED"
		if percent < 100 {
			masked = MaskSecret(secret, percent)
		}
		pairs = append(pairs, secret, masked)
	}
	replacer := strings.NewReplacer(pairs...)
	redactMatch := func(match *Match) {
		match.Full = replacer.Replace(match.Full)
		match.Value = replacer.Replace(match.Value)
		for key, value := range match.Captures {
			match.Captures[key] = replacer.Replace(value)
		}
	}
	redactMatch(&f.Match)
	f.Line = replacer.Replace(f.Line)
	f.MatchContext = replacer.Replace(f.MatchContext)
	seen := make(map[*ComponentFinding]struct{})
	for _, set := range f.ComponentSets {
		for _, component := range set.Components {
			if component == nil {
				continue
			}
			if _, ok := seen[component]; ok {
				continue
			}
			seen[component] = struct{}{}
			redactMatch(&component.Match)
			component.Line = replacer.Replace(component.Line)
		}
	}

	f.Analysis = SanitizeAnalysis(f.Analysis, secrets)
	for i := range f.ComponentSets {
		f.ComponentSets[i].Analysis = SanitizeAnalysis(f.ComponentSets[i].Analysis, secrets)
	}
}

// RedactedCopy returns a redacted finding without modifying maps, component
// findings, or component sets shared with the original finding.
func (f Finding) RedactedCopy(percent uint) Finding {
	f.Match.Captures = maps.Clone(f.Match.Captures)

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
					copyValue.Match.Captures = maps.Clone(component.Match.Captures)
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

func (f *Finding) SetAttr(key, value string) {
	if key == sources.AttrPath {
		f.Location.Path = value
		delete(f.Attributes, key)
		return
	}
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
	if key == sources.AttrPath {
		return f.Location.Path
	}
	if key == confidence.Attribute {
		return f.Confidence
	}
	if f.Attributes != nil {
		return f.Attributes[key]
	}
	return ""
}

// SetAttributes stores a copy of attrs, promoting path and confidence into typed fields.
func (f *Finding) SetAttributes(attrs map[string]string) {
	f.Attributes = maps.Clone(attrs)
	f.Location.Path = attrs[sources.AttrPath]
	delete(f.Attributes, sources.AttrPath)
	if value, ok := f.Attributes[confidence.Attribute]; ok {
		f.Confidence = value
		delete(f.Attributes, confidence.Attribute)
	}
}

// ExprAttributes returns the source attributes used by rule expressions, including
// the promoted path. The map is independent of the finding so local helpers may
// write to it. Report consumers should use Location.Path.
func (f Finding) ExprAttributes() map[string]string {
	attrs := make(map[string]string, len(f.Attributes)+1)
	maps.Copy(attrs, f.Attributes)
	delete(attrs, sources.AttrPath)
	if f.Location.Path != "" {
		attrs[sources.AttrPath] = f.Location.Path
	}
	return attrs
}

// ToExprMap returns the fixed-shape map[string]string used as the `finding`
// variable in filter, validation, and analysis expressions.
func (f *Finding) ToExprMap() map[string]string {
	return map[string]string{
		"secret":      f.Match.Value,
		"match":       f.Match.Full,
		"line":        f.Line,
		"rule_id":     f.RuleID,
		"description": f.Description,
		"confidence":  f.Confidence,
		"context":     f.MatchContext,
	}
}
