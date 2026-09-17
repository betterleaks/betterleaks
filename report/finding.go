package report

import (
	"encoding/json"
	"maps"
	"math"
	"slices"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/confidence"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// Finding describes what a rule matched, where it was found, and optional provider
// enrichment. Scanner owns discovery fields; Analyzer owns Analysis.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	Confidence  string `json:"confidence"`

	Match Match `json:"match"`

	// Attributes holds extensible source metadata. Well-known keys are defined
	// by the sources package. Path is stored in Location; SetAttributes promotes
	// it when importing source metadata.
	Attributes map[string]string `json:"attributes,omitempty"`

	Location Location `json:"location"`
	Analysis Analysis `json:"analysis,omitzero"`

	// ComponentSets holds the Cartesian-product combinations of component findings.
	// Each set is one complete group of components that can be validated independently.
	ComponentSets []ComponentSet `json:"component_sets,omitempty"`

	// ComponentSetsTruncated means discovery omitted combinations at its hard limit.
	// A successful tested set establishes validity; failed tests cannot exhaust the search.
	ComponentSetsTruncated bool `json:"component_sets_truncated,omitempty"`

	Tags []string `json:"tags"`
}

// MarshalJSON omits internal attributes and limits Git message metadata to its
// first line. Full attributes remain available on the in-memory finding for
// local filters.
func (f Finding) MarshalJSON() ([]byte, error) {
	type wireFinding Finding

	wire := wireFinding(f)
	wire.Attributes = reportAttributes(f.Attributes)
	return json.Marshal(struct {
		SchemaVersion int `json:"schema_version"`
		wireFinding
	}{SchemaVersion: SchemaVersion, wireFinding: wire})
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

// Match groups matched text, the extracted value, and retained source text.
// A component or path rule need not identify a secret.
type Match struct {
	Full     string            `json:"full"`
	Value    string            `json:"value"`
	Captures map[string]string `json:"captures,omitempty"`

	// Line contains the original source line(s) covering the match, retained for
	// pretty-output snippets and local filtering. It is not serialized or exposed
	// to provider expressions.
	Line string `json:"-"`

	// Context is the explicitly requested source window around the match, also
	// exposed as finding.context to local filters. It stays empty when no context
	// was requested; Line is never used as a default. Provider expressions cannot
	// read it.
	Context string `json:"context,omitempty"`
}

// Location identifies a finding's position in its source. Path has source-defined
// semantics and is optional. Text coordinates use one-based lines and byte columns.
type Location struct {
	Path        string `json:"path,omitempty"`
	StartLine   int    `json:"start_line,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	StartColumn int    `json:"start_column,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
}

// ComponentSet represents one combination of component findings (one element per
// matched component rule) from the Cartesian product. Each set can be validated
// independently and carries its own Analysis result.
type ComponentSet struct {
	Components []ComponentFinding `json:"components"`
	Analysis   Analysis           `json:"analysis,omitzero"`
}

// ComponentFinding is the discovery information for one component match.
type ComponentFinding struct {
	RuleID   string   `json:"rule_id"`
	Optional bool     `json:"optional,omitempty"`
	Match    Match    `json:"match"`
	Location Location `json:"location"`
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact(percent uint) {
	secrets := f.CredentialValues()

	// Replace all primary and component values in each match and its surrounding
	// text. Longest values win when credentials overlap; replacements are applied
	// once so masking one value cannot expose or corrupt another.
	secrets = credentialSecretsForRedaction(secrets)
	pairs := make([]string, 0, len(secrets)*2)
	for _, secret := range secrets {
		masked := "REDACTED"
		if percent < 100 {
			masked = MaskSecret(secret, percent)
			for _, other := range secrets {
				if len(other) < len(secret) {
					visible := strings.TrimSuffix(masked, "...")
					if index := strings.Index(visible, other); index >= 0 {
						keep := len(strings.TrimSuffix(MaskSecret(other, percent), "..."))
						masked = visible[:index+keep] + "..."
					}
				}
			}
		}
		pairs = append(pairs, secret, masked)
	}
	replacer := strings.NewReplacer(pairs...)
	redactMatch := func(match *Match) {
		match.Full = replacer.Replace(match.Full)
		match.Value = replacer.Replace(match.Value)
		match.Captures = redactStrings(match.Captures, replacer.Replace)
		match.Line = replacer.Replace(match.Line)
		match.Context = replacer.Replace(match.Context)
	}
	f.RuleID = replacer.Replace(f.RuleID)
	f.Description = replacer.Replace(f.Description)
	f.Confidence = replacer.Replace(f.Confidence)
	f.Location.Path = replacer.Replace(f.Location.Path)
	f.Attributes = redactStrings(f.Attributes, replacer.Replace)
	for i := range f.Tags {
		f.Tags[i] = replacer.Replace(f.Tags[i])
	}
	redactMatch(&f.Match)
	for _, set := range f.ComponentSets {
		for i := range set.Components {
			component := &set.Components[i]
			component.RuleID = replacer.Replace(component.RuleID)
			component.Location.Path = replacer.Replace(component.Location.Path)
			redactMatch(&component.Match)
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
	f = f.Clone()
	f.Redact(percent)
	return f
}

// Clone snapshots a finding's mutable maps, slices and component findings.
func (f Finding) Clone() Finding {
	f.Attributes = maps.Clone(f.Attributes)
	f.Tags = slices.Clone(f.Tags)
	f.Analysis = cloneAnalysis(f.Analysis)
	f.Match.Captures = maps.Clone(f.Match.Captures)

	f.ComponentSets = slices.Clone(f.ComponentSets)
	for i := range f.ComponentSets {
		set := &f.ComponentSets[i]
		set.Analysis = cloneAnalysis(set.Analysis)
		set.Components = slices.Clone(set.Components)
		for j := range set.Components {
			set.Components[j].Match.Captures = maps.Clone(set.Components[j].Match.Captures)
		}
	}
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

// CredentialValues returns primary and component values and captures that must
// be sanitized before exporting provider results. Empty values are harmless.
func (f Finding) CredentialValues() []string {
	values := matchValues(nil, f.Match)
	for _, set := range f.ComponentSets {
		for _, c := range set.Components {
			values = matchValues(values, c.Match)
		}
	}
	return values
}

func matchValues(values []string, match Match) []string {
	values = append(values, match.Value)
	for _, value := range match.Captures {
		values = append(values, value)
	}
	return values
}

func redactStrings(input map[string]string, replace func(string) string) map[string]string {
	if input == nil {
		return nil
	}
	out := make(map[string]string, len(input))
	for k, v := range input {
		out[replace(k)] = replace(v)
	}
	return out
}
