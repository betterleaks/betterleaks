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

	RuleSpecificity int `json:"-"`

	// ComponentSets holds the Cartesian-product combinations of component findings.
	// Each set is one complete group of components that can be validated independently.
	ComponentSets []ComponentSet `json:",omitempty"`

	ValidationStatus ValidationStatus `json:",omitempty"`
	ValidationReason string           `json:",omitempty"`
	// TODO maybe just use the Attribute map
	ValidationMeta map[string]any `json:",omitempty"`

	// unique identifier
	Fingerprint string

	// Hidden field to hold expression context without bloating the report output.
	exprContext string

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

// ComponentSet represents one combination of component findings (one element per
// matched component rule) from the Cartesian product. Each set can be validated
// independently and carries its own validation result.
type ComponentSet struct {
	Components       []*ComponentFinding `json:"components"`
	ValidationStatus ValidationStatus    `json:"validationStatus,omitempty"`
	ValidationReason string              `json:"validationReason,omitempty"`
}

type ComponentFinding struct {
	// contains a subset of the Finding fields
	// only used for reporting
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

// redactedUnlocatable replaces Line when Secret can't be found in it as a
// literal substring. This happens for decode-depth/component findings, where
// Secret is deliberately captured from decoded text while Line is kept as
// the original, still-encoded file content (so users see their actual file,
// not an internal decoded intermediate — see detect.go's decode pass). Line
// is the field print_pretty.go's secretByteBounds/renderLinesOnly treat as
// "the raw text to display", so if a literal replace can't verify redaction
// succeeded there, we must not fall back to showing it un-redacted.
const redactedUnlocatable = "[secret redacted: exact location could not be verified]"

// secretOffsetInLine returns the 0-indexed byte offset within line where
// secret is expected to start, or -1 if that can't be determined at all.
// startColumn is the finding's 1-indexed byte offset (from the start of
// line) where match — not necessarily secret itself — is known to start
// (see detect/location.go: Finding.StartColumn/ComponentFinding.StartColumn
// are always relative to the start of Line, including for multi-line
// findings). secret is frequently a narrower capture group *within* match
// (many rules capture just the credential value, e.g. after a "key: "
// prefix — see detect.go, where Finding.Secret is reassigned to a regex
// submatch of the original full-match text that Finding.Match still holds),
// so secret's own offset is startColumn's offset plus secret's offset
// within match, not startColumn alone.
//
// The detector also trims leading newlines off Match/Secret without
// adjusting StartColumn (see detect.go's strings.Trim(rawMatch, "\n") when
// building the pre-capture-group secret), so for a rule whose regex itself
// matches a leading newline (e.g. "\n(secret)"), startColumn can still point
// at that newline byte in line rather than at match's actual first byte
// post-trim — matchStart below walks past any such bytes to compensate.
//
// strings.Trim's cutset there is "\n" only, though: it stops at the very
// first leading byte that isn't in the cutset, so a leading "\r\n" (e.g. a
// CRLF rule like "\r\n(secret)") is left completely untrimmed — match still
// starts with those bytes verbatim. matchStart's walk-forward can't tell
// the difference and always advances past leading \r/\n bytes in line, so
// matchPrefixLen measures how many such bytes match itself still retains
// and subtracts them back out, undoing the walk-forward exactly when it
// wasn't warranted.
// secretAmbiguous is a sentinel secretOffsetInLine returns when secret
// occurs more than once within match: strings.Index can only find the
// *first* occurrence, which isn't necessarily the one the rule's capture
// group actually matched. For example, the built-in generic-credential-uri
// rule can decode a URI like "https://plaintext-secret:<base64(plaintext-
// secret)>@host" into a match whose username textually precedes the
// captured, decoded password — both now reading "plaintext-secret". Trusting
// the first (username) occurrence would verify successfully (the username
// really is that literal text in Line too) and redact it, while the real
// credential — still base64-encoded a few bytes later in the same Line —
// is a completely different string and goes untouched. Unlike -1 (no
// position hint at all, which still falls back to a plain Contains search),
// callers must never fall back to that lenient search for this sentinel
// either: Contains would just as readily match the same wrong occurrence.
const secretAmbiguous = -2

func secretOffsetInLine(line, match, secret string, startColumn int) int {
	if startColumn <= 0 || secret == "" {
		return -1
	}
	relOffset := strings.Index(match, secret)
	if relOffset < 0 {
		return -1
	}
	if strings.Index(match[relOffset+len(secret):], secret) >= 0 {
		return secretAmbiguous
	}
	matchStart := startColumn - 1
	for matchStart < len(line) && (line[matchStart] == '\n' || line[matchStart] == '\r') {
		matchStart++
	}
	matchPrefixLen := len(match) - len(strings.TrimLeft(match, "\r\n"))
	return matchStart + relOffset - matchPrefixLen
}

// redactLine redacts secret out of line, verified via secretOffsetInLine.
//
// Once that position verifies (line really does hold secret, in this exact
// representation, at its known real location), the whole line is passed
// through strings.ReplaceAll rather than touching only that single span:
// having proven this exact representation of secret is genuinely present at
// a known-correct location, any further identical occurrence elsewhere in
// line is provably a duplicate of the same credential, not an unrelated
// coincidence, and must be redacted too rather than left exposed.
//
// It deliberately does NOT fall back to a blind Contains/ReplaceAll search
// when a position hint was available but didn't verify: secret (the decoded
// value, for a decode-depth finding) can coincidentally — or, in a crafted
// file, deliberately — appear elsewhere in line as an unrelated plaintext
// copy while the finding's actual, still-encoded span goes untouched;
// trusting that coincidental occurrence would leave the real one exposed.
// If no reliable position can be established at all (e.g. a Finding built
// outside the normal detection path, where startColumn is unavailable), it
// falls back to the same Contains-based search as before this hardening —
// strictly better than showing raw text, if not as precise.
func redactLine(line, match, secret, replacement string, startColumn int) string {
	if line == "" || secret == "" {
		return line
	}
	b := secretOffsetInLine(line, match, secret, startColumn)
	if b == secretAmbiguous {
		return redactedUnlocatable
	}
	if b >= 0 {
		if b+len(secret) <= len(line) && line[b:b+len(secret)] == secret {
			return strings.ReplaceAll(line, secret, replacement)
		}
		return redactedUnlocatable
	}
	if !strings.Contains(line, secret) {
		return redactedUnlocatable
	}
	return strings.ReplaceAll(line, secret, replacement)
}

// redactContext is redactLine's counterpart for MatchContext. MatchContext
// isn't itself addressable by a single column — it's a separate window of
// text around Line (see detect.go, contextwindow.Extract) — so instead it's
// verified by anchoring on line (Line's own, not-yet-redacted value): if
// matchContext contains line intact, secret's absolute position within
// matchContext is that occurrence's offset plus secret's already-verified
// offset within line. Once verified, the whole matchContext is passed
// through strings.ReplaceAll (not just that one span) for the same reason
// redactLine does: any other identical occurrence — including, notably, a
// duplicate copy of line elsewhere in the context window — is a real
// duplicate of the same credential once we've proven this representation is
// genuine, not something to leave untouched because a different copy of
// line happened to anchor the check.
//
// A column-based --match-context window can be clipped shorter than a full
// line, so matchContext may not contain line intact even for an entirely
// ordinary finding. When secretOffsetInLine did establish a position (b >= 0)
// but the anchor can't be found or verified there, this fails closed
// (blanks matchContext) rather than falling through to the same lenient
// Contains-based search redactLine also refuses in that situation — for the
// same reason: an unrelated coincidental occurrence of secret elsewhere in
// the clipped window must not be mistaken for the real, still-encoded span.
// The lenient fallback below is reserved for when no position could be
// established at all.
//
// Box-mode MatchContext (see detect.go, contextwindow.extractBox) ends at a
// line's trailing newline rather than past it, while Line (for any but the
// file's last line) includes that trailing newline — so for a non-final
// line the anchor lookup would otherwise always fail even for an entirely
// ordinary finding. b's own value doesn't depend on line's end, only its
// start, so it's safe to retry the lookup with line's own trailing \r\n
// stripped when the untrimmed lookup fails.
func redactContext(matchContext, line, match, secret, replacement string, startColumn int) string {
	if matchContext == "" {
		return matchContext
	}
	b := secretOffsetInLine(line, match, secret, startColumn)
	if b == secretAmbiguous {
		return redactedUnlocatable
	}
	if b >= 0 {
		if line == "" {
			return redactedUnlocatable
		}
		lineIdx := strings.Index(matchContext, line)
		if lineIdx < 0 {
			if trimmed := strings.TrimRight(line, "\r\n"); trimmed != line {
				lineIdx = strings.Index(matchContext, trimmed)
			}
		}
		if lineIdx < 0 {
			return redactedUnlocatable
		}
		abs := lineIdx + b
		if abs+len(secret) <= len(matchContext) && matchContext[abs:abs+len(secret)] == secret {
			return strings.ReplaceAll(matchContext, secret, replacement)
		}
		return redactedUnlocatable
	}
	if secret == "" {
		return matchContext
	}
	if !strings.Contains(matchContext, secret) {
		return redactedUnlocatable
	}
	return strings.ReplaceAll(matchContext, secret, replacement)
}

// redactLineAndMatch redacts line/match/matchContext using secret →
// replacement and returns the results. line and matchContext use the
// position-verified redactLine/redactContext — both are sliced from the
// original fragment text at the match's (possibly decode-depth-adjusted)
// location, so both share the same Secret/representation mismatch risk (see
// detect.go, where finding.MatchContext is extracted from fragment.Raw
// exactly like Line). match keeps the simple leave-as-is-when-absent
// behavior, since Match is always derived from the same representation as
// Secret.
//
// Deliberately excludes CaptureGroups and ComponentSets: both are reference
// types (a map, and a slice of pointers) that can be shared with another copy
// of the same Finding that still needs to see the un-redacted original —
// e.g. the verbose/legacy console printers hold a value-copy of a Finding
// whose ComponentSets/CaptureGroups point at the exact same underlying data
// the report-writing path (or, for ComponentSets, PrintComponentFindings'
// own independent masking) will redact separately. A caller that redacted
// those fields here would mutate that shared data out from under whichever
// consumer redacts it next, causing double-redaction. Only Finding.Redact()
// — the single, authoritative, one-time redaction pass before a finding is
// persisted or printed — touches CaptureGroups/ComponentSets.
func redactLineAndMatch(line, match, matchContext, secret, replacement string, startColumn int) (newLine, newMatch, newMatchContext string) {
	newMatchContext = redactContext(matchContext, line, match, secret, replacement, startColumn)
	newLine = redactLine(line, match, secret, replacement, startColumn)
	newMatch = strings.ReplaceAll(match, secret, replacement)
	return
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact(percent uint) {
	secret := MaskSecret(f.Secret, percent)
	if percent >= 100 {
		secret = "REDACTED"
	}
	f.Line, f.Match, f.MatchContext = redactLineAndMatch(f.Line, f.Match, f.MatchContext, f.Secret, secret, f.StartColumn)
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
			comp.Line = redactLine(comp.Line, comp.Match, comp.Secret, compSecret, comp.StartColumn)
			comp.Match = strings.ReplaceAll(comp.Match, comp.Secret, compSecret)
			for k, v := range comp.CaptureGroups {
				comp.CaptureGroups[k] = strings.ReplaceAll(v, comp.Secret, compSecret)
			}
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
