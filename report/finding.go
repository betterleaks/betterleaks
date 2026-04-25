package report

import (
	"fmt"
	"maps"
	"math"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/color"
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

	ValidationStatus ValidationStatus `json:",omitempty"`
	ValidationReason string           `json:",omitempty"`
	// TODO maybe just use the Attribute map
	ValidationMeta map[string]any `json:",omitempty"`

	// unique identifier
	Fingerprint string

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
	ValidationStatus ValidationStatus   `json:"validationStatus,omitempty"`
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

func (f *Finding) PrintRequiredFindings(noColor bool, redact uint) {
	if len(f.RequiredSets) == 0 {
		return
	}

	fmt.Println("Required:")

	orangeStyle := color.New()
	if !noColor {
		orangeStyle = orangeStyle.Foreground("#bf9478")
	}

	for _, set := range f.RequiredSets {
		statusSuffix := ""
		if set.ValidationStatus != "" {
			statusSuffix = " " + formatSetStatus(set.ValidationStatus, noColor)
		}

		if len(set.Components) == 1 {
			// Single-component set: inline on the bullet line.
			comp := set.Components[0]
			secret := redactForDisplay(comp.Secret, redact)
			fmt.Printf("  - %s:%d: %s%s\n", comp.RuleID, comp.StartLine, orangeStyle.Render(secret), statusSuffix)
			continue
		}

		// Multi-component set: status on the bullet, components indented below.
		if statusSuffix != "" {
			fmt.Printf("  - %s\n", formatSetStatus(set.ValidationStatus, noColor))
		} else {
			fmt.Println("  -")
		}

		maxLabelLen := 0
		for _, comp := range set.Components {
			label := fmt.Sprintf("%s:%d:", comp.RuleID, comp.StartLine)
			if len(label) > maxLabelLen {
				maxLabelLen = len(label)
			}
		}

		for _, comp := range set.Components {
			secret := redactForDisplay(comp.Secret, redact)
			label := fmt.Sprintf("%s:%d:", comp.RuleID, comp.StartLine)
			fmt.Printf("    %-*s %s\n", maxLabelLen, label, orangeStyle.Render(secret))
		}
	}
}

// redactForDisplay returns a display-safe version of a secret, applying
// truncation and optional redaction without mutating the original.
func redactForDisplay(secret string, redact uint) string {
	if redact > 0 {
		if redact >= 100 {
			return "REDACTED"
		}
		secret = MaskSecret(secret, redact)
	}
	return truncateSecret(secret)
}

func truncateSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 40 {
		return s[:37] + "..."
	}
	return s
}

// formatSetStatus returns a styled status string for a required set header.
func formatSetStatus(status ValidationStatus, noColor bool) string {
	if noColor {
		return "[" + strings.ToUpper(status.String()) + "]"
	}
	var style color.Style
	switch status {
	case ValidationStatusValid:
		style = color.New().Foreground("#00d26a")
	case ValidationStatusInvalid:
		style = color.New().Foreground("#888888")
	case ValidationStatusRevoked:
		style = color.New().Foreground("#f5d445")
	case ValidationStatusError:
		style = color.New().Foreground("#f05c07")
	default:
		style = color.New().Foreground("#c0c0c0")
	}
	return style.Render("[" + strings.ToUpper(status.String()) + "]")
}

func (f Finding) Print(noColor bool, redact uint) {
	if redact > 0 {
		// Redact top-level fields only (f is a value copy, so this is safe).
		// RequiredSets share pointers with the original finding stored in
		// d.findings, so we must not mutate them here — they are redacted
		// separately for display by PrintRequiredFindings.
		secret := MaskSecret(f.Secret, redact)
		if redact >= 100 {
			secret = "REDACTED"
		}
		f.Line = strings.ReplaceAll(f.Line, f.Secret, secret)
		f.Match = strings.ReplaceAll(f.Match, f.Secret, secret)
		f.MatchContext = strings.ReplaceAll(f.MatchContext, f.Secret, secret)
		f.Secret = secret
	}
	// trim all whitespace and tabs
	f.Line = strings.TrimSpace(f.Line)
	f.Secret = strings.TrimSpace(f.Secret)
	f.Match = strings.TrimSpace(f.Match)

	isFileMatch := strings.HasPrefix(f.Match, "file detected:")
	skipColor := noColor
	finding := ""
	secretDisplay := ""
	matchStyle := color.New().Foreground("#f5d445")
	secretStyle := color.New().Bold().Italic().Foreground("#f05c07")

	// Matches from filenames do not have a |line| or |secret|
	if !isFileMatch {
		matchInLineIDX := locateMatch(f.Line, f.Match, f.StartColumn)
		secretInMatchIdx := strings.Index(f.Match, f.Secret)

		skipColor = false

		if matchInLineIDX == -1 || noColor {
			skipColor = true
			matchInLineIDX = 0
		}

		start := f.Line[0:matchInLineIDX]
		startMatchIdx := 0
		if matchInLineIDX > 20 {
			startMatchIdx = matchInLineIDX - 20
			start = "..." + f.Line[startMatchIdx:matchInLineIDX]
		}

		if secretInMatchIdx == -1 {
			secretInMatchIdx = 0
		}

		matchBeginning := matchStyle.Render(f.Match[0:secretInMatchIdx])
		secretDisplay = f.Secret
		if len(f.Secret) > 100 {
			secretDisplay = f.Secret[0:100] + "..."
		}
		styledSecret := secretStyle.Render(secretDisplay)
		matchEnd := matchStyle.Render(f.Match[secretInMatchIdx+len(f.Secret):])

		lineEndIdx := matchInLineIDX + len(f.Match)
		if lineEndIdx > len(f.Line) {
			lineEndIdx = len(f.Line)
		}

		lineEnd := f.Line[lineEndIdx:]

		if len(lineEnd) > 20 {
			lineEnd = lineEnd[0:20] + "..."
		}

		finding = fmt.Sprintf("%s%s%s%s%s\n", strings.TrimPrefix(strings.TrimLeft(start, " "), "\n"), matchBeginning, styledSecret, matchEnd, lineEnd)
		secretDisplay = styledSecret
	}

	if skipColor || isFileMatch {
		fmt.Printf("%-12s %s\n", "Finding:", f.Match)
		fmt.Printf("%-12s %s\n", "Secret:", f.Secret)
	} else {
		fmt.Printf("%-12s %s", "Finding:", finding)
		fmt.Printf("%-12s %s\n", "Secret:", secretDisplay)
	}

	fmt.Printf("%-12s %s\n", "RuleID:", f.RuleID)
	fmt.Printf("%-12s %f\n", "Entropy:", f.Entropy)

	path := f.Attr(sources.AttrPath)
	commit := f.Attr(sources.AttrGitSHA)
	author := f.Attr(sources.AttrGitAuthorName)
	email := f.Attr(sources.AttrGitAuthorEmail)
	date := f.Attr(sources.AttrGitDate)

	if path == "" {
		if f.MatchContext != "" {
			fmt.Printf("%-12s\n%s\n", "Context:", formatMatchContext(f.MatchContext, f.Match, f.Secret, noColor))
		}
		printValidation(f, noColor)
		f.PrintRequiredFindings(noColor, redact)
		fmt.Println("")
		return
	}
	if len(f.Tags) > 0 {
		fmt.Printf("%-12s %s\n", "Tags:", strings.Join(f.Tags, ", "))
	}
	fmt.Printf("%-12s %s\n", "File:", path)
	fmt.Printf("%-12s %d\n", "Line:", f.StartLine)
	if commit == "" {
		fmt.Printf("%-12s %s\n", "Fingerprint:", f.Fingerprint)
		if f.MatchContext != "" {
			fmt.Printf("%-12s\n%s\n", "Context:", formatMatchContext(f.MatchContext, f.Match, f.Secret, noColor))
		}
		printValidation(f, noColor)
		f.PrintRequiredFindings(noColor, redact)
		fmt.Println("")
		return
	}
	fmt.Printf("%-12s %s\n", "Commit:", commit)
	fmt.Printf("%-12s %s\n", "Author:", author)
	fmt.Printf("%-12s %s\n", "Email:", email)
	fmt.Printf("%-12s %s\n", "Date:", date)
	fmt.Printf("%-12s %s\n", "Fingerprint:", f.Fingerprint)
	if f.Link != "" {
		fmt.Printf("%-12s %s\n", "Link:", f.Link)
	}

	if f.MatchContext != "" {
		fmt.Printf("%-12s\n%s\n", "Context:", formatMatchContext(f.MatchContext, f.Match, f.Secret, noColor))
	}
	printValidation(f, noColor)
	f.PrintRequiredFindings(noColor, redact)
	fmt.Println("")
}

// printValidation prints the validation status block when validation has run.
func printValidation(f Finding, noColor bool) {
	if f.ValidationStatus == "" {
		return
	}

	statusStyle := validationStyle(f.ValidationStatus, noColor)

	fmt.Printf("%-12s %s", "Validation:", statusStyle.Render(strings.ToUpper(f.ValidationStatus.String())))
	if f.ValidationReason != "" {
		fmt.Printf("  (%s)", f.ValidationReason)
	}
	fmt.Println()

	metaStyle := color.New()
	if !noColor {
		metaStyle = metaStyle.Foreground("#9ca3af")
	}

	for _, k := range sortedMapKeys(f.ValidationMeta) {
		fmt.Printf("  %s\n", metaStyle.Render(fmt.Sprintf("%-10s %v", k+" =", f.ValidationMeta[k])))
	}
}

func validationStyle(status ValidationStatus, noColor bool) color.Style {
	if noColor {
		return color.New()
	}
	switch status {
	case ValidationStatusValid:
		return color.New().Bold().Foreground("#00d26a")
	case ValidationStatusInvalid:
		return color.New().Foreground("#888888")
	case ValidationStatusRevoked:
		return color.New().Foreground("#f5d445")
	case ValidationStatusUnknown:
		return color.New().Foreground("#c0c0c0")
	case ValidationStatusError:
		return color.New().Foreground("#f05c07")
	default:
		return color.New()
	}
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

func formatMatchContext(context string, match string, secret string, noColor bool) string {
	indent := "    " // 4 spaces
	matchStyle := color.New().Foreground("#f5d445")
	secretStyle := color.New().Bold().Italic().Foreground("#f05c07")

	lines := strings.Split(context, "\n")
	for i, line := range lines {
		if !noColor {
			if secretIdx := strings.Index(line, secret); secret != "" && secretIdx != -1 {
				// Try to highlight the full match with the secret emphasized inside it
				if matchIdx := strings.Index(line, match); match != "" && matchIdx != -1 {
					before, after, _ := strings.Cut(match, secret)
					highlighted := matchStyle.Render(before) +
						secretStyle.Render(secret) +
						matchStyle.Render(after)
					line = line[:matchIdx] + highlighted + line[matchIdx+len(match):]
				} else {
					// Fall back to highlighting just the secret
					line = line[:secretIdx] + secretStyle.Render(secret) + line[secretIdx+len(secret):]
				}
			}
		}
		lines[i] = indent + line
	}
	return strings.Join(lines, "\n")
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
