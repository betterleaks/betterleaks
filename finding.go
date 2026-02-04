package betterleaks

import (
	"fmt"
	"math"
	"strings"

	"github.com/betterleaks/betterleaks/config"
	"github.com/charmbracelet/lipgloss"
)

type Finding struct {
	// Rule is the name of the rule that was matched
	RuleID      string
	Description string

	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	Line string `json:"-"`

	Match string

	// Captured secret
	Secret string

	// File is the name of the file containing the finding
	File        string
	SymlinkFile string
	Commit      string
	Link        string `json:",omitempty"`

	// Entropy is the shannon entropy of Value
	Entropy float64

	Author  string
	Email   string
	Date    string
	Message string
	Tags    []string

	// unique identifier
	Fingerprint string

	Fragment *Fragment `json:",omitempty"`

	// TODO keeping private for now to during experimental phase
	requiredFindings []*RequiredFinding
}

type RequiredFinding struct {
	// contains a subset of the Finding fields
	// only used for reporting
	RuleID      string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Line        string `json:"-"`
	Match       string
	Secret      string
}

func (f *Finding) AddRequiredFindings(afs []*RequiredFinding) {
	if f.requiredFindings == nil {
		f.requiredFindings = make([]*RequiredFinding, 0)
	}
	f.requiredFindings = append(f.requiredFindings, afs...)
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact(percent uint) {
	secret := maskSecret(f.Secret, percent)
	if percent >= 100 {
		secret = "REDACTED"
	}
	f.Line = strings.ReplaceAll(f.Line, f.Secret, secret)
	f.Match = strings.ReplaceAll(f.Match, f.Secret, secret)
	f.Secret = secret
}

func maskSecret(secret string, percent uint) string {
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

func (f *Finding) PrintRequiredFindings() {
	if len(f.requiredFindings) == 0 {
		return
	}

	fmt.Printf("%-12s ", "Required:")

	// Create orange style for secrets
	orangeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#bf9478"))

	for i, aux := range f.requiredFindings {
		auxSecret := strings.TrimSpace(aux.Secret)
		// Truncate long secrets for readability
		if len(auxSecret) > 40 {
			auxSecret = auxSecret[:37] + "..."
		}

		// Format: rule-id:line:secret
		if i == 0 {
			fmt.Printf("%s:%d:%s\n", aux.RuleID, aux.StartLine, orangeStyle.Render(auxSecret))
		} else {
			fmt.Printf("%-12s %s:%d:%s\n", "", aux.RuleID, aux.StartLine, orangeStyle.Render(auxSecret))
		}
	}
}

// CreateFinding creates a Finding from a fragment, match, and rule without
// computing location data. Call HydrateFindingLocation after filtering to add
// line/column information.
func CreateFinding(fragment Fragment, match Match, rule config.Rule) *Finding {
	secret := extractSecret(rule, match.MatchString)
	entropy := shannonEntropy(secret)

	return &Finding{
		RuleID:      match.RuleID,
		Match:       match.MatchString,
		Secret:      secret,
		Entropy:     entropy,
		File:        fragment.Path,
		SymlinkFile: fragment.Resource.Get(MetaSymlinkFile),
		Commit:      fragment.Resource.Get(MetaCommitSHA),
		Author:      fragment.Resource.Get(MetaAuthorName),
		Email:       fragment.Resource.Get(MetaAuthorEmail),
		Date:        fragment.Resource.Get(MetaCommitDate),
		Message:     fragment.Resource.Get(MetaCommitMessage),
		Line:        match.FullDecodedLine,
		Fragment:    &fragment,
		Tags:        match.MetaTags,
	}
}

// AddLocationToFinding populates location fields on a finding.
func AddLocationToFinding(finding *Finding, fragment Fragment, match Match, newLineIndices [][]int) {
	loc := location(newLineIndices, fragment.Raw, []int{match.MatchStart, match.MatchEnd})
	finding.StartLine = loc.startLine
	finding.EndLine = loc.endLine
	finding.StartColumn = loc.startColumn
	finding.EndColumn = loc.endColumn
}

func extractSecret(r config.Rule, matchedString string) string {
	if r.Regex == nil {
		return matchedString
	}
	groups := r.Regex.FindStringSubmatch(matchedString)
	if len(groups) >= 2 {
		if r.SecretGroup > 0 {
			if len(groups) <= r.SecretGroup {
				return ""
			}
			return groups[r.SecretGroup]
		} else {
			for _, s := range groups[1:] {
				if len(s) > 0 {
					return s
				}
			}
		}
	}
	return matchedString
}

// shannonEntropy calculates the entropy of data using the formula defined here:
// https://en.wiktionary.org/wiki/Shannon_entropy
func shannonEntropy(data string) float64 {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	var entropy float64
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// Location represents a location in a file
type Location struct {
	startLine      int
	endLine        int
	startColumn    int
	endColumn      int
	startLineIndex int
	endLineIndex   int
}

func location(newlineIndices [][]int, raw string, matchIndex []int) Location {
	var (
		prevNewLine int
		location    Location
		lineSet     bool
		_lineNum    int
	)

	start := matchIndex[0]
	end := matchIndex[1]

	location.startLineIndex = 0

	if len(newlineIndices) == 0 {
		newlineIndices = [][]int{
			{len(raw), len(raw) + 1},
		}
	}

	for lineNum, pair := range newlineIndices {
		_lineNum = lineNum
		newLineByteIndex := pair[0]
		if prevNewLine <= start && start < newLineByteIndex {
			lineSet = true
			location.startLine = lineNum
			location.endLine = lineNum
			location.startColumn = (start - prevNewLine) + 1
			location.startLineIndex = prevNewLine
			location.endLineIndex = newLineByteIndex
		}
		if prevNewLine < end && end <= newLineByteIndex {
			location.endLine = lineNum
			location.endColumn = (end - prevNewLine)
			location.endLineIndex = newLineByteIndex
		}

		prevNewLine = pair[0]
	}

	if !lineSet {
		location.startColumn = (start - prevNewLine) + 1
		location.endColumn = (end - prevNewLine)
		location.startLine = _lineNum + 1
		location.endLine = _lineNum + 1

		i := 0
		for end+i < len(raw) {
			if raw[end+i] == '\n' {
				break
			}
			if raw[end+i] == '\r' {
				break
			}
			i++
		}
		location.endLineIndex = end + i
	}
	return location
}
