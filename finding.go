package betterleaks

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type Finding struct {
	// Rule is the name of the rule that was matched
	RuleID      string
	Description string

	// Location Information
	// Line number _within_ the resource
	// Then resource info
	// validation info
	// required findings info
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	// Line is the full line content containing the finding.
	Line string `json:"-"`

	// DecodedLine is the fully decoded line content, used for allowlist matching.
	DecodedLine string `json:"-"`

	// Match is the part of the line that matched the rule
	Match string

	// Captured secret
	Secret string

	// Entropy is the shannon entropy of Value
	Entropy float64

	// Tags are arbitrary labels associated with the finding
	// Tags can be added by rules or during decoding
	Tags []string

	// unique identifier
	Fingerprint string

	// Used for bookkeeping back to the fragment
	Fragment *Fragment `json:"-"`

	// Metadata holds per-finding metadata copied from the resource at creation
	// time. Finding-specific augmentations (e.g. SCM link with line numbers) are
	// stored here so they don't bleed across findings that share a Resource.
	Metadata map[string]string `json:"-"`

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
	secret := MaskSecret(f.Secret, percent)
	if percent >= 100 {
		secret = "REDACTED"
	}
	f.Line = strings.ReplaceAll(f.Line, f.Secret, secret)
	f.Match = strings.ReplaceAll(f.Match, f.Secret, secret)
	f.Secret = secret
}

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

// ResourceContext returns the source type and metadata for allowlist matching.
func (f *Finding) ResourceContext() (string, map[string]string) {
	if f == nil || f.Fragment == nil || f.Fragment.Resource == nil {
		return "", nil
	}
	return f.Fragment.Resource.Source, f.Fragment.Resource.Metadata
}

// findingJSON is the JSON representation of a Finding, preserving backward
// compatibility by flattening resource metadata into top-level fields.
type findingJSON struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	Fingerprint string   `json:"Fingerprint"`
	Link        string   `json:"Link,omitempty"`
}

func (f Finding) MarshalJSON() ([]byte, error) {
	j := findingJSON{
		RuleID:      f.RuleID,
		Description: f.Description,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		StartColumn: f.StartColumn,
		EndColumn:   f.EndColumn,
		Match:       f.Match,
		Secret:      f.Secret,
		Entropy:     f.Entropy,
		Tags:        f.Tags,
		Fingerprint: f.Fingerprint,
		File:        f.Metadata[MetaPath],
		SymlinkFile: f.Metadata[MetaSymlinkFile],
		Commit:      f.Metadata[MetaCommitSHA],
		Link:        f.Metadata[MetaLink],
		Author:      f.Metadata[MetaAuthorName],
		Email:       f.Metadata[MetaAuthorEmail],
		Date:        f.Metadata[MetaCommitDate],
		Message:     f.Metadata[MetaCommitMessage],
	}
	return json.Marshal(j)
}

func (f *Finding) UnmarshalJSON(data []byte) error {
	var j findingJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}

	f.RuleID = j.RuleID
	f.Description = j.Description
	f.StartLine = j.StartLine
	f.EndLine = j.EndLine
	f.StartColumn = j.StartColumn
	f.EndColumn = j.EndColumn
	f.Match = j.Match
	f.Secret = j.Secret
	f.Entropy = j.Entropy
	f.Tags = j.Tags
	f.Fingerprint = j.Fingerprint

	// Reconstruct a synthetic Fragment + Resource from the JSON fields
	// so that resource.Get() works on deserialized findings (e.g. baselines).
	meta := map[string]string{
		MetaPath:          j.File,
		MetaSymlinkFile:   j.SymlinkFile,
		MetaCommitSHA:     j.Commit,
		MetaLink:          j.Link,
		MetaAuthorName:    j.Author,
		MetaAuthorEmail:   j.Email,
		MetaCommitDate:    j.Date,
		MetaCommitMessage: j.Message,
	}
	f.Metadata = meta
	f.Fragment = &Fragment{
		Path: j.File,
		Resource: &Resource{
			Path:     j.File,
			Metadata: meta,
		},
	}
	return nil
}
