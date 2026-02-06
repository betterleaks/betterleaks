package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
)

// --------------------------------------------------------------------------
// Legacy (gitleaks-compatible) SARIF reporter.
//
// LegacySarifReporter outputs SARIF 2.1.0 with the gitleaks driver name and
// branding. Activated by --legacy.
// --------------------------------------------------------------------------

// LegacySarifReporter writes findings in the gitleaks-compatible SARIF format.
type LegacySarifReporter struct {
	OrderedRules []config.Rule
}

var _ betterleaks.Reporter = (*LegacySarifReporter)(nil)

func (r *LegacySarifReporter) Write(w io.WriteCloser, findings []betterleaks.Finding) error {
	sarif := Sarif{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    r.getRuns(findings),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(sarif)
}

func (r *LegacySarifReporter) getRuns(findings []betterleaks.Finding) []Runs {
	return []Runs{
		{
			Tool:    r.getTool(),
			Results: legacyGetResults(findings),
		},
	}
}

func (r *LegacySarifReporter) getTool() Tool {
	// Legacy: use gitleaks driver name and branding.
	tool := Tool{
		Driver: Driver{
			Name:            legacyDriver,
			SemanticVersion: legacyVersion,
			InformationUri:  "https://github.com/gitleaks/gitleaks",
			Rules:           r.getRules(),
		},
	}

	if hasEmptyRules(tool) {
		tool.Driver.Rules = make([]Rules, 0)
	}

	return tool
}

func (r *LegacySarifReporter) getRules() []Rules {
	var rules []Rules
	for _, rule := range r.OrderedRules {
		rules = append(rules, Rules{
			ID: rule.RuleID,
			Description: ShortDescription{
				Text: rule.Description,
			},
		})
	}
	return rules
}

func legacyMessageText(f betterleaks.Finding) string {
	commit := f.Metadata[betterleaks.MetaCommitSHA]
	file := f.Metadata[betterleaks.MetaPath]
	if commit == "" {
		return fmt.Sprintf("%s has detected secret for file %s.", f.RuleID, file)
	}
	return fmt.Sprintf("%s has detected secret for file %s at commit %s.", f.RuleID, file, commit)
}

func legacyGetResults(findings []betterleaks.Finding) []Results {
	results := []Results{}
	for _, f := range findings {
		result := Results{
			Message: Message{
				Text: legacyMessageText(f),
			},
			RuleId:    f.RuleID,
			Locations: legacyGetLocation(f),
			PartialFingerPrints: PartialFingerPrints{
				CommitSha:     f.Metadata[betterleaks.MetaCommitSHA],
				Email:         f.Metadata[betterleaks.MetaAuthorEmail],
				CommitMessage: f.Metadata[betterleaks.MetaCommitMessage],
				Date:          f.Metadata[betterleaks.MetaCommitDate],
				Author:        f.Metadata[betterleaks.MetaAuthorName],
			},
			Properties: Properties{
				Tags: f.Tags,
			},
		}
		results = append(results, result)
	}
	return results
}

func legacyGetLocation(f betterleaks.Finding) []Locations {
	uri := f.Metadata[betterleaks.MetaPath]
	if symlink := f.Metadata[betterleaks.MetaSymlinkFile]; symlink != "" {
		uri = symlink
	}
	return []Locations{
		{
			PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI: uri,
				},
				Region: Region{
					StartLine:   f.StartLine,
					EndLine:     f.EndLine,
					StartColumn: f.StartColumn,
					EndColumn:   f.EndColumn,
					Snippet: Snippet{
						Text: f.Secret,
					},
				},
			},
		},
	}
}
