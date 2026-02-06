package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/betterleaks/betterleaks"
)

// isNewFormatFingerprint checks if a fingerprint uses the new !-delimited format.
func isNewFormatFingerprint(fp string) bool {
	return strings.Contains(fp, "!")
}

func IsNew(finding betterleaks.Finding, redact uint, baseline []betterleaks.Finding) bool {
	for _, b := range baseline {
		// Fast path: both have new-format fingerprints
		if isNewFormatFingerprint(finding.Fingerprint) && isNewFormatFingerprint(b.Fingerprint) {
			if finding.Fingerprint == b.Fingerprint {
				return false
			}
			continue
		}

		// Fallback: field-by-field comparison (existing logic, unchanged)
		if finding.RuleID == b.RuleID &&
			finding.Description == b.Description &&
			finding.StartLine == b.StartLine &&
			finding.EndLine == b.EndLine &&
			finding.StartColumn == b.StartColumn &&
			finding.EndColumn == b.EndColumn &&
			(redact > 0 || (finding.Match == b.Match && finding.Secret == b.Secret)) &&
			finding.Metadata[betterleaks.MetaPath] == b.Metadata[betterleaks.MetaPath] &&
			finding.Metadata[betterleaks.MetaCommitSHA] == b.Metadata[betterleaks.MetaCommitSHA] &&
			finding.Metadata[betterleaks.MetaAuthorName] == b.Metadata[betterleaks.MetaAuthorName] &&
			finding.Metadata[betterleaks.MetaAuthorEmail] == b.Metadata[betterleaks.MetaAuthorEmail] &&
			finding.Metadata[betterleaks.MetaCommitDate] == b.Metadata[betterleaks.MetaCommitDate] &&
			finding.Metadata[betterleaks.MetaCommitMessage] == b.Metadata[betterleaks.MetaCommitMessage] &&
			finding.Entropy == b.Entropy {
			return false
		}
	}
	return true
}

func LoadBaseline(baselinePath string) ([]betterleaks.Finding, error) {
	bytes, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s", baselinePath)
	}

	var previousFindings []betterleaks.Finding
	err = json.Unmarshal(bytes, &previousFindings)
	if err != nil {
		return nil, fmt.Errorf("the format of the file %s is not supported", baselinePath)
	}

	return previousFindings, nil
}

func (p *Pipeline) AddBaseline(baselinePath string, source string) error {
	if baselinePath != "" {
		absoluteSource, err := filepath.Abs(source)
		if err != nil {
			return err
		}

		absoluteBaseline, err := filepath.Abs(baselinePath)
		if err != nil {
			return err
		}

		relativeBaseline, err := filepath.Rel(absoluteSource, absoluteBaseline)
		if err != nil {
			return err
		}

		baseline, err := LoadBaseline(baselinePath)
		if err != nil {
			return err
		}

		p.baseline = baseline
		baselinePath = relativeBaseline

	}

	p.baselinePath = baselinePath
	return nil
}
