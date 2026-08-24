package detect

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

var removedFindingJSONFields = [...]string{
	"File",
	"SymlinkFile",
	"Commit",
	"Link",
	"Entropy",
	"Author",
	"Email",
	"Date",
	"Message",
}

func IsNew(finding report.Finding, redact uint, baseline []report.Finding) bool {
	// Explicitly testing each property as it gives significantly better performance in comparison to cmp.Equal(). Drawback is that
	// the code requires maintenance if/when the Finding struct changes
	for _, b := range baseline {
		if finding.RuleID == b.RuleID &&
			finding.Description == b.Description &&
			finding.StartLine == b.StartLine &&
			finding.EndLine == b.EndLine &&
			finding.StartColumn == b.StartColumn &&
			finding.EndColumn == b.EndColumn &&
			(redact > 0 || (finding.Match == b.Match && finding.Secret == b.Secret)) &&
			finding.Attr(sources.AttrPath) == b.Attr(sources.AttrPath) &&
			finding.Attr(sources.AttrGitSHA) == b.Attr(sources.AttrGitSHA) &&
			finding.Attr(sources.AttrGitAuthorName) == b.Attr(sources.AttrGitAuthorName) &&
			finding.Attr(sources.AttrGitAuthorEmail) == b.Attr(sources.AttrGitAuthorEmail) &&
			finding.Attr(sources.AttrGitDate) == b.Attr(sources.AttrGitDate) &&
			finding.Attr(sources.AttrGitMessage) == b.Attr(sources.AttrGitMessage) {
			// Omit checking Fingerprint: changing its format must not make every
			// existing baseline finding appear new.
			return false
		}
	}
	return true
}

func LoadBaseline(baselinePath string) ([]report.Finding, error) {
	file, err := os.Open(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("open baseline %q: %w", baselinePath, err)
	}
	defer func() { _ = file.Close() }()

	// encoding/json intentionally ignores unknown fields. Once the deprecated
	// Finding fields were removed, that otherwise made an old baseline appear to
	// load successfully while discarding all of its source identity. Reject that
	// schema explicitly instead of silently changing baseline behavior. Decode
	// one entry at a time so this check does not retain a second copy of a large
	// baseline in memory.
	decoder := json.NewDecoder(file)
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("decode baseline %q: %w", baselinePath, err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '[' {
		return nil, fmt.Errorf("decode baseline %q: expected a JSON array", baselinePath)
	}

	previousFindings := make([]report.Finding, 0)
	for index := 0; decoder.More(); index++ {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("decode baseline %q: %w", baselinePath, err)
		}
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, fmt.Errorf("decode baseline %q: finding %d: %w", baselinePath, index, err)
		}
		for key := range entry {
			for _, removed := range removedFindingJSONFields {
				if strings.EqualFold(key, removed) {
					return nil, fmt.Errorf(
						"decode baseline %q: finding %d uses removed field %q; regenerate the baseline with this version",
						baselinePath,
						index,
						key,
					)
				}
			}
		}

		var finding report.Finding
		if err := json.Unmarshal(raw, &finding); err != nil {
			return nil, fmt.Errorf("decode baseline %q: finding %d: %w", baselinePath, index, err)
		}
		previousFindings = append(previousFindings, finding)
	}
	token, err = decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("decode baseline %q: %w", baselinePath, err)
	}
	delimiter, ok = token.(json.Delim)
	if !ok || delimiter != ']' {
		return nil, fmt.Errorf("decode baseline %q: expected end of JSON array", baselinePath)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode baseline %q: unexpected data after JSON array", baselinePath)
		}
		return nil, fmt.Errorf("decode baseline %q: %w", baselinePath, err)
	}

	return previousFindings, nil
}
