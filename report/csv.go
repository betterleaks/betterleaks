package report

import (
	"encoding/csv"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks"
)

// CsvReporter writes findings in the new betterleaks CSV format, including all
// metadata key-value pairs as columns. Use LegacyCsvReporter for the
// gitleaks-compatible fixed-column layout (--legacy).
type CsvReporter struct{}

var _ betterleaks.Reporter = (*CsvReporter)(nil)

// knownMetaKeys is the preferred column order for well-known metadata keys.
// Any metadata keys not in this list are appended alphabetically.
var knownMetaKeys = []string{
	betterleaks.MetaPath,
	betterleaks.MetaSymlinkFile,
	betterleaks.MetaCommitSHA,
	betterleaks.MetaAuthorName,
	betterleaks.MetaAuthorEmail,
	betterleaks.MetaCommitDate,
	betterleaks.MetaCommitMessage,
	betterleaks.MetaLink,
}

// collectMetaColumns returns a stable ordered list of metadata column names,
// starting with the known keys (if present in any finding), followed by any
// extra keys sorted alphabetically.
func collectMetaColumns(findings []betterleaks.Finding) []string {
	seen := make(map[string]bool)
	for _, f := range findings {
		for k := range f.Metadata {
			seen[k] = true
		}
	}

	var columns []string
	knownSet := make(map[string]bool)
	for _, k := range knownMetaKeys {
		knownSet[k] = true
		if seen[k] {
			columns = append(columns, k)
		}
	}

	// Extras: any key not in the known set, sorted alphabetically.
	var extras []string
	for k := range seen {
		if !knownSet[k] {
			extras = append(extras, k)
		}
	}
	sort.Strings(extras)
	columns = append(columns, extras...)

	return columns
}

func (r *CsvReporter) Write(w io.WriteCloser, findings []betterleaks.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	var (
		cw  = csv.NewWriter(w)
		err error
	)

	metaCols := collectMetaColumns(findings)

	// Header: core fields + one column per metadata key.
	header := []string{
		"RuleID",
		"Description",
		"Match",
		"Secret",
		"StartLine",
		"EndLine",
		"StartColumn",
		"EndColumn",
		"Entropy",
		"Tags",
		"Fingerprint",
	}
	for _, k := range metaCols {
		header = append(header, "meta:"+k)
	}

	if err = cw.Write(header); err != nil {
		return err
	}

	for _, f := range findings {
		row := []string{
			f.RuleID,
			f.Description,
			f.Match,
			f.Secret,
			strconv.Itoa(f.StartLine),
			strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn),
			strconv.Itoa(f.EndColumn),
			strconv.FormatFloat(f.Entropy, 'f', -1, 64),
			strings.Join(f.Tags, " "),
			f.Fingerprint,
		}
		for _, k := range metaCols {
			row = append(row, f.Metadata[k])
		}

		if err = cw.Write(row); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}
