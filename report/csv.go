package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
)

type CsvReporter struct {
}

var _ Reporter = (*CsvReporter)(nil)

// csvFormulaPrefixes are the characters a spreadsheet may treat as the start of
// a formula. A scanned secret/match/path beginning with one of these would be
// executed as a formula when the report is opened (CSV / formula injection).
const csvFormulaPrefixes = "=+-@\t\r"

// sanitizeCSVField neutralizes CSV/formula injection by prefixing a value that
// begins with a formula trigger character with a single quote, per the OWASP
// recommendation. The formula triggers are all ASCII, so inspecting the first
// byte is sufficient and safe for multi-byte UTF-8 values.
func sanitizeCSVField(s string) string {
	if s != "" && strings.IndexByte(csvFormulaPrefixes, s[0]) != -1 {
		return "'" + s
	}
	return s
}

func (r *CsvReporter) Write(w io.WriteCloser, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}

	var (
		cw  = csv.NewWriter(w)
		err error
	)
	columns := []string{"RuleID",
		"Commit",
		"File",
		"SymlinkFile",
		"Secret",
		"Match",
		"StartLine",
		"EndLine",
		"StartColumn",
		"EndColumn",
		"Author",
		"Message",
		"Date",
		"Email",
		"Fingerprint",
		"Tags",
	}
	// A miserable attempt at "omitempty" so tests don't yell at me.
	if findings[0].Link != "" {
		columns = append(columns, "Link")
	}
	hasMatchContext := false
	for _, f := range findings {
		if f.MatchContext != "" {
			hasMatchContext = true
			break
		}
	}
	if hasMatchContext {
		columns = append(columns, "MatchContext")
	}

	if err = cw.Write(columns); err != nil {
		return err
	}
	for _, f := range findings {
		row := []string{f.RuleID,
			f.Commit,
			f.File,
			f.SymlinkFile,
			f.Secret,
			f.Match,
			strconv.Itoa(f.StartLine),
			strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn),
			strconv.Itoa(f.EndColumn),
			f.Author,
			f.Message,
			f.Date,
			f.Email,
			f.Fingerprint,
			strings.Join(f.Tags, " "),
		}
		if findings[0].Link != "" {
			row = append(row, f.Link)
		}
		if hasMatchContext {
			row = append(row, f.MatchContext)
		}

		for i := range row {
			row[i] = sanitizeCSVField(row[i])
		}

		if err = cw.Write(row); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}
