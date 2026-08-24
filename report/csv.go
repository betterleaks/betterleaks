package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/sources"
)

type CsvReporter struct {
}

var _ Reporter = (*CsvReporter)(nil)
var _ StreamReporter = (*CsvReporter)(nil)

func (r *CsvReporter) Write(w io.Writer, findings []Finding) error {
	return r.WriteStream(w, len(findings), iterateFindings(findings))
}

func (r *CsvReporter) WriteStream(w io.Writer, count int, findings FindingIterator) error {
	if count == 0 {
		return nil
	}
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
	var seen, hasLink, hasMatchContext bool
	if err := findings(func(f Finding) error {
		seen = true
		if f.Attr(sources.AttrURL) != "" {
			hasLink = true
		}
		if f.MatchContext != "" {
			hasMatchContext = true
		}
		return nil
	}); err != nil {
		return err
	}
	if !seen {
		return nil
	}

	if hasLink {
		columns = append(columns, "Link")
	}
	if hasMatchContext {
		columns = append(columns, "MatchContext")
	}

	cw := csv.NewWriter(w)
	if err := cw.Write(columns); err != nil {
		return err
	}
	if err := findings(func(f Finding) error {
		row := []string{f.RuleID,
			f.Attr(sources.AttrGitSHA),
			f.Attr(sources.AttrPath),
			f.Attr(sources.AttrFSSymlink),
			f.Secret,
			f.Match,
			strconv.Itoa(f.StartLine),
			strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn),
			strconv.Itoa(f.EndColumn),
			f.Attr(sources.AttrGitAuthorName),
			f.Attr(sources.AttrGitMessage),
			f.Attr(sources.AttrGitDate),
			f.Attr(sources.AttrGitAuthorEmail),
			f.Fingerprint,
			strings.Join(f.Tags, " "),
		}
		if hasLink {
			row = append(row, f.Attr(sources.AttrURL))
		}
		if hasMatchContext {
			row = append(row, f.MatchContext)
		}
		return cw.Write(row)
	}); err != nil {
		return err
	}

	cw.Flush()
	return cw.Error()
}
