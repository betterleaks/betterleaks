package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks"
)

type CsvReporter struct {
}

var _ betterleaks.Reporter = (*CsvReporter)(nil)

func (r *CsvReporter) Write(w io.WriteCloser, findings []betterleaks.Finding) error {
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
	if findings[0].Metadata[betterleaks.MetaLink] != "" {
		columns = append(columns, "Link")
	}

	if err = cw.Write(columns); err != nil {
		return err
	}
	for _, f := range findings {
		row := []string{f.RuleID,
			f.Metadata[betterleaks.MetaCommitSHA],
			f.Metadata[betterleaks.MetaPath],
			f.Metadata[betterleaks.MetaSymlinkFile],
			f.Secret,
			f.Match,
			strconv.Itoa(f.StartLine),
			strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn),
			strconv.Itoa(f.EndColumn),
			f.Metadata[betterleaks.MetaAuthorName],
			f.Metadata[betterleaks.MetaCommitMessage],
			f.Metadata[betterleaks.MetaCommitDate],
			f.Metadata[betterleaks.MetaAuthorEmail],
			f.Fingerprint,
			strings.Join(f.Tags, " "),
		}
		if findings[0].Metadata[betterleaks.MetaLink] != "" {
			row = append(row, f.Metadata[betterleaks.MetaLink])
		}

		if err = cw.Write(row); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}
