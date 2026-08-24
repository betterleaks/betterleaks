package report

import (
	"io"
)

const (
	// https://cwe.mitre.org/data/definitions/798.html
	CWE              = "CWE-798"
	CWE_DESCRIPTION  = "Use of Hard-coded Credentials"
	StdoutReportPath = "-"
)

type Reporter interface {
	Write(w io.Writer, findings []Finding) error
}

// FindingIterator visits every finding in order. Implementations must be
// replayable: reporters such as CSV make an initial pass to discover their
// output shape before writing it.
type FindingIterator func(visit func(Finding) error) error

// StreamReporter writes a report without requiring all findings to be resident
// in memory. Count must equal the number of values produced by findings.
// Reporter is retained for callers that already have a slice; the command uses
// this interface when a reporter supports it.
type StreamReporter interface {
	WriteStream(w io.Writer, count int, findings FindingIterator) error
}

func iterateFindings(findings []Finding) FindingIterator {
	return func(visit func(Finding) error) error {
		for i := range findings {
			if err := visit(findings[i]); err != nil {
				return err
			}
		}
		return nil
	}
}
