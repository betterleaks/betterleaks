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
	Write(w io.WriteCloser, findings []Finding) error
}

// FindingWriter writes findings one at a time and finalizes the report once all
// findings have been written. It does not close the underlying writer.
type FindingWriter interface {
	WriteFinding(finding Finding) error
	Close() error
}

// StreamingReporter can create a report writer that does not retain findings.
type StreamingReporter interface {
	Reporter
	NewWriter(w io.Writer) (FindingWriter, error)
}
