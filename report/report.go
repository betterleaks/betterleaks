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

// FindingWriter writes findings incrementally and finalizes the stream without
// closing the underlying writer.
type FindingWriter interface {
	WriteFinding(finding Finding) error
	Close() error
}

// StreamingReporter creates a writer that does not retain findings.
type StreamingReporter interface {
	Reporter
	NewWriter(w io.Writer) (FindingWriter, error)
}
