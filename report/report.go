// Package report defines findings, credential results, and their output formats.
package report

// FindingWriter writes findings incrementally. Close finalizes the document;
// it never closes the caller's underlying writer. Calls must be serialized.
type FindingWriter interface {
	WriteFinding(Finding) error
	Close() error
}
