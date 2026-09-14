package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

const stdoutReportPath = "-"

// findingCollector counts and writes findings as they arrive. Reports are
// streamed so enabling --output does not retain every finding in memory.
type findingCollector struct {
	count int

	pretty  bool
	stdout  io.Writer
	noColor bool
	redact  uint

	stdoutWriter report.FindingWriter
	reportWriter report.FindingWriter
	reportOutput io.WriteCloser
	reportPath   string
	closeReport  bool
	closed       bool
}

func newFindingCollector(flags *ScanFlags, noColor bool, stdout io.Writer) (*findingCollector, error) {
	collector := &findingCollector{
		noColor:    noColor,
		stdout:     stdout,
		redact:     uint(flags.Redact),
		reportPath: flags.Output,
	}

	// A report directed to stdout owns the stream, preventing pretty or JSONL
	// finding output from being interleaved with the report document.
	if !flags.Silent && flags.Output != stdoutReportPath {
		if flags.JSONL {
			var err error
			collector.stdoutWriter, err = report.NewJSONLWriter(stdout)
			if err != nil {
				return nil, err
			}
		} else {
			collector.pretty = true
		}
	}

	if flags.Output == "" {
		return collector, nil
	}

	reporter, err := reporterForPath(flags.Output, flags.JSONL)
	if err != nil {
		return nil, err
	}
	if flags.Output == stdoutReportPath {
		collector.reportOutput = nopWriteCloser{Writer: stdout}
	} else {
		collector.reportOutput, err = os.Create(flags.Output)
		if err != nil {
			return nil, fmt.Errorf("create output %q: %w", flags.Output, err)
		}
		collector.closeReport = true
	}
	collector.reportWriter, err = reporter(collector.reportOutput)
	if err != nil {
		if collector.closeReport {
			_ = collector.reportOutput.Close()
		}
		return nil, err
	}
	return collector, nil
}

func mustNewFindingCollector(runtime *commandRuntime, flags *ScanFlags, noColor bool) *findingCollector {
	collector, err := newFindingCollector(flags, noColor, runtime.stdout)
	if err != nil {
		runtime.fatal("failed to configure finding output", "error", err)
	}
	return collector
}

func reporterForPath(path string, stdoutJSONL bool) (func(io.Writer) (report.FindingWriter, error), error) {
	if path == stdoutReportPath {
		if stdoutJSONL {
			return report.NewJSONLWriter, nil
		}
		return report.NewJSONWriter, nil
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return report.NewJSONWriter, nil
	case ".jsonl":
		return report.NewJSONLWriter, nil
	default:
		return nil, fmt.Errorf("output path %q must end in .json or .jsonl", path)
	}
}

func (c *findingCollector) Add(finding report.Finding) error {
	if c.closed {
		return errors.New("finding collector is closed")
	}
	c.count++

	if c.pretty {
		width, _ := strconv.Atoi(os.Getenv("COLUMNS"))
		if width < 60 {
			width = 100
		}
		if err := report.WritePretty(c.stdout, finding, report.PrettyOptions{NoColor: c.noColor, Redact: c.redact, Width: width}); err != nil {
			return err
		}
	}
	if c.stdoutWriter == nil && c.reportWriter == nil {
		return nil
	}

	if c.redact > 0 {
		finding = finding.RedactedCopy(c.redact)
	}
	if c.stdoutWriter != nil {
		if err := c.stdoutWriter.WriteFinding(finding); err != nil {
			return err
		}
	}
	if c.reportWriter != nil {
		if err := c.reportWriter.WriteFinding(finding); err != nil {
			return err
		}
	}
	return nil
}

func (c *findingCollector) Count() int {
	return c.count
}

// FileSkipFunc composes the configured source prefilter with a guard for the
// report file. Files invokes this callback before opening a path, which keeps a
// scan from consuming the report while the collector is appending to it.
func (c *findingCollector) FileSkipFunc(configured sources.SkipFunc) sources.SkipFunc {
	if c.reportPath == "" || c.reportPath == stdoutReportPath {
		return configured
	}

	reportPath, err := filepath.Abs(c.reportPath)
	if err != nil {
		return configured
	}
	reportPath = filepath.Clean(reportPath)
	reportInfo, _ := os.Stat(reportPath)

	return func(attributes map[string]string) bool {
		if configured != nil && configured(attributes) {
			return true
		}

		path := attributes[sources.AttrPath]
		if path == "" {
			return false
		}
		candidate, err := filepath.Abs(filepath.FromSlash(path))
		if err != nil {
			return false
		}
		candidate = filepath.Clean(candidate)
		if candidate == reportPath {
			return true
		}
		if reportInfo == nil {
			return false
		}
		candidateInfo, err := os.Stat(candidate)
		return err == nil && os.SameFile(reportInfo, candidateInfo)
	}
}

func (c *findingCollector) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true

	var errs []error
	if c.stdoutWriter != nil {
		errs = append(errs, c.stdoutWriter.Close())
	}
	if c.reportWriter != nil {
		errs = append(errs, c.reportWriter.Close())
	}
	if c.closeReport {
		errs = append(errs, c.reportOutput.Close())
	}
	return errors.Join(errs...)
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
