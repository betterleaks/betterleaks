package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

// findingCollector counts and writes findings as they arrive. Reports are
// streamed so enabling --report does not retain every finding in memory.
type findingCollector struct {
	count int

	pretty  bool
	noColor bool
	redact  uint

	stdoutWriter report.FindingWriter
	reportWriter report.FindingWriter
	reportOutput io.WriteCloser
	reportPath   string
	closeReport  bool
	closed       bool
}

func newFindingCollector(cmd *cobra.Command) (*findingCollector, error) {
	silent, err := cmd.Flags().GetBool("silent")
	if err != nil {
		return nil, err
	}
	jsonl, err := cmd.Flags().GetBool("jsonl")
	if err != nil {
		return nil, err
	}
	reportPath, err := cmd.Flags().GetString("report")
	if err != nil {
		return nil, err
	}

	noColor, err := cmd.Flags().GetBool("no-color")
	if err != nil {
		return nil, err
	}
	redact, err := cmd.Flags().GetUint("redact")
	if err != nil {
		return nil, err
	}
	collector := &findingCollector{
		noColor:    noColor,
		redact:     redact,
		reportPath: reportPath,
	}

	// A report directed to stdout owns the stream, preventing pretty or JSONL
	// finding output from being interleaved with the report document.
	if !silent && reportPath != report.StdoutReportPath {
		if jsonl {
			collector.stdoutWriter, err = (&report.JsonlReporter{}).NewWriter(cmd.OutOrStdout())
			if err != nil {
				return nil, err
			}
		} else {
			collector.pretty = true
		}
	}

	if reportPath == "" {
		return collector, nil
	}

	reporter, err := reporterForPath(reportPath, jsonl)
	if err != nil {
		return nil, err
	}
	if reportPath == report.StdoutReportPath {
		collector.reportOutput = nopWriteCloser{Writer: cmd.OutOrStdout()}
	} else {
		collector.reportOutput, err = os.Create(reportPath)
		if err != nil {
			return nil, fmt.Errorf("create report %q: %w", reportPath, err)
		}
		collector.closeReport = true
	}
	collector.reportWriter, err = reporter.NewWriter(collector.reportOutput)
	if err != nil {
		if collector.closeReport {
			_ = collector.reportOutput.Close()
		}
		return nil, err
	}
	return collector, nil
}

func mustNewFindingCollector(cmd *cobra.Command) *findingCollector {
	collector, err := newFindingCollector(cmd)
	if err != nil {
		logging.Fatal().Err(err).Msg("failed to configure finding output")
	}
	return collector
}

func reporterForPath(path string, stdoutJSONL bool) (report.StreamingReporter, error) {
	if path == report.StdoutReportPath {
		if stdoutJSONL {
			return &report.JsonlReporter{}, nil
		}
		return &report.JsonReporter{}, nil
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return &report.JsonReporter{}, nil
	case ".jsonl":
		return &report.JsonlReporter{}, nil
	default:
		return nil, fmt.Errorf("report path %q must end in .json or .jsonl", path)
	}
}

func (c *findingCollector) Add(finding report.Finding) error {
	if c.closed {
		return errors.New("finding collector is closed")
	}
	c.count++

	if c.pretty {
		finding.Print(c.noColor, c.redact)
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
	if c.reportPath == "" || c.reportPath == report.StdoutReportPath {
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
