package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/version"
)

const stdoutReportPath = "-"

// findingCollector counts and writes findings as they arrive. Reports are
// streamed so enabling --output does not retain every finding in memory.
type findingCollector struct {
	scan       report.ScanMetadata
	jsonReport bool

	pretty  bool
	stdout  io.Writer
	noColor bool
	redact  uint

	stdoutWriter report.FindingWriter
	reportWriter report.FindingWriter
	stdoutErr    error
	reportErr    error
	reportOutput io.WriteCloser
	reportPath   string
	closeReport  bool
	closed       bool
}

func newFindingCollector(flags *ScanFlags, noColor bool, stdout io.Writer) (*findingCollector, error) {
	collector := &findingCollector{
		scan:       report.ScanMetadata{State: report.ScanStateIncomplete, Started: time.Now().UTC(), BetterleaksVersion: version.Version},
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
	collector.jsonReport = strings.EqualFold(filepath.Ext(flags.Output), ".json") || (flags.Output == stdoutReportPath && !flags.JSONL)
	if flags.Output == stdoutReportPath {
		collector.reportOutput = nopWriteCloser{Writer: stdout}
	} else {
		collector.reportOutput, err = os.Create(flags.Output)
		if err != nil {
			return nil, fmt.Errorf("create output %q: %w", flags.Output, err)
		}
		collector.closeReport = true
	}
	if collector.jsonReport {
		_, err = fmt.Fprintf(collector.reportOutput, "{\n \"schema_version\": %q,\n \"findings\": ", report.SchemaVersion)
	}
	if err == nil {
		collector.reportWriter, err = reporter(collector.reportOutput)
	}
	if err != nil {
		if collector.closeReport {
			_ = collector.reportOutput.Close()
		}
		return nil, err
	}
	return collector, nil
}

func mustNewFindingCollector(runtime *commandRuntime, flags *ScanFlags, noColor bool, started time.Time, cfg *config.Config, sourceType string, targets ...string) *findingCollector {
	collector, err := newFindingCollector(flags, noColor, runtime.stdout)
	if err != nil {
		runtime.fatal("failed to configure finding output", "error", err)
	}
	collector.scan.Started = started.UTC()
	collector.scan.ConfigHash = cfg.Hash()
	collector.scan.Source.Type = sourceType
	for _, target := range targets {
		if sourceType != "filesystem" && (sourceType != "git" || remoteGitURL(target)) {
			target = urlredact.PublicString(target)
		}
		collector.scan.Source.Targets = append(collector.scan.Source.Targets, target)
	}
	return collector
}

func (c *findingCollector) startScan(runtime *commandRuntime) {
	runtime.Logger().Info("starting scan", "config_hash", c.scan.ConfigHash)
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
	if c.stdoutErr != nil || c.reportErr != nil {
		return errors.Join(c.stdoutErr, c.reportErr)
	}
	// Try both destinations so a terminal failure does not lose a finding from
	// a healthy report. Failed destinations receive no misleading final totals.
	delivered := !c.pretty && c.stdoutWriter == nil && c.reportWriter == nil

	if c.pretty {
		width, _ := strconv.Atoi(os.Getenv("COLUMNS"))
		if width < 60 {
			width = 100
		}
		c.stdoutErr = report.WritePretty(c.stdout, finding, report.PrettyOptions{NoColor: c.noColor, Redact: c.redact, Width: width})
		delivered = delivered || c.stdoutErr == nil
	}

	if c.redact > 0 && (c.stdoutWriter != nil || c.reportWriter != nil) {
		finding = finding.RedactedCopy(c.redact)
	}
	if c.stdoutWriter != nil {
		c.stdoutErr = c.stdoutWriter.WriteFinding(finding)
		delivered = delivered || c.stdoutErr == nil
	}
	if c.reportWriter != nil {
		c.reportErr = c.reportWriter.WriteFinding(finding)
		delivered = delivered || c.reportErr == nil
	}
	if delivered {
		c.countFinding(finding)
	}
	return errors.Join(c.stdoutErr, c.reportErr)
}

func (c *findingCollector) Count() int {
	return c.scan.NumFindings
}

func (c *findingCollector) countFinding(finding report.Finding) {
	c.scan.NumFindings++
	switch finding.Confidence {
	case "high":
		c.scan.ConfidenceCounts.High++
	case "medium":
		c.scan.ConfidenceCounts.Medium++
	case "low":
		c.scan.ConfidenceCounts.Low++
	case "":
		c.scan.ConfidenceCounts.None++
	default:
		c.scan.ConfidenceCounts.Other++
	}
	switch finding.Analysis.Severity {
	case report.SeverityHigh:
		c.scan.SeverityCounts.High++
	case report.SeverityMedium:
		c.scan.SeverityCounts.Medium++
	case report.SeverityNone:
		c.scan.SeverityCounts.None++
	default:
		c.scan.SeverityCounts.Unknown++
	}
	switch finding.Analysis.Status {
	case report.ValidationStatusValid:
		c.scan.StatusCounts.Valid++
	case report.ValidationStatusInvalid:
		c.scan.StatusCounts.Invalid++
	case report.ValidationStatusRevoked:
		c.scan.StatusCounts.Revoked++
	case report.ValidationStatusNeedsValidation:
		c.scan.StatusCounts.NeedsValidation++
	case report.ValidationStatusError:
		c.scan.StatusCounts.Error++
	case report.ValidationStatusNone:
		c.scan.StatusCounts.None++
	default:
		c.scan.StatusCounts.Unknown++
	}
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
	c.scan.Finished = time.Now().UTC()

	errs := []error{c.stdoutErr, c.reportErr}
	if c.stdoutWriter != nil && c.stdoutErr == nil {
		err := c.stdoutWriter.Close()
		if err == nil {
			err = c.writeScanMetadata(c.stdout, false)
		}
		errs = append(errs, err)
	}
	if c.reportWriter != nil && c.reportErr == nil {
		err := c.reportWriter.Close()
		if err == nil {
			err = c.writeScanMetadata(c.reportOutput, c.jsonReport)
		}
		errs = append(errs, err)
	}
	if c.closeReport {
		errs = append(errs, c.reportOutput.Close())
	}
	return errors.Join(errs...)
}

func (c *findingCollector) writeScanMetadata(w io.Writer, jsonReport bool) error {
	if !jsonReport {
		return json.NewEncoder(w).Encode(struct {
			SchemaVersion string              `json:"schema_version"`
			Scan          report.ScanMetadata `json:"scan"`
		}{report.SchemaVersion, c.scan})
	}
	metadata, err := json.MarshalIndent(c.scan, " ", " ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, ",\n \"scan\": %s\n}\n", metadata)
	return err
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
