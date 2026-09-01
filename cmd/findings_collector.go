package cmd

import (
	"errors"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/report"
)

// findingCollector counts findings and optionally buffers them for a report.
// Its zero value is count-only. It is used by a single Run result consumer and
// is not synchronized.
type findingCollector struct {
	count           int
	retainForReport bool
	reportFindings  []report.Finding

	streamReporter    report.StreamingReporter
	reportPath        string
	streamWriter      report.FindingWriter
	reportOutput      io.WriteCloser
	closeReportOutput bool
	redact            uint
	closed            bool
}

func newFindingCollector(cmd *cobra.Command) (*findingCollector, error) {
	collector := new(findingCollector)
	reportPath := mustGetStringFlag(cmd, "report-path")
	if reportPath == "" {
		return collector, nil
	}

	reportFormat, err := reportFormatForCommand(cmd, reportPath)
	if err != nil {
		return nil, err
	}
	switch reportFormat {
	case "json":
		collector.streamReporter = &report.JsonReporter{}
	case "jsonl":
		collector.streamReporter = &report.JsonlReporter{}
	default:
		collector.retainForReport = true
	}
	collector.reportPath = reportPath
	collector.redact = mustGetUIntFlag(cmd, "redact")
	return collector, nil
}

// Add counts a finding and either streams it to a JSON/JSONL report or retains
// it for one of the report formats that require the full result set.
func (c *findingCollector) Add(finding report.Finding) error {
	if c.closed {
		return errors.New("finding collector is closed")
	}
	c.count++
	if c.retainForReport {
		c.reportFindings = append(c.reportFindings, finding)
		return nil
	}
	if c.streamReporter == nil {
		return nil
	}
	if err := c.initializeStream(); err != nil {
		return err
	}

	if c.redact > 0 {
		finding = finding.RedactedCopy(c.redact)
	}
	return c.streamWriter.WriteFinding(finding)
}

func (c *findingCollector) Count() int {
	return c.count
}

func (c *findingCollector) ReportFindings() []report.Finding {
	return c.reportFindings
}

func (c *findingCollector) StreamsReport() bool {
	return c.streamReporter != nil
}

// Close completes a streaming report and closes an owned output file. It is a
// no-op for count-only collectors and report formats that retain findings.
func (c *findingCollector) Close() error {
	if c.closed {
		return nil
	}
	if c.streamReporter == nil {
		c.closed = true
		return nil
	}
	if err := c.initializeStream(); err != nil {
		return err
	}

	finishErr := c.streamWriter.Close()
	var closeErr error
	if c.closeReportOutput {
		closeErr = c.reportOutput.Close()
	}
	c.closed = true
	return errors.Join(finishErr, closeErr)
}

func (c *findingCollector) initializeStream() error {
	if c.streamWriter != nil {
		return nil
	}

	if c.reportPath == report.StdoutReportPath {
		c.reportOutput = os.Stdout
	} else {
		file, createErr := os.Create(c.reportPath)
		if createErr != nil {
			return createErr
		}
		c.reportOutput = file
		c.closeReportOutput = true
	}

	streamWriter, err := c.streamReporter.NewWriter(c.reportOutput)
	if err != nil {
		if c.closeReportOutput {
			_ = c.reportOutput.Close()
		}
		return err
	}
	c.streamWriter = streamWriter
	return nil
}
