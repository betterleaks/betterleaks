package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/report"
)

// findingCollector owns the CLI lifetime of accepted findings. Normal report
// formats are replayed from a temporary JSON stream instead of retaining every
// Finding in the heap. Custom templates keep their historical []Finding input
// because arbitrary templates may index the slice or call len on it.
type findingCollector struct {
	count int

	reportEnabled bool
	retainSlice   bool
	redact        uint
	verbose       bool
	legacyPrint   bool
	noColor       bool

	file     *os.File
	tempPath string
	buffer   *bufio.Writer
	encoder  *json.Encoder
	retained []report.Finding
	sealed   bool
	closed   bool
}

func newFindingCollector(cmd *cobra.Command) *findingCollector {
	reportEnabled := mustGetStringFlag(cmd, "report-path") != ""
	reportFormat := strings.TrimSpace(strings.ToLower(mustGetStringFlag(cmd, "report-format")))
	reportTemplate := mustGetStringFlag(cmd, "report-template")

	return &findingCollector{
		reportEnabled: reportEnabled,
		retainSlice:   reportEnabled && (reportTemplate != "" || reportFormat == "template"),
		redact:        mustGetUIntFlag(cmd, "redact"),
		verbose:       mustGetBoolFlag(cmd, "verbose"),
		legacyPrint:   mustGetBoolFlag(cmd, "legacy-print"),
		noColor:       mustGetBoolFlag(cmd, "no-color"),
	}
}

func (c *findingCollector) Add(finding report.Finding) error {
	if c == nil {
		return errors.New("nil finding collector")
	}
	if c.closed {
		return errors.New("finding collector is closed")
	}
	if c.sealed {
		return errors.New("finding collector cannot accept findings after iteration")
	}

	if c.verbose {
		if c.legacyPrint {
			finding.PrintLegacy(c.noColor, c.redact)
		} else {
			finding.Print(c.noColor, c.redact)
		}
	}
	if !c.reportEnabled {
		c.count++
		return nil
	}

	finding.Redact(c.redact)
	if c.retainSlice {
		c.retained = append(c.retained, finding)
		c.count++
		return nil
	}
	if err := c.openSpool(); err != nil {
		return err
	}
	if err := c.encoder.Encode(&finding); err != nil {
		return fmt.Errorf("spool finding: %w", err)
	}
	c.count++
	return nil
}

func (c *findingCollector) openSpool() error {
	if c.file != nil {
		return nil
	}
	file, err := os.CreateTemp("", "betterleaks-findings-*")
	if err != nil {
		return fmt.Errorf("create findings spool: %w", err)
	}

	// CreateTemp uses mode 0600. On Unix, unlink the directory entry while the
	// descriptor is open so an interrupted scan cannot leave secrets in /tmp.
	// Windows does not permit removing an open file, so Close removes it there.
	tempPath := file.Name()
	if err := os.Remove(tempPath); err == nil {
		tempPath = ""
	}

	c.file = file
	c.tempPath = tempPath
	c.buffer = bufio.NewWriterSize(file, 64*1024)
	c.encoder = json.NewEncoder(c.buffer)
	return nil
}

func (c *findingCollector) Len() int {
	if c == nil {
		return 0
	}
	return c.count
}

func (c *findingCollector) Iterate(visit func(report.Finding) error) error {
	if c == nil {
		return errors.New("nil finding collector")
	}
	if c.closed {
		return errors.New("finding collector is closed")
	}
	if visit == nil {
		return errors.New("nil finding visitor")
	}
	c.sealed = true

	if c.retainSlice {
		for i := range c.retained {
			if err := visit(c.retained[i]); err != nil {
				return err
			}
		}
		return nil
	}
	if c.file == nil {
		return nil
	}
	if c.buffer != nil {
		if err := c.buffer.Flush(); err != nil {
			return fmt.Errorf("flush findings spool: %w", err)
		}
		c.buffer = nil
		c.encoder = nil
	}
	if _, err := c.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind findings spool: %w", err)
	}

	decoder := json.NewDecoder(c.file)
	decoder.UseNumber()
	for {
		var finding report.Finding
		if err := decoder.Decode(&finding); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read findings spool: %w", err)
		}
		if err := visit(finding); err != nil {
			return err
		}
	}
}

func (c *findingCollector) Slice() ([]report.Finding, error) {
	if c == nil {
		return nil, errors.New("nil finding collector")
	}
	if c.retainSlice {
		c.sealed = true
		return c.retained, nil
	}

	findings := make([]report.Finding, 0, c.count)
	if err := c.Iterate(func(finding report.Finding) error {
		findings = append(findings, finding)
		return nil
	}); err != nil {
		return nil, err
	}
	return findings, nil
}

func (c *findingCollector) Close() error {
	if c == nil || c.closed {
		return nil
	}
	c.closed = true
	c.retained = nil

	var flushErr, closeErr, removeErr error
	if c.buffer != nil {
		if err := c.buffer.Flush(); err != nil {
			flushErr = fmt.Errorf("flush findings spool: %w", err)
		}
		c.buffer = nil
	}
	c.encoder = nil
	if c.file != nil {
		closeErr = c.file.Close()
		c.file = nil
	}
	if c.tempPath != "" {
		removeErr = os.Remove(c.tempPath)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		c.tempPath = ""
	}
	return errors.Join(flushErr, closeErr, removeErr)
}
