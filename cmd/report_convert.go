package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/report"
)

func init() {
	reportCmd.AddCommand(convertCmd)
}

var convertCmd = &cobra.Command{
	Use:   "convert [report.json]",
	Args:  cobra.MaximumNArgs(1),
	Short: "convert a JSON report to another format",
	Long: `Reads a JSON or JSONL report and writes it in the requested output format.

No filtering or suppression is applied; all input findings appear in the output.
Use --report-path and --report-format (or --report-template) to select the output.
Use --verbose to print verbose findings to stdout.`,
	RunE: runConvert,
}

func runConvert(cmd *cobra.Command, args []string) error {
	inputPath := "-"
	if len(args) > 0 {
		inputPath = args[0]
	}

	// Config is only needed for SARIF rule ordering; use the input file's
	// directory for discovery, falling back to "." for stdin.
	inputDir := "."
	if inputPath != "-" {
		inputDir = filepath.Dir(inputPath)
	}
	initConfig(inputDir)
	initDiagnostics()
	cfg := Config(cmd)

	noColor := mustGetBoolFlag(cmd, "no-color")
	redact := mustGetUIntFlag(cmd, "redact")
	verbose := mustGetBoolFlag(cmd, "verbose")
	legacyPrint := mustGetBoolFlag(cmd, "legacy-print")

	findings, err := report.LoadFindings(inputPath)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	// Verbose output (Print handles its own redaction on a value copy).
	if verbose {
		for _, f := range findings {
			if legacyPrint {
				f.PrintLegacy(noColor, redact)
			} else {
				f.Print(noColor, redact)
			}
		}
	}

	// Permanently redact before writing the report.
	detect.RedactFindings(findings, redact)

	reporter, reportPath, err := buildReporter(cmd, cfg)
	if err != nil {
		return err
	}
	if reporter == nil {
		return nil
	}

	var out io.WriteCloser
	if reportPath == report.StdoutReportPath {
		out = os.Stdout
	} else {
		if out, err = os.Create(reportPath); err != nil {
			return fmt.Errorf("opening report path: %w", err)
		}
		defer func() { _ = out.Close() }()
	}
	if err = reporter.Write(out, findings); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return nil
}
