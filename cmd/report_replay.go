package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
)

func init() {
	reportCmd.AddCommand(replayCmd)
}

var replayCmd = &cobra.Command{
	Use:   "replay [report.json]",
	Args:  cobra.MaximumNArgs(1),
	Short: "re-evaluate filters and suppression rules against a saved report",
	Long: `Reads a previously generated JSON report and re-evaluates the current
config's prefilter, filters, and ignore/baseline suppression against every
finding. Produces a new report containing only the findings that still pass.

Filters referencing finding.line require the original scan to have been run
with --report-include-line.

filter.setConfidence(...) side effects are applied: findings whose confidence
is changed by a filter expression appear with the updated value in the output.

Validation is not re-evaluated; ValidationStatus, ValidationReason, and
ValidationMeta are copied verbatim from the input report.`,
	RunE: runReplay,
}

func runReplay(cmd *cobra.Command, args []string) error {
	start := time.Now()

	inputPath := "-"
	if len(args) > 0 {
		inputPath = args[0]
	}

	// Use the input file's directory for config + ignore-file discovery.
	// Falls back to "." when reading from stdin.
	inputDir := "."
	if inputPath != "-" {
		inputDir = filepath.Dir(inputPath)
	}

	initConfig(inputDir)
	initDiagnostics()

	cfg := Config(cmd)

	exitCode := mustGetIntFlag(cmd, "exit-code")
	noColor := mustGetBoolFlag(cmd, "no-color")
	redact := mustGetUIntFlag(cmd, "redact")
	verbose := mustGetBoolFlag(cmd, "verbose")
	legacyPrint := mustGetBoolFlag(cmd, "legacy-print")

	// Load input findings.
	findings, err := report.LoadFindings(inputPath)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	// Build expr runtime and compile prefilter.
	rt, err := exprruntime.New(nil)
	if err != nil {
		return fmt.Errorf("creating expr runtime: %w", err)
	}
	if err = cfg.CompileFilters(nil); err != nil {
		return fmt.Errorf("compiling filters: %w", err)
	}

	// Load ignore file + baseline suppression.
	suppression, err := loadReplaySuppression(cmd, inputDir, redact)
	if err != nil {
		return err
	}

	// Run replay engine.
	results, err := report.Replay(findings, report.ReplayOptions{
		Config:      cfg,
		ExprRuntime: rt,
		FilterSet:   detect.NewFilterSet(cfg, rt),
		Suppression: suppression,
	})
	if err != nil {
		return err
	}

	// Verbose output (Print handles its own redaction on a value copy).
	if verbose {
		for _, f := range results {
			if legacyPrint {
				f.PrintLegacy(noColor, redact)
			} else {
				f.Print(noColor, redact)
			}
		}
	}

	// Permanently redact before writing the report.
	detect.RedactFindings(results, redact)

	// Write report file if requested.
	reporter, reportPath, err := buildReporter(cmd, cfg)
	if err != nil {
		return err
	}
	if reporter != nil {
		var out io.WriteCloser
		if reportPath == report.StdoutReportPath {
			out = os.Stdout
		} else {
			if out, err = os.Create(reportPath); err != nil {
				return fmt.Errorf("opening report path: %w", err)
			}
			defer func() { _ = out.Close() }()
		}
		if err = reporter.Write(out, results); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
	}

	// Summary and exit code (mirrors scan-command semantics).
	elapsed := time.Since(start)
	if len(results) == 0 {
		logging.Info().Msgf("no findings after replay (%s)", FormatDuration(elapsed))
	} else {
		logging.Warn().Msgf("%d finding(s) after replay (%s)", len(results), FormatDuration(elapsed))
		os.Exit(exitCode)
	}
	return nil
}

// loadReplaySuppression builds a Suppression from the standard ignore/baseline flags.
// inputDir is searched for ignore files in place of the scan source directory.
func loadReplaySuppression(cmd *cobra.Command, inputDir string, redact uint) (*detect.Suppression, error) {
	suppression := detect.NewSuppression()
	suppression.Redact = redact

	ignorePath, err := cmd.Flags().GetString("gitleaks-ignore-path")
	if err != nil {
		return nil, err
	}

	loadIgnoreFilesFrom(suppression.AddIgnoreFile, ignorePath, inputDir)

	baselinePath, _ := cmd.Flags().GetString("baseline-path")
	if baselinePath != "" {
		baseline, err := detect.LoadBaseline(baselinePath)
		if err != nil {
			logging.Warn().Err(err).Msg("could not load baseline")
		} else {
			suppression.Baseline = baseline
		}
	}

	return suppression, nil
}
