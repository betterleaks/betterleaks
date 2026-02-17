package cmd

import (
	"os"
	"time"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/scan"
	"github.com/betterleaks/betterleaks/sources/file"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(stdInCmd)
}

var stdInCmd = &cobra.Command{
	Use:   "stdin",
	Short: "detect secrets from stdin",
	Run:   runStdIn,
}

func runStdIn(cmd *cobra.Command, _ []string) {
	// setup config (aka, the thing that defines rules)
	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)

	// parse flags
	noColor := mustGetBoolFlag(cmd, "no-color")
	maxArchiveDepth := mustGetIntFlag(cmd, "max-archive-depth")

	// create a File source that reads from stdin
	src := &file.File{
		Content:         os.Stdin,
		Path:            "stdin",
		Config:          &cfg,
		Source:          "stdin",
		MaxArchiveDepth: maxArchiveDepth,
	}

	// create scanner
	scanner := scan.NewScanner(cmd.Context(), &cfg, 0, false, 10)

	// load ignore files
	ignorePath := mustGetStringFlag(cmd, "gitleaks-ignore-path")
	if altPath := mustGetStringFlag(cmd, "betterleaks-ignore-path"); altPath != "" {
		ignorePath = altPath
	}
	scanner.SetIgnore(scan.LoadIgnoreFiles(ignorePath, "."))

	// create pipeline
	p := scan.NewPipeline(cfg, src, *scanner)

	// run pipeline and collect findings
	var findings []betterleaks.Finding
	legacy := mustGetBoolFlag(cmd, "legacy")
	start := time.Now()

	err := p.Run(cmd.Context(), func(finding betterleaks.Finding, err error) error {
		if err != nil {
			return err
		}
		// Legacy: use gitleaks-compatible print format.
		if legacy {
			scan.LegacyPrintFinding(finding, noColor)
		} else {
			scan.PrintFinding(finding, noColor)
		}
		findings = append(findings, finding)
		return nil
	})

	findingSummary(cmd, cfg, findings, start, err, p.TotalBytes())
}
