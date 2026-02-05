package cmd

import (
	"time"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/scan"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/fatih/semgroup"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(directoryCmd)
	directoryCmd.Flags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")
}

var directoryCmd = &cobra.Command{
	Use:     "dir [flags] [path]",
	Aliases: []string{"file", "directory"},
	Short:   "scan directories or files for secrets",
	Run:     runDirectory,
}

func runDirectory(cmd *cobra.Command, args []string) {
	// grab source
	source := "."
	if len(args) == 1 {
		source = args[0]
		if source == "" {
			source = "."
		}
	}

	initConfig(source)
	initDiagnostics()

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	followSymlinks := mustGetBoolFlag(cmd, "follow-symlinks")
	maxTargetMegaBytes := mustGetIntFlag(cmd, "max-target-megabytes")
	maxArchiveDepth := mustGetIntFlag(cmd, "max-archive-depth")

	src := &sources.Files{
		Config:          &cfg,
		FollowSymlinks:  followSymlinks,
		MaxFileSize:     maxTargetMegaBytes * 1_000_000,
		Path:            source,
		Sema:            semgroup.NewGroup(cmd.Context(), 10),
		MaxArchiveDepth: maxArchiveDepth,
	}

	scanner := scan.NewScanner(cmd.Context(), &cfg, 0, false, 10)

	// Load ignore files
	ignorePath := mustGetStringFlag(cmd, "gitleaks-ignore-path")
	if altPath := mustGetStringFlag(cmd, "betterleaks-ignore-path"); altPath != "" {
		ignorePath = altPath
	}
	scanner.SetIgnore(scan.LoadIgnoreFiles(ignorePath, source))

	p := scan.NewPipeline(cfg, src, *scanner)

	var findings []betterleaks.Finding
	noColor := mustGetBoolFlag(cmd, "no-color")
	start := time.Now()

	err := p.Run(cmd.Context(), func(finding betterleaks.Finding, err error) error {
		if err != nil {
			return err
		}
		scan.PrintFinding(finding, noColor)
		findings = append(findings, finding)
		return nil
	})

	findingSummary(cmd, cfg, findings, start, err)
}
