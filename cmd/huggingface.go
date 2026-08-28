package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
)

func init() {
	rootCmd.AddCommand(huggingFaceCmd)
	huggingFaceCmd.Flags().String("token", "", "Hugging Face access token (or set HUGGINGFACE_TOKEN/HF_TOKEN)")
	huggingFaceCmd.Flags().StringSlice("include", nil, "resource types to scan: repos (default), discussions, prs, buckets")
	huggingFaceCmd.Flags().StringSlice("exclude", nil, "resource types to skip: repos, discussions, prs, buckets")
	huggingFaceCmd.Flags().StringSlice("exclude-repo", nil, "glob patterns to exclude repos by owner/name")
	huggingFaceCmd.Flags().String("log-opts", "", "git log options passed to each repo scan")
	huggingFaceCmd.Flags().String("max-bucket-object-size", "", "bucket objects larger than this size are skipped (e.g. 250MiB, 1GB; 0 = 250 MiB default)")
}

var huggingFaceCmd = &cobra.Command{
	Use:     "huggingface <target-url> [flags]",
	Aliases: []string{"hf"},
	Short:   "scan Hugging Face repositories and community resources for secrets",
	Example: `  # Scan a model's git history
  betterleaks huggingface https://huggingface.co/owner/model

  # Scan a dataset
  betterleaks huggingface https://huggingface.co/datasets/owner/dataset

  # Scan a Space
  betterleaks huggingface https://huggingface.co/spaces/owner/space

  # Enumerate and scan all models, datasets, and Spaces for an owner
  betterleaks huggingface https://huggingface.co/myorg

  # Also scan discussion and PR comments
  betterleaks huggingface --include=discussions,prs https://huggingface.co/owner/model

  # Scan a Hugging Face Storage Bucket
  betterleaks hf hf://buckets/owner/bucket/path

  # Include buckets when scanning an owner
  betterleaks hf --include=buckets https://huggingface.co/myorg`,
	Args: cobra.ExactArgs(1),
	Run:  runHuggingFace,
}

func runHuggingFace(cmd *cobra.Command, args []string) {
	start := time.Now()

	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)
	detector := Detector(cmd, cfg, ".")

	token := mustGetStringFlag(cmd, "token")
	if token == "" {
		token = os.Getenv("HUGGINGFACE_TOKEN")
	}
	if token == "" {
		token = os.Getenv("HF_TOKEN")
	}

	include, _ := cmd.Flags().GetStringSlice("include")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	excludeRepos, _ := cmd.Flags().GetStringSlice("exclude-repo")

	src := &sources.HuggingFace{
		Token:               token,
		URL:                 args[0],
		Include:             include,
		Exclude:             exclude,
		ExcludeRepos:        excludeRepos,
		ShouldSkip:          detector.SkipFunc(),
		MaxArchiveDepth:     mustGetIntFlag(cmd, "max-archive-depth"),
		Workers:             mustGetIntFlag(cmd, "source-workers"),
		LogOpts:             mustGetStringFlag(cmd, "log-opts"),
		MaxBucketObjectSize: mustGetSizeFlag(cmd, "max-bucket-object-size"),
	}

	if err := src.Validate(); err != nil {
		logging.Fatal().Err(err).Msg("invalid Hugging Face configuration")
	}

	exitCode := mustGetIntFlag(cmd, "exit-code")
	findings := newFindingCollector(mustGetStringFlag(cmd, "report-path") != "")

	var scanErrs []error
	for result := range detector.Run(cmd.Context(), src) {
		if result.Err != nil {
			scanErrs = append(scanErrs, result.Err)
			logging.Error().Err(result.Err).Msg("scan error")
			continue
		}
		collectFinding(cmd, findings, result.Finding)
	}

	var scanErr error
	if n := len(scanErrs); n > 0 {
		scanErr = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) during Hugging Face scan", n),
			errs: scanErrs,
		}
	}
	findingSummaryAndExit(cmd, detector, findings, exitCode, start, scanErr)
}
