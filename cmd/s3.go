package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
)

func init() {
	rootCmd.AddCommand(s3Cmd)
	s3Cmd.Flags().String("region", "", "AWS region (required for some non-AWS endpoints; auto-probed for AWS)")
	s3Cmd.Flags().Bool("anonymous", false, "do not sign requests; ignore AWS_* env vars and --access-key/--secret-key")
	s3Cmd.Flags().String("access-key", "", "AWS access key (overrides AWS_ACCESS_KEY_ID)")
	s3Cmd.Flags().String("secret-key", "", "AWS secret key (overrides AWS_SECRET_ACCESS_KEY)")
	s3Cmd.Flags().String("session-token", "", "AWS session token (overrides AWS_SESSION_TOKEN)")
	s3Cmd.Flags().String("max-object-size", "", "objects larger than this size are skipped (e.g. 250MiB, 1GB; 0 = 250 MiB default)")
	s3Cmd.Flags().Int("workers", 0, "concurrent object fetches (0 = --source-workers or source default)")
}

var s3Cmd = &cobra.Command{
	Use:   "s3 <url> [flags]",
	Short: "scan an S3 (or S3-compatible) bucket for secrets",
	Example: `  # Scan an AWS bucket
  betterleaks s3 https://my-bucket.s3.us-east-1.amazonaws.com/logs/

  # AWS shorthand (region auto-probed)
  betterleaks s3 s3://my-bucket/logs/

  # Enumerate and scan all buckets in the account
  # (requires s3:ListAllMyBuckets on the credentials)
  betterleaks s3 'https://s3.us-east-1.amazonaws.com/*'

  # Enumerate buckets matching a glob, scan a shared prefix in each
  # (same permission requirement as above)
  betterleaks s3 'https://s3.us-east-1.amazonaws.com/prod-*/logs/'

  # Scan a public bucket without credentials
  # (the bucket policy must grant anonymous s3:ListBucket, not just s3:GetObject)
  betterleaks s3 --anonymous https://<public-bucket>.s3.<region>.amazonaws.com/

  # Scan a single Cloudflare R2 bucket
  betterleaks s3 https://my-bucket.acct123.r2.cloudflarestorage.com/

  # Enumerate all R2 buckets in an account
  # (requires an admin-scoped R2 API token, not a bucket-scoped one)
  betterleaks s3 'https://acct123.r2.cloudflarestorage.com/*'

  # Scan a MinIO bucket
  betterleaks s3 --region=us-east-1 http://localhost:9000/mybucket`,
	Args: cobra.ExactArgs(1),
	Run:  runS3,
}

func runS3(cmd *cobra.Command, args []string) {
	start := time.Now()

	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)
	detector := Detector(cmd, cfg, ".")
	workers := mustGetIntFlag(cmd, "workers")
	if workers == 0 {
		workers = mustGetIntFlag(cmd, "source-workers")
	}

	src := &sources.S3{
		URL:             args[0],
		Region:          mustGetStringFlag(cmd, "region"),
		Anonymous:       mustGetBoolFlag(cmd, "anonymous"),
		AccessKey:       mustGetStringFlag(cmd, "access-key"),
		SecretKey:       mustGetStringFlag(cmd, "secret-key"),
		SessionToken:    mustGetStringFlag(cmd, "session-token"),
		MaxObjectSize:   mustGetSizeFlag(cmd, "max-object-size"),
		Workers:         workers,
		ShouldSkip:      detector.SkipFunc(),
		MaxArchiveDepth: mustGetIntFlag(cmd, "max-archive-depth"),
	}

	if err := src.Validate(); err != nil {
		logging.Fatal().Err(err).Msg("invalid S3 configuration")
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
			msg:  fmt.Sprintf("%d error(s) during S3 scan", n),
			errs: scanErrs,
		}
	}
	findingSummaryAndExit(cmd, detector, findings, exitCode, start, scanErr)
}
