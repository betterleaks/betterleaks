package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func init() {
	rootCmd.AddCommand(s3Cmd)
	s3Cmd.Flags().String("region", "", "AWS region (required for some non-AWS endpoints; auto-probed for AWS)")
	s3Cmd.Flags().Bool("anonymous", false, "do not sign requests; ignore AWS_* env vars and --access-key/--secret-key")
	s3Cmd.Flags().String("access-key", "", "AWS access key (overrides AWS_ACCESS_KEY_ID)")
	s3Cmd.Flags().String("secret-key", "", "AWS secret key (overrides AWS_SECRET_ACCESS_KEY)")
	s3Cmd.Flags().String("session-token", "", "AWS session token (overrides AWS_SESSION_TOKEN)")
	s3Cmd.Flags().Int64("max-object-size", 0, "objects larger than this many bytes are skipped (0 = 250 MiB default)")
	s3Cmd.Flags().Int("workers", 0, "concurrent object fetches (0 = 16 default)")
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

	src := &sources.S3{
		URL:             args[0],
		Region:          mustGetStringFlag(cmd, "region"),
		Anonymous:       mustGetBoolFlag(cmd, "anonymous"),
		AccessKey:       mustGetStringFlag(cmd, "access-key"),
		SecretKey:       mustGetStringFlag(cmd, "secret-key"),
		SessionToken:    mustGetStringFlag(cmd, "session-token"),
		MaxObjectSize:   mustGetInt64Flag(cmd, "max-object-size"),
		Workers:         mustGetIntFlag(cmd, "workers"),
		ShouldSkip:      detector.SkipFunc(),
		MaxArchiveDepth: detector.MaxArchiveDepth,
	}

	if err := src.Validate(); err != nil {
		logging.Fatal().Err(err).Msg("invalid S3 configuration")
	}

	exitCode := mustGetIntFlag(cmd, "exit-code")
	noColor := mustGetBoolFlag(cmd, "no-color")
	redact := mustGetUIntFlag(cmd, "redact")
	verbose := mustGetBoolFlag(cmd, "verbose")

	detector.SkipFindingAppend = true
	var findings []report.Finding
	var scanErrs []error
	for result := range detector.Run(cmd.Context(), src) {
		if result.Err != nil {
			scanErrs = append(scanErrs, result.Err)
			logging.Error().Err(result.Err).Msg("scan error")
			continue
		}
		findings = append(findings, result.Finding)
		if verbose {
			if detector.LegacyPrint {
				result.Finding.PrintLegacy(noColor, redact)
			} else {
				result.Finding.Print(noColor, redact)
			}
		}
	}

	var scanErr error
	if n := len(scanErrs); n > 0 {
		scanErr = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) during S3 scan", n),
			errs: scanErrs,
		}
	}
	findingSummaryAndExit(detector, findings, exitCode, start, scanErr)
}
