package cmd

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources/container"
)

func init() { rootCmd.AddCommand(newContainerCmd()) }

func newContainerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "container [image...] [flags]",
		Aliases: []string{"docker"},
		Short:   "scan container images, historical layers, and metadata for secrets",
		Example: `  betterleaks container ghcr.io/example/app:latest
  betterleaks container --daemon docker my-app:latest
  betterleaks container --daemon podman my-app:latest
  betterleaks container --archive image.tar --platform linux/amd64
  betterleaks container --oci-layout ./image-layout --report-path findings.json`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			_, err := containerSource(cmd, args)
			return err
		},
		Run: runContainer,
	}
	flags := cmd.Flags()
	flags.StringArray("archive", nil, "Docker save or OCI image archive (repeatable; compression detected automatically)")
	flags.StringArray("oci-layout", nil, "OCI image layout directory (repeatable)")
	flags.String("daemon", "", "export local images using docker or podman; requires an explicit runtime")
	flags.StringArray("platform", nil, "select os/architecture[/variant] (repeatable; default: all platforms)")
	flags.Bool("anonymous", false, "ignore Docker registry credentials and credential helpers")
	flags.Bool("plain-http", false, "use unencrypted HTTP for registry access")
	flags.String("max-file-size", "0", "maximum layer file size (e.g. 250MiB; 0 = unlimited); exceeding it makes the scan incomplete")
	flags.String("max-archive-size", "0", "maximum expanded outer archive size, including headers and padding (e.g. 20GiB; 0 = 20 GiB)")
	return cmd
}

func containerSize(cmd *cobra.Command, name string) (int64, error) {
	raw, err := cmd.Flags().GetString(name)
	if err != nil {
		return 0, err
	}
	size, err := humanize.ParseBytes(raw)
	if err != nil || size > math.MaxInt64 {
		return 0, fmt.Errorf("invalid --%s %q: expected a non-negative byte size such as 250MiB", name, raw)
	}
	return int64(size), nil
}

func containerSource(cmd *cobra.Command, args []string) (*container.Source, error) {
	maxFileSize, err := containerSize(cmd, "max-file-size")
	if err != nil {
		return nil, err
	}
	maxArchiveSize, err := containerSize(cmd, "max-archive-size")
	if err != nil {
		return nil, err
	}
	depth, err := cmd.Flags().GetInt("max-archive-depth")
	if err != nil {
		return nil, err
	}
	// Respect v1's shared file-size flag unless the container-specific one is set.
	if !cmd.Flags().Changed("max-file-size") {
		megabytes, err := cmd.Flags().GetInt("max-target-megabytes")
		if err != nil {
			return nil, err
		}
		if megabytes < 0 || int64(megabytes) > math.MaxInt64/1_000_000 {
			return nil, errors.New("invalid --max-target-megabytes")
		}
		maxFileSize = int64(megabytes) * 1_000_000
	}
	archives, _ := cmd.Flags().GetStringArray("archive")
	layouts, _ := cmd.Flags().GetStringArray("oci-layout")
	platforms, _ := cmd.Flags().GetStringArray("platform")
	daemon, _ := cmd.Flags().GetString("daemon")
	anonymous, _ := cmd.Flags().GetBool("anonymous")
	plainHTTP, _ := cmd.Flags().GetBool("plain-http")
	if cmd.Flags().Changed("daemon") && daemon == "" {
		return nil, errors.New("--daemon requires docker or podman")
	}
	src := &container.Source{Images: args, Archives: archives, Layouts: layouts, Platforms: platforms, Daemon: daemon, Anonymous: anonymous, PlainHTTP: plainHTTP, MaxFileSize: maxFileSize, MaxArchiveSize: maxArchiveSize, MaxArchiveDepth: depth}
	return src, src.Validate()
}

func runContainer(cmd *cobra.Command, args []string) {
	start := time.Now()
	src, err := containerSource(cmd, args)
	if err != nil {
		logging.Fatal().Err(err).Msg("invalid container configuration")
	}
	initConfig(".")
	initDiagnostics()
	detector := Detector(cmd, Config(cmd), ".")
	detector.SkipFindingAppend = true
	src.Logger, src.Prefilter = &logging.Logger, detector.SkipFunc()
	verbose := mustGetBoolFlag(cmd, "verbose")
	noColor := mustGetBoolFlag(cmd, "no-color")
	printFinding := func(finding report.Finding) {
		finding = containerFindingForDisplay(finding, detector.Redact)
		if detector.LegacyPrint {
			finding.PrintLegacy(noColor, detector.Redact)
		} else {
			finding.Print(noColor, detector.Redact)
		}
	}
	var findings []report.Finding
	var scanErrs []error
	for result := range detector.Run(cmd.Context(), src) {
		if result.Err != nil {
			scanErrs = append(scanErrs, result.Err)
			logging.Error().Err(result.Err).Msg("container scan error")
			continue
		}
		findings = append(findings, result.Finding)
		if verbose {
			printFinding(result.Finding)
		}
	}
	redactContainerFindings(findings, detector.Redact)

	if err := cmd.Context().Err(); err != nil {
		scanErrs = append(scanErrs, err)
	}
	var scanErr error
	if len(scanErrs) > 0 {
		scanErr = &multipleErrors{msg: fmt.Sprintf("%d error(s) during container scan", len(scanErrs)), errs: scanErrs}
	}
	findingSummaryAndExit(detector, findings, mustGetIntFlag(cmd, "exit-code"), start, scanErr)
}
