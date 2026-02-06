package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks"
	config2 "github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/version"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const banner = `

  ○           
  ○           
  ●           
  ○  betterleaks v0.1.0 

`

const configDescription = `config file path
order of precedence:
1. --config/-c
2. env var GITLEAKS_CONFIG
3. env var GITLEAKS_CONFIG_TOML with the file content
4. (target path)/.gitleaks.toml
If none of the four options are used, then gitleaks will use the default config`

var (
	rootCmd = &cobra.Command{
		Use:     "gitleaks",
		Short:   "Gitleaks scans code, past or present, for secrets",
		Version: version.Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Set the timeout for all the commands
			if timeout, err := cmd.Flags().GetInt("timeout"); err != nil {
				return err
			} else if timeout > 0 {
				ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeout)*time.Second)
				cmd.SetContext(ctx)
				cobra.OnFinalize(cancel)
			}
			return nil
		},
	}

	// diagnostics manager is global to ensure it can be started before a scan begins
	// and stopped after a scan completes
	diagnosticsManager *DiagnosticsManager
)

const (
	BYTE     = 1.0
	KILOBYTE = BYTE * 1000
	MEGABYTE = KILOBYTE * 1000
	GIGABYTE = MEGABYTE * 1000
)

func init() {
	cobra.OnInitialize(initLog)
	rootCmd.PersistentFlags().StringP("config", "c", "", configDescription)
	rootCmd.PersistentFlags().Int("exit-code", 1, "exit code when leaks have been encountered")
	rootCmd.PersistentFlags().StringP("report-path", "r", "", "report file (use \"-\" for stdout)")
	rootCmd.PersistentFlags().StringP("report-format", "f", "", "output format (json, csv, junit, sarif, template)")
	rootCmd.PersistentFlags().StringP("report-template", "", "", "template file used to generate the report (implies --report-format=template)")
	rootCmd.PersistentFlags().StringP("baseline-path", "b", "", "path to baseline with issues that can be ignored")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (trace, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "show verbose output from scan")
	rootCmd.PersistentFlags().BoolP("no-color", "", false, "turn off color for verbose output")
	rootCmd.PersistentFlags().Int("max-target-megabytes", 0, "files larger than this will be skipped")
	rootCmd.PersistentFlags().BoolP("ignore-gitleaks-allow", "", false, "ignore gitleaks:allow comments")
	rootCmd.PersistentFlags().Uint("redact", 0, "redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%)")
	rootCmd.Flag("redact").NoOptDefVal = "100"
	rootCmd.PersistentFlags().Bool("no-banner", false, "suppress banner")
	rootCmd.PersistentFlags().StringSlice("enable-rule", []string{}, "only enable specific rules by id")
	rootCmd.PersistentFlags().StringP("gitleaks-ignore-path", "i", ".", "path to .gitleaksignore or .betterleaksignore file or folder containing one")
	rootCmd.PersistentFlags().StringP("betterleaks-ignore-path", "", "", "alias for --gitleaks-ignore-path")
	rootCmd.PersistentFlags().Int("max-decode-depth", 5, "allow recursive decoding up to this depth")
	rootCmd.PersistentFlags().Int("max-archive-depth", 0, "allow scanning into nested archives up to this depth (default \"0\", no archive traversal is done)")
	rootCmd.PersistentFlags().Int("timeout", 0, "set a timeout for gitleaks commands in seconds (default \"0\", no timeout is set)")
	rootCmd.PersistentFlags().Bool("legacy", false, "enable gitleaks-compatible output format for printing and reporting")

	// Add diagnostics flags
	rootCmd.PersistentFlags().String("diagnostics", "", "enable diagnostics (http OR comma-separated list: cpu,mem,trace). cpu=CPU prof, mem=memory prof, trace=exec tracing, http=serve via net/http/pprof")
	rootCmd.PersistentFlags().String("diagnostics-dir", "", "directory to store diagnostics output files when not using http mode (defaults to current directory)")

	err := viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	if err != nil {
		logging.Fatal().Msgf("err binding config %s", err.Error())
	}
}

var logLevel = zerolog.InfoLevel

func initLog() {
	ll, err := rootCmd.Flags().GetString("log-level")
	if err != nil {
		logging.Fatal().Msg(err.Error())
	}

	switch strings.ToLower(ll) {
	case "trace":
		logLevel = zerolog.TraceLevel
	case "debug":
		logLevel = zerolog.DebugLevel
	case "info":
		logLevel = zerolog.InfoLevel
	case "warn":
		logLevel = zerolog.WarnLevel
	case "err", "error":
		logLevel = zerolog.ErrorLevel
	case "fatal":
		logLevel = zerolog.FatalLevel
	default:
		logging.Warn().Msgf("unknown log level: %s", ll)
	}
	logging.Logger = logging.Logger.Level(logLevel)
}

func initConfig(source string) {
	hideBanner, err := rootCmd.Flags().GetBool("no-banner")
	viper.SetConfigType("toml")

	if err != nil {
		logging.Fatal().Msg(err.Error())
	}
	if !hideBanner {
		_, _ = fmt.Fprint(os.Stderr, banner)
	}

	logging.Debug().Msgf("using %s regex engine", regexp.Version)

	cfgPath, err := rootCmd.Flags().GetString("config")
	if err != nil {
		logging.Fatal().Msg(err.Error())
	}
	if cfgPath != "" {
		viper.SetConfigFile(cfgPath)
		logging.Debug().Msgf("using gitleaks config %s from `--config`", cfgPath)
	} else if os.Getenv("GITLEAKS_CONFIG") != "" {
		envPath := os.Getenv("GITLEAKS_CONFIG")
		viper.SetConfigFile(envPath)
		logging.Debug().Msgf("using gitleaks config from GITLEAKS_CONFIG env var: %s", envPath)
	} else if os.Getenv("GITLEAKS_CONFIG_TOML") != "" {
		configContent := []byte(os.Getenv("GITLEAKS_CONFIG_TOML"))
		if err := viper.ReadConfig(bytes.NewBuffer(configContent)); err != nil {
			logging.Fatal().Err(err).Str("content", os.Getenv("GITLEAKS_CONFIG_TOML")).Msg("unable to load gitleaks config from GITLEAKS_CONFIG_TOML env var")
		}
		logging.Debug().Str("content", os.Getenv("GITLEAKS_CONFIG_TOML")).Msg("using gitleaks config from GITLEAKS_CONFIG_TOML env var content")
		return
	} else {
		fileInfo, err := os.Stat(source)
		if err != nil {
			logging.Fatal().Msg(err.Error())
		}

		if !fileInfo.IsDir() {
			logging.Debug().Msgf("unable to load gitleaks config from %s since --source=%s is a file, using default config",
				filepath.Join(source, ".gitleaks.toml"), source)
			if err = viper.ReadConfig(strings.NewReader(config2.DefaultConfig)); err != nil {
				logging.Fatal().Msgf("err reading toml %s", err.Error())
			}
			return
		}

		if _, err := os.Stat(filepath.Join(source, ".gitleaks.toml")); os.IsNotExist(err) {
			logging.Debug().Msgf("no gitleaks config found in path %s, using default gitleaks config", filepath.Join(source, ".gitleaks.toml"))

			if err = viper.ReadConfig(strings.NewReader(config2.DefaultConfig)); err != nil {
				logging.Fatal().Msgf("err reading default config toml %s", err.Error())
			}
			return
		} else {
			logging.Debug().Msgf("using existing gitleaks config %s from `(--source)/.gitleaks.toml`", filepath.Join(source, ".gitleaks.toml"))
		}

		viper.AddConfigPath(source)
		viper.SetConfigName(".gitleaks")
	}
	if err := viper.ReadInConfig(); err != nil {
		logging.Fatal().Msgf("unable to load gitleaks config, err: %s", err)
	}
}

func initDiagnostics() {
	// Initialize diagnostics manager
	diagnosticsFlag, err := rootCmd.PersistentFlags().GetString("diagnostics")
	if err != nil {
		logging.Fatal().Err(err).Msg("Error getting diagnostics flag")
	}

	diagnosticsDir, err := rootCmd.PersistentFlags().GetString("diagnostics-dir")
	if err != nil {
		logging.Fatal().Err(err).Msg("Error getting diagnostics-dir flag")
	}

	var diagErr error
	diagnosticsManager, diagErr = NewDiagnosticsManager(diagnosticsFlag, diagnosticsDir)
	if diagErr != nil {
		logging.Fatal().Err(diagErr).Msg("Error initializing diagnostics")
	}

	if diagnosticsManager.Enabled {
		logging.Info().Msg("Starting diagnostics...")
		if diagErr := diagnosticsManager.StartDiagnostics(); diagErr != nil {
			logging.Fatal().Err(diagErr).Msg("Failed to start diagnostics")
		}
	}

}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if strings.Contains(err.Error(), "unknown flag") {
			// exit code 126: Command invoked cannot execute
			os.Exit(126)
		}
		logging.Fatal().Msg(err.Error())
	}
}

func Config(cmd *cobra.Command) config2.Config {
	var vc config2.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		logging.Fatal().Err(err).Msg("Failed to load config")
	}

	// Tell the config which gitleaks version this interface intends to emulate
	vc.SetCurrentVersion(version.Version)

	cfg, err := vc.Translate()
	if err != nil {
		logging.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg.Path, _ = cmd.Flags().GetString("config")

	return cfg
}

func bytesConvert(bytes uint64) string {
	unit := ""
	value := float32(bytes)

	switch {
	case bytes >= GIGABYTE:
		unit = "GB"
		value = value / GIGABYTE
	case bytes >= MEGABYTE:
		unit = "MB"
		value = value / MEGABYTE
	case bytes >= KILOBYTE:
		unit = "KB"
		value = value / KILOBYTE
	case bytes >= BYTE:
		unit = "bytes"
	case bytes == 0:
		return "0"
	}

	stringValue := strings.TrimSuffix(
		fmt.Sprintf("%.2f", value), ".00",
	)

	return fmt.Sprintf("%s %s", stringValue, unit)
}

func fileExists(fileName string) bool {
	// check for a .gitleaksignore file
	info, err := os.Stat(fileName)
	if err != nil && !os.IsNotExist(err) {
		return false
	}

	if info != nil && err == nil {
		if !info.IsDir() {
			return true
		}
	}
	return false
}

func FormatDuration(d time.Duration) string {
	scale := 100 * time.Second
	// look for the max scale that is smaller than d
	for scale > d {
		scale = scale / 10
	}
	return d.Round(scale / 100).String()
}

func mustGetBoolFlag(cmd *cobra.Command, name string) bool {
	value, err := cmd.Flags().GetBool(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	return value
}

func mustGetIntFlag(cmd *cobra.Command, name string) int {
	value, err := cmd.Flags().GetInt(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	return value
}

func mustGetStringFlag(cmd *cobra.Command, name string) string {
	value, err := cmd.Flags().GetString(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	return value
}

// getReporter creates a Reporter based on command flags.
// Returns nil if no report is requested.
func getReporter(cmd *cobra.Command, cfg config2.Config) betterleaks.Reporter {
	reportPath := mustGetStringFlag(cmd, "report-path")
	if reportPath == "" {
		return nil
	}

	reportFormat := mustGetStringFlag(cmd, "report-format")
	reportTemplate := mustGetStringFlag(cmd, "report-template")
	legacy := mustGetBoolFlag(cmd, "legacy")

	// Template flag implies template format
	if reportTemplate != "" {
		reportFormat = "template"
	}

	// Infer format from file extension if not specified
	if reportFormat == "" && reportPath != betterleaks.StdoutReportPath {
		ext := strings.ToLower(filepath.Ext(reportPath))
		switch ext {
		case ".json":
			reportFormat = "json"
		case ".csv":
			reportFormat = "csv"
		case ".xml":
			reportFormat = "junit"
		case ".sarif":
			reportFormat = "sarif"
		default:
			reportFormat = "json"
		}
	}

	switch reportFormat {
	case "json", "":
		// Legacy: gitleaks-compatible JSON with flattened metadata fields.
		if legacy {
			return &report.LegacyJsonReporter{}
		}
		return &report.JsonReporter{}
	case "csv":
		// Legacy: gitleaks-compatible CSV with fixed columns.
		if legacy {
			return &report.LegacyCsvReporter{}
		}
		return &report.CsvReporter{}
	case "junit":
		// Legacy: gitleaks-compatible JUnit with "gitleaks" test suite name.
		if legacy {
			return &report.LegacyJunitReporter{}
		}
		return &report.JunitReporter{}
	case "sarif":
		// Legacy: gitleaks-compatible SARIF with gitleaks branding.
		if legacy {
			return &report.LegacySarifReporter{OrderedRules: cfg.GetOrderedRules()}
		}
		return &report.SarifReporter{OrderedRules: cfg.GetOrderedRules()}
	case "template":
		if reportTemplate == "" {
			logging.Fatal().Msg("--report-template is required when using --report-format=template")
		}
		r, err := report.NewTemplateReporter(reportTemplate)
		if err != nil {
			logging.Fatal().Err(err).Msg("could not create template reporter")
		}
		return r
	default:
		logging.Fatal().Msgf("unknown report format: %s", reportFormat)
		return nil
	}
}

// writeReport writes findings to the report file if a reporter is configured.
func writeReport(reporter betterleaks.Reporter, reportPath string, findings []betterleaks.Finding) error {
	if reporter == nil {
		return nil
	}

	var file io.WriteCloser
	var err error

	if reportPath == betterleaks.StdoutReportPath {
		file = os.Stdout
	} else {
		file, err = os.Create(reportPath)
		if err != nil {
			return fmt.Errorf("could not create report file: %w", err)
		}
		defer file.Close()
	}

	return reporter.Write(file, findings)
}

// findingSummary logs a summary of the scan results and writes the report.
func findingSummary(cmd *cobra.Command, cfg config2.Config, findings []betterleaks.Finding, start time.Time, scanErr error) {
	exitCode := mustGetIntFlag(cmd, "exit-code")
	reportPath := mustGetStringFlag(cmd, "report-path")
	reporter := getReporter(cmd, cfg)

	if scanErr == nil {
		logging.Info().Msgf("scan completed in %s", FormatDuration(time.Since(start)))
		if len(findings) != 0 {
			logging.Warn().Msgf("leaks found: %d", len(findings))
		} else {
			logging.Info().Msg("no leaks found")
		}
	} else {
		logging.Warn().Msgf("partial scan completed in %s", FormatDuration(time.Since(start)))
		if len(findings) != 0 {
			logging.Warn().Msgf("%d leaks found in partial scan", len(findings))
		} else {
			logging.Warn().Msg("no leaks found in partial scan")
		}
	}

	// Write report if configured
	if err := writeReport(reporter, reportPath, findings); err != nil {
		logging.Fatal().Err(err).Msg("failed to write report")
	}

	if scanErr != nil {
		os.Exit(1)
	}

	if len(findings) != 0 {
		os.Exit(exitCode)
	}
}
