package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/internal/confidence"
	"github.com/betterleaks/betterleaks/internal/contextwindow"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/regexp"
	regexpre2 "github.com/betterleaks/betterleaks/regexp/re2"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/version"
)

var banner = fmt.Sprintf(`
 + ○
   ▾
 betterleaks %s

`, version.Version)

func confidenceFlag(cmd *cobra.Command) (string, error) {
	return confidence.Parse(mustGetStringFlag(cmd, "confidence"))
}

const configDescription = `config file path
order of precedence:
1. --config/-c
2. env var BETTERLEAKS_CONFIG or GITLEAKS_CONFIG
3. env var BETTERLEAKS_CONFIG_TOML or GITLEAKS_CONFIG_TOML with the file content
4. (target path)/.betterleaks.toml or .gitleaks.toml
If none of the four options are used, then the default config will be used`

var (
	rootCmd = &cobra.Command{
		Use:     "betterleaks",
		Short:   "Betterleaks scans code, past or present, for secrets",
		Version: version.Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Lookup("confidence") != nil {
				if _, err := confidenceFlag(cmd); err != nil {
					return err
				}
			}
			if cmd.Flags().Lookup("source-workers") != nil {
				if workers, err := cmd.Flags().GetInt("source-workers"); err != nil {
					return err
				} else if workers < 0 {
					return fmt.Errorf("--source-workers must be non-negative")
				}
			}
			if cmd.Flags().Lookup("detect-workers") != nil {
				if workers, err := cmd.Flags().GetInt("detect-workers"); err != nil {
					return err
				} else if workers < 0 {
					return fmt.Errorf("--detect-workers must be non-negative")
				}
			}
			if cmd.Flags().Lookup("git-workers") != nil {
				if workers, err := cmd.Flags().GetInt("git-workers"); err != nil {
					return err
				} else if workers < 0 {
					return fmt.Errorf("--git-workers must be non-negative")
				}
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
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (trace, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().BoolP("no-color", "", false, "turn off color in terminal output")
	rootCmd.PersistentFlags().String("regex-engine", "re2", "regex engine (stdlib, re2)")
	rootCmd.PersistentFlags().String("regexp-engine", "re2", "regex engine (stdlib, re2)")
	_ = rootCmd.PersistentFlags().MarkHidden("regexp-engine")
}

var logLevel = zerolog.InfoLevel

func initLog() {
	ll, err := rootCmd.PersistentFlags().GetString("log-level")
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

	var engineName string
	if rootCmd.PersistentFlags().Changed("regex-engine") {
		engineName, _ = rootCmd.PersistentFlags().GetString("regex-engine")
	} else if rootCmd.PersistentFlags().Changed("regexp-engine") {
		engineName, _ = rootCmd.PersistentFlags().GetString("regexp-engine")
	}
	switch engineName {
	case "", "re2":
		regexp.SetEngine(regexpre2.RE2{})
	case "stdlib":
		regexp.SetEngine(regexp.Stdlib{})
	default:
		logging.Fatal().Msgf("unknown regex engine %q (valid values: re2, stdlib)", engineName)
	}
}

var (
	bannerPrinted      bool
	resolvedConfigPath string // set by initConfig to the actual config file path that was loaded
	loadedConfig       *config.Config
)

func initConfig(cmd *cobra.Command, source string) {
	resolvedConfigPath = "" // reset for each call (cmd/directory.go calls per-source)
	loadedConfig = nil
	hideBanner, err := cmd.Flags().GetBool("no-banner")
	if err != nil {
		logging.Fatal().Msg(err.Error())
	}
	silent, err := cmd.Flags().GetBool("silent")
	if err != nil {
		logging.Fatal().Msg(err.Error())
	}
	hideBanner = hideBanner || silent
	if !hideBanner && !bannerPrinted {
		_, _ = fmt.Fprint(os.Stderr, banner)
		bannerPrinted = true
	}

	logging.Debug().Msgf("using %s regex engine", regexp.Version())

	cfgPath, err := cmd.Flags().GetString("config")
	if err != nil {
		logging.Fatal().Msg(err.Error())
	}
	if cfgPath != "" {
		resolvedConfigPath = cfgPath
		logging.Debug().Msgf("using config %s from `--config`", cfgPath)
		loadedConfig = mustLoadConfigFile(cfgPath)
	} else if envPath := getEnvWithFallback("BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG"); envPath != "" {
		resolvedConfigPath = envPath
		logging.Debug().Msgf("using config from env var: %s", envPath)
		loadedConfig = mustLoadConfigFile(envPath)
	} else if configContent := getEnvWithFallback("BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML"); configContent != "" {
		cfg, err := config.ParseTOMLString(configContent, "")
		if err != nil {
			logging.Fatal().Err(err).Str("content", configContent).Msg("unable to load config from env var")
		}
		logging.Debug().Str("content", configContent).Msg("using config from env var content")
		// resolvedConfigPath stays "" — inline content, no file to skip.
		loadedConfig = cfg
		return
	} else {
		fileInfo, err := os.Stat(source)
		if err != nil {
			logging.Fatal().Msg(err.Error())
		}

		if !fileInfo.IsDir() {
			logging.Debug().Msgf("unable to load config from %s since --source=%s is a file, using default config",
				filepath.Join(source, ".betterleaks.toml"), source)
			loadedConfig, err = config.Default()
			if err != nil {
				logging.Fatal().Msgf("err reading toml %s", err.Error())
			}
			// resolvedConfigPath stays "" — using embedded default config.
			return
		}

		// Check for config file: .betterleaks.toml first, then .gitleaks.toml
		configFile := findConfigFile(source)
		if configFile == "" {
			logging.Debug().Msgf("no config found in path %s, using default config", source)

			loadedConfig, err = config.Default()
			if err != nil {
				logging.Fatal().Msgf("err reading default config toml %s", err.Error())
			}
			// resolvedConfigPath stays "" — using embedded default config.
			return
		} else {
			resolvedConfigPath = configFile
			logging.Debug().Msgf("using existing config %s", configFile)
		}

		loadedConfig = mustLoadConfigFile(configFile)
	}
}

func mustLoadConfigFile(path string) *config.Config {
	cfg, err := config.LoadFile(path)
	if err != nil {
		logging.Fatal().Msgf("unable to load config, err: %s", err)
	}
	return cfg
}

// getEnvWithFallback returns the value of the first environment variable that is set.
// This allows betterleaks env vars to take precedence over gitleaks env vars.
func getEnvWithFallback(primary, fallback string) string {
	if val := os.Getenv(primary); val != "" {
		return val
	}
	return os.Getenv(fallback)
}

// findConfigFile looks for a config file in the given directory.
// It checks for .betterleaks.toml first, then .gitleaks.toml for backwards compatibility.
func findConfigFile(source string) string {
	for _, name := range []string{".betterleaks.toml", ".gitleaks.toml"} {
		path := filepath.Join(source, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func initDiagnostics(cmd *cobra.Command) {
	// Initialize diagnostics manager
	diagnosticsFlag, err := cmd.Flags().GetString("diagnostics")
	if err != nil {
		logging.Fatal().Err(err).Msg("Error getting diagnostics flag")
	}

	diagnosticsDir, err := cmd.Flags().GetString("diagnostics-dir")
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
	ExecuteContext(context.Background())
}

func ExecuteContext(ctx context.Context) {
	// pflag only supports single-character shorthands. Expand the requested
	// multi-character aliases before Cobra parses the command line.
	rootCmd.SetArgs(expandRuleFlagShorthands(os.Args[1:]))
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		if strings.Contains(err.Error(), "unknown flag") {
			// exit code 126: Command invoked cannot execute
			os.Exit(126)
		}
		logging.Fatal().Msg(err.Error())
	}
}

func Config(cmd *cobra.Command) *config.Config {
	if loadedConfig == nil {
		logging.Fatal().Msg("Failed to load config")
	}
	cfg := *loadedConfig
	cfg.Path = resolvedConfigPath

	return &cfg
}

func Detector(cmd *cobra.Command, cfg *config.Config, source string) *detect.Detector {
	var err error

	// Apply rule overrides BEFORE constructing the detector so that
	// NewDetectorContext compiles expression filters for the final rule set.
	if err := applyRuleSelection(cmd, cfg); err != nil {
		logging.Fatal().Err(err).Msg("unable to apply rule selection")
	}

	// Setup common detector. NewDetectorContext compiles all expression programs
	// and sets up the validation pool, so the cfg must be fully prepared.
	validationEnvVars, err := cmd.Flags().GetStringSlice("validation-env-vars")
	if err != nil {
		logging.Fatal().Err(err).Msg("validation-env-vars flag")
	}
	validationMaxRequests, err := getValidationMaxRequests(cmd)
	if err != nil {
		logging.Fatal().Err(err).Msg("validation maximum requests")
	}
	validationRPS := mustGetFloat64Flag(cmd, "validation-rps")
	if err := validateValidationRPS(validationRPS); err != nil {
		logging.Fatal().Err(err).Msg("validation-rps")
	}
	validationRPSRuleValues, err := cmd.Flags().GetStringSlice("validation-rps-rule")
	if err != nil {
		logging.Fatal().Err(err).Msg("validation-rps-rule flag")
	}
	validationRPSByRule, err := parseValidationRuleRPS(validationRPSRuleValues)
	if err != nil {
		logging.Fatal().Err(err).Msg("validation-rps-rule")
	}
	valOpts := detect.ValidationOptions{
		Enabled:                 mustGetBoolFlag(cmd, "validation"),
		Debug:                   mustGetBoolFlag(cmd, "validation-debug"),
		Workers:                 mustGetIntFlag(cmd, "validation-workers"),
		ExtractEmpty:            mustGetBoolFlag(cmd, "validation-extract-empty"),
		StatusFilter:            mustGetStringFlag(cmd, "validation-status"),
		MaxRequestsPerTarget:    validationMaxRequests,
		RequestsPerSecond:       validationRPS,
		RequestsPerSecondByRule: validationRPSByRule,
		ValidationEnvVars:       validationEnvVars,
	}
	valOpts.Timeout, _ = cmd.Flags().GetDuration("validation-timeout")

	detector := detect.NewDetectorContext(cmd.Context(), cfg, valOpts)
	detector.DetectWorkers = mustGetIntFlag(cmd, "detect-workers")
	detector.MinConfidence, err = confidenceFlag(cmd)
	if err != nil {
		logging.Fatal().Err(err).Send()
	}
	if diagnosticsManager != nil && diagnosticsManager.RuleTimings != nil {
		detector.RuleTimings = diagnosticsManager.RuleTimings
	}

	if detector.MaxDecodeDepth, err = cmd.Flags().GetInt("max-decode-depth"); err != nil {
		logging.Fatal().Err(err).Send()
	}

	// set color flag at first
	noColor, err := cmd.Flags().GetBool("no-color")
	if err != nil {
		logging.Fatal().Err(err).Send()
	}
	// also init logger again without color
	if noColor {
		logging.Logger = log.Output(zerolog.ConsoleWriter{
			Out:     os.Stderr,
			NoColor: noColor,
		}).Level(logLevel)
	}

	matchContextStr, err := cmd.Flags().GetString("match-context")
	if err != nil {
		logging.Fatal().Err(err).Send()
	}
	if matchContextStr != "" {
		detector.MatchContext, err = contextwindow.Parse(matchContextStr)
		if err != nil {
			logging.Fatal().Err(err).Msg("invalid --match-context value")
		}
	}

	return detector
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

func collectFinding(findings *findingCollector, finding report.Finding) {
	if err := findings.Add(finding); err != nil {
		logging.Fatal().Err(err).Msg("failed to write finding")
	}
}

func findingSummaryAndExit(cmd *cobra.Command, detector *detect.Detector, findings *findingCollector, exitCode int, start time.Time, err error) {
	// Finalize streaming reports first. In particular, JSON needs its closing
	// bracket even when the command context was canceled by an interrupt.
	if outputErr := findings.Close(); outputErr != nil {
		logging.Fatal().Err(outputErr).Msg("failed to finish finding output")
	}
	if err == nil {
		err = cmd.Context().Err()
	}

	if diagnosticsManager.Enabled {
		logging.Debug().Msg("Finalizing diagnostics...")
		diagnosticsManager.StopDiagnostics()
	}

	if detector.ValidationPool != nil {
		logging.Info().
			Int("valid", detector.ValidationCounts["valid"]).
			Int("needs_validation", detector.ValidationCounts["needs_validation"]).
			Int("invalid", detector.ValidationCounts["invalid"]).
			Int("revoked", detector.ValidationCounts["revoked"]).
			Int("unknown", detector.ValidationCounts["unknown"]).
			Int("errors", detector.ValidationCounts["error"]).
			Msg("validation complete")
	}

	totalBytes := detector.TotalBytes.Load()
	bytesMsg := fmt.Sprintf("scanned ~%d bytes (%s)", totalBytes, bytesConvert(totalBytes))
	if err == nil {
		logging.Info().Msgf("%s in %s", bytesMsg, FormatDuration(time.Since(start)))
		if findings.Count() != 0 {
			logging.Warn().Msgf("leaks found: %d", findings.Count())
		} else {
			logging.Info().Msg("no leaks found")
		}
	} else {
		logging.Warn().Msg(bytesMsg)
		logging.Warn().Msgf("partial scan completed in %s", FormatDuration(time.Since(start)))
		if findings.Count() != 0 {
			logging.Warn().Msgf("%d leaks found in partial scan", findings.Count())
		} else {
			logging.Warn().Msg("no leaks found in partial scan")
		}
	}

	if err != nil {
		os.Exit(1)
	}

	if findings.Count() != 0 {
		os.Exit(exitCode)
	}
}

func FormatDuration(d time.Duration) string {
	scale := 100 * time.Second
	// look for the max scale that is smaller than d
	for scale > d {
		scale = scale / 10
	}
	return d.Round(scale / 100).String()
}
