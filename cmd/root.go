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
			if _, err := confidenceFlag(cmd); err != nil {
				return err
			}
			if workers, err := cmd.Flags().GetInt("source-workers"); err != nil {
				return err
			} else if workers < 0 {
				return fmt.Errorf("--source-workers must be non-negative")
			}
			if workers, err := cmd.Flags().GetInt("detect-workers"); err != nil {
				return err
			} else if workers < 0 {
				return fmt.Errorf("--detect-workers must be non-negative")
			}
			if cmd.Flags().Lookup("git-workers") != nil {
				if workers, err := cmd.Flags().GetInt("git-workers"); err != nil {
					return err
				} else if workers < 0 {
					return fmt.Errorf("--git-workers must be non-negative")
				}
			}
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
	rootCmd.PersistentFlags().StringP("report-format", "f", "", "output format (json, csv, junit, sarif, template; validate supports pretty or jsonl)")
	// rootCmd.PersistentFlags().StringP("report-template", "", "", "template file used to generate the report (implies --report-format=template)")
	// rootCmd.PersistentFlags().StringP("baseline-path", "b", "", "path to baseline with issues that can be ignored")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (trace, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().String("confidence", "", "minimum confidence to include (low, medium, high)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "show verbose output from scan")
	// rootCmd.PersistentFlags().Bool("legacy-print", false, "use legacy key/value verbose finding format (requires --verbose)")
	rootCmd.PersistentFlags().BoolP("no-color", "", false, "turn off color in terminal output")
	rootCmd.PersistentFlags().Int("max-target-megabytes", 0, "files larger than this will be skipped")
	rootCmd.PersistentFlags().Int("source-workers", 0, "number of concurrent source workers (0 = source default)")
	rootCmd.PersistentFlags().Int("detect-workers", 0, "number of concurrent detection workers (0 = GOMAXPROCS)")
	rootCmd.PersistentFlags().BoolP("ignore-betterleaks-allow", "", false, "ignore betterleaks:allow comments")
	rootCmd.PersistentFlags().Uint("redact", 0, "redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%)")
	rootCmd.Flag("redact").NoOptDefVal = "100"
	rootCmd.PersistentFlags().Bool("no-banner", false, "suppress banner")
	rootCmd.PersistentFlags().StringSlice("disable-rule", nil, "disable specific rules by id (repeatable; shorthand: -dr)")
	rootCmd.PersistentFlags().StringSlice("isolate-rule", nil, "only enable specific rules by id (repeatable; shorthand: -ir)")
	rootCmd.PersistentFlags().String("match-context", "", "context around match (this gets reported): L (lines), C (columns/characters). e.g. 10L, 100C, -2C,+4C")
	rootCmd.PersistentFlags().Int("max-decode-depth", 5, "allow recursive decoding up to this depth")
	rootCmd.PersistentFlags().Int("max-archive-depth", 8, "allow scanning into nested archives up to this depth")
	rootCmd.PersistentFlags().Int("timeout", 0, "set a timeout for betterleaks scan in seconds (default \"0\", no timeout is set)")
	rootCmd.PersistentFlags().String("regex-engine", "re2", "regex engine (stdlib, re2)")
	rootCmd.PersistentFlags().String("regexp-engine", "re2", "regex engine (stdlib, re2)")
	_ = rootCmd.PersistentFlags().MarkHidden("regexp-engine")

	// Validation flags
	rootCmd.PersistentFlags().Bool("validation", false, "enable validation of findings against live APIs")
	rootCmd.PersistentFlags().String("validation-status", "", "comma-separated list of validation statuses to include: valid, needs_validation, invalid, revoked, error, unknown, none (none = rules without validation)")
	rootCmd.PersistentFlags().Duration("validation-timeout", 10*time.Second, "per-request timeout for validation")
	rootCmd.PersistentFlags().Int("validation-workers", 10, "number of concurrent validation workers")
	rootCmd.PersistentFlags().Int("validation-max-requests", 0, "maximum validation requests sent to each provider target (0 = unlimited)")
	rootCmd.PersistentFlags().Int("validation-max-request", 0, "alias for --validation-max-requests")
	_ = rootCmd.PersistentFlags().MarkHidden("validation-max-request")
	rootCmd.PersistentFlags().Float64("validation-rps", 0, "global validation requests per second (0 = unlimited)")
	rootCmd.PersistentFlags().StringSlice("validation-rps-rule", nil, "rule-specific validation request rate as RULE=RPS (repeatable)")
	rootCmd.PersistentFlags().Bool("validation-extract-empty", false, "include empty values from extractors in output")
	rootCmd.PersistentFlags().Bool("validation-debug", false, "include validation HTTP debug metadata in output")
	rootCmd.PersistentFlags().StringSlice("validation-env-vars", nil, "comma-separated env var names the validation env.get(...) binding may read (repeat flag to add more); unset means env access is disabled")

	// Add diagnostics flags
	rootCmd.PersistentFlags().String("diagnostics", "", "enable diagnostics (http OR comma-separated list: cpu,mem,trace,rules,rules-csv). cpu=CPU prof, mem=memory prof, trace=exec tracing, rules=rule timings text, rules-csv=rule timings CSV, http=serve via net/http/pprof")
	rootCmd.PersistentFlags().String("diagnostics-dir", "", "directory to store diagnostics output files when not using http mode (defaults to ./diagnostics)")

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

	var engineName string
	if rootCmd.Flags().Changed("regex-engine") {
		engineName, _ = rootCmd.Flags().GetString("regex-engine")
	} else if rootCmd.Flags().Changed("regexp-engine") {
		engineName, _ = rootCmd.Flags().GetString("regexp-engine")
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

func initConfig(source string) {
	resolvedConfigPath = "" // reset for each call (cmd/directory.go calls per-source)
	loadedConfig = nil
	hideBanner, err := rootCmd.Flags().GetBool("no-banner")

	if err != nil {
		logging.Fatal().Msg(err.Error())
	}
	if !hideBanner && !bannerPrinted {
		_, _ = fmt.Fprint(os.Stderr, banner)
		bannerPrinted = true
	}

	logging.Debug().Msgf("using %s regex engine", regexp.Version())

	cfgPath, err := rootCmd.Flags().GetString("config")
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
	// pflag only supports single-character shorthands. Expand the requested
	// multi-character aliases before Cobra parses the command line.
	rootCmd.SetArgs(expandRuleFlagShorthands(os.Args[1:]))
	if err := rootCmd.Execute(); err != nil {
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

func collectFinding(cmd *cobra.Command, findings *findingCollector, finding report.Finding) {
	findings.Add(finding)
	if !mustGetBoolFlag(cmd, "verbose") {
		return
	}
	noColor := mustGetBoolFlag(cmd, "no-color")
	redact := mustGetUIntFlag(cmd, "redact")
	finding.Print(noColor, redact)
}

func findingSummaryAndExit(cmd *cobra.Command, detector *detect.Detector, findings *findingCollector, exitCode int, start time.Time, err error) {
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
