package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/internal/fingerprint"
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

const configDescription = `config file path
order of precedence:
1. --config/-c
2. env var BETTERLEAKS_CONFIG or GITLEAKS_CONFIG
3. env var BETTERLEAKS_CONFIG_TOML or GITLEAKS_CONFIG_TOML with the file content
4. (target path)/.betterleaks.toml or .gitleaks.toml
If none of the four options are used, then the default config will be used.`

type GlobalFlags struct {
	Config       string      `short:"c" help:"${config_help}"`
	LogLevel     string      `name:"log-level" short:"l" default:"info" help:"Log level: trace, debug, info, warn, error, fatal."`
	NoColor      bool        `name:"no-color" help:"Turn off color in terminal output."`
	RegexEngine  string      `name:"regex-engine" default:"re2" help:"Regex engine: stdlib or re2."`
	RegexpEngine string      `name:"regexp-engine" hidden:"" help:"Deprecated alias for --regex-engine."`
	Version      versionFlag `short:"v" help:"Print version information and quit."`
}

type CLI struct {
	GlobalFlags `embed:""`

	Directory   DirectoryCmd   `cmd:"" name:"dir" aliases:"file,directory" help:"Scan directories or files for secrets."`
	Git         GitCmd         `cmd:"" help:"Scan Git repositories for secrets."`
	GitHub      GitHubCmd      `cmd:"" name:"github" help:"Scan GitHub repositories and resources for secrets."`
	GitLab      GitLabCmd      `cmd:"" name:"gitlab" help:"Scan GitLab projects and resources for secrets."`
	HuggingFace HuggingFaceCmd `cmd:"" name:"huggingface" aliases:"hf" help:"Scan Hugging Face repositories and community resources for secrets."`
	S3          S3Cmd          `cmd:"" name:"s3" help:"Scan an S3 or S3-compatible bucket for secrets."`
	Stdin       StdinCmd       `cmd:"" help:"Detect secrets from stdin."`
	Fingerprint FingerprintCmd `cmd:"" help:"Generate a secret fingerprint from stdin."`
	Validate    ValidateCmd    `cmd:"" help:"Validate a known secret without running detection."`
	ConfigCmd   ConfigCmd      `cmd:"" name:"config" help:"Validate and inspect betterleaks configs."`
	VersionCmd  VersionCmd     `cmd:"" name:"version" help:"Display betterleaks version."`
}

type commandRuntime struct {
	context.Context
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	exit   func(int)
}

// diagnostics manager is global to ensure it can be started before a scan
// begins and stopped after a scan completes.
var diagnosticsManager *DiagnosticsManager

const (
	BYTE     = 1.0
	KILOBYTE = BYTE * 1000
	MEGABYTE = KILOBYTE * 1000
	GIGABYTE = MEGABYTE * 1000
)

var logLevel = zerolog.InfoLevel

func initLog(globals *GlobalFlags, ctx *kong.Context) error {
	switch strings.ToLower(globals.LogLevel) {
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
		logging.Warn().Msgf("unknown log level: %s", globals.LogLevel)
	}
	logging.Logger = logging.Logger.Level(logLevel)

	engineName := globals.RegexEngine
	if !flagWasSet(ctx, "regex-engine") && flagWasSet(ctx, "regexp-engine") {
		engineName = globals.RegexpEngine
	}
	switch engineName {
	case "re2":
		regexp.SetEngine(regexpre2.RE2{})
	case "stdlib":
		regexp.SetEngine(regexp.Stdlib{})
	default:
		return fmt.Errorf("unknown regex engine %q (valid values: re2, stdlib)", engineName)
	}
	return nil
}

func flagWasSet(ctx *kong.Context, name string) bool {
	for _, trace := range ctx.Path {
		if trace.Flag != nil && trace.Flag.Name == name {
			return true
		}
	}
	return false
}

var (
	bannerPrinted      bool
	resolvedConfigPath string // set by initConfig to the actual config file path that was loaded
	loadedConfig       *config.Config
)

func initConfig(runtime *commandRuntime, globals *GlobalFlags, flags *ScanFlags, source string) {
	resolvedConfigPath = "" // reset for each call (cmd/directory.go calls per-source)
	loadedConfig = nil
	hideBanner := flags.NoBanner || flags.Silent
	if !hideBanner && !bannerPrinted {
		_, _ = fmt.Fprint(runtime.stderr, banner)
		bannerPrinted = true
	}

	logging.Debug().Msgf("using %s regex engine", regexp.Version())

	cfgPath := globals.Config
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

func initDiagnostics(flags *ScanFlags) {
	var diagErr error
	diagnosticsManager, diagErr = NewDiagnosticsManager(flags.Diagnostics, flags.DiagnosticsDir)
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
	runtime := &commandRuntime{
		Context: ctx,
		stdin:   os.Stdin,
		stdout:  os.Stdout,
		stderr:  os.Stderr,
		exit:    os.Exit,
	}
	if err := runCLIWithErrorHandling(expandRuleFlagShorthands(os.Args[1:]), runtime); err != nil {
		logging.Fatal().Msg(err.Error())
	}
}

func runCLI(args []string, runtime *commandRuntime) error {
	cli := &CLI{}
	parser, err := newCLIParser(cli, runtime)
	if err != nil {
		return err
	}
	return runCLIWithParser(args, runtime, cli, parser)
}

func runCLIWithErrorHandling(args []string, runtime *commandRuntime) error {
	cli := &CLI{}
	parser, err := newCLIParser(cli, runtime)
	if err != nil {
		return err
	}
	err = runCLIWithParser(args, runtime, cli, parser)
	if err == nil {
		return nil
	}

	var parseErr *kong.ParseError
	if !errors.As(err, &parseErr) {
		return err
	}
	if strings.Contains(err.Error(), "unknown flag") {
		// Preserve the exit code used before the Kong migration.
		err = cliExitError{error: err, code: 126}
	}
	parser.FatalIfErrorf(err)
	return nil
}

type cliExitError struct {
	error
	code int
}

func (e cliExitError) ExitCode() int { return e.code }
func (e cliExitError) Unwrap() error { return e.error }

func runCLIWithParser(args []string, runtime *commandRuntime, cli *CLI, parser *kong.Kong) error {
	if len(args) == 0 {
		args = []string{"--help"}
	}
	var err error
	args, err = normalizeProviderFlagAliases(args)
	if err != nil {
		return err
	}
	parsed, err := parser.Parse(args)
	if err != nil {
		return err
	}
	if err := initLog(&cli.GlobalFlags, parsed); err != nil {
		return err
	}
	return parsed.Run(runtime)
}

func newCLIParser(cli *CLI, runtime *commandRuntime) (*kong.Kong, error) {
	return kong.New(
		cli,
		kong.Name("betterleaks"),
		kong.Description("Betterleaks scans code, past or present, for secrets"),
		kong.Vars{"config_help": configDescription},
		kong.Writers(runtime.stdout, runtime.stderr),
		kong.Exit(runtime.exit),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
		kong.UsageOnError(),
	)
}

type versionFlag bool

func (v *versionFlag) Decode(*kong.DecodeContext) error {
	*v = true
	return nil
}

func (*versionFlag) IsBool() bool { return true }

func (versionFlag) BeforeApply(app *kong.Kong) error {
	_, _ = fmt.Fprintln(app.Stdout, version.Version)
	app.Exit(0)
	return nil
}

func Config() *config.Config {
	if loadedConfig == nil {
		logging.Fatal().Msg("Failed to load config")
	}
	cfg := *loadedConfig
	cfg.Path = resolvedConfigPath

	return &cfg
}

func Detector(runtime *commandRuntime, globals *GlobalFlags, flags *ScanFlags, cfg *config.Config, source string, extraOptions ...detect.Option) *detect.Detector {
	var err error

	// Apply rule overrides before taking the detector's immutable rule snapshot.
	if err := applyRuleSelection(flags, cfg); err != nil {
		logging.Fatal().Err(err).Msg("unable to apply rule selection")
	}

	if err := validateProviderRPS(flags.ProviderRPS); err != nil {
		logging.Fatal().Err(err).Msg("provider-rps")
	}
	providerRPSByRule, err := parseProviderRuleRPS(flags.ProviderRPSRule)
	if err != nil {
		logging.Fatal().Err(err).Msg("provider-rps-rule")
	}
	detectorOptions, err := ignoreOptions(runtime, flags.IgnoreFile, source)
	if err != nil {
		logging.Fatal().Err(err).Msg("unable to load ignore file")
	}
	detectorOptions = append(detectorOptions,
		detect.WithJobs(flags.Jobs),
		detect.WithMaxDecodeDepth(flags.MaxDecodeDepth),
		detect.WithMinimumConfidence(detect.Confidence(flags.Confidence)),
		detect.WithIgnoreAllowComments(flags.IgnoreAllowComments),
	)
	if flags.MatchContext != "" {
		detectorOptions = append(detectorOptions, detect.WithMatchContext(flags.MatchContext))
	}
	if diagnosticsManager != nil && diagnosticsManager.RuleTimings != nil {
		detectorOptions = append(detectorOptions, detect.WithRuleTimings(diagnosticsManager.RuleTimings))
	}
	if flags.Validation || flags.Analysis {
		statuses, statusErr := parseValidationStatuses(flags.ValidationStatus)
		if statusErr != nil {
			logging.Fatal().Err(statusErr).Msg("validation-status")
		}
		providerOptions := detect.ProviderOptions{
			Debug:                   flags.ProviderDebug,
			Workers:                 flags.ProviderWorkers,
			ExtractEmpty:            flags.ValidationExtractEmpty,
			Statuses:                statuses,
			MaxRequestsPerTarget:    flags.ProviderMaxRequests,
			RequestsPerSecond:       flags.ProviderRPS,
			RequestsPerSecondByRule: providerRPSByRule,
			ValidationEnvVars:       flags.ProviderEnvVars,
			Timeout:                 flags.ProviderTimeout,
		}
		if flags.Analysis {
			detectorOptions = append(detectorOptions, detect.WithAnalysis(providerOptions))
		} else {
			detectorOptions = append(detectorOptions, detect.WithValidation(providerOptions))
		}
	}
	detectorOptions = append(detectorOptions, extraOptions...)
	detector, err := detect.NewDetector(cfg, detectorOptions...)
	if err != nil {
		logging.Fatal().Err(err).Msg("unable to create detector")
	}
	if (flags.Validation || flags.Analysis) && !detector.ValidationEnabled() {
		logging.Warn().Msg("validation enabled but no rules have validation expressions")
	}
	if flags.Analysis && !detector.AnalysisEnabled() {
		logging.Warn().Msg("analysis enabled but no rules have analysis expressions")
	}

	// set color flag at first
	// also init logger again without color
	if globals.NoColor {
		logging.Logger = log.Output(zerolog.ConsoleWriter{
			Out:     runtime.stderr,
			NoColor: true,
		}).Level(logLevel)
	}

	return detector
}

func parseValidationStatuses(value string) ([]report.ValidationStatus, error) {
	var statuses []report.ValidationStatus
	for value := range strings.SplitSeq(value, ",") {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if value == "none" {
			statuses = append(statuses, report.ValidationStatusNone)
			continue
		}
		status := report.ValidationStatus(value)
		switch status {
		case report.ValidationStatusValid,
			report.ValidationStatusNeedsValidation,
			report.ValidationStatusInvalid,
			report.ValidationStatusRevoked,
			report.ValidationStatusUnknown,
			report.ValidationStatusError:
			statuses = append(statuses, status)
		default:
			return nil, fmt.Errorf("invalid validation status %q", value)
		}
	}
	return statuses, nil
}

func ignoreOptions(runtime *commandRuntime, explicitPath, source string) ([]detect.Option, error) {
	path := explicitPath
	explicit := path != ""
	if !explicit {
		path = filepath.Join(".", ".betterleaksignore")
		if source != "" {
			info, err := os.Stat(source)
			if err != nil {
				return nil, err
			}
			if info.IsDir() {
				path = filepath.Join(source, ".betterleaksignore")
			} else {
				path = filepath.Join(filepath.Dir(source), ".betterleaksignore")
			}
		}
	}

	file, err := os.Open(path)
	if err != nil {
		if !explicit && os.IsNotExist(err) {
			return nil, nil
		}
		if explicit {
			return nil, fmt.Errorf("open %q: %w", path, err)
		}
		_, _ = fmt.Fprintf(runtime.stderr, "warning: %s: %v\n", path, err)
		return nil, nil
	}
	defer file.Close()

	set, diagnostics, readErr := fingerprint.Load(file)
	for _, diagnostic := range diagnostics {
		_, _ = fmt.Fprintf(runtime.stderr, "warning: %s:%d: %s; entry ignored\n", path, diagnostic.Line, diagnostic.Reason)
	}
	if readErr != nil {
		if explicit {
			return nil, fmt.Errorf("read %q: %w", path, readErr)
		}
		_, _ = fmt.Fprintf(runtime.stderr, "warning: %s: %v\n", path, readErr)
	}

	var excluded []string
	if source != "" {
		excluded = append(excluded, path)
		ignorePath, ignoreErr := filepath.Abs(path)
		if ignoreErr == nil {
			excluded = append(excluded, ignorePath)
		}
		if info, err := os.Stat(source); err == nil && info.IsDir() {
			sourcePath, sourceErr := filepath.Abs(source)
			if sourceErr == nil && ignoreErr == nil {
				if relative, err := filepath.Rel(sourcePath, ignorePath); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
					excluded = append(excluded, relative)
				}
			}
		}
	}
	var options []detect.Option
	if len(excluded) > 0 {
		options = append(options, detect.WithExcludedPaths(excluded...))
	}
	if set.Len() > 0 {
		options = append(options, detect.WithIgnoredSecrets(set))
	}
	return options, nil
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

func addScanSummary(total *detect.ScanSummary, next detect.ScanSummary) {
	total.BytesInspected += next.BytesInspected
	total.Findings += next.Findings
	if total.ValidationCounts == nil {
		total.ValidationCounts = make(map[report.ValidationStatus]int)
	}
	for status, count := range next.ValidationCounts {
		total.ValidationCounts[status] += count
	}
}

func findingSummaryAndExit(runtime *commandRuntime, summary detect.ScanSummary, validationEnabled bool, findings *findingCollector, exitCode int, start time.Time, err error) {
	// Finalize streaming reports first. In particular, JSON needs its closing
	// bracket even when the command context was canceled by an interrupt.
	if outputErr := findings.Close(); outputErr != nil {
		logging.Fatal().Err(outputErr).Msg("failed to finish finding output")
	}
	if err == nil {
		err = runtime.Err()
	}

	if diagnosticsManager.Enabled {
		logging.Debug().Msg("Finalizing diagnostics...")
		diagnosticsManager.StopDiagnostics()
	}

	if validationEnabled {
		logging.Info().
			Int("valid", summary.ValidationCounts[report.ValidationStatusValid]).
			Int("needs_validation", summary.ValidationCounts[report.ValidationStatusNeedsValidation]).
			Int("invalid", summary.ValidationCounts[report.ValidationStatusInvalid]).
			Int("revoked", summary.ValidationCounts[report.ValidationStatusRevoked]).
			Int("unknown", summary.ValidationCounts[report.ValidationStatusUnknown]).
			Int("errors", summary.ValidationCounts[report.ValidationStatusError]).
			Msg("validation complete")
	}

	totalBytes := summary.BytesInspected
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
		runtime.exit(1)
		return
	}

	if findings.Count() != 0 {
		runtime.exit(exitCode)
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
