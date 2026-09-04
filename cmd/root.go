package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/detect"
	"github.com/betterleaks/betterleaks/v2/internal/fingerprint"
	"github.com/betterleaks/betterleaks/v2/logging"
	"github.com/betterleaks/betterleaks/v2/regexp"
	regexpre2 "github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/version"
)

var banner = fmt.Sprintf(`
 + ○
   ▾
 betterleaks %s

`, version.Version)

const configDescription = `config file path
order of precedence:
1. --config/-c
2. env var BETTERLEAKS_CONFIG
3. env var BETTERLEAKS_CONFIG_TOML with the file content
4. (target path)/.betterleaks.toml
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
	logger *slog.Logger
	exit   func(int)
}

var discardLogger = slog.New(slog.DiscardHandler)

func (r *commandRuntime) Logger() *slog.Logger {
	if r == nil || r.logger == nil {
		return discardLogger
	}
	return r.logger
}

func (r *commandRuntime) logContext() context.Context {
	if r == nil || r.Context == nil {
		return context.Background()
	}
	return r.Context
}

func (r *commandRuntime) fatal(msg string, args ...any) {
	r.Logger().Log(r.logContext(), logging.LevelFatal, msg, args...)
	if r == nil || r.exit == nil {
		panic("command runtime exit function is not configured")
	}
	r.exit(1)
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

func initLog(globals *GlobalFlags, ctx *kong.Context, runtime *commandRuntime) error {
	logLevel := slog.LevelInfo
	var unknownLevel string
	switch strings.ToLower(globals.LogLevel) {
	case "trace":
		logLevel = logging.LevelTrace
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "err", "error":
		logLevel = slog.LevelError
	case "fatal":
		logLevel = logging.LevelFatal
	default:
		logLevel = slog.LevelInfo
		unknownLevel = globals.LogLevel
	}
	runtime.logger = logging.NewConsole(runtime.stderr, logging.ConsoleOptions{
		Level:   logLevel,
		NoColor: globals.NoColor,
	})
	if unknownLevel != "" {
		runtime.Logger().Warn("unknown log level", "level", unknownLevel)
	}

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

	runtime.Logger().Debug("using regex engine", "version", regexp.Version())

	cfgPath := globals.Config
	if cfgPath != "" {
		resolvedConfigPath = cfgPath
		runtime.Logger().Debug("using config from --config", "path", cfgPath)
		loadedConfig = mustLoadConfigFile(runtime, cfgPath)
	} else if envPath := os.Getenv("BETTERLEAKS_CONFIG"); envPath != "" {
		resolvedConfigPath = envPath
		runtime.Logger().Debug("using config from environment", "path", envPath)
		loadedConfig = mustLoadConfigFile(runtime, envPath)
	} else if configContent := os.Getenv("BETTERLEAKS_CONFIG_TOML"); configContent != "" {
		cfg, err := config.ParseTOMLString(configContent, "", config.WithLogger(runtime.Logger()))
		if err != nil {
			runtime.fatal("unable to load config from environment", "error", err, "content", configContent)
		}
		runtime.Logger().Debug("using config from environment content", "content", configContent)
		// resolvedConfigPath stays "" — inline content, no file to skip.
		loadedConfig = cfg
		return
	} else {
		fileInfo, err := os.Stat(source)
		if err != nil {
			runtime.fatal(err.Error())
		}

		if !fileInfo.IsDir() {
			runtime.Logger().Debug("config search path is a file; using default config",
				"config", filepath.Join(source, ".betterleaks.toml"),
				"source", source,
			)
			loadedConfig, err = config.Default(config.WithLogger(runtime.Logger()))
			if err != nil {
				runtime.fatal("error reading default config", "error", err)
			}
			// resolvedConfigPath stays "" — using embedded default config.
			return
		}

		configFile := findConfigFile(source)
		if configFile == "" {
			runtime.Logger().Debug("no config found; using default config", "path", source)

			loadedConfig, err = config.Default(config.WithLogger(runtime.Logger()))
			if err != nil {
				runtime.fatal("error reading default config", "error", err)
			}
			// resolvedConfigPath stays "" — using embedded default config.
			return
		} else {
			resolvedConfigPath = configFile
			runtime.Logger().Debug("using existing config", "path", configFile)
		}

		loadedConfig = mustLoadConfigFile(runtime, configFile)
	}
}

func mustLoadConfigFile(runtime *commandRuntime, path string) *config.Config {
	cfg, err := config.LoadFile(path, config.WithLogger(runtime.Logger()))
	if err != nil {
		runtime.fatal("unable to load config", "error", err)
	}
	return cfg
}

// findConfigFile looks for .betterleaks.toml in source.
func findConfigFile(source string) string {
	path := filepath.Join(source, ".betterleaks.toml")
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

func initDiagnostics(runtime *commandRuntime, flags *ScanFlags) {
	var diagErr error
	diagnosticsManager, diagErr = NewDiagnosticsManager(flags.Diagnostics, flags.DiagnosticsDir, runtime.Logger())
	if diagErr != nil {
		runtime.fatal("Error initializing diagnostics", "error", diagErr)
	}

	if diagnosticsManager.Enabled {
		runtime.Context = diagnosticsManager.withContext(runtime.Context)
		runtime.Logger().Info("Starting diagnostics...")
		if diagErr := diagnosticsManager.StartDiagnostics(); diagErr != nil {
			runtime.fatal("Failed to start diagnostics", "error", diagErr)
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
		logger: logging.NewConsole(os.Stderr, logging.ConsoleOptions{
			Level: slog.LevelInfo,
		}),
		exit: os.Exit,
	}
	if err := runCLIWithErrorHandling(expandRuleFlagShorthands(os.Args[1:]), runtime); err != nil {
		runtime.fatal(err.Error())
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
	if err := initLog(&cli.GlobalFlags, parsed, runtime); err != nil {
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

func Config(runtime *commandRuntime) *config.Config {
	if loadedConfig == nil {
		runtime.fatal("Failed to load config")
	}
	cfg := *loadedConfig
	cfg.Path = resolvedConfigPath

	return &cfg
}

func Detector(runtime *commandRuntime, globals *GlobalFlags, flags *ScanFlags, cfg *config.Config, source string, extraOptions ...detect.Option) *detect.Detector {
	var err error

	// Apply rule overrides before taking the detector's immutable rule snapshot.
	if err := applyRuleSelection(runtime.Logger(), flags, cfg); err != nil {
		runtime.fatal("unable to apply rule selection", "error", err)
	}

	if err := validateProviderRPS(flags.ProviderRPS); err != nil {
		runtime.fatal("provider-rps", "error", err)
	}
	providerRPSByRule, err := parseProviderRuleRPS(flags.ProviderRPSRule)
	if err != nil {
		runtime.fatal("provider-rps-rule", "error", err)
	}
	detectorOptions, err := applyIgnorePolicy(runtime, flags.IgnoreFile, source, cfg)
	if err != nil {
		runtime.fatal("unable to load ignore file", "error", err)
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
	validationEnabled := flags.validationEnabled()
	analysisEnabled := flags.analysisEnabled()
	if validationEnabled {
		statuses, statusErr := parseValidationStatuses(flags.ValidationStatus)
		if statusErr != nil {
			runtime.fatal("validation-status", "error", statusErr)
		}
		providerOptions := detect.ProviderOptions{
			Debug:                   flags.ProviderDebug,
			Workers:                 flags.ProviderWorkers,
			Statuses:                statuses,
			MaxRequestsPerTarget:    flags.ProviderMaxRequests,
			RequestsPerSecond:       flags.ProviderRPS,
			RequestsPerSecondByRule: providerRPSByRule,
			EnvVars:                 flags.ProviderEnvVars,
			Timeout:                 flags.ProviderTimeout,
		}
		if analysisEnabled {
			detectorOptions = append(detectorOptions, detect.WithAnalysis(providerOptions))
		} else {
			detectorOptions = append(detectorOptions, detect.WithValidation(providerOptions))
		}
	}
	detectorOptions = append(detectorOptions, detect.WithLogger(runtime.Logger()))
	detectorOptions = append(detectorOptions, extraOptions...)
	detector, err := detect.NewDetector(cfg, detectorOptions...)
	if err != nil {
		runtime.fatal("unable to create detector", "error", err)
	}
	if validationEnabled && !detector.ValidationEnabled() {
		runtime.Logger().Debug("no enabled rules have validation expressions")
	}
	if analysisEnabled && !detector.AnalysisEnabled() {
		runtime.Logger().Debug("no enabled rules have analysis expressions")
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

func applyIgnorePolicy(runtime *commandRuntime, explicitPath, source string, cfg *config.Config) ([]detect.Option, error) {
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

	list, diagnostics, readErr := fingerprint.Load(file)
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
	if expression := list.FilterExpression(); expression != "" {
		if cfg.Filter == "" {
			cfg.Filter = expression
		} else {
			cfg.Filter = "(\n" + strings.TrimSpace(cfg.Filter) + "\n) || (\n" + expression + "\n)"
		}
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
		runtime.fatal("failed to finish finding output", "error", outputErr)
	}
	if err == nil {
		err = runtime.Err()
	}

	if diagnosticsManager.Enabled {
		runtime.Logger().Debug("Finalizing diagnostics...")
		diagnosticsManager.StopDiagnostics()
	}

	if validationEnabled {
		runtime.Logger().Info("validation complete",
			"valid", summary.ValidationCounts[report.ValidationStatusValid],
			"needs_validation", summary.ValidationCounts[report.ValidationStatusNeedsValidation],
			"invalid", summary.ValidationCounts[report.ValidationStatusInvalid],
			"revoked", summary.ValidationCounts[report.ValidationStatusRevoked],
			"unknown", summary.ValidationCounts[report.ValidationStatusUnknown],
			"errors", summary.ValidationCounts[report.ValidationStatusError],
		)
	}

	totalBytes := summary.BytesInspected
	bytesMsg := fmt.Sprintf("scanned ~%d bytes (%s)", totalBytes, bytesConvert(totalBytes))
	if err == nil {
		runtime.Logger().Info(fmt.Sprintf("%s in %s", bytesMsg, FormatDuration(time.Since(start))))
		if findings.Count() != 0 {
			runtime.Logger().Warn(fmt.Sprintf("leaks found: %d", findings.Count()))
		} else {
			runtime.Logger().Info("no leaks found")
		}
	} else {
		runtime.Logger().Warn(bytesMsg)
		runtime.Logger().Warn(fmt.Sprintf("partial scan completed in %s", FormatDuration(time.Since(start))))
		if findings.Count() != 0 {
			runtime.Logger().Warn(fmt.Sprintf("%d leaks found in partial scan", findings.Count()))
		} else {
			runtime.Logger().Warn("no leaks found in partial scan")
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
