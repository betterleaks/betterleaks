package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/betterleaks/betterleaks/v2/analyze"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/internal/logging"
	"github.com/betterleaks/betterleaks/v2/pipeline"
	"github.com/betterleaks/betterleaks/v2/regexp"
	regexpre2 "github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
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
If none of these options are used, the embedded default config is used.
Config files in scan targets or the current directory are not loaded automatically.`

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

	Auto        AutoCmd        `cmd:"" default:"withargs" help:"Detect and scan a local path or remote URL (auto may be omitted)."`
	Directory   DirectoryCmd   `cmd:"" name:"filesystem" aliases:"fs" help:"Scan files and directories."`
	URL         URLCmd         `cmd:"" name:"url" help:"Download and scan one HTTP(S) URL for secrets."`
	Git         GitCmd         `cmd:"" help:"Scan Git repositories for secrets."`
	GitHub      GitHubCmd      `cmd:"" name:"github" help:"Scan GitHub repositories and resources for secrets."`
	GitLab      GitLabCmd      `cmd:"" name:"gitlab" help:"Scan GitLab projects and resources for secrets."`
	HuggingFace HuggingFaceCmd `cmd:"" name:"huggingface" aliases:"hf" help:"Scan Hugging Face repositories and community resources for secrets."`
	S3          S3Cmd          `cmd:"" name:"s3" help:"Scan an S3 or S3-compatible bucket for secrets."`
	Stdin       StdinCmd       `cmd:"" help:"Detect secrets from stdin."`
	Fingerprint FingerprintCmd `cmd:"" help:"Generate a SHA-256 value fingerprint from stdin."`
	Validate    ValidateCmd    `cmd:"" help:"Validate a known secret without running detection."`
	Analyze     AnalyzeCmd     `cmd:"" help:"Validate a known credential and resolve its identity and permissions."`
	Revoke      RevokeCmd      `cmd:"" help:"Revoke a known credential using its rule's revoke expression."`
	ConfigCmd   ConfigCmd      `cmd:"" name:"config" help:"Validate and inspect betterleaks configs."`
	VersionCmd  VersionCmd     `cmd:"" name:"version" help:"Display betterleaks version."`
}

type commandRuntime struct {
	context.Context
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	logger *slog.Logger
	engine regexp.Engine
	exit   func(int)
}

func (r *commandRuntime) regexEngine() regexp.Engine {
	if r == nil || r.engine == nil {
		return regexp.Stdlib{}
	}
	return r.engine
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
		runtime.engine = regexpre2.RE2{}
	case "stdlib":
		runtime.engine = regexp.Stdlib{}
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

var bannerPrinted bool

func initConfig(runtime *commandRuntime, globals *GlobalFlags, flags *ScanFlags) *config.Config {
	if !flags.NoBanner && !flags.Silent && !bannerPrinted {
		_, _ = fmt.Fprint(runtime.stderr, banner)
		bannerPrinted = true
	}
	runtime.Logger().Debug("using regex engine", "version", runtime.regexEngine().Version())
	resolved, err := resolveConfig(runtime, globals.Config, "")
	if err != nil {
		runtime.fatal("unable to load config", "error", err)
	}
	runtime.Logger().Debug("using config", "source", resolved.source)
	// Apply rule selection once, before any target constructs its engines.
	if err := applyRuleSelection(runtime.Logger(), flags, resolved.cfg); err != nil {
		runtime.fatal("unable to apply rule selection", "error", err)
	}
	return resolved.cfg
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

func runCLIWithParser(args []string, runtime *commandRuntime, cli *CLI, parser *cliParser) error {
	if len(args) == 0 {
		args = []string{"--help"}
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

func newCLIParser(cli *CLI, runtime *commandRuntime) (*cliParser, error) {
	parser, err := kong.New(
		cli,
		kong.Name("betterleaks"),
		kong.Description("Betterleaks scans code, past or present, for secrets"),
		kong.Vars{
			"config_help":     configDescription,
			"analyze_workers": strconv.Itoa(defaultAnalyzeWorkers),
		},
		kong.Writers(runtime.stdout, runtime.stderr),
		kong.Exit(runtime.exit),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
		kong.Help(printCLIHelp),
		kong.Groups{
			"scanning":    "Scanning Options:",
			"output":      "Output Options:",
			"validation":  "Validation & Analysis Options:",
			"source":      "Source Options:",
			"diagnostics": "Diagnostics Options:",
		},
		kong.AutoGroup(func(kong.Visitable, *kong.Flag) *kong.Group {
			return &kong.Group{Key: "options", Title: "Options:"}
		}),
		kong.UsageOnError(),
	)
	if err != nil {
		return nil, err
	}
	return &cliParser{Kong: parser}, nil
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

func newScanPipeline(runtime *commandRuntime, globals *GlobalFlags, flags *ScanFlags, cfg *config.Config, extraOptions ...scan.Option) (*pipeline.Pipeline, error) {
	if err := validateProviderRPS(flags.ProviderRPS); err != nil {
		return nil, fmt.Errorf("provider-rps: %w", err)
	}
	providerRPSByRule, err := parseProviderRuleRPS(flags.ProviderRPSRule)
	if err != nil {
		return nil, fmt.Errorf("provider-rps-rule: %w", err)
	}
	scannerOptions := []scan.Option{
		scan.WithRegexEngine(runtime.regexEngine()),
		scan.WithWorkers(resolveScanWorkers(flags.Jobs)),
		scan.WithMaxDecodeDepth(flags.MaxDecodeDepth),
		scan.WithMinimumConfidence(scan.Confidence(flags.Confidence)),
		scan.WithIgnoreAllowComments(flags.IgnoreAllowComments),
	}
	if flags.MatchContext != "" {
		scannerOptions = append(scannerOptions, scan.WithMatchContext(flags.MatchContext))
	}
	scannerOptions = append(scannerOptions, scan.WithLogger(runtime.Logger()))
	scannerOptions = append(scannerOptions, extraOptions...)
	scanner, err := scan.New(cfg, scannerOptions...)
	if err != nil {
		return nil, fmt.Errorf("unable to create scanner: %w", err)
	}
	var analyzer *analyze.Analyzer
	var pipelineOptions []pipeline.Option
	if flags.validationEnabled() {
		statuses, statusErr := parseValidationStatuses(flags.ValidationStatus)
		if statusErr != nil {
			return nil, fmt.Errorf("status: %w", statusErr)
		}
		pipelineOptions = append(pipelineOptions, pipeline.WithValidationStatuses(statuses...))
		analyzer, err = analyze.New(cfg,
			analyze.WithRegexEngine(runtime.regexEngine()),
			analyze.WithLogger(runtime.Logger()),
			analyze.WithWorkers(resolveAnalyzeWorkers(flags.ProviderWorkers)),
			analyze.WithDebug(flags.ProviderDebug),
			analyze.WithTimeout(flags.ProviderTimeout),
			analyze.WithMaxRequestsPerTarget(flags.ProviderMaxRequests),
			analyze.WithRequestsPerSecond(flags.ProviderRPS),
			analyze.WithRequestsPerSecondByRule(providerRPSByRule),
			analyze.WithEnvVars(flags.ProviderEnvVars...),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create analyzer: %w", err)
		}
		if !flags.analysisEnabled() {
			pipelineOptions = append(pipelineOptions, pipeline.WithValidationOnly())
		}
		if !analyzer.HasValidation() {
			runtime.Logger().Debug("no enabled rules have validation expressions")
		}
		if flags.analysisEnabled() && !analyzer.HasAnalysis() {
			runtime.Logger().Debug("no enabled rules have analysis expressions")
		}
	}
	runner, err := pipeline.New(scanner, analyzer, pipelineOptions...)
	if err != nil {
		return nil, fmt.Errorf("unable to create pipeline: %w", err)
	}
	return runner, nil
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

type scanFilters struct {
	shouldSkip   sources.PrefilterFunc
	fingerprints []fingerprint.Hash
}

func loadScanFilters(runtime *commandRuntime, cfg *config.Config, ignorePath, source string) (scanFilters, error) {
	hashes, excluded, err := readIgnoreFile(runtime, ignorePath, source)
	if err != nil {
		return scanFilters{}, fmt.Errorf("unable to load ignore file: %w", err)
	}
	if cfg.Path != "" {
		excluded = append(excluded, cfg.Path)
	}
	skip, err := prefilter.Compile(cfg.Prefilter, prefilter.Options{
		ExcludedPaths: excluded,
		RegexEngine:   runtime.regexEngine(),
		Logger:        runtime.Logger(),
	})
	if err != nil {
		return scanFilters{}, fmt.Errorf("unable to compile source prefilter: %w", err)
	}
	return scanFilters{shouldSkip: skip, fingerprints: hashes}, nil
}

func readIgnoreFile(runtime *commandRuntime, explicitPath, source string) ([]fingerprint.Hash, []string, error) {
	path := explicitPath
	explicit := path != ""
	if !explicit {
		path = filepath.Join(".", ".betterleaksignore")
		if source != "" {
			info, err := os.Stat(source)
			if err != nil {
				return nil, nil, err
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
			return nil, nil, nil
		}
		if explicit {
			return nil, nil, fmt.Errorf("open %q: %w", path, err)
		}
		_, _ = fmt.Fprintf(runtime.stderr, "warning: %s: %v\n", path, err)
		return nil, nil, nil
	}
	defer file.Close()

	hashes, diagnostics, readErr := fingerprint.Load(file)
	for _, diagnostic := range diagnostics {
		_, _ = fmt.Fprintf(runtime.stderr, "warning: %s:%d: %s; entry ignored\n", path, diagnostic.Line, diagnostic.Reason)
	}
	if readErr != nil {
		if explicit {
			return nil, nil, fmt.Errorf("read %q: %w", path, readErr)
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
	return hashes, excluded, nil
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

func addScanSummary(total *pipeline.ScanSummary, next pipeline.ScanSummary) {
	total.BytesInspected += next.BytesInspected
	total.DetectedFindings += next.DetectedFindings
	total.EmittedFindings += next.EmittedFindings
	if total.ValidationCounts == nil {
		total.ValidationCounts = make(map[report.ValidationStatus]int)
	}
	for status, count := range next.ValidationCounts {
		total.ValidationCounts[status] += count
	}
}

func findingSummaryAndExit(runtime *commandRuntime, summary pipeline.ScanSummary, validationEnabled bool, findings *findingCollector, exitCode int, start time.Time, err error) {
	if err == nil {
		err = runtime.Err()
	}
	findings.scan.State = report.ScanStateIncomplete
	if err == nil {
		findings.scan.State = report.ScanStateComplete
	}
	findings.scan.BytesScanned = summary.BytesInspected
	// Resolve cancellation before finalization so interrupted reports cannot be
	// marked complete. Close still writes their metadata and JSON delimiters.
	if outputErr := findings.Close(); outputErr != nil {
		runtime.fatal("failed to finish finding output", "error", outputErr)
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
			"unchecked", summary.ValidationCounts[report.ValidationStatusNone],
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
		runtime.Logger().Warn(fmt.Sprintf("incomplete scan ended after %s", FormatDuration(time.Since(start))))
		if findings.Count() != 0 {
			runtime.Logger().Warn(fmt.Sprintf("%d leaks found in incomplete scan", findings.Count()))
		} else {
			runtime.Logger().Warn("no leaks found in incomplete scan")
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
