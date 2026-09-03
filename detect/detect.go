package detect

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net/http"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/detect/codec"
	"github.com/betterleaks/betterleaks/v2/internal/ahocorasick"
	"github.com/betterleaks/betterleaks/v2/internal/confidence"
	"github.com/betterleaks/betterleaks/v2/internal/contextwindow"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/ruletiming"
	"github.com/betterleaks/betterleaks/v2/internal/tokenizer"
	"github.com/betterleaks/betterleaks/v2/internal/validate"
	blregexp "github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// ValidationOptions controls secret validation behavior. Validation is enabled
// when these options are passed to [WithValidation].
type ValidationOptions struct {
	// Debug includes provider HTTP metadata in findings.
	Debug bool
	// Workers is the number of provider workers. Zero uses 10.
	Workers int
	// Timeout is the per-request timeout. Zero uses the runtime default.
	Timeout time.Duration
	// ExtractEmpty preserves empty extractor values in validation metadata.
	ExtractEmpty bool
	// Statuses restricts findings delivered by a scan. Empty includes all.
	Statuses []report.ValidationStatus
	// MaxRequestsPerTarget limits requests to each provider target. Zero is unlimited.
	MaxRequestsPerTarget int
	// RequestsPerSecond is the global request rate. Zero is unlimited.
	RequestsPerSecond float64
	// RequestsPerSecondByRule overrides the request rate for individual rules.
	RequestsPerSecondByRule map[string]float64
	// ValidationEnvVars lists environment variable names that provider Expr
	// programs may read through env.get(...). Names not listed are unavailable.
	ValidationEnvVars []string
}

// ProviderOptions is the shared request environment used by validation and
// credential analysis. ValidationOptions remains as an alias for SDK
// compatibility.
type ProviderOptions = ValidationOptions

// allowSignatures are comment tags that can be used to ignore findings.
// betterleaks:allow is checked first (preferred), followed by gitleaks:allow for backwards compatibility.
var allowSignatures = []string{"betterleaks:allow", "gitleaks:allow"}

var errStopIteration = errors.New("pipeline: stop iteration")

var discardLogger = slog.New(slog.DiscardHandler)

const (
	levelTrace = slog.LevelDebug - 4

	// maxComponentSets caps the Cartesian product of component-finding combinations
	// to prevent excessive memory use with large multi-part rules.
	maxComponentSets = 100
)

func logTrace(logger *slog.Logger, msg string, args ...any) {
	logger.Log(context.Background(), levelTrace, msg, args...)
}

func loggerOrDiscard(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return discardLogger
	}
	return logger
}

// Result is one finding or recoverable error emitted by [Detector.Run].
type Result struct {
	// Finding is populated when Err is nil.
	Finding report.Finding
	// Err is a recoverable source or pipeline error.
	Err error
}

// ScanSummary describes the work completed by one scan.
type ScanSummary struct {
	// BytesInspected excludes fragments rejected by the detector prefilter.
	BytesInspected uint64
	// Findings is the number of findings that passed output filters.
	Findings int
	// ValidationCounts includes validation outcomes before status filtering.
	ValidationCounts map[report.ValidationStatus]int
}

// Handler consumes one finding. Scan invokes handlers synchronously and never
// concurrently. Returning an error stops the scan. A handler must not start
// another scan on the same Detector because scans are sequential.
type Handler func(report.Finding) error

// SecretMatcher reports whether a secret should be ignored.
type SecretMatcher interface {
	Contains(secret string) bool
}

// Confidence is the minimum confidence classification accepted by a detector.
type Confidence string

const (
	ConfidenceAny    Confidence = ""
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type detectorOptions struct {
	jobs                int
	maxDecodeDepth      int
	matchContext        contextwindow.Spec
	minimumConfidence   string
	validationEnabled   bool
	analysisEnabled     bool
	validation          ValidationOptions
	ignoreAllowComments bool
	ignoredSecrets      SecretMatcher
	excludedPaths       []string
	precompile          bool
	logger              *slog.Logger
}

// Option configures a Detector during construction. Options are created by the
// With... functions in this package.
type Option struct {
	apply func(*detectorOptions) error
}

// WithIgnoredSecrets suppresses secrets contained by matcher.
func WithIgnoredSecrets(matcher SecretMatcher) Option {
	return Option{apply: func(options *detectorOptions) error {
		if matcher == nil {
			return errors.New("ignored-secret matcher is nil")
		}
		options.ignoredSecrets = matcher
		return nil
	}}
}

// WithExcludedPaths suppresses fragments whose path equals one of paths.
func WithExcludedPaths(paths ...string) Option {
	paths = slices.Clone(paths)
	return Option{apply: func(options *detectorOptions) error {
		options.excludedPaths = append(options.excludedPaths, paths...)
		return nil
	}}
}

// WithJobs sets the maximum number of concurrent detector workers. Zero uses
// GOMAXPROCS.
func WithJobs(jobs int) Option {
	return Option{apply: func(options *detectorOptions) error {
		if jobs < 0 {
			return errors.New("jobs must be non-negative")
		}
		options.jobs = jobs
		return nil
	}}
}

// WithMaxDecodeDepth limits recursive decoding passes. Zero disables decoding.
func WithMaxDecodeDepth(depth int) Option {
	return Option{apply: func(options *detectorOptions) error {
		if depth < 0 {
			return errors.New("maximum decode depth must be non-negative")
		}
		options.maxDecodeDepth = depth
		return nil
	}}
}

// WithMatchContext configures the context captured around each finding using
// the same grammar as the CLI --match-context flag.
func WithMatchContext(spec string) Option {
	return Option{apply: func(options *detectorOptions) error {
		parsed, err := contextwindow.Parse(spec)
		if err != nil {
			return fmt.Errorf("match context: %w", err)
		}
		options.matchContext = parsed
		return nil
	}}
}

// WithMinimumConfidence suppresses classified findings below confidence.
func WithMinimumConfidence(value Confidence) Option {
	return Option{apply: func(options *detectorOptions) error {
		parsed, err := confidence.Parse(string(value))
		if err != nil {
			return err
		}
		options.minimumConfidence = parsed
		return nil
	}}
}

// WithValidation enables active-secret validation for every scan.
func WithValidation(validation ValidationOptions) Option {
	validation = cloneValidationOptions(validation)
	return Option{apply: func(options *detectorOptions) error {
		options.validationEnabled = true
		options.validation = validation
		return nil
	}}
}

// WithAnalysis enables validation followed by credential analysis. Analysis is
// only evaluated for rules with an analyze expression and a valid credential.
func WithAnalysis(provider ProviderOptions) Option {
	provider = cloneValidationOptions(provider)
	return Option{apply: func(options *detectorOptions) error {
		options.validationEnabled = true
		options.analysisEnabled = true
		options.validation = provider
		return nil
	}}
}

func cloneValidationOptions(options ValidationOptions) ValidationOptions {
	options.Statuses = slices.Clone(options.Statuses)
	options.RequestsPerSecondByRule = maps.Clone(options.RequestsPerSecondByRule)
	options.ValidationEnvVars = slices.Clone(options.ValidationEnvVars)
	return options
}

// WithIgnoreAllowComments controls whether betterleaks:allow and
// gitleaks:allow comments are ignored instead of suppressing findings.
func WithIgnoreAllowComments(ignore bool) Option {
	return Option{apply: func(options *detectorOptions) error {
		options.ignoreAllowComments = ignore
		return nil
	}}
}

// WithLogger directs detector diagnostics to logger. Detectors are silent
// unless a logger is supplied.
func WithLogger(logger *slog.Logger) Option {
	return Option{apply: func(options *detectorOptions) error {
		options.logger = loggerOrDiscard(logger)
		return nil
	}}
}

// WithPrecompile forces every regex and expression to compile during
// construction. Lazy compilation remains the default.
func WithPrecompile() Option {
	return Option{apply: func(options *detectorOptions) error {
		options.precompile = true
		return nil
	}}
}

type ruleCandidates struct {
	// Indexes match rulesBySpecificity, preserving rule order without building
	// a map and sorted slice for every fragment and decode pass.
	marked []bool
}

// Detector is an immutable rule engine with thread-safe lazy compilation. A
// Detector may be reused for multiple scans. Scan executions are serialized.
type Detector struct {
	maxDecodeDepth         int
	matchContext           contextwindow.Spec
	validationStatusFilter map[report.ValidationStatus]struct{}
	minimumConfidence      string
	validationExtractEmpty bool
	ignoreAllowComments    bool
	jobs                   int
	logger                 *slog.Logger
	scanMu                 sync.Mutex

	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter        *ahocorasick.Matcher
	prefilterProgram exprruntime.Program
	globalFilterExpr string
	configPath       string
	ignoredSecrets   SecretMatcher
	excludedPaths    []string

	tokenCounter     *tokenizer.Counter
	tokenCounterOnce sync.Once

	exprRuntime *exprruntime.Runtime

	// validationRuntime compiles and caches per-rule provider expressions. The
	// workers and evaluation runtime are created separately for each scan.
	validationRuntime  *exprruntime.Runtime
	validationEnabled  bool
	analysisEnabled    bool
	validationOptions  ValidationOptions
	validationProgramM sync.Mutex
	validationPrograms map[string]exprruntime.Program
	analysisProgramM   sync.Mutex
	analysisPrograms   map[string]exprruntime.Program
	globalFilter       exprruntime.Program
	filterProgramM     sync.Mutex
	filterPrograms     map[string]exprruntime.Program

	// rulesBySpecificity contains an immutable snapshot of every configured rule in descending
	// specificity order. Its positions are the shared index space used by the
	// candidate slices below, so it must not change after detector construction.
	rulesBySpecificity []config.Rule
	ruleIndexByID      map[string]int

	// keywordRuleIndexes maps each Aho-Corasick pattern ID to the positions in
	// rulesBySpecificity of rules that use that keyword. Precomputing this avoids
	// keyword strings and map lookups while scanning each fragment.
	keywordRuleIndexes [][]int

	// noKeywordIndexes contains positions in rulesBySpecificity for rules with no
	// keyword prefilter. These rules are candidates on every scan and decode pass.
	noKeywordIndexes []int

	// candidatePool reuses bitmaps across detector workers and repeated scans. A
	// set bit means the rule at the same rulesBySpecificity position should run.
	// Bitmaps must be cleared before they are returned.
	candidatePool sync.Pool
}

// NewDetector creates a Detector from cfg. The source prefilter compiles during
// construction; rule regexes, finding filters, and provider expressions stay
// lazy unless [WithPrecompile] is supplied. Construction never starts scan or
// validation workers.
func NewDetector(cfg *config.Config, options ...Option) (*Detector, error) {
	if cfg == nil {
		return nil, errors.New("config is required to create detector")
	}
	settings := detectorOptions{logger: discardLogger}
	for _, option := range options {
		if option.apply == nil {
			return nil, errors.New("detector option is invalid")
		}
		if err := option.apply(&settings); err != nil {
			return nil, err
		}
	}
	rulesBySpecificity, ruleIndexByID, snapshotErr := snapshotDetectorRules(cfg)
	if snapshotErr != nil {
		return nil, fmt.Errorf("invalid config: %w", snapshotErr)
	}

	var validationRuntime *exprruntime.Runtime
	for _, rule := range rulesBySpecificity {
		if rule.ValidateExpr == "" {
			continue
		}
		var validationErr error
		validationRuntime, validationErr = exprruntime.New(nil)
		if validationErr != nil {
			return nil, fmt.Errorf("create validation runtime: %w", validationErr)
		}
		break
	}
	if settings.validationEnabled {
		if err := validateValidationOptions(settings.validation, validationRuntime); err != nil {
			return nil, err
		}
	}
	if validationRuntime != nil && settings.validationEnabled {
		validationRuntime.AllowedEnv = exprruntime.ParseValidationEnvAllowlist(settings.validation.ValidationEnvVars)
	}
	exprRuntime, exprErr := exprruntime.New(nil)
	if exprErr != nil {
		return nil, fmt.Errorf("create expression runtime: %w", exprErr)
	}

	keywordToRuleIndexes := make(map[string][]int)
	noKeywordIndexes := make([]int, 0)
	for ruleIndex, rule := range rulesBySpecificity {
		if len(rule.Keywords) == 0 {
			noKeywordIndexes = append(noKeywordIndexes, ruleIndex)
			continue
		}
		for _, keyword := range rule.Keywords {
			keyword = strings.ToLower(keyword)
			indexes := keywordToRuleIndexes[keyword]
			// A rule may repeat a keyword with different casing. Dispatch it once.
			if len(indexes) == 0 || indexes[len(indexes)-1] != ruleIndex {
				keywordToRuleIndexes[keyword] = append(indexes, ruleIndex)
			}
		}
	}
	keywords := make([]string, 0, len(keywordToRuleIndexes))
	for keyword := range keywordToRuleIndexes {
		keywords = append(keywords, keyword)
	}
	sort.Strings(keywords)
	keywordRuleIndexes := make([][]int, len(keywords))
	for patternID, keyword := range keywords {
		keywordRuleIndexes[patternID] = keywordToRuleIndexes[keyword]
	}
	d := &Detector{
		maxDecodeDepth:      settings.maxDecodeDepth,
		matchContext:        settings.matchContext,
		minimumConfidence:   settings.minimumConfidence,
		validationEnabled:   settings.validationEnabled,
		analysisEnabled:     settings.analysisEnabled,
		validationOptions:   settings.validation,
		ignoreAllowComments: settings.ignoreAllowComments,
		ignoredSecrets:      settings.ignoredSecrets,
		excludedPaths:       slices.Clone(settings.excludedPaths),
		jobs:                settings.jobs,
		logger:              settings.logger,
		configPath:          cfg.Path,
		globalFilterExpr:    cfg.Filter,
		prefilter:           ahocorasick.Compile(keywords, true),
		exprRuntime:         exprRuntime,
		validationRuntime:   validationRuntime,
		validationPrograms:  make(map[string]exprruntime.Program),
		analysisPrograms:    make(map[string]exprruntime.Program),
		filterPrograms:      make(map[string]exprruntime.Program),
		rulesBySpecificity:  rulesBySpecificity,
		ruleIndexByID:       ruleIndexByID,
		keywordRuleIndexes:  keywordRuleIndexes,
		noKeywordIndexes:    noKeywordIndexes,
	}
	if settings.validationEnabled {
		d.validationExtractEmpty = settings.validation.ExtractEmpty
		d.validationStatusFilter = make(map[report.ValidationStatus]struct{}, len(settings.validation.Statuses))
		for _, status := range settings.validation.Statuses {
			d.validationStatusFilter[status] = struct{}{}
		}
	}
	d.candidatePool.New = func() any {
		return &ruleCandidates{marked: make([]bool, len(d.rulesBySpecificity))}
	}
	exprRuntime.SetTokenCounterProvider(d.tokenCounterInstance)

	// Compile only the global prefilter so sources can use it before scanning.
	// Finding filters and per-rule expressions compile lazily on first candidate.
	if cfg.Prefilter != "" {
		program, compileErr := exprRuntime.CompilePrefilter(cfg.Prefilter)
		if compileErr != nil {
			return nil, fmt.Errorf("compile global prefilter: %w", compileErr)
		}
		d.prefilterProgram = program
	}

	if settings.precompile {
		if err := d.compileAll(); err != nil {
			return nil, err
		}
	}

	return d, nil
}

func validateValidationOptions(options ValidationOptions, runtime *exprruntime.Runtime) error {
	if options.Workers < 0 {
		return errors.New("validation workers must be non-negative")
	}
	if options.Timeout < 0 {
		return errors.New("validation timeout must be non-negative")
	}
	for _, status := range options.Statuses {
		switch status {
		case report.ValidationStatusNone,
			report.ValidationStatusValid,
			report.ValidationStatusNeedsValidation,
			report.ValidationStatusInvalid,
			report.ValidationStatusRevoked,
			report.ValidationStatusUnknown,
			report.ValidationStatusError:
		default:
			return fmt.Errorf("invalid validation status %q", status)
		}
	}
	if runtime == nil {
		var err error
		runtime, err = exprruntime.New(nil)
		if err != nil {
			return fmt.Errorf("create validation runtime: %w", err)
		}
	}
	if err := runtime.SetValidationRequestLimits(exprruntime.ValidationRequestLimits{
		MaxRequestsPerTarget:    options.MaxRequestsPerTarget,
		RequestsPerSecond:       options.RequestsPerSecond,
		RequestsPerSecondByRule: options.RequestsPerSecondByRule,
	}); err != nil {
		return fmt.Errorf("invalid validation request limits: %w", err)
	}
	return nil
}

func (d *Detector) compileAll() error {
	if _, _, err := d.globalFilterProgram(); err != nil {
		return err
	}
	for _, rule := range d.rulesBySpecificity {
		if rule.Regex != nil {
			if err := rule.Regex.Compile(); err != nil {
				return fmt.Errorf("compile rule %q regex: %w", rule.RuleID, err)
			}
		}
		if rule.Path != nil {
			if err := rule.Path.Compile(); err != nil {
				return fmt.Errorf("compile rule %q path regex: %w", rule.RuleID, err)
			}
		}
		if _, _, err := d.ruleFilterProgram(rule); err != nil {
			return err
		}
		if _, _, err := d.validationProgram(rule.RuleID); err != nil {
			return err
		}
		if _, _, err := d.analysisProgram(rule.RuleID); err != nil {
			return err
		}
	}
	return nil
}

func (d *Detector) newValidationPool(ctx context.Context) (*validate.Pool, error) {
	if !d.ValidationEnabled() {
		return nil, nil
	}
	options := d.validationOptions
	runtime, err := exprruntime.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create validation runtime: %w", err)
	}
	runtime.AllowedEnv = exprruntime.ParseValidationEnvAllowlist(options.ValidationEnvVars)
	if options.Timeout > 0 {
		runtime.SetHTTPClient(&http.Client{Timeout: options.Timeout})
	}
	if err := runtime.SetValidationRequestLimits(exprruntime.ValidationRequestLimits{
		MaxRequestsPerTarget:    options.MaxRequestsPerTarget,
		RequestsPerSecond:       options.RequestsPerSecond,
		RequestsPerSecondByRule: options.RequestsPerSecondByRule,
	}); err != nil {
		return nil, fmt.Errorf("configure validation request limits: %w", err)
	}
	workers := options.Workers
	if workers <= 0 {
		workers = 10
	}
	pool := validate.NewPoolContext(ctx, workers, runtime)
	pool.Debug = options.Debug
	return pool, nil
}

// ValidationEnabled reports whether scans will validate matching findings.
func (d *Detector) ValidationEnabled() bool {
	return d != nil && d.validationEnabled && d.validationRuntime != nil
}

// AnalysisEnabled reports whether scans will analyze valid credentials.
func (d *Detector) AnalysisEnabled() bool {
	if d == nil || !d.analysisEnabled || d.validationRuntime == nil {
		return false
	}
	for _, rule := range d.rulesBySpecificity {
		if rule.AnalyzeExpr != "" {
			return true
		}
	}
	return false
}

func (d *Detector) tokenCounterInstance() *tokenizer.Counter {
	d.tokenCounterOnce.Do(func() {
		counter, err := tokenizer.Default()
		if err != nil {
			d.logger.Warn("could not initialize cl100k_base tokenizer", "error", err)
			return
		}
		d.tokenCounter = counter
	})
	return d.tokenCounter
}

func (d *Detector) globalFilterProgram() (exprruntime.Program, bool, error) {
	if d.globalFilterExpr == "" {
		return nil, false, nil
	}
	d.filterProgramM.Lock()
	defer d.filterProgramM.Unlock()
	if d.globalFilter != nil {
		return d.globalFilter, true, nil
	}
	prg, err := d.exprRuntime.CompileFilter(d.globalFilterExpr, nil)
	if err != nil {
		return nil, false, fmt.Errorf("compiling global filter: %w", err)
	}
	d.globalFilter = prg
	return prg, true, nil
}

func (d *Detector) validationProgram(ruleID string) (exprruntime.Program, bool, error) {
	if d.validationRuntime == nil {
		return nil, false, nil
	}
	d.validationProgramM.Lock()
	defer d.validationProgramM.Unlock()

	ruleIndex, ok := d.ruleIndexByID[ruleID]
	if !ok {
		return nil, false, nil
	}
	rule := d.rulesBySpecificity[ruleIndex]
	if rule.ValidateExpr == "" {
		return nil, false, nil
	}
	if prg := d.validationPrograms[ruleID]; prg != nil {
		return prg, true, nil
	}
	prg, err := d.validationRuntime.CompileValidation(rule.ValidateExpr)
	if err != nil {
		return nil, false, fmt.Errorf("compiling rule %s validation: %w", ruleID, err)
	}
	d.validationPrograms[ruleID] = prg
	return prg, true, nil
}

func (d *Detector) analysisProgram(ruleID string) (exprruntime.Program, bool, error) {
	if !d.AnalysisEnabled() {
		return nil, false, nil
	}
	d.analysisProgramM.Lock()
	defer d.analysisProgramM.Unlock()

	ruleIndex, ok := d.ruleIndexByID[ruleID]
	if !ok {
		return nil, false, nil
	}
	rule := d.rulesBySpecificity[ruleIndex]
	if rule.AnalyzeExpr == "" {
		return nil, false, nil
	}
	if prg := d.analysisPrograms[ruleID]; prg != nil {
		return prg, true, nil
	}
	prg, err := d.validationRuntime.CompileAnalysis(rule.AnalyzeExpr)
	if err != nil {
		return nil, false, fmt.Errorf("compiling rule %s analysis: %w", ruleID, err)
	}
	d.analysisPrograms[ruleID] = prg
	return prg, true, nil
}

func (d *Detector) ruleFilterProgram(r config.Rule) (exprruntime.Program, bool, error) {
	d.filterProgramM.Lock()
	defer d.filterProgramM.Unlock()

	if r.Filter == "" {
		return nil, false, nil
	}
	cacheKey := r.RuleID + "\x00" + r.Filter
	if prg := d.filterPrograms[cacheKey]; prg != nil {
		return prg, true, nil
	}
	prg, err := d.exprRuntime.CompileFilter(r.Filter, nil)
	if err != nil {
		return nil, false, fmt.Errorf("compiling rule %s filter: %w", r.RuleID, err)
	}
	d.filterPrograms[cacheKey] = prg
	return prg, true, nil
}

// SkipFunc returns a sources.SkipFunc callback that evaluates the config's
// prefilter program against fragment attributes. Pass it to a source's
// ShouldSkip field to filter fragments before their contents are loaded. It
// returns nil when no prefilter is configured.
func (d *Detector) SkipFunc() sources.SkipFunc {
	prg := d.prefilterProgram
	if prg == nil && len(d.excludedPaths) == 0 {
		return nil
	}
	return func(attrs map[string]string) bool {
		if d.pathExcluded(attrs[sources.AttrPath]) {
			return true
		}
		if prg != nil {
			skip, err := d.exprRuntime.EvalPrefilter(prg, attrs)
			if err != nil {
				d.logger.Warn("prefilter eval error; not skipping", "error", err)
				return false
			}
			return skip
		}
		return false
	}
}

func (d *Detector) pathExcluded(path string) bool {
	for _, excluded := range d.excludedPaths {
		if path != "" && samePath(path, excluded) {
			return true
		}
	}
	return false
}

func rulePathMatchesFragment(pathRule *blregexp.Regexp, fragment sources.Fragment) bool {
	path := fragment.Attr(sources.AttrPath)
	return path != "" && pathRule != nil && pathRule.MatchString(path)
}

func newPathOnlyFinding(r config.Rule, fragment sources.Fragment) report.Finding {
	path := fragment.Attr(sources.AttrPath)
	finding := report.Finding{
		RuleID:          r.RuleID,
		Description:     r.Description,
		Match:           "file detected: " + path,
		Tags:            append([]string{}, r.Tags...),
		RuleSpecificity: r.Specificity,
	}
	finding.SetAttributes(fragment.Attributes)
	if r.Confidence != "" {
		finding.Confidence = r.Confidence
	}
	return finding
}

// promoteConfidence moves the value written by filter.setConfidence from the
// mutable expression attributes into Finding's typed field.
func promoteConfidence(finding *report.Finding, findingMap map[string]any) {
	value, ok := finding.Attributes[confidence.Attribute]
	if !ok {
		return
	}
	finding.Confidence = value
	delete(finding.Attributes, confidence.Attribute)
	findingMap["confidence"] = value
}

// Run executes the pipeline and yields findings and recoverable source errors.
// Findings are not retained. Result order is not guaranteed. Concurrent calls
// on the same Detector are safe but execute sequentially.
func (d *Detector) Run(ctx context.Context, source sources.Source) iter.Seq[Result] {
	return func(yield func(Result) bool) {
		if d == nil {
			_ = yield(Result{Err: errors.New("detector is nil")})
			return
		}
		_ = d.run(ctx, source, yield)
	}
}

// Scan executes the pipeline, passes each finding to handler, and returns a
// per-call summary. Recoverable source errors are joined. Returning an error
// from handler stops the scan. A nil handler discards findings.
func (d *Detector) Scan(ctx context.Context, source sources.Source, handler Handler) (ScanSummary, error) {
	if d == nil {
		return ScanSummary{}, errors.New("detector is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var scanErr error
	summary := d.run(ctx, source, func(result Result) bool {
		if result.Err != nil {
			scanErr = errors.Join(scanErr, result.Err)
			return true
		}
		if handler != nil {
			if err := handler(result.Finding); err != nil {
				scanErr = errors.Join(scanErr, fmt.Errorf("handle finding: %w", err))
				return false
			}
		}
		return true
	})
	if err := ctx.Err(); err != nil && !errors.Is(scanErr, err) {
		scanErr = errors.Join(scanErr, err)
	}
	return summary, scanErr
}

type scanState struct {
	bytes       atomic.Uint64
	summary     ScanSummary
	ruleTimings *ruletiming.Collector
}

func (d *Detector) run(ctx context.Context, source sources.Source, yield func(Result) bool) (summary ScanSummary) {
	d.scanMu.Lock()
	defer d.scanMu.Unlock()

	state := scanState{summary: ScanSummary{
		ValidationCounts: make(map[report.ValidationStatus]int),
	}}
	if source == nil {
		_ = yield(Result{Err: errors.New("pipeline: nil source")})
		return state.summary
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state.ruleTimings = ruletiming.FromContext(ctx)

	runCtx, cancel := context.WithCancel(ctx)
	validationPool, err := d.newValidationPool(runCtx)
	if err != nil {
		cancel()
		_ = yield(Result{Err: err})
		return state.summary
	}

	workerCount := d.jobCount()
	resultsCh := make(chan Result, workerCount)
	defer func() {
		cancel()
		for range resultsCh {
		}
		state.summary.BytesInspected = state.bytes.Load()
		summary = state.summary
	}()

	emit := func(result Result) error {
		select {
		case <-runCtx.Done():
			return errStopIteration
		case resultsCh <- result:
			return nil
		}
	}
	if validationPool != nil {
		validationPool.Emit = func(finding report.Finding) {
			_ = emit(Result{Finding: finding})
		}
	}
	go func() {
		defer close(resultsCh)

		fragmentsCh := make(chan sources.Fragment, workerCount)
		var workers sync.WaitGroup
		workers.Add(workerCount)
		for range workerCount {
			go func() {
				defer workers.Done()
				for fragment := range fragmentsCh {
					if err := d.scanFragment(runCtx, fragment, emit, validationPool, &state); err != nil {
						if !isPipelineStop(err) {
							_ = emit(Result{Err: err})
						}
						cancel()
						return
					}
				}
			}()
		}

		sourceErr := source.Fragments(runCtx, func(fragment sources.Fragment, fragmentErr error) error {
			if fragmentErr != nil {
				if isPipelineStop(fragmentErr) {
					return errStopIteration
				}
				return emit(Result{Err: fragmentErr})
			}
			if len(fragment.Raw) == 0 && fragment.Attr(sources.AttrPath) == "" {
				return nil
			}
			select {
			case <-runCtx.Done():
				return errStopIteration
			case fragmentsCh <- fragment:
				return nil
			}
		})
		close(fragmentsCh)
		workers.Wait()

		if validationPool != nil {
			validationPool.Close()
			hits, misses := validationPool.Stats()
			d.logger.Debug("validation cache stats",
				"http_requests", misses,
				"cache_hits", hits,
			)
			if d.AnalysisEnabled() {
				analysisHits, analysisMisses := validationPool.AnalysisStats()
				d.logger.Debug("analysis cache stats",
					"evaluations", analysisMisses,
					"cache_hits", analysisHits,
				)
			}
		}
		if sourceErr != nil && !isPipelineStop(sourceErr) {
			_ = emit(Result{Err: sourceErr})
		}
	}()

	for result := range resultsCh {
		if isPipelineStop(result.Err) {
			continue
		}
		if result.Err == nil {
			if !d.validationExtractEmpty {
				result.Finding.Validation.Metadata = stripEmptyMeta(result.Finding.Validation.Metadata)
			}
			status := result.Finding.Validation.Status
			if status != report.ValidationStatusNone {
				state.summary.ValidationCounts[status]++
			}
			if len(d.validationStatusFilter) > 0 {
				if _, ok := d.validationStatusFilter[status]; !ok {
					continue
				}
			}
			state.summary.Findings++
		}
		if !yield(result) {
			return state.summary
		}
	}
	return state.summary
}

func isPipelineStop(err error) bool {
	return errors.Is(err, errStopIteration) || errors.Is(err, context.Canceled)
}

func (d *Detector) jobCount() int {
	if d.jobs > 0 {
		return d.jobs
	}
	return max(runtime.GOMAXPROCS(0), 1)
}

func (d *Detector) scanFragment(
	ctx context.Context,
	fragment sources.Fragment,
	emit func(Result) error,
	validationPool *validate.Pool,
	state *scanState,
) error {
	for _, finding := range d.detectFragmentWithState(ctx, fragment, state) {
		if validationPool != nil {
			if prg, ok, err := d.validationProgram(finding.RuleID); err != nil {
				return err
			} else if ok {
				analysisProgram, _, analysisErr := d.analysisProgram(finding.RuleID)
				if analysisErr != nil {
					return analysisErr
				}
				if err := validationPool.SubmitWithAnalysisContext(ctx, finding, prg, analysisProgram); err != nil {
					if errors.Is(err, context.Canceled) {
						return errStopIteration
					}
					return err
				}
				continue
			}
		}
		if err := emit(Result{Finding: finding}); err != nil {
			return err
		}
	}
	return nil
}

// DetectString scans content and returns its findings. It is a convenience for
// callers that do not need source errors, validation, or a scan summary.
func (d *Detector) DetectString(content string) []report.Finding {
	if d == nil {
		return nil
	}
	// d.scanMu.Lock()
	// defer d.scanMu.Unlock()
	return d.detectFragment(context.Background(), sources.Fragment{
		Raw: content,
	})
}

func (d *Detector) detectFragment(ctx context.Context, fragment sources.Fragment) []report.Finding {
	return d.detectFragmentWithState(ctx, fragment, nil)
}

func (d *Detector) detectFragmentWithState(ctx context.Context, fragment sources.Fragment, state *scanState) []report.Finding {
	// Ensure default fields are properly set
	fragment.SetDefaults()

	// Skip configuration and policy files to prevent self-scanning.
	if path := fragment.Attr(sources.AttrPath); path != "" {
		if samePath(path, d.configPath) || d.pathExcluded(path) {
			return nil
		}
	}

	var ruleTimings *ruletiming.Collector
	if state != nil {
		state.bytes.Add(uint64(len(fragment.Raw)))
		ruleTimings = state.ruleTimings
	}

	findings := []report.Finding{}

	// setup variables to handle different decoding passes
	currentRaw := fragment.Raw
	encodedSegments := []*codec.EncodedSegment{}
	currentDecodeDepth := 0
	decoder := codec.NewDecoder()

ScanLoop:
	for {
		select {
		case <-ctx.Done():
			break ScanLoop
		default:
			candidates := d.candidatePool.Get().(*ruleCandidates)
			// A rule is a candidate when any of its keywords matched. The bitmap
			// deduplicates rules referenced by multiple matching keywords.
			d.prefilter.Visit(currentRaw, func(patternID, _, _ int) bool {
				for _, ruleIndex := range d.keywordRuleIndexes[patternID] {
					candidates.marked[ruleIndex] = true
				}
				return true
			})
			// Always include rules that have no keywords.
			for _, ruleIndex := range d.noKeywordIndexes {
				candidates.marked[ruleIndex] = true
			}

			for ruleIndex, rule := range d.rulesBySpecificity {
				if !candidates.marked[ruleIndex] {
					continue
				}
				select {
				case <-ctx.Done():
					clear(candidates.marked)
					d.candidatePool.Put(candidates)
					break ScanLoop
				default:
					// A path-only rule cannot produce a new result after decoding content
					// or for later chunks of the same file. Keep missing attributes eligible
					// so fragments from sources other than File retain their existing behavior.
					if rule.Regex == nil && (currentDecodeDepth > 0 || fragment.Attr(sources.AttrFSFirstFragment) == "false") {
						continue
					}
					for _, finding := range d.detectFragmentWithRuleTimed(ruleTimings, fragment, currentRaw, rule, encodedSegments, findings) {
						if confidence.Meets(finding.Confidence, d.minimumConfidence) {
							findings = append(findings, finding)
						}
					}
				}
			}
			// Pool entries must be blank because later scans may run on any goroutine.
			clear(candidates.marked)
			d.candidatePool.Put(candidates)

			// increment the depth by 1 as we start our decoding pass
			currentDecodeDepth++

			// stop the loop if we've hit our max decoding depth
			if currentDecodeDepth > d.maxDecodeDepth {
				break ScanLoop
			}

			// decode the currentRaw for the next pass
			currentRaw, encodedSegments = decoder.Decode(currentRaw, encodedSegments)

			// stop the loop when there's nothing else to decode
			if len(encodedSegments) == 0 {
				break ScanLoop
			}
		}
	}
	findings = d.filter(findings)
	if d.ignoredSecrets == nil {
		return findings
	}
	kept := findings[:0]
	for _, finding := range findings {
		if finding.Secret == "" || !d.ignoredSecrets.Contains(finding.Secret) {
			kept = append(kept, finding)
		}
	}
	return kept
}

func (d *Detector) detectFragmentWithRuleTimed(ruleTimings *ruletiming.Collector,
	fragment sources.Fragment,
	currentRaw string,
	r config.Rule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings []report.Finding) []report.Finding {
	if ruleTimings == nil {
		return d.detectFragmentWithRule(nil, fragment, currentRaw, r, encodedSegments, priorFindings)
	}

	start := time.Now()
	findings := d.detectFragmentWithRule(ruleTimings, fragment, currentRaw, r, encodedSegments, priorFindings)
	ruleTimings.Record(r.RuleID, time.Since(start))
	return findings
}

func snapshotDetectorRules(cfg *config.Config) ([]config.Rule, map[string]int, error) {
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	rules := make([]config.Rule, len(cfg.Rules))
	for i, source := range cfg.Rules {
		rule := source
		rule.Keywords = slices.Clone(source.Keywords)
		rule.Tags = slices.Clone(source.Tags)
		if len(source.Components) > 0 {
			rule.Components = make([]*config.Component, len(source.Components))
			for componentIndex, component := range source.Components {
				copy := *component
				rule.Components[componentIndex] = &copy
			}
		}
		rules[i] = rule
	}
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Specificity > rules[j].Specificity
	})
	indexes := make(map[string]int, len(rules))
	for i, rule := range rules {
		indexes[rule.RuleID] = i
	}
	return rules, indexes, nil
}

// detectFragmentWithRule scans the given fragment for the given rule and returns a list of findings
func (d *Detector) detectFragmentWithRule(ruleTimings *ruletiming.Collector,
	fragment sources.Fragment,
	currentRaw string,
	r config.Rule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings []report.Finding) []report.Finding {
	var (
		findings []report.Finding
		logger   = d.logger
	)

	if r.SkipReport && !fragment.InheritedFromFinding {
		return findings
	}

	// Ensure default fields are properly set
	fragment.SetDefaults()

	if r.Regex == nil {
		// Decoding content cannot change a path-only result.
		if len(encodedSegments) > 0 {
			return findings
		}
		if rulePathMatchesFragment(r.Path, fragment) {
			return append(findings, newPathOnlyFinding(r, fragment))
		}
		return findings
	}

	if r.Path != nil && !rulePathMatchesFragment(r.Path, fragment) {
		// If a rule defines both `path` and `regex`, the normalized fragment path
		// must match before we spend time checking the content regex.
		return findings
	}

	matches := r.Regex.FindAllStringIndex(currentRaw, -1)
	if len(matches) == 0 {
		return findings
	}

	// Lazily compute line offsets — only when we actually need location info.
	var lineOffsets []int
	lineOffsetsComputed := false

	// Reuse the matches slice from above instead of calling FindAllStringIndex again.
	for _, matchIndex := range matches {
		// Extract secret from match
		// Clone to release the fragment.Raw string; substring would keep the
		// whole fragment alive, which uses much more memory.
		secret := strings.Clone(strings.Trim(currentRaw[matchIndex[0]:matchIndex[1]], "\n"))
		filterMatchStartIdx, filterMatchEndIdx := matchIndex[0], matchIndex[1]

		// For any meta data from decoding
		var metaTags []string
		currentLine := ""

		// Check if the decoded portions of the segment overlap with the match
		// to see if its potentially a new match
		if len(encodedSegments) > 0 {
			segments := codec.SegmentsWithDecodedOverlap(encodedSegments, matchIndex[0], matchIndex[1])
			if len(segments) == 0 {
				// This item has already been added to a finding
				continue
			}

			matchIndex = codec.AdjustMatchIndex(segments, matchIndex)
			metaTags = append(metaTags, codec.Tags(segments)...)
			currentLine = codec.CurrentLine(segments, currentRaw)
		} else {
			// Fixes: https://github.com/gitleaks/gitleaks/issues/1352
			// removes the incorrectly following line that was detected by regex expression '\n'
			matchIndex[1] = matchIndex[0] + len(secret)
		}

		// determine location of match. Note that the location
		// in the finding will be the line/column numbers of the _match_
		// not the _secret_, which will be different if the secretGroup
		// value is set for this rule
		if !lineOffsetsComputed {
			lineOffsets = computeLineOffsets(fragment.Raw)
			lineOffsetsComputed = true
		}

		loc := location(lineOffsets, fragment.Raw, matchIndex)

		tags := append([]string{}, r.Tags...)
		if len(metaTags) > 0 {
			tags = append(tags, metaTags...)
		}

		prevFragmentEndLine := fragment.StartLine - 1
		finding := report.Finding{
			RuleID:          r.RuleID,
			Description:     r.Description,
			Line:            strings.Clone(fragment.Raw[loc.startLineIndex:loc.endLineIndex]),
			Match:           secret,
			Secret:          secret,
			Tags:            tags,
			RuleSpecificity: r.Specificity,
			Location: report.Location{
				StartLine:   prevFragmentEndLine + loc.startLine,
				EndLine:     prevFragmentEndLine + loc.endLine,
				StartColumn: loc.startColumn,
				EndColumn:   loc.endColumn,
			},
		}
		finding.SetAttributes(fragment.Attributes)
		if r.Confidence != "" {
			finding.Confidence = r.Confidence
		}

		// TODO eventually move this git specific bit into somewhere... better?
		platform := finding.Attr(sources.AttrGitPlatform)
		remoteURL := finding.Attr(sources.AttrGitRemoteURL)
		if platform != "" && remoteURL != "" {
			if link := createScmLink(platform, remoteURL, finding); link != "" {
				finding.SetAttr(sources.AttrURL, link)
			}
		}

		// move to filter?
		if !d.ignoreAllowComments && containsAllowSignature(finding.Line) {
			logTrace(logger, "skipping finding: allow signature found", "finding", finding.Secret)
			continue
		}
		if currentLine == "" {
			currentLine = finding.Line
		}

		// Set the value of |secret|, if the pattern contains at least one capture group.
		// (The first element is the full match, hence we check >= 2.)
		groups := r.Regex.FindStringSubmatch(finding.Secret)
		if len(groups) >= 2 {
			if r.SecretGroup > 0 {
				if len(groups) <= r.SecretGroup {
					// Config validation should prevent this
					continue
				}
				finding.Secret = groups[r.SecretGroup]
			} else {
				// If |secretGroup| is not set, we will use the first suitable capture group.
				for _, s := range groups[1:] {
					if len(s) > 0 {
						finding.Secret = s
						break
					}
				}
			}

			// Extract named capture groups for use as template variables.
			names := r.Regex.SubexpNames()
			captures := make(map[string]string)
			for i, name := range names {
				if i > 0 && name != "" && i < len(groups) && groups[i] != "" {
					captures[name] = strings.Clone(groups[i])
				}
			}
			if len(captures) > 0 {
				finding.CaptureGroups = captures
			}
		}

		if len(priorFindings) > 0 && d.isSuppressedByHigherSpecificityFinding(finding, priorFindings) {
			continue
		}

		entropy := shannonEntropy(finding.Secret)

		hasGlobalFilter := d.globalFilterExpr != ""
		hasRuleFilter := r.Filter != ""
		// Validation/filter expressions need context text in the finding map.
		if r.ValidateExpr != "" || r.AnalyzeExpr != "" || hasGlobalFilter || hasRuleFilter {
			finding.SetExprContext(strings.Clone(contextwindow.Extract(fragment.Raw, matchIndex, contextwindow.Spec{
				Mode:        contextwindow.ModeBox,
				LinesBefore: 20,
				LinesAfter:  20,
				ColsBefore:  350,
				ColsAfter:   350,
			})))
		}

		// Build finding map once, only when at least one filter program is compiled.
		var findingMap map[string]any
		if hasGlobalFilter || hasRuleFilter {
			if finding.Attributes == nil {
				finding.Attributes = make(map[string]string)
			}
			findingMap = make(map[string]any, 12)
			for key, value := range finding.ToExprMap() {
				findingMap[key] = value
			}
			findingMap["entropy"] = strconv.FormatFloat(entropy, 'g', -1, 64)
			findingMap["fragment_raw"] = currentRaw
			findingMap["match_start_idx"] = filterMatchStartIdx
			findingMap["match_end_idx"] = filterMatchEndIdx
			findingMap["match_line_start_idx"] = 0
			findingMap["match_line_end_idx"] = len(currentRaw)
			if newline := strings.LastIndexAny(currentRaw[:filterMatchStartIdx], "\r\n"); newline >= 0 {
				findingMap["match_line_start_idx"] = newline + 1
			}
			if newline := strings.IndexAny(currentRaw[filterMatchEndIdx:], "\r\n"); newline >= 0 {
				findingMap["match_line_end_idx"] = filterMatchEndIdx + newline
			}
			// For decoded segments, currentLine carries the decoded line text
			// (via codec.CurrentLine). The old checkFindingAllowed used this for
			// regexTarget="line". Preserve that behaviour in the Expr path.
			if currentLine != "" {
				findingMap["line"] = currentLine
			}
		}
		// Global filter: Expr path (attributes + finding).
		if prg, ok, err := d.globalFilterProgram(); err != nil {
			logger.Warn("global filter compile error", "error", err)
		} else if ok {
			skip, err := d.exprRuntime.EvalFilter(prg, findingMap, finding.Attributes)
			promoteConfidence(&finding, findingMap)
			if err != nil {
				logger.Warn("global filter eval error", "error", err)
			} else if skip {
				logTrace(logger, "skipping finding: global filter", "finding", finding.Secret)
				continue
			}
		}

		// Rule filter: Expr path (includes entropy and token-efficiency checks).
		if prg, ok, err := d.ruleFilterProgram(r); err != nil {
			logger.Warn("rule filter compile error", "error", err)
		} else if ok {
			skip, err := d.exprRuntime.EvalFilter(prg, findingMap, finding.Attributes)
			promoteConfidence(&finding, findingMap)
			if err != nil {
				logger.Warn("rule filter eval error", "error", err)
			} else if skip {
				logTrace(logger, "skipping finding: rule filter", "finding", finding.Secret)
				continue
			}
		}

		if !d.matchContext.IsZero() {
			finding.MatchContext = strings.Clone(contextwindow.Extract(fragment.Raw, matchIndex, d.matchContext))
		}
		findings = append(findings, finding)
	}

	// Handle component rules (multi-part rules).
	if fragment.InheritedFromFinding || len(r.Components) == 0 {
		return findings
	}

	return d.processComponents(ruleTimings, fragment, currentRaw, r, encodedSegments, findings, logger)
}

// processComponents attaches nearby component matches and enforces required components.
func (d *Detector) processComponents(ruleTimings *ruletiming.Collector, fragment sources.Fragment, currentRaw string, r config.Rule, encodedSegments []*codec.EncodedSegment, primaryFindings []report.Finding, logger *slog.Logger) []report.Finding {
	if len(primaryFindings) == 0 {
		logger.Debug("no primary findings to process for components")
		return primaryFindings
	}

	// Pre-collect each component rule's findings once per fragment.
	allComponentFindings := make(map[string][]report.Finding)
	componentWindows := make(map[string]contextwindow.Spec, len(r.Components))

	for _, component := range r.Components {
		window, err := contextwindow.Parse(component.Within)
		if err != nil {
			logger.Error("invalid component within value", "error", err, "rule_id", component.RuleID, "within", component.Within)
			continue
		}
		componentWindows[component.RuleID] = window

		ruleIndex, ok := d.ruleIndexByID[component.RuleID]
		if !ok {
			logger.Error("component rule not found in config", "rule_id", component.RuleID)
			continue
		}
		rule := d.rulesBySpecificity[ruleIndex]

		// Mark fragment as inherited to prevent infinite recursion
		inheritedFragment := fragment
		inheritedFragment.InheritedFromFinding = true

		componentFindings := d.detectFragmentWithRuleTimed(ruleTimings, inheritedFragment, currentRaw, rule, encodedSegments, nil)
		allComponentFindings[component.RuleID] = componentFindings

		logger.Debug("collected component rule findings",
			"rule_id", component.RuleID,
			"findings", len(componentFindings),
		)
	}

	var finalFindings []report.Finding

	// Process each primary finding against the pre-collected component findings.
	for _, primaryFinding := range primaryFindings {
		var componentFindings []*report.ComponentFinding

		for _, component := range r.Components {
			foundComponentFindings, exists := allComponentFindings[component.RuleID]
			if !exists {
				continue
			}
			window := componentWindows[component.RuleID]

			for _, found := range foundComponentFindings {
				if withinProximity(fragment.Raw, fragment.StartLine, primaryFinding, found, window) {
					componentFindings = append(componentFindings, &report.ComponentFinding{
						RuleID:          found.RuleID,
						Optional:        component.Optional,
						Line:            found.Line,
						Match:           found.Match,
						Secret:          found.Secret,
						CaptureGroups:   found.CaptureGroups,
						Location:        found.Location,
						RuleSpecificity: found.RuleSpecificity,
					})
				}
			}
		}

		if d.hasAllRequiredComponents(componentFindings, r.Components) {
			newFinding := primaryFinding
			newFinding.BuildComponentSets(componentFindings, maxComponentSets)
			finalFindings = append(finalFindings, newFinding)

			logger.Debug("multi-part rule satisfied",
				"primary_rule", r.RuleID,
				"primary_line", primaryFinding.Location.StartLine,
				"component_count", len(componentFindings),
			)
		}
	}

	return finalFindings
}

// hasAllRequiredComponents checks that every required component has a nearby match.
func (d *Detector) hasAllRequiredComponents(componentFindings []*report.ComponentFinding, components []*config.Component) bool {
	foundRules := make(map[string]bool)
	for _, finding := range componentFindings {
		foundRules[finding.RuleID] = true
	}

	for _, component := range components {
		if !component.Optional && !foundRules[component.RuleID] {
			return false
		}
	}

	return true
}

func withinProximity(raw string, fragmentStartLine int, primary, component report.Finding, window contextwindow.Spec) bool {
	if window.IsZero() {
		return true
	}

	switch window.Mode {
	case contextwindow.ModeCols:
		lineStarts := rawLineStarts(raw)
		primaryStart, ok := findingStartOffset(lineStarts, fragmentStartLine, primary)
		if !ok {
			return false
		}
		primaryEnd, ok := findingEndOffset(lineStarts, fragmentStartLine, primary)
		if !ok {
			return false
		}
		componentStart, ok := findingStartOffset(lineStarts, fragmentStartLine, component)
		if !ok {
			return false
		}
		return componentStart >= max(primaryStart-window.ColsBefore, 0) &&
			componentStart < min(primaryEnd+window.ColsAfter, len(raw))

	case contextwindow.ModeBox:
		if component.Location.StartLine < primary.Location.StartLine-window.LinesBefore ||
			component.Location.StartLine > primary.Location.EndLine+window.LinesAfter {
			return false
		}
		if primary.Location.StartLine == primary.Location.EndLine && (window.ColsBefore > 0 || window.ColsAfter > 0) {
			componentColumn := component.Location.StartColumn - 1
			windowStart := max(primary.Location.StartColumn-1-window.ColsBefore, 0)
			windowEnd := primary.Location.EndColumn + window.ColsAfter
			return componentColumn >= windowStart && componentColumn < windowEnd
		}
		return true

	default:
		return false
	}
}

func rawLineStarts(raw string) []int {
	starts := []int{0}
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func findingStartOffset(lineStarts []int, fragmentStartLine int, finding report.Finding) (int, bool) {
	line := finding.Location.StartLine - fragmentStartLine
	if line < 0 || line >= len(lineStarts) || finding.Location.StartColumn < 1 {
		return 0, false
	}
	return lineStarts[line] + finding.Location.StartColumn - 1, true
}

func findingEndOffset(lineStarts []int, fragmentStartLine int, finding report.Finding) (int, bool) {
	line := finding.Location.EndLine - fragmentStartLine
	if line < 0 || line >= len(lineStarts) || finding.Location.EndColumn < 0 {
		return 0, false
	}
	return lineStarts[line] + finding.Location.EndColumn, true
}
