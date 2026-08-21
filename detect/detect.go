package detect

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkoukk/tiktoken-go"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect/codec"
	"github.com/betterleaks/betterleaks/internal/ahocorasick"
	"github.com/betterleaks/betterleaks/internal/confidence"
	"github.com/betterleaks/betterleaks/internal/contextwindow"
	orchestrate "github.com/betterleaks/betterleaks/internal/detect"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/internal/validate"
	"github.com/betterleaks/betterleaks/logging"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"

	"github.com/fatih/semgroup"
	"github.com/rs/zerolog"
	"golang.org/x/exp/maps"
)

// ValidationOptions controls secret validation behavior.
// Zero value means validation is disabled.
type ValidationOptions struct {
	Enabled                 bool
	Debug                   bool
	Workers                 int
	Timeout                 time.Duration
	ExtractEmpty            bool
	StatusFilter            string // comma-separated list of statuses to include
	MaxRequestsPerTarget    int
	RequestsPerSecond       float64
	RequestsPerSecondByRule map[string]float64
	// ValidationEnvVars lists environment variable names the validation Expr
	// env(...) binding may read (see --validation-env-vars). Parsed into
	// exprruntime.Runtime.AllowedEnv when the validation env is created.
	ValidationEnvVars []string
}

// allowSignatures are comment tags that can be used to ignore findings.
// betterleaks:allow is checked first (preferred), followed by gitleaks:allow for backwards compatibility.
var allowSignatures = []string{"betterleaks:allow", "gitleaks:allow"}

var errStopIteration = errors.New("pipeline: stop iteration")

const (
	// SlowWarningThreshold is the amount of time to wait before logging that a file is slow.
	// This is useful for identifying problematic files and tuning the allowlist.
	SlowWarningThreshold = 5 * time.Second

	// maxComponentSets caps the Cartesian product of component-finding combinations
	// to prevent excessive memory use with large multi-part rules.
	maxComponentSets = 100
)

type Result struct {
	Finding report.Finding
	Err     error
}

type ruleCandidates struct {
	// Indexes match rulesBySpecificity, preserving rule order without building
	// a map and sorted slice for every fragment and decode pass.
	marked  []bool
	decoder codec.Decoder
}

// scanWorkspace is owned by one long-lived detection worker. Keeping the rule
// bitmap and decoder here removes shared-pool traffic from the fragment hot
// path while preserving a pooled compatibility path for direct Detect calls.
type scanWorkspace struct {
	candidates ruleCandidates
}

func (d *Detector) newScanWorkspace() *scanWorkspace {
	return &scanWorkspace{
		candidates: ruleCandidates{marked: make([]bool, len(d.rulesBySpecificity))},
	}
}

func getStringMap(pool *sync.Pool, capacity int) map[string]string {
	if pooled := pool.Get(); pooled != nil {
		return pooled.(map[string]string)
	}
	return make(map[string]string, capacity)
}

func putStringMap(pool *sync.Pool, values map[string]string) {
	clear(values)
	pool.Put(values)
}

func getAnyMap(pool *sync.Pool, capacity int) map[string]any {
	if pooled := pool.Get(); pooled != nil {
		return pooled.(map[string]any)
	}
	return make(map[string]any, capacity)
}

func putAnyMap(pool *sync.Pool, values map[string]any) {
	clear(values)
	pool.Put(values)
}

// Detector is the main detector struct
type Detector struct {
	// Config is the configuration for the detector
	Config *config.Config

	// MaxDecodeDepths limits how many recursive decoding passes are allowed
	MaxDecodeDepth int

	// MatchContext specifies how much context to extract around a match.
	MatchContext contextwindow.Spec

	// ValidationStatusFilter, when non-empty, restricts which findings are
	// printed in verbose mode. Parsed from --validation-status.
	ValidationStatusFilter map[string]struct{}

	// MinConfidence suppresses classified findings below this level.
	MinConfidence string

	// ValidationPool is the expression validation worker pool.
	ValidationPool *validate.Pool

	// ValidationCounts tracks how many findings were returned for each
	// ValidationStatus value. Populated by the Run/DetectSource consumer;
	// safe to read after the scan returns.
	ValidationCounts map[report.ValidationStatus]int

	// ValidationExtractEmpty controls whether empty values from extractors
	// are included in validation output.
	ValidationExtractEmpty bool

	// IgnoreGitleaksAllow is a flag to ignore gitleaks:allow comments.
	IgnoreGitleaksAllow bool

	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter *ahocorasick.Matcher

	// a list of known findings that should be ignored
	baseline []report.Finding

	// path to baseline
	baselinePath string

	// gitleaksIgnore
	gitleaksIgnore map[string]struct{}

	TotalBytes atomic.Uint64

	// RuleTimings records per-rule diagnostic timings when diagnostics are enabled.
	RuleTimings *RuleTimingCollector

	// SourceWorkers limits concurrent source tasks. Zero uses the source default.
	SourceWorkers int

	// DetectWorkers limits concurrent fragment detection. Zero uses GOMAXPROCS.
	DetectWorkers int

	tokenizer     *tiktoken.Tiktoken
	tokenizerOnce sync.Once

	exprRuntime *exprruntime.Runtime

	// validationRuntime evaluates per-rule validation expressions. Created during
	// construction; nil when no rules have ValidateExpr. The cmd layer may
	// reconfigure the HTTP client/debug settings before evaluation begins.
	validationRuntime  *exprruntime.Runtime
	validationProgramM sync.Mutex
	validationPrograms map[string]exprruntime.Program
	globalFilterOnce   sync.Once
	globalFilter       exprruntime.Program
	globalFilterErr    error
	filterProgramM     sync.Mutex
	filterPrograms     sync.Map // rule ID -> filterProgramResult

	// rulesBySpecificity contains every configured rule ID in descending
	// specificity order. Its positions are the shared index space used by the
	// candidate slices below, so it must not change after detector construction.
	rulesBySpecificity []string

	// keywordRuleIndexes maps each Aho-Corasick pattern ID to the positions in
	// rulesBySpecificity of rules that use that keyword. Precomputing this avoids
	// keyword strings and map lookups while scanning each fragment.
	keywordRuleIndexes [][]int

	// noKeywordIndexes contains positions in rulesBySpecificity for rules with no
	// keyword prefilter. These rules are candidates on every scan and decode pass.
	noKeywordIndexes []int

	// candidatePool reuses one bitmap per active scan. A set bit means the rule at
	// the same rulesBySpecificity position should run. Bitmaps must be cleared
	// before they are returned because the pool is shared by concurrent scans.
	candidatePool sync.Pool

	// Candidate attributes and Expr finding maps are callback-scoped scratch.
	// Rejected matches return them immediately; accepted findings retain their
	// private attributes map.
	candidateAttributesPool sync.Pool
	filterFindingMapPool    sync.Pool

	// TODO remove this in v2
	// SkipFindingAppend skips populating the deprecated detector-level findings
	// slice while consuming results from Run.
	//
	// This keeps Run callers from retaining a second compatibility copy of the
	// same findings when they are already consuming results directly.
	//
	// DetectSource intentionally ignores this flag to preserve its historical
	// return contract.
	SkipFindingAppend bool

	// ----------------------------------------------------------------
	// DEPRECATED fields below, to be removed in the next major version
	//
	//
	// report-related settings.
	// Deprecated: detect should not handle reporting
	ReportPath string
	// Deprecated: detect should not handle reporting
	Reporter report.Reporter
	// findings is a slice of report.Findings. This is the result
	// of the detector's scan which can then be used to generate a
	// report.
	// Deprecated: findings are now emitted via the channel returned by Run.
	// This slice is retained only for compatibility with deprecated callers and
	// optional accumulation during Run when SkipFindingAppend is false.
	findings []report.Finding

	// findingsCh is created by DetectSource and carries all ready-to-display
	// findings. A single consumer goroutine reads from it.
	// Deprecated: findings are now emitted via the channel returned by Run;
	// this field is only used for the legacy DetectSource method and will be removed in v2.
	findingsCh chan report.Finding

	// Redact is a flag to redact findings. This is exported
	// so users using gitleaks as a library can set this flag
	// without calling `detector.Start(cmd *cobra.Command)`
	Redact uint

	// verbose is a flag to print findings
	Verbose bool

	// MaxArchiveDepth limits how deep the sources will explore nested archives
	MaxArchiveDepth int

	// files larger than this will be skipped
	MaxTargetMegaBytes int

	// followSymlinks is a flag to enable scanning symlink files
	FollowSymlinks bool

	// NoColor is a flag to disable color output
	NoColor bool

	// LegacyPrint uses the legacy key/value verbose format (typically with Verbose=true).
	LegacyPrint bool

	// commitMutex is to prevent concurrent access to the
	// commit map when adding commits
	// Deprecated: this is only used for logging in git scans and can be removed when the legacy git scan is removed in v2.
	commitMutex *sync.Mutex

	// commitMap is used to keep track of commits that have been scanned.
	// This is only used for logging purposes and git scans.
	// Deprecated: this is only used for logging in git scans and can be removed when the legacy git scan is removed in v2.
	commitMap map[string]bool

	// Sema (https://github.com/fatih/semgroup) controls the concurrency
	// Deprecated: this is only used for git log workers and can be removed when the legacy git scan is removed in v2.
	Sema *semgroup.Group
}

// NewDetectorContext creates a new Detector.
// It compiles global expressions and, when valOpts.Enabled is true, creates the
// validation worker pool. Per-rule expressions compile lazily on first use.
func NewDetectorContext(ctx context.Context, cfg *config.Config, valOpts ValidationOptions) *Detector {
	if cfg == nil {
		// TODO in v2 use NewDetector(ctx context.Context, cfg *config.Config, valOpts ValidationOptions) (*Detector, error)
		// Could be logging.Error?
		logging.Fatal().Msg("config is required to create detector")
		return nil
	}
	// Compile validation programs (no-op if no rules have ValidateExpr).
	validationRuntime, validationErr := cfg.CompileValidation()
	if validationErr != nil {
		logging.Fatal().Err(validationErr).Msg("failed to compile validation expressions")
	}
	if validationRuntime != nil {
		validationRuntime.AllowedEnv = exprruntime.ParseValidationEnvAllowlist(valOpts.ValidationEnvVars)
	}
	exprRuntime, exprErr := exprruntime.New(nil)
	if exprErr != nil {
		logging.Fatal().Err(exprErr).Msg("failed to create expr runtime")
	}

	keywords := maps.Keys(cfg.Keywords)
	d := &Detector{
		gitleaksIgnore:         make(map[string]struct{}),
		findings:               make([]report.Finding, 0),
		ValidationCounts:       make(map[report.ValidationStatus]int),
		Config:                 cfg,
		prefilter:              ahocorasick.Compile(keywords, true),
		Sema:                   semgroup.NewGroup(ctx, 40),
		exprRuntime:            exprRuntime,
		validationRuntime:      validationRuntime,
		validationPrograms:     make(map[string]exprruntime.Program),
		ValidationExtractEmpty: valOpts.ExtractEmpty,
	}
	d.rulesBySpecificity = orderedRulesBySpecificity(cfg)
	// The matcher returns stable keyword indexes. Resolve those to rule indexes
	// once so the hot scan loop does not allocate strings or maps.
	d.keywordRuleIndexes = make([][]int, len(keywords))
	ruleIndexes := make(map[string]int, len(d.rulesBySpecificity))
	for i, ruleID := range d.rulesBySpecificity {
		ruleIndexes[ruleID] = i
	}
	for patternID, keyword := range keywords {
		ruleIDs := cfg.KeywordToRules[keyword]
		for _, ruleID := range ruleIDs {
			ruleIndex, ok := ruleIndexes[ruleID]
			if !ok {
				continue
			}
			d.keywordRuleIndexes[patternID] = append(d.keywordRuleIndexes[patternID], ruleIndex)
		}
	}
	for _, ruleID := range cfg.NoKeywordRules {
		ruleIndex, ok := ruleIndexes[ruleID]
		if !ok {
			continue
		}
		d.noKeywordIndexes = append(d.noKeywordIndexes, ruleIndex)
	}
	d.candidatePool.New = func() any {
		return &ruleCandidates{marked: make([]bool, len(d.rulesBySpecificity))}
	}
	exprRuntime.SetTokenizerProvider(d.Tokenizer)

	// Compile only global prefilter programs so they are available before scanning.
	// Global finding filters and per-rule filters compile lazily on first candidate.
	if compileErr := cfg.CompileFilters(nil); compileErr != nil {
		logging.Fatal().Err(compileErr).Msg("failed to compile filters")
	}

	// Set up validation pool when enabled.
	if valOpts.Enabled && validationRuntime != nil {
		if valOpts.Timeout > 0 {
			validationRuntime.SetHTTPClient(&http.Client{Timeout: valOpts.Timeout})
		}
		if err := validationRuntime.SetValidationRequestLimits(exprruntime.ValidationRequestLimits{
			MaxRequestsPerTarget:    valOpts.MaxRequestsPerTarget,
			RequestsPerSecond:       valOpts.RequestsPerSecond,
			RequestsPerSecondByRule: valOpts.RequestsPerSecondByRule,
		}); err != nil {
			logging.Fatal().Err(err).Msg("invalid validation request limits")
		}
		workers := valOpts.Workers
		if workers <= 0 {
			workers = 10
		}
		d.ValidationPool = validate.NewPoolContext(ctx, workers, validationRuntime)
		d.ValidationPool.Debug = valOpts.Debug

		if valOpts.StatusFilter != "" {
			d.ValidationStatusFilter = make(map[string]struct{})
			for s := range strings.SplitSeq(valOpts.StatusFilter, ",") {
				s = strings.TrimSpace(s)
				s = strings.ToLower(s)
				if s != "" {
					d.ValidationStatusFilter[s] = struct{}{}
				}
			}
		}
	} else if valOpts.Enabled && validationRuntime == nil {
		logging.Warn().Msg("validation enabled but no rules have validation expressions")
	}

	return d
}

// Tokenizer returns the BPE tokenizer used for token efficiency filtering.
// May be nil if the tokenizer failed to initialize.
func (d *Detector) Tokenizer() *tiktoken.Tiktoken {
	d.tokenizerOnce.Do(func() {
		tiktoken.SetBpeLoader(&TiktokenLoader{})
		tke, err := tiktoken.GetEncoding("cl100k_base")
		if err != nil {
			logging.Warn().Err(err).Msg("Could not initialize cl100k_base tiktokenizer")
			return
		}
		d.tokenizer = tke
	})
	return d.tokenizer
}

func (d *Detector) globalFilterProgram() (exprruntime.Program, bool, error) {
	configured := d.Config.FilterProgram()
	if d.Config.Filter == "" && configured == nil {
		return nil, false, nil
	}
	d.globalFilterOnce.Do(func() {
		if configured != nil {
			d.globalFilter = configured
			return
		}
		prg, err := d.exprRuntime.CompileFilter(d.Config.Filter, nil)
		if err != nil {
			d.globalFilterErr = fmt.Errorf("compiling global filter: %w", err)
			return
		}
		d.globalFilter = prg
	})
	return d.globalFilter, d.globalFilter != nil, d.globalFilterErr
}

func (d *Detector) validationProgram(ruleID string) (exprruntime.Program, bool, error) {
	if d.validationRuntime == nil {
		return nil, false, nil
	}
	d.validationProgramM.Lock()
	defer d.validationProgramM.Unlock()

	rule, ok := d.Config.Rules[ruleID]
	if !ok || rule.ValidateExpr == "" {
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

type filterProgramResult struct {
	program exprruntime.Program
	err     error
}

func (d *Detector) ruleFilterProgram(r config.Rule) (exprruntime.Program, bool, error) {
	rule := r
	cacheable := false
	if cfgRule, ok := d.Config.Rules[r.RuleID]; ok {
		rule = cfgRule
		cacheable = true
	}
	configured := rule.FilterProgram()
	if rule.Filter == "" && configured == nil {
		return nil, false, nil
	}
	if configured != nil {
		return configured, true, nil
	}
	if cacheable {
		if cached, ok := d.filterPrograms.Load(rule.RuleID); ok {
			result := cached.(filterProgramResult)
			return result.program, result.program != nil, result.err
		}
	}

	// Compilation is cold-path work. Serialize misses so concurrent workers do
	// not compile the same expression, while successful hot-path lookups above
	// remain lock-free.
	d.filterProgramM.Lock()
	defer d.filterProgramM.Unlock()
	if cacheable {
		if cached, ok := d.filterPrograms.Load(rule.RuleID); ok {
			result := cached.(filterProgramResult)
			return result.program, result.program != nil, result.err
		}
	}
	prg, err := d.exprRuntime.CompileFilter(rule.Filter, nil)
	if err != nil {
		err = fmt.Errorf("compiling rule %s filter: %w", rule.RuleID, err)
	}
	if cacheable {
		d.filterPrograms.Store(rule.RuleID, filterProgramResult{program: prg, err: err})
	}
	return prg, prg != nil, err
}

// SkipFunc returns a sources.SkipFunc callback that evaluates the config's
// prefilter program against fragment attributes. Returns nil when no prefilter
// is configured (sources treat nil as "skip nothing").
func (d *Detector) SkipFunc() sources.SkipFunc {
	if d.Config == nil {
		return nil
	}
	prg := d.Config.PrefilterProgram()
	if prg == nil {
		return nil
	}
	return func(attrs map[string]string) bool {
		skip, err := d.exprRuntime.EvalPrefilter(prg, attrs)
		if err != nil {
			logging.Warn().Err(err).Msg("prefilter eval error; not skipping")
			return false
		}
		return skip
	}
}

// PathSkipFunc returns the path-only prefilter callback used by Files. It
// shares the compiled program with SkipFunc but reuses an expression-owned map.
func (d *Detector) PathSkipFunc() sources.PathSkipFunc {
	if d.Config == nil {
		return nil
	}
	prg := d.Config.PrefilterProgram()
	if prg == nil {
		return nil
	}
	return func(path string) bool {
		skip, err := d.exprRuntime.EvalPathPrefilter(prg, path)
		if err != nil {
			logging.Warn().Err(err).Msg("prefilter eval error; not skipping")
			return false
		}
		return skip
	}
}

func rulePathMatchesFragment(pathRule *blregexp.Regexp, fragment sources.Fragment) bool {
	path := fragment.Attr(sources.AttrPath)
	return path != "" && pathRule != nil && pathRule.MatchString(path)
}

func fragmentRuleEvent(fragment sources.Fragment, ruleID string, event *zerolog.Event) *zerolog.Event {
	event.Str("path", fragment.Attr(sources.AttrPath))
	if sha := fragment.Attr(sources.AttrGitSHA); sha != "" {
		event.Str("commit", sha)
	}
	return event.Str("rule_id", ruleID)
}

func newPathOnlyFinding(r config.Rule, fragment sources.Fragment) report.Finding {
	path := fragment.Attr(sources.AttrPath)
	finding := report.Finding{
		RuleID:          r.RuleID,
		Description:     r.Description,
		Match:           "file detected: " + path,
		Tags:            r.Tags,
		Attributes:      maps.Clone(fragment.Attributes),
		RuleSpecificity: r.Specificity,
	}
	if r.Confidence != "" {
		finding.SetAttr(confidence.Attribute, r.Confidence)
	}
	finding.SyncDeprecatedSourceFields()
	return finding
}

// NewDetectorDefaultConfig creates a new detector with the default config
func NewDetectorDefaultConfig() (*Detector, error) {
	cfg, err := config.Default()
	if err != nil {
		return nil, err
	}
	d := NewDetector(cfg)
	return d, nil
}

// Run executes the pipeline on the given source and yields results as they are found.
// It returns an iterator of Results, which can be consumed by the caller. We return an iterator to make the API clean.
// You can do things like:
//
//		for result := range detector.Run(ctx, source) {
//	    	// do something
//		}
//
// The context can be used to cancel the scan.
// Internally uses a channel to send results from the scanning goroutine to the caller,
// allowing for concurrent processing of findings as they are discovered.
func (d *Detector) Run(ctx context.Context, source sources.Source) iter.Seq[Result] {
	return func(yield func(Result) bool) {
		if source == nil {
			_ = yield(Result{Err: fmt.Errorf("pipeline: nil source")})
			return
		}
		if ctx == nil {
			ctx = context.Background()
		}

		runCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// main channel for sending results back to the caller (eventually gets consumed by `emit`)
		resultsCh := make(chan Result, 1000)

		if d.ValidationCounts == nil {
			d.ValidationCounts = make(map[report.ValidationStatus]int)
		} else {
			clear(d.ValidationCounts)
		}

		// This function is used to send results back to the caller.
		// It checks for context cancellation and stops the pipeline if the context is done.
		emit := func(res Result) error {
			select {
			case <-runCtx.Done():
				return errStopIteration
			case resultsCh <- res:
				return nil
			}
		}

		// If ValidationPool is set, we want to emit findings from the pool instead of directly from addFinding, so we set the Emit function here.
		if d.ValidationPool != nil {
			d.ValidationPool.Emit = func(f report.Finding) {
				_ = emit(Result{Finding: f})
			}
		}

		go func() {
			defer close(resultsCh)

			err := orchestrate.RunWorkers(
				runCtx,
				source,
				orchestrate.Options{
					SourceWorkers: d.SourceWorkers,
					DetectWorkers: d.DetectWorkers,
				},
				func(_ *sources.Fragment, err error) error {
					return emit(Result{Err: err})
				},
				func() orchestrate.ConsumeFunc {
					workspace := d.newScanWorkspace()
					return func(workerCtx context.Context, fragment *sources.Fragment) error {
						var timer *time.Timer
						if logging.Logger.GetLevel() <= zerolog.DebugLevel {
							logger := fragment.Logger()
							timer = time.AfterFunc(SlowWarningThreshold, func() {
								logger.Debug().Msgf("Taking longer than %s to inspect fragment", SlowWarningThreshold.String())
							})
						}
						defer func() {
							if timer != nil {
								timer.Stop()
							}
						}()

						for _, finding := range d.detectFragmentWithWorkspace(workerCtx, *fragment, workspace) {
							if d.ignore(finding) {
								continue
							}
							if d.ValidationPool != nil {
								if prg, ok, err := d.validationProgram(finding.RuleID); err != nil {
									return err
								} else if ok {
									if err := d.ValidationPool.SubmitContext(workerCtx, finding, prg); err != nil {
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
				},
			)

			if d.ValidationPool != nil {
				d.ValidationPool.Close()

				hits, misses := d.ValidationPool.Stats()
				logging.Debug().
					Uint64("http_requests", misses).
					Uint64("cache_hits", hits).
					Msg("validation cache stats")
			}

			if err != nil &&
				!errors.Is(err, errStopIteration) &&
				!errors.Is(err, context.Canceled) {
				_ = emit(Result{Err: err})
			}
		}()

		// consume results and send to caller via yield
		for res := range resultsCh {
			if res.Err == nil {
				if !d.ValidationExtractEmpty {
					res.Finding.ValidationMeta = stripEmptyMeta(res.Finding.ValidationMeta)
				}
				if res.Finding.ValidationStatus != "" {
					d.ValidationCounts[res.Finding.ValidationStatus]++
				}

				// Check validation status and if we should filter or not
				// Check validation status and if we should filter or not
				if len(d.ValidationStatusFilter) > 0 {
					if res.Finding.ValidationStatus != "" {
						if _, ok := d.ValidationStatusFilter[string(res.Finding.ValidationStatus)]; !ok {
							continue
						}
					} else if _, ok := d.ValidationStatusFilter["none"]; !ok {
						continue
					}
				}

				if !d.SkipFindingAppend {
					d.findings = append(d.findings, res.Finding)
				}
			}

			if !yield(res) {
				cancel()
				// RunWorkers drains and releases every accepted fragment after
				// cancellation. Wait for its result channel to close so iterator
				// consumers never inherit background source work or live leases.
				for range resultsCh {
				}
				return
			}
		}
	}
}

// ignore compares a finding against a baseline report or betterleaksignore
// file entries.
func (d *Detector) ignore(finding report.Finding) bool {
	logger := logging.With().Str("finding", finding.Secret).Logger()
	path := finding.Attributes[sources.AttrPath]
	globalFingerprint := fmt.Sprintf("%s:%s:%d", path, finding.RuleID, finding.StartLine)

	if _, ok := d.gitleaksIgnore[globalFingerprint]; ok {
		logger.Debug().
			Str("fingerprint", finding.Fingerprint).
			Msg("skipping finding: global fingerprint")
		return true
	}

	if _, ok := d.gitleaksIgnore[finding.Fingerprint]; ok {
		logger.Debug().
			Str("fingerprint", finding.Fingerprint).
			Msg("skipping finding: fingerprint")
		return true
	}

	if d.baseline != nil && !IsNew(finding, d.Redact, d.baseline) {
		logger.Debug().
			Str("fingerprint", finding.Fingerprint).
			Msgf("skipping finding: baseline")
		return true
	}
	return false
}

func (d *Detector) AddGitleaksIgnore(gitleaksIgnorePath string) error {
	logging.Debug().Str("path", gitleaksIgnorePath).Msgf("found .gitleaksignore file")
	file, err := os.Open(gitleaksIgnorePath)
	if err != nil {
		return err
	}
	defer func() {
		// https://github.com/securego/gosec/issues/512
		if err := file.Close(); err != nil {
			logging.Warn().Err(err).Msgf("Error closing .gitleaksignore file")
		}
	}()

	scanner := bufio.NewScanner(file)
	replacer := strings.NewReplacer("\\", "/")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip lines that start with a comment
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Normalize the path.
		// TODO: Make this a breaking change in v9.
		s := strings.Split(line, ":")
		switch len(s) {
		case 3:
			// Global fingerprint.
			// `file:rule-id:start-line`
			s[0] = replacer.Replace(s[0])
		case 4:
			// Commit fingerprint.
			// `commit:file:rule-id:start-line`
			s[1] = replacer.Replace(s[1])
		default:
			logging.Warn().Str("fingerprint", line).Msg("Invalid .gitleaksignore entry")
		}
		d.gitleaksIgnore[strings.Join(s, ":")] = struct{}{}
	}
	return nil
}

// DetectString scans the given string and returns a list of findings
func (d *Detector) DetectString(content string) []report.Finding {
	// Keep the convenience API string-backed so callers do not pay for a full
	// string-to-byte copy. Source fragments remain canonically byte-backed.
	return d.detectFragmentContent(
		context.Background(),
		sources.Fragment{},
		stringScanContent(content),
		nil,
	)
}

// DetectBytes scans byte content without materializing a duplicate string.
func (d *Detector) DetectBytes(content []byte) []report.Finding {
	return d.Detect(sources.Fragment{Raw: content})
}

func (d *Detector) detectFragment(ctx context.Context, fragment sources.Fragment) []report.Finding {
	return d.detectFragmentWithWorkspace(ctx, fragment, nil)
}

func (d *Detector) detectFragmentWithWorkspace(ctx context.Context, fragment sources.Fragment, workspace *scanWorkspace) []report.Finding {
	content := byteScanContent(fragment.Raw)
	return d.detectFragmentContent(ctx, fragment, content, workspace)
}

func (d *Detector) detectFragmentContent(ctx context.Context, fragment sources.Fragment, original scanContent, workspace *scanWorkspace) []report.Finding {
	// Ensure default fields are properly set
	fragment.SetDefaults()

	// Skip the config file and baseline file to prevent self-scanning.
	if path := fragment.Attr(sources.AttrPath); path != "" {
		if samePath(path, d.Config.Path) || (d.baselinePath != "" && samePath(path, d.baselinePath)) {
			return nil
		}
	}

	d.TotalBytes.Add(uint64(original.len()))

	var findings []report.Finding

	// setup variables to handle different decoding passes
	current := original
	var encodedSegments []*codec.EncodedSegment
	currentDecodeDepth := 0
	var (
		candidates       *ruleCandidates
		pooledCandidates bool
	)
	if workspace != nil {
		candidates = &workspace.candidates
	} else {
		candidates = d.candidatePool.Get().(*ruleCandidates)
		pooledCandidates = true
	}
	decoder := &candidates.decoder
	defer func() {
		clear(candidates.marked)
		// Reset all decoder-owned state before publishing the workspace back to
		// the shared pool. Putting it first lets another scan acquire and mutate
		// the decoder concurrently with Release.
		decoder.Release()
		if pooledCandidates {
			d.candidatePool.Put(candidates)
		}
	}()

ScanLoop:
	for {
		select {
		case <-ctx.Done():
			break ScanLoop
		default:
			// A rule is a candidate when any of its keywords matched. The bitmap
			// deduplicates rules referenced by multiple matching keywords.
			current.visit(d.prefilter, func(patternID int) bool {
				for _, ruleIndex := range d.keywordRuleIndexes[patternID] {
					candidates.marked[ruleIndex] = true
				}
				return true
			})
			// Always include rules that have no keywords.
			for _, ruleIndex := range d.noKeywordIndexes {
				candidates.marked[ruleIndex] = true
			}

			for ruleIndex, ruleID := range d.rulesBySpecificity {
				if !candidates.marked[ruleIndex] {
					continue
				}
				select {
				case <-ctx.Done():
					break ScanLoop
				default:
					rule := d.Config.Rules[ruleID]
					for _, finding := range d.detectContentWithRuleTimed(fragment, &original, &current, rule, encodedSegments, findings) {
						if confidence.Meets(finding.Attr(confidence.Attribute), d.MinConfidence) {
							findings = append(findings, finding)
						}
					}
				}
			}
			// Blank the worker-local bitmap before a recursive decode pass.
			clear(candidates.marked)

			// increment the depth by 1 as we start our decoding pass
			currentDecodeDepth++

			// stop the loop if we've hit our max decoding depth
			if currentDecodeDepth > d.MaxDecodeDepth {
				break ScanLoop
			}

			// decode the currentRaw for the next pass
			current, encodedSegments = current.decode(decoder, encodedSegments)

			// stop the loop when there's nothing else to decode
			if len(encodedSegments) == 0 {
				break ScanLoop
			}
		}
	}
	return filter(findings)
}

func (d *Detector) detectContentWithRuleTimed(fragment sources.Fragment,
	original, current *scanContent,
	r config.Rule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings []report.Finding) []report.Finding {
	if d.RuleTimings == nil {
		return d.detectContentWithRule(fragment, original, current, r, encodedSegments, priorFindings)
	}

	start := time.Now()
	findings := d.detectContentWithRule(fragment, original, current, r, encodedSegments, priorFindings)
	d.RuleTimings.Record(r.RuleID, time.Since(start))
	return findings
}

func orderedRulesBySpecificity(cfg *config.Config) []string {
	ruleIDs := make([]string, 0, len(cfg.Rules))
	seen := make(map[string]struct{}, len(cfg.Rules))
	for _, ruleID := range cfg.OrderedRules {
		if _, ok := cfg.Rules[ruleID]; !ok {
			continue
		}
		seen[ruleID] = struct{}{}
		ruleIDs = append(ruleIDs, ruleID)
	}
	for ruleID := range cfg.Rules {
		if _, ok := seen[ruleID]; ok {
			continue
		}
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.SliceStable(ruleIDs, func(i, j int) bool {
		return cfg.Rules[ruleIDs[i]].Specificity > cfg.Rules[ruleIDs[j]].Specificity
	})
	return ruleIDs
}

// detectFragmentWithRule scans the given fragment for the given rule and returns a list of findings
func (d *Detector) detectFragmentWithRule(fragment sources.Fragment,
	currentRaw string,
	r config.Rule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings []report.Finding) []report.Finding {
	original := byteScanContent(fragment.Raw)
	current := stringScanContent(currentRaw)
	return d.detectContentWithRule(fragment, &original, &current, r, encodedSegments, priorFindings)
}

func (d *Detector) detectContentWithRule(fragment sources.Fragment,
	original, current *scanContent,
	r config.Rule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings []report.Finding) []report.Finding {
	var findings []report.Finding

	if r.SkipReport && !fragment.InheritedFromFinding {
		return findings
	}

	// Ensure default fields are properly set
	fragment.SetDefaults()

	if r.Path != nil {
		if r.Regex == nil && len(encodedSegments) == 0 {
			if rulePathMatchesFragment(r.Path, fragment) {
				return append(findings, newPathOnlyFinding(r, fragment))
			}
			return findings
		}

		if !rulePathMatchesFragment(r.Path, fragment) {
			// If a rule defines both `path` and `regex`, the normalized fragment path
			// must match before we spend time checking the content regex.
			return findings
		}
	}

	// if path only rule, skip content checks
	if r.Regex == nil {
		return findings
	}

	hasSubexpressions := r.Regex.NumSubexp() > 0
	matches := current.findAllIndex(r.Regex)
	if len(matches) == 0 {
		return findings
	}

	hasGlobalFilter := d.Config.Filter != "" || d.Config.FilterProgram() != nil
	hasRuleFilter := r.Filter != "" || r.FilterProgram() != nil
	globalPrg, globalOK, globalErr := d.globalFilterProgram()
	rulePrg, ruleOK, ruleErr := d.ruleFilterProgram(r)
	needsContext := (globalOK && globalPrg.NeedsContext()) || (ruleOK && rulePrg.NeedsContext())
	needsLine := (globalOK && globalPrg.NeedsLine()) || (ruleOK && rulePrg.NeedsLine())
	needsFragmentRaw := (globalOK && globalPrg.NeedsFragmentRaw()) || (ruleOK && rulePrg.NeedsFragmentRaw())
	needsLocalLine := (globalOK && globalPrg.NeedsLocalLine()) || (ruleOK && rulePrg.NeedsLocalLine())
	needsMatchWindow := (globalOK && globalPrg.NeedsMatchWindow()) || (ruleOK && rulePrg.NeedsMatchWindow())
	needsNearbyContext := (globalOK && globalPrg.NeedsNearbyContext()) || (ruleOK && rulePrg.NeedsNearbyContext())
	needsFinding := func(field string) bool {
		return (globalOK && globalPrg.NeedsFinding(field)) || (ruleOK && rulePrg.NeedsFinding(field))
	}
	needsSecret := needsFinding("secret")
	needsMatch := needsFinding("match")
	needsRuleID := needsFinding("rule_id")
	needsDescription := needsFinding("description")
	needsEntropyField := needsFinding("entropy")
	needsMatchStart := needsFinding("match_start_idx")
	needsMatchEnd := needsFinding("match_end_idx")
	needsMatchLineStart := needsFinding("match_line_start_idx")
	needsMatchLineEnd := needsFinding("match_line_end_idx")
	needsLocalLineValue := needsFinding("local_line")
	needsLocalLineStart := needsFinding("local_line_match_start_idx")
	needsLocalLineEnd := needsFinding("local_line_match_end_idx")
	needsMatchPrefix := needsFinding("match_prefix")
	needsMatchSuffix := needsFinding("match_suffix")
	needsNearbyContextValue := needsFinding("nearby_context")
	needsLinePrefix := needsFinding("line_prefix")

	// Capacity is fixed for this rule/filter pair. Count it once per fragment,
	// rather than populating and boxing the complete compatibility map for every
	// candidate when expressions read only a handful of fields.
	findingMapCapacity := 0
	for _, needed := range [...]bool{
		needsSecret, needsMatch, needsLine, needsRuleID, needsDescription,
		needsContext, needsEntropyField, needsFragmentRaw, needsMatchStart,
		needsMatchEnd, needsMatchLineStart, needsMatchLineEnd,
		needsLocalLineValue, needsLocalLineStart, needsLocalLineEnd,
		needsMatchPrefix, needsMatchSuffix, needsNearbyContextValue, needsLinePrefix,
	} {
		if needed {
			findingMapCapacity++
		}
	}

	// Lazily compute line offsets — only when we actually need location info.
	var lineOffsetBuf *lineOffsetBuffer

	// Reuse the matches slice from above instead of calling FindAllStringIndex again.
	for _, matchIndex := range matches {
		// Keep candidate text as views into the fragment while filters run. Text
		// for accepted findings is cloned at the retention boundary below.
		secret := current.trimmedMatch(matchIndex[0], matchIndex[1])
		filterMatchStartIdx, filterMatchEndIdx := matchIndex[0], matchIndex[1]

		// For any meta data from decoding
		var metaTags []string
		var matchedSegments []*codec.EncodedSegment

		// Check if the decoded portions of the segment overlap with the match
		// to see if its potentially a new match
		if len(encodedSegments) > 0 {
			matchedSegments = codec.SegmentsWithDecodedOverlap(encodedSegments, matchIndex[0], matchIndex[1])
			if len(matchedSegments) == 0 {
				// This item has already been added to a finding
				continue
			}

			matchIndex = codec.AdjustMatchIndex(matchedSegments, matchIndex)
			metaTags = append(metaTags, codec.Tags(matchedSegments)...)
		} else {
			// Fixes: https://github.com/gitleaks/gitleaks/issues/1352
			// removes the incorrectly following line that was detected by regex expression '\n'
			matchIndex[1] = matchIndex[0] + len(secret)
		}

		// determine location of match. Note that the location
		// in the finding will be the line/column numbers of the _match_
		// not the _secret_, which will be different if the secretGroup
		// value is set for this rule
		if lineOffsetBuf == nil {
			lineOffsetBuf = original.lineOffsets()
		}

		loc := locationForLength(lineOffsetBuf.offsets, original.len(), matchIndex)

		tags := r.Tags
		if len(metaTags) > 0 {
			tags = append(append([]string(nil), r.Tags...), metaTags...)
		}

		prevFragmentEndLine := fragment.StartLine - 1
		finding := report.Finding{
			RuleID:      r.RuleID,
			Description: r.Description,
			StartLine:   prevFragmentEndLine + loc.startLine,
			EndLine:     prevFragmentEndLine + loc.endLine,
			StartColumn: loc.startColumn,
			EndColumn:   loc.endColumn,
			Match:       secret,
			Secret:      secret,
			// Use the fragment's read-only attributes while cheap rejection checks
			// run. A private copy is made before filters can mutate confidence and
			// before an accepted finding can outlive the fragment.
			Attributes:      fragment.Attributes,
			Tags:            tags,
			RuleSpecificity: r.Specificity,
		}

		// move to filter?
		hasAllowSignature := false
		if !d.IgnoreGitleaksAllow {
			for _, signature := range allowSignatures {
				if original.contains(loc.startLineIndex, loc.endLineIndex, signature) {
					hasAllowSignature = true
					break
				}
			}
		}
		if hasAllowSignature {
			fragmentRuleEvent(fragment, r.RuleID, logging.Trace()).
				Str("finding", finding.Secret).
				Msg("skipping finding: allow signature found")
			continue
		}
		// Set the value of |secret|, if the pattern contains at least one capture group.
		// (The first element is the full match, hence we check >= 2.)
		if hasSubexpressions {
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
					for _, captured := range groups[1:] {
						if captured != "" {
							finding.Secret = captured
							break
						}
					}
				}

				// Extract named capture groups for use as template variables.
				var captures map[string]string
				for group, name := range r.Regex.SubexpNames() {
					if group == 0 || group >= len(groups) || name == "" || groups[group] == "" {
						continue
					}
					if captures == nil {
						captures = make(map[string]string)
					}
					captures[name] = groups[group]
				}
				finding.CaptureGroups = captures
			}
		}

		if len(priorFindings) > 0 && isSuppressedByHigherSpecificityFinding(finding, priorFindings) {
			continue
		}

		pooledAttributes := hasGlobalFilter || hasRuleFilter
		if pooledAttributes {
			finding.Attributes = getStringMap(&d.candidateAttributesPool, len(fragment.Attributes)+1)
			maps.Copy(finding.Attributes, fragment.Attributes)
		} else {
			finding.Attributes = maps.Clone(fragment.Attributes)
		}
		if r.Confidence != "" {
			finding.SetAttr(confidence.Attribute, r.Confidence)
		}

		// TODO eventually move this git specific bit into somewhere... better?
		platform := finding.Attr(sources.AttrGitPlatform)
		remoteURL := finding.Attr(sources.AttrGitRemoteURL)
		if platform != "" && remoteURL != "" {
			if link := createScmLink(platform, remoteURL, finding); link != "" {
				finding.SetAttr(sources.AttrURL, link)
			}
		}
		finding.SyncDeprecatedSourceFields()

		// Entropy is always computed — needed for report output regardless of filter path.
		entropy := shannonEntropy(finding.Secret)
		finding.Entropy = float32(entropy)

		finding.SetFingerprint()

		// Context construction clips and copies multiple surrounding lines. Most
		// filters never reference it, so only build it before filtering when a
		// compiled filter explicitly needs the field. Validation-only context is
		// delayed until the candidate has survived both filters below.
		var exprContext string
		hasExprContext := false
		if needsContext {
			exprContext = original.extractContext(matchIndex, contextwindow.Spec{
				Mode:        contextwindow.ModeBox,
				LinesBefore: 20,
				LinesAfter:  20,
				ColsBefore:  350,
				ColsAfter:   350,
			})
			finding.SetExprContext(exprContext)
			hasExprContext = true
		}
		// Build finding map once, only when at least one filter program is compiled.
		var findingMap map[string]any
		if hasGlobalFilter || hasRuleFilter {
			if finding.Attributes == nil {
				finding.Attributes = make(map[string]string)
			}
			findingMap = getAnyMap(&d.filterFindingMapPool, findingMapCapacity)
			if needsSecret {
				findingMap["secret"] = finding.Secret
			}
			if needsMatch {
				findingMap["match"] = finding.Match
			}
			if needsLine {
				if finding.Line == "" {
					finding.Line = original.sliceString(loc.startLineIndex, loc.endLineIndex)
				}
				filterLine := finding.Line
				if len(matchedSegments) > 0 {
					filterLine = current.currentLine(matchedSegments)
				}
				findingMap["line"] = filterLine
			}
			if needsRuleID {
				findingMap["rule_id"] = finding.RuleID
			}
			if needsDescription {
				findingMap["description"] = finding.Description
			}
			if needsContext {
				findingMap["context"] = exprContext
			}
			if needsEntropyField {
				findingMap["entropy"] = strconv.FormatFloat(entropy, 'g', -1, 64)
			}
			if needsFragmentRaw {
				findingMap["fragment_raw"] = current.fullText()
			}
			if needsMatchStart {
				findingMap["match_start_idx"] = filterMatchStartIdx
			}
			if needsMatchEnd {
				findingMap["match_end_idx"] = filterMatchEndIdx
			}
			if needsLocalLine || needsMatchLineStart || needsMatchLineEnd {
				matchLineStartIdx := 0
				matchLineEndIdx := current.len()
				if newline := current.lastIndexAnyBefore(filterMatchStartIdx, "\r\n"); newline >= 0 {
					matchLineStartIdx = newline + 1
				}
				if newline := current.indexAnyAfter(filterMatchEndIdx, "\r\n"); newline >= 0 {
					matchLineEndIdx = filterMatchEndIdx + newline
				}
				if needsMatchLineStart {
					findingMap["match_line_start_idx"] = matchLineStartIdx
				}
				if needsMatchLineEnd {
					findingMap["match_line_end_idx"] = matchLineEndIdx
				}
				if needsLocalLine {
					localLine := ""
					if len(matchedSegments) == 0 && matchLineEndIdx-matchLineStartIdx == loc.endLineIndex-loc.startLineIndex {
						if finding.Line == "" {
							finding.Line = original.sliceString(loc.startLineIndex, loc.endLineIndex)
						}
						localLine = finding.Line
					} else {
						localLine = current.sliceString(matchLineStartIdx, matchLineEndIdx)
					}
					if needsLocalLineValue {
						findingMap["local_line"] = localLine
					}
					if needsLocalLineStart {
						findingMap["local_line_match_start_idx"] = filterMatchStartIdx - matchLineStartIdx
					}
					if needsLocalLineEnd {
						findingMap["local_line_match_end_idx"] = filterMatchEndIdx - matchLineStartIdx
					}
				}
			}
			if needsMatchWindow {
				const windowBytes = 8192
				if needsMatchPrefix {
					findingMap["match_prefix"] = current.sliceString(max(filterMatchStartIdx-windowBytes, 0), filterMatchStartIdx)
				}
				if needsMatchSuffix {
					findingMap["match_suffix"] = current.sliceString(filterMatchEndIdx, min(filterMatchEndIdx+windowBytes, current.len()))
				}
			}
			if needsNearbyContext {
				nearbyContext, linePrefix := current.matchSurroundings(filterMatchStartIdx, filterMatchEndIdx, 8192, 6)
				if needsNearbyContextValue {
					findingMap["nearby_context"] = nearbyContext
				}
				if needsLinePrefix {
					findingMap["line_prefix"] = linePrefix
				}
			}
		}
		// Global filter: Expr path (attributes + finding).
		if globalErr != nil {
			fragmentRuleEvent(fragment, r.RuleID, logging.Warn()).Err(globalErr).Msg("global filter compile error")
		} else if globalOK {
			skip, err := d.exprRuntime.EvalFilter(globalPrg, findingMap, finding.Attributes)
			if err != nil {
				fragmentRuleEvent(fragment, r.RuleID, logging.Warn()).Err(err).Msg("global filter eval error")
			} else if skip {
				fragmentRuleEvent(fragment, r.RuleID, logging.Trace()).
					Str("finding", finding.Secret).
					Msg("skipping finding: global filter")
				putAnyMap(&d.filterFindingMapPool, findingMap)
				if pooledAttributes {
					putStringMap(&d.candidateAttributesPool, finding.Attributes)
				}
				continue
			}
		}

		// Rule filter: Expr path (includes entropy, regex/stopword allowlists, tokenEfficiency).
		if ruleErr != nil {
			fragmentRuleEvent(fragment, r.RuleID, logging.Warn()).Err(ruleErr).Msg("rule filter compile error")
		} else if ruleOK {
			skip, err := d.exprRuntime.EvalFilter(rulePrg, findingMap, finding.Attributes)
			if err != nil {
				fragmentRuleEvent(fragment, r.RuleID, logging.Warn()).Err(err).Msg("rule filter eval error")
			} else if skip {
				fragmentRuleEvent(fragment, r.RuleID, logging.Trace()).
					Str("finding", finding.Secret).
					Msg("skipping finding: rule filter")
				putAnyMap(&d.filterFindingMapPool, findingMap)
				if pooledAttributes {
					putStringMap(&d.candidateAttributesPool, finding.Attributes)
				}
				continue
			}
		}
		if findingMap != nil {
			putAnyMap(&d.filterFindingMapPool, findingMap)
		}
		if finding.Line == "" {
			finding.Line = original.sliceString(loc.startLineIndex, loc.endLineIndex)
		}

		// Validation expressions run only for accepted findings. Preserve their
		// bounded context without paying for it on candidates rejected above.
		if !hasExprContext && (r.ValidateExpr != "" || r.ValidationProgram() != nil) {
			exprContext = original.extractContext(matchIndex, contextwindow.Spec{
				Mode:        contextwindow.ModeBox,
				LinesBefore: 20,
				LinesAfter:  20,
				ColsBefore:  350,
				ColsAfter:   350,
			})
			finding.SetExprContext(exprContext)
		}

		if !d.MatchContext.IsZero() {
			finding.MatchContext = original.extractContext(matchIndex, d.MatchContext)
		}
		if !original.byteBacked {
			cloneRetainedFindingText(&finding, exprContext)
		}
		findings = append(findings, finding)
	}
	if lineOffsetBuf != nil {
		putLineOffsets(lineOffsetBuf)
	}

	// Handle component rules (multi-part rules).
	if fragment.InheritedFromFinding || len(r.Components) == 0 {
		return findings
	}

	return d.processContentComponents(fragment, original, current, r, encodedSegments, findings)
}

// cloneRetainedFindingText detaches accepted findings from the fragment-sized
// backing string. Candidate views are safe during synchronous filtering, but a
// returned finding can outlive the pooled source buffer that produced it.
func cloneRetainedFindingText(finding *report.Finding, exprContext string) {
	match := finding.Match
	secret := finding.Secret
	finding.Match = strings.Clone(match)
	if secret == match {
		finding.Secret = finding.Match
	} else {
		finding.Secret = strings.Clone(secret)
	}
	finding.Line = strings.Clone(finding.Line)
	finding.MatchContext = strings.Clone(finding.MatchContext)
	for name, capture := range finding.CaptureGroups {
		finding.CaptureGroups[name] = strings.Clone(capture)
	}
	finding.SetExprContext(strings.Clone(exprContext))
}

// processComponents attaches nearby component matches and enforces required components.
func (d *Detector) processComponents(fragment sources.Fragment, currentRaw string, r config.Rule, encodedSegments []*codec.EncodedSegment, primaryFindings []report.Finding) []report.Finding {
	original := byteScanContent(fragment.Raw)
	current := stringScanContent(currentRaw)
	return d.processContentComponents(fragment, &original, &current, r, encodedSegments, primaryFindings)
}

func (d *Detector) processContentComponents(fragment sources.Fragment, original, current *scanContent, r config.Rule, encodedSegments []*codec.EncodedSegment, primaryFindings []report.Finding) []report.Finding {
	if len(primaryFindings) == 0 {
		fragmentRuleEvent(fragment, r.RuleID, logging.Debug()).Msg("no primary findings to process for components")
		return primaryFindings
	}

	// Pre-collect each component rule's findings once per fragment.
	allComponentFindings := make(map[string][]report.Finding)
	componentWindows := make(map[string]contextwindow.Spec, len(r.Components))

	for _, component := range r.Components {
		window, err := contextwindow.Parse(component.Within)
		if err != nil {
			fragmentRuleEvent(fragment, r.RuleID, logging.Error()).Err(err).Str("rule-id", component.RuleID).Str("within", component.Within).Msg("invalid component within value")
			continue
		}
		componentWindows[component.RuleID] = window

		rule, ok := d.Config.Rules[component.RuleID]
		if !ok {
			fragmentRuleEvent(fragment, r.RuleID, logging.Error()).Str("rule-id", component.RuleID).Msg("component rule not found in config")
			continue
		}

		// Mark fragment as inherited to prevent infinite recursion
		inheritedFragment := fragment
		inheritedFragment.InheritedFromFinding = true

		componentFindings := d.detectContentWithRuleTimed(inheritedFragment, original, current, rule, encodedSegments, nil)
		allComponentFindings[component.RuleID] = componentFindings

		fragmentRuleEvent(fragment, r.RuleID, logging.Debug()).
			Str("rule-id", component.RuleID).
			Int("findings", len(componentFindings)).
			Msg("collected component rule findings")
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
				if withinProximityContent(original, fragment.StartLine, primaryFinding, found, window) {
					componentFindings = append(componentFindings, &report.ComponentFinding{
						RuleID:          found.RuleID,
						Optional:        component.Optional,
						StartLine:       found.StartLine,
						EndLine:         found.EndLine,
						StartColumn:     found.StartColumn,
						EndColumn:       found.EndColumn,
						Line:            found.Line,
						Match:           found.Match,
						Secret:          found.Secret,
						CaptureGroups:   found.CaptureGroups,
						RuleSpecificity: found.RuleSpecificity,
					})
				}
			}
		}

		if d.hasAllRequiredComponents(componentFindings, r.Components) {
			newFinding := primaryFinding
			newFinding.BuildComponentSets(componentFindings, maxComponentSets)
			finalFindings = append(finalFindings, newFinding)

			fragmentRuleEvent(fragment, r.RuleID, logging.Debug()).
				Str("primary-rule", r.RuleID).
				Int("primary-line", primaryFinding.StartLine).
				Int("component-count", len(componentFindings)).
				Msg("multi-part rule satisfied")
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
	content := stringScanContent(raw)
	return withinProximityContent(&content, fragmentStartLine, primary, component, window)
}

func withinProximityContent(raw *scanContent, fragmentStartLine int, primary, component report.Finding, window contextwindow.Spec) bool {
	if window.IsZero() {
		return true
	}

	switch window.Mode {
	case contextwindow.ModeCols:
		lineStarts := raw.rawLineStarts()
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
			componentStart < min(primaryEnd+window.ColsAfter, raw.len())

	case contextwindow.ModeBox:
		if component.StartLine < primary.StartLine-window.LinesBefore ||
			component.StartLine > primary.EndLine+window.LinesAfter {
			return false
		}
		if primary.StartLine == primary.EndLine && (window.ColsBefore > 0 || window.ColsAfter > 0) {
			componentColumn := component.StartColumn - 1
			windowStart := max(primary.StartColumn-1-window.ColsBefore, 0)
			windowEnd := primary.EndColumn + window.ColsAfter
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
	line := finding.StartLine - fragmentStartLine
	if line < 0 || line >= len(lineStarts) || finding.StartColumn < 1 {
		return 0, false
	}
	return lineStarts[line] + finding.StartColumn - 1, true
}

func findingEndOffset(lineStarts []int, fragmentStartLine int, finding report.Finding) (int, bool) {
	line := finding.EndLine - fragmentStartLine
	if line < 0 || line >= len(lineStarts) || finding.EndColumn < 0 {
		return 0, false
	}
	return lineStarts[line] + finding.EndColumn, true
}
