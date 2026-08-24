package detect

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/internal/validate"
	"github.com/betterleaks/betterleaks/logging"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"

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

var (
	// A cl100k tokenizer owns a large immutable vocabulary. Initialize one shared
	// instance so concurrent detectors do not duplicate that memory; construction
	// bypasses tiktoken-go's unsynchronized package-global loader.
	tokenizerOnce   sync.Once
	sharedTokenizer *tiktoken.Tiktoken
)

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
	marked          []bool
	matchSpanStates []ruleMatchSpanState
	matchSpanEpoch  uint32
	decoder         codec.Decoder
}

// scanWorkspace is owned by one long-lived detection worker. Keeping the rule
// bitmap and decoder here removes shared-pool traffic from the fragment hot
// path while preserving a pooled compatibility path for direct Detect calls.
type scanWorkspace struct {
	candidates ruleCandidates
}

const maxPooledCandidateMapEntries = 64

func (d *Detector) newScanWorkspace() *scanWorkspace {
	return &scanWorkspace{
		candidates: ruleCandidates{
			marked:          make([]bool, len(d.rulesBySpecificity)),
			matchSpanStates: make([]ruleMatchSpanState, len(d.rulesBySpecificity)),
		},
	}
}

func getStringMap(pool *sync.Pool, capacity int) map[string]string {
	if pooled := pool.Get(); pooled != nil {
		return pooled.(map[string]string)
	}
	return make(map[string]string, capacity)
}

func putStringMap(pool *sync.Pool, values map[string]string) {
	if len(values) > maxPooledCandidateMapEntries {
		return
	}
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
	if len(values) > maxPooledCandidateMapEntries {
		return
	}
	clear(values)
	pool.Put(values)
}

// Detector is the main detector struct
type Detector struct {
	// Config is retained for caller introspection and reporting. Detection uses
	// the immutable runtime snapshot built by NewDetector; modifying Config after
	// construction has no effect on scans and is unsupported.
	Config *config.Config

	// MaxDecodeDepth limits how many recursive decoding passes are allowed
	MaxDecodeDepth int

	// MatchContext specifies how much context to extract around a match.
	MatchContext contextwindow.Spec

	// ValidationStatusFilter, when non-empty, restricts which findings Run
	// yields. Parsed from --validation-status.
	ValidationStatusFilter map[string]struct{}

	// MinConfidence suppresses classified findings below this level.
	MinConfidence string

	// ValidationCounts tracks how many findings were returned for each
	// ValidationStatus value. Populated by the Run consumer;
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

	// prefilterProgram is compiled once during construction. Keeping it on the
	// detector leaves Config as data and gives SkipFunc a stable program even if
	// the caller later mutates the config.
	prefilterProgram exprruntime.Program
	globalFilterExpr string
	configPath       string

	// path to baseline
	baselinePath string

	// gitleaksIgnore
	gitleaksIgnore map[string]struct{}

	TotalBytes atomic.Uint64

	// RuleTimings records per-rule diagnostic timings when diagnostics are enabled.
	RuleTimings *RuleTimingCollector

	// DetectWorkers limits concurrent fragment detection. Zero uses GOMAXPROCS.
	DetectWorkers int

	exprRuntime *exprruntime.Runtime

	// validationRuntime evaluates per-rule validation expressions. It is nil when
	// validation is disabled or no rules have ValidateExpr. Run owns its workers.
	validationRuntime  *exprruntime.Runtime
	validationEnabled  bool
	validationWorkers  int
	validationDebug    bool
	validationProgramM sync.Mutex
	validationPrograms map[string]exprruntime.Program
	globalFilterOnce   sync.Once
	globalFilter       exprruntime.Program
	globalFilterErr    error
	filterProgramM     sync.Mutex
	filterPrograms     sync.Map // rule ID -> filterProgramResult

	// rulesBySpecificity contains an immutable runtime snapshot of every rule in
	// descending specificity order. Its positions are the shared index space
	// used by candidate slices, so it must not change after construction.
	rulesBySpecificity []config.Rule
	ruleIndexByID      map[string]int

	// keywordRuleIndexes maps each Aho-Corasick pattern ID to the positions in
	// rulesBySpecificity of rules that use that keyword. Precomputing this avoids
	// keyword strings and map lookups while scanning each fragment.
	keywordRuleIndexes   [][]int
	keywordRuleSpanPlans [][]matchSpanPlan

	// ruleMatchSpanEligible records which rules provably contain a literal
	// anchor keyword on every regex path. Individual plans may still leave an
	// unbounded prefix or suffix open to the fragment edge.
	ruleMatchSpanEligible []bool

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

	// Redact controls baseline comparison against redacted reports. Presentation
	// redaction belongs to the caller and is not performed by Detector.Run.
	Redact uint

	// Run owns mutable counters and per-scan validation state. Detect methods
	// remain independently concurrency-safe, but overlapping Run calls are not.
	runActive atomic.Bool
}

// NewDetector creates a new Detector.
// Construction starts no background work: workers are created only while Run
// is consumed. Per-rule expressions compile lazily on first use.
func NewDetector(cfg *config.Config, valOpts ValidationOptions) (*Detector, error) {
	if cfg == nil {
		return nil, errors.New("detect: config is required")
	}
	rulesBySpecificity, ruleIndexByID, snapshotErr := snapshotDetectorRules(cfg)
	if snapshotErr != nil {
		return nil, fmt.Errorf("detect: invalid config: %w", snapshotErr)
	}
	var validationRuntime *exprruntime.Runtime
	if valOpts.Enabled {
		for _, rule := range rulesBySpecificity {
			if rule.ValidateExpr == "" {
				continue
			}
			var validationErr error
			validationRuntime, validationErr = exprruntime.New(nil)
			if validationErr != nil {
				return nil, fmt.Errorf("detect: create validation runtime: %w", validationErr)
			}
			break
		}
		if validationRuntime != nil {
			validationRuntime.AllowedEnv = exprruntime.ParseValidationEnvAllowlist(valOpts.ValidationEnvVars)
		}
	}
	exprRuntime, exprErr := exprruntime.New(nil)
	if exprErr != nil {
		return nil, fmt.Errorf("detect: create expression runtime: %w", exprErr)
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
			// Duplicate/case-variant keywords in one rule need only one dispatch
			// entry. Rules are visited contiguously, so the last index is enough.
			if len(indexes) == 0 || indexes[len(indexes)-1] != ruleIndex {
				keywordToRuleIndexes[keyword] = append(indexes, ruleIndex)
			}
		}
	}
	keywords := maps.Keys(keywordToRuleIndexes)
	sort.Strings(keywords)
	ruleSpanPlans := make([]ruleMatchSpanPlan, len(rulesBySpecificity))
	ruleMatchSpanEligible := make([]bool, len(rulesBySpecificity))
	for ruleIndex, rule := range rulesBySpecificity {
		if plan, ok := analyzeRuleMatchSpans(rule); ok {
			ruleSpanPlans[ruleIndex] = plan
			ruleMatchSpanEligible[ruleIndex] = true
		}
	}
	keywordRuleIndexes := make([][]int, len(keywords))
	keywordRuleSpanPlans := make([][]matchSpanPlan, len(keywords))
	for patternID, keyword := range keywords {
		indexes := keywordToRuleIndexes[keyword]
		keywordRuleIndexes[patternID] = indexes
		plans := make([]matchSpanPlan, len(indexes))
		for dispatchIndex, ruleIndex := range indexes {
			plans[dispatchIndex] = ruleSpanPlans[ruleIndex].keywords[keyword]
		}
		keywordRuleSpanPlans[patternID] = plans
	}
	d := &Detector{
		gitleaksIgnore:         make(map[string]struct{}),
		ValidationCounts:       make(map[report.ValidationStatus]int),
		Config:                 cfg,
		configPath:             cfg.Path,
		globalFilterExpr:       cfg.Filter,
		prefilter:              ahocorasick.Compile(keywords, true),
		rulesBySpecificity:     rulesBySpecificity,
		ruleIndexByID:          ruleIndexByID,
		keywordRuleIndexes:     keywordRuleIndexes,
		keywordRuleSpanPlans:   keywordRuleSpanPlans,
		ruleMatchSpanEligible:  ruleMatchSpanEligible,
		noKeywordIndexes:       noKeywordIndexes,
		exprRuntime:            exprRuntime,
		validationRuntime:      validationRuntime,
		validationEnabled:      valOpts.Enabled && validationRuntime != nil,
		validationPrograms:     make(map[string]exprruntime.Program),
		ValidationExtractEmpty: valOpts.ExtractEmpty,
	}
	d.candidatePool.New = func() any {
		return &ruleCandidates{
			marked:          make([]bool, len(d.rulesBySpecificity)),
			matchSpanStates: make([]ruleMatchSpanState, len(d.rulesBySpecificity)),
		}
	}
	exprRuntime.SetTokenizerProvider(d.Tokenizer)

	// Configuration is data only; the detector owns the compiled program and
	// keeps it on the same runtime used for evaluation.
	if cfg.Prefilter != "" {
		program, compileErr := exprRuntime.CompilePrefilter(cfg.Prefilter)
		if compileErr != nil {
			return nil, fmt.Errorf("detect: compile filters: %w", compileErr)
		}
		d.prefilterProgram = program
	}

	// Configure validation once; Run creates and owns the worker pool.
	if valOpts.Enabled && validationRuntime != nil {
		if valOpts.Timeout > 0 {
			validationRuntime.SetHTTPClient(&http.Client{Timeout: valOpts.Timeout})
		}
		if err := validationRuntime.SetValidationRequestLimits(exprruntime.ValidationRequestLimits{
			MaxRequestsPerTarget:    valOpts.MaxRequestsPerTarget,
			RequestsPerSecond:       valOpts.RequestsPerSecond,
			RequestsPerSecondByRule: valOpts.RequestsPerSecondByRule,
		}); err != nil {
			return nil, fmt.Errorf("detect: configure validation request limits: %w", err)
		}
		workers := valOpts.Workers
		if workers <= 0 {
			workers = 10
		}
		d.validationWorkers = workers
		d.validationDebug = valOpts.Debug

	} else if valOpts.Enabled && validationRuntime == nil {
		logging.Warn().Msg("validation enabled but no rules have validation expressions")
	}
	if valOpts.StatusFilter != "" {
		d.ValidationStatusFilter = make(map[string]struct{})
		for status := range strings.SplitSeq(valOpts.StatusFilter, ",") {
			status = strings.ToLower(strings.TrimSpace(status))
			if status == "" {
				continue
			}
			if !validValidationStatusFilter(status) {
				return nil, fmt.Errorf("detect: unknown validation status %q", status)
			}
			d.ValidationStatusFilter[status] = struct{}{}
		}
	}

	return d, nil
}

func validValidationStatusFilter(status string) bool {
	switch report.ValidationStatus(status) {
	case report.ValidationStatusValid,
		report.ValidationStatusNeedsValidation,
		report.ValidationStatusInvalid,
		report.ValidationStatusRevoked,
		report.ValidationStatusUnknown,
		report.ValidationStatusError:
		return true
	default:
		return status == "none"
	}
}

// ValidationEnabled reports whether Run will validate findings. It intentionally
// does not expose the internal worker pool, whose lifetime belongs to each run.
func (d *Detector) ValidationEnabled() bool {
	return d != nil && d.validationEnabled
}

// Tokenizer returns the BPE tokenizer used for token efficiency filtering.
// May be nil if the tokenizer failed to initialize.
func (d *Detector) Tokenizer() *tiktoken.Tiktoken {
	tokenizerOnce.Do(func() {
		tke, err := newEmbeddedTokenizer()
		if err != nil {
			logging.Warn().Err(err).Msg("Could not initialize cl100k_base tiktokenizer")
			return
		}
		sharedTokenizer = tke
	})
	return sharedTokenizer
}

func (d *Detector) globalFilterProgram() (exprruntime.Program, bool, error) {
	if d.globalFilterExpr == "" {
		return nil, false, nil
	}
	d.globalFilterOnce.Do(func() {
		prg, err := d.exprRuntime.CompileFilter(d.globalFilterExpr, nil)
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

type filterProgramResult struct {
	program exprruntime.Program
	err     error
}

func (d *Detector) ruleFilterProgram(r config.Rule) (exprruntime.Program, bool, error) {
	rule := r
	cacheable := false
	if ruleIndex, ok := d.ruleIndexByID[r.RuleID]; ok {
		rule = d.rulesBySpecificity[ruleIndex]
		cacheable = true
	}
	if rule.Filter == "" {
		return nil, false, nil
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
	if d == nil {
		return nil
	}
	prg := d.prefilterProgram
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
	if d == nil {
		return nil
	}
	prg := d.prefilterProgram
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
		Tags:            slices.Clone(r.Tags),
		Attributes:      maps.Clone(fragment.Attributes),
		RuleSpecificity: r.Specificity,
	}
	if r.Confidence != "" {
		finding.SetAttr(confidence.Attribute, r.Confidence)
	}
	finding.SetFingerprint()
	return finding
}

// NewDetectorDefaultConfig creates a new detector with the default config
func NewDetectorDefaultConfig() (*Detector, error) {
	cfg, err := config.Default()
	if err != nil {
		return nil, err
	}
	return NewDetector(cfg, ValidationOptions{})
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
		if d == nil {
			_ = yield(Result{Err: errors.New("detect: nil detector")})
			return
		}
		if source == nil {
			_ = yield(Result{Err: errors.New("detect: nil source")})
			return
		}
		if !d.runActive.CompareAndSwap(false, true) {
			_ = yield(Result{Err: errors.New("detect: concurrent Run calls are not supported")})
			return
		}
		defer d.runActive.Store(false)
		if ctx == nil {
			ctx = context.Background()
		}

		runCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Bound retained findings to the same order as active detection work.
		resultsCh := make(chan Result, d.detectWorkerCount())

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

		var validationPool *validate.Pool
		if d.ValidationEnabled() {
			validationPool = validate.NewPoolContext(runCtx, d.validationWorkers, d.validationRuntime)
			validationPool.Debug = d.validationDebug
			validationPool.Emit = func(f report.Finding) {
				_ = emit(Result{Finding: f})
			}
		}

		go func() {
			defer close(resultsCh)

			err := d.runSource(runCtx, source, validationPool, emit)

			if validationPool != nil {
				validationPool.Close()

				hits, misses := validationPool.Stats()
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
		pipelineDone := false
		defer func() {
			if pipelineDone {
				return
			}
			// Early termination, including a panic in the consumer's yield function,
			// still has to honor the Run lifetime contract. Cancel production, then
			// wait for workers to drain and release every fragment before returning.
			cancel()
			for range resultsCh {
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

				// Check validation status and if we should filter or not.
				if len(d.ValidationStatusFilter) > 0 {
					if res.Finding.ValidationStatus != "" {
						if _, ok := d.ValidationStatusFilter[string(res.Finding.ValidationStatus)]; !ok {
							continue
						}
					} else if _, ok := d.ValidationStatusFilter["none"]; !ok {
						continue
					}
				}
			}

			if !yield(res) {
				return
			}
		}
		pipelineDone = true
	}
}

func (d *Detector) detectWorkerCount() int {
	if d.DetectWorkers > 0 {
		return d.DetectWorkers
	}
	return max(runtime.GOMAXPROCS(0), 1)
}

// runSource connects source production to the detector's bounded worker pool.
// Each worker owns its scan workspace, and every accepted fragment is released
// exactly once after it is processed or drained during cancellation.
func (d *Detector) runSource(
	ctx context.Context,
	source sources.Source,
	validationPool *validate.Pool,
	emit func(Result) error,
) error {
	if source == nil {
		return errors.New("detect: nil source")
	}
	if emit == nil {
		return errors.New("detect: nil result handler")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workerCount := d.detectWorkerCount()

	// One queued fragment per worker overlaps source I/O with detection while
	// tightly bounding leased file buffers.
	jobs := make(chan *sources.Fragment, workerCount)

	var (
		workers   sync.WaitGroup
		workerErr error
		errOnce   sync.Once
	)
	recordWorkerError := func(err error) {
		if err == nil {
			return
		}
		errOnce.Do(func() {
			workerErr = err
			cancel()
		})
	}

	workers.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		workspace := d.newScanWorkspace()
		go func(workspace *scanWorkspace) {
			defer workers.Done()
			for fragment := range jobs {
				if runCtx.Err() == nil {
					recordWorkerError(d.scanSourceFragment(runCtx, fragment, workspace, validationPool, emit))
				}
				fragment.Release()
			}
		}(workspace)
	}

	sourceErr := source.Fragments(runCtx, func(fragment *sources.Fragment, err error) error {
		if err != nil {
			if fragment != nil {
				defer fragment.Release()
			}
			if emitErr := emit(Result{Err: err}); emitErr != nil {
				recordWorkerError(emitErr)
				return emitErr
			}
			return nil
		}
		if fragment == nil {
			return nil
		}
		if len(fragment.Raw) == 0 && fragment.Attr(sources.AttrPath) == "" {
			fragment.Release()
			return nil
		}

		select {
		case jobs <- fragment:
			return nil
		case <-runCtx.Done():
			fragment.Release()
			return runCtx.Err()
		}
	})
	close(jobs)
	workers.Wait()

	if workerErr != nil {
		if sourceErr != nil && !errors.Is(sourceErr, context.Canceled) {
			return errors.Join(workerErr, sourceErr)
		}
		return workerErr
	}
	if sourceErr == nil {
		return ctx.Err()
	}
	return sourceErr
}

func (d *Detector) scanSourceFragment(
	ctx context.Context,
	fragment *sources.Fragment,
	workspace *scanWorkspace,
	validationPool *validate.Pool,
	emit func(Result) error,
) error {
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

	for _, finding := range d.detectFragmentWithWorkspace(ctx, *fragment, workspace) {
		if d.ignore(finding) {
			continue
		}
		if validationPool != nil {
			if program, ok, err := d.validationProgram(finding.RuleID); err != nil {
				return err
			} else if ok {
				if err := validationPool.SubmitContext(ctx, finding, program); err != nil {
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

// ignore compares a finding against a baseline report or betterleaksignore
// file entries.
func (d *Detector) ignore(finding report.Finding) bool {
	if _, ok := d.gitleaksIgnore[finding.Fingerprint]; ok {
		logging.Debug().
			Str("finding", finding.Secret).
			Str("fingerprint", finding.Fingerprint).
			Msg("skipping finding: fingerprint")
		return true
	}

	// Directory findings already use the global fingerprint, so only Git
	// findings need a second key with the commit prefix removed.
	if finding.Attr(sources.AttrGitSHA) != "" {
		path := finding.Attr(sources.AttrPath)
		var digits [20]byte
		line := strconv.AppendInt(digits[:0], int64(finding.StartLine), 10)
		var fingerprint strings.Builder
		fingerprint.Grow(len(path) + len(finding.RuleID) + len(line) + 2)
		fingerprint.WriteString(path)
		fingerprint.WriteByte(':')
		fingerprint.WriteString(finding.RuleID)
		fingerprint.WriteByte(':')
		_, _ = fingerprint.Write(line)
		if _, ok := d.gitleaksIgnore[fingerprint.String()]; ok {
			logging.Debug().
				Str("finding", finding.Secret).
				Str("fingerprint", finding.Fingerprint).
				Msg("skipping finding: global fingerprint")
			return true
		}
	}

	if d.baseline != nil && !IsNew(finding, d.Redact, d.baseline) {
		logging.Debug().
			Str("finding", finding.Secret).
			Str("fingerprint", finding.Fingerprint).
			Msgf("skipping finding: baseline")
		return true
	}
	return false
}

func (d *Detector) AddBaseline(baselinePath string, source string) error {
	if d == nil {
		return errors.New("detect: nil detector")
	}
	if baselinePath != "" {
		absoluteSource, err := filepath.Abs(source)
		if err != nil {
			return err
		}

		absoluteBaseline, err := filepath.Abs(baselinePath)
		if err != nil {
			return err
		}

		relativeBaseline, err := filepath.Rel(absoluteSource, absoluteBaseline)
		if err != nil {
			return err
		}

		baseline, err := LoadBaseline(baselinePath)
		if err != nil {
			return err
		}

		d.baseline = baseline
		baselinePath = relativeBaseline
	}

	d.baselinePath = baselinePath
	return nil
}

func (d *Detector) AddGitleaksIgnore(gitleaksIgnorePath string) error {
	return d.addGitleaksIgnore(gitleaksIgnorePath)
}

func (d *Detector) addGitleaksIgnore(gitleaksIgnorePath string) error {
	if d == nil {
		return errors.New("detect: nil detector")
	}
	logging.Debug().Str("path", gitleaksIgnorePath).Msgf("found .gitleaksignore file")
	file, err := os.Open(gitleaksIgnorePath)
	if err != nil {
		return err
	}
	pending := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	replacer := strings.NewReplacer("\\", "/")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip lines that start with a comment
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Fingerprints end in :rule-id:start-line. Parse from the right so
		// colons in paths (notably Windows drive letters) remain valid.
		line = replacer.Replace(line)
		lineSeparator := strings.LastIndexByte(line, ':')
		ruleSeparator := -1
		if lineSeparator > 0 {
			ruleSeparator = strings.LastIndexByte(line[:lineSeparator], ':')
		}
		if ruleSeparator <= 0 || ruleSeparator == lineSeparator-1 {
			logging.Warn().Str("fingerprint", line).Msg("Invalid .gitleaksignore entry")
			continue
		}
		if _, err := strconv.ParseUint(line[lineSeparator+1:], 10, 64); err != nil {
			logging.Warn().Str("fingerprint", line).Msg("Invalid .gitleaksignore entry")
			continue
		}
		pending[line] = struct{}{}
	}
	scanErr := scanner.Err()
	closeErr := file.Close()
	if scanErr != nil || closeErr != nil {
		if scanErr != nil {
			scanErr = fmt.Errorf("read ignore file: %w", scanErr)
		}
		if closeErr != nil {
			closeErr = fmt.Errorf("close ignore file: %w", closeErr)
		}
		return errors.Join(scanErr, closeErr)
	}
	if d.gitleaksIgnore == nil {
		d.gitleaksIgnore = make(map[string]struct{}, len(pending))
	}
	for fingerprint := range pending {
		d.gitleaksIgnore[fingerprint] = struct{}{}
	}
	return nil
}

// DetectString scans the given string and returns a list of findings
func (d *Detector) DetectString(content string) []report.Finding {
	if d == nil {
		return nil
	}
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
	if d == nil {
		return nil
	}
	return d.DetectFragment(context.Background(), sources.Fragment{Raw: content})
}

// DetectFragment scans one fragment directly. Use Run when scanning a Source;
// Run additionally applies ignores, baselines, validation, and concurrency.
func (d *Detector) DetectFragment(ctx context.Context, fragment sources.Fragment) []report.Finding {
	if d == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return d.detectFragment(ctx, fragment)
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
		if samePath(path, d.configPath) || (d.baselinePath != "" && samePath(path, d.baselinePath)) {
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
		candidates.resetMatchSpans()
		// Reset all decoder-owned state before publishing the workspace back to
		// the shared pool. Publishing first would let another scan acquire and
		// mutate the decoder concurrently with Release.
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
			current.visit(d.prefilter, func(patternID, end int) bool {
				for dispatchIndex, ruleIndex := range d.keywordRuleIndexes[patternID] {
					candidates.marked[ruleIndex] = true
					if plan := d.keywordRuleSpanPlans[patternID][dispatchIndex]; plan.valid {
						candidates.addMatchSpan(ruleIndex, end, current.len(), plan)
					}
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
				// A span-eligible regex cannot match unless one of its literal
				// anchor keywords matched. Context-only keyword hits still mark the
				// rule above for compatibility, but do not require a regex scan.
				if d.ruleMatchSpanEligible[ruleIndex] && !candidates.hasMatchSpan(ruleIndex) {
					continue
				}
				select {
				case <-ctx.Done():
					break ScanLoop
				default:
					for _, finding := range d.detectContentWithRuleTimed(fragment, &original, &current, rule, encodedSegments, findings, candidates.matchSpanWindow(ruleIndex)) {
						if confidence.Meets(finding.Attr(confidence.Attribute), d.MinConfidence) {
							findings = append(findings, finding)
						}
					}
				}
			}
			// Blank the worker-local bitmap before a recursive decode pass.
			clear(candidates.marked)
			candidates.resetMatchSpans()

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
	priorFindings []report.Finding,
	window matchSpanWindow) []report.Finding {
	if d.RuleTimings == nil {
		return d.detectContentWithRule(fragment, original, current, r, encodedSegments, priorFindings, window)
	}

	start := time.Now()
	findings := d.detectContentWithRule(fragment, original, current, r, encodedSegments, priorFindings, window)
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
		if _, ok := seen[ruleID]; ok {
			continue
		}
		seen[ruleID] = struct{}{}
		ruleIDs = append(ruleIDs, ruleID)
	}
	missing := make([]string, 0, len(cfg.Rules)-len(seen))
	for ruleID := range cfg.Rules {
		if _, ok := seen[ruleID]; ok {
			continue
		}
		missing = append(missing, ruleID)
	}
	sort.Strings(missing)
	ruleIDs = append(ruleIDs, missing...)
	sort.SliceStable(ruleIDs, func(i, j int) bool {
		return cfg.Rules[ruleIDs[i]].Specificity > cfg.Rules[ruleIDs[j]].Specificity
	})
	return ruleIDs
}

func snapshotDetectorRules(cfg *config.Config) ([]config.Rule, map[string]int, error) {
	ruleIDs := orderedRulesBySpecificity(cfg)
	rules := make([]config.Rule, len(ruleIDs))
	indexes := make(map[string]int, len(ruleIDs))
	for i, mapID := range ruleIDs {
		rule := cfg.Rules[mapID]
		if rule.RuleID != mapID {
			return nil, nil, fmt.Errorf("rule map key %q does not match rule ID %q", mapID, rule.RuleID)
		}
		for _, keyword := range rule.Keywords {
			if keyword == "" {
				return nil, nil, fmt.Errorf("rule %q has an empty keyword", rule.RuleID)
			}
		}
		if err := rule.Validate(); err != nil {
			return nil, nil, err
		}

		// Clone mutable slices used while scanning. Regexes are immutable and
		// intentionally shared.
		rule.Keywords = slices.Clone(rule.Keywords)
		rule.Tags = slices.Clone(rule.Tags)
		if len(rule.Components) > 0 {
			components := make([]*config.Component, len(rule.Components))
			for componentIndex, component := range rule.Components {
				copy := *component // Validate above rejects nil components.
				components[componentIndex] = &copy
			}
			rule.Components = components
		}
		rules[i] = rule
		indexes[rule.RuleID] = i
	}
	for _, rule := range rules {
		for _, component := range rule.Components {
			if _, ok := indexes[component.RuleID]; !ok {
				return nil, nil, fmt.Errorf("%s: component rule ID %q does not exist", rule.RuleID, component.RuleID)
			}
		}
	}
	return rules, indexes, nil
}

// detectFragmentWithRule scans the given fragment for the given rule and returns a list of findings
func (d *Detector) detectFragmentWithRule(fragment sources.Fragment,
	currentRaw string,
	r config.Rule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings []report.Finding) []report.Finding {
	original := byteScanContent(fragment.Raw)
	current := stringScanContent(currentRaw)
	return d.detectContentWithRule(fragment, &original, &current, r, encodedSegments, priorFindings, matchSpanWindow{})
}

func (d *Detector) detectContentWithRule(fragment sources.Fragment,
	original, current *scanContent,
	r config.Rule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings []report.Finding,
	window matchSpanWindow) []report.Finding {
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
	matches := current.findAllIndexSpan(r.Regex, window)
	if len(matches) == 0 {
		return findings
	}

	hasGlobalFilter := d.globalFilterExpr != ""
	hasRuleFilter := r.Filter != ""
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
		locationIndex := [2]int{matchIndex[0], matchIndex[1]}
		matchIndex = locationIndex[:]
		// Keep candidate text as views into the fragment while filters run. Text
		// for accepted findings is cloned at the retention boundary below.
		secret := current.trimmedMatch(matchIndex[0], matchIndex[1])
		filterMatchStartIdx, filterMatchEndIdx := matchIndex[0], matchIndex[1]
		var submatchIndex []int
		if hasSubexpressions {
			// Preserve the detector's historical capture semantics. Capture groups
			// are evaluated against the isolated full match, not the surrounding
			// fragment. That distinction matters when a delimiter can either end
			// the match or be consumed by a greedy capture. Index-based matching
			// avoids allocating the isolated match string.
			submatchIndex = current.submatchIndex(r.Regex, filterMatchStartIdx, filterMatchEndIdx)
		}

		// For any meta data from decoding
		var matchedSegments []*codec.EncodedSegment
		var matchedSegmentStorage [8]*codec.EncodedSegment

		// Check if the decoded portions of the segment overlap with the match
		// to see if its potentially a new match
		if len(encodedSegments) > 0 {
			matchedSegments = codec.AppendSegmentsWithDecodedOverlap(
				matchedSegmentStorage[:0], encodedSegments, matchIndex[0], matchIndex[1],
			)
			if len(matchedSegments) == 0 {
				// This item has already been added to a finding
				continue
			}

			matchIndex[0], matchIndex[1] = codec.AdjustMatchRange(
				matchedSegments, matchIndex[0], matchIndex[1],
			)
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
		if len(matchedSegments) > 0 {
			tags = make([]string, len(r.Tags), len(r.Tags)+5)
			copy(tags, r.Tags)
			tags = codec.AppendTags(tags, matchedSegments)
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
		if hasSubexpressions {
			groupCount := len(submatchIndex) / 2
			// The historical detector retried capture extraction on the isolated
			// full match and only changed the secret when that retry matched. A
			// context-sensitive expression (for example, one using \B) can match
			// in the fragment but not in isolation; retain the full match then.
			if groupCount >= 2 {
				selectedGroup := 0
				if r.SecretGroup > 0 {
					if r.SecretGroup >= groupCount {
						// Config validation should prevent this.
						continue
					}
					selectedGroup = r.SecretGroup
					start, end := submatchIndex[r.SecretGroup*2], submatchIndex[r.SecretGroup*2+1]
					if start >= 0 && end > start {
						finding.Secret = current.sliceString(filterMatchStartIdx+start, filterMatchStartIdx+end)
					} else {
						finding.Secret = ""
					}
				} else {
					// If SecretGroup is not set, use the first non-empty capture.
					for group := 1; group < groupCount; group++ {
						start, end := submatchIndex[group*2], submatchIndex[group*2+1]
						if start >= 0 && end > start {
							finding.Secret = current.sliceString(filterMatchStartIdx+start, filterMatchStartIdx+end)
							selectedGroup = group
							break
						}
					}
				}

				// Extract named capture groups for use as template variables.
				var captures map[string]string
				for group, name := range r.Regex.SubexpNames() {
					if group == 0 || group >= groupCount || name == "" {
						continue
					}
					start, end := submatchIndex[group*2], submatchIndex[group*2+1]
					if start < 0 || end <= start {
						continue
					}
					if captures == nil {
						captures = make(map[string]string)
					}
					if group == selectedGroup {
						captures[name] = finding.Secret
					} else {
						captures[name] = current.sliceString(filterMatchStartIdx+start, filterMatchStartIdx+end)
					}
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
		var entropy float64
		if needsEntropyField {
			entropy = shannonEntropy(finding.Secret)
		}

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
		finding.SetFingerprint()
		if finding.Line == "" {
			finding.Line = original.sliceString(loc.startLineIndex, loc.endLineIndex)
		}

		// Validation expressions run only for accepted findings. Preserve their
		// bounded context without paying for it on candidates rejected above.
		if !hasExprContext && r.ValidateExpr != "" {
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
		// A returned finding belongs to the caller. Normal matches borrow the
		// immutable rule tags while filtering; detach them only once the candidate
		// is accepted so caller mutation cannot corrupt the detector snapshot.
		if len(matchedSegments) == 0 {
			finding.Tags = slices.Clone(finding.Tags)
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
	line := finding.Line
	matchContext := finding.MatchContext

	total := len(match) + len(line) + len(matchContext) + len(exprContext)
	if secret != match {
		total += len(secret)
	}
	for _, capture := range finding.CaptureGroups {
		if capture != match && capture != secret {
			total += len(capture)
		}
	}

	var retained strings.Builder
	retained.Grow(total)
	appendText := func(value string) string {
		if value == "" {
			return ""
		}
		start := retained.Len()
		retained.WriteString(value)
		return retained.String()[start:retained.Len()]
	}

	finding.Match = appendText(match)
	if secret == match {
		finding.Secret = finding.Match
	} else {
		finding.Secret = appendText(secret)
	}
	finding.Line = appendText(line)
	finding.MatchContext = appendText(matchContext)
	for name, capture := range finding.CaptureGroups {
		switch capture {
		case match:
			finding.CaptureGroups[name] = finding.Match
		case secret:
			finding.CaptureGroups[name] = finding.Secret
		default:
			finding.CaptureGroups[name] = appendText(capture)
		}
	}
	finding.SetExprContext(appendText(exprContext))
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

		ruleIndex, ok := d.ruleIndexByID[component.RuleID]
		if !ok {
			fragmentRuleEvent(fragment, r.RuleID, logging.Error()).Str("rule-id", component.RuleID).Msg("component rule not found in config")
			continue
		}
		rule := d.rulesBySpecificity[ruleIndex]

		// Mark fragment as inherited to prevent infinite recursion
		inheritedFragment := fragment
		inheritedFragment.InheritedFromFinding = true

		componentFindings := d.detectContentWithRuleTimed(inheritedFragment, original, current, rule, encodedSegments, nil, matchSpanWindow{})
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

		if hasAllRequiredComponents(componentFindings, r.Components) {
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
func hasAllRequiredComponents(componentFindings []*report.ComponentFinding, components []*config.Component) bool {
	for _, component := range components {
		if component.Optional {
			continue
		}
		found := false
		for _, finding := range componentFindings {
			if finding.RuleID == component.RuleID {
				found = true
				break
			}
		}
		if !found {
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
