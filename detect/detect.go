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
	Enabled      bool
	Debug        bool
	Workers      int
	Timeout      time.Duration
	ExtractEmpty bool
	StatusFilter string // comma-separated list of statuses to include
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

	// maxRequiredSets caps the Cartesian product of required-finding combinations
	// to prevent excessive memory use with large multi-part rules.
	maxRequiredSets = 100
)

type Result struct {
	Finding report.Finding
	Err     error
}

type ruleCandidates struct {
	marked []bool
}

// Detector is the main detector struct
type Detector struct {
	// Config is the configuration for the detector
	Config *config.Config

	// MaxDecodeDepths limits how many recursive decoding passes are allowed
	MaxDecodeDepth int

	// MatchContext specifies how much context to extract around a match.
	MatchContext MatchContextSpec

	// ValidationStatusFilter, when non-empty, restricts which findings are
	// printed in verbose mode. Parsed from --validation-status.
	ValidationStatusFilter map[string]struct{}

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

	tokenizer     *tiktoken.Tiktoken
	tokenizerOnce sync.Once

	exprRuntime *exprruntime.Runtime

	// validationRuntime evaluates per-rule validation expressions. Created during
	// construction; nil when no rules have ValidateExpr. The cmd layer may
	// reconfigure the HTTP client/debug settings before evaluation begins.
	validationRuntime  *exprruntime.Runtime
	validationProgramM sync.Mutex
	validationPrograms map[string]exprruntime.Program
	globalFilter       exprruntime.Program
	filterProgramM     sync.Mutex
	filterPrograms     map[string]exprruntime.Program
	rulesBySpecificity []string
	keywordRuleIndexes [][]int
	noKeywordIndexes   []int
	candidatePool      sync.Pool

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
		filterPrograms:         make(map[string]exprruntime.Program),
		ValidationExtractEmpty: valOpts.ExtractEmpty,
	}
	d.rulesBySpecificity = orderedRulesBySpecificity(cfg)
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
		workers := valOpts.Workers
		if workers <= 0 {
			workers = 10
		}
		d.ValidationPool = validate.NewPool(workers, validationRuntime)
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
	if d.Config.Filter == "" {
		return nil, false, nil
	}
	d.filterProgramM.Lock()
	defer d.filterProgramM.Unlock()
	if d.globalFilter != nil {
		return d.globalFilter, true, nil
	}
	prg, err := d.exprRuntime.CompileFilter(d.Config.Filter, nil)
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

func (d *Detector) ruleFilterProgram(r config.Rule) (exprruntime.Program, bool, error) {
	d.filterProgramM.Lock()
	defer d.filterProgramM.Unlock()

	rule := r
	cacheable := false
	if cfgRule, ok := d.Config.Rules[r.RuleID]; ok {
		rule = cfgRule
		cacheable = true
	}
	if rule.Filter == "" {
		return nil, false, nil
	}
	if cacheable {
		if prg := d.filterPrograms[rule.RuleID]; prg != nil {
			return prg, true, nil
		}
	}
	if prg := rule.FilterProgram(); prg != nil {
		return prg, true, nil
	}
	prg, err := d.exprRuntime.CompileFilter(rule.Filter, nil)
	if err != nil {
		return nil, false, fmt.Errorf("compiling rule %s filter: %w", rule.RuleID, err)
	}
	if cacheable {
		d.filterPrograms[rule.RuleID] = prg
	}
	return prg, true, nil
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
		Tags:            r.Tags,
		Attributes:      maps.Clone(fragment.Attributes),
		RuleSpecificity: r.Specificity,
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

			err := source.Fragments(runCtx, func(fragment sources.Fragment, err error) error {
				if err != nil {
					return emit(Result{Err: err})
				}

				logger := fragment.Logger()
				if len(fragment.Raw) == 0 && fragment.Attr(sources.AttrPath) == "" {
					logger.Trace().Msg("skipping empty fragment")
					return nil
				}

				var timer *time.Timer
				if logger.GetLevel() <= zerolog.DebugLevel {
					timer = time.AfterFunc(SlowWarningThreshold, func() {
						logger.Debug().Msgf("Taking longer than %s to inspect fragment", SlowWarningThreshold.String())
					})
				}
				defer func() {
					if timer != nil {
						timer.Stop()
					}
				}()

				findings := d.detectFragment(runCtx, fragment)
				for _, finding := range findings {
					if d.ignore(finding) {
						continue
					}
					if d.ValidationPool != nil {
						if prg, ok, err := d.validationProgram(finding.RuleID); err != nil {
							return err
						} else if ok {
							if err := d.ValidationPool.SubmitContext(runCtx,
								finding,
								prg); err != nil {
								if errors.Is(err, context.Canceled) {
									return errStopIteration
								}
								return err
							}
							continue
						}
					}
					emit(Result{Finding: finding})
				}

				return nil
			})

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
	return d.Detect(sources.Fragment{
		Raw: content,
	})
}

func (d *Detector) detectFragment(ctx context.Context, fragment sources.Fragment) []report.Finding {
	// Skip the config file and baseline file to prevent self-scanning.
	if path := fragment.Attr(sources.AttrPath); path != "" {
		if samePath(path, d.Config.Path) || (d.baselinePath != "" && samePath(path, d.baselinePath)) {
			return nil
		}
	}

	if fragment.Bytes == nil {
		d.TotalBytes.Add(uint64(len(fragment.Raw)))
	}
	d.TotalBytes.Add(uint64(len(fragment.Bytes)))

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

			for ruleIndex, ruleID := range d.rulesBySpecificity {
				if !candidates.marked[ruleIndex] {
					continue
				}
				select {
				case <-ctx.Done():
					clear(candidates.marked)
					d.candidatePool.Put(candidates)
					break ScanLoop
				default:
					rule := d.Config.Rules[ruleID]
					findings = append(findings, d.detectFragmentWithRuleTimed(fragment, currentRaw, rule, encodedSegments, findings)...)
				}
			}
			clear(candidates.marked)
			d.candidatePool.Put(candidates)

			// increment the depth by 1 as we start our decoding pass
			currentDecodeDepth++

			// stop the loop if we've hit our max decoding depth
			if currentDecodeDepth > d.MaxDecodeDepth {
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
	return filter(findings)
}

func (d *Detector) detectFragmentWithRuleTimed(fragment sources.Fragment,
	currentRaw string,
	r config.Rule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings []report.Finding) []report.Finding {
	if d.RuleTimings == nil {
		return d.detectFragmentWithRule(fragment, currentRaw, r, encodedSegments, priorFindings)
	}

	start := time.Now()
	findings := d.detectFragmentWithRule(fragment, currentRaw, r, encodedSegments, priorFindings)
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
	var (
		findings []report.Finding
		logger   = fragment.Logger().With().Str("rule_id", r.RuleID).Logger()
	)

	if r.SkipReport && !fragment.InheritedFromFinding {
		return findings
	}

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

	matches := r.Regex.FindAllStringIndex(currentRaw, -1)
	if len(matches) == 0 {
		return findings
	}

	// Lazily compute newline indices — only when we actually need location info.
	var newlineIndices [][]int
	newlineComputed := false

	// Reuse the matches slice from above instead of calling FindAllStringIndex again.
	for _, matchIndex := range matches {
		// Extract secret from match
		secret := strings.Trim(currentRaw[matchIndex[0]:matchIndex[1]], "\n")
		filterMatchIndex := [2]int{matchIndex[0], matchIndex[1]}

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
		if !newlineComputed {
			newlineIndices = findNewlineIndices(fragment.Raw)
			newlineComputed = true
		}
		loc := location(newlineIndices, fragment.Raw, matchIndex)

		if matchIndex[1] > loc.endLineIndex {
			loc.endLineIndex = matchIndex[1]
		}

		tags := r.Tags
		if len(metaTags) > 0 {
			tags = append(append([]string(nil), r.Tags...), metaTags...)
		}

		finding := report.Finding{
			RuleID:          r.RuleID,
			Description:     r.Description,
			StartLine:       fragment.StartLine + loc.startLine,
			EndLine:         fragment.StartLine + loc.endLine,
			StartColumn:     loc.startColumn,
			EndColumn:       loc.endColumn,
			Line:            fragment.Raw[loc.startLineIndex:loc.endLineIndex],
			Match:           secret,
			Secret:          secret,
			Attributes:      maps.Clone(fragment.Attributes),
			Tags:            tags,
			RuleSpecificity: r.Specificity,
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
		if !d.IgnoreGitleaksAllow && containsAllowSignature(finding.Line) {
			logger.Trace().
				Str("finding", finding.Secret).
				Msg("skipping finding: allow signature found")
			continue
		}
		finding.SyncDeprecatedSourceFields()

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
					captures[name] = groups[i]
				}
			}
			if len(captures) > 0 {
				finding.CaptureGroups = captures
			}
		}

		if len(priorFindings) > 0 && isSuppressedByHigherSpecificityFinding(finding, priorFindings) {
			continue
		}

		// Entropy is always computed — needed for report output regardless of filter path.
		entropy := shannonEntropy(finding.Secret)
		finding.Entropy = float32(entropy)

		finding.SetFingerprint()

		hasGlobalFilter := d.Config.Filter != "" || d.Config.FilterProgram() != nil
		hasRuleFilter := r.Filter != "" || r.FilterProgram() != nil
		// Validation/filter expressions need context text in the finding map.
		if r.ValidateExpr != "" || r.ValidationProgram() != nil || hasGlobalFilter || hasRuleFilter {
			finding.SetExprContext(extractContext(fragment.Raw, matchIndex, MatchContextSpec{
				Mode:        ContextModeBox,
				LinesBefore: 20,
				LinesAfter:  20,
				ColsBefore:  350,
				ColsAfter:   350,
			}))
		}

		// Build finding map once, only when at least one filter program is compiled.
		var findingMap map[string]string
		if hasGlobalFilter || hasRuleFilter {
			findingMap = finding.ToExprMap()
			findingMap["entropy"] = strconv.FormatFloat(entropy, 'g', -1, 64)
			// For decoded segments, currentLine carries the decoded line text
			// (via codec.CurrentLine). The old checkFindingAllowed used this for
			// regexTarget="line". Preserve that behaviour in the Expr path.
			if currentLine != "" {
				findingMap["line"] = currentLine
			}
		}
		matchWindow := exprruntime.MatchWindow{Raw: currentRaw, MatchStart: filterMatchIndex[0], MatchEnd: filterMatchIndex[1]}

		// Global filter: Expr path (attributes + finding).
		if prg, ok, err := d.globalFilterProgram(); err != nil {
			logger.Warn().Err(err).Msg("global filter compile error")
		} else if ok {
			skip, err := d.exprRuntime.EvalFilterWithMatchWindow(prg, findingMap, fragment.Attributes, matchWindow)
			if err != nil {
				logger.Warn().Err(err).Msg("global filter eval error")
			} else if skip {
				logger.Trace().
					Str("finding", finding.Secret).
					Msg("skipping finding: global filter")
				continue
			}
		}

		// Rule filter: Expr path (includes entropy, regex/stopword allowlists, tokenEfficiency).
		if prg, ok, err := d.ruleFilterProgram(r); err != nil {
			logger.Warn().Err(err).Msg("rule filter compile error")
		} else if ok {
			skip, err := d.exprRuntime.EvalFilterWithMatchWindow(prg, findingMap, fragment.Attributes, matchWindow)
			if err != nil {
				logger.Warn().Err(err).Msg("rule filter eval error")
			} else if skip {
				logger.Trace().
					Str("finding", finding.Secret).
					Msg("skipping finding: rule filter")
				continue
			}
		}

		if !d.MatchContext.IsZero() {
			finding.MatchContext = extractContext(fragment.Raw, matchIndex, d.MatchContext)
		}
		findings = append(findings, finding)
	}

	// Handle required rules (multi-part rules)
	if fragment.InheritedFromFinding || len(r.RequiredRules) == 0 {
		return findings
	}

	// Process required rules and create findings with auxiliary findings
	return d.processRequiredRules(fragment, currentRaw, r, encodedSegments, findings, logger)
}

// processRequiredRules handles the logic for multi-part rules with auxiliary findings
func (d *Detector) processRequiredRules(fragment sources.Fragment, currentRaw string, r config.Rule, encodedSegments []*codec.EncodedSegment, primaryFindings []report.Finding, logger zerolog.Logger) []report.Finding {
	if len(primaryFindings) == 0 {
		logger.Debug().Msg("no primary findings to process for required rules")
		return primaryFindings
	}

	// Pre-collect all required rule findings once
	allRequiredFindings := make(map[string][]report.Finding)

	for _, requiredRule := range r.RequiredRules {
		rule, ok := d.Config.Rules[requiredRule.RuleID]
		if !ok {
			logger.Error().Str("rule-id", requiredRule.RuleID).Msg("required rule not found in config")
			continue
		}

		// Mark fragment as inherited to prevent infinite recursion
		inheritedFragment := fragment
		inheritedFragment.InheritedFromFinding = true

		// Call detectRule once for each required rule
		requiredFindings := d.detectFragmentWithRuleTimed(inheritedFragment, currentRaw, rule, encodedSegments, nil)
		allRequiredFindings[requiredRule.RuleID] = requiredFindings

		logger.Debug().
			Str("rule-id", requiredRule.RuleID).
			Int("findings", len(requiredFindings)).
			Msg("collected required rule findings")
	}

	var finalFindings []report.Finding

	// Now process each primary finding against the pre-collected required findings
	for _, primaryFinding := range primaryFindings {
		var requiredFindings []*report.RequiredFinding

		for _, requiredRule := range r.RequiredRules {
			foundRequiredFindings, exists := allRequiredFindings[requiredRule.RuleID]
			if !exists {
				continue // Rule wasn't found earlier, skip
			}

			// Filter findings that are within proximity of the primary finding
			for _, requiredFinding := range foundRequiredFindings {
				if d.withinProximity(primaryFinding, requiredFinding, requiredRule) {
					req := &report.RequiredFinding{
						RuleID:          requiredFinding.RuleID,
						StartLine:       requiredFinding.StartLine,
						EndLine:         requiredFinding.EndLine,
						StartColumn:     requiredFinding.StartColumn,
						EndColumn:       requiredFinding.EndColumn,
						Line:            requiredFinding.Line,
						Match:           requiredFinding.Match,
						Secret:          requiredFinding.Secret,
						CaptureGroups:   requiredFinding.CaptureGroups,
						RuleSpecificity: requiredFinding.RuleSpecificity,
					}
					requiredFindings = append(requiredFindings, req)
				}
			}
		}

		// Check if we have at least one auxiliary finding for each required rule
		if len(requiredFindings) > 0 && d.hasAllRequiredRules(requiredFindings, r.RequiredRules) {
			// Create a finding with auxiliary findings
			newFinding := primaryFinding // Copy the primary finding
			newFinding.BuildRequiredSets(requiredFindings, maxRequiredSets)
			finalFindings = append(finalFindings, newFinding)

			logger.Debug().
				Str("primary-rule", r.RuleID).
				Int("primary-line", primaryFinding.StartLine).
				Int("auxiliary-count", len(requiredFindings)).
				Msg("multi-part rule satisfied")
		}
	}

	return finalFindings
}

// hasAllRequiredRules checks if we have at least one auxiliary finding for each required rule
func (d *Detector) hasAllRequiredRules(auxiliaryFindings []*report.RequiredFinding, requiredRules []*config.Required) bool {
	foundRules := make(map[string]bool)
	// AuxiliaryFinding
	for _, aux := range auxiliaryFindings {
		foundRules[aux.RuleID] = true
	}

	for _, required := range requiredRules {
		if !foundRules[required.RuleID] {
			return false
		}
	}

	return true
}

func (d *Detector) withinProximity(primary, required report.Finding, requiredRule *config.Required) bool {
	// If neither within_lines nor within_columns is set, findings just need to be in the same fragment
	if requiredRule.WithinLines == nil && requiredRule.WithinColumns == nil {
		return true
	}

	// Check line proximity (vertical distance)
	if requiredRule.WithinLines != nil {
		lineDiff := abs(primary.StartLine - required.StartLine)
		if lineDiff > *requiredRule.WithinLines {
			return false
		}
	}

	// Check column proximity (horizontal distance)
	if requiredRule.WithinColumns != nil {
		// Use the start column of each finding for proximity calculation
		colDiff := abs(primary.StartColumn - required.StartColumn)
		if colDiff > *requiredRule.WithinColumns {
			return false
		}
	}

	return true
}
