package detect

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/http"
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
	// env.get(...) binding may read (see --validation-env-vars). Parsed into
	// exprruntime.Runtime.AllowedEnv when the validation env is created.
	ValidationEnvVars []string
}

// allowSignatures are comment tags that can be used to ignore findings.
// betterleaks:allow is checked first (preferred), followed by gitleaks:allow for backwards compatibility.
var allowSignatures = []string{"betterleaks:allow", "gitleaks:allow"}

var errStopIteration = errors.New("pipeline: stop iteration")

const (
	// SlowWarningThreshold is the amount of time to wait before logging that a file is slow.
	// This is useful for identifying problematic files and tuning the prefilter.
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
	marked []bool
}

// Detector is the main detector struct
type Detector struct {
	// Config is the configuration for the detector
	Config *config.Config

	// MaxDecodeDepths limits how many recursive decoding passes are allowed
	MaxDecodeDepth int

	// MatchContext specifies how much context to extract around a match.
	MatchContext contextwindow.Spec

	// ValidationStatusFilter, when non-empty, restricts which findings Run emits.
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
		ValidationCounts:       make(map[report.ValidationStatus]int),
		Config:                 cfg,
		prefilter:              ahocorasick.Compile(keywords, true),
		exprRuntime:            exprRuntime,
		validationRuntime:      validationRuntime,
		validationPrograms:     make(map[string]exprruntime.Program),
		filterPrograms:         make(map[string]exprruntime.Program),
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

// Run executes the pipeline on the given source and yields results as they are found.
// Findings are not retained by the Detector; callers that need them after Run
// must collect them while consuming the iterator.
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
					res.Finding.Validation.Metadata = stripEmptyMeta(res.Finding.Validation.Metadata)
				}
				if res.Finding.Validation.Status != "" {
					d.ValidationCounts[res.Finding.Validation.Status]++
				}

				// Check validation status and if we should filter or not
				if len(d.ValidationStatusFilter) > 0 {
					if res.Finding.Validation.Status != "" {
						if _, ok := d.ValidationStatusFilter[string(res.Finding.Validation.Status)]; !ok {
							continue
						}
					} else if _, ok := d.ValidationStatusFilter["none"]; !ok {
						continue
					}
				}
			}

			if !yield(res) {
				cancel()
				return
			}
		}
	}
}

// DetectString scans the given string and returns a list of findings
func (d *Detector) DetectString(content string) []report.Finding {
	return d.detectFragment(context.Background(), sources.Fragment{
		Raw: content,
	})
}

func (d *Detector) detectFragment(ctx context.Context, fragment sources.Fragment) []report.Finding {
	// Ensure default fields are properly set
	fragment.SetDefaults()

	// Skip the config file and baseline file to prevent self-scanning.
	if path := fragment.Attr(sources.AttrPath); path != "" {
		if samePath(path, d.Config.Path) {
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
					// A path-only rule cannot produce a new result after decoding content
					// or for later chunks of the same file. Keep missing attributes eligible
					// so fragments from sources other than File retain their existing behavior.
					if rule.Regex == nil && (currentDecodeDepth > 0 || fragment.Attr(sources.AttrFSFirstFragment) == "false") {
						continue
					}
					for _, finding := range d.detectFragmentWithRuleTimed(fragment, currentRaw, rule, encodedSegments, findings) {
						if confidence.Meets(finding.Confidence, d.MinConfidence) {
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
		if !d.IgnoreGitleaksAllow && containsAllowSignature(finding.Line) {
			logger.Trace().
				Str("finding", finding.Secret).
				Msg("skipping finding: allow signature found")
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

		if len(priorFindings) > 0 && isSuppressedByHigherSpecificityFinding(finding, priorFindings) {
			continue
		}

		entropy := shannonEntropy(finding.Secret)

		hasGlobalFilter := d.Config.Filter != "" || d.Config.FilterProgram() != nil
		hasRuleFilter := r.Filter != "" || r.FilterProgram() != nil
		// Validation/filter expressions need context text in the finding map.
		if r.ValidateExpr != "" || r.ValidationProgram() != nil || hasGlobalFilter || hasRuleFilter {
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
			logger.Warn().Err(err).Msg("global filter compile error")
		} else if ok {
			skip, err := d.exprRuntime.EvalFilter(prg, findingMap, finding.Attributes)
			promoteConfidence(&finding, findingMap)
			if err != nil {
				logger.Warn().Err(err).Msg("global filter eval error")
			} else if skip {
				logger.Trace().
					Str("finding", finding.Secret).
					Msg("skipping finding: global filter")
				continue
			}
		}

		// Rule filter: Expr path (includes entropy and token-efficiency checks).
		if prg, ok, err := d.ruleFilterProgram(r); err != nil {
			logger.Warn().Err(err).Msg("rule filter compile error")
		} else if ok {
			skip, err := d.exprRuntime.EvalFilter(prg, findingMap, finding.Attributes)
			promoteConfidence(&finding, findingMap)
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
			finding.MatchContext = strings.Clone(contextwindow.Extract(fragment.Raw, matchIndex, d.MatchContext))
		}
		findings = append(findings, finding)
	}

	// Handle component rules (multi-part rules).
	if fragment.InheritedFromFinding || len(r.Components) == 0 {
		return findings
	}

	return d.processComponents(fragment, currentRaw, r, encodedSegments, findings, logger)
}

// processComponents attaches nearby component matches and enforces required components.
func (d *Detector) processComponents(fragment sources.Fragment, currentRaw string, r config.Rule, encodedSegments []*codec.EncodedSegment, primaryFindings []report.Finding, logger zerolog.Logger) []report.Finding {
	if len(primaryFindings) == 0 {
		logger.Debug().Msg("no primary findings to process for components")
		return primaryFindings
	}

	// Pre-collect each component rule's findings once per fragment.
	allComponentFindings := make(map[string][]report.Finding)
	componentWindows := make(map[string]contextwindow.Spec, len(r.Components))

	for _, component := range r.Components {
		window, err := contextwindow.Parse(component.Within)
		if err != nil {
			logger.Error().Err(err).Str("rule-id", component.RuleID).Str("within", component.Within).Msg("invalid component within value")
			continue
		}
		componentWindows[component.RuleID] = window

		rule, ok := d.Config.Rules[component.RuleID]
		if !ok {
			logger.Error().Str("rule-id", component.RuleID).Msg("component rule not found in config")
			continue
		}

		// Mark fragment as inherited to prevent infinite recursion
		inheritedFragment := fragment
		inheritedFragment.InheritedFromFinding = true

		componentFindings := d.detectFragmentWithRuleTimed(inheritedFragment, currentRaw, rule, encodedSegments, nil)
		allComponentFindings[component.RuleID] = componentFindings

		logger.Debug().
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

			logger.Debug().
				Str("primary-rule", r.RuleID).
				Int("primary-line", primaryFinding.Location.StartLine).
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
