package scan

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/internal/ahocorasick"
	"github.com/betterleaks/betterleaks/v2/internal/codec"
	"github.com/betterleaks/betterleaks/v2/internal/confidence"
	"github.com/betterleaks/betterleaks/v2/internal/contextwindow"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/limits"
	"github.com/betterleaks/betterleaks/v2/internal/ruletiming"
	"github.com/betterleaks/betterleaks/v2/internal/tokenizer"
	"github.com/betterleaks/betterleaks/v2/logging"
	blregexp "github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

var allowSignatures = [...]string{"betterleaks:allow", "gitleaks:allow"}

var errStopIteration = errors.New("scanner: stop iteration")

const (
	levelTrace = slog.LevelDebug - 4

	// maxComponentSets caps the Cartesian product of component-finding combinations
	// to prevent excessive memory use with large multi-part rules.
	maxComponentSets = limits.ComponentSets
)

func logTrace(logger *slog.Logger, msg string, args ...any) {
	logger.Log(context.Background(), levelTrace, msg, args...)
}

type ruleCandidates struct {
	// Indexes match rulesBySpecificity, preserving rule order without building
	// a map and sorted slice for every fragment and decode pass.
	marked []bool
}

// Scanner is an immutable rule engine with thread-safe lazy compilation. A
// Scanner may be reused concurrently with independent sources. Each scan
// owns its execution state and shares the Scanner's detection worker limit.
type Scanner struct {
	ignoredFingerprints map[fingerprint.Hash]struct{}
	maxDecodeDepth      int
	matchContext        contextwindow.Spec
	minimumConfidence   string
	ignoreAllowComments bool
	workers             int
	workerSlots         *semaphore.Weighted
	logger              *slog.Logger

	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter        *ahocorasick.Matcher
	prefilterProgram exprruntime.Program
	globalFilterExpr string
	excludedPaths    []string

	tokenCounter     *tokenizer.Counter
	tokenCounterOnce sync.Once

	exprRuntime *exprruntime.LocalRuntime

	globalFilter lazyFilter

	// rulesBySpecificity contains an immutable snapshot of every configured rule in descending
	// specificity order. Its positions are the shared index space used by the
	// candidate slices below, so it must not change after scanner construction.
	rulesBySpecificity []compiledRule
	ruleIndexByID      map[string]int

	// keywordRuleIndexes maps each Aho-Corasick pattern ID to the positions in
	// rulesBySpecificity of rules that use that keyword. Precomputing this avoids
	// keyword strings and map lookups while scanning each fragment.
	keywordRuleIndexes [][]int

	// noKeywordIndexes contains positions in rulesBySpecificity for rules with no
	// keyword prefilter. These rules are candidates on every scan and decode pass.
	noKeywordIndexes []int

	// candidatePool reuses bitmaps across scanner workers and repeated scans. A
	// set bit means the rule at the same rulesBySpecificity position should run.
	// Bitmaps must be cleared before they are returned.
	candidatePool sync.Pool
}

// New creates a Scanner from cfg. The source prefilter compiles during
// construction; rule regexes and finding filters stay
// lazy unless [WithPrecompile] is supplied. Construction never starts scan or
// provider workers.
func New(cfg *config.Config, options ...Option) (*Scanner, error) {
	if cfg == nil {
		return nil, errors.New("config is required to create scanner")
	}
	var settings scannerOptions
	for _, option := range options {
		if option.apply == nil {
			return nil, errors.New("scanner option is invalid")
		}
		if err := option.apply(&settings); err != nil {
			return nil, err
		}
	}
	if settings.workers == 0 {
		settings.workers = max(runtime.GOMAXPROCS(0), 1)
	}
	rulesBySpecificity, ruleIndexByID, snapshotErr := snapshotRules(cfg)
	if snapshotErr != nil {
		return nil, fmt.Errorf("invalid config: %w", snapshotErr)
	}

	exprRuntime := exprruntime.NewLocal()

	keywordToRuleIndexes := make(map[string][]int)
	noKeywordIndexes := make([]int, 0)
	for ruleIndex, rule := range rulesBySpecificity {
		if len(rule.rule.Keywords) == 0 {
			noKeywordIndexes = append(noKeywordIndexes, ruleIndex)
			continue
		}
		for _, keyword := range rule.rule.Keywords {
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
	d := &Scanner{
		maxDecodeDepth:      settings.maxDecodeDepth,
		matchContext:        settings.matchContext,
		minimumConfidence:   settings.minimumConfidence,
		ignoreAllowComments: settings.ignoreAllowComments,
		excludedPaths:       slices.Clone(settings.excludedPaths),
		workers:             settings.workers,
		workerSlots:         semaphore.NewWeighted(int64(settings.workers)),
		logger:              logging.OrDiscard(settings.logger),
		globalFilterExpr:    cfg.Filter,
		prefilter:           ahocorasick.Compile(keywords, true),
		exprRuntime:         exprRuntime,
		rulesBySpecificity:  rulesBySpecificity,
		ruleIndexByID:       ruleIndexByID,
		keywordRuleIndexes:  keywordRuleIndexes,
		noKeywordIndexes:    noKeywordIndexes,
	}
	if len(settings.ignoredFingerprints) > 0 {
		d.ignoredFingerprints = make(map[fingerprint.Hash]struct{}, len(settings.ignoredFingerprints))
		for _, hash := range settings.ignoredFingerprints {
			d.ignoredFingerprints[hash] = struct{}{}
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

func (d *Scanner) compileAll() error {
	if _, _, err := d.globalFilterProgram(); err != nil {
		return err
	}
	for i := range d.rulesBySpecificity {
		rule := &d.rulesBySpecificity[i]
		if rule.regex != nil {
			if err := rule.regex.Compile(); err != nil {
				return fmt.Errorf("compile rule %q regex: %w", rule.rule.ID, err)
			}
		}
		if rule.path != nil {
			if err := rule.path.Compile(); err != nil {
				return fmt.Errorf("compile rule %q path regex: %w", rule.rule.ID, err)
			}
		}
		if _, _, err := d.ruleFilterProgram(rule); err != nil {
			return err
		}
	}
	return nil
}

func (d *Scanner) tokenCounterInstance() *tokenizer.Counter {
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

func (d *Scanner) globalFilterProgram() (exprruntime.Program, bool, error) {
	if d.globalFilterExpr == "" {
		return nil, false, nil
	}
	program, err := d.globalFilter.compile(d.exprRuntime, d.globalFilterExpr)
	if err != nil {
		return nil, false, fmt.Errorf("compiling global filter: %w", err)
	}
	return program, true, nil
}

func (d *Scanner) ruleFilterProgram(r *compiledRule) (exprruntime.Program, bool, error) {
	if r.rule.Filter == "" {
		return nil, false, nil
	}
	program, err := r.filter.compile(d.exprRuntime, r.rule.Filter)
	if err != nil {
		return nil, false, fmt.Errorf("compiling rule %s filter: %w", r.rule.ID, err)
	}
	return program, true, nil
}

// SkipFunc returns a sources.SkipFunc callback that evaluates the config's
// prefilter program against fragment attributes. Pass it to a source's
// ShouldSkip field to filter fragments before their contents are loaded. It
// returns nil when no prefilter or excluded paths are configured.
func (d *Scanner) SkipFunc() sources.SkipFunc {
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

func (d *Scanner) pathExcluded(path string) bool {
	for _, excluded := range d.excludedPaths {
		if path != "" && samePath(path, excluded) {
			return true
		}
	}
	return false
}

// Result is one finding or recoverable error emitted by [Scanner.Run].
type Result struct {
	// Finding is populated when Err is nil.
	Finding report.Finding
	// Err is a recoverable source or scan error.
	Err error
}

// ScanSummary describes the work completed by one scan.
type ScanSummary struct {
	// BytesInspected excludes fragments rejected by the scanner prefilter.
	BytesInspected uint64
	// Findings is the number of findings that passed local detection filters.
	Findings int
}

// Handler consumes one finding. Scan invokes handlers synchronously and never
// concurrently. Returning an error stops the scan. Handlers may start another
// scan with an independent source.
type Handler func(report.Finding) error

// Run scans the source and yields findings and recoverable source errors.
// Findings are not retained. Result order is not guaranteed. Concurrent calls
// on the same Scanner are safe with independent sources.
func (d *Scanner) Run(ctx context.Context, source sources.Source) iter.Seq[Result] {
	return func(yield func(Result) bool) {
		if d == nil {
			_ = yield(Result{Err: errors.New("scanner is nil")})
			return
		}
		_ = d.run(ctx, source, yield)
	}
}

// Scan scans the source, passes each finding to handler, and returns a
// per-call summary. Recoverable source errors are joined. Returning an error
// from handler stops the scan. A nil handler discards findings.
func (d *Scanner) Scan(ctx context.Context, source sources.Source, handler Handler) (ScanSummary, error) {
	if d == nil {
		return ScanSummary{}, errors.New("scanner is nil")
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

type fragmentResult struct {
	findings []report.Finding
	err      error
}

func (d *Scanner) run(ctx context.Context, source sources.Source, yield func(Result) bool) (summary ScanSummary) {
	state := scanState{}
	if source == nil {
		_ = yield(Result{Err: errors.New("scanner: nil source")})
		return state.summary
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state.ruleTimings = ruletiming.FromContext(ctx)

	runCtx, cancel := context.WithCancel(ctx)
	resultsCh := make(chan fragmentResult, d.workers)
	// Reserve output capacity before acquiring a worker slot. Every worker can
	// then publish its entire fragment without blocking on a handler, including
	// handlers that start another scan on this Scanner. The reservations also
	// bound queued and in-flight fragments when a consumer is slow.
	resultSlots := make(chan struct{}, d.workers)
	defer func() {
		cancel()
		for range resultsCh {
			<-resultSlots
		}
		state.summary.BytesInspected = state.bytes.Load()
		summary = state.summary
	}()

	reserveResult := func() error {
		select {
		case <-runCtx.Done():
			return errStopIteration
		case resultSlots <- struct{}{}:
			return nil
		}
	}
	emitError := func(err error) error {
		if reserveErr := reserveResult(); reserveErr != nil {
			return reserveErr
		}
		resultsCh <- fragmentResult{err: err}
		return nil
	}
	go func() {
		defer close(resultsCh)

		var workers sync.WaitGroup
		sourceErr := source.Fragments(runCtx, func(fragment sources.Fragment, fragmentErr error) error {
			if fragmentErr != nil {
				if isPipelineStop(fragmentErr) {
					return errStopIteration
				}
				return emitError(fragmentErr)
			}
			if len(fragment.Raw) == 0 && fragment.Attr(sources.AttrPath) == "" {
				return nil
			}
			if err := reserveResult(); err != nil {
				return err
			}
			// Acquire before starting a goroutine so concurrent scans do not
			// create their own pools of idle detection workers.
			if err := d.workerSlots.Acquire(runCtx, 1); err != nil {
				<-resultSlots
				return err
			}
			workers.Go(func() {
				findings := d.detectFragmentWithState(runCtx, fragment, &state)
				d.workerSlots.Release(1)
				resultsCh <- fragmentResult{findings: findings}
			})
			return nil
		})
		workers.Wait()

		if sourceErr != nil && !isPipelineStop(sourceErr) {
			_ = emitError(sourceErr)
		}
	}()

	for result := range resultsCh {
		<-resultSlots
		if isPipelineStop(result.err) {
			continue
		}
		if result.err != nil {
			if !yield(Result{Err: result.err}) {
				return state.summary
			}
			continue
		}
		for _, finding := range result.findings {
			if runCtx.Err() != nil {
				return state.summary
			}
			state.summary.Findings++
			if !yield(Result{Finding: finding}) {
				return state.summary
			}
		}
	}
	return state.summary
}

func isPipelineStop(err error) bool {
	return errors.Is(err, errStopIteration) || errors.Is(err, context.Canceled)
}

func rulePathMatchesFragment(pathRule *blregexp.Regexp, fragment sources.Fragment) bool {
	path := fragment.Attr(sources.AttrPath)
	return path != "" && pathRule != nil && pathRule.MatchString(path)
}

func newPathOnlyFinding(r *compiledRule, fragment sources.Fragment) report.Finding {
	path := fragment.Attr(sources.AttrPath)
	finding := report.Finding{
		RuleID:      r.rule.ID,
		Description: r.rule.Description,
		Match:       report.Match{Full: "file detected: " + path},
		Tags:        append([]string{}, r.rule.Tags...),
	}
	finding.SetAttributes(fragment.Attributes)
	if r.rule.Confidence != "" {
		finding.Confidence = r.rule.Confidence
	}
	return finding
}

// promoteConfidence moves the value written by setConfidence from the
// mutable expression attributes into Finding's typed field.
func promoteConfidence(finding *report.Finding, findingMap map[string]any, attributes map[string]string) {
	value, ok := attributes[confidence.Attribute]
	if !ok {
		return
	}
	finding.Confidence = value
	delete(attributes, confidence.Attribute)
	findingMap["confidence"] = value
}

// ScanString scans content and returns its findings. It is a convenience for
// callers that do not need source errors or a scan summary.
func (d *Scanner) ScanString(content string) []report.Finding {
	if d == nil {
		return nil
	}
	return d.detectFragment(context.Background(), sources.Fragment{
		Raw: content,
	})
}

func (d *Scanner) detectFragment(ctx context.Context, fragment sources.Fragment) []report.Finding {
	if err := d.workerSlots.Acquire(ctx, 1); err != nil {
		return nil
	}
	defer d.workerSlots.Release(1)
	return d.detectFragmentWithState(ctx, fragment, nil)
}

func (d *Scanner) detectFragmentWithState(ctx context.Context, fragment sources.Fragment, state *scanState) []report.Finding {
	// Ensure default fields are properly set
	fragment.SetDefaults()

	// Apply explicit source policy. Config.Path is provenance only.
	if path := fragment.Attr(sources.AttrPath); path != "" {
		if d.pathExcluded(path) {
			return nil
		}
	}

	var ruleTimings *ruletiming.Collector
	if state != nil {
		state.bytes.Add(uint64(len(fragment.Raw)))
		ruleTimings = state.ruleTimings
	}

	findings := []report.Finding{}
	priorFindings := &findingIndex{}

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

			for ruleIndex := range d.rulesBySpecificity {
				if !candidates.marked[ruleIndex] {
					continue
				}
				rule := &d.rulesBySpecificity[ruleIndex]
				select {
				case <-ctx.Done():
					clear(candidates.marked)
					d.candidatePool.Put(candidates)
					break ScanLoop
				default:
					// A path-only rule cannot produce a new result after decoding content
					// or for later chunks of the same file. Keep missing attributes eligible
					// so fragments from sources other than File retain their existing behavior.
					if rule.regex == nil && (currentDecodeDepth > 0 || fragment.Attr(sources.AttrFSFirstFragment) == "false") {
						continue
					}
					for _, finding := range d.detectFragmentWithRuleTimed(ruleTimings, fragment, currentRaw, rule, encodedSegments, priorFindings, detectionState{}) {
						// These findings have their components assembled. Recursive
						// component matching never applies fingerprint suppression.
						if len(d.ignoredFingerprints) > 0 {
							if _, ignored := d.ignoredFingerprints[fingerprint.Sum([]byte(finding.Match.Value))]; ignored {
								continue
							}
						}
						if confidence.Meets(finding.Confidence, d.minimumConfidence) {
							findings = append(findings, finding)
							priorFindings.findings = findings
							priorFindings.add(len(findings) - 1)
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
	findings = d.filterIndexed(findings, priorFindings)
	return findings
}

// detectionState is local to a rule evaluation, never part of source metadata.
// Component matches may use skipReport rules, but do not expand components again.
// The zero value describes a normal top-level match.
type detectionState struct {
	component bool
}

func (d *Scanner) detectFragmentWithRuleTimed(ruleTimings *ruletiming.Collector,
	fragment sources.Fragment,
	currentRaw string,
	r *compiledRule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings *findingIndex,
	state detectionState) []report.Finding {
	if ruleTimings == nil {
		return d.detectFragmentWithRule(nil, fragment, currentRaw, r, encodedSegments, priorFindings, state)
	}

	start := time.Now()
	findings := d.detectFragmentWithRule(ruleTimings, fragment, currentRaw, r, encodedSegments, priorFindings, state)
	ruleTimings.Record(r.rule.ID, time.Since(start))
	return findings
}

func snapshotRules(cfg *config.Config) ([]compiledRule, map[string]int, error) {
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	rules := make([]compiledRule, len(cfg.Rules))
	for i, source := range cfg.Rules {
		rule := source
		rule.Keywords = slices.Clone(source.Keywords)
		rule.Tags = slices.Clone(source.Tags)
		rule.Components = slices.Clone(source.Components)
		compiled := compiledRule{rule: rule, filter: &lazyFilter{}}
		if rule.Regex != "" {
			var err error
			compiled.regex, err = blregexp.Compile(rule.Regex)
			if err != nil {
				return nil, nil, fmt.Errorf("compile rule %q regex: %w", rule.ID, err)
			}
		}
		if rule.Path != "" {
			var err error
			compiled.path, err = blregexp.Compile(rule.Path)
			if err != nil {
				return nil, nil, fmt.Errorf("compile rule %q path regex: %w", rule.ID, err)
			}
		}
		rules[i] = compiled
	}
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].rule.Specificity > rules[j].rule.Specificity
	})
	indexes := make(map[string]int, len(rules))
	for i, rule := range rules {
		indexes[rule.rule.ID] = i
	}
	return rules, indexes, nil
}

// detectFragmentWithRule scans the given fragment for the given rule and returns a list of findings
func (d *Scanner) detectFragmentWithRule(ruleTimings *ruletiming.Collector,
	fragment sources.Fragment,
	currentRaw string,
	r *compiledRule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings *findingIndex,
	state detectionState) []report.Finding {
	var (
		findings []report.Finding
		logger   = d.logger
	)

	if r.rule.SkipReport && !state.component {
		return findings
	}

	// Ensure default fields are properly set
	fragment.SetDefaults()

	if r.regex == nil {
		// Decoding content cannot change a path-only result.
		if len(encodedSegments) > 0 {
			return findings
		}
		if rulePathMatchesFragment(r.path, fragment) {
			finding := newPathOnlyFinding(r, fragment)
			if !d.filterPathFinding(r, &finding) {
				return append(findings, finding)
			}
		}
		return findings
	}

	if r.path != nil && !rulePathMatchesFragment(r.path, fragment) {
		// If a rule defines both `path` and `regex`, the normalized fragment path
		// must match before we spend time checking the content regex.
		return findings
	}

	matches := r.regex.FindAllStringIndex(currentRaw, -1)
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

		tags := append([]string{}, r.rule.Tags...)
		if len(metaTags) > 0 {
			tags = append(tags, metaTags...)
		}

		prevFragmentEndLine := fragment.StartLine - 1
		finding := report.Finding{
			RuleID:      r.rule.ID,
			Description: r.rule.Description,
			Match: report.Match{
				Full:  secret,
				Value: secret,
				Line:  strings.Clone(fragment.Raw[loc.startLineIndex:loc.endLineIndex]),
			},
			Tags: tags,
			Location: report.Location{
				StartLine:   prevFragmentEndLine + loc.startLine,
				EndLine:     prevFragmentEndLine + loc.endLine,
				StartColumn: loc.startColumn,
				EndColumn:   loc.endColumn,
			},
		}
		finding.SetAttributes(fragment.Attributes)
		if r.rule.Confidence != "" {
			finding.Confidence = r.rule.Confidence
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
		if !d.ignoreAllowComments && containsAllowSignature(finding.Match.Line) {
			logTrace(logger, "skipping finding: allow signature found", "finding", finding.Match.Value)
			continue
		}
		if currentLine == "" {
			currentLine = finding.Match.Line
		}

		// Set the value of |secret|, if the pattern contains at least one capture group.
		// (The first element is the full match, hence we check >= 2.)
		groups := r.regex.FindStringSubmatch(finding.Match.Value)
		if len(groups) >= 2 {
			if r.rule.SecretGroup > 0 {
				if len(groups) <= r.rule.SecretGroup {
					// Config validation should prevent this
					continue
				}
				finding.Match.Value = groups[r.rule.SecretGroup]
			} else {
				// If |secretGroup| is not set, we will use the first suitable capture group.
				for _, s := range groups[1:] {
					if len(s) > 0 {
						finding.Match.Value = s
						break
					}
				}
			}

			// Extract named capture groups for use as template variables.
			names := r.regex.SubexpNames()
			captures := make(map[string]string)
			for i, name := range names {
				if i > 0 && name != "" && i < len(groups) && groups[i] != "" {
					captures[name] = strings.Clone(groups[i])
				}
			}
			if len(captures) > 0 {
				finding.Match.Captures = captures
			}
		}

		if d.isSuppressedByHigherSpecificityFinding(finding, priorFindings) {
			continue
		}

		entropy := shannonEntropy(finding.Match.Value)

		hasGlobalFilter := d.globalFilterExpr != ""
		hasRuleFilter := r.rule.Filter != ""
		// Context is opt-in. Filters can slice fragment_raw using match offsets
		// without retaining an additional context window on every finding.
		if !d.matchContext.IsZero() {
			finding.Match.Context = strings.Clone(contextwindow.Extract(fragment.Raw, matchIndex, d.matchContext))
		}

		// Build finding map once, only when at least one filter program is compiled.
		var findingMap map[string]any
		var filterAttributes map[string]string
		if hasGlobalFilter || hasRuleFilter {
			filterAttributes = exprAttributes(finding)
			findingMap = make(map[string]any, 12)
			for key, value := range exprFinding(finding) {
				findingMap[key] = value
			}
			findingMap["captures"] = finding.Match.Captures
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
			skip, err := d.exprRuntime.EvalFilter(prg, findingMap, filterAttributes)
			promoteConfidence(&finding, findingMap, filterAttributes)
			if err != nil {
				logger.Warn("global filter eval error", "error", err)
			} else if skip {
				logTrace(logger, "skipping finding: global filter", "finding", finding.Match.Value)
				continue
			}
		}

		// Rule filter: Expr path (includes entropy and token-efficiency checks).
		if prg, ok, err := d.ruleFilterProgram(r); err != nil {
			logger.Warn("rule filter compile error", "error", err)
		} else if ok {
			skip, err := d.exprRuntime.EvalFilter(prg, findingMap, filterAttributes)
			promoteConfidence(&finding, findingMap, filterAttributes)
			if err != nil {
				logger.Warn("rule filter eval error", "error", err)
			} else if skip {
				logTrace(logger, "skipping finding: rule filter", "finding", finding.Match.Value)
				continue
			}
		}

		findings = append(findings, finding)
	}

	// Handle component rules (multi-part rules).
	if state.component || len(r.rule.Components) == 0 {
		return findings
	}

	return d.processComponents(ruleTimings, fragment, currentRaw, r, encodedSegments, findings, logger)
}

// processComponents attaches nearby component matches and enforces required components.
func (d *Scanner) processComponents(ruleTimings *ruletiming.Collector, fragment sources.Fragment, currentRaw string, r *compiledRule, encodedSegments []*codec.EncodedSegment, primaryFindings []report.Finding, logger *slog.Logger) []report.Finding {
	if len(primaryFindings) == 0 {
		logger.Debug("no primary findings to process for components")
		return primaryFindings
	}

	// Pre-collect each component rule's findings once per fragment.
	allComponentFindings := make(map[string][]report.Finding)
	componentWindows := make(map[string]contextwindow.Spec, len(r.rule.Components))

	for _, component := range r.rule.Components {
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
		rule := &d.rulesBySpecificity[ruleIndex]

		componentFindings := d.detectFragmentWithRuleTimed(ruleTimings, fragment, currentRaw, rule, encodedSegments, nil, detectionState{component: true})
		allComponentFindings[component.RuleID] = componentFindings

		logger.Debug("collected component rule findings",
			"rule_id", component.RuleID,
			"findings", len(componentFindings),
		)
	}

	var finalFindings []report.Finding

	// Process each primary finding against the pre-collected component findings.
	for _, primaryFinding := range primaryFindings {
		var componentFindings []report.ComponentFinding

		for _, component := range r.rule.Components {
			foundComponentFindings, exists := allComponentFindings[component.RuleID]
			if !exists {
				continue
			}
			window := componentWindows[component.RuleID]

			for _, found := range foundComponentFindings {
				if withinProximity(fragment.Raw, fragment.StartLine, primaryFinding, found, window) {
					componentFindings = append(componentFindings, report.ComponentFinding{
						RuleID:   found.RuleID,
						Optional: component.Optional,
						Match:    found.Match,
						Location: found.Location,
					})
				}
			}
		}

		if d.hasAllRequiredComponents(componentFindings, r.rule.Components) {
			newFinding := primaryFinding
			newFinding.ComponentSets, newFinding.ComponentSetsTruncated = buildComponentSets(componentFindings, maxComponentSets)
			finalFindings = append(finalFindings, newFinding)

			logger.Debug("multi-part rule satisfied",
				"primary_rule", r.rule.ID,
				"primary_line", primaryFinding.Location.StartLine,
				"component_count", len(componentFindings),
			)
		}
	}

	return finalFindings
}

// hasAllRequiredComponents checks that every required component has a nearby match.
func (d *Scanner) hasAllRequiredComponents(componentFindings []report.ComponentFinding, components []config.Component) bool {
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

// Path findings have metadata but no content match. They still obey local
// filters; content offsets and fragment text are explicitly empty.
func (d *Scanner) filterPathFinding(r *compiledRule, finding *report.Finding) bool {
	if d.globalFilterExpr == "" && r.rule.Filter == "" {
		return false
	}
	attrs := exprAttributes(*finding)
	values := make(map[string]any, 15)
	for key, value := range exprFinding(*finding) {
		values[key] = value
	}
	values["captures"] = map[string]string{}
	values["entropy"] = "0"
	values["fragment_raw"] = ""
	for _, key := range []string{"match_start_idx", "match_end_idx", "match_line_start_idx", "match_line_end_idx"} {
		values[key] = 0
	}
	for _, compile := range []func() (exprruntime.Program, bool, error){d.globalFilterProgram, func() (exprruntime.Program, bool, error) { return d.ruleFilterProgram(r) }} {
		prg, ok, err := compile()
		if err != nil {
			d.logger.Warn("path filter compile error", "error", err)
			continue
		}
		if !ok {
			continue
		}
		skip, err := d.exprRuntime.EvalFilter(prg, values, attrs)
		promoteConfidence(finding, values, attrs)
		if err != nil {
			d.logger.Warn("path filter eval error", "error", err)
		} else if skip {
			return true
		}
	}
	return false
}

// filter will dedupe and redact findings
func (d *Scanner) filter(findings []report.Finding) []report.Finding {
	return d.filterIndexed(findings, newFindingIndex(findings))
}

func (d *Scanner) filterIndexed(findings []report.Finding, index *findingIndex) []report.Finding {
	// Collect every component finding's (rule, line, secret) identity so the
	// corresponding top-level finding can be suppressed.
	componentSet := make(map[string]struct{})
	for _, f := range findings {
		for _, set := range f.ComponentSets {
			for _, comp := range set.Components {
				componentSet[fmt.Sprintf("%s:%d:%d:%d:%d:%s", comp.RuleID, comp.Location.StartLine, comp.Location.StartColumn, comp.Location.EndLine, comp.Location.EndColumn, comp.Match.Value)] = struct{}{}
			}
		}
	}

	var retFindings []report.Finding
	for _, f := range findings {
		include := true

		// Skip findings already surfaced as the same rule's component of a
		// composite finding in this batch.
		_, isComponent := componentSet[fmt.Sprintf("%s:%d:%d:%d:%d:%s", f.RuleID, f.Location.StartLine, f.Location.StartColumn, f.Location.EndLine, f.Location.EndColumn, f.Match.Value)]
		if isComponent {
			redactedMatch := strings.ReplaceAll(f.Match.Full, f.Match.Value, "REDACTED")
			logTrace(d.logger, "skipping finding already used as a component", "rule_id", f.RuleID, "finding", redactedMatch)
			include = false
		} else if d.isSuppressedByHigherSpecificityFinding(f, index) {
			include = false
		}

		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

func (d *Scanner) isSuppressedByHigherSpecificityFinding(f report.Finding, index *findingIndex) bool {
	if index == nil {
		return false
	}
	for _, i := range index.byLine[f.Location.StartLine] {
		fPrime := &index.findings[i]
		if f.Location.StartLine == fPrime.Location.StartLine &&
			f.Attributes[sources.AttrGitSHA] == fPrime.Attributes[sources.AttrGitSHA] &&
			f.RuleID != fPrime.RuleID &&
			strings.Contains(fPrime.Match.Value, f.Match.Value) &&
			d.ruleSpecificity(fPrime.RuleID) > d.ruleSpecificity(f.RuleID) {
			genericMatch := strings.ReplaceAll(f.Match.Full, f.Match.Value, "REDACTED")
			betterMatch := strings.ReplaceAll(fPrime.Match.Full, fPrime.Match.Value, "REDACTED")
			d.logger.Debug("skipping finding because a more specific rule takes precedence",
				"rule_id", f.RuleID,
				"finding", genericMatch,
				"precedence_rule_id", fPrime.RuleID,
				"precedence_finding", betterMatch,
			)
			return true
		}
		for _, set := range fPrime.ComponentSets {
			for _, comp := range set.Components {
				if f.RuleID != fPrime.RuleID &&
					f.Location.StartLine == comp.Location.StartLine &&
					f.RuleID != comp.RuleID &&
					strings.Contains(comp.Match.Value, f.Match.Value) &&
					d.ruleSpecificity(comp.RuleID) > d.ruleSpecificity(f.RuleID) {
					genericMatch := strings.ReplaceAll(f.Match.Full, f.Match.Value, "REDACTED")
					betterMatch := strings.ReplaceAll(comp.Match.Full, comp.Match.Value, "REDACTED")
					logTrace(d.logger, "skipping finding because a more specific component takes precedence",
						"rule_id", f.RuleID,
						"finding", genericMatch,
						"precedence_rule_id", comp.RuleID,
						"precedence_finding", betterMatch,
					)
					return true
				}
			}
		}
	}
	return false
}

// Specificity is immutable rule configuration, not finding data.
func (d *Scanner) ruleSpecificity(id string) int {
	return d.rulesBySpecificity[d.ruleIndexByID[id]].rule.Specificity
}
