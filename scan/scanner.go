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
	"github.com/betterleaks/betterleaks/v2/internal/regexspan"
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
	marked  []bool
	windows []regexspan.Windows
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

	keywordMatcher   *ahocorasick.Matcher
	globalFilterExpr string

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
	// anchorRuleIndexes locates windows without making a rule eligible.
	anchorRuleIndexes [][]int

	// noKeywordIndexes contains positions in rulesBySpecificity for rules without
	// keywords. These rules are candidates on every scan and decode pass.
	noKeywordIndexes []int

	// candidatePool reuses bitmaps across scanner workers and repeated scans. A
	// set bit means the rule at the same rulesBySpecificity position should run.
	// Bitmaps must be cleared before they are returned.
	candidatePool sync.Pool
}

// New creates a Scanner from cfg. Rule regexes and finding filters compile
// lazily unless [WithPrecompile] is supplied. Sources own prefilter evaluation;
// cfg.Prefilter is not used by the Scanner.
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
	anchorToRuleIndexes := make(map[string][]int)
	noKeywordIndexes := make([]int, 0)
	for ruleIndex, rule := range rulesBySpecificity {
		if len(rule.rule.Keywords) == 0 {
			noKeywordIndexes = append(noKeywordIndexes, ruleIndex)
			continue
		}
		for _, anchor := range rule.searchAnchors {
			anchor = strings.ToLower(anchor)
			indexes := anchorToRuleIndexes[anchor]
			if len(indexes) == 0 || indexes[len(indexes)-1] != ruleIndex {
				anchorToRuleIndexes[anchor] = append(indexes, ruleIndex)
			}
			if _, ok := keywordToRuleIndexes[anchor]; !ok {
				keywordToRuleIndexes[anchor] = nil
			}
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
	anchorRuleIndexes := make([][]int, len(keywords))
	for patternID, keyword := range keywords {
		keywordRuleIndexes[patternID] = keywordToRuleIndexes[keyword]
		anchorRuleIndexes[patternID] = anchorToRuleIndexes[keyword]
	}
	s := &Scanner{
		maxDecodeDepth:      settings.maxDecodeDepth,
		matchContext:        settings.matchContext,
		minimumConfidence:   settings.minimumConfidence,
		ignoreAllowComments: settings.ignoreAllowComments,
		workers:             settings.workers,
		workerSlots:         semaphore.NewWeighted(int64(settings.workers)),
		logger:              logging.OrDiscard(settings.logger),
		globalFilterExpr:    cfg.Filter,
		keywordMatcher:      ahocorasick.Compile(keywords, true),
		exprRuntime:         exprRuntime,
		rulesBySpecificity:  rulesBySpecificity,
		ruleIndexByID:       ruleIndexByID,
		keywordRuleIndexes:  keywordRuleIndexes,
		anchorRuleIndexes:   anchorRuleIndexes,
		noKeywordIndexes:    noKeywordIndexes,
	}
	if len(settings.ignoredFingerprints) > 0 {
		s.ignoredFingerprints = make(map[fingerprint.Hash]struct{}, len(settings.ignoredFingerprints))
		for _, hash := range settings.ignoredFingerprints {
			s.ignoredFingerprints[hash] = struct{}{}
		}
	}
	s.candidatePool.New = func() any {
		return &ruleCandidates{
			marked:  make([]bool, len(s.rulesBySpecificity)),
			windows: make([]regexspan.Windows, len(s.rulesBySpecificity)),
		}
	}
	exprRuntime.SetTokenCounterProvider(s.tokenCounterInstance)

	if settings.precompile {
		if err := s.compileAll(); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (s *Scanner) compileAll() error {
	if _, _, err := s.globalFilterProgram(); err != nil {
		return err
	}
	for i := range s.rulesBySpecificity {
		rule := &s.rulesBySpecificity[i]
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
		if _, _, err := s.ruleFilterProgram(rule); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) tokenCounterInstance() *tokenizer.Counter {
	s.tokenCounterOnce.Do(func() {
		counter, err := tokenizer.Default()
		if err != nil {
			s.logger.Warn("could not initialize cl100k_base tokenizer", "error", err)
			return
		}
		s.tokenCounter = counter
	})
	return s.tokenCounter
}

func (s *Scanner) globalFilterProgram() (exprruntime.Program, bool, error) {
	if s.globalFilterExpr == "" {
		return nil, false, nil
	}
	program, err := s.globalFilter.compile(s.exprRuntime, s.globalFilterExpr)
	if err != nil {
		return nil, false, fmt.Errorf("compiling global filter: %w", err)
	}
	return program, true, nil
}

func (s *Scanner) ruleFilterProgram(r *compiledRule) (exprruntime.Program, bool, error) {
	if r.rule.Filter == "" {
		return nil, false, nil
	}
	program, err := r.filter.compile(s.exprRuntime, r.rule.Filter)
	if err != nil {
		return nil, false, fmt.Errorf("compiling rule %s filter: %w", r.rule.ID, err)
	}
	return program, true, nil
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
	// BytesInspected counts fragment bytes after source and path exclusions.
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
func (s *Scanner) Run(ctx context.Context, source sources.Source) iter.Seq[Result] {
	return func(yield func(Result) bool) {
		if s == nil {
			_ = yield(Result{Err: errors.New("scanner is nil")})
			return
		}
		_ = s.run(ctx, source, yield)
	}
}

// Scan scans the source, passes each finding to handler, and returns a
// per-call summary. Recoverable source errors are joined. Returning an error
// from handler stops the scan. A nil handler discards findings.
func (s *Scanner) Scan(ctx context.Context, source sources.Source, handler Handler) (ScanSummary, error) {
	if s == nil {
		return ScanSummary{}, errors.New("scanner is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var scanErr error
	summary := s.run(ctx, source, func(result Result) bool {
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

func (s *Scanner) run(ctx context.Context, source sources.Source, yield func(Result) bool) (summary ScanSummary) {
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
	resultsCh := make(chan fragmentResult, s.workers)
	// Reserve output capacity before acquiring a worker slot. Every worker can
	// then publish its entire fragment without blocking on a handler, including
	// handlers that start another scan on this Scanner. The reservations also
	// bound queued and in-flight fragments when a consumer is slow.
	resultSlots := make(chan struct{}, s.workers)
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
			if err := s.workerSlots.Acquire(runCtx, 1); err != nil {
				<-resultSlots
				return err
			}
			workers.Go(func() {
				findings := s.detectFragmentWithState(runCtx, fragment, &state)
				s.workerSlots.Release(1)
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

func rulePathMatchesFragment(rule *compiledRule, fragment sources.Fragment) bool {
	path := fragment.Attr(sources.AttrPath)
	return path != "" && rule.path != nil && pathSuffixPossible(path, rule.pathSuffixes) && rule.path.MatchString(path)
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
func (s *Scanner) ScanString(content string) []report.Finding {
	if s == nil {
		return nil
	}
	return s.detectFragment(context.Background(), sources.Fragment{
		Raw: content,
	})
}

func (s *Scanner) detectFragment(ctx context.Context, fragment sources.Fragment) []report.Finding {
	if err := s.workerSlots.Acquire(ctx, 1); err != nil {
		return nil
	}
	defer s.workerSlots.Release(1)
	return s.detectFragmentWithState(ctx, fragment, nil)
}

func (s *Scanner) detectFragmentWithState(ctx context.Context, fragment sources.Fragment, state *scanState) []report.Finding {
	// Ensure default fields are properly set
	fragment.SetDefaults()

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
	detection := detectionState{}

ScanLoop:
	for {
		select {
		case <-ctx.Done():
			break ScanLoop
		default:
			candidates := s.candidatePool.Get().(*ruleCandidates)
			// Keywords select rules; proven assignment shapes can reject a hit.
			// Keep every eligible location for merging conservative search windows.
			s.keywordMatcher.Visit(currentRaw, func(patternID, start, end int) bool {
				for _, ruleIndex := range s.keywordRuleIndexes[patternID] {
					rule := &s.rulesBySpecificity[ruleIndex]
					if rule.guard != nil && !rule.guard.possible(currentRaw, end) {
						continue
					}
					candidates.marked[ruleIndex] = true
					if rule.span != nil && rule.searchAnchors == nil {
						candidates.windows[ruleIndex].Add(currentRaw, start, end, rule.span)
					}
				}
				// Additional anchors locate matches but never admit a rule.
				for _, ruleIndex := range s.anchorRuleIndexes[patternID] {
					candidates.windows[ruleIndex].Add(currentRaw, start, end, s.rulesBySpecificity[ruleIndex].span)
				}
				return true
			})
			// Always include rules that have no keywords.
			for _, ruleIndex := range s.noKeywordIndexes {
				candidates.marked[ruleIndex] = true
			}

			for ruleIndex := range s.rulesBySpecificity {
				if !candidates.marked[ruleIndex] {
					continue
				}
				rule := &s.rulesBySpecificity[ruleIndex]
				select {
				case <-ctx.Done():
					clear(candidates.marked)
					for i := range candidates.windows {
						candidates.windows[i].Reset()
					}
					s.candidatePool.Put(candidates)
					break ScanLoop
				default:
					// A path-only rule cannot produce a new result after decoding content
					// or for later chunks of the same file. Keep missing attributes eligible
					// so fragments from sources other than File retain their existing behavior.
					if rule.regex == nil && (currentDecodeDepth > 0 || fragment.Attr(sources.AttrFSFirstFragment) == "false") {
						continue
					}
					if len(rule.searchAnchors) > 0 && len(candidates.windows[ruleIndex].Spans) == 0 {
						continue
					}
					detection.spans = candidates.windows[ruleIndex].Spans
					for _, finding := range s.detectFragmentWithRuleTimed(ruleTimings, fragment, currentRaw, rule, encodedSegments, priorFindings, &detection) {
						// These findings have their components assembled. Recursive
						// component matching never applies fingerprint suppression.
						if len(s.ignoredFingerprints) > 0 {
							if _, ignored := s.ignoredFingerprints[fingerprint.Sum([]byte(finding.Match.Value))]; ignored {
								continue
							}
						}
						if confidence.Meets(finding.Confidence, s.minimumConfidence) {
							findings = append(findings, finding)
							priorFindings.findings = findings
							priorFindings.add(len(findings) - 1)
						}
					}
				}
			}
			// Pool entries must be blank because later scans may run on any goroutine.
			clear(candidates.marked)
			for i := range candidates.windows {
				candidates.windows[i].Reset()
			}
			s.candidatePool.Put(candidates)

			// increment the depth by 1 as we start our decoding pass
			currentDecodeDepth++

			// stop the loop if we've hit our max decoding depth
			if currentDecodeDepth > s.maxDecodeDepth {
				break ScanLoop
			}

			// decode the currentRaw for the next pass
			currentRaw, encodedSegments = codec.Decode(currentRaw, encodedSegments)

			// stop the loop when there's nothing else to decode
			if len(encodedSegments) == 0 {
				break ScanLoop
			}
		}
	}
	findings = s.filterIndexed(findings, priorFindings)
	detachFindingText(findings)
	return findings
}

// Copy text after filtering so returned findings don't keep entire source or
// decoded buffers alive. Findings and components covering the same source lines
// share one copy of those lines.
func detachFindingText(findings []report.Finding) {
	lines := make(map[[2]int]string)
	ownMatch := func(match *report.Match, location report.Location) {
		if match.Value == match.Full {
			match.Full = strings.Clone(match.Full)
			match.Value = match.Full
		} else {
			match.Full = strings.Clone(match.Full)
			match.Value = strings.Clone(match.Value)
		}
		for name, value := range match.Captures {
			match.Captures[name] = strings.Clone(value)
		}
		if match.Line != "" {
			key := [2]int{location.StartLine, location.EndLine}
			line, ok := lines[key]
			if !ok {
				line = strings.Clone(match.Line)
				lines[key] = line
			}
			match.Line = line
		}
		match.Context = strings.Clone(match.Context)
	}
	for i := range findings {
		finding := &findings[i]
		ownMatch(&finding.Match, finding.Location)
		for _, set := range finding.ComponentSets {
			for j := range set.Components {
				component := &set.Components[j]
				ownMatch(&component.Match, component.Location)
			}
		}
	}
}

// detectionState belongs to one fragment, never to source metadata or a Scanner.
// Line offsets refer to the original bytes and are shared across rules and
// decoding passes, whose match locations are remapped to those bytes.
// Component matches may use skipReport rules, but do not expand components again.
// The zero value describes a normal top-level match.
type detectionState struct {
	spans       []regexspan.Span
	component   bool
	lineOffsets []int
}

func (s *Scanner) detectFragmentWithRuleTimed(ruleTimings *ruletiming.Collector,
	fragment sources.Fragment,
	currentRaw string,
	r *compiledRule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings *findingIndex,
	state *detectionState) []report.Finding {
	if ruleTimings == nil {
		return s.detectFragmentWithRule(nil, fragment, currentRaw, r, encodedSegments, priorFindings, state)
	}

	start := time.Now()
	findings := s.detectFragmentWithRule(ruleTimings, fragment, currentRaw, r, encodedSegments, priorFindings, state)
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
		compiled := compiledRule{rule: rule, filter: &lazyFilter{}}
		if rule.Regex != "" {
			var err error
			compiled.guard = compileAssignmentGuard(rule.Regex, rule.Keywords)
			compiled.span = regexspan.Compile(rule.Regex, rule.Keywords)
			if compiled.span == nil {
				compiled.span, compiled.searchAnchors = compilePrefixWindows(rule.Regex, rule.Keywords)
			}
			compiled.regex, err = blregexp.Compile(rule.Regex)
			if err != nil {
				return nil, nil, fmt.Errorf("compile rule %q regex: %w", rule.ID, err)
			}
		}
		if rule.Path != "" {
			var err error
			compiled.pathSuffixes = compilePathSuffixes(rule.Path)
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
	// Resolve against the final specificity order. Validate has checked every
	// reference and window; retain only their compiled representation.
	for i := range rules {
		r := &rules[i]
		for _, component := range r.rule.Components {
			window, _ := contextwindow.Parse(component.Within)
			r.components = append(r.components, compiledComponent{
				ruleIndex: indexes[component.RuleID], window: window, optional: component.Optional,
			})
		}
		r.rule.Components = nil
	}
	return rules, indexes, nil
}

// Detection borrows match text until detachFindingText detaches accepted results.
// Filters and component selection must finish before that ownership boundary.
func (s *Scanner) detectFragmentWithRule(ruleTimings *ruletiming.Collector,
	fragment sources.Fragment,
	currentRaw string,
	r *compiledRule,
	encodedSegments []*codec.EncodedSegment,
	priorFindings *findingIndex,
	state *detectionState) []report.Finding {
	var (
		findings []report.Finding
		logger   = s.logger
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
		if rulePathMatchesFragment(r, fragment) {
			finding := newPathOnlyFinding(r, fragment)
			if !s.filterPathFinding(r, &finding) {
				return append(findings, finding)
			}
		}
		return findings
	}

	if r.path != nil && !rulePathMatchesFragment(r, fragment) {
		// If a rule defines both `path` and `regex`, the normalized fragment path
		// must match before we spend time checking the content regex.
		return findings
	}

	var matches [][]int
	find := func(raw string) [][]int {
		if r.span != nil && r.span.RequiredByte != 0 && strings.IndexByte(raw, r.span.RequiredByte) < 0 {
			return nil
		}
		if r.regex.NumSubexp() > 0 {
			return r.regex.FindAllStringSubmatchIndex(raw, -1)
		}
		return r.regex.FindAllStringIndex(raw, -1)
	}
	if len(state.spans) == 0 {
		matches = find(currentRaw)
	} else {
		for _, span := range state.spans {
			part := find(currentRaw[span.Start:span.End])
			// Translate every participating capture, keeping currentRaw intact
			// for decoded mappings, filter context, and finding construction.
			for _, indexes := range part {
				for i, index := range indexes {
					if index >= 0 {
						indexes[i] += span.Start
					}
				}
			}
			matches = append(matches, part...)
		}
	}
	if len(matches) == 0 {
		return findings
	}
	var names []string
	if r.regex.NumSubexp() > 0 {
		names = r.regex.SubexpNames()
	}

	for _, indexes := range matches {
		matchIndex := indexes[:2]
		secret := strings.Trim(currentRaw[matchIndex[0]:matchIndex[1]], "\n")
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
		if state.lineOffsets == nil {
			state.lineOffsets = computeLineOffsets(fragment.Raw)
		}

		loc := location(state.lineOffsets, fragment.Raw, matchIndex)

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
				Line:  fragment.Raw[loc.startLineIndex:loc.endLineIndex],
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
		if !s.ignoreAllowComments && containsAllowSignature(finding.Match.Line) {
			logTrace(logger, "skipping finding: allow signature found", "rule_id", finding.RuleID)
			continue
		}
		if currentLine == "" {
			currentLine = finding.Match.Line
		}

		// Subgroup offsets stay in currentRaw even when the whole-match location
		// is trimmed or mapped back to encoded source bytes. Rematching the
		// extracted text would change anchor and boundary semantics.
		if len(indexes) > 2 {
			if r.rule.SecretGroup > 0 {
				group := 2 * r.rule.SecretGroup
				if group+1 >= len(indexes) {
					// Config validation should prevent this
					continue
				}
				finding.Match.Value = ""
				if start, end := indexes[group], indexes[group+1]; start >= 0 {
					finding.Match.Value = currentRaw[start:end]
				}
			} else {
				for group := 2; group < len(indexes); group += 2 {
					if start, end := indexes[group], indexes[group+1]; start >= 0 && end > start {
						finding.Match.Value = currentRaw[start:end]
						break
					}
				}
			}

			for i, name := range names {
				if i == 0 || name == "" {
					continue
				}
				start, end := indexes[2*i], indexes[2*i+1]
				if start >= 0 && end > start {
					if finding.Match.Captures == nil {
						finding.Match.Captures = make(map[string]string)
					}
					finding.Match.Captures[name] = currentRaw[start:end]
				}
			}
		}

		if s.isSuppressedByHigherSpecificityFinding(finding, priorFindings) {
			continue
		}

		entropy := shannonEntropy(finding.Match.Value)

		hasGlobalFilter := s.globalFilterExpr != ""
		hasRuleFilter := r.rule.Filter != ""
		// Context is opt-in. Filters can slice fragment_raw using match offsets
		// without retaining an additional context window on every finding.
		if !s.matchContext.IsZero() {
			finding.Match.Context = contextwindow.Extract(fragment.Raw, matchIndex, s.matchContext)
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
		if prg, ok, err := s.globalFilterProgram(); err != nil {
			logger.Warn("global filter compile error", "error", err)
		} else if ok {
			skip, err := s.exprRuntime.EvalFilter(prg, findingMap, filterAttributes)
			promoteConfidence(&finding, findingMap, filterAttributes)
			if err != nil {
				logger.Warn("global filter eval error", "error", err)
			} else if skip {
				logTrace(logger, "skipping finding: global filter", "rule_id", finding.RuleID)
				continue
			}
		}

		// Rule filter: Expr path (includes entropy and token-efficiency checks).
		if prg, ok, err := s.ruleFilterProgram(r); err != nil {
			logger.Warn("rule filter compile error", "error", err)
		} else if ok {
			skip, err := s.exprRuntime.EvalFilter(prg, findingMap, filterAttributes)
			promoteConfidence(&finding, findingMap, filterAttributes)
			if err != nil {
				logger.Warn("rule filter eval error", "error", err)
			} else if skip {
				logTrace(logger, "skipping finding: rule filter", "rule_id", finding.RuleID)
				continue
			}
		}

		findings = append(findings, finding)
	}

	// Handle component rules (multi-part rules).
	if state.component || len(r.components) == 0 {
		return findings
	}

	return s.processComponents(ruleTimings, fragment, currentRaw, r, encodedSegments, findings, state)
}

// processComponents attaches nearby component matches and enforces required components.
func (s *Scanner) processComponents(ruleTimings *ruletiming.Collector, fragment sources.Fragment, currentRaw string, r *compiledRule, encodedSegments []*codec.EncodedSegment, primaryFindings []report.Finding, state *detectionState) []report.Finding {
	if len(primaryFindings) == 0 {
		return primaryFindings
	}

	allComponentFindings := make([][]report.Finding, len(r.components))
	componentState := detectionState{component: true, lineOffsets: state.lineOffsets}
	for i, component := range r.components {
		rule := &s.rulesBySpecificity[component.ruleIndex]
		allComponentFindings[i] = s.detectFragmentWithRuleTimed(ruleTimings, fragment, currentRaw, rule, encodedSegments, nil, &componentState)
	}

	var finalFindings []report.Finding
nextPrimary:
	for _, primaryFinding := range primaryFindings {
		var componentFindings []report.ComponentFinding
		for i, component := range r.components {
			before := len(componentFindings)
			for _, found := range allComponentFindings[i] {
				if withinProximity(fragment.Raw, state.lineOffsets, fragment.StartLine, primaryFinding, found, component.window) {
					componentFindings = append(componentFindings, report.ComponentFinding{
						RuleID:   found.RuleID,
						Optional: component.optional,
						Match:    found.Match,
						Location: found.Location,
					})
				}
			}
			if !component.optional && len(componentFindings) == before {
				continue nextPrimary
			}
		}

		primaryFinding.ComponentSets, primaryFinding.ComponentSetsTruncated = buildComponentSets(componentFindings, maxComponentSets)
		finalFindings = append(finalFindings, primaryFinding)
	}
	return finalFindings
}

func withinProximity(raw string, lineOffsets []int, fragmentStartLine int, primary, component report.Finding, window contextwindow.Spec) bool {
	if window.IsZero() {
		return true
	}

	switch window.Mode {
	case contextwindow.ModeCols:
		primaryStart, ok := findingStartOffset(lineOffsets, fragmentStartLine, primary)
		if !ok {
			return false
		}
		primaryEnd, ok := findingEndOffset(lineOffsets, fragmentStartLine, primary)
		if !ok {
			return false
		}
		componentStart, ok := findingStartOffset(lineOffsets, fragmentStartLine, component)
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

func findingStartOffset(lineOffsets []int, fragmentStartLine int, finding report.Finding) (int, bool) {
	line := finding.Location.StartLine - fragmentStartLine
	if line < 0 || line >= len(lineOffsets) || finding.Location.StartColumn < 1 {
		return 0, false
	}
	return lineOffsets[line] + finding.Location.StartColumn - 1, true
}

func findingEndOffset(lineOffsets []int, fragmentStartLine int, finding report.Finding) (int, bool) {
	line := finding.Location.EndLine - fragmentStartLine
	if line < 0 || line >= len(lineOffsets) || finding.Location.EndColumn < 0 {
		return 0, false
	}
	return lineOffsets[line] + finding.Location.EndColumn, true
}

// Path findings have metadata but no content match. They still obey local
// filters; content offsets and fragment text are explicitly empty.
func (s *Scanner) filterPathFinding(r *compiledRule, finding *report.Finding) bool {
	if s.globalFilterExpr == "" && r.rule.Filter == "" {
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
	for _, compile := range []func() (exprruntime.Program, bool, error){s.globalFilterProgram, func() (exprruntime.Program, bool, error) { return s.ruleFilterProgram(r) }} {
		prg, ok, err := compile()
		if err != nil {
			s.logger.Warn("path filter compile error", "error", err)
			continue
		}
		if !ok {
			continue
		}
		skip, err := s.exprRuntime.EvalFilter(prg, values, attrs)
		promoteConfidence(finding, values, attrs)
		if err != nil {
			s.logger.Warn("path filter eval error", "error", err)
		} else if skip {
			return true
		}
	}
	return false
}

// filter will dedupe and redact findings
func (s *Scanner) filter(findings []report.Finding) []report.Finding {
	return s.filterIndexed(findings, newFindingIndex(findings))
}

func (s *Scanner) filterIndexed(findings []report.Finding, index *findingIndex) []report.Finding {
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
			logTrace(s.logger, "skipping finding already used as a component", "rule_id", f.RuleID)
			include = false
		} else if s.isSuppressedByHigherSpecificityFinding(f, index) {
			include = false
		}

		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

func (s *Scanner) isSuppressedByHigherSpecificityFinding(f report.Finding, index *findingIndex) bool {
	if index == nil {
		return false
	}
	for _, i := range index.byLine[f.Location.StartLine] {
		fPrime := &index.findings[i]
		if f.Location.StartLine == fPrime.Location.StartLine &&
			f.Attributes[sources.AttrGitSHA] == fPrime.Attributes[sources.AttrGitSHA] &&
			f.RuleID != fPrime.RuleID &&
			strings.Contains(fPrime.Match.Value, f.Match.Value) &&
			s.ruleSpecificity(fPrime.RuleID) > s.ruleSpecificity(f.RuleID) {
			s.logger.Debug("skipping finding because a more specific rule takes precedence",
				"rule_id", f.RuleID,
				"precedence_rule_id", fPrime.RuleID,
			)
			return true
		}
		for _, set := range fPrime.ComponentSets {
			for _, comp := range set.Components {
				if f.RuleID != fPrime.RuleID &&
					f.Location.StartLine == comp.Location.StartLine &&
					f.RuleID != comp.RuleID &&
					strings.Contains(comp.Match.Value, f.Match.Value) &&
					s.ruleSpecificity(comp.RuleID) > s.ruleSpecificity(f.RuleID) {
					logTrace(s.logger, "skipping finding because a more specific component takes precedence",
						"rule_id", f.RuleID,
						"precedence_rule_id", comp.RuleID,
					)
					return true
				}
			}
		}
	}
	return false
}

// Specificity is immutable rule configuration, not finding data.
func (s *Scanner) ruleSpecificity(id string) int {
	return s.rulesBySpecificity[s.ruleIndexByID[id]].rule.Specificity
}
