package scan

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/betterleaks/betterleaks/v2/internal/logging"
	"github.com/betterleaks/betterleaks/v2/internal/regexspan"
	"github.com/betterleaks/betterleaks/v2/internal/ruletiming"
	"github.com/betterleaks/betterleaks/v2/internal/tokenizer"
	blregexp "github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

var allowSignatures = [...]string{"betterleaks:allow", "gitleaks:allow"}

var errStopScan = errors.New("scanner: stop scan")

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

// Scanner is an immutable rule engine with thread-safe lazy regex compilation. A
// Scanner may be reused concurrently with independent sources. Each scan
// owns its execution state and shares the Scanner's detection worker limit.
// A Scanner must be constructed with New; its zero value is not usable.
type Scanner struct {
	ignoredFingerprints map[fingerprint.Hash]struct{}
	maxDecodeDepth      int
	matchContext        contextwindow.Spec
	minimumConfidence   string
	ignoreAllowComments bool
	workers             int
	workerSlots         *semaphore.Weighted
	logger              *slog.Logger

	keywordMatcher *ahocorasick.Matcher

	tokenCounter     *tokenizer.Counter
	tokenCounterOnce sync.Once

	exprRuntime *exprruntime.LocalRuntime

	globalFilter exprruntime.Program

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

// New creates a Scanner from cfg and compiles all finding filters, returning an
// error for invalid expressions. Rule regexes compile lazily unless
// [WithPrecompile] is supplied. Sources own prefilter evaluation; cfg.Prefilter
// is not used by the Scanner.
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
	rulesBySpecificity, ruleIndexByID, snapshotErr := snapshotRules(cfg, settings.regexEngine)
	if snapshotErr != nil {
		return nil, fmt.Errorf("invalid config: %w", snapshotErr)
	}

	exprRuntime := exprruntime.NewLocal(settings.regexEngine)

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
	if err := s.compileFilters(cfg.Filter); err != nil {
		return nil, err
	}

	if settings.precompile {
		if err := s.compileRegexes(); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (s *Scanner) compileRegexes() error {
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

// Scan scans the source, passes each finding to handler, and returns a
// per-call summary. Recoverable source errors are joined. Returning an error
// from handler stops the scan. A nil handler discards findings. Finding order
// is not guaranteed. Concurrent calls are safe with independent sources.
// Detection regex compilation failures stop the scan and are returned as errors.
// A nil or zero-value Scanner returns an error.
func (s *Scanner) Scan(ctx context.Context, source sources.Source, handler Handler) (ScanSummary, error) {
	if s == nil || s.workerSlots == nil {
		return ScanSummary{}, errors.New("scanner must be constructed with New")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var scanErr error
	summary := s.run(ctx, source, func(result scanResult) bool {
		if result.err != nil {
			scanErr = errors.Join(scanErr, result.err)
			return true
		}
		if handler != nil {
			if err := handler(result.finding); err != nil {
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

type scanResult struct {
	finding report.Finding
	err     error
}

type scanState struct {
	bytes       atomic.Uint64
	summary     ScanSummary
	ruleTimings *ruletiming.Collector
}

type fragmentResult struct {
	findings []report.Finding
	err      error
	// Detection failures stop the scan; yielded source errors can be accumulated.
	fatal bool
}

//nolint:nonamedreturns // Deferred cleanup joins workers before collecting the final byte count.
func (s *Scanner) run(ctx context.Context, source sources.Source, yield func(scanResult) bool) (summary ScanSummary) {
	state := scanState{}
	if source == nil {
		_ = yield(scanResult{err: errors.New("scanner: nil source")})
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
			return errStopScan
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
					return errStopScan
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
				findings, err := s.detectFragmentWithState(runCtx, fragment, &state)
				s.workerSlots.Release(1)
				resultsCh <- fragmentResult{findings: findings, err: err, fatal: err != nil}
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
		if !result.fatal && isPipelineStop(result.err) {
			continue
		}
		for _, finding := range result.findings {
			if runCtx.Err() != nil {
				return state.summary
			}
			state.summary.Findings++
			if !yield(scanResult{finding: finding}) {
				return state.summary
			}
		}
		if result.err != nil {
			if !yield(scanResult{err: result.err}) || result.fatal {
				return state.summary
			}
		}
	}
	return state.summary
}

func isPipelineStop(err error) bool {
	return errors.Is(err, errStopScan) || errors.Is(err, context.Canceled)
}

func rulePathMatchesFragment(rule *compiledRule, fragment sources.Fragment) (bool, error) {
	path := fragment.Attr(sources.AttrPath)
	if path == "" || rule.path == nil || !pathSuffixPossible(path, rule.pathSuffixes) {
		return false, nil
	}
	if err := rule.path.Compile(); err != nil {
		return false, fmt.Errorf("compile rule %q path regex: %w", rule.rule.ID, err)
	}
	return rule.path.MatchString(path), nil
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
// Backend compilation failures are logged through the configured logger;
// findings collected before the failure are returned. Use Scan to receive errors.
// If the Scanner is nil or was not constructed with New, it logs a warning
// through slog's default logger and returns no findings.
func (s *Scanner) ScanString(content string) []report.Finding {
	if s == nil || s.workerSlots == nil {
		slog.Warn("scanner must be constructed with New")
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
	findings, err := s.detectFragmentWithState(ctx, fragment, nil)
	if err != nil {
		s.logger.Error("could not scan fragment", "error", err)
	}
	return findings
}

func (s *Scanner) detectFragmentWithState(ctx context.Context, fragment sources.Fragment, state *scanState) ([]report.Finding, error) {
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
	var detectionErr error

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

		RulesLoop:
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
					ruleFindings, err := s.detectFragmentWithRuleTimed(ruleTimings, fragment, currentRaw, rule, encodedSegments, priorFindings, &detection)
					if err != nil {
						detectionErr = err
						break RulesLoop
					}
					for _, finding := range ruleFindings {
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
			if detectionErr != nil {
				break ScanLoop
			}

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
	return findings, detectionErr
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
	state *detectionState) ([]report.Finding, error) {
	if ruleTimings == nil {
		return s.detectFragmentWithRule(nil, fragment, currentRaw, r, encodedSegments, priorFindings, state)
	}

	start := time.Now()
	findings, err := s.detectFragmentWithRule(ruleTimings, fragment, currentRaw, r, encodedSegments, priorFindings, state)
	ruleTimings.Record(r.rule.ID, time.Since(start))
	return findings, err
}

func snapshotRules(cfg *config.Config, engine blregexp.Engine) ([]compiledRule, map[string]int, error) {
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	rules := make([]compiledRule, len(cfg.Rules))
	for i, source := range cfg.Rules {
		rule := source
		rule.Keywords = slices.Clone(source.Keywords)
		rule.Tags = slices.Clone(source.Tags)
		compiled := compiledRule{rule: rule}
		if rule.Regex != "" {
			var err error
			compiled.guard = compileAssignmentGuard(rule.Regex, rule.Keywords)
			compiled.span = regexspan.Compile(rule.Regex, rule.Keywords)
			if compiled.span == nil {
				compiled.span, compiled.searchAnchors = compilePrefixWindows(rule.Regex, rule.Keywords)
			}
			compiled.regex, err = blregexp.CompileWithEngine(rule.Regex, engine)
			if err != nil {
				return nil, nil, fmt.Errorf("compile rule %q regex: %w", rule.ID, err)
			}
		}
		if rule.Path != "" {
			var err error
			compiled.pathSuffixes = compilePathSuffixes(rule.Path)
			compiled.path, err = blregexp.CompileWithEngine(rule.Path, engine)
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
	state *detectionState) ([]report.Finding, error) {
	var (
		findings []report.Finding
		logger   = s.logger
	)

	if r.rule.SkipReport && !state.component {
		return findings, nil
	}

	// Ensure default fields are properly set
	fragment.SetDefaults()

	if r.regex == nil {
		// Decoding content cannot change a path-only result.
		if len(encodedSegments) > 0 {
			return findings, nil
		}
		matched, err := rulePathMatchesFragment(r, fragment)
		if err != nil {
			return nil, err
		}
		if matched {
			finding := newPathOnlyFinding(r, fragment)
			if !s.filterPathFinding(r, &finding) {
				return append(findings, finding), nil
			}
		}
		return findings, nil
	}

	if r.path != nil {
		// If a rule defines both `path` and `regex`, the normalized fragment path
		// must match before we spend time checking the content regex.
		matched, err := rulePathMatchesFragment(r, fragment)
		if err != nil || !matched {
			return nil, err
		}
	}

	var matches [][]int
	find := func(raw string) ([][]int, error) {
		if r.span != nil && r.span.RequiredByte != 0 && strings.IndexByte(raw, r.span.RequiredByte) < 0 {
			return nil, nil
		}
		if err := r.regex.Compile(); err != nil {
			return nil, fmt.Errorf("compile rule %q regex: %w", r.rule.ID, err)
		}
		if r.regex.NumSubexp() > 0 {
			return r.regex.FindAllStringSubmatchIndex(raw, -1), nil
		}
		return r.regex.FindAllStringIndex(raw, -1), nil
	}
	if len(state.spans) == 0 {
		var err error
		matches, err = find(currentRaw)
		if err != nil {
			return nil, err
		}
	} else {
		for _, span := range state.spans {
			part, err := find(currentRaw[span.Start:span.End])
			if err != nil {
				return nil, err
			}
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
		return findings, nil
	}
	var names []string
	if r.regex.NumSubexp() > 0 {
		names = r.regex.SubexpNames()
	}

	for _, indexes := range matches {
		matchIndex := indexes[:2]
		secret := strings.Trim(currentRaw[matchIndex[0]:matchIndex[1]], "\n")
		filterMatchStartIdx, filterMatchEndIdx := matchIndex[0], matchIndex[1]

		var encodings []string
		var decodeDepth int
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
			encodings, decodeDepth = codec.Decoding(segments)
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

		prevFragmentEndLine := fragment.StartLine - 1
		finding := report.Finding{
			RuleID:      r.rule.ID,
			Description: r.rule.Description,
			Encodings:   encodings,
			DecodeDepth: decodeDepth,
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

		hasGlobalFilter := s.globalFilter != nil
		hasRuleFilter := r.filter != nil
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
		if prg := s.globalFilter; prg != nil {
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
		if prg := r.filter; prg != nil {
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
		return findings, nil
	}

	return s.processComponents(ruleTimings, fragment, currentRaw, r, encodedSegments, findings, state)
}

// processComponents attaches nearby component matches and enforces required components.
func (s *Scanner) processComponents(ruleTimings *ruletiming.Collector, fragment sources.Fragment, currentRaw string, r *compiledRule, encodedSegments []*codec.EncodedSegment, primaryFindings []report.Finding, state *detectionState) ([]report.Finding, error) {
	if len(primaryFindings) == 0 {
		return primaryFindings, nil
	}

	allComponentFindings := make([][]report.Finding, len(r.components))
	componentState := detectionState{component: true, lineOffsets: state.lineOffsets}
	for i, component := range r.components {
		rule := &s.rulesBySpecificity[component.ruleIndex]
		var err error
		allComponentFindings[i], err = s.detectFragmentWithRuleTimed(ruleTimings, fragment, currentRaw, rule, encodedSegments, nil, &componentState)
		if err != nil {
			return nil, err
		}
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
						RuleID:      found.RuleID,
						Optional:    component.optional,
						Match:       found.Match,
						Location:    found.Location,
						Encodings:   found.Encodings,
						DecodeDepth: found.DecodeDepth,
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
	return finalFindings, nil
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
	if s.globalFilter == nil && r.filter == nil {
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
	for _, prg := range []exprruntime.Program{s.globalFilter, r.filter} {
		if prg == nil {
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
