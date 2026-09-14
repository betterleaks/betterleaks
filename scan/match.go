package scan

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/internal/codec"
	"github.com/betterleaks/betterleaks/v2/internal/confidence"
	"github.com/betterleaks/betterleaks/v2/internal/contextwindow"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/ruletiming"
	blregexp "github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

func rulePathMatchesFragment(pathRule *blregexp.Regexp, fragment sources.Fragment) bool {
	path := fragment.Attr(sources.AttrPath)
	return path != "" && pathRule != nil && pathRule.MatchString(path)
}

func newPathOnlyFinding(r *compiledRule, fragment sources.Fragment) report.Finding {
	path := fragment.Attr(sources.AttrPath)
	finding := report.Finding{
		RuleID:          r.rule.ID,
		Description:     r.rule.Description,
		Match:           report.Match{Full: "file detected: " + path},
		Tags:            append([]string{}, r.rule.Tags...),
		RuleSpecificity: r.rule.Specificity,
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
		if len(source.Components) > 0 {
			rule.Components = make([]*config.Component, len(source.Components))
			for componentIndex, component := range source.Components {
				copy := *component
				rule.Components[componentIndex] = &copy
			}
		}
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
			RuleID:          r.rule.ID,
			Description:     r.rule.Description,
			Line:            strings.Clone(fragment.Raw[loc.startLineIndex:loc.endLineIndex]),
			Match:           report.Match{Full: secret, Value: secret},
			Tags:            tags,
			RuleSpecificity: r.rule.Specificity,
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
		if !d.ignoreAllowComments && containsAllowSignature(finding.Line) {
			logTrace(logger, "skipping finding: allow signature found", "finding", finding.Match.Value)
			continue
		}
		if currentLine == "" {
			currentLine = finding.Line
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
			finding.MatchContext = strings.Clone(contextwindow.Extract(fragment.Raw, matchIndex, d.matchContext))
		}

		// Build finding map once, only when at least one filter program is compiled.
		var findingMap map[string]any
		var exprAttributes map[string]string
		if hasGlobalFilter || hasRuleFilter {
			exprAttributes = finding.ExprAttributes()
			findingMap = make(map[string]any, 12)
			for key, value := range finding.ToExprMap() {
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
			skip, err := d.exprRuntime.EvalFilter(prg, findingMap, exprAttributes)
			promoteConfidence(&finding, findingMap, exprAttributes)
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
			skip, err := d.exprRuntime.EvalFilter(prg, findingMap, exprAttributes)
			promoteConfidence(&finding, findingMap, exprAttributes)
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
		var componentFindings []*report.ComponentFinding

		for _, component := range r.rule.Components {
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
						Location:        found.Location,
						RuleSpecificity: found.RuleSpecificity,
					})
				}
			}
		}

		if d.hasAllRequiredComponents(componentFindings, r.rule.Components) {
			newFinding := primaryFinding
			newFinding.BuildComponentSets(componentFindings, maxComponentSets)
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
func (d *Scanner) hasAllRequiredComponents(componentFindings []*report.ComponentFinding, components []*config.Component) bool {
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
	attrs := finding.ExprAttributes()
	values := make(map[string]any, 15)
	for key, value := range finding.ToExprMap() {
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
