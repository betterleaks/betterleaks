package pipeline

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"iter"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkoukk/tiktoken-go"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect/codec"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/validate"
	"github.com/betterleaks/betterleaks/words"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/rs/zerolog"
	"golang.org/x/exp/maps"
)

// allowSignatures are comment tags that can be used to ignore findings.
// betterleaks:allow is checked first (preferred), followed by gitleaks:allow for backwards compatibility.
var allowSignatures = []string{"betterleaks:allow", "gitleaks:allow"}

var newlineReplacer = strings.NewReplacer("\n", "", "\r", "")

var errStopIteration = errors.New("pipeline: stop iteration")

const (
	// SlowWarningThreshold is the amount of time to wait before logging that a file is slow.
	// This is useful for identifying problematic files and tuning the allowlist.
	SlowWarningThreshold = 5 * time.Second

	// maxRequiredSets caps the Cartesian product of required-finding combinations
	// to prevent excessive memory use with large multi-part rules.
	maxRequiredSets = 100
)

// Pipeline is the main detector struct
type Pipeline struct {
	// Config is the configuration for the detector
	Config config.Config

	// MaxDecodeDepths limits how many recursive decoding passes are allowed
	MaxDecodeDepth int

	// MatchContext specifies how much context to extract around a match.
	MatchContext MatchContextSpec

	// ValidationStatusFilter, when non-empty, restricts which findings are
	// printed in verbose mode. Parsed from --validation-status.
	ValidationStatusFilter map[string]struct{}

	// ValidationPool is the CEL validation worker pool.
	ValidationPool *validate.Pool

	// ValidationCounts tracks how many findings were returned for each
	// ValidationStatus value. Populated by the DetectSource consumer goroutine;
	// safe to read after DetectSource returns.
	ValidationCounts map[string]int

	// ValidationExtractEmpty controls whether empty values from extractors
	// are included in validation output.
	ValidationExtractEmpty bool

	// IgnoreGitleaksAllow is a flag to ignore gitleaks:allow comments.
	IgnoreGitleaksAllow bool

	TotalBytes atomic.Uint64

	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter ahocorasick.Trie

	// a list of known findings that should be ignored
	baseline []report.Finding

	// path to baseline
	baselinePath string

	// gitleaksIgnore
	gitleaksIgnore map[string]struct{}

	tokenizer *tiktoken.Tiktoken
}

type Result struct {
	Finding report.Finding
	Err     error
}

// NewPipeline is the same as NewDetector but supports passing in a
// context to use for timeouts
func NewPipeline(ctx context.Context, cfg config.Config) *Pipeline {
	// grab offline tiktoken encoder
	tiktoken.SetBpeLoader(&TiktokenLoader{})
	tke, err := tiktoken.GetEncoding("cl100k_base")
	if err != nil {
		logging.Warn().Err(err).Msgf("Could not pull down cl100k_base tiktokenizer")
	}

	return &Pipeline{
		gitleaksIgnore:   make(map[string]struct{}),
		ValidationCounts: make(map[string]int),
		Config:           cfg,
		prefilter:        *ahocorasick.NewTrieBuilder().AddStrings(maps.Keys(cfg.Keywords)).Build(),
		tokenizer:        tke,
	}
}

// Run executes the pipeline on the given source and yields results as they are found.
// It returns an iterator of Results, which can be consumed by the caller. We return an iterator to make the API clean.
// You can do things like:
//
//		for result := range pipeline.Run(ctx, source) {
//	    	// do something
//		}
//
// The context can be used to cancel the scan.
// Internally uses a channel to send results from the scanning goroutine to the caller,
// allowing for concurrent processing of findings as they are discovered.
func (p *Pipeline) Run(ctx context.Context, source sources.Source) iter.Seq[Result] {
	return func(yield func(Result) bool) {
		if source == nil {
			_ = yield(Result{Err: fmt.Errorf("pipeline: nil source")})
			return
		}

		runCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// main channel for sending results back to the caller (eventually gets consumed by `emit`)
		resultsCh := make(chan Result, 1000)

		if p.ValidationCounts == nil {
			p.ValidationCounts = make(map[string]int)
		} else {
			clear(p.ValidationCounts)
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
		if p.ValidationPool != nil {
			p.ValidationPool.Emit = func(f report.Finding) {
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

				findings := p.scanFragment(runCtx, fragment)
				for _, finding := range findings {
					// if err := routeFinding(finding); err != nil {
					if err := p.routeFinding(finding, emit); err != nil {
						return err
					}
				}

				return nil
			})

			if p.ValidationPool != nil {
				p.ValidationPool.Close()

				hits, misses := p.ValidationPool.Stats()
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
				if !p.ValidationExtractEmpty {
					res.Finding.ValidationMeta = stripEmptyMeta(res.Finding.ValidationMeta)
				}
				if res.Finding.ValidationStatus != "" {
					p.ValidationCounts[res.Finding.ValidationStatus]++
				}
			}

			if !yield(res) {
				cancel()
				return
			}
		}
	}
}

func (p *Pipeline) routeFinding(finding report.Finding, emit func(Result) error) error {
	globalFingerprint := fmt.Sprintf("%s:%s:%d", finding.File, finding.RuleID, finding.StartLine)
	if finding.Commit != "" {
		finding.Fingerprint = fmt.Sprintf("%s:%s:%s:%d", finding.Commit, finding.File, finding.RuleID, finding.StartLine)
	} else {
		finding.Fingerprint = globalFingerprint
	}

	logger := logging.With().Str("finding", finding.Secret).Logger()
	if _, ok := p.gitleaksIgnore[globalFingerprint]; ok {
		logger.Debug().
			Str("fingerprint", globalFingerprint).
			Msg("skipping finding: global fingerprint")
		return nil
	} else if finding.Commit != "" {
		if _, ok := p.gitleaksIgnore[finding.Fingerprint]; ok {
			logger.Debug().
				Str("fingerprint", finding.Fingerprint).
				Msgf("skipping finding: fingerprint")
			return nil
		}
	}

	if p.baseline != nil && !IsNew(finding, 0, p.baseline) {
		logger.Debug().
			Str("fingerprint", finding.Fingerprint).
			Msgf("skipping finding: baseline")
		return nil
	}

	if p.ValidationPool != nil {
		if rule, ok := p.Config.Rules[finding.RuleID]; ok && rule.CelProgram() != nil {
			p.submitValidation(finding, rule)
			return nil
		}
	}

	return emit(Result{Finding: finding})
}

// submitValidation submits a finding to the validation pool.
// RequiredSets are already populated on the finding.
func (p *Pipeline) submitValidation(finding report.Finding, rule config.Rule) {
	p.ValidationPool.Submit(finding, rule.CelProgram(), finding.CaptureGroups)
}

func (p *Pipeline) scanFragment(ctx context.Context, fragment sources.Fragment) []report.Finding {
	if fragment.Bytes == nil {
		p.TotalBytes.Add(uint64(len(fragment.Raw)))
	}
	p.TotalBytes.Add(uint64(len(fragment.Bytes)))

	var (
		findings []report.Finding
		logger   = fragment.Logger()
	)

	// check if filepath is allowed
	if fragment.Attr(sources.AttrPath) != "" {
		// is the path our config or baseline file?
		if fragment.Attr(sources.AttrPath) == p.Config.Path || (p.baselinePath != "" && fragment.Attr(sources.AttrPath) == p.baselinePath) {
			logging.Trace().Msg("skipping file: matches config or baseline path")
			return findings
		}
	}
	// check if commit or filepath is allowed.
	if isAllowed, event := checkCommitOrPathAllowed(logger, fragment, p.Config.Allowlists); isAllowed {
		event.Msg("skipping file: global allowlist")
		return findings
	}

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
			// Use Aho-Corasick to find keyword matches, then map directly
			// to the rules that need checking via KeywordToRules.
			// Use a pooled byte buffer for lowercasing to avoid allocating
			lowerBufPtr, lowerBuf := getLowerBuf(currentRaw)
			acMatches := p.prefilter.Match(lowerBuf)

			// Build a set of rule IDs to check based on keyword matches.
			rulesToCheck := make(map[string]struct{}, len(acMatches))
			for _, m := range acMatches {
				// m.Match() returns the keyword as []byte; convert to string
				// for the map lookup. This is a small allocation per keyword
				// match (typically few), not per fragment byte.
				keyword := string(m.Match())
				for _, ruleID := range p.Config.KeywordToRules[keyword] {
					rulesToCheck[ruleID] = struct{}{}
				}
			}
			putLowerBuf(lowerBufPtr)
			// Always include rules that have no keywords.
			for _, ruleID := range p.Config.NoKeywordRules {
				rulesToCheck[ruleID] = struct{}{}
			}

			for ruleID := range rulesToCheck {
				select {
				case <-ctx.Done():
					break ScanLoop
				default:
					rule := p.Config.Rules[ruleID]
					findings = append(findings, p.scanWithRule(fragment, currentRaw, rule, encodedSegments)...)
				}
			}

			// increment the depth by 1 as we start our decoding pass
			currentDecodeDepth++

			// stop the loop if we've hit our max decoding depth
			if currentDecodeDepth > p.MaxDecodeDepth {
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

// scanWithRule scans the given fragment for the given rule and returns a list of findings
func (p *Pipeline) scanWithRule(fragment sources.Fragment, currentRaw string, r config.Rule, encodedSegments []*codec.EncodedSegment) []report.Finding {
	var (
		findings []report.Finding
		logger   = fragment.Logger().With().Str("rule_id", r.RuleID).Logger()
	)

	if r.SkipReport && !fragment.InheritedFromFinding {
		return findings
	}

	// check if commit or file is allowed for this rule.
	if isAllowed, event := checkCommitOrPathAllowed(logger, fragment, r.Allowlists); isAllowed {
		event.Msg("skipping file: rule allowlist")
		return findings
	}

	if r.Path != nil {
		wp := fragment.Attr(sources.AttrFSWindowsPath)
		if r.Regex == nil && len(encodedSegments) == 0 {
			// Path _only_ rule
			if r.Path.MatchString(fragment.Attr(sources.AttrPath)) || (wp != "" && r.Path.MatchString(wp)) {
				finding := report.Finding{
					Commit:      fragment.Attr(sources.AttrGitSHA),
					RuleID:      r.RuleID,
					Description: r.Description,
					File:        fragment.Attr(sources.AttrPath),
					SymlinkFile: fragment.Attr(sources.AttrFSSymlink),
					Match:       "file detected: " + fragment.Attr(sources.AttrPath),
					Tags:        r.Tags,
				}
				if finding.Commit != "" {
					finding.Author = fragment.Attr(sources.AttrGitAuthorName)
					finding.Date = fragment.Attr(sources.AttrGitDate)
					finding.Email = fragment.Attr(sources.AttrGitAuthorEmail)
					finding.Message = fragment.Attr(sources.AttrGitMessage)
					finding.Link = createScmLink(
						fragment.Attr(sources.AttrGitPlatform),
						fragment.Attr(sources.AttrGitRemoteURL),
						finding,
					)
				}
				return append(findings, finding)
			}
		} else {
			// if path is set _and_ a regex is set, then we need to check both
			// so if the path does not match, then we should return early and not
			// consider the regex
			if !r.Path.MatchString(fragment.Attr(sources.AttrPath)) && (wp == "" || !r.Path.MatchString(wp)) {
				return findings
			}
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

		finding := report.Finding{
			Commit:      fragment.Attr(sources.AttrGitSHA),
			RuleID:      r.RuleID,
			Description: r.Description,
			StartLine:   fragment.StartLine + loc.startLine,
			EndLine:     fragment.StartLine + loc.endLine,
			StartColumn: loc.startColumn,
			EndColumn:   loc.endColumn,
			Line:        fragment.Raw[loc.startLineIndex:loc.endLineIndex],
			Match:       secret,
			Secret:      secret,
			File:        fragment.Attr(sources.AttrPath),
			SymlinkFile: fragment.Attr(sources.AttrFSSymlink),
			Tags: func() []string {
				if len(metaTags) == 0 {
					return r.Tags
				}
				return append(r.Tags, metaTags...)
			}(),
		}
		if finding.Commit != "" {
			finding.Author = fragment.Attr(sources.AttrGitAuthorName)
			finding.Date = fragment.Attr(sources.AttrGitDate)
			finding.Email = fragment.Attr(sources.AttrGitAuthorEmail)
			finding.Message = fragment.Attr(sources.AttrGitMessage)
			finding.Link = createScmLink(
				fragment.Attr(sources.AttrGitPlatform),
				fragment.Attr(sources.AttrGitRemoteURL),
				finding,
			)
		}
		if !p.IgnoreGitleaksAllow && containsAllowSignature(finding.Line) {
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
					captures[name] = groups[i]
				}
			}
			if len(captures) > 0 {
				finding.CaptureGroups = captures
			}
		}

		// check entropy
		entropy := shannonEntropy(finding.Secret)
		finding.Entropy = float32(entropy)
		if r.Entropy != 0.0 {
			// entropy is too low, skip this finding
			if entropy <= r.Entropy {
				logger.Trace().
					Str("finding", finding.Secret).
					Float32("entropy", finding.Entropy).
					Msg("skipping finding: low entropy")
				continue
			}
		}

		// check if the result matches any of the global allowlists.
		if isAllowed, event := checkFindingAllowed(logger, finding, fragment, currentLine, p.Config.Allowlists); isAllowed {
			event.Msg("skipping finding: global allowlist")
			continue
		}

		// check if the result matches any of the rule allowlists.
		if isAllowed, event := checkFindingAllowed(logger, finding, fragment, currentLine, r.Allowlists); isAllowed {
			event.Msg("skipping finding: rule allowlist")
			continue
		}

		if r.TokenEfficiency {
			if p.failsTokenEfficiencyFilter(finding.Secret) {
				continue
			}
		}
		if !p.MatchContext.IsZero() {
			finding.MatchContext = extractContext(fragment.Raw, matchIndex, p.MatchContext)
		}
		findings = append(findings, finding)
	}

	// Handle required rules (multi-part rules)
	if fragment.InheritedFromFinding || len(r.RequiredRules) == 0 {
		return findings
	}

	// Process required rules and create findings with auxiliary findings
	return p.processRequiredRules(fragment, currentRaw, r, encodedSegments, findings, logger)
}

func (p *Pipeline) failsTokenEfficiencyFilter(secret string) bool {
	// Skip token-efficiency filtering if the tokenizer failed to initialize.
	// (e.g., network error downloading cl100k_base)
	if p.tokenizer == nil {
		return false
	}

	// For short secrets (< 20 chars) that contain newlines, strip the newlines
	// before analysis so that strings like "123\n\nTest" are evaluated as "123Test"
	// allowing word detection to work.
	analyzed := secret
	if len(analyzed) < 20 && strings.ContainsAny(analyzed, "\n\r") {
		analyzed = newlineReplacer.Replace(analyzed)
	}

	tokens := p.tokenizer.Encode(analyzed, nil, nil)

	matches := words.HasMatchInList(analyzed, 5)
	if len(matches) > 0 {
		return true
	}
	threshold := 2.5
	if len(analyzed) < 12 {
		threshold = 2.1
		matches := words.HasMatchInList(analyzed, 4)
		if len(matches) == 0 {
			threshold = 2.5
		}
	}
	return float64(len(analyzed))/float64(len(tokens)) >= threshold
}

// processRequiredRules handles the logic for multi-part rules with auxiliary findings
func (p *Pipeline) processRequiredRules(fragment sources.Fragment, currentRaw string, r config.Rule, encodedSegments []*codec.EncodedSegment, primaryFindings []report.Finding, logger zerolog.Logger) []report.Finding {
	if len(primaryFindings) == 0 {
		logger.Debug().Msg("no primary findings to process for required rules")
		return primaryFindings
	}

	// Pre-collect all required rule findings once
	allRequiredFindings := make(map[string][]report.Finding)

	for _, requiredRule := range r.RequiredRules {
		rule, ok := p.Config.Rules[requiredRule.RuleID]
		if !ok {
			logger.Error().Str("rule-id", requiredRule.RuleID).Msg("required rule not found in config")
			continue
		}

		// Mark fragment as inherited to prevent infinite recursion
		inheritedFragment := fragment
		inheritedFragment.InheritedFromFinding = true

		// Call detectRule once for each required rule
		requiredFindings := p.scanWithRule(inheritedFragment, currentRaw, rule, encodedSegments)
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
				if p.withinProximity(primaryFinding, requiredFinding, requiredRule) {
					req := &report.RequiredFinding{
						RuleID:        requiredFinding.RuleID,
						StartLine:     requiredFinding.StartLine,
						EndLine:       requiredFinding.EndLine,
						StartColumn:   requiredFinding.StartColumn,
						EndColumn:     requiredFinding.EndColumn,
						Line:          requiredFinding.Line,
						Match:         requiredFinding.Match,
						Secret:        requiredFinding.Secret,
						CaptureGroups: requiredFinding.CaptureGroups,
					}
					requiredFindings = append(requiredFindings, req)
				}
			}
		}

		// Check if we have at least one auxiliary finding for each required rule
		if len(requiredFindings) > 0 && p.hasAllRequiredRules(requiredFindings, r.RequiredRules) {
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
func (p *Pipeline) hasAllRequiredRules(auxiliaryFindings []*report.RequiredFinding, requiredRules []*config.Required) bool {
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

func (p *Pipeline) withinProximity(primary, required report.Finding, requiredRule *config.Required) bool {
	// fmt.Println(requiredRule.WithinLines)
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

// FilterByStatus returns findings whose ValidationStatus is in
// d.ValidationStatusFilter. If the filter is empty, all findings are returned.
// The pseudo-status "none" matches findings with no ValidationStatus set.
func (p *Pipeline) FilterByStatus(findings []report.Finding) []report.Finding {
	if len(p.ValidationStatusFilter) == 0 {
		return findings
	}
	_, includeNone := p.ValidationStatusFilter["none"]
	var filtered []report.Finding
	for _, f := range findings {
		if f.ValidationStatus == "" {
			if includeNone {
				filtered = append(filtered, f)
			}
			continue
		}
		if _, ok := p.ValidationStatusFilter[f.ValidationStatus]; ok {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// checkCommitOrPathAllowed evaluates |fragment| against all provided |allowlists|.
//
// If the match condition is "OR", only commit and path are checked.
// Otherwise, if regexes or stopwords are defined this will fail.
func checkCommitOrPathAllowed(
	logger zerolog.Logger,
	fragment sources.Fragment,
	allowlists []*config.Allowlist,
) (bool, *zerolog.Event) {
	if fragment.Attr(sources.AttrPath) == "" && fragment.Attr(sources.AttrGitSHA) == "" {
		return false, nil
	}

	for _, a := range allowlists {
		windowsPath := fragment.Attr(sources.AttrFSWindowsPath)
		var (
			isAllowed        bool
			allowlistChecks  []bool
			commitAllowed, _ = a.CommitAllowed(fragment.Attr(sources.AttrGitSHA))
			pathAllowed      = a.PathAllowed(fragment.Attr(sources.AttrPath)) || (windowsPath != "" && a.PathAllowed(windowsPath))
		)
		// If the condition is "AND" we need to check all conditions.
		if a.MatchCondition == config.AllowlistMatchAnd {
			if len(a.Commits) > 0 {
				allowlistChecks = append(allowlistChecks, commitAllowed)
			}
			if len(a.Paths) > 0 {
				allowlistChecks = append(allowlistChecks, pathAllowed)
			}
			// These will be checked later.
			if len(a.Regexes) > 0 {
				continue
			}
			if len(a.StopWords) > 0 {
				continue
			}

			isAllowed = allTrue(allowlistChecks)
		} else {
			isAllowed = commitAllowed || pathAllowed
		}
		if isAllowed {
			event := logger.Trace().Str("condition", a.MatchCondition.String())
			if commitAllowed {
				event.Bool("allowed-commit", commitAllowed)
			}
			if pathAllowed {
				event.Bool("allowed-path", pathAllowed)
			}
			return true, event
		}
	}
	return false, nil
}

// checkFindingAllowed evaluates |finding| against all provided |allowlists|.
//
// If the match condition is "OR", only regex and stopwords are run. (Commit and path should be handled separately).
// Otherwise, all conditions are checked.
//
// TODO: The method signature is awkward. I can't think of a better way to log helpful info.
func checkFindingAllowed(
	logger zerolog.Logger,
	finding report.Finding,
	fragment sources.Fragment,
	currentLine string,
	allowlists []*config.Allowlist,
) (bool, *zerolog.Event) {
	for _, a := range allowlists {
		allowlistTarget := finding.Secret
		switch a.RegexTarget {
		case "match":
			allowlistTarget = finding.Match
		case "line":
			allowlistTarget = currentLine
		}

		var (
			checks                 []bool
			isAllowed              bool
			commitAllowed          bool
			commit                 string
			pathAllowed            bool
			regexAllowed           = a.RegexAllowed(allowlistTarget)
			containsStopword, word = a.ContainsStopWord(finding.Secret)
		)
		// If the condition is "AND" we need to check all conditions.
		if a.MatchCondition == config.AllowlistMatchAnd {
			// Determine applicable checks.
			if len(a.Commits) > 0 {
				commitAllowed, commit = a.CommitAllowed(fragment.Attr(sources.AttrGitSHA))
				checks = append(checks, commitAllowed)
			}
			if len(a.Paths) > 0 {
				wp := fragment.Attr(sources.AttrFSWindowsPath)
				pathAllowed = a.PathAllowed(fragment.Attr(sources.AttrPath)) || (wp != "" && a.PathAllowed(wp))
				checks = append(checks, pathAllowed)
			}
			if len(a.Regexes) > 0 {
				checks = append(checks, regexAllowed)
			}
			if len(a.StopWords) > 0 {
				checks = append(checks, containsStopword)
			}

			isAllowed = allTrue(checks)
		} else {
			isAllowed = regexAllowed || containsStopword
		}

		if isAllowed {
			event := logger.Trace().
				Str("finding", finding.Secret).
				Str("condition", a.MatchCondition.String())
			if commitAllowed {
				event.Str("allowed-commit", commit)
			}
			if pathAllowed {
				event.Bool("allowed-path", pathAllowed)
			}
			if regexAllowed {
				event.Bool("allowed-regex", regexAllowed)
			}
			if containsStopword {
				event.Str("allowed-stopword", word)
			}
			return true, event
		}
	}
	return false, nil
}

func (p *Pipeline) AddGitleaksIgnore(gitleaksIgnorePath string) error {
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
		p.gitleaksIgnore[strings.Join(s, ":")] = struct{}{}
	}
	return nil
}
