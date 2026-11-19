package scan

import (
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/codec"
	"github.com/betterleaks/betterleaks/v2/internal/ruletiming"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// routeAlert is one provider keyword occurrence in the text currently being scanned.
type routeAlert struct {
	ruleIndex  int
	start, end int
}

// genericHit is a generic finding still paired with its match offsets. Those
// offsets are in the current decode pass, which is also where route alerts are.
type genericHit struct {
	finding    report.Finding
	start, end int
	line       string
}

// isGenericRule reports fallback detectors. Their findings can be kept beside
// a provider rule that matches the same secret.
func isGenericRule(id string) bool {
	return strings.HasPrefix(id, "generic-")
}

// claimsGenerics reports whether a keyword hit should be considered when
// pairing generic findings with this rule. The rule's own regex must require
// the keyword beside an assignment; token rules already match wherever their
// keyword sits. Words shared with the generic rules, such as "key", would
// otherwise claim every generic credential.
func (s *Scanner) claimsGenerics(ruleIndex int, genericWord bool) bool {
	if genericWord {
		return false
	}
	return s.providerPairsGeneric(s.rulesBySpecificity[ruleIndex].rule.ID)
}

// providerPairsGeneric reports assignment rules that may be reported together
// with a generic finding of the same secret. Generic credential words do not.
func (s *Scanner) providerPairsGeneric(ruleID string) bool {
	ruleIndex, ok := s.ruleIndexByID[ruleID]
	if !ok {
		return false
	}
	rule := &s.rulesBySpecificity[ruleIndex]
	if rule.guard == nil || rule.rule.SkipReport || isGenericRule(rule.rule.ID) {
		return false
	}
	for _, keyword := range rule.rule.Keywords {
		if _, genericWord := s.genericKeywords[strings.ToLower(keyword)]; !genericWord {
			return true
		}
	}
	return false
}

// isPairedProvider reports a provider finding that extracted the same secret
// as a generic finding at an overlapping location.
func (s *Scanner) isPairedProvider(generic, owner *report.Finding) bool {
	if !isGenericRule(generic.RuleID) || generic.Match.Value == "" || generic.Match.Value != owner.Match.Value {
		return false
	}
	if generic.Attributes[sources.AttrGitSHA] != owner.Attributes[sources.AttrGitSHA] {
		return false
	}
	if !locationsOverlap(generic.Location, owner.Location) {
		return false
	}
	return s.providerPairsGeneric(owner.RuleID)
}

// notePairedRules records provider rules that matched this generic secret so
// validation can drop the generic when one of those rules is confirmed live.
func (s *Scanner) notePairedRules(f *report.Finding, index *findingIndex) {
	if index == nil || !isGenericRule(f.RuleID) || f.Match.Value == "" {
		return
	}
	ids := make(map[string]struct{})
	s.visitOwners(*f, index, func(owner *report.Finding) {
		if s.isPairedProvider(f, owner) {
			ids[owner.RuleID] = struct{}{}
		}
	})
	if len(ids) == 0 {
		return
	}
	list := slices.Collect(maps.Keys(ids))
	slices.Sort(list)
	f.SetAttr(sources.AttrScanPairedRules, strings.Join(list, ","))
}

func (s *Scanner) visitOwners(f report.Finding, index *findingIndex, visit func(*report.Finding)) {
	if index == nil {
		return
	}
	seen := make(map[int]struct{})
	consider := func(i int) {
		if _, ok := seen[i]; ok {
			return
		}
		seen[i] = struct{}{}
		visit(&index.findings[i])
	}
	endLine := max(f.Location.StartLine, f.Location.EndLine)
	if len(index.byLine) > 0 {
		for line := f.Location.StartLine; line <= endLine; line++ {
			for _, i := range index.byLine[line] {
				consider(i)
			}
		}
	}
	if len(index.byBlock) > 0 {
		for block := f.Location.StartLine / findingLineBlockSize; block <= endLine/findingLineBlockSize; block++ {
			for _, i := range index.byBlock[block] {
				consider(i)
			}
		}
	}
}

// discardFinding applies the global filter and the rule filter. True means the
// finding is dropped. Filter errors are logged and do not drop the finding.
func (s *Scanner) discardFinding(logger *slog.Logger, r *compiledRule, finding *report.Finding, currentRaw, currentLine string, matchStart, matchEnd int) bool {
	if s.globalFilter == nil && r.filter == nil {
		return false
	}
	filterAttributes := exprAttributes(*finding)
	findingMap := make(map[string]any, 12)
	for key, value := range exprFinding(*finding) {
		findingMap[key] = value
	}
	findingMap["captures"] = finding.Match.Captures
	findingMap["entropy"] = strconv.FormatFloat(shannonEntropy(finding.Match.Value), 'g', -1, 64)
	findingMap["fragment_raw"] = currentRaw
	findingMap["match_start_idx"] = matchStart
	findingMap["match_end_idx"] = matchEnd
	findingMap["match_line_start_idx"] = 0
	findingMap["match_line_end_idx"] = len(currentRaw)
	if newline := strings.LastIndexAny(currentRaw[:matchStart], "\r\n"); newline >= 0 {
		findingMap["match_line_start_idx"] = newline + 1
	}
	if newline := strings.IndexAny(currentRaw[matchEnd:], "\r\n"); newline >= 0 {
		findingMap["match_line_end_idx"] = matchEnd + newline
	}
	// For decoded segments, currentLine carries the decoded line text
	// (via codec.CurrentLine). The old checkFindingAllowed used this for
	// regexTarget="line". Preserve that behaviour in the Expr path.
	if currentLine != "" {
		findingMap["line"] = currentLine
	}
	if prg := s.globalFilter; prg != nil {
		skip, err := s.exprRuntime.EvalFilter(prg, findingMap, filterAttributes)
		promoteConfidence(finding, findingMap, filterAttributes)
		if err != nil {
			logger.Warn("global filter eval error", "error", err)
		} else if skip {
			logTrace(logger, "skipping finding: global filter", "rule_id", finding.RuleID)
			return true
		}
	}
	if prg := r.filter; prg != nil {
		skip, err := s.exprRuntime.EvalFilter(prg, findingMap, filterAttributes)
		promoteConfidence(finding, findingMap, filterAttributes)
		if err != nil {
			logger.Warn("rule filter eval error", "error", err)
		} else if skip {
			logTrace(logger, "skipping finding: rule filter", "rule_id", finding.RuleID)
			return true
		}
	}
	return false
}

// routeGenericFindings adds a provider finding only when that rule's keyword
// appears in the fragment and the secret matches the provider regex's value
// pattern. The keyword does not have to sit next to the secret. Path, filter,
// and required components still apply. The generic finding stays until
// validation confirms the provider rule.
func (s *Scanner) routeGenericFindings(logger *slog.Logger, ruleTimings *ruletiming.Collector, fragment sources.Fragment, currentRaw string, genericRule *compiledRule, encodedSegments []*codec.EncodedSegment, priorFindings *findingIndex, hits []genericHit, state *detectionState) ([]report.Finding, error) {
	ruleOrder, err := s.routeRulesForFragment(fragment, state.routeAlerts)
	if err != nil {
		return nil, err
	}
	var staged []routedFinding
	for _, hit := range hits {
		for _, ruleIndex := range ruleOrder {
			rule := &s.rulesBySpecificity[ruleIndex]
			claims, err := s.providerRegexClaimsHit(rule, currentRaw, ruleIndex, state.routeAlerts, hit)
			if err != nil {
				return nil, err
			}
			if !claims {
				continue
			}
			candidate := retargetFinding(hit.finding, rule)
			if findingCovers(priorFindings, candidate) || routedCovers(staged, candidate) {
				continue
			}
			if s.discardFinding(logger, rule, &candidate, currentRaw, hit.line, hit.start, hit.end) {
				continue
			}
			logTrace(logger, "routing generic finding to keyword rule",
				"rule_id", candidate.RuleID, "generic_rule_id", genericRule.rule.ID)
			staged = append(staged, routedFinding{ruleIndex: ruleIndex, finding: candidate})
		}
	}
	if len(staged) == 0 {
		return nil, nil
	}

	grouped := make(map[int][]report.Finding)
	var groupOrder []int
	for _, item := range staged {
		if _, ok := grouped[item.ruleIndex]; !ok {
			groupOrder = append(groupOrder, item.ruleIndex)
		}
		grouped[item.ruleIndex] = append(grouped[item.ruleIndex], item.finding)
	}
	var routed []report.Finding
	for _, ruleIndex := range groupOrder {
		rule := &s.rulesBySpecificity[ruleIndex]
		primaries := grouped[ruleIndex]
		if len(rule.components) > 0 {
			var err error
			primaries, err = s.processComponents(ruleTimings, fragment, currentRaw, rule, encodedSegments, primaries, state)
			if err != nil {
				return nil, err
			}
		}
		routed = append(routed, primaries...)
	}
	return routed, nil
}

type routedFinding struct {
	ruleIndex int
	finding   report.Finding
}

// routeRulesForFragment drops assignment rules whose path does not match
// this fragment. Alerts were recorded before the path was considered.
func (s *Scanner) routeRulesForFragment(fragment sources.Fragment, alerts []routeAlert) ([]int, error) {
	order := routeRuleOrder(alerts)
	eligible := make([]int, 0, len(order))
	for _, ruleIndex := range order {
		rule := &s.rulesBySpecificity[ruleIndex]
		if rule.path == nil {
			eligible = append(eligible, ruleIndex)
			continue
		}
		matched, err := rulePathMatchesFragment(rule, fragment)
		if err != nil {
			return nil, err
		}
		if matched {
			eligible = append(eligible, ruleIndex)
		}
	}
	return eligible, nil
}

func routeRuleOrder(alerts []routeAlert) []int {
	seen := make(map[int]struct{}, len(alerts))
	order := make([]int, 0, len(alerts))
	for _, alert := range alerts {
		if _, ok := seen[alert.ruleIndex]; ok {
			continue
		}
		seen[alert.ruleIndex] = struct{}{}
		order = append(order, alert.ruleIndex)
	}
	return order
}

func keywordOutsideMatch(alerts []routeAlert, ruleIndex, start, end int) bool {
	for _, alert := range alerts {
		if alert.ruleIndex != ruleIndex {
			continue
		}
		if !spansOverlap(alert.start, alert.end, start, end) {
			return true
		}
	}
	return false
}

func spansOverlap(aStart, aEnd, bStart, bEnd int) bool {
	return aStart < bEnd && bStart < aEnd
}

func retargetFinding(src report.Finding, rule *compiledRule) report.Finding {
	dst := src
	dst.RuleID = rule.rule.ID
	dst.RuleHash = rule.hash
	dst.Description = rule.rule.Description
	dst.Confidence = rule.rule.Confidence
	dst.Tags = slices.Clone(rule.rule.Tags)
	dst.Encodings = slices.Clone(src.Encodings)
	dst.Attributes = maps.Clone(src.Attributes)
	if dst.Attributes != nil {
		delete(dst.Attributes, sources.AttrScanPairedRules)
	}
	dst.Match.Captures = nil
	dst.Match.Fingerprint = ""
	dst.ComponentSets = nil
	dst.ComponentSetsTruncated = false
	return dst
}

func findingCovers(index *findingIndex, candidate report.Finding) bool {
	if index == nil {
		return false
	}
	for i := range index.findings {
		if sameSecretOccurrence(&index.findings[i], &candidate) {
			return true
		}
	}
	return false
}

func routedCovers(staged []routedFinding, candidate report.Finding) bool {
	for i := range staged {
		if sameSecretOccurrence(&staged[i].finding, &candidate) {
			return true
		}
	}
	return false
}

func sameSecretOccurrence(a, b *report.Finding) bool {
	return a.RuleID == b.RuleID &&
		a.Match.Value == b.Match.Value &&
		locationsOverlap(a.Location, b.Location)
}

// providerRegexClaimsHit reports whether a provider keyword in this fragment
// can take the generic secret. The keyword must sit outside the generic match,
// and the secret must match the provider rule's value pattern. The keyword does
// not have to be next to the secret.
func (s *Scanner) providerRegexClaimsHit(rule *compiledRule, _ string, ruleIndex int, alerts []routeAlert, hit genericHit) (bool, error) {
	if !keywordOutsideMatch(alerts, ruleIndex, hit.start, hit.end) {
		return false, nil
	}
	return s.secretMatchesProviderRule(rule, hit.finding.Match.Value)
}

// secretMatchesProviderRule reports whether the provider regex accepts secret
// as its captured value. The probe is an assignment using the rule's own
// keyword, so a distant api_key can still match the value pattern.
func (s *Scanner) secretMatchesProviderRule(rule *compiledRule, secret string) (bool, error) {
	if rule.regex == nil || secret == "" || strings.ContainsAny(secret, "\r\n") {
		return false, nil
	}
	if err := rule.regex.Compile(); err != nil {
		return false, err
	}
	for _, keyword := range rule.rule.Keywords {
		if _, genericWord := s.genericKeywords[strings.ToLower(keyword)]; genericWord {
			continue
		}
		line := keyword + "=" + secret
		var indexes []int
		if rule.regex.NumSubexp() > 0 {
			if found := rule.regex.FindAllStringSubmatchIndex(line, 1); len(found) > 0 {
				indexes = found[0]
			}
		} else if found := rule.regex.FindAllStringIndex(line, 1); len(found) > 0 {
			indexes = found[0]
		}
		if ruleRegexValue(rule, line, indexes) == secret {
			return true, nil
		}
	}
	return false, nil
}

func ruleRegexValue(r *compiledRule, raw string, indexes []int) string {
	if len(indexes) < 2 || indexes[0] < 0 || indexes[1] < indexes[0] {
		return ""
	}
	if r.regex == nil || r.regex.NumSubexp() == 0 || len(indexes) <= 2 {
		return raw[indexes[0]:indexes[1]]
	}
	if r.rule.ValueGroup > 0 {
		group := 2 * r.rule.ValueGroup
		if group+1 < len(indexes) && indexes[group] >= 0 && indexes[group+1] > indexes[group] {
			return raw[indexes[group]:indexes[group+1]]
		}
		return ""
	}
	for group := 2; group < len(indexes); group += 2 {
		if start, end := indexes[group], indexes[group+1]; start >= 0 && end > start {
			return raw[start:end]
		}
	}
	return raw[indexes[0]:indexes[1]]
}
