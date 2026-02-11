package scan

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
	"github.com/fatih/semgroup"
)

var (
	allowSignatures = []string{"gitleaks:allow", "betterleaks:allow"}
)

// findNewlineIndices returns the byte offsets of every '\n' in s as [][]int
// (each entry is {pos, pos+1}) to match the format previously returned by
// regexp.FindAllStringIndex. This avoids the overhead of a WASM regex call
// for finding literal newline characters.
func findNewlineIndices(s string) [][]int {
	// Count newlines first to pre-allocate exactly.
	n := strings.Count(s, "\n")
	if n == 0 {
		return nil
	}
	indices := make([][]int, 0, n)
	off := 0
	for {
		i := strings.IndexByte(s[off:], '\n')
		if i < 0 {
			break
		}
		pos := off + i
		indices = append(indices, []int{pos, pos + 1})
		off = pos + 1
	}
	return indices
}

type Pipeline struct {
	// same as it ever was
	Config config.Config

	// resource enumerator, fragment producer
	Source betterleaks.Source

	// fragment consumer, match producer
	// TODO optionally set regex engine like hyperscan
	Scanner Scanner

	// Validator provides validation capabilities for finding
	// Validator TODO

	// finding consumer, final output
	// Writer TODO

	// PipelineOptions
	SourceConcurrency   int
	FragmentConcurrency int

	baseline     []betterleaks.Finding
	baselinePath string
	totalBytes   atomic.Uint64
}

// ProcessFragment filters, scans, and produces finding for a single fragment.
// This is the channel-free API for processing fragments directly.
func (p *Pipeline) ProcessFragment(ctx context.Context, fragment betterleaks.Fragment) ([]betterleaks.Finding, error) {
	if fragment.Bytes == nil {
		p.totalBytes.Add(uint64(len(fragment.Raw)))
	}
	p.totalBytes.Add(uint64(len(fragment.Bytes)))

	if !p.Config.FragmentAllowed(fragment) {
		return nil, nil
	}

	matches, err := p.Scanner.ScanFragment(ctx, fragment)
	if err != nil {
		return nil, err
	}

	var findings []betterleaks.Finding
	var newLineIndices [][]int
	for _, match := range matches {
		rule := p.Config.Rules[match.RuleID]
		finding := CreateFinding(fragment, match, rule)
		finding.DecodedLine = match.FullDecodedLine

		if containsAllowSignature(finding.Line) {
			continue
		}

		// check entropy if applicable
		if rule.Entropy != 0.0 {
			if finding.Entropy <= rule.Entropy {
				continue
			}
		}

		if !p.Config.FindingAllowed(*finding, rule) {
			continue
		}
		if newLineIndices == nil {
			newLineIndices = findNewlineIndices(fragment.Raw)
		}
		AddLocationToFinding(finding, fragment, match, newLineIndices)

		// Composite rules: defer fingerprinting to processRequiredRules
		// so the fingerprint includes required findings.
		if len(rule.RequiredRules) > 0 {
			findings = append(findings, *finding)
			continue
		}

		betterleaks.AddFingerprintToFinding(finding)

		// Check if finding is in ignore list
		if p.Scanner.IsIgnored(finding) {
			continue
		}

		findings = append(findings, *finding)
	}

	// After collecting all primary findings, evaluate required rules for any
	// composite rules. This is done as a second pass so we can batch-scan
	// required rules per rule ID (avoiding redundant decode loops).
	findings, err = p.processRequiredRules(ctx, fragment, findings)
	if err != nil {
		return nil, err
	}

	return findings, nil
}

// FindingsFunc is the type of function called by Run to yield findings.
// Returning a non-nil error stops iteration.
type FindingsFunc func(finding betterleaks.Finding, err error) error

// Run processes all fragments from the source concurrently and yields findings
// to the provided callback. The callback is serialized with a mutex so callers
// do not need to synchronize access. Returning an error from the callback
// stops the scan.
func (p *Pipeline) Run(ctx context.Context, yield FindingsFunc) error {
	var mu sync.Mutex
	sg := semgroup.NewGroup(ctx, 16)
	err := p.Source.Fragments(ctx, func(fragment betterleaks.Fragment, err error) error {
		if err != nil {
			return err
		}

		sg.Go(func() error {
			findings, err := p.ProcessFragment(ctx, fragment)
			if err != nil {
				return err
			}

			// filtering at fragment level for deduplication and
			// demoting generic rules in favor of more specific rules.
			findings = filter(findings, 0)

			mu.Lock()
			defer mu.Unlock()
			for _, finding := range findings {
				if err := yield(finding, nil); err != nil {
					return err
				}
			}
			return nil
		})
		return nil
	})
	if err != nil {
		return err
	}

	return sg.Wait()
}

// TotalBytes returns the total number of content bytes processed by the pipeline.
func (p *Pipeline) TotalBytes() uint64 {
	return p.totalBytes.Load()
}

// TODO probably don't need a `New` function here, just define a struct.
func NewPipeline(cfg config.Config, src betterleaks.Source, scanner Scanner) *Pipeline {
	return &Pipeline{
		Config:  cfg,
		Source:  src,
		Scanner: scanner,
	}
}

// containsAllowSignature checks if the line contains any of the allow signatures.
func containsAllowSignature(line string) bool {
	for _, sig := range allowSignatures {
		if strings.Contains(line, sig) {
			return true
		}
	}
	return false
}

// processRequiredRules evaluates composite rules. For each primary finding
// whose rule has RequiredRules, it lazily scans the fragment for the required
// (skipReport) rules, checks proximity, and either enriches the finding with
// RequiredFindings or drops it if unsatisfied.
func (p *Pipeline) processRequiredRules(ctx context.Context, fragment betterleaks.Fragment, primaryFindings []betterleaks.Finding) ([]betterleaks.Finding, error) {
	// Fast path: if no primary finding has required rules, return as-is.
	hasComposite := false
	for i := range primaryFindings {
		rule := p.Config.Rules[primaryFindings[i].RuleID]
		if len(rule.RequiredRules) > 0 {
			hasComposite = true
			break
		}
	}
	if !hasComposite {
		return primaryFindings, nil
	}

	// Cache required-rule scan results so we only run the decode loop once
	// per required rule ID per fragment.
	requiredMatchCache := make(map[string][]betterleaks.Match)

	// Pre-compute newline indices for location calculations.
	newLineIndices := findNewlineIndices(fragment.Raw)

	var results []betterleaks.Finding
	for i := range primaryFindings {
		primary := primaryFindings[i]
		rule := p.Config.Rules[primary.RuleID]

		// Non-composite rule: pass through unchanged.
		if len(rule.RequiredRules) == 0 {
			results = append(results, primary)
			continue
		}

		// Lazily scan each required rule (with full decode support).
		for _, req := range rule.RequiredRules {
			if _, cached := requiredMatchCache[req.RuleID]; !cached {
				reqRule, ok := p.Config.Rules[req.RuleID]
				if !ok {
					continue
				}
				reqMatches, err := p.Scanner.ScanFragmentWithRules(ctx, fragment, []config.Rule{reqRule})
				if err != nil {
					return nil, err
				}
				requiredMatchCache[req.RuleID] = reqMatches
			}
		}

		// Build required findings from cached matches, checking proximity.
		var requiredFindings []*betterleaks.Finding
		for _, req := range rule.RequiredRules {
			reqRule, ok := p.Config.Rules[req.RuleID]
			if !ok {
				continue
			}
			for _, m := range requiredMatchCache[req.RuleID] {
				rf := CreateFinding(fragment, m, reqRule)
				AddLocationToFinding(rf, fragment, m, newLineIndices)

				if !withinProximity(primary, *rf, req) {
					continue
				}

				requiredFindings = append(requiredFindings, rf)
			}
		}

		// Only emit the primary finding if every required rule is satisfied.
		if hasAllRequiredRules(requiredFindings, rule.RequiredRules) {
			primary.AddRequiredFindings(requiredFindings)

			// Compute the composite fingerprint now that required findings
			// are attached, then check the ignore list.
			betterleaks.AddFingerprintToFinding(&primary)
			if p.Scanner.IsIgnored(&primary) {
				continue
			}

			results = append(results, primary)
		}
	}

	return results, nil
}

// hasAllRequiredRules checks that we have at least one required finding
// for each required rule.
func hasAllRequiredRules(requiredFindings []*betterleaks.Finding, requiredRules []*config.Required) bool {
	foundRules := make(map[string]bool, len(requiredFindings))
	for _, rf := range requiredFindings {
		foundRules[rf.RuleID] = true
	}
	for _, required := range requiredRules {
		if !foundRules[required.RuleID] {
			return false
		}
	}
	return true
}
