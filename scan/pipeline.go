package scan

import (
	"context"
	"sync"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/regexp"
	"github.com/fatih/semgroup"
)

var newLineRegexp = regexp.MustCompile("\n")

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
}

// ProcessFragment filters, scans, and produces finding for a single fragment.
// This is the channel-free API for processing fragments directly.
func (p *Pipeline) ProcessFragment(ctx context.Context, fragment betterleaks.Fragment) ([]betterleaks.Finding, error) {
	if !FragmentAllowed(&p.Config, fragment) {
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
		finding := betterleaks.CreateFinding(fragment, match, rule)
		if !FindingAllowed(&p.Config, *finding, match.FullDecodedLine, rule) {
			continue
		}
		if newLineIndices == nil {
			newLineIndices = newLineRegexp.FindAllStringIndex(fragment.Raw, -1)
		}
		betterleaks.AddLocationToFinding(finding, fragment, match, newLineIndices)
		findings = append(findings, *finding)
	}

	return findings, nil
}

// Run processes all fragments from the source concurrently and returns all finding.
func (p *Pipeline) Run(ctx context.Context) ([]betterleaks.Finding, error) {
	var (
		mu          sync.Mutex
		retFindings []betterleaks.Finding
	)

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

			// TODO filtering needs to be done at the fragment level for deduplication and
			// demoting generic rules in favor of more specific rules. We may want to change this.
			findings = filter(findings, 0)

			// TODO we should be yielding findings instead of appending to a slice. This avoids
			// unbounded growth of the findings slice.
			if len(findings) > 0 {
				mu.Lock()
				retFindings = append(retFindings, findings...)
				mu.Unlock()
			}

			// TODO printing should be done by the caller of `Run`
			for _, finding := range findings {
				printFinding(finding, false)
			}
			return nil
		})
		return nil
	})
	if err != nil {
		return retFindings, err
	}

	if err := sg.Wait(); err != nil {
		return retFindings, err
	}

	return retFindings, nil
}

// TODO probably don't need a `New` function here, just define a struct.
func NewPipeline(cfg config.Config, src betterleaks.Source, scanner Scanner) *Pipeline {
	return &Pipeline{
		Config:  cfg,
		Source:  src,
		Scanner: scanner,
	}
}

// TODO FragmentAllowed and FindingAllowed should probably be moved to config
func FragmentAllowed(cfg *config.Config, fragment betterleaks.Fragment) bool {
	if fragment.Path != "" {
		if fragment.Path == cfg.Path {
			logging.Trace().Msg("skipping file: matches config or baseline path")
			return false
		}
	}

	source, metadata := resourceContext(fragment.Resource)
	for _, a := range cfg.Allowlists {
		if a.FragmentAllowed(source, metadata) {
			return false
		}
	}
	return true
}

// FindingAllowed returns true if the finding should be reported.
// It checks entropy, global allowlists, and rule-level allowlists.
func FindingAllowed(cfg *config.Config, finding betterleaks.Finding, decodedLine string, rule config.Rule) bool {
	if rule.Entropy != 0.0 {
		if finding.Entropy <= rule.Entropy {
			return false
		}
	}

	source, metadata := resourceContext(finding.Fragment.Resource)
	for _, a := range cfg.Allowlists {
		regexTarget := resolveRegexTarget(a.RegexTarget, finding, decodedLine)
		if a.FindingAllowed(regexTarget, finding.Secret, source, metadata) {
			return false
		}
	}
	for _, a := range rule.Allowlists {
		regexTarget := resolveRegexTarget(a.RegexTarget, finding, decodedLine)
		if a.FindingAllowed(regexTarget, finding.Secret, source, metadata) {
			return false
		}
	}

	return true
}

// resolveRegexTarget picks the string to test regexes against based on the allowlist's RegexTarget.
func resolveRegexTarget(target string, finding betterleaks.Finding, line string) string {
	switch target {
	case "match":
		return finding.Match
	case "line":
		return line
	default:
		return finding.Secret
	}
}

func resourceContext(r *betterleaks.Resource) (string, map[string]string) {
	if r == nil {
		return "", nil
	}
	return r.Source, r.Metadata
}
