package scan

import (
	"context"
	"sync"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
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
			newLineIndices = newLineRegexp.FindAllStringIndex(fragment.Raw, -1)
		}
		AddLocationToFinding(finding, fragment, match, newLineIndices)
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
