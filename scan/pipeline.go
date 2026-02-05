package scan

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
	"github.com/fatih/semgroup"
)

var (
	newLineRegexp   = regexp.MustCompile("\n")
	allowSignatures = []string{"gitleaks:allow", "betterleaks:allow"}
)

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
			// logger.Trace().
			// 	Str("finding", finding.Secret).
			// 	Msg("skipping finding: allow signature")
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
			newLineIndices = newLineRegexp.FindAllStringIndex(fragment.Raw, -1)
		}
		AddLocationToFinding(finding, fragment, match, newLineIndices)
		AddFingerprintToFinding(finding)

		// Check if finding is in ignore list
		if p.Scanner.IsIgnored(*finding) {
			continue
		}

		findings = append(findings, *finding)
	}

	return findings, nil
}

// FindingsFunc is the type of function called by Run to yield findings.
// Returning a non-nil error stops iteration.
type FindingsFunc func(finding betterleaks.Finding, err error) error

// Run processes all fragments from the source concurrently and yields findings
// to the provided callback. The callback may be invoked concurrently from
// multiple goroutines. Returning an error from the callback stops the scan.
func (p *Pipeline) Run(ctx context.Context, yield FindingsFunc) error {
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
