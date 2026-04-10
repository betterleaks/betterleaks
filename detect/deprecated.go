package detect

import (
	"context"
	"fmt"
	"time"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/rs/zerolog"
)

// NewDetector creates a new detector with the given config
//
// Deprecated: use NewDetectorContext instead.
func NewDetector(cfg config.Config) *Detector {
	return NewDetectorContext(context.Background(), cfg)
}

// DetectSource scans the given source and returns a list of findings
// Deprecated: use Run instead for more flexible and efficient processing of findings.
func (d *Detector) DetectSource(ctx context.Context, source sources.Source) ([]report.Finding, error) {
	// We have a single channel for sending findings to.
	// Findings get sent to this channel straight from
	// scanFragmentWithRule (non validation) OR from the ValidationPool which
	// is responsible for attempting async validation attempts.
	d.findingsCh = make(chan report.Finding, 1000)

	// little hacky. this will all be cleared up in v2
	// little hacky. this will all be cleared up in v2
	if d.ValidationPool != nil {
		d.ValidationPool.Emit = func(f report.Finding) {
			d.findingsCh <- f
		}
	}

	// non-validation rule findings get printed in d.AddFinding().
	// But we have to do it here.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range d.findingsCh {
			if !d.ValidationExtractEmpty {
				f.ValidationMeta = stripEmptyMeta(f.ValidationMeta)
			}
			d.findings = append(d.findings, f)
			if f.ValidationStatus != "" {
				d.ValidationCounts[f.ValidationStatus]++
			}
			if d.shouldVerbosePrint(f) {
				printFinding(f, d.NoColor, d.Redact)
			}
		}
	}()

	err := source.Fragments(ctx, func(fragment sources.Fragment, err error) error {
		logger := fragment.Logger()

		commitSHA := fragment.Attr(sources.AttrGitSHA)
		if commitSHA != "" {
			d.addCommit(commitSHA)
		}

		if err != nil {
			// Log the error and move on to the next fragment
			logger.Error().Err(err).Send()
			return nil
		}

		// both the fragment's content and path should be empty for it to be
		// considered empty at this point because of path based matches
		if len(fragment.Raw) == 0 && fragment.Attr(sources.AttrPath) == "" {
			logger.Trace().Msg("skipping empty fragment")
			return nil
		}

		var timer *time.Timer
		// Only start the timer in debug mode
		if logger.GetLevel() <= zerolog.DebugLevel {
			timer = time.AfterFunc(SlowWarningThreshold, func() {
				logger.Debug().Msgf("Taking longer than %s to inspect fragment", SlowWarningThreshold.String())
			})
		}

		for _, finding := range d.DetectContext(ctx, fragment) {
			d.AddFinding(finding)
		}

		// Stop the timer if it was created
		if timer != nil {
			timer.Stop()
		}

		return nil
	})

	if _, isGit := source.(*sources.Git); isGit {
		logging.Info().Msgf("%d commits scanned.", len(d.commitMap))
		logging.Debug().Msg("Note: this number might be smaller than expected due to commits with no additions")
	}

	if d.ValidationPool != nil {
		d.ValidationPool.Close()

		hits, misses := d.ValidationPool.Stats()
		logging.Debug().
			Uint64("http_requests", misses).
			Uint64("cache_hits", hits).
			Msg("validation cache stats")
	}

	close(d.findingsCh)
	<-done

	return d.Findings(), err
}

// Detect scans the given fragment and returns a list of findings
//
// Deprecated: use DetectContext instead.
func (d *Detector) Detect(fragment sources.Fragment) []report.Finding {
	return d.DetectContext(context.Background(), fragment)
}

// DetectContext is the same as Detect but supports passing in a
// context to use for timeouts
//
// Deprecated: use Run or DetectString
func (d *Detector) DetectContext(ctx context.Context, fragment sources.Fragment) []report.Finding {
	return d.scanFragment(ctx, fragment)
}

// AddFinding adds a finding to the pipeline. Findings needing CEL validation
// are submitted to the pool; all others go directly to findingsCh.
// Deprecated: only used in deprecated calls. New code calls routeFinding directly.
func (d *Detector) AddFinding(finding report.Finding) {
	globalFingerprint := fmt.Sprintf("%s:%s:%d", finding.File, finding.RuleID, finding.StartLine)
	if finding.Commit != "" {
		finding.Fingerprint = fmt.Sprintf("%s:%s:%s:%d", finding.Commit, finding.File, finding.RuleID, finding.StartLine)
	} else {
		finding.Fingerprint = globalFingerprint
	}

	// check if we should ignore this finding
	logger := logging.With().Str("finding", finding.Secret).Logger()
	if _, ok := d.gitleaksIgnore[globalFingerprint]; ok {
		logger.Debug().
			Str("fingerprint", globalFingerprint).
			Msg("skipping finding: global fingerprint")
		return
	} else if finding.Commit != "" {
		// Awkward nested if because I'm not sure how to chain these two conditions.
		if _, ok := d.gitleaksIgnore[finding.Fingerprint]; ok {
			logger.Debug().
				Str("fingerprint", finding.Fingerprint).
				Msgf("skipping finding: fingerprint")
			return
		}
	}

	if d.baseline != nil && !IsNew(finding, d.Redact, d.baseline) {
		logger.Debug().
			Str("fingerprint", finding.Fingerprint).
			Msgf("skipping finding: baseline")
		return
	}

	if d.ValidationPool != nil {
		if rule, ok := d.Config.Rules[finding.RuleID]; ok && rule.CelProgram() != nil {
			d.submitValidation(finding, rule)
			return
		}
	}

	d.findingsCh <- finding
}

// AddCommit synchronously adds a commit to the commit slice
func (d *Detector) addCommit(commit string) {
	d.commitMutex.Lock()
	d.commitMap[commit] = true
	d.commitMutex.Unlock()
}
