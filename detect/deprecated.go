package detect

import (
	"context"
	"fmt"
	"sync"
	"time"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/fatih/semgroup"
	"github.com/pkoukk/tiktoken-go"
	"github.com/rs/zerolog"
	"golang.org/x/exp/maps"
)

// DetectSource scans the given source and returns a list of findings
// Deprecated: use Run instead for more flexible and efficient processing of findings.
func (d *Detector) DetectSource(ctx context.Context, source sources.Source) ([]report.Finding, error) {
	// Initialize deprecated fields used only by this code path.
	if d.commitMap == nil {
		d.commitMap = make(map[string]bool)
		d.commitMutex = &sync.Mutex{}
	}

	// We have a single channel for sending findings to.
	// Findings get sent to this channel straight from
	// scanFragmentWithRule (non validation) OR from the ValidationPool which
	// is responsible for attempting async validation attempts.
	d.findingsCh = make(chan report.Finding, 1000)

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
	return d.detectFragment(ctx, fragment)
}

// AddFinding adds a finding to the pipeline. Findings needing CEL validation
// are submitted to the pool; all others go directly to findingsCh.
// Deprecated: only used in deprecated calls. New code calls routeFinding directly.
func (d *Detector) AddFinding(finding report.Finding) {
	finding.SyncDeprecatedSourceFields()

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
			d.ValidationPool.Submit(finding, rule.CelProgram())
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

// Findings returns the findings added to the detector, applying redaction if configured.
// Deprecated: this is only used in deprecated calls. New code should access findings directly from the channel or ValidationPool.
func (d *Detector) Findings() []report.Finding {
	if d.Redact > 0 {
		for i := range d.findings {
			d.findings[i].Redact(d.Redact)
		}
	}
	return d.findings
}

// Deprecated: this is only used in deprecated calls. New code should access findings directly from the channel or ValidationPool.
func (d *Detector) shouldVerbosePrint(f report.Finding) bool {
	if !d.Verbose {
		return false
	}
	if len(d.ValidationStatusFilter) == 0 {
		return true
	}
	if f.ValidationStatus == "" {
		_, ok := d.ValidationStatusFilter["none"]
		return ok
	}
	_, ok := d.ValidationStatusFilter[f.ValidationStatus]
	return ok
}

// FilterByStatus returns findings whose ValidationStatus is in
// d.ValidationStatusFilter. If the filter is empty, all findings are returned.
// The pseudo-status "none" matches findings with no ValidationStatus set.
func (d *Detector) FilterByStatus(findings []report.Finding) []report.Finding {
	if len(d.ValidationStatusFilter) == 0 {
		return findings
	}
	_, includeNone := d.ValidationStatusFilter["none"]
	var filtered []report.Finding
	for _, f := range findings {
		if f.ValidationStatus == "" {
			if includeNone {
				filtered = append(filtered, f)
			}
			continue
		}
		if _, ok := d.ValidationStatusFilter[f.ValidationStatus]; ok {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// NewDetectorContext is the same as NewDetector but supports passing in a
// context to use for timeouts
func NewDetectorContext(ctx context.Context, cfg config.Config) *Detector {
	// grab offline tiktoken encoder
	tiktoken.SetBpeLoader(&TiktokenLoader{})
	tke, err := tiktoken.GetEncoding("cl100k_base")
	if err != nil {
		logging.Warn().Err(err).Msgf("Could not pull down cl100k_base tiktokenizer")
	}

	return &Detector{
		gitleaksIgnore:   make(map[string]struct{}),
		findings:         make([]report.Finding, 0),
		ValidationCounts: make(map[string]int),
		Config:           cfg,
		prefilter:        *ahocorasick.NewTrieBuilder().AddStrings(maps.Keys(cfg.Keywords)).Build(),
		Sema:             semgroup.NewGroup(ctx, 40),
		tokenizer:        tke,
	}
}
