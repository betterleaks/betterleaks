// Package pipeline composes local discovery and provider analysis with bounded
// queues and independent worker pools. Scanner and Analyzer remain usable alone.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/betterleaks/betterleaks/v2/analyze"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// Pipeline holds reusable engines and output policy. Executions own their
// cancellation and accounting state and may run concurrently with fresh sources.
type Pipeline struct {
	scanner        *scan.Scanner
	analyzer       *analyze.Analyzer
	validationOnly bool
	statuses       []report.ValidationStatus
}

type Option struct{ apply func(*Pipeline) error }

// WithValidationOnly skips permission analysis while still checking liveness.
func WithValidationOnly() Option {
	return Option{apply: func(p *Pipeline) error { p.validationOnly = true; return nil }}
}

// WithValidationStatuses restricts emitted findings after counting all outcomes.
// Empty includes every status. Analyzer results are never suppressed internally.
func WithValidationStatuses(statuses ...report.ValidationStatus) Option {
	statuses = slices.Clone(statuses)
	return Option{apply: func(p *Pipeline) error {
		for _, status := range statuses {
			switch status {
			case report.ValidationStatusNone, report.ValidationStatusValid,
				report.ValidationStatusNeedsValidation, report.ValidationStatusInvalid,
				report.ValidationStatusRevoked, report.ValidationStatusUnknown, report.ValidationStatusError:
			default:
				return fmt.Errorf("invalid validation status %q", status)
			}
		}
		p.statuses = statuses
		return nil
	}}
}

// New composes a scanner and optional analyzer. A nil analyzer performs local
// discovery only. Construction starts no workers and performs no provider work.
// Scanner and Analyzer must use compatible resolved configurations: every emitted
// rule and its credential requirements must be understood by Analyzer. Using the
// same configuration for both is sufficient. Incompatibilities return errors when
// findings reach Analyzer.
func New(scanner *scan.Scanner, analyzer *analyze.Analyzer, options ...Option) (*Pipeline, error) {
	if scanner == nil {
		return nil, errors.New("scanner is required")
	}
	p := &Pipeline{scanner: scanner, analyzer: analyzer}
	for _, option := range options {
		if option.apply == nil {
			return nil, errors.New("pipeline option is invalid")
		}
		if err := option.apply(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// ScanSummary describes completed discovery and provider work.
type ScanSummary struct {
	BytesInspected uint64
	// DetectedFindings counts discoveries after local scan filtering.
	DetectedFindings int
	// EmittedFindings counts findings delivered after status filtering.
	// A finding delivered to a failing handler is included.
	EmittedFindings int
	// ValidationCounts counts every resolved status before output filtering.
	ValidationCounts map[report.ValidationStatus]int
}

// ValidationEnabled reports whether this pipeline can validate credentials.
func (p *Pipeline) ValidationEnabled() bool { return p != nil && p.analyzer.HasValidation() }

// AnalysisEnabled reports whether this pipeline can resolve permissions.
func (p *Pipeline) AnalysisEnabled() bool {
	return p != nil && !p.validationOnly && p.analyzer.HasAnalysis()
}

// Scan consumes source and invokes handler serially as findings finish. Detection
// and provider workers run independently with bounded backpressure. Handler
// failure cancels all work; Scan waits for every worker before returning. A nil
// handler discards findings. Source and handler errors remain discoverable with
// errors.Is. Sources may perform I/O independently of provider analysis.
func (p *Pipeline) Scan(ctx context.Context, source sources.Source, handler func(report.Finding) error) (ScanSummary, error) {
	var summary ScanSummary
	if p == nil || p.scanner == nil {
		return summary, errors.New("pipeline must be constructed with New")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	summary.ValidationCounts = make(map[report.ValidationStatus]int)
	emit := func(f report.Finding) error {
		summary.ValidationCounts[f.Analysis.Status]++
		if len(p.statuses) != 0 && !slices.Contains(p.statuses, f.Analysis.Status) {
			return nil
		}
		summary.EmittedFindings++
		if handler != nil {
			return handler(f)
		}
		return nil
	}
	var scanned scan.ScanSummary
	var err error
	if p.analyzer == nil || !p.analyzer.HasValidation() {
		// Preserve the direct scan path: no provider runtime, queue, or workers.
		scanned, err = p.scanner.Scan(ctx, source, emit)
	} else {
		produce := func(ctx context.Context, yield func(report.Finding) error) error {
			var scanErr error
			scanned, scanErr = p.scanner.Scan(ctx, source, yield)
			return scanErr
		}
		if p.validationOnly {
			err = p.analyzer.ValidateStream(ctx, produce, emit)
		} else {
			err = p.analyzer.AnalyzeStream(ctx, produce, emit)
		}
	}
	summary.BytesInspected = scanned.BytesInspected
	summary.DetectedFindings = scanned.Findings
	return summary, err
}
