package detect

import (
	"context"
	"errors"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

// DetectSource scans the given source and returns a list of findings
// Deprecated: use Run instead for more flexible and efficient processing of findings.
func (d *Detector) DetectSource(ctx context.Context, source sources.Source) ([]report.Finding, error) {
	var (
		findings []report.Finding
		scanErrs []error
	)
	for result := range d.Run(ctx, source) {
		if result.Err != nil {
			scanErrs = append(scanErrs, result.Err)
			continue
		}
		findings = append(findings, result.Finding)
	}
	if err := ctx.Err(); err != nil {
		scanErrs = append(scanErrs, err)
	}
	return findings, errors.Join(scanErrs...)
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
		if _, ok := d.ValidationStatusFilter[string(f.ValidationStatus)]; ok {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// NewDetector creates a new detector with the given config
//
// Deprecated: use NewDetectorContext instead.
func NewDetector(cfg *config.Config) *Detector {
	return NewDetectorContext(context.Background(), cfg, ValidationOptions{})
}
