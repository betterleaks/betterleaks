package detect

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func newTestDetector(t testing.TB, cfg *config.Config) *Detector {
	t.Helper()
	detector, err := NewDetector(context.Background(), cfg, ValidationOptions{})
	require.NoError(t, err)
	return detector
}

func collectTestRun(ctx context.Context, detector *Detector, source sources.Source) ([]report.Finding, error) {
	var findings []report.Finding
	var scanErrs []error
	for result := range detector.Run(ctx, source) {
		if result.Err != nil {
			scanErrs = append(scanErrs, result.Err)
			continue
		}
		findings = append(findings, result.Finding)
	}
	return findings, errors.Join(scanErrs...)
}
