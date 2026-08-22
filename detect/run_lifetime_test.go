package detect

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/config"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/stretchr/testify/require"
)

type runTrackingSource struct {
	inner     sources.Source
	fragments []*sources.Fragment
}

type runSourceFunc func(context.Context, sources.FragmentsFunc) error

func (f runSourceFunc) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	return f(ctx, yield)
}

func (s *runTrackingSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	return s.inner.Fragments(ctx, func(fragment *sources.Fragment, err error) error {
		if fragment != nil {
			s.fragments = append(s.fragments, fragment)
		}
		return yield(fragment, err)
	})
}

func TestRunEarlyStopWaitsForFragmentRelease(t *testing.T) {
	detector, _ := allocationDetector(t)
	detector.DetectWorkers = 1
	source := &runTrackingSource{inner: &sources.File{
		Content: strings.NewReader(
			"candidate_ABCDEFGHIJKLMNOPQRST\n" + strings.Repeat("ordinary content\n", 20_000),
		),
		Path: "large.txt",
	}}

	var found report.Finding
	for result := range detector.Run(t.Context(), source) {
		require.NoError(t, result.Err)
		found = result.Finding
		break
	}

	require.Equal(t, "candidate_ABCDEFGHIJKLMNOPQRST", found.Secret)
	// Findings must own both their text and metadata before Run releases the
	// pooled source fragment during the iterator's cancellation drain.
	require.Equal(t, "large.txt", found.Attr(sources.AttrPath))
	require.NotEmpty(t, source.fragments)
	for _, fragment := range source.fragments {
		require.Nil(t, fragment.Raw)
		require.Nil(t, fragment.Attributes)
	}
}

func TestRunReleasesFragmentLeasesOnCompletion(t *testing.T) {
	detector, _ := allocationDetector(t)
	source := &runTrackingSource{inner: &sources.File{
		Content: strings.NewReader("ordinary content"),
		Path:    "lease.txt",
	}}

	for result := range detector.Run(t.Context(), source) {
		require.NoError(t, result.Err)
	}

	require.Len(t, source.fragments, 1)
	require.Nil(t, source.fragments[0].Raw)
	require.Nil(t, source.fragments[0].Attributes)
}

func TestRunSourceDrainsFragmentLeasesAfterWorkerError(t *testing.T) {
	detector, _ := allocationDetector(t)
	detector.DetectWorkers = 1
	source := &runTrackingSource{inner: &sources.File{
		Content: strings.NewReader(
			"candidate_ABCDEFGHIJKLMNOPQRST\n" + strings.Repeat("ordinary content\n", 20_000),
		),
		Path: "large.txt",
	}}
	wantErr := errors.New("stop detection")

	err := detector.runSource(t.Context(), source, nil, func(Result) error {
		return wantErr
	})

	require.ErrorIs(t, err, wantErr)
	require.NotEmpty(t, source.fragments)
	for _, fragment := range source.fragments {
		require.Nil(t, fragment.Raw)
		require.Nil(t, fragment.Attributes)
	}
}

func TestRunSourceReturnsExternalCancellation(t *testing.T) {
	detector, _ := allocationDetector(t)
	ctx, cancel := context.WithCancel(t.Context())
	source := runSourceFunc(func(_ context.Context, yield sources.FragmentsFunc) error {
		if err := yield(&sources.Fragment{Raw: []byte("ordinary content")}, nil); err != nil {
			return err
		}
		cancel()
		return nil
	})

	err := detector.runSource(ctx, source, nil, func(Result) error { return nil })
	require.ErrorIs(t, err, context.Canceled)
}

func TestValidationDetectorCanRunMoreThanOnce(t *testing.T) {
	rule := config.Rule{
		RuleID:       "validation-test",
		Keywords:     []string{"candidate_"},
		Regex:        blregexp.MustCompile(`candidate_[A-Z]{20}`),
		ValidateExpr: `{"result": "valid"}`,
	}
	cfg := &config.Config{
		Rules:          map[string]config.Rule{rule.RuleID: rule},
		Keywords:       map[string]struct{}{"candidate_": {}},
		KeywordToRules: map[string][]string{"candidate_": {rule.RuleID}},
		OrderedRules:   []string{rule.RuleID},
	}
	detector, err := NewDetector(cfg, ValidationOptions{Enabled: true, Workers: 1})
	require.NoError(t, err)
	require.True(t, detector.ValidationEnabled())

	for range 2 {
		findings, err := collectTestRun(t.Context(), detector, &sources.File{
			Content: strings.NewReader("candidate_ABCDEFGHIJKLMNOPQRST"),
			Path:    "validation.txt",
		})
		require.NoError(t, err)
		require.Len(t, findings, 1)
		require.Equal(t, report.ValidationStatusValid, findings[0].ValidationStatus)
	}
}
