package detect

import (
	"context"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/stretchr/testify/require"
)

type runTrackingSource struct {
	inner     sources.Source
	fragments []*sources.Fragment
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
	detector, _ := allocationDetector()
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
