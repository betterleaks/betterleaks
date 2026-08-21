package detect

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/betterleaks/betterleaks/sources"
	"github.com/stretchr/testify/require"
)

type trackingSource struct {
	inner     sources.Source
	fragments []*sources.Fragment
}

type sourceFunc func(context.Context, sources.FragmentsFunc) error

func (f sourceFunc) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	return f(ctx, yield)
}

func (s *trackingSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	return s.inner.Fragments(ctx, func(fragment *sources.Fragment, err error) error {
		if fragment != nil {
			s.fragments = append(s.fragments, fragment)
		}
		return yield(fragment, err)
	})
}

func TestRunTransfersAndReleasesFragmentLeases(t *testing.T) {
	source := &trackingSource{inner: &sources.File{
		Content: strings.NewReader("leased content"),
		Path:    "lease.txt",
	}}

	var consumed atomic.Int64
	err := Run(t.Context(), source, Options{DetectWorkers: 2}, nil,
		func(_ context.Context, fragment *sources.Fragment) error {
			require.Equal(t, "leased content", string(fragment.Raw))
			consumed.Add(1)
			return nil
		})
	require.NoError(t, err)
	require.EqualValues(t, 1, consumed.Load())
	require.Len(t, source.fragments, 1)
	require.Nil(t, source.fragments[0].Raw)
	require.Nil(t, source.fragments[0].Attributes)
}

func TestRunReleasesQueuedFragmentsAfterWorkerError(t *testing.T) {
	content := strings.Repeat("x", 350_000)
	source := &trackingSource{inner: &sources.File{
		Content: strings.NewReader(content),
		Path:    "large.txt",
	}}
	wantErr := errors.New("stop detection")

	err := Run(t.Context(), source, Options{DetectWorkers: 1, QueueSize: 4}, nil,
		func(_ context.Context, _ *sources.Fragment) error { return wantErr })
	require.ErrorIs(t, err, wantErr)
	require.NotEmpty(t, source.fragments)
	for _, fragment := range source.fragments {
		require.Nil(t, fragment.Raw)
		require.Nil(t, fragment.Attributes)
	}
}

func TestRunWorkersCreatesOneConsumerPerWorker(t *testing.T) {
	source := &sources.File{
		Content: strings.NewReader("content"),
		Path:    "one.txt",
	}
	var factories atomic.Int64

	err := RunWorkers(t.Context(), source, Options{DetectWorkers: 3}, nil, func() ConsumeFunc {
		factories.Add(1)
		return func(context.Context, *sources.Fragment) error { return nil }
	})
	require.NoError(t, err)
	require.EqualValues(t, 3, factories.Load())
}

func TestRunReturnsExternalCancellationAfterSourceCompletes(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	source := sourceFunc(func(_ context.Context, yield sources.FragmentsFunc) error {
		if err := yield(&sources.Fragment{Raw: []byte("content")}, nil); err != nil {
			return err
		}
		cancel()
		return nil
	})

	err := Run(ctx, source, Options{DetectWorkers: 1}, nil,
		func(ctx context.Context, _ *sources.Fragment) error {
			<-ctx.Done()
			return nil
		})
	require.ErrorIs(t, err, context.Canceled)
}
