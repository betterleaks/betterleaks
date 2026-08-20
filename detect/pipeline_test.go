package detect

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/sources"
)

type pipelineTestSource struct {
	fragments []sources.Fragment
}

func (s pipelineTestSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	for _, fragment := range s.fragments {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := yield(fragment, nil); err != nil {
			return err
		}
	}
	return nil
}

func TestRunDetectionWorkersHonorsLimit(t *testing.T) {
	const (
		workers   = 2
		fragments = 8
	)

	source := pipelineTestSource{fragments: make([]sources.Fragment, fragments)}
	for i := range source.fragments {
		source.fragments[i].Raw = "content"
	}

	detector := new(Detector)
	detector.DetectWorkers = workers
	started := make(chan struct{}, fragments)
	release := make(chan struct{})
	done := make(chan error, 1)
	var active, peak, processed atomic.Int64

	go func() {
		done <- detector.runDetectionWorkers(
			t.Context(),
			source,
			nil,
			func(ctx context.Context, _ fragmentJob) error {
				current := active.Add(1)
				defer active.Add(-1)
				for {
					previous := peak.Load()
					if current <= previous || peak.CompareAndSwap(previous, current) {
						break
					}
				}
				started <- struct{}{}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-release:
					processed.Add(1)
					return nil
				}
			},
		)
	}()

	for range workers {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("detection workers did not start")
		}
	}
	require.EqualValues(t, workers, active.Load())
	require.EqualValues(t, workers, peak.Load())

	close(release)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("detection workers did not stop")
	}
	require.EqualValues(t, fragments, processed.Load())
	require.EqualValues(t, workers, peak.Load())
}

func TestNewFragmentJobDetachesSourceBuffer(t *testing.T) {
	buffer := []byte("secret")
	attributes := map[string]string{sources.AttrPath: "original"}
	fragment := new(sources.Fragment)
	fragment.Raw = string(buffer)
	fragment.Bytes = buffer
	fragment.Attributes = attributes
	job := newFragmentJob(*fragment)

	buffer[0] = 'X'
	attributes[sources.AttrPath] = "changed"
	require.Equal(t, "secret", job.fragment.Raw)
	require.Nil(t, job.fragment.Bytes)
	require.Equal(t, "original", job.fragment.Attr(sources.AttrPath))
	require.Equal(t, len(buffer), job.byteCount)
}

func TestRunProcessesQueuedFragments(t *testing.T) {
	content := "-----BEGIN OPENSSH PRIVATE KEY-----"
	fragment := new(sources.Fragment)
	fragment.Raw = content
	fragment.Bytes = []byte(content)
	source := pipelineTestSource{fragments: []sources.Fragment{*fragment}}
	detector := NewDetector(loadTestConfig(t, "simple"))
	detector.DetectWorkers = 2

	var results []Result
	for result := range detector.Run(t.Context(), source) {
		results = append(results, result)
	}

	require.Len(t, results, 1)
	require.NoError(t, results[0].Err)
	require.Equal(t, "apkey", results[0].Finding.RuleID)
	require.EqualValues(t, len(content), detector.TotalBytes.Load())
}
