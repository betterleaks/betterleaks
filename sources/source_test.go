package sources

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSourceWorkerCount(t *testing.T) {
	defaultCtx := WithSourceWorkers(t.Context(), 0)
	explicitCtx := WithSourceWorkers(t.Context(), 7)

	require.Equal(t, 100, sourceWorkerCount(t.Context(), 100))
	require.Equal(t, 100, sourceWorkerCount(defaultCtx, 100))
	require.Equal(t, 7, sourceWorkerCount(explicitCtx, 100))
	require.Zero(t, sourceWorkerOverride(defaultCtx))
	require.Equal(t, 7, sourceWorkerOverride(explicitCtx))
	require.Equal(t, defaultSourceWorkers, cap(sourceWorkersFromContext(defaultCtx).limiter.tokens))
	require.Equal(t, 7, cap(sourceWorkersFromContext(explicitCtx).limiter.tokens))
}

func TestSourceTaskGroupsShareWorkerLimit(t *testing.T) {
	const (
		workers = 2
		tasks   = 8
	)

	ctx := WithSourceWorkers(t.Context(), workers)
	groups := []*sourceTaskGroup{newSourceTaskGroup(ctx), newSourceTaskGroup(ctx)}
	started := make(chan struct{}, tasks)
	release := make(chan struct{})
	done := make(chan error, 1)
	var active, peak, processed atomic.Int64

	go func() {
		var scheduleErr error
		for i := range tasks {
			if err := groups[i%len(groups)].Go(func(ctx context.Context) error {
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
			}); err != nil {
				scheduleErr = err
				break
			}
		}
		done <- errors.Join(scheduleErr, groups[0].Wait(nil), groups[1].Wait(nil))
	}()

	for range workers {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("source workers did not start")
		}
	}
	require.EqualValues(t, workers, active.Load())
	require.EqualValues(t, workers, peak.Load())

	close(release)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("source workers did not stop")
	}
	require.EqualValues(t, tasks, processed.Load())
	require.EqualValues(t, workers, peak.Load())
}

func TestSourceTaskGroupReturnsWorkerError(t *testing.T) {
	wantErr := errors.New("worker failed")
	group := newSourceTaskGroup(t.Context())
	require.NoError(t, group.Go(func(context.Context) error {
		return wantErr
	}))
	require.ErrorIs(t, group.Wait(nil), wantErr)
}
