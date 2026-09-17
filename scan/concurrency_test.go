package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
)

// detectionGate blocks inside detection, after matching a rule. This lets tests
// observe active workers without depending on input size or execution speed.
type detectionGate struct {
	resume <-chan struct{}
	active atomic.Int32
	peak   atomic.Int32
	calls  atomic.Int32
}

func (g *detectionGate) Enabled(context.Context, slog.Level) bool { return true }
func (g *detectionGate) WithAttrs([]slog.Attr) slog.Handler       { return g }
func (g *detectionGate) WithGroup(string) slog.Handler            { return g }
func (g *detectionGate) Handle(_ context.Context, record slog.Record) error {
	if record.Message != "skipping finding: rule filter" {
		return nil
	}
	active := g.active.Add(1)
	defer g.active.Add(-1)
	g.calls.Add(1)
	for peak := g.peak.Load(); active > peak; peak = g.peak.Load() {
		if g.peak.CompareAndSwap(peak, active) {
			break
		}
	}
	<-g.resume
	return nil
}

func TestWorkersSharedAcrossScanRunAndScanString(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		resume := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(resume) })
		defer unblock()
		gate := &detectionGate{resume: resume}
		cfg := testConfig()
		cfg.Rules[0].Filter = "true"
		scanner := mustNew(t, cfg, WithWorkers(5), WithLogger(slog.New(gate)))

		const scans = 100
		done := make(chan error, scans)
		for i := range scans {
			go func() {
				source := fragmentSource{fragments: []sources.Fragment{{Raw: "secret-alpha"}}}
				var err error
				switch i % 3 {
				case 0:
					scanner.ScanString("secret-alpha")
				case 1:
					_, err = scanner.Scan(t.Context(), source, nil)
				case 2:
					for result := range scanner.Run(t.Context(), source) {
						err = errors.Join(err, result.Err)
					}
				}
				done <- err
			}()
		}
		synctest.Wait()
		require.EqualValues(t, 5, gate.active.Load())
		require.EqualValues(t, 5, gate.calls.Load())
		require.Empty(t, done)

		// A different Scanner has its own worker budget.
		independent := mustNew(t, testConfig(), WithWorkers(1))
		require.Len(t, independent.ScanString("secret-beta"), 1)

		unblock()
		for range scans {
			require.NoError(t, <-done)
		}
		require.EqualValues(t, scans, gate.calls.Load())
		require.EqualValues(t, 5, gate.peak.Load())
		require.Zero(t, gate.active.Load())
	})
}

func TestWaitingScanCancellationDoesNotStopOtherScans(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		resume := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(resume) })
		defer unblock()
		gate := &detectionGate{resume: resume}
		cfg := testConfig()
		cfg.Rules[0].Filter = "true"
		scanner := mustNew(t, cfg, WithWorkers(1), WithLogger(slog.New(gate)))
		ownerDone := make(chan struct{})
		go func() {
			scanner.ScanString("secret-alpha")
			close(ownerDone)
		}()
		synctest.Wait()
		require.EqualValues(t, 1, gate.active.Load())

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		waitingDone := make(chan error, 1)
		go func() {
			_, err := scanner.Scan(ctx, fragmentSource{fragments: []sources.Fragment{{Raw: "secret-beta"}}}, nil)
			waitingDone <- err
		}()
		synctest.Wait()
		require.Empty(t, waitingDone)
		cancel()
		require.ErrorIs(t, <-waitingDone, context.Canceled)
		require.EqualValues(t, 1, gate.active.Load())
		require.EqualValues(t, 1, gate.calls.Load())

		unblock()
		<-ownerDone
		scanner.ScanString("secret-gamma")
		require.EqualValues(t, 2, gate.calls.Load())
	})
}

func TestSlowHandlerDoesNotOccupyWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		scanner := mustNew(t, testConfig(), WithWorkers(1))
		source := &countedFragmentSource{count: 100}
		resume := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(resume) })
		defer unblock()
		done := make(chan error, 1)
		go func() {
			summary, err := scanner.Scan(t.Context(), source, func(report.Finding) error {
				<-resume
				return nil
			})
			if err == nil && summary.Findings != source.count*3 {
				err = fmt.Errorf("got %d findings, want %d", summary.Findings, source.count*3)
			}
			done <- err
		}()
		synctest.Wait()

		// One fragment is in the handler and one can be queued. A slow handler
		// must neither stall other scans nor let its source run without bounds.
		require.EqualValues(t, 2, source.accepted.Load())
		require.Len(t, scanner.ScanString("secret-independent"), 1)
		unblock()
		require.NoError(t, <-done)
	})
}

func TestStoppedScanReleasesWorkerAndOutputSlots(t *testing.T) {
	for _, method := range []string{"Scan", "Run"} {
		t.Run(method, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				scanner := mustNew(t, testConfig(), WithWorkers(1))
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				source := &countedFragmentSource{count: 100}
				if method == "Scan" {
					stop := errors.New("handler stopped")
					summary, err := scanner.Scan(ctx, source, func(report.Finding) error { return stop })
					require.ErrorIs(t, err, stop)
					require.Equal(t, 1, summary.Findings)
				} else {
					for result := range scanner.Run(ctx, source) {
						require.NoError(t, result.Err)
						break
					}
				}
				require.NoError(t, ctx.Err())
				require.Less(t, source.accepted.Load(), int32(source.count))
				_, err := scanner.Scan(ctx, fragmentSource{fragments: []sources.Fragment{{Raw: "secret-next"}}}, nil)
				require.NoError(t, err)
			})
		})
	}
}

type countedFragmentSource struct {
	count    int
	accepted atomic.Int32
}

func (s *countedFragmentSource) Fragments(_ context.Context, yield sources.FragmentsFunc) error {
	for range s.count {
		if err := yield(sources.Fragment{Raw: "secret-alpha secret-beta secret-gamma"}, nil); err != nil {
			return err
		}
		s.accepted.Add(1)
	}
	return nil
}
