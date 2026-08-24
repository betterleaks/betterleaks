package detect

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/exp/maps"

	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

type fragmentJob struct {
	fragment  sources.Fragment
	byteCount int
}

func (d *Detector) detectWorkerCount() int {
	if d.DetectWorkers > 0 {
		return d.DetectWorkers
	}
	return max(runtime.GOMAXPROCS(0), 1)
}

// newFragmentJob separates a fragment from source-owned buffers and maps before
// it crosses the detection queue. File fragments keep their content in Raw;
// Bytes is retained by sources only so detection can account for the original
// size.
func newFragmentJob(fragment sources.Fragment) fragmentJob {
	byteCount := len(fragment.Raw)
	if fragment.Bytes != nil {
		byteCount = len(fragment.Bytes)
		fragment.Bytes = nil
	}
	fragment.Attributes = maps.Clone(fragment.Attributes)
	return fragmentJob{fragment: fragment, byteCount: byteCount}
}

// runDetectionWorkers connects a source to a bounded fragment queue and a
// fixed-size detection pool. A worker error cancels source production and is
// returned after all workers have stopped.
func (d *Detector) runDetectionWorkers(
	ctx context.Context,
	source sources.Source,
	onFragmentError func(sources.Fragment, error) error,
	consume func(context.Context, fragmentJob) error,
) error {
	if source == nil {
		return errors.New("pipeline: nil source")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if d.SourceWorkers > 0 {
		runCtx = sources.WithSourceWorkers(runCtx, d.SourceWorkers)
	}

	workers := d.detectWorkerCount()
	jobs := make(chan fragmentJob, workers*2)

	var (
		workerWG  sync.WaitGroup
		workerErr error
		errOnce   sync.Once
	)
	recordWorkerError := func(err error) {
		if err == nil {
			return
		}
		errOnce.Do(func() {
			workerErr = err
			cancel()
		})
	}

	for range workers {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for {
				select {
				case <-runCtx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}
					if err := consume(runCtx, job); err != nil {
						recordWorkerError(err)
						return
					}
				}
			}
		}()
	}

	sourceErr := source.Fragments(runCtx, func(fragment sources.Fragment, err error) error {
		if err != nil {
			if onFragmentError == nil {
				return nil
			}
			return onFragmentError(fragment, err)
		}

		logger := fragment.Logger()
		if len(fragment.Raw) == 0 && fragment.Attr(sources.AttrPath) == "" {
			logger.Trace().Msg("skipping empty fragment")
			return nil
		}

		job := newFragmentJob(fragment)
		select {
		case <-runCtx.Done():
			return runCtx.Err()
		case jobs <- job:
			return nil
		}
	})
	close(jobs)
	workerWG.Wait()

	if workerErr != nil {
		if sourceErr != nil && !errors.Is(sourceErr, context.Canceled) && !errors.Is(sourceErr, errStopIteration) {
			return errors.Join(workerErr, sourceErr)
		}
		return workerErr
	}
	return sourceErr
}

func (d *Detector) inspectFragment(
	ctx context.Context,
	job fragmentJob,
	consume func(report.Finding) error,
) error {
	logger := job.fragment.Logger()
	var timer *time.Timer
	if logger.GetLevel() <= zerolog.DebugLevel {
		timer = time.AfterFunc(SlowWarningThreshold, func() {
			logger.Debug().Msgf("Taking longer than %s to inspect fragment", SlowWarningThreshold.String())
		})
		defer timer.Stop()
	}

	for _, finding := range d.detectFragmentSized(ctx, job.fragment, job.byteCount) {
		if err := consume(finding); err != nil {
			return err
		}
	}
	return nil
}
