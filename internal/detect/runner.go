// Package detect contains the allocation-conscious scan orchestration used by
// the public detect package. It deliberately depends only on the source API so
// the detection engine and its compatibility facade can evolve independently.
package detect

import (
	"context"
	"errors"
	"runtime"
	"sync"

	"github.com/betterleaks/betterleaks/sources"
)

// Options controls the independent source and detection stages.
type Options struct {
	// SourceWorkers limits concurrent source tasks. Zero uses the source default.
	SourceWorkers int
	// DetectWorkers limits concurrent fragment consumers. Zero uses GOMAXPROCS.
	DetectWorkers int
	// QueueSize is the maximum number of leased fragments waiting for detection.
	// Zero uses the resolved detection worker count.
	QueueSize int
}

// FragmentErrorFunc handles an error emitted alongside a source fragment. A
// non-nil fragment is borrowed for the duration of the call and released by
// Run afterward.
type FragmentErrorFunc func(*sources.Fragment, error) error

// ConsumeFunc processes one leased fragment. Run releases the fragment after
// ConsumeFunc returns, so retained data must be copied before then.
type ConsumeFunc func(context.Context, *sources.Fragment) error

// ConsumeFactory creates one consumer for each detection worker. It lets an
// engine attach worker-local scratch without synchronization or per-fragment
// pool traffic.
type ConsumeFactory func() ConsumeFunc

func (o Options) detectWorkers() int {
	if o.DetectWorkers > 0 {
		return o.DetectWorkers
	}
	return max(runtime.GOMAXPROCS(0), 1)
}

// Run connects source production to a bounded, fixed-size detection pool.
// Fragment ownership crosses the queue without copying Raw or Attributes; all
// success, error, and cancellation paths release each accepted lease once.
func Run(
	ctx context.Context,
	source sources.Source,
	options Options,
	onFragmentError FragmentErrorFunc,
	consume ConsumeFunc,
) error {
	return RunWorkers(ctx, source, options, onFragmentError, func() ConsumeFunc {
		return consume
	})
}

// RunWorkers is Run with a worker-local consumer factory.
func RunWorkers(
	ctx context.Context,
	source sources.Source,
	options Options,
	onFragmentError FragmentErrorFunc,
	newConsumer ConsumeFactory,
) error {
	if source == nil {
		return errors.New("detect: nil source")
	}
	if newConsumer == nil {
		return errors.New("detect: nil consumer")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runCtx = sources.WithSourceWorkers(runCtx, options.SourceWorkers)

	workerCount := options.detectWorkers()
	queueSize := options.QueueSize
	if queueSize <= 0 {
		// One queued fragment per worker is enough to overlap source I/O with
		// detection while tightly bounding leased file buffers.
		queueSize = workerCount
	}
	jobs := make(chan *sources.Fragment, queueSize)

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

	consumers := make([]ConsumeFunc, workerCount)
	for i := range consumers {
		consume := newConsumer()
		if consume == nil {
			return errors.New("detect: consumer factory returned nil")
		}
		consumers[i] = consume
	}
	workerWG.Add(workerCount)
	for _, consume := range consumers {
		go func() {
			defer workerWG.Done()
			for fragment := range jobs {
				if runCtx.Err() == nil {
					recordWorkerError(consume(runCtx, fragment))
				}
				fragment.Release()
			}
		}()
	}

	sourceErr := source.Fragments(runCtx, func(fragment *sources.Fragment, err error) error {
		if err != nil {
			if fragment != nil {
				defer fragment.Release()
			}
			if onFragmentError == nil {
				return nil
			}
			if handlerErr := onFragmentError(fragment, err); handlerErr != nil {
				recordWorkerError(handlerErr)
				return handlerErr
			}
			return nil
		}
		if fragment == nil {
			return nil
		}
		if len(fragment.Raw) == 0 && fragment.Attr(sources.AttrPath) == "" {
			fragment.Release()
			return nil
		}

		select {
		case jobs <- fragment:
			return nil
		case <-runCtx.Done():
			fragment.Release()
			return runCtx.Err()
		}
	})
	close(jobs)
	workerWG.Wait()

	if workerErr != nil {
		if sourceErr != nil && !errors.Is(sourceErr, context.Canceled) {
			return errors.Join(workerErr, sourceErr)
		}
		return workerErr
	}
	if sourceErr == nil {
		return ctx.Err()
	}
	return sourceErr
}
