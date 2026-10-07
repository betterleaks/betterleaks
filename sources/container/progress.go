package container

import (
	"context"
	"io"
	"sync/atomic"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/rs/zerolog"
)

const progressInterval = 5 * time.Second

func (r *session) debug(message string, attrs ...any) {
	if r.s.Logger != nil {
		r.s.Logger.Debug().Fields(attrs).Msg(message)
	}
}

// Progress runs independently of reads and callbacks, so stalled HTTP reads
// and detection backpressure still produce updates. Only debug scans allocate
// the ticker/goroutine or wrap readers. finish joins it before returning.
type progress struct {
	logger        zerolog.Logger
	operation     string
	started       time.Time
	done, stopped chan struct{}
	bytes         atomic.Int64
	files         atomic.Int64
	tracking      atomic.Bool
	phase         atomic.Value
}

func (r *session) startProgress(ctx context.Context, operation string, attrs ...any) *progress {
	return newProgress(ctx, r.s.Logger, progressInterval, operation, attrs...)
}

func newProgress(ctx context.Context, logger *zerolog.Logger, interval time.Duration, operation string, attrs ...any) *progress {
	if logger == nil || logger.GetLevel() > zerolog.DebugLevel || zerolog.GlobalLevel() > zerolog.DebugLevel {
		return nil
	}
	p := &progress{logger: logger.With().Fields(attrs).Logger(), operation: operation, started: time.Now(), done: make(chan struct{}), stopped: make(chan struct{})}
	p.logger.Debug().Msg(operation + " started")
	go func() {
		defer close(p.stopped)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.log(operation + " progress")
			case <-p.done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return p
}

func (p *progress) log(message string, attrs ...any) {
	attrs = append(attrs, "elapsed", time.Since(p.started).Round(time.Millisecond))
	if phase := p.phase.Load(); phase != nil {
		attrs = append(attrs, "phase", phase)
	}
	if p.tracking.Load() {
		n := p.bytes.Load()
		attrs = append(attrs, "bytes_read", n, "read", humanize.IBytes(uint64(n)))
	}
	if n := p.files.Load(); n > 0 {
		attrs = append(attrs, "files_enumerated", n)
	}
	p.logger.Debug().Fields(attrs).Msg(message)
}

func (p *progress) finish(err error) {
	if p == nil {
		return
	}
	close(p.done)
	<-p.stopped
	// Do not echo response bodies, config values, or build commands in progress
	// logs. The normal source error path supplies sanitized diagnostics.
	p.log(p.operation+" finished", "failed", err != nil)
}

func (p *progress) setPhase(phase string) {
	if p != nil {
		p.phase.Store(phase)
	}
}

func (p *progress) file() {
	if p != nil {
		p.files.Add(1)
	}
}

func (p *progress) reader(reader io.Reader) io.Reader {
	if p == nil {
		return reader
	}
	p.tracking.Store(true)
	return progressReader{Reader: reader, progress: p}
}

type progressReader struct {
	io.Reader
	progress *progress
}

func (r progressReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.progress.bytes.Add(int64(n))
	return n, err
}
