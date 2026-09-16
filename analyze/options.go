package analyze

import (
	"errors"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/betterleaks/betterleaks/v2/internal/provider"
)

type options struct {
	provider.RuntimeOptions
	workers    int
	logger     *slog.Logger
	precompile bool
}

// Option configures provider execution. Output filtering belongs to the caller.
type Option struct{ apply func(*options) error }

// WithWorkers bounds concurrent provider evaluations per streaming operation.
// Zero uses ten workers.
func WithWorkers(workers int) Option {
	return Option{apply: func(o *options) error {
		if workers < 0 {
			return errors.New("provider workers must be non-negative")
		}
		o.workers = workers
		if o.workers == 0 {
			o.workers = 10
		}
		return nil
	}}
}

// WithTimeout sets the per-request timeout. Zero uses ten seconds.
func WithTimeout(timeout time.Duration) Option {
	return Option{apply: func(o *options) error { o.Timeout = timeout; return nil }}
}

// WithMaxRequestsPerTarget limits requests per provider origin within one
// operation. The budget is shared by validation and analysis. Zero is unlimited.
func WithMaxRequestsPerTarget(limit int) Option {
	return Option{apply: func(o *options) error { o.MaxRequestsPerTarget = limit; return nil }}
}

// WithRequestsPerSecond sets the shared provider request rate for an operation.
// Zero is unlimited.
func WithRequestsPerSecond(rate float64) Option {
	return Option{apply: func(o *options) error { o.RequestsPerSecond = rate; return nil }}
}

// WithRequestsPerSecondByRule supplies per-rule request rate overrides.
func WithRequestsPerSecondByRule(rates map[string]float64) Option {
	rates = maps.Clone(rates)
	return Option{apply: func(o *options) error { o.RequestsPerSecondByRule = rates; return nil }}
}

// WithEnvVars lists environment variables accessible to provider expressions.
func WithEnvVars(names ...string) Option {
	names = slices.Clone(names)
	return Option{apply: func(o *options) error { o.EnvVars = names; return nil }}
}

// WithDebug includes sanitized provider request diagnostics in results.
func WithDebug(debug bool) Option {
	return Option{apply: func(o *options) error { o.Debug = debug; return nil }}
}

// WithLogger directs analyzer diagnostics to logger. The default is silent.
func WithLogger(logger *slog.Logger) Option {
	return Option{apply: func(o *options) error {
		if logger != nil {
			o.logger = logger
		}
		return nil
	}}
}

// WithPrecompile checks all validation and analysis expressions at construction.
// Detection regexes and scan filters are not compiled.
func WithPrecompile() Option {
	return Option{apply: func(o *options) error { o.precompile = true; return nil }}
}
