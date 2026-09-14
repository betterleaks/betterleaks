package scan

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/internal/confidence"
	"github.com/betterleaks/betterleaks/v2/internal/contextwindow"
)

// Confidence is the minimum confidence classification accepted by a scanner.
type Confidence string

const (
	ConfidenceAny    Confidence = ""
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type scannerOptions struct {
	jobs                int
	maxDecodeDepth      int
	matchContext        contextwindow.Spec
	minimumConfidence   string
	ignoreAllowComments bool
	excludedPaths       []string
	ignoredFingerprints []fingerprint.Hash
	precompile          bool
	logger              *slog.Logger
}

// Option configures a Scanner during construction. Options are created by the
// With... functions in this package.
type Option struct {
	apply func(*scannerOptions) error
}

// WithExcludedPaths suppresses fragments whose path equals one of paths.
func WithExcludedPaths(paths ...string) Option {
	paths = slices.Clone(paths)
	return Option{apply: func(options *scannerOptions) error {
		options.excludedPaths = append(options.excludedPaths, paths...)
		return nil
	}}
}

// WithIgnoredFingerprints suppresses completed findings whose primary secret
// matches a hash, independent of rule, source, or location. Component matches
// remain available to assemble other findings. Suppression precedes validation
// and analysis and applies to Run, Scan, and ScanString.
// The hashes are copied; repeated options add to the ignored set.
func WithIgnoredFingerprints(hashes ...fingerprint.Hash) Option {
	hashes = slices.Clone(hashes)
	return Option{apply: func(options *scannerOptions) error {
		options.ignoredFingerprints = append(options.ignoredFingerprints, hashes...)
		return nil
	}}
}

// WithJobs sets the maximum number of concurrent scanner workers. Zero uses
// GOMAXPROCS.
func WithJobs(jobs int) Option {
	return Option{apply: func(options *scannerOptions) error {
		if jobs < 0 {
			return errors.New("jobs must be non-negative")
		}
		options.jobs = jobs
		return nil
	}}
}

// WithMaxDecodeDepth limits recursive decoding passes. Zero disables decoding.
func WithMaxDecodeDepth(depth int) Option {
	return Option{apply: func(options *scannerOptions) error {
		if depth < 0 {
			return errors.New("maximum decode depth must be non-negative")
		}
		options.maxDecodeDepth = depth
		return nil
	}}
}

// WithMatchContext configures the context captured around each finding using
// the same grammar as the CLI --match-context flag. The captured text is stored
// in Finding.MatchContext and available to expressions as finding.context.
// By default, no surrounding context is retained.
func WithMatchContext(spec string) Option {
	return Option{apply: func(options *scannerOptions) error {
		parsed, err := contextwindow.Parse(spec)
		if err != nil {
			return fmt.Errorf("match context: %w", err)
		}
		options.matchContext = parsed
		return nil
	}}
}

// WithMinimumConfidence suppresses classified findings below confidence.
func WithMinimumConfidence(value Confidence) Option {
	return Option{apply: func(options *scannerOptions) error {
		parsed, err := confidence.Parse(string(value))
		if err != nil {
			return err
		}
		options.minimumConfidence = parsed
		return nil
	}}
}

// WithIgnoreAllowComments controls whether allow comments are ignored instead
// of suppressing findings.
func WithIgnoreAllowComments(ignore bool) Option {
	return Option{apply: func(options *scannerOptions) error {
		options.ignoreAllowComments = ignore
		return nil
	}}
}

// WithLogger directs scanner diagnostics to logger. Scanners are silent
// unless a logger is supplied.
func WithLogger(logger *slog.Logger) Option {
	return Option{apply: func(options *scannerOptions) error {
		options.logger = loggerOrDiscard(logger)
		return nil
	}}
}

// WithPrecompile compiles detection regexes and local filter expressions during
// construction. Provider expressions are never compiled. Lazy compilation remains the default.
func WithPrecompile() Option {
	return Option{apply: func(options *scannerOptions) error {
		options.precompile = true
		return nil
	}}
}
