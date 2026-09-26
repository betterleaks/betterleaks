package scan

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/internal/confidence"
	"github.com/betterleaks/betterleaks/v2/internal/contextwindow"
	"github.com/betterleaks/betterleaks/v2/regexp"
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
	regexEngine         regexp.Engine
	workers             int
	maxDecodeDepth      int
	matchContext        contextwindow.Spec
	minimumConfidence   string
	allowSignatures     []string
	ignoredFingerprints []fingerprint.Hash
	precompile          bool
	logger              *slog.Logger
}

// Option configures a Scanner during construction. Options are created by the
// With... functions in this package.
type Option struct {
	apply func(*scannerOptions) error
}

// WithRegexEngine selects the engine for detection regexes, path regexes, and
// finding filter helpers. The default is regexp.Stdlib. Engine is retained and
// must support concurrent use. Source prefilters are configured separately.
func WithRegexEngine(engine regexp.Engine) Option {
	return Option{apply: func(options *scannerOptions) error {
		if engine == nil {
			return errors.New("regex engine is required")
		}
		options.regexEngine = engine
		return nil
	}}
}

// WithIgnoredFingerprints suppresses findings with an ignored primary secret
// and excludes ignored component matches, independent of rule, source, or location.
// Hashes identify exact Match.Value bytes, including non-secret component values.
// A primary is suppressed if a required component has no remaining matches.
// Ignored optional components are treated as absent. Filtering precedes validation
// and analysis and applies to Scan and ScanString.
// The hashes are copied; repeated options add to the ignored set.
func WithIgnoredFingerprints(hashes ...fingerprint.Hash) Option {
	hashes = slices.Clone(hashes)
	return Option{apply: func(options *scannerOptions) error {
		options.ignoredFingerprints = append(options.ignoredFingerprints, hashes...)
		return nil
	}}
}

// WithWorkers limits concurrent detection across all Scan and ScanString
// calls on the same Scanner. Workers start as needed; source I/O and result
// handlers do not occupy worker slots. Zero uses GOMAXPROCS at construction.
func WithWorkers(workers int) Option {
	return Option{apply: func(options *scannerOptions) error {
		if workers < 0 {
			return errors.New("workers must be non-negative")
		}
		options.workers = workers
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
// in Finding.Match.Context and available to local filter expressions as finding.context.
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

// WithAllowSignatures replaces the default betterleaks:allow and gitleaks:allow
// markers. Matching is a case-sensitive literal substring check on finding lines;
// markers need not appear inside comments. No signatures disables suppression.
// Empty strings are rejected by New. The slice is copied when the option is
// created; repeated options replace the list, with the last option taking effect.
func WithAllowSignatures(signatures ...string) Option {
	signatures = slices.Clone(signatures)
	return Option{apply: func(options *scannerOptions) error {
		for _, signature := range signatures {
			if signature == "" {
				return errors.New("allow signatures must not be empty")
			}
		}
		options.allowSignatures = signatures
		return nil
	}}
}

// WithLogger directs scanner diagnostics to logger. Scanners are silent
// unless a logger is supplied.
func WithLogger(logger *slog.Logger) Option {
	return Option{apply: func(options *scannerOptions) error {
		options.logger = logger
		return nil
	}}
}

// WithPrecompile compiles detection and path regexes during construction instead
// of on first use. Finding filters always compile during construction. Provider
// expressions are never compiled by the scanner.
func WithPrecompile() Option {
	return Option{apply: func(options *scannerOptions) error {
		options.precompile = true
		return nil
	}}
}
