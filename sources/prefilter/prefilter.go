// Package prefilter compiles attribute predicates for source ShouldSkip callbacks.
package prefilter

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"

	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/logging"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// Options adds exact path exclusions and evaluation diagnostics.
type Options struct {
	ExcludedPaths []string
	Logger        *slog.Logger
}

// Compile creates a predicate reusable across concurrent sources.
// It copies exclusions and borrows attributes only during evaluation. Evaluation
// errors keep the input and are logged when Logger is set. No policy returns nil.
func Compile(expression string, options Options) (sources.SkipFunc, error) {
	if expression == "" && len(options.ExcludedPaths) == 0 {
		return nil, nil
	}
	excluded := make([]string, len(options.ExcludedPaths))
	for i, path := range options.ExcludedPaths {
		excluded[i] = filepath.ToSlash(filepath.Clean(path))
	}
	var runtime *exprruntime.LocalRuntime
	var program exprruntime.Program
	if expression != "" {
		runtime = exprruntime.NewLocal()
		var err error
		program, err = runtime.CompilePrefilter(expression)
		if err != nil {
			return nil, fmt.Errorf("compile source prefilter: %w", err)
		}
	}
	logger := logging.OrDiscard(options.Logger)
	return func(attributes map[string]string) bool {
		if path := attributes[sources.AttrPath]; path != "" && len(excluded) > 0 {
			path = filepath.ToSlash(filepath.Clean(path))
			if slices.Contains(excluded, path) {
				return true
			}
		}
		if program == nil {
			return false
		}
		skip, err := runtime.EvalPrefilter(program, attributes)
		if err != nil {
			logger.Warn("prefilter eval error; not skipping", "error", err)
			return false
		}
		return skip
	}, nil
}
