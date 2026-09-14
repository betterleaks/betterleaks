package scan

import (
	"fmt"
	"sync"

	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/tokenizer"
	"github.com/betterleaks/betterleaks/v2/sources"
)

func (d *Scanner) tokenCounterInstance() *tokenizer.Counter {
	d.tokenCounterOnce.Do(func() {
		counter, err := tokenizer.Default()
		if err != nil {
			d.logger.Warn("could not initialize cl100k_base tokenizer", "error", err)
			return
		}
		d.tokenCounter = counter
	})
	return d.tokenCounter
}

// lazyFilter belongs to one immutable rule. After the first compilation, the
// hot path needs neither a cache-key lookup nor a shared mutex. Errors are also
// memoized so malformed filters are not recompiled for every candidate.
type lazyFilter struct {
	once    sync.Once
	program exprruntime.Program
	err     error
}

func (f *lazyFilter) compile(runtime *exprruntime.LocalRuntime, expression string) (exprruntime.Program, error) {
	f.once.Do(func() { f.program, f.err = runtime.CompileFilter(expression, nil) })
	return f.program, f.err
}

func (d *Scanner) globalFilterProgram() (exprruntime.Program, bool, error) {
	if d.globalFilterExpr == "" {
		return nil, false, nil
	}
	program, err := d.globalFilter.compile(d.exprRuntime, d.globalFilterExpr)
	if err != nil {
		return nil, false, fmt.Errorf("compiling global filter: %w", err)
	}
	return program, true, nil
}

func (d *Scanner) ruleFilterProgram(r *compiledRule) (exprruntime.Program, bool, error) {
	if r.rule.Filter == "" {
		return nil, false, nil
	}
	program, err := r.filter.compile(d.exprRuntime, r.rule.Filter)
	if err != nil {
		return nil, false, fmt.Errorf("compiling rule %s filter: %w", r.rule.ID, err)
	}
	return program, true, nil
}

// SkipFunc returns a sources.SkipFunc callback that evaluates the config's
// prefilter program against fragment attributes. Pass it to a source's
// ShouldSkip field to filter fragments before their contents are loaded. It
// returns nil when no prefilter or excluded paths are configured.
func (d *Scanner) SkipFunc() sources.SkipFunc {
	prg := d.prefilterProgram
	if prg == nil && len(d.excludedPaths) == 0 {
		return nil
	}
	return func(attrs map[string]string) bool {
		if d.pathExcluded(attrs[sources.AttrPath]) {
			return true
		}
		if prg != nil {
			skip, err := d.exprRuntime.EvalPrefilter(prg, attrs)
			if err != nil {
				d.logger.Warn("prefilter eval error; not skipping", "error", err)
				return false
			}
			return skip
		}
		return false
	}
}

func (d *Scanner) pathExcluded(path string) bool {
	for _, excluded := range d.excludedPaths {
		if path != "" && samePath(path, excluded) {
			return true
		}
	}
	return false
}
