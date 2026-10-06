package exprruntime

import (
	"github.com/betterleaks/betterleaks/v2/internal/tokenizer"
	"github.com/betterleaks/betterleaks/v2/regexp"
)

// LocalRuntime exposes only deterministic finding and source filters. It has no
// HTTP client, provider environment, or request budget.
type LocalRuntime struct {
	runtime Runtime
}

// NewLocal creates a filter runtime. A nil engine selects the standard library.
func NewLocal(engine regexp.Engine) *LocalRuntime {
	return &LocalRuntime{runtime: Runtime{cache: make(map[string]Program), regexEngine: engine}}
}

func (r *LocalRuntime) SetTokenCounterProvider(provider func() *tokenizer.Counter) {
	r.runtime.SetTokenCounterProvider(provider)
}

func (r *LocalRuntime) CompileFilter(expression string, counter *tokenizer.Counter) (Program, error) {
	return r.runtime.CompileFilter(expression, counter)
}

func (r *LocalRuntime) CompilePrefilter(expression string) (Program, error) {
	return r.runtime.CompilePrefilter(expression)
}

func (r *LocalRuntime) EvalFilter(program Program, finding map[string]any, attributes map[string]string) (bool, error) {
	return r.runtime.EvalFilter(program, finding, attributes)
}

func (r *LocalRuntime) EvalPrefilter(program Program, attributes map[string]string) (bool, error) {
	return r.runtime.EvalPrefilter(program, attributes)
}
