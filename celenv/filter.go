package celenv

import (
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	tiktoken "github.com/pkoukk/tiktoken-go"
)

// FilterEnv is a CEL environment for evaluating per-match filter expressions.
// Both `attributes map<string,string>` and `finding map<string,string>` are in scope.
type FilterEnv struct {
	env   *cel.Env
	mu    sync.RWMutex
	cache map[string]cel.Program
}

// NewFilterEnv creates a CEL environment for evaluating per-match filter expressions.
// If tokenizer is nil, failsTokenEfficiency always returns false (tokenizer unavailable).
func NewFilterEnv(tokenizer *tiktoken.Tiktoken) (*FilterEnv, error) {
	opts := []cel.EnvOption{
		cel.OptionalTypes(),
		ext.Bindings(),
		ext.Strings(),
		cel.Variable("attributes", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("finding", cel.MapType(cel.StringType, cel.StringType)),
	}
	opts = append(opts, fastBindings(tokenizer)...)

	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating FilterEnv: %w", err)
	}
	return &FilterEnv{
		env:   env,
		cache: make(map[string]cel.Program),
	}, nil
}

// Compile compiles a CEL expression and caches the result.
func (e *FilterEnv) Compile(expression string) (cel.Program, error) {
	e.mu.RLock()
	if prg, ok := e.cache[expression]; ok {
		e.mu.RUnlock()
		return prg, nil
	}
	e.mu.RUnlock()

	ast, issues := e.env.Compile(expression)
	if issues.Err() != nil {
		return nil, fmt.Errorf("filter CEL compile error:\n%s", issues.String())
	}
	prg, err := e.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("filter CEL program error: %w", err)
	}

	e.mu.Lock()
	e.cache[expression] = prg
	e.mu.Unlock()

	return prg, nil
}

// EvalFilter evaluates a compiled filter program against the given finding and attributes.
// Returns true if the finding should be skipped, false if it should be kept.
func EvalFilter(prg cel.Program, finding, attributes map[string]string) (bool, error) {
	if finding == nil {
		finding = emptyStringMap
	}
	if attributes == nil {
		attributes = emptyStringMap
	}
	val, _, err := prg.Eval(map[string]any{
		"finding":    finding,
		"attributes": attributes,
	})
	if err != nil {
		return false, err
	}
	b, ok := val.Value().(bool)
	if !ok {
		return false, fmt.Errorf("filter returned non-bool: %T", val.Value())
	}
	return b, nil
}
