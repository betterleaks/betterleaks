package celenv

import (
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

// emptyStringMap is a sentinel used in place of nil maps during CEL activation.
var emptyStringMap = map[string]string{}

// PrefilterEnv is a CEL environment for evaluating prefilter expressions.
// Only `attributes map<string,string>` is in scope — no `finding`, no HTTP, no AWS.
// An expression referencing `finding["..."]` fails at compile time.
type PrefilterEnv struct {
	env   *cel.Env
	mu    sync.RWMutex
	cache map[string]cel.Program
}

// NewPrefilterEnv creates a CEL environment for evaluating prefilter expressions.
func NewPrefilterEnv() (*PrefilterEnv, error) {
	opts := []cel.EnvOption{
		cel.OptionalTypes(),
		ext.Bindings(),
		ext.Strings(),
		cel.Variable("attributes", cel.MapType(cel.StringType, cel.StringType)),
	}
	opts = append(opts, fastBindings(nil)...)

	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating PrefilterEnv: %w", err)
	}
	return &PrefilterEnv{
		env:   env,
		cache: make(map[string]cel.Program),
	}, nil
}

// Compile compiles a CEL expression and caches the result.
// Returns an error if the expression references variables not in scope (e.g., `finding`).
func (e *PrefilterEnv) Compile(expression string) (cel.Program, error) {
	e.mu.RLock()
	if prg, ok := e.cache[expression]; ok {
		e.mu.RUnlock()
		return prg, nil
	}
	e.mu.RUnlock()

	ast, issues := e.env.Compile(expression)
	if issues.Err() != nil {
		return nil, fmt.Errorf("prefilter CEL compile error:\n%s", issues.String())
	}
	prg, err := e.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("prefilter CEL program error: %w", err)
	}

	e.mu.Lock()
	e.cache[expression] = prg
	e.mu.Unlock()

	return prg, nil
}

// EvalPrefilter evaluates a compiled prefilter program against the given attributes.
// Returns true if the fragment should be kept, false if it should be skipped.
func EvalPrefilter(prg cel.Program, attributes map[string]string) (bool, error) {
	if attributes == nil {
		attributes = emptyStringMap
	}
	val, _, err := prg.Eval(map[string]any{"attributes": attributes})
	if err != nil {
		return false, err
	}
	b, ok := val.Value().(bool)
	if !ok {
		return false, fmt.Errorf("prefilter returned non-bool: %T", val.Value())
	}
	return b, nil
}
