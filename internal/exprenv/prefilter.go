package exprenv

import (
	"fmt"
	"sync"

	"github.com/expr-lang/expr"
)

type PrefilterEnv struct {
	mu    sync.RWMutex
	cache map[string]Program
}

func NewPrefilterEnv() (*PrefilterEnv, error) {
	return &PrefilterEnv{cache: make(map[string]Program)}, nil
}

func (e *PrefilterEnv) Compile(expression string) (Program, error) {
	rewritten, err := RewriteCELCompat(expression)
	if err != nil {
		return nil, err
	}
	e.mu.RLock()
	if prg, ok := e.cache[rewritten]; ok {
		e.mu.RUnlock()
		return prg, nil
	}
	e.mu.RUnlock()

	env := baseEnv(&runtimeBindings{})
	vmPrg, err := expr.Compile(rewritten, expr.Env(env), expr.AsBool())
	if err != nil {
		if rewritten != expression {
			return nil, fmt.Errorf("prefilter expr compile error: %w\noriginal expression:\n%s\nrewritten expression:\n%s", err, expression, rewritten)
		}
		return nil, fmt.Errorf("prefilter expr compile error: %w", err)
	}
	prg := &compiledProgram{vm: vmPrg}
	e.mu.Lock()
	e.cache[rewritten] = prg
	e.mu.Unlock()
	return prg, nil
}

func EvalPrefilter(prg Program, attributes map[string]string) (bool, error) {
	env := baseEnv(&runtimeBindings{
		attrs: stringMapToAny(nonNilStringMap(attributes)),
	})
	val, err := expr.Run(prg.vm, env)
	if err != nil {
		return false, err
	}
	b, ok := val.(bool)
	if !ok {
		return false, fmt.Errorf("prefilter returned non-bool: %T", val)
	}
	return b, nil
}
