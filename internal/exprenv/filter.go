package exprenv

import (
	"fmt"
	"sync"

	"github.com/expr-lang/expr"
	tiktoken "github.com/pkoukk/tiktoken-go"
)

type FilterEnv struct {
	tokenizer *tiktoken.Tiktoken
	mu        sync.RWMutex
	cache     map[string]Program
}

func NewFilterEnv(tokenizer *tiktoken.Tiktoken) (*FilterEnv, error) {
	return &FilterEnv{tokenizer: tokenizer, cache: make(map[string]Program)}, nil
}

func (e *FilterEnv) Compile(expression string) (Program, error) {
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

	env := baseEnv(&runtimeBindings{tokenizer: e.tokenizer})
	vmPrg, err := expr.Compile(rewritten, expr.Env(env), expr.AsBool())
	if err != nil {
		if rewritten != expression {
			return nil, fmt.Errorf("filter expr compile error: %w\noriginal expression:\n%s\nrewritten expression:\n%s", err, expression, rewritten)
		}
		return nil, fmt.Errorf("filter expr compile error: %w", err)
	}
	prg := &compiledProgram{vm: vmPrg, tokenizer: e.tokenizer}
	e.mu.Lock()
	e.cache[rewritten] = prg
	e.mu.Unlock()
	return prg, nil
}

func EvalFilter(prg Program, finding, attributes map[string]string) (bool, error) {
	env := baseEnv(&runtimeBindings{
		tokenizer: prg.tokenizer,
		finding:   stringMapToAny(nonNilStringMap(finding)),
		attrs:     stringMapToAny(nonNilStringMap(attributes)),
		captures:  map[string]any{},
	})
	val, err := expr.Run(prg.vm, env)
	if err != nil {
		return false, err
	}
	b, ok := val.(bool)
	if !ok {
		return false, fmt.Errorf("filter returned non-bool: %T", val)
	}
	return b, nil
}

func nonNilStringMap(m map[string]string) map[string]string {
	if m == nil {
		return emptyStringMap
	}
	return m
}
