package exprruntime

import (
	"sync"
	"testing"
)

// TestEvalFilter_ConcurrentSameProgram guards against the data race where a
// single cached filter Program, evaluated concurrently, mutates the shared
// *runtimeBindings stored in its bindings map. Run with -race.
func TestEvalFilter_ConcurrentSameProgram(t *testing.T) {
	rt, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	prg, err := rt.CompileFilter(`entropy(finding["secret"]) >= 0.0 && !failsTokenEfficiency(finding["secret"])`, nil)
	if err != nil {
		t.Fatalf("CompileFilter: %v", err)
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, err := rt.EvalFilter(prg, map[string]string{"secret": "value"}, nil); err != nil {
					t.Errorf("EvalFilter: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestEvalPrefilter_ConcurrentSameProgram is the prefilter analogue.
func TestEvalPrefilter_ConcurrentSameProgram(t *testing.T) {
	rt, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	prg, err := rt.CompilePrefilter(`entropy(get(attributes, "path", "")) >= 0.0`)
	if err != nil {
		t.Fatalf("CompilePrefilter: %v", err)
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, err := rt.EvalPrefilter(prg, map[string]string{"path": "x"}); err != nil {
					t.Errorf("EvalPrefilter: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
