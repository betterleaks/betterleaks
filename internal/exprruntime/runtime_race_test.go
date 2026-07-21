package exprruntime

import (
	"sync"
	"testing"

	tiktoken "github.com/pkoukk/tiktoken-go"
)

// The Runtime caches compiled filter/prefilter programs and shares each
// Program across scan workers, so EvalFilter and EvalPrefilter run
// concurrently on one Program value. These tests reproduce that access
// pattern. They fail under -race if any eval writes the shared
// *runtimeBindings, and fail functionally if a racing write leaves the
// tokenizer unresolved, which flips failsTokenEfficiency verdicts and makes
// findings nondeterministic.

func testTokenizer(t *testing.T) *tiktoken.Tiktoken {
	t.Helper()
	tke, err := tiktoken.GetEncoding("cl100k_base")
	if err != nil {
		t.Skipf("tokenizer unavailable: %v", err)
	}
	return tke
}

func TestEvalFilterConcurrentSharedProgram(t *testing.T) {
	rt, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	tke := testTokenizer(t)

	// Lazy provider mirrors Detector.Tokenizer: rule filters compile with a
	// nil tokenizer and resolve it through the provider at eval time.
	rt.SetTokenizerProvider(func() *tiktoken.Tiktoken { return tke })

	prg, err := rt.CompileFilter(`filter.failsTokenEfficiency(finding["secret"])`, nil)
	if err != nil {
		t.Fatal(err)
	}

	// cl100k_base encodes "sk-test" to 2 tokens over 7 characters; the 3.5
	// ratio clears the token-efficiency threshold, so failsTokenEfficiency
	// returns true under every interleaving. A false result then signals a
	// race, not a borderline input.
	finding := map[string]string{"secret": "sk-test"}

	const workers = 32
	const evals = 200
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < evals; i++ {
				got, err := rt.EvalFilter(prg, finding, nil)
				if err != nil {
					t.Errorf("EvalFilter: %v", err)
					return
				}
				if !got {
					// The verdict is deterministically true; a false result
					// means a concurrent write left the shared tokenizer
					// unresolved, forcing failsTokenEfficiency to return false.
					t.Error("EvalFilter verdict flipped under concurrency")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestEvalPrefilterConcurrentSharedProgram(t *testing.T) {
	rt, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}

	prg, err := rt.CompilePrefilter(`matchesAny(get(attributes, "path", ""), ["\\.png$"])`)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 32
	const evals = 500
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			attrs := map[string]string{"path": "img/logo.png"}
			if w%2 == 1 {
				attrs["path"] = "src/main.go"
			}
			want := w%2 == 0
			for i := 0; i < evals; i++ {
				got, err := rt.EvalPrefilter(prg, attrs)
				if err != nil {
					t.Errorf("EvalPrefilter: %v", err)
					return
				}
				if got != want {
					t.Errorf("EvalPrefilter = %v, want %v", got, want)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}
