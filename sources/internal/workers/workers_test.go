package workers

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProviderTargetWorkers(t *testing.T) {
	tests := []struct {
		name         string
		workers      int
		singleTarget bool
		want         int
	}{
		{name: "one worker", workers: 1, want: 1},
		{name: "four workers", workers: 4, want: 4},
		{name: "target workers cap at four", workers: 16, want: 4},
		{name: "single target", workers: 16, singleTarget: true, want: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ProviderTargets(test.workers, test.singleTarget)
			if got != test.want {
				t.Fatalf("ProviderTargets(%d, %t) = %d, want %d",
					test.workers, test.singleTarget, got, test.want)
			}
		})
	}
}

func TestAutomaticSourceWorkersUseAdditionalIOFanout(t *testing.T) {
	processorCount := Automatic()
	if got, want := AutomaticFiles(), max(processorCount, min(processorCount*12, 120)); got != want {
		t.Fatalf("AutomaticFiles() = %d, want %d", got, want)
	}
	if got, want := AutomaticObjects(), processorCount*2; got != want {
		t.Fatalf("AutomaticObjects() = %d, want %d", got, want)
	}
}

func TestWorkersWithinBudget(t *testing.T) {
	budget := NewBudget(4)
	tests := []struct {
		name       string
		configured int
		fallback   int
		budget     *Budget
		want       int
	}{
		{name: "configured", configured: 8, fallback: 2, want: 8},
		{name: "fallback", fallback: 6, want: 6},
		{name: "shared budget caps configured", configured: 8, fallback: 2, budget: budget, want: 4},
		{name: "shared budget caps fallback", fallback: 6, budget: budget, want: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := WithinBudget(test.configured, test.fallback, test.budget); got != test.want {
				t.Fatalf("WithinBudget(%d, %d) = %d, want %d", test.configured, test.fallback, got, test.want)
			}
		})
	}
}

func TestNilWorkerBudgetRunsDirectly(t *testing.T) {
	var budget *Budget
	called := false
	if err := budget.Run(t.Context(), func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("budget.run: %v", err)
	}
	if !called {
		t.Fatal("nil worker budget did not run work")
	}
}

func TestWorkerBudgetBoundsNestedWork(t *testing.T) {
	budget := NewBudget(2)
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var active atomic.Int64
	var peak atomic.Int64
	var wg sync.WaitGroup

	for range 4 {
		wg.Go(func() {
			if err := budget.Run(t.Context(), func() error {
				current := active.Add(1)
				for {
					previous := peak.Load()
					if current <= previous || peak.CompareAndSwap(previous, current) {
						break
					}
				}
				started <- struct{}{}
				<-release
				active.Add(-1)
				return nil
			}); err != nil {
				t.Errorf("budget.run: %v", err)
			}
		})
	}

	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for budgeted work")
		}
	}
	select {
	case <-started:
		t.Fatal("worker budget admitted more than two tasks")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if got := peak.Load(); got != 2 {
		t.Fatalf("peak workers = %d, want 2", got)
	}
}
