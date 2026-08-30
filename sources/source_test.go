package sources

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProviderTargetJobs(t *testing.T) {
	tests := []struct {
		name         string
		jobs         int
		singleTarget bool
		want         int
	}{
		{name: "one job", jobs: 1, want: 1},
		{name: "four jobs", jobs: 4, want: 4},
		{name: "target jobs cap at four", jobs: 16, want: 4},
		{name: "single target", jobs: 16, singleTarget: true, want: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := providerTargetJobs(test.jobs, test.singleTarget)
			if got != test.want {
				t.Fatalf("providerTargetJobs(%d, %t) = %d, want %d",
					test.jobs, test.singleTarget, got, test.want)
			}
		})
	}
}

func TestAutomaticSourceJobsUseAdditionalIOFanout(t *testing.T) {
	processorJobs := automaticJobs()
	if got, want := automaticFileJobs(), max(processorJobs, min(processorJobs*4, 40)); got != want {
		t.Fatalf("automaticFileJobs() = %d, want %d", got, want)
	}
	if got, want := automaticObjectJobs(), processorJobs*2; got != want {
		t.Fatalf("automaticObjectJobs() = %d, want %d", got, want)
	}
}

func TestJobsWithinBudget(t *testing.T) {
	budget := newJobBudget(4)
	tests := []struct {
		name       string
		configured int
		fallback   int
		budget     *jobBudget
		want       int
	}{
		{name: "configured", configured: 8, fallback: 2, want: 8},
		{name: "fallback", fallback: 6, want: 6},
		{name: "shared budget caps configured", configured: 8, fallback: 2, budget: budget, want: 4},
		{name: "shared budget caps fallback", fallback: 6, budget: budget, want: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := jobsWithinBudget(test.configured, test.fallback, test.budget); got != test.want {
				t.Fatalf("jobsWithinBudget(%d, %d) = %d, want %d", test.configured, test.fallback, got, test.want)
			}
		})
	}
}

func TestNilJobBudgetRunsDirectly(t *testing.T) {
	var budget *jobBudget
	called := false
	if err := budget.run(t.Context(), func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("budget.run: %v", err)
	}
	if !called {
		t.Fatal("nil job budget did not run work")
	}
}

func TestJobBudgetBoundsNestedWork(t *testing.T) {
	budget := newJobBudget(2)
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var active atomic.Int64
	var peak atomic.Int64
	var wg sync.WaitGroup

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := budget.run(t.Context(), func() error {
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
		}()
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
		t.Fatal("job budget admitted more than two tasks")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if got := peak.Load(); got != 2 {
		t.Fatalf("peak jobs = %d, want 2", got)
	}
}
