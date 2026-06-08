package regexp

import (
	"sync"
	"testing"
)

// TestSetEngineConcurrentWithCompile exercises concurrent SetEngine / Compile /
// Version access. Run with -race (the Makefile does) to catch data races on the
// shared engine; it trips the detector on the pre-atomic implementation.
func TestSetEngineConcurrentWithCompile(t *testing.T) {
	t.Cleanup(func() { SetEngine(Stdlib{}) })

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				SetEngine(Stdlib{})
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stop)
		for i := 0; i < 2000; i++ {
			if _, err := Compile(`a[b-z]+\d`); err != nil {
				t.Errorf("Compile failed: %v", err)
				return
			}
			_ = Version()
		}
	}()

	wg.Wait()
}
