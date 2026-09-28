package cache

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheStoresSuccessfulComputations(t *testing.T) {
	cache := New[string]()
	var calls int

	first, err := cache.GetOrDo("key", func() (string, error) {
		calls++
		return "value", nil
	})
	require.NoError(t, err)
	second, err := cache.GetOrDo("key", func() (string, error) {
		calls++
		return "other", nil
	})
	require.NoError(t, err)

	assert.Equal(t, "value", first)
	assert.Equal(t, "value", second)
	assert.Equal(t, 1, calls)
	assert.Equal(t, uint64(1), cache.Hits())
	assert.Equal(t, uint64(1), cache.Misses())
}

func TestCacheDoesNotStoreErrors(t *testing.T) {
	cache := New[string]()
	wantErr := errors.New("transient")
	var calls int

	_, err := cache.GetOrDo("key", func() (string, error) {
		calls++
		return "", wantErr
	})
	require.ErrorIs(t, err, wantErr)
	value, err := cache.GetOrDo("key", func() (string, error) {
		calls++
		return "value", nil
	})
	require.NoError(t, err)

	assert.Equal(t, "value", value)
	assert.Equal(t, 2, calls)
	assert.Zero(t, cache.Hits())
	assert.Equal(t, uint64(2), cache.Misses())
}

func TestCacheStorePolicyRejectsValues(t *testing.T) {
	cache := NewWithStorePolicy(func(value int) bool { return value > 0 })
	var calls int

	first, err := cache.GetOrDo("key", func() (int, error) {
		calls++
		return 0, nil
	})
	require.NoError(t, err)
	second, err := cache.GetOrDo("key", func() (int, error) {
		calls++
		return 1, nil
	})
	require.NoError(t, err)
	third, err := cache.GetOrDo("key", func() (int, error) {
		calls++
		return 2, nil
	})
	require.NoError(t, err)

	assert.Zero(t, first)
	assert.Equal(t, 1, second)
	assert.Equal(t, 1, third)
	assert.Equal(t, 2, calls)
	assert.Equal(t, uint64(1), cache.Hits())
	assert.Equal(t, uint64(2), cache.Misses())
}

func TestCacheCoalescesConcurrentMisses(t *testing.T) {
	cache := New[int]()
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64

	const callers = 32
	results := make(chan int, callers)
	errors := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			value, err := cache.GetOrDo("key", func() (int, error) {
				if calls.Add(1) == 1 {
					close(started)
				}
				<-release
				return 42, nil
			})
			results <- value
			errors <- err
		}()
	}

	<-started
	close(release)
	wg.Wait()
	close(results)
	close(errors)

	for err := range errors {
		require.NoError(t, err)
	}
	for value := range results {
		assert.Equal(t, 42, value)
	}
	assert.Equal(t, int64(1), calls.Load())
	assert.Equal(t, uint64(1), cache.Misses())
}
