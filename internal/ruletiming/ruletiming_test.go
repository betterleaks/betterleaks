package ruletiming

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectorConcurrentRecord(t *testing.T) {
	collector := NewCollector()
	const (
		workers = 8
		records = 100
	)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range records {
				collector.Record("test-rule", time.Nanosecond)
			}
		}()
	}
	wg.Wait()

	timings := collector.Snapshot()
	require.Len(t, timings, 1)
	assert.Equal(t, uint64(workers*records), timings[0].Hits)
	assert.Equal(t, time.Duration(workers*records)*time.Nanosecond, timings[0].Total)
}

func TestSnapshotSortsRuleTimings(t *testing.T) {
	collector := NewCollector()
	collector.Record("charlie", 2*time.Second)
	collector.Record("bravo", time.Second)
	collector.Record("bravo", time.Second)
	collector.Record("alpha", 2*time.Second)

	timings := collector.Snapshot()
	require.Len(t, timings, 3)
	assert.Equal(t, []string{"bravo", "alpha", "charlie"}, []string{
		timings[0].RuleID,
		timings[1].RuleID,
		timings[2].RuleID,
	})
	assert.Equal(t, time.Second, timings[0].Average())
}

func TestWriteHuman(t *testing.T) {
	timings := []Timing{
		{RuleID: "fast", Total: time.Second, Hits: 2},
		{RuleID: "slow-rule", Total: 3 * time.Second, Hits: 3},
	}
	var output strings.Builder

	require.NoError(t, WriteHuman(&output, timings))
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	require.Len(t, lines, 7)
	assert.Equal(t, "Rule Timings", lines[0])
	assert.Equal(t, "Rules timed: 2", lines[2])
	assert.Contains(t, lines[4], "Rule ID")
	assert.Contains(t, lines[4], "Average")
	assert.Contains(t, lines[5], "slow-rule")
	assert.Contains(t, lines[5], "3s")
	assert.Contains(t, lines[6], "fast")
	assert.Contains(t, lines[6], "500ms")

	// Rendering sorts a copy rather than changing the caller's diagnostic data.
	assert.Equal(t, "fast", timings[0].RuleID)
}

func TestCollectorContext(t *testing.T) {
	collector := NewCollector()
	ctx := WithCollector(t.Context(), collector)
	assert.Same(t, collector, FromContext(ctx))
	assert.Nil(t, FromContext(t.Context()))
}
