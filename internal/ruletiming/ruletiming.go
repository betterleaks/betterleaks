package ruletiming

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// Timing is the aggregate execution time for one rule.
type Timing struct {
	RuleID string
	Total  time.Duration
	Hits   uint64
}

func (t Timing) Average() time.Duration {
	if t.Hits == 0 {
		return 0
	}
	return t.Total / time.Duration(t.Hits)
}

// Collector safely aggregates timings from concurrent detector workers.
type Collector struct {
	mu      sync.Mutex
	timings map[string]Timing
}

func NewCollector() *Collector {
	return &Collector{timings: make(map[string]Timing)}
}

func (c *Collector) Record(ruleID string, duration time.Duration) {
	if c == nil || ruleID == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	timing := c.timings[ruleID]
	timing.RuleID = ruleID
	timing.Total += duration
	timing.Hits++
	c.timings[ruleID] = timing
}

func (c *Collector) Snapshot() []Timing {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	timings := make([]Timing, 0, len(c.timings))
	for _, timing := range c.timings {
		timings = append(timings, timing)
	}
	sortTimings(timings)
	return timings
}

func WriteHuman(w io.Writer, timings []Timing) error {
	timings = append([]Timing(nil), timings...)
	sortTimings(timings)

	ruleIDWidth := len("Rule ID")
	for _, timing := range timings {
		if len(timing.RuleID) > ruleIDWidth {
			ruleIDWidth = len(timing.RuleID)
		}
	}

	if _, err := fmt.Fprintf(w, "Rule Timings\n\nRules timed: %d\n\n", len(timings)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%-*s  %14s  %8s  %14s\n", ruleIDWidth, "Rule ID", "Total", "Hits", "Average"); err != nil {
		return err
	}
	for _, timing := range timings {
		if _, err := fmt.Fprintf(w, "%-*s  %14s  %8d  %14s\n",
			ruleIDWidth,
			timing.RuleID,
			timing.Total.String(),
			timing.Hits,
			timing.Average().String(),
		); err != nil {
			return err
		}
	}
	return nil
}

func sortTimings(timings []Timing) {
	sort.SliceStable(timings, func(i, j int) bool {
		if timings[i].Total != timings[j].Total {
			return timings[i].Total > timings[j].Total
		}
		if timings[i].Hits != timings[j].Hits {
			return timings[i].Hits > timings[j].Hits
		}
		return timings[i].RuleID < timings[j].RuleID
	})
}

type collectorContextKey struct{}

// WithCollector attaches scan-scoped rule timing diagnostics to ctx.
func WithCollector(ctx context.Context, collector *Collector) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if collector == nil {
		return ctx
	}
	return context.WithValue(ctx, collectorContextKey{}, collector)
}

// FromContext returns the rule timing collector attached to ctx, if any.
func FromContext(ctx context.Context) *Collector {
	if ctx == nil {
		return nil
	}
	collector, _ := ctx.Value(collectorContextKey{}).(*Collector)
	return collector
}
