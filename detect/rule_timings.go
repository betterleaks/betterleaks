package detect

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
	"sync"
	"time"
)

type RuleTiming struct {
	RuleID string
	Total  time.Duration
	Hits   uint64
}

func (rt RuleTiming) Average() time.Duration {
	if rt.Hits == 0 {
		return 0
	}
	return rt.Total / time.Duration(rt.Hits)
}

type RuleTimingCollector struct {
	mu      sync.Mutex
	timings map[string]RuleTiming
}

func NewRuleTimingCollector() *RuleTimingCollector {
	return &RuleTimingCollector{
		timings: make(map[string]RuleTiming),
	}
}

func (c *RuleTimingCollector) Record(ruleID string, duration time.Duration) {
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

func (c *RuleTimingCollector) Snapshot() []RuleTiming {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	timings := make([]RuleTiming, 0, len(c.timings))
	for _, timing := range c.timings {
		timings = append(timings, timing)
	}
	SortRuleTimings(timings)
	return timings
}

func SortRuleTimings(timings []RuleTiming) {
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

func WriteRuleTimingsCSV(w io.Writer, timings []RuleTiming) error {
	timings = sortedRuleTimings(timings)
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"rule_id",
		"total_duration_ns",
		"total_duration",
		"hits",
		"avg_duration_ns",
		"avg_duration",
	}); err != nil {
		return err
	}

	for _, timing := range timings {
		avg := timing.Average()
		if err := cw.Write([]string{
			timing.RuleID,
			strconv.FormatInt(int64(timing.Total), 10),
			timing.Total.String(),
			strconv.FormatUint(timing.Hits, 10),
			strconv.FormatInt(int64(avg), 10),
			avg.String(),
		}); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

func WriteRuleTimingsHuman(w io.Writer, timings []RuleTiming) error {
	timings = sortedRuleTimings(timings)
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

func sortedRuleTimings(timings []RuleTiming) []RuleTiming {
	sorted := append([]RuleTiming(nil), timings...)
	SortRuleTimings(sorted)
	return sorted
}
