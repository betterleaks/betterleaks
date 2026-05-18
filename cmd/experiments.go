package cmd

import (
	"fmt"
	"sort"
	"strings"
)

// validExperiments is the set of values --experiments will accept.
// Add new entries here as experimental features land.
var validExperiments = map[string]struct{}{}

// validateExperiments returns an error if s contains any comma-separated
// tokens that aren't in validExperiments. Empty entries (e.g. from trailing
// or doubled commas) are ignored so users can build the list incrementally.
func validateExperiments(s string) error {
	if s == "" {
		return nil
	}
	var unknown []string
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, ok := validExperiments[e]; !ok {
			unknown = append(unknown, e)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("unknown --experiments value(s): %s", strings.Join(unknown, ", "))
}
