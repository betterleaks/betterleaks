package cmd

import (
	"fmt"
	"sort"
	"strings"
)

// knownExperiments is the set of recognized values for the --experiments flag.
//
// Experimental features are opt-in and may change or be removed without notice.
// When a new experimental feature is introduced, add its key here so that
// --experiments can recognize (and gate on) it.
var knownExperiments = map[string]struct{}{
	// (no experimental features are currently available)
}

// parseExperiments splits a comma-separated --experiments value and validates
// each entry against knownExperiments. Surrounding whitespace and empty entries
// are ignored. It returns the set of enabled experiments, or an error naming
// every unrecognized value so that typos fail fast instead of being silently
// ignored.
func parseExperiments(raw string) (map[string]struct{}, error) {
	enabled := make(map[string]struct{})
	var unknown []string

	for _, part := range strings.Split(raw, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if _, ok := knownExperiments[name]; !ok {
			unknown = append(unknown, name)
			continue
		}
		enabled[name] = struct{}{}
	}

	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown --experiments value(s): %s%s",
			strings.Join(unknown, ", "), experimentsHint())
	}
	return enabled, nil
}

// experimentsHint returns a human-friendly suffix listing the valid experiment
// values, or a note that none are currently available.
func experimentsHint() string {
	if len(knownExperiments) == 0 {
		return " (no experimental features are currently available)"
	}
	names := make([]string, 0, len(knownExperiments))
	for name := range knownExperiments {
		names = append(names, name)
	}
	sort.Strings(names)
	return " (valid values: " + strings.Join(names, ", ") + ")"
}
