package detect

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseMatchContext parses a --match-context value (number of bytes).
func ParseMatchContext(spec string) (int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, nil
	}

	bytes, err := strconv.Atoi(spec)
	if err != nil {
		return 0, fmt.Errorf("invalid match-context value: %q (expected a number of bytes)", spec)
	}
	if bytes < 0 {
		return 0, fmt.Errorf("match-context must be non-negative")
	}

	return bytes, nil
}

// extractContext extracts bytes before and after the match from the fragment raw content.
// matchIndex is the [start, end) byte range of the match within raw.
func extractContext(raw string, matchIndex []int, matchContextBytes int) string {
	if matchContextBytes <= 0 || len(raw) == 0 {
		return ""
	}

	start := matchIndex[0] - matchContextBytes
	if start < 0 {
		start = 0
	}
	end := matchIndex[1] + matchContextBytes
	if end > len(raw) {
		end = len(raw)
	}

	return raw[start:end]
}
