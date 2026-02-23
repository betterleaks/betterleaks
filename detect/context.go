package detect

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
