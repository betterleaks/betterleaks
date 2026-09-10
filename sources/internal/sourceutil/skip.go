package sourceutil

// ShouldSkipAttrs evaluates the skip callback against attrs.
// Returns true if the fragment should be skipped.
// If no callback is set (nil), nothing is skipped.
func ShouldSkipAttrs(skip func(map[string]string) bool, attrs map[string]string) bool {
	if skip == nil {
		return false
	}
	return skip(attrs)
}
