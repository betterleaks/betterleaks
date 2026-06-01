package sources

import (
	"path/filepath"
	"strings"
)

// ShouldScanPath reports whether path should be scanned given optional include
// and exclude glob patterns. Exclude is checked first. When include is
// non-empty, the path must match at least one include pattern.
func ShouldScanPath(path string, include, exclude []string) bool {
	path = filepath.ToSlash(path)
	if pathMatchesAnyGlob(path, exclude) {
		return false
	}
	if len(include) > 0 && !pathMatchesAnyGlob(path, include) {
		return false
	}
	return true
}

// pathMatchesAnyGlob reports whether path matches any glob pattern.
// Patterns use filepath.Match syntax. A trailing "/" or "/**" matches that
// directory and all descendants.
func pathMatchesAnyGlob(path string, globs []string) bool {
	if len(globs) == 0 {
		return false
	}
	for _, pattern := range globs {
		pattern = filepath.ToSlash(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, "/**") {
			prefix := strings.TrimSuffix(pattern, "/**")
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				return true
			}
			continue
		}
		if strings.HasSuffix(pattern, "/") {
			prefix := strings.TrimSuffix(pattern, "/")
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				return true
			}
			continue
		}
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
	}
	return false
}
