package sources

import (
	"path/filepath"
	"strings"
)

// ShouldScanPath reports whether a file path should be scanned. Exclude is
// checked first. When include is non-empty, the path must match at least one
// include pattern.
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

// ShouldWalkDir reports whether a directory should be entered during a walk.
// Unlike ShouldScanPath, a directory that does not itself match an include
// pattern is still walked when it is an ancestor of a matching path (e.g. "."
// with include "src/**").
func ShouldWalkDir(path string, include, exclude []string) bool {
	path = filepath.ToSlash(filepath.Clean(path))
	if pathMatchesAnyGlob(path, exclude) {
		return false
	}
	if len(include) == 0 {
		return true
	}
	if pathMatchesAnyGlob(path, include) {
		return true
	}
	return isAncestorOfAnyInclude(path, include)
}

// pathMatchesAnyGlob reports whether path matches any glob pattern.
// Patterns use filepath.Match syntax against the full path. A trailing "/" or
// "/**" matches that directory and all descendants.
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
	}
	return false
}

// isAncestorOfAnyInclude reports whether path is a parent (or walk root) of a
// path that could match one of the include patterns.
func isAncestorOfAnyInclude(path string, includes []string) bool {
	if path == "." {
		path = ""
	}
	for _, pattern := range includes {
		pattern = filepath.ToSlash(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		for _, prefix := range includePathPrefixes(pattern) {
			if prefix == "" {
				// Pattern has no directory anchor (e.g. "*.go"); walk full tree.
				return true
			}
			if path == "" {
				return true
			}
			if prefix == path || strings.HasPrefix(prefix, path+"/") {
				return true
			}
		}
	}
	return false
}

// includePathPrefixes returns directory prefixes that must be traversed to
// reach paths matched by pattern.
func includePathPrefixes(pattern string) []string {
	if strings.HasSuffix(pattern, "/**") {
		return []string{strings.TrimSuffix(pattern, "/**")}
	}
	if strings.HasSuffix(pattern, "/") {
		return []string{strings.TrimSuffix(pattern, "/")}
	}
	if idx := strings.LastIndex(pattern, "/"); idx >= 0 {
		return []string{pattern[:idx]}
	}
	return []string{""}
}
