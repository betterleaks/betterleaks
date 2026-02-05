package scan

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/betterleaks/betterleaks/logging"
)

// LoadIgnoreFile loads a .gitleaksignore or .betterleaksignore file and returns
// a map of fingerprints to ignore. The file format supports:
// - Comments starting with #
// - Blank lines (ignored)
// - Global fingerprints: file:rule-id:start-line
// - Commit fingerprints: commit:file:rule-id:start-line
func LoadIgnoreFile(path string) (map[string]struct{}, error) {
	ignore := make(map[string]struct{})

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	replacer := strings.NewReplacer("\\", "/")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Normalize the path separators
		s := strings.Split(line, ":")
		switch len(s) {
		case 3:
			// Global fingerprint: file:rule-id:start-line
			s[0] = replacer.Replace(s[0])
		case 4:
			// Commit fingerprint: commit:file:rule-id:start-line
			s[1] = replacer.Replace(s[1])
		default:
			logging.Warn().Str("fingerprint", line).Msg("Invalid ignore file entry")
			continue
		}
		ignore[strings.Join(s, ":")] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ignore, nil
}

// LoadIgnoreFiles loads ignore files from multiple paths and merges them.
// It checks for .betterleaksignore first, then .gitleaksignore for each path.
func LoadIgnoreFiles(ignorePath string, sourcePath string) map[string]struct{} {
	ignore := make(map[string]struct{})

	// Helper to try loading an ignore file
	tryLoad := func(path string) {
		if _, err := os.Stat(path); err == nil {
			logging.Debug().Str("path", path).Msg("loading ignore file")
			if loaded, err := LoadIgnoreFile(path); err == nil {
				for k, v := range loaded {
					ignore[k] = v
				}
			} else {
				logging.Warn().Err(err).Str("path", path).Msg("failed to load ignore file")
			}
		}
	}

	// Check explicit path if it's a file
	if info, err := os.Stat(ignorePath); err == nil && !info.IsDir() {
		tryLoad(ignorePath)
	}

	// Check for ignore files in ignorePath directory
	tryLoad(filepath.Join(ignorePath, ".betterleaksignore"))
	tryLoad(filepath.Join(ignorePath, ".gitleaksignore"))

	// Check for ignore files in source directory (if different from ignorePath)
	if sourcePath != ignorePath {
		tryLoad(filepath.Join(sourcePath, ".betterleaksignore"))
		tryLoad(filepath.Join(sourcePath, ".gitleaksignore"))
	}

	return ignore
}
