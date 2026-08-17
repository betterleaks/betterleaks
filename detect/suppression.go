package detect

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

// Suppression combines the ignore-file fingerprint set and baseline findings
// so the replay engine can apply them without instantiating a Detector.
type Suppression struct {
	Ignore   map[string]struct{}
	Baseline []report.Finding
	Redact   uint
}

// NewSuppression creates an empty Suppression ready for use.
func NewSuppression() *Suppression {
	return &Suppression{Ignore: make(map[string]struct{})}
}

// AddIgnoreFile loads a .betterleaksignore / .gitleaksignore file and merges its entries.
func (s *Suppression) AddIgnoreFile(path string) error {
	entries, err := LoadIgnoreFile(path)
	if err != nil {
		return err
	}
	for k := range entries {
		s.Ignore[k] = struct{}{}
	}
	return nil
}

// LoadIgnoreFile parses .betterleaksignore / .gitleaksignore entries into a fingerprint set.
func LoadIgnoreFile(path string) (map[string]struct{}, error) {
	logging.Debug().Str("path", path).Msgf("found .gitleaksignore file")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			logging.Warn().Err(err).Msgf("Error closing .gitleaksignore file")
		}
	}()

	entries := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	replacer := strings.NewReplacer("\\", "/")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Normalize the path.
		// TODO: Make this a breaking change in v9.
		s := strings.Split(line, ":")
		switch len(s) {
		case 3:
			// Global fingerprint: file:rule-id:start-line
			s[0] = replacer.Replace(s[0])
		case 4:
			// Commit fingerprint: commit:file:rule-id:start-line
			s[1] = replacer.Replace(s[1])
		default:
			logging.Warn().Str("fingerprint", line).Msg("Invalid .gitleaksignore entry")
		}
		entries[strings.Join(s, ":")] = struct{}{}
	}
	return entries, nil
}

// Suppressed reports whether a finding matches the ignore set or the baseline.
func (s *Suppression) Suppressed(f report.Finding) bool {
	logger := logging.With().Str("finding", f.Secret).Logger()
	path := f.Attributes[sources.AttrPath]
	globalFingerprint := fmt.Sprintf("%s:%s:%d", path, f.RuleID, f.StartLine)

	if _, ok := s.Ignore[globalFingerprint]; ok {
		logger.Debug().
			Str("fingerprint", f.Fingerprint).
			Msg("skipping finding: global fingerprint")
		return true
	}
	if _, ok := s.Ignore[f.Fingerprint]; ok {
		logger.Debug().
			Str("fingerprint", f.Fingerprint).
			Msg("skipping finding: fingerprint")
		return true
	}
	if s.Baseline != nil && !IsNew(f, s.Redact, s.Baseline) {
		logger.Debug().
			Str("fingerprint", f.Fingerprint).
			Msg("skipping finding: baseline")
		return true
	}
	return false
}
