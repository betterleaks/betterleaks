package scan

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/logging"
)

// FingerprintMatcher represents a parsed ignore entry that can match against findings.
// Zero-value fields are wildcards (match anything).
type FingerprintMatcher struct {
	Source       string            // "" = wildcard
	ResourceKind string            // "" = wildcard
	IdentityKVs  map[string]string // subset match: all specified KVs must be present
	RuleID       string            // "" = wildcard
	SecretHash   string            // "" = wildcard
	StartLine    int               // 0 = wildcard
	EndLine      int               // 0 = wildcard
	StartColumn  int               // 0 = wildcard
	EndColumn    int               // 0 = wildcard

	// hasLines/hasColumns distinguishes "not specified" from "line 0"
	hasLines   bool
	hasColumns bool
}

// IgnoreSet holds parsed ignore entries organized for fast lookup.
type IgnoreSet struct {
	// Tier 1: exact full-fingerprint match — O(1)
	exact map[string]struct{}

	// Tier 2: indexed by the most selective field for fast bucket lookup
	bySecretHash map[string][]int // indexes into matchers slice
	byRuleID     map[string][]int // indexes into matchers slice

	// Tier 3: matchers with no indexable field (broadest wildcards)
	unindexed []FingerprintMatcher

	// All wildcard matchers (referenced by tier 2 indexes)
	matchers []FingerprintMatcher
}

// NewIgnoreSet creates a new IgnoreSet.
func NewIgnoreSet() *IgnoreSet {
	return &IgnoreSet{
		exact:        make(map[string]struct{}),
		bySecretHash: make(map[string][]int),
		byRuleID:     make(map[string][]int),
	}
}

// Add parses and adds an ignore entry to the set.
func (s *IgnoreSet) Add(entry string) {
	m, isExact := ParseIgnoreEntry(entry)
	if m == nil {
		return // invalid entry, skip
	}

	if isExact {
		// Tier 1: store exact fingerprint in exact map
		s.exact[entry] = struct{}{}
		return
	}

	idx := len(s.matchers)
	s.matchers = append(s.matchers, *m)

	// Tier 2: index by the most selective non-wildcard field
	if m.SecretHash != "" {
		s.bySecretHash[m.SecretHash] = append(s.bySecretHash[m.SecretHash], idx)
	} else if m.RuleID != "" {
		s.byRuleID[m.RuleID] = append(s.byRuleID[m.RuleID], idx)
	} else {
		// Tier 3: no indexable field
		s.unindexed = append(s.unindexed, *m)
	}
}

// matchContext holds pre-extracted data from a finding for matching.
// Avoids per-matcher allocations.
type matchContext struct {
	source       string
	resourceKind string
	resource     *betterleaks.Resource
	ruleID       string
	secretHash   string
	startLine    int
	endLine      int
	startColumn  int
	endColumn    int
}

func matchContextFromFinding(f *betterleaks.Finding) matchContext {
	r := f.Fragment.Resource

	// Extract secret hash from the already-computed fingerprint rather than
	// recomputing XXH3. The hash is in segment 4 (0-indexed), terminated
	// by '#' (format: hash#L#C).
	var secretHash string
	if fp := f.Fingerprint; fp != "" {
		count := 0
		for i := 0; i < len(fp); i++ {
			if fp[i] == '!' {
				count++
				if count == 4 {
					start := i + 1
					end := len(fp)
					for j := start; j < len(fp); j++ {
						if fp[j] == '#' {
							end = j
							break
						}
					}
					secretHash = fp[start:end]
					break
				}
			}
		}
	}

	return matchContext{
		source:       r.Source,
		resourceKind: string(r.Kind),
		resource:     r,
		ruleID:       f.RuleID,
		secretHash:   secretHash,
		startLine:    f.StartLine,
		endLine:      f.EndLine,
		startColumn:  f.StartColumn,
		endColumn:    f.EndColumn,
	}
}

// IsIgnored checks if a finding should be ignored based on the ignore set.
func (s *IgnoreSet) IsIgnored(f *betterleaks.Finding) bool {
	// Tier 1: exact fingerprint match
	if _, ok := s.exact[f.Fingerprint]; ok {
		return true
	}

	// No wildcard matchers? Done.
	if len(s.matchers) == 0 && len(s.unindexed) == 0 {
		return false
	}

	// Build match context once for all matchers
	ctx := matchContextFromFinding(f)

	// Tier 2: indexed lookup by secret hash
	for _, idx := range s.bySecretHash[ctx.secretHash] {
		if s.matchers[idx].Matches(&ctx) {
			return true
		}
	}

	// Tier 2: indexed lookup by rule ID
	for _, idx := range s.byRuleID[ctx.ruleID] {
		if s.matchers[idx].Matches(&ctx) {
			return true
		}
	}

	// Tier 3: unindexed (broadest matchers)
	for i := range s.unindexed {
		if s.unindexed[i].Matches(&ctx) {
			return true
		}
	}

	return false
}

// Matches checks if this matcher matches the given context.
// Order comparisons from cheapest/most-selective to most-expensive.
func (m *FingerprintMatcher) Matches(ctx *matchContext) bool {
	// Cheap string comparisons first — most selective fields
	if m.SecretHash != "" && m.SecretHash != ctx.secretHash {
		return false
	}
	if m.RuleID != "" && m.RuleID != ctx.ruleID {
		return false
	}
	if m.Source != "" && m.Source != ctx.source {
		return false
	}
	if m.ResourceKind != "" && m.ResourceKind != ctx.resourceKind {
		return false
	}

	// Int comparisons for location
	if m.hasLines {
		if m.StartLine != ctx.startLine || m.EndLine != ctx.endLine {
			return false
		}
	}
	if m.hasColumns {
		if m.StartColumn != ctx.startColumn || m.EndColumn != ctx.endColumn {
			return false
		}
	}

	// Most expensive: subset match on identity KVs
	// All KVs in the matcher must be present in the resource's metadata.
	for k, v := range m.IdentityKVs {
		if ctx.resource.Metadata[k] != v {
			return false
		}
	}

	return true
}

// ParseIgnoreEntry parses a single ignore file line into a FingerprintMatcher.
// Returns (matcher, isExact). isExact=true means no wildcards — can go in the exact map.
// Returns (nil, false) for invalid entries.
func ParseIgnoreEntry(line string) (*FingerprintMatcher, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, false
	}

	// Detect legacy colon-delimited format (no '!' present)
	if !strings.Contains(line, "!") {
		return parseLegacyIgnoreEntry(line)
	}

	parts := strings.Split(line, "!")

	m := &FingerprintMatcher{}
	isExact := true

	// Pad to at least 5 segments (source, kind, identity, rule, hash+loc).
	for len(parts) < 5 {
		parts = append(parts, "*")
	}

	// Segment 0: source
	if parts[0] != "*" {
		m.Source = parts[0]
	} else {
		isExact = false
	}

	// Segment 1: resource_kind
	if parts[1] != "*" {
		m.ResourceKind = parts[1]
	} else {
		isExact = false
	}

	// Segment 2: identity KVs
	if parts[2] != "*" {
		m.IdentityKVs = parseIdentityKVs(parts[2])
	} else {
		isExact = false
	}

	// Segment 3: rule_id
	if parts[3] != "*" {
		m.RuleID = parts[3]
	} else {
		isExact = false
	}

	// Segment 4: "hash#L{s}-{e}#C{s}-{e}" — secret hash and location
	// bundled in one segment with # delimiters.
	if parts[4] == "*" {
		isExact = false
	} else {
		sub := strings.Split(parts[4], "#")
		if sub[0] != "*" {
			m.SecretHash = sub[0]
		} else {
			isExact = false
		}
		if len(sub) > 1 {
			start, end, ok := parseRange(sub[1], 'L')
			if ok {
				m.StartLine = start
				m.EndLine = end
				m.hasLines = true
			}
		} else {
			isExact = false
		}
		if len(sub) > 2 {
			start, end, ok := parseRange(sub[2], 'C')
			if ok {
				m.StartColumn = start
				m.EndColumn = end
				m.hasColumns = true
			}
		} else {
			isExact = false
		}
	}

	return m, isExact
}

// parseIdentityKVs parses "key=value,key=value" into a map.
func parseIdentityKVs(s string) map[string]string {
	kvs := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if ok {
			kvs[k] = v
		}
	}
	return kvs
}

// parseRange parses "L42-42" or "C5-25" into (start, end, ok).
// prefix is 'L' or 'C'.
func parseRange(s string, prefix byte) (int, int, bool) {
	if len(s) == 0 || s[0] != prefix {
		return 0, 0, false
	}
	parts := strings.SplitN(s[1:], "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	start, err1 := strconv.Atoi(parts[0])
	end, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return start, end, true
}

// parseLegacyIgnoreEntry translates old colon-delimited gitleaks format.
// 3-part: path:rule:line → global (any source, any commit)
// 4-part: commit:path:rule:line → git-specific
func parseLegacyIgnoreEntry(line string) (*FingerprintMatcher, bool) {
	// Normalize path separators
	replacer := strings.NewReplacer("\\", "/")
	parts := strings.Split(line, ":")

	switch len(parts) {
	case 3:
		// path:rule:line — global fingerprint
		path := replacer.Replace(parts[0])
		ruleID := parts[1]
		lineNum, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, false
		}
		return &FingerprintMatcher{
			IdentityKVs: map[string]string{"path": path},
			RuleID:      ruleID,
			StartLine:   lineNum,
			EndLine:     lineNum,
			hasLines:    true,
		}, false // not exact (no source, no secret hash, no columns)

	case 4:
		// commit:path:rule:line — commit-specific fingerprint
		commit := parts[0]
		path := replacer.Replace(parts[1])
		ruleID := parts[2]
		lineNum, err := strconv.Atoi(parts[3])
		if err != nil {
			return nil, false
		}
		return &FingerprintMatcher{
			Source:      "git",
			IdentityKVs: map[string]string{"commit_sha": commit, "path": path},
			RuleID:      ruleID,
			StartLine:   lineNum,
			EndLine:     lineNum,
			hasLines:    true,
		}, false

	default:
		return nil, false
	}
}

// LoadIgnoreFile loads a .gitleaksignore or .betterleaksignore file into an IgnoreSet.
func LoadIgnoreFile(path string, set *IgnoreSet) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		set.Add(scanner.Text())
	}
	return scanner.Err()
}

// LoadIgnoreFiles loads ignore files from multiple paths and merges them into an IgnoreSet.
// It checks for .betterleaksignore first, then .gitleaksignore for each path.
func LoadIgnoreFiles(ignorePath string, sourcePath string) *IgnoreSet {
	set := NewIgnoreSet()

	tryLoad := func(path string) {
		if _, err := os.Stat(path); err == nil {
			logging.Debug().Str("path", path).Msg("loading ignore file")
			if err := LoadIgnoreFile(path, set); err != nil {
				logging.Warn().Err(err).Str("path", path).Msg("failed to load ignore file")
			}
		}
	}

	if info, err := os.Stat(ignorePath); err == nil && !info.IsDir() {
		tryLoad(ignorePath)
	}

	tryLoad(filepath.Join(ignorePath, ".betterleaksignore"))
	tryLoad(filepath.Join(ignorePath, ".gitleaksignore"))

	if sourcePath != ignorePath {
		tryLoad(filepath.Join(sourcePath, ".betterleaksignore"))
		tryLoad(filepath.Join(sourcePath, ".gitleaksignore"))
	}

	return set
}
