package scan

import (
	"context"
	"fmt"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/scan/codec"
	"github.com/fatih/semgroup"
	"golang.org/x/exp/maps"
)

type Scanner struct {
	Config *config.Config

	// MaxDecodeDepths limits how many recursive decoding passes are allowed
	MaxDecodeDepth int

	// Maybe here? IgnoreGitleaksAllow is a flag to ignore gitleaks:allow comments.
	IgnoreGitleaksAllow bool

	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter ahocorasick.Trie

	// gitleaksIgnore
	gitleaksIgnore map[string]struct{}

	// Sema (https://github.com/fatih/semgroup) controls the concurrency
	Sema *semgroup.Group

	// TotalBytes atomic.Uint64
}

func NewScanner(ctx context.Context, cfg *config.Config, maxDecodeDepth int, ignoreGitleaksAllow bool, concurrency int) *Scanner {
	return &Scanner{
		Config:         cfg,
		prefilter:      *ahocorasick.NewTrieBuilder().AddStrings(maps.Keys(cfg.Keywords)).Build(),
		Sema:           semgroup.NewGroup(ctx, int64(concurrency)),
		MaxDecodeDepth: maxDecodeDepth,
		gitleaksIgnore: make(map[string]struct{}),
	}
}

// SetIgnore adds fingerprints from the ignore map to the scanner's ignore list.
func (s *Scanner) SetIgnore(ignore map[string]struct{}) {
	for k, v := range ignore {
		s.gitleaksIgnore[k] = v
	}
}

// IsIgnored checks if a finding should be ignored based on its fingerprint.
// It checks both the full fingerprint and the global fingerprint (without commit).
func (s *Scanner) IsIgnored(finding betterleaks.Finding) bool {
	// Check full fingerprint (commit:file:rule:line for git, or file:rule:line for files)
	if _, ok := s.gitleaksIgnore[finding.Fingerprint]; ok {
		return true
	}
	// For git findings, also check global fingerprint (file:rule:line)
	if finding.Metadata[betterleaks.MetaCommitSHA] != "" {
		globalFingerprint := fmt.Sprintf("%s:%s:%d", finding.Metadata[betterleaks.MetaPath], finding.RuleID, finding.StartLine)
		if _, ok := s.gitleaksIgnore[globalFingerprint]; ok {
			return true
		}
	}
	return false
}

// ScanFragment scans a fragment for secrets and returns any potential finding.
func (s *Scanner) ScanFragment(ctx context.Context, fragment betterleaks.Fragment) ([]betterleaks.Match, error) {
	retMatches := []betterleaks.Match{}

	currentRaw := fragment.Raw
	encodedSegments := []*codec.EncodedSegment{}
	currentDecodeDepth := 0
	decoder := codec.NewDecoder()
ScanLoop:
	for {
		select {
		case <-ctx.Done():
			break ScanLoop
		default:
			// Build set of rules to check based on keyword matches
			rulesToCheck := make(map[string]struct{})
			normalizedRaw := strings.ToLower(currentRaw)
			matches := s.prefilter.MatchString(normalizedRaw)
			for _, m := range matches {
				keyword := normalizedRaw[m.Pos() : int(m.Pos())+len(m.Match())]
				for _, ruleID := range s.Config.KeywordToRules[keyword] {
					rulesToCheck[ruleID] = struct{}{}
				}
			}

			// Always check rules that have no keywords
			for _, ruleID := range s.Config.NoKeywordRules {
				rulesToCheck[ruleID] = struct{}{}
			}

			for ruleID := range rulesToCheck {
				select {
				case <-ctx.Done():
					break ScanLoop
				default:
					rule := s.Config.Rules[ruleID]
					retMatches = append(retMatches, s.scanRule(fragment, currentRaw, rule, encodedSegments)...)
				}
			}

			// increment the depth by 1 as we start our decoding pass
			currentDecodeDepth++

			// stop the loop if we've hit our max decoding depth
			if currentDecodeDepth > s.MaxDecodeDepth {
				break ScanLoop
			}

			// decode the currentRaw for the next pass
			currentRaw, encodedSegments = decoder.Decode(currentRaw, encodedSegments)

			// stop the loop when there's nothing else to decode
			if len(encodedSegments) == 0 {
				break ScanLoop
			}
		}
	}

	return retMatches, nil
}

func (s *Scanner) scanRule(fragment betterleaks.Fragment, currentRaw string, r config.Rule, encodedSegments []*codec.EncodedSegment) []betterleaks.Match {
	var retMatches = []betterleaks.Match{}
	if r.Path != nil {
		if r.Regex == nil && len(encodedSegments) == 0 {
			// Path _only_ rule
			if r.Path.MatchString(fragment.Path) {
				return append(retMatches, betterleaks.Match{
					RuleID:     r.RuleID,
					MatchStart: 0,
					MatchEnd:   0,
					NoPattern:  true,
				})
			}
		} else {
			// if path is set _and_ a regex is set, then we need to check both
			// so if the path does not match, then we should return early and not
			// consider the regex
			if !r.Path.MatchString(fragment.Path) {
				return retMatches
			}
		}
	}

	// if path only rule, skip content checks
	if r.Regex == nil {
		return retMatches
	}

	matches := r.Regex.FindAllStringIndex(currentRaw, -1)
	if len(matches) == 0 {
		return retMatches
	}

	for _, m := range matches {
		rawMatched := strings.Trim(currentRaw[m[0]:m[1]], "\n")
		var metaTags []string
		currentLine := ""
		rawLine := ""

		// Check if the decoded portions of the segment overlap with the match
		// to see if its potentially a new match
		if len(encodedSegments) > 0 {
			segments := codec.SegmentsWithDecodedOverlap(encodedSegments, m[0], m[1])
			if len(segments) == 0 {
				// This item has already been added to a finding
				continue
			}

			m = codec.AdjustMatchIndex(segments, m)
			metaTags = append(metaTags, codec.Tags(segments)...)
			currentLine = codec.CurrentLine(segments, currentRaw)

			// Calculate raw matched line from the original (non-decoded) content
			// using the adjusted match indices. This is used for allow tag checking.
			rawLine = extractLine(fragment.Raw, m[0], m[1])
		} else {
			// Fixes: https://github.com/gitleaks/gitleaks/issues/1352
			// removes the incorrectly following line that was detected by regex expression '\n'
			m[1] = m[0] + len(rawMatched)

			// Extract the line containing the match from the raw content
			rawLine = extractLine(fragment.Raw, m[0], m[1])
			currentLine = rawLine
		}

		retMatches = append(retMatches, betterleaks.Match{
			RuleID:          r.RuleID,
			MatchStart:      m[0],
			MatchEnd:        m[1],
			MatchString:     rawMatched,
			MetaTags:        metaTags,
			RawLine:         rawLine,
			FullDecodedLine: currentLine,
		})
	}

	return retMatches
}

// extractLine extracts the line containing the match from start to end indices.
// It finds the newline boundaries around the match and returns the full line.
func extractLine(raw string, start, end int) string {
	if len(raw) == 0 {
		return ""
	}

	// Clamp indices to valid range
	if start < 0 {
		start = 0
	}
	if end > len(raw) {
		end = len(raw)
	}

	// Find the start of the line (search backwards for newline)
	lineStart := start
	for i := start - 1; i >= 0; i-- {
		if raw[i] == '\n' {
			lineStart = i + 1
			break
		}
		lineStart = i
	}

	// Find the end of the line (search forwards for newline)
	lineEnd := end
	for i := end; i < len(raw); i++ {
		if raw[i] == '\n' {
			lineEnd = i
			break
		}
		lineEnd = i + 1
	}

	return raw[lineStart:lineEnd]
}
