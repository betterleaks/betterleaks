package detect

import (
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/ahocorasick"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	regexpre2 "github.com/betterleaks/betterleaks/regexp/re2"
)

func spanPlan(t *testing.T, pattern string, keywords ...string) (ruleMatchSpanPlan, bool) {
	t.Helper()
	return analyzeRuleMatchSpans(config.Rule{
		Regex:    blregexp.MustCompile(pattern),
		Keywords: keywords,
	})
}

func TestAnalyzeRuleMatchSpan(t *testing.T) {
	t.Run("bounded mandatory literal", func(t *testing.T) {
		plan, ok := spanPlan(t, `foo.{0,2}[A-Z]{3}`, "foo")
		require.True(t, ok)
		require.Equal(t, matchSpanPlan{beforeBytes: 3, afterBytes: 11, beforeBounded: true, afterBounded: true, valid: true}, plan.keywords["foo"])
	})

	t.Run("covered alternatives", func(t *testing.T) {
		plan, ok := spanPlan(t, `(?:foo.{0,2}x|bar[0-9]{3})`, "foo", "bar")
		require.True(t, ok)
		require.Equal(t, matchSpanPlan{beforeBytes: 3, afterBytes: 9, beforeBounded: true, afterBounded: true, valid: true}, plan.keywords["foo"])
		require.Equal(t, matchSpanPlan{beforeBytes: 3, afterBytes: 3, beforeBounded: true, afterBounded: true, valid: true}, plan.keywords["bar"])
	})

	t.Run("context keyword is not an anchor", func(t *testing.T) {
		plan, ok := spanPlan(t, `foo[0-9]{3}`, "foo", "provider")
		require.True(t, ok)
		require.NotContains(t, plan.keywords, "provider")
	})

	t.Run("bounded repetition", func(t *testing.T) {
		plan, ok := spanPlan(t, `(?:xxfoo){1,3}bar`, "foo")
		require.True(t, ok)
		require.Equal(t, matchSpanPlan{beforeBytes: 15, afterBytes: 13, beforeBounded: true, afterBounded: true, valid: true}, plan.keywords["foo"])
	})

	t.Run("unicode fold width", func(t *testing.T) {
		plan, ok := spanPlan(t, `(?i)key[0-9]`, "key")
		require.True(t, ok)
		require.Equal(t, matchSpanPlan{beforeBytes: 5, afterBytes: 1, beforeBounded: true, afterBounded: true, valid: true}, plan.keywords["key"])
	})

	t.Run("unbounded suffix", func(t *testing.T) {
		plan, ok := spanPlan(t, `foo.*secret`, "foo")
		require.True(t, ok)
		require.Equal(t, matchSpanPlan{beforeBytes: 3, beforeBounded: true, valid: true}, plan.keywords["foo"])
	})

	t.Run("unbounded prefix", func(t *testing.T) {
		plan, ok := spanPlan(t, `.*foo`, "foo")
		require.True(t, ok)
		require.Equal(t, matchSpanPlan{afterBounded: true, valid: true}, plan.keywords["foo"])
	})

	t.Run("unbounded both sides", func(t *testing.T) {
		plan, ok := spanPlan(t, `.*foo.*`, "foo")
		require.True(t, ok)
		require.Equal(t, matchSpanPlan{valid: true}, plan.keywords["foo"])
	})

	t.Run("keyword assembled across alternatives", func(t *testing.T) {
		plan, ok := spanPlan(t, `(?i)(?:a(?:ccess|uth)|api)[=:][a-z]{3}`, "access", "auth", "api")
		require.True(t, ok)
		for _, keyword := range []string{"access", "auth", "api"} {
			keywordPlan := plan.keywords[keyword]
			require.True(t, keywordPlan.valid, keyword)
			require.True(t, keywordPlan.beforeBounded, keyword)
			require.True(t, keywordPlan.afterBounded, keyword)
		}
	})

	t.Run("keyword assembled across optional suffix", func(t *testing.T) {
		plan, ok := spanPlan(t, `(?i)(?:https?|ssh)://[^ ]+`, "http://", "https://", "ssh://")
		require.True(t, ok)
		for _, keyword := range []string{"http://", "https://", "ssh://"} {
			keywordPlan := plan.keywords[keyword]
			require.True(t, keywordPlan.valid, keyword)
			require.True(t, keywordPlan.beforeBounded, keyword)
			require.False(t, keywordPlan.afterBounded, keyword)
		}
	})

	for _, test := range []struct {
		name     string
		pattern  string
		keywords []string
	}{
		{name: "uncovered alternative", pattern: `(?:foo.{0,2}x|quux[0-9]{3})`, keywords: []string{"foo"}},
		{name: "context-only keyword", pattern: `secret_[A-Z]{20}`, keywords: []string{"provider"}},
		{name: "optional keyword", pattern: `(?:foo)?secret`, keywords: []string{"foo"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, ok := spanPlan(t, test.pattern, test.keywords...)
			require.False(t, ok)
		})
	}

	t.Run("anchors are bounded", func(t *testing.T) {
		for _, pattern := range []string{`^foo[0-9]{3}`, `foo[0-9]{3}$`} {
			_, ok := spanPlan(t, pattern, "foo")
			require.True(t, ok)
		}
	})

	t.Run("keywords are canonicalized", func(t *testing.T) {
		plan, ok := spanPlan(t, `(?i)foo[0-9]{3}`, "FOO")
		require.True(t, ok)
		require.True(t, plan.keywords["foo"].valid)
	})
}

func TestDefaultHighTrafficRulesUseMatchSpans(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)

	for _, ruleID := range []string{"generic-api-key", "generic-credential-uri"} {
		rule := cfg.Rules[ruleID]
		plan, ok := analyzeRuleMatchSpans(rule)
		require.True(t, ok, ruleID)
		for _, keyword := range rule.Keywords {
			require.True(t, plan.keywords[strings.ToLower(keyword)].valid, "%s keyword %q", ruleID, keyword)
		}
	}
}

func TestRegexMaxBytesRejectsUnboundedWidths(t *testing.T) {
	for _, pattern := range []string{`a*`, `a+`, `a{1,}`, `(?:ab)*`} {
		parsed, err := syntax.Parse(pattern, syntax.Perl)
		require.NoError(t, err)
		_, bounded := regexMaxBytes(parsed)
		require.False(t, bounded)
	}
}

func TestRegexMaxBytesUsesActualUTF8Widths(t *testing.T) {
	for _, test := range []struct {
		pattern string
		want    int
	}{
		{pattern: `[a-z]`, want: 1},
		{pattern: `(?i)a`, want: 1},
		{pattern: `(?i)s`, want: 2}, // long s
		{pattern: `(?i)k`, want: 3}, // Kelvin sign
		{pattern: `(?i)[a-z]`, want: 3},
		{pattern: `.`, want: 4},
	} {
		parsed, err := syntax.Parse(test.pattern, syntax.Perl)
		require.NoError(t, err)
		got, bounded := regexMaxBytes(parsed)
		require.True(t, bounded)
		require.Equal(t, test.want, got, test.pattern)
	}
}

func TestMatchSpanRegexParity(t *testing.T) {
	defer blregexp.SetEngine(blregexp.Stdlib{})
	for _, engine := range []struct {
		name   string
		engine blregexp.Engine
	}{
		{name: "stdlib", engine: blregexp.Stdlib{}},
		{name: "re2", engine: regexpre2.RE2{}},
	} {
		t.Run(engine.name, func(t *testing.T) {
			blregexp.SetEngine(engine.engine)
			testMatchSpanRegexParity(t)
		})
	}
}

func testMatchSpanRegexParity(t *testing.T) {
	for _, test := range []struct {
		name     string
		pattern  string
		keywords []string
		content  string
	}{
		{
			name:     "separated matches",
			pattern:  `(?i)provider.{0,8}(token_[a-z0-9]{6})(?:;|$)`,
			keywords: []string{"provider"},
			content:  strings.Repeat("x", 512) + " provider = token_abc123;" + strings.Repeat("x", 512) + "provider token_def456; " + strings.Repeat("x", 512),
		},
		{
			name:     "begin text anchor",
			pattern:  `^provider.{0,8}token_[a-z0-9]{6}`,
			keywords: []string{"provider"},
			content:  "provider token_abc123 " + strings.Repeat("x", 512),
		},
		{
			name:     "end text anchor",
			pattern:  `provider.{0,8}token_[a-z0-9]{6}$`,
			keywords: []string{"provider"},
			content:  strings.Repeat("x", 512) + " provider token_abc123",
		},
		{
			name:     "unicode simple fold",
			pattern:  `(?i)key[0-9]{3}`,
			keywords: []string{"key"},
			content:  strings.Repeat("x", 512) + " \u212aEY123 " + strings.Repeat("x", 512),
		},
		{
			name:     "covered alternatives",
			pattern:  `(?:foo.{0,3}[0-9]{3}|bar.{0,2}[a-z]{4})`,
			keywords: []string{"foo", "bar"},
			content:  strings.Repeat("x", 512) + " foo--123 " + strings.Repeat("x", 512) + " bar-zabcd " + strings.Repeat("x", 512),
		},
		{
			name:     "unbounded suffix",
			pattern:  `foo.*secret`,
			keywords: []string{"foo"},
			content:  strings.Repeat("x", 800) + "foo value secret " + strings.Repeat("x", 50),
		},
		{
			name:     "unbounded prefix",
			pattern:  `.*foo`,
			keywords: []string{"foo"},
			content:  "prefix foo " + strings.Repeat("x", 800),
		},
		{
			name:     "assembled alternatives",
			pattern:  `(?i)(?:a(?:ccess|uth)|api)[=:][a-z]{3}`,
			keywords: []string{"access", "auth", "api"},
			content:  strings.Repeat("x", 512) + " ACCESS=abc AUTH:def API=ghi " + strings.Repeat("x", 512),
		},
		{
			name:     "assembled optional suffix",
			pattern:  `(?i)(?:https?|ssh)://[^ ]+`,
			keywords: []string{"http://", "https://", "ssh://"},
			content:  strings.Repeat("x", 800) + " HTTP://first HTTPS://second SSH://third " + strings.Repeat("x", 50),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rule := config.Rule{Regex: blregexp.MustCompile(test.pattern), Keywords: test.keywords}
			plan, ok := analyzeRuleMatchSpans(rule)
			require.True(t, ok)

			candidates := ruleCandidates{matchSpanStates: make([]ruleMatchSpanState, 1)}
			matcher := ahocorasick.Compile(test.keywords, true)
			matcher.VisitEnds(test.content, func(patternID, end int) bool {
				keywordPlan := plan.keywords[strings.ToLower(test.keywords[patternID])]
				if keywordPlan.valid {
					candidates.addMatchSpan(0, end, len(test.content), keywordPlan)
				}
				return true
			})

			require.True(t, candidates.matchSpanWindow(0).active)
			for _, content := range []scanContent{stringScanContent(test.content), byteScanContent([]byte(test.content))} {
				require.Equal(t, content.findAllIndex(rule.Regex), content.findAllIndexSpan(rule.Regex, candidates.matchSpanWindow(0)))
			}
		})
	}
}

func TestFindAllIndexRangeRejectsArtificialBoundaries(t *testing.T) {
	for _, test := range []struct {
		content string
		pattern string
		start   int
		end     int
	}{
		{content: "prefix foo suffix", pattern: `^foo`, start: 7, end: 10},
		{content: "prefix foo suffix", pattern: `foo$`, start: 7, end: 10},
		{content: "prefixfoobar", pattern: `foo\b`, start: 6, end: 9},
		{content: "prefixfoo suffix", pattern: `(?m)^foo`, start: 6, end: 9},
		{content: "prefix foo suffix", pattern: `(?m)foo$`, start: 7, end: 10},
	} {
		for _, content := range []scanContent{stringScanContent(test.content), byteScanContent([]byte(test.content))} {
			require.Empty(t, content.findAllIndexRange(blregexp.MustCompile(test.pattern), test.start, test.end), test.pattern)
		}
	}
}

func TestRuleMatchSpansMergeAndFallBack(t *testing.T) {
	candidates := ruleCandidates{matchSpanStates: make([]ruleMatchSpanState, 1)}
	plan := matchSpanPlan{beforeBytes: 3, afterBytes: 2, beforeBounded: true, afterBounded: true, valid: true}

	candidates.addMatchSpan(0, 11, 100, plan)
	candidates.addMatchSpan(0, 15, 100, plan)
	window := candidates.matchSpanWindow(0)
	require.Equal(t, matchSpan{start: 4, end: 21}, window.span)

	candidates.addMatchSpan(0, 71, 100, matchSpanPlan{beforeBytes: 21, afterBytes: 20, beforeBounded: true, afterBounded: true, valid: true})
	require.Equal(t, matchSpan{start: 4, end: 95}, candidates.matchSpanWindow(0).span)

	candidates.addMatchSpan(0, 50, 100, matchSpanPlan{valid: true})
	require.False(t, candidates.matchSpanWindow(0).active, "a span covering the full fragment uses the ordinary full scan")
	require.True(t, candidates.hasMatchSpan(0))
	candidates.resetMatchSpans()
	require.False(t, candidates.hasMatchSpan(0))
	require.Equal(t, uint32(1), candidates.matchSpanEpoch)
	// The old state is intentionally left untouched; the epoch makes it stale.
	require.True(t, candidates.matchSpanStates[0].active)
}

func TestRuleMatchSpanEpochWrapClearsStaleState(t *testing.T) {
	candidates := ruleCandidates{
		matchSpanStates: make([]ruleMatchSpanState, 1),
		matchSpanEpoch:  ^uint32(0),
	}
	candidates.addMatchSpan(0, 10, 100, matchSpanPlan{beforeBytes: 3, afterBytes: 2, beforeBounded: true, afterBounded: true, valid: true})
	require.True(t, candidates.hasMatchSpan(0))

	candidates.resetMatchSpans()
	require.Zero(t, candidates.matchSpanEpoch)
	require.Equal(t, ruleMatchSpanState{}, candidates.matchSpanStates[0])
	require.False(t, candidates.hasMatchSpan(0))
}

func TestDetectorSkipsSpanEligibleRuleWithoutAnchorKeyword(t *testing.T) {
	rule := config.Rule{
		RuleID:   "anchored",
		Regex:    blregexp.MustCompile(`foo[0-9]{3}`),
		Keywords: []string{"foo", "context"},
	}
	detector, err := NewDetector(&config.Config{
		Rules:        map[string]config.Rule{rule.RuleID: rule},
		OrderedRules: []string{rule.RuleID},
	}, ValidationOptions{})
	require.NoError(t, err)
	detector.RuleTimings = NewRuleTimingCollector()

	require.Empty(t, detector.DetectString("context without the literal anchor"))
	require.Empty(t, detector.RuleTimings.Snapshot(), "a context-only keyword must not invoke the regex")

	findings := detector.DetectString("context followed by foo123")
	require.Len(t, findings, 1)
	require.Equal(t, "foo123", findings[0].Match)
	require.Equal(t, uint64(1), detector.RuleTimings.Snapshot()[0].Hits)
}
