package detect

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/sources"
)

func TestNewDetectorRequiresConfig(t *testing.T) {
	detector, err := NewDetector(nil, ValidationOptions{})
	require.Nil(t, detector)
	require.EqualError(t, err, "detect: config is required")
}

func TestNilDetectorDirectDetectionIsEmpty(t *testing.T) {
	var detector *Detector
	require.Empty(t, detector.DetectString("secret"))
	require.Empty(t, detector.DetectBytes([]byte("secret")))
	require.Empty(t, detector.DetectFragment(t.Context(), sources.Fragment{Raw: []byte("secret")}))
	require.Nil(t, detector.SkipFunc())
	require.Nil(t, detector.PathSkipFunc())
}

func TestNewDetectorReturnsPrefilterCompilationError(t *testing.T) {
	cfg := &config.Config{
		Rules:     make(map[string]config.Rule),
		Prefilter: `attributes["path"] ==`,
	}

	detector, err := NewDetector(cfg, ValidationOptions{})
	require.Nil(t, detector)
	require.ErrorContains(t, err, "detect: compile filters")
}

func TestNewDetectorDoesNotMutateConfigWhenCompilingPrefilter(t *testing.T) {
	cfg := &config.Config{
		Rules:     make(map[string]config.Rule),
		Prefilter: `attributes["path"] == "ignored.txt"`,
	}

	detector, err := NewDetector(cfg, ValidationOptions{})
	require.NoError(t, err)
	require.Equal(t, `attributes["path"] == "ignored.txt"`, cfg.Prefilter)
	require.NotNil(t, detector.SkipFunc())
	require.True(t, detector.SkipFunc()(map[string]string{"path": "ignored.txt"}))
}

func TestNewDetectorDoesNotRequireContext(t *testing.T) {
	cfg := &config.Config{
		Rules: make(map[string]config.Rule),
	}

	detector, err := NewDetector(cfg, ValidationOptions{})
	require.NoError(t, err)
	require.NotNil(t, detector)
}

func TestTokenizerIsSharedAcrossConcurrentDetectors(t *testing.T) {
	const detectorCount = 16
	var (
		wg         sync.WaitGroup
		tokenizers [detectorCount]any
	)
	wg.Add(detectorCount)
	for i := range detectorCount {
		go func() {
			defer wg.Done()
			tokenizers[i] = (&Detector{}).Tokenizer()
		}()
	}
	wg.Wait()

	require.NotNil(t, tokenizers[0])
	for _, tokenizer := range tokenizers[1:] {
		require.Same(t, tokenizers[0], tokenizer)
	}
}

func TestSharedTokenizerSupportsConcurrentEncoding(t *testing.T) {
	tokenizer := (&Detector{}).Tokenizer()
	require.NotNil(t, tokenizer)
	require.Equal(t, []int{15339, 1917}, tokenizer.EncodeOrdinary("hello world"))
	text := "this-is-a-long-readable-placeholder-value"
	want := tokenizer.EncodeOrdinary(text)

	const goroutineCount = 16
	var (
		wg      sync.WaitGroup
		results [goroutineCount][]int
	)
	wg.Add(goroutineCount)
	for i := range goroutineCount {
		go func() {
			defer wg.Done()
			for range 100 {
				results[i] = tokenizer.EncodeOrdinary(text)
			}
		}()
	}
	wg.Wait()

	for _, got := range results {
		require.Equal(t, want, got)
	}
}

func TestNewDetectorOrdersUnlistedRulesDeterministically(t *testing.T) {
	match := blregexp.MustCompile(`test`)
	cfg := &config.Config{
		Rules: map[string]config.Rule{
			"listed":  {RuleID: "listed", Regex: match, Specificity: 1},
			"z-last":  {RuleID: "z-last", Regex: match, Specificity: 1},
			"a-first": {RuleID: "a-first", Regex: match, Specificity: 1},
		},
		OrderedRules: []string{"listed", "listed"},
	}

	detector, err := NewDetector(cfg, ValidationOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"listed", "a-first", "z-last"}, []string{
		detector.rulesBySpecificity[0].RuleID,
		detector.rulesBySpecificity[1].RuleID,
		detector.rulesBySpecificity[2].RuleID,
	})
}

func TestNewDetectorRejectsInconsistentRuleIdentity(t *testing.T) {
	detector, err := NewDetector(&config.Config{Rules: map[string]config.Rule{
		"map-id": {RuleID: "rule-id", Regex: blregexp.MustCompile(`test`)},
	}}, ValidationOptions{})
	require.Nil(t, detector)
	require.EqualError(t, err, `detect: invalid config: rule map key "map-id" does not match rule ID "rule-id"`)
}

func TestNewDetectorRejectsEmptyKeyword(t *testing.T) {
	detector, err := NewDetector(&config.Config{Rules: map[string]config.Rule{
		"test": {RuleID: "test", Regex: blregexp.MustCompile(`test`), Keywords: []string{""}},
	}}, ValidationOptions{})
	require.Nil(t, detector)
	require.EqualError(t, err, `detect: invalid config: rule "test" has an empty keyword`)
}

func TestDetectorUsesConstructionSnapshot(t *testing.T) {
	tags := []string{"original"}
	rule := config.Rule{
		RuleID:   "snapshot",
		Regex:    blregexp.MustCompile(`candidate`),
		Keywords: []string{"candidate"},
		Tags:     tags,
		Filter:   `false`,
	}
	cfg := &config.Config{
		Path:   "config.toml",
		Filter: `false`,
		Rules:  map[string]config.Rule{rule.RuleID: rule},
	}
	detector, err := NewDetector(cfg, ValidationOptions{})
	require.NoError(t, err)

	// Mutating caller-owned config state after construction must not produce a
	// detector with half-old dispatch and half-new rule behavior.
	tags[0] = "mutated"
	rule.Regex = blregexp.MustCompile(`different`)
	rule.Filter = `true`
	cfg.Rules[rule.RuleID] = rule
	cfg.Filter = `true`
	cfg.Path = "scan.txt"

	findings := detector.DetectFragment(t.Context(), sources.Fragment{
		Raw:        []byte("candidate"),
		Attributes: map[string]string{sources.AttrPath: "scan.txt"},
	})
	require.Len(t, findings, 1)
	require.Equal(t, []string{"original"}, findings[0].Tags)

	findings[0].Tags[0] = "caller-mutated"
	next := detector.DetectBytes([]byte("candidate"))
	require.Len(t, next, 1)
	require.Equal(t, []string{"original"}, next[0].Tags)
}

func TestNewDetectorDerivesKeywordDispatchFromRules(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.Rule{
			"keyword": {
				RuleID:      "keyword",
				Keywords:    []string{"Candidate_"},
				Regex:       blregexp.MustCompile(`(?i)candidate_[a-z]+`),
				Specificity: 1,
			},
			"always": {
				RuleID: "always",
				Regex:  blregexp.MustCompile(`always_[a-z]+`),
			},
		},
	}

	detector, err := NewDetector(cfg, ValidationOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"keyword", "always"}, findingRuleIDs(detector.DetectString("CANDIDATE_value always_value")))
}

func TestNewDetectorRejectsUnknownValidationStatus(t *testing.T) {
	cfg := &config.Config{
		Rules: make(map[string]config.Rule),
	}

	detector, err := NewDetector(cfg, ValidationOptions{StatusFilter: "valid, typo"})
	require.Nil(t, detector)
	require.EqualError(t, err, `detect: unknown validation status "typo"`)
}
