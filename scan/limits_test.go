//nolint:exhaustruct // Tests use minimal rules, fragments, and deliberately invalid limits.
package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	blregexp "github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
)

func testScanLimits() ScanLimits {
	return ScanLimits{MaxFindings: 10000, MaxCandidates: 10000, MaxBytes: 64 << 20,
		MaxFragmentBytes: 128 << 10, MaxMatchIndexBytes: 1 << 20}
}

type limitedMatchEngine struct {
	lastN atomic.Int64
	enter chan struct{}
	leave chan struct{}
	once  sync.Once
}

func (e *limitedMatchEngine) Version() string { return "limited-match-test" }
func (e *limitedMatchEngine) Compile(pattern string) (blregexp.CompiledRegexp, error) {
	r, err := (blregexp.Stdlib{}).Compile(pattern)
	return limitedMatchRegexp{r, e}, err
}

type limitedMatchRegexp struct {
	blregexp.CompiledRegexp
	engine *limitedMatchEngine
}

func (r limitedMatchRegexp) record(n int) {
	r.engine.lastN.Store(int64(n))
	if r.engine.enter != nil {
		r.engine.once.Do(func() { close(r.engine.enter) })
		<-r.engine.leave
	}
}

func (r limitedMatchRegexp) FindAllStringIndex(raw string, n int) [][]int {
	r.record(n)
	return r.CompiledRegexp.FindAllStringIndex(raw, n)
}

func (r limitedMatchRegexp) FindAllStringSubmatchIndex(raw string, n int) [][]int {
	r.record(n)
	return r.CompiledRegexp.FindAllStringSubmatchIndex(raw, n)
}

func TestScanLimitsStopRegexCollectionBeforeMaterializingFindings(t *testing.T) {
	for _, pattern := range []string{"TOKEN", "(?P<value>TOKEN)"} {
		t.Run(pattern, func(t *testing.T) {
			engine := &limitedMatchEngine{}
			s := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: pattern}}}, WithRegexEngine(engine))
			limits := testScanLimits()
			limits.MaxCandidates = 4
			calls := 0
			_, err := s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader(strings.Repeat("TOKEN ", 10000))}, limits,
				func(report.Finding) error { calls++; return nil })
			require.ErrorIs(t, err, ErrLimitExceeded)
			require.EqualValues(t, 5, engine.lastN.Load(), "only four candidates plus one sentinel may be requested")
			require.Zero(t, calls)
			// A failed call does not poison this scanner or a later call's budget.
			summary, err := s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("TOKEN")}, limits, nil)
			require.NoError(t, err)
			require.Equal(t, 1, summary.Findings)
		})
	}
}

func TestScanLimitsBoundMatchIndexScratch(t *testing.T) {
	engine := &limitedMatchEngine{}
	s := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: "(T)(O)(K)(E)(N)"}}}, WithRegexEngine(engine))
	limits := testScanLimits()
	limits.MaxMatchIndexBytes = 1024
	_, err := s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("TOKEN TOKEN TOKEN")}, limits, nil)
	require.ErrorIs(t, err, ErrLimitExceeded)
	require.ErrorContains(t, err, "match-index")
	require.EqualValues(t, 2, engine.lastN.Load())
	_, err = s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("TOKEN")}, limits, nil)
	require.NoError(t, err)
	// An empty match at every byte position exhausts the theoretical maximum;
	// filling scratch exactly must not imply undiscovered matches in that case.
	s = mustNew(t, &config.Config{Rules: []config.Rule{{ID: "empty", Regex: "a*"}}})
	limits.MaxMatchIndexBytes = 384
	summary, err := s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("x")}, limits, nil)
	require.NoError(t, err)
	require.Equal(t, 2, summary.Findings)
}

func TestScanLimitsBoundRegexCollectionByBytes(t *testing.T) {
	engine := &limitedMatchEngine{}
	s := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: "TOKEN", FilterExpr: "true"}}}, WithWorkers(1), WithRegexEngine(engine))
	limits := testScanLimits()
	limits.MaxBytes, limits.MaxMatchIndexBytes = 50000, 10000
	_, err := s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader(strings.Repeat("TOKEN ", 3000))}, limits, nil)
	require.ErrorIs(t, err, ErrLimitExceeded)
	require.Positive(t, engine.lastN.Load(), "the test must reach regex collection")
	require.Less(t, engine.lastN.Load(), int64(10), "the byte budget must constrain raw collection before filters")
}

func TestScanLimitsCountFindingsAcrossFragments(t *testing.T) {
	s := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: "TOKEN"}}}, WithWorkers(1))
	limits := testScanLimits()
	limits.MaxFindings = 2
	fragments := fragmentSource{fragments: []sources.Fragment{{Raw: "TOKEN"}, {Raw: "TOKEN"}, {Raw: "TOKEN"}}}
	_, err := s.ScanWithLimits(t.Context(), fragments, limits, nil)
	require.ErrorIs(t, err, ErrLimitExceeded)
	require.ErrorContains(t, err, "returned findings")
}

func TestScanLimitsRejectHugeWorkerQueuesBeforeAllocation(t *testing.T) {
	s := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: "TOKEN"}}}, WithWorkers(1<<30))
	_, err := s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("TOKEN")}, testScanLimits(), nil)
	require.ErrorIs(t, err, ErrLimitExceeded)
}

func TestScanLimitsPreserveFilteredOutputSemantics(t *testing.T) {
	s := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: "skip|keep", FilterExpr: `finding.secret == "skip"`}}})
	limits := testScanLimits()
	limits.MaxFindings = 1
	var findings []report.Finding
	_, err := s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("skip skip keep")}, limits,
		func(f report.Finding) error { findings = append(findings, f); return nil })
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, "keep", findings[0].Match.Value)
	limits.MaxCandidates = 2
	_, err = s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("skip skip skip")}, limits, nil)
	require.ErrorIs(t, err, ErrLimitExceeded, "filtered candidates still consume detection budget")
	_, err = s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("keep keep")}, testScanLimitsWithOneFinding(),
		func(report.Finding) error { t.Error("over-limit fragment must fail before delivery"); return nil })
	require.ErrorIs(t, err, ErrLimitExceeded)
}

func testScanLimitsWithOneFinding() ScanLimits {
	limits := testScanLimits()
	limits.MaxFindings = 1
	return limits
}

func TestScanLimitsAreSharedAcrossWorkersAndIndependentAcrossCalls(t *testing.T) {
	s := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: "TOKEN"}}}, WithWorkers(4))
	limits := testScanLimits()
	limits.MaxCandidates = 3
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			fragments := make([]sources.Fragment, 8)
			for i := range fragments {
				fragments[i].Raw = "TOKEN"
			}
			_, err := s.ScanWithLimits(ctx, fragmentSource{fragments: fragments}, limits, nil)
			if !errors.Is(err, ErrLimitExceeded) {
				t.Errorf("expected shared candidate limit: %v", err)
			}
			summary, err := s.ScanWithLimits(ctx, &sources.Reader{Content: strings.NewReader("TOKEN TOKEN TOKEN")}, limits, nil)
			if err != nil || summary.Findings != 3 {
				t.Errorf("independent call: summary=%+v error=%v", summary, err)
			}
		})
	}
	group.Wait()
	require.NoError(t, ctx.Err())
}

func TestScanLimitsCancelScratchWaiters(t *testing.T) {
	engine := &limitedMatchEngine{enter: make(chan struct{}), leave: make(chan struct{})}
	s := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: "TOKEN"}}}, WithWorkers(2), WithRegexEngine(engine))
	limits := testScanLimits()
	limits.MaxMatchIndexBytes = 384 // one regex call, including its sentinel
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := s.ScanWithLimits(ctx, fragmentSource{fragments: []sources.Fragment{{Raw: "TOKEN"}, {Raw: "TOKEN"}}}, limits, nil)
		done <- err
	}()
	<-engine.enter
	cancel()
	close(engine.leave)
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled scan failed to join workers")
	}
}

func TestScanLimitsBoundComponentsAndDecoding(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "primary", Regex: "PRIMARY", Components: []config.Component{{RuleID: "a"}, {RuleID: "b"}}},
		{ID: "a", Regex: "AAAA", SkipReport: true},
		{ID: "b", Regex: "BBBB", SkipReport: true},
	}}
	s := mustNew(t, cfg)
	limits := testScanLimits()
	limits.MaxBytes, limits.MaxMatchIndexBytes = 100000, 10000
	_, err := s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("PRIMARY " + strings.Repeat("AAAA BBBB ", 10))}, limits, nil)
	require.ErrorIs(t, err, ErrLimitExceeded, "component Cartesian products must be reserved before allocation")
	_, err = s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("PRIMARY AAAA BBBB")}, limits, nil)
	require.NoError(t, err)
	limits.MaxCandidates = 2
	_, err = s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("PRIMARY AAAA BBBB")}, limits, nil)
	require.ErrorIs(t, err, ErrLimitExceeded, "components must share the candidate count")

	s = mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: "secret-alpha"}}}, WithWorkers(1), WithMaxDecodeDepth(2))
	encoded := base64.StdEncoding.EncodeToString([]byte("secret-alpha"))
	limits = testScanLimits()
	summary, err := s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader(encoded)}, limits, nil)
	require.NoError(t, err)
	require.Equal(t, 1, summary.Findings)
	limits.MaxBytes, limits.MaxMatchIndexBytes = 512, 384
	_, err = s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader(encoded)}, limits, nil)
	require.ErrorIs(t, err, ErrLimitExceeded)
	limits.MaxBytes = 10000
	_, err = s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader(strings.Repeat("~", 3000))}, limits, nil)
	require.NoError(t, err, "a decode pass with no encodings must not reserve a worst-case decoded buffer")
}

func TestScanLimitsValidateInputAndCoverPathOnlyRules(t *testing.T) {
	s := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "a", Path: `\.env$`}, {ID: "b", Path: `\.env$`}}})
	_, err := s.ScanWithLimits(t.Context(), nil, ScanLimits{}, nil)
	require.Error(t, err)
	limits := testScanLimits()
	limits.MaxFragmentBytes = 4
	_, err = s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader("12345")}, limits, nil)
	require.ErrorIs(t, err, ErrLimitExceeded)
	limits.MaxCandidates = 1
	_, err = s.ScanWithLimits(t.Context(), fragmentSource{fragments: []sources.Fragment{{Attributes: map[string]string{sources.AttrPath: "a.env"}}}}, limits, nil)
	require.ErrorIs(t, err, ErrLimitExceeded)
}

func TestScanLimitsPreserveRegexSemantics(t *testing.T) {
	for _, pattern := range []string{`(?m)^TOKEN$`, `\bTOKEN\b`, `(?P<value>TOKEN)`, `a*`} {
		t.Run(pattern, func(t *testing.T) {
			cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: pattern}}}
			s := mustNew(t, cfg)
			const raw = "é TOKEN\nTOKEN\nTOKENx\naaa"
			var normal, bounded []report.Finding
			_, err := s.Scan(t.Context(), &sources.Reader{Content: strings.NewReader(raw)}, func(f report.Finding) error { normal = append(normal, f); return nil })
			require.NoError(t, err)
			_, err = s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader(raw)}, testScanLimits(), func(f report.Finding) error { bounded = append(bounded, f); return nil })
			require.NoError(t, err)
			require.Equal(t, normal, bounded)
		})
	}
}

func TestScanLimitsPreserveKeywordWindows(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: `TOKEN[0-9]{4}`, Keywords: []string{"TOKEN"}}}}
	s := mustNew(t, cfg)
	raw := "TOKEN1234" + strings.Repeat("-", 5000) + "TOKEN5678"
	var normal, bounded []report.Finding
	_, err := s.Scan(t.Context(), &sources.Reader{Content: strings.NewReader(raw)}, func(f report.Finding) error { normal = append(normal, f); return nil })
	require.NoError(t, err)
	_, err = s.ScanWithLimits(t.Context(), &sources.Reader{Content: strings.NewReader(raw)}, testScanLimits(), func(f report.Finding) error { bounded = append(bounded, f); return nil })
	require.NoError(t, err)
	require.Len(t, bounded, 2)
	require.Equal(t, normal, bounded)
}

func TestFindingAllocationChargeCoversSerializedOutput(t *testing.T) {
	escaped := strings.Repeat("\x00\n<&\"\\", 1000)
	f := report.Finding{
		RuleID: escaped, RuleHash: escaped, Description: escaped, Confidence: escaped,
		Location: report.Location{Path: strings.Repeat("% ", 1000), StartLine: 1, EndLine: 999},
		Match: report.Match{Full: escaped, Value: escaped, Fingerprint: escaped, Context: escaped,
			Captures: map[string]string{escaped: escaped}},
		Attributes: map[string]string{sources.AttrGitPlatform: "github", sources.AttrGitRemoteURL: "https://github.com/test/repo", sources.AttrGitSHA: "abc", escaped: escaped},
		Tags:       []string{escaped}, Encodings: []string{escaped},
		ComponentSets: []report.ComponentSet{{Components: []report.ComponentFinding{{RuleID: escaped, Match: report.Match{Value: escaped}, Location: report.Location{Path: escaped}, Encodings: []string{escaped}}}}},
	}
	charge := findingAllocationBytes(f)
	ownFindingAttributes(&f)
	require.NotEmpty(t, f.Attributes[sources.AttrURL])
	serialized, err := json.Marshal(f)
	require.NoError(t, err)
	require.GreaterOrEqual(t, charge, int64(len(serialized)))
}
