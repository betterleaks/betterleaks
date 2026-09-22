package scan_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/betterleaks/betterleaks/v2/analyze"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/credential"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
	"github.com/stretchr/testify/require"
)

// Separate instances deliberately have the same Version: caches must belong to
// an operation's engine, not a global namespace keyed by engine name or pattern.
type recordingEngine struct {
	mu       sync.Mutex
	patterns map[string]bool
}

func (e *recordingEngine) Version() string { return "recording" }

func (e *recordingEngine) Compile(pattern string) (regexp.CompiledRegexp, error) {
	e.mu.Lock()
	if e.patterns == nil {
		e.patterns = make(map[string]bool)
	}
	e.patterns[pattern] = true
	e.mu.Unlock()
	return regexp.Stdlib{}.Compile(pattern)
}

func (e *recordingEngine) requirePatterns(t *testing.T, patterns ...string) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, pattern := range patterns {
		require.True(t, e.patterns[pattern], "selected engine did not compile %q", pattern)
	}
}

func TestScannerOwnsRegexSelection(t *testing.T) {
	for i := range 2 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			engine := new(recordingEngine)
			cfg := &config.Config{Rules: []config.Rule{{
				ID: "token", Regex: "TOKEN", Path: `\.env$`,
				Filter: `matchesAny(finding.secret, ["^skip$"]) || findMatch(finding.secret, "TOKEN") == ""`,
			}}}
			scanner, err := scan.New(cfg, scan.WithRegexEngine(engine))
			require.NoError(t, err)
			require.Empty(t, engine.patterns, "backend compilation must remain lazy")
			var workers sync.WaitGroup
			for range 4 {
				workers.Go(func() {
					summary, err := scanner.Scan(t.Context(), &sources.Reader{
						Content:    strings.NewReader("TOKEN"),
						Attributes: map[string]string{sources.AttrPath: "app.env"},
					}, nil)
					if err != nil || summary.Findings != 1 {
						t.Errorf("Scan: summary=%+v error=%v", summary, err)
					}
				})
			}
			workers.Wait()
			engine.requirePatterns(t, "TOKEN", `\.env$`, "(?:^skip$)", "(?:TOKEN)")
		})
	}
}

func TestExpressionEnginesAreIndependent(t *testing.T) {
	for i := range 2 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			for _, expression := range []string{
				`matchesAny(attributes.path, ["^TOKEN$"])`,
				`matchesAny(attributes.path, [attributes.pattern])`,
			} {
				engine := new(recordingEngine)
				skip, err := prefilter.Compile(expression, prefilter.Options{RegexEngine: engine})
				require.NoError(t, err)
				require.True(t, skip(map[string]string{"path": "TOKEN", "pattern": "^TOKEN$"}))
				engine.requirePatterns(t, "(?:^TOKEN$)")
			}
			engine := new(recordingEngine)
			a, err := analyze.New(&config.Config{Rules: []config.Rule{{
				ID: "token", Regex: "TOKEN",
				ValidateExpr: `{"result": matchesAny(finding.secret, ["^TOKEN$"]) ? "valid" : "invalid"}`,
			}}}, analyze.WithRegexEngine(engine))
			require.NoError(t, err)
			result, err := a.ValidateCredential(t.Context(), credential.Input{RuleID: "token", Secret: "TOKEN"})
			require.NoError(t, err)
			require.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
			engine.requirePatterns(t, "(?:^TOKEN$)")
		})
	}
}

func TestNilEngineOptionIsRejected(t *testing.T) {
	cfg := &config.Config{}
	_, err := scan.New(cfg, scan.WithRegexEngine(nil))
	require.ErrorContains(t, err, "regex engine")
	_, err = analyze.New(cfg, analyze.WithRegexEngine(nil))
	require.ErrorContains(t, err, "regex engine")
}
