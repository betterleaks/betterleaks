package scan_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestExpressionRegexFailuresFollowRuntimeErrorPolicy(t *testing.T) {
	engine := failingEngine{pattern: "(?:TOKEN)", err: errors.New("backend compilation failed")}
	t.Run("prefilters keep input and warn", func(t *testing.T) {
		for _, expression := range []string{
			`matchesAny(attributes.path, ["TOKEN"])`,
			`!matchesAny(attributes.path, ["TOKEN"])`,
			`matchesAny(attributes.path, [attributes.pattern])`,
		} {
			var logs bytes.Buffer
			skip, err := prefilter.Compile(expression, prefilter.Options{
				RegexEngine: engine, Logger: slog.New(slog.NewTextHandler(&logs, nil)),
			})
			require.NoError(t, err)
			for range 2 {
				logs.Reset()
				require.False(t, skip(map[string]string{"path": "TOKEN", "pattern": "TOKEN"}))
				require.Contains(t, logs.String(), "backend compilation failed")
			}
		}
	})
	t.Run("finding filters keep findings and warn", func(t *testing.T) {
		for _, expression := range []string{
			`!matchesAny(finding.secret, ["TOKEN"])`,
			`findMatch(finding.secret, "TOKEN") == ""`,
		} {
			var logs bytes.Buffer
			scanner, err := scan.New(&config.Config{Rules: []config.Rule{{ID: "test", Regex: "TOKEN", Filter: expression}}},
				scan.WithRegexEngine(engine), scan.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
			require.NoError(t, err)
			for range 2 {
				logs.Reset()
				summary, err := scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("TOKEN")}, nil)
				require.NoError(t, err)
				require.Equal(t, 1, summary.Findings)
				require.Contains(t, logs.String(), "backend compilation failed")
			}
		}
	})
	t.Run("validation reports error instead of invalid", func(t *testing.T) {
		a, err := analyze.New(&config.Config{Rules: []config.Rule{{
			ID: "test", Regex: "TOKEN",
			ValidateExpr: `{"result": matchesAny(finding.secret, ["TOKEN"]) ? "valid" : "invalid"}`,
		}}}, analyze.WithRegexEngine(engine))
		require.NoError(t, err)
		result, err := a.ValidateCredential(t.Context(), credential.Input{RuleID: "test", Secret: "TOKEN"})
		require.NoError(t, err)
		require.Equal(t, report.ValidationStatusError, result.Analysis.Status)
		require.Contains(t, result.Analysis.StatusReason, "backend compilation failed")
	})
	t.Run("analysis preserves liveness and reports enrichment failure", func(t *testing.T) {
		a, err := analyze.New(&config.Config{Rules: []config.Rule{{
			ID: "test", Regex: "TOKEN", ValidateExpr: `{"result": "valid"}`,
			AnalyzeExpr: `{"capabilities": analysis.capabilities({"read": matchesAny(finding.secret, ["TOKEN"])})}`,
		}}}, analyze.WithRegexEngine(engine))
		require.NoError(t, err)
		result, err := a.AnalyzeCredential(t.Context(), credential.Input{RuleID: "test", Secret: "TOKEN"})
		require.NoError(t, err)
		require.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
		require.Equal(t, report.SeverityUnknown, result.Analysis.Severity)
		require.Empty(t, result.Analysis.Capabilities)
		require.Contains(t, result.Analysis.Reason, "backend compilation failed")
	})
}

type failingEngine struct {
	pattern string
	err     error
}

func (e failingEngine) Version() string { return "failing" }

func (e failingEngine) Compile(pattern string) (regexp.CompiledRegexp, error) {
	if pattern == e.pattern {
		return nil, e.err
	}
	return regexp.Stdlib{}.Compile(pattern)
}

func TestScanReturnsLazyRegexErrors(t *testing.T) {
	backendErr := errors.New("backend compilation failed")
	for _, tc := range []struct {
		name    string
		rules   []config.Rule
		pattern string
		want    string
	}{
		{
			name:    "content",
			rules:   []config.Rule{{ID: "token", Regex: "TOKEN"}},
			pattern: "TOKEN", want: `compile rule "token" regex`,
		},
		{
			name:    "captures",
			rules:   []config.Rule{{ID: "token", Regex: "(TOKEN)"}},
			pattern: "(TOKEN)", want: `compile rule "token" regex`,
		},
		{
			name:    "search windows",
			rules:   []config.Rule{{ID: "token", Regex: `TOKEN[0-9]{4}`, Keywords: []string{"TOKEN"}}},
			pattern: `TOKEN[0-9]{4}`, want: `compile rule "token" regex`,
		},
		{
			name:    "path only",
			rules:   []config.Rule{{ID: "path", Path: `\.env$`}},
			pattern: `\.env$`, want: `compile rule "path" path regex`,
		},
		{
			name:    "path restricted content",
			rules:   []config.Rule{{ID: "token", Regex: "TOKEN", Path: `\.env$`}},
			pattern: `\.env$`, want: `compile rule "token" path regex`,
		},
		{
			name: "required component",
			rules: []config.Rule{
				{ID: "token", Regex: "TOKEN", Components: []config.Component{{RuleID: "companion"}}},
				{ID: "companion", Regex: "COMPANION", SkipReport: true},
			},
			pattern: "COMPANION", want: `compile rule "companion" regex`,
		},
		{
			name: "optional component",
			rules: []config.Rule{
				{ID: "token", Regex: "TOKEN", Components: []config.Component{{RuleID: "companion", Optional: true}}},
				{ID: "companion", Regex: "COMPANION", SkipReport: true},
			},
			pattern: "COMPANION", want: `compile rule "companion" regex`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Rules: tc.rules}
			engine := failingEngine{pattern: tc.pattern, err: backendErr}
			scanner, err := scan.New(cfg, scan.WithRegexEngine(engine))
			require.NoError(t, err, "backend compilation must remain lazy")
			// Repeat on the same scanner to exercise cached errors and worker reuse.
			for range 2 {
				summary, err := scanner.Scan(t.Context(), &sources.Reader{
					Content:    strings.NewReader("TOKEN1234 COMPANION"),
					Attributes: map[string]string{sources.AttrPath: "app.env"},
				}, nil)
				require.ErrorIs(t, err, backendErr)
				require.ErrorContains(t, err, tc.want)
				require.Zero(t, summary.Findings)
			}
			_, err = scan.New(cfg, scan.WithRegexEngine(engine), scan.WithPrecompile())
			require.ErrorIs(t, err, backendErr)
		})
	}
}

func TestLazyRegexErrorsPreserveEarlierFindings(t *testing.T) {
	backendErr := errors.New("backend compilation failed")
	var logs bytes.Buffer
	scanner, err := scan.New(&config.Config{Rules: []config.Rule{
		{ID: "good", Regex: "GOOD", Specificity: 100},
		{ID: "bad", Regex: "BAD", Keywords: []string{"BAD"}},
	}}, scan.WithRegexEngine(failingEngine{pattern: "BAD", err: backendErr}),
		scan.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	require.NoError(t, err)
	var findings []report.Finding
	summary, err := scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("GOOD BAD")}, func(f report.Finding) error {
		findings = append(findings, f)
		return nil
	})
	require.ErrorIs(t, err, backendErr)
	require.Equal(t, 1, summary.Findings)
	require.Len(t, findings, 1)
	require.Equal(t, "good", findings[0].RuleID)

	require.Len(t, scanner.ScanString("GOOD BAD"), 1)
	require.Contains(t, logs.String(), "backend compilation failed")
	// A previous failure must not poison scans where the failed rule is ineligible.
	summary, err = scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("GOOD")}, nil)
	require.NoError(t, err)
	require.Equal(t, 1, summary.Findings)
}

type waitingSource struct {
	stopped chan struct{}
}

func (s waitingSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	defer close(s.stopped)
	if err := yield(sources.Fragment{Raw: "TOKEN"}, nil); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestLazyRegexErrorCancelsAndJoinsSource(t *testing.T) {
	for _, backendErr := range []error{errors.New("backend compilation failed"), context.Canceled} {
		scanner, err := scan.New(&config.Config{Rules: []config.Rule{{ID: "token", Regex: "TOKEN"}}},
			scan.WithRegexEngine(failingEngine{pattern: "TOKEN", err: backendErr}), scan.WithWorkers(1))
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		source := waitingSource{stopped: make(chan struct{})}
		_, err = scanner.Scan(ctx, source, nil)
		require.ErrorIs(t, err, backendErr)
		require.NoError(t, ctx.Err(), "scan must stop on the backend error, before the deadline")
		select {
		case <-source.stopped:
		default:
			t.Fatal("Scan returned before the source stopped")
		}
	}
}
