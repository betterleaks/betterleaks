package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
)

func TestScannerNeverExecutesProviderPrograms(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = fmt.Sprintf(`let r = http.get(%q, {}); {"result":"valid"}`, server.URL)
	cfg.Rules[0].AnalyzeExpr = `this is not a valid program ???`
	scanner := mustNew(t, cfg, WithPrecompile())
	findings := scanner.ScanString("secret-alpha")
	require.Len(t, findings, 1)
	require.True(t, findings[0].Analysis.IsZero())
	_, err := scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("secret-alpha")}, nil)
	require.NoError(t, err)
	require.Zero(t, requests.Load())
	// Local filter bindings cannot use provider HTTP or environment access.
	for _, filter := range []string{`http.get("https://example.invalid", {}).status == 200`, `env.get("TOKEN") == "skip"`} {
		cfg.Filter = filter
		_, err := New(cfg, WithPrecompile())
		require.Error(t, err)
	}
}

func TestScannerConcurrentReuse(t *testing.T) {
	cfg := testConfig()
	cfg.Filter = `finding.secret == "secret-ignored"`
	scanner := mustNew(t, cfg, WithJobs(2))
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			const content = "secret-alpha secret-ignored"
			summary, err := scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader(content)}, func(f report.Finding) error {
				if f.Match.Value != "secret-alpha" {
					return fmt.Errorf("unexpected finding: %s", f.RuleID)
				}
				return nil
			})
			if err != nil || summary.Findings != 1 || summary.BytesInspected != uint64(len(content)) {
				t.Errorf("scan failed: summary=%+v err=%v", summary, err)
			}
		})
	}
	wg.Wait()
}

func TestScannerHandlerMayStartIndependentScan(t *testing.T) {
	scanner := mustNew(t, testConfig())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, err := scanner.Scan(ctx, &sources.Reader{Content: strings.NewReader("secret-alpha")}, func(report.Finding) error {
		_, err := scanner.Scan(ctx, &sources.Reader{Content: strings.NewReader("secret-beta")}, nil)
		return err
	})
	require.NoError(t, err)
}

func TestFindingMatchAndLocationHandoff(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[0].Regex = `token=(?P<token>[a-z]+)`
	cfg.Rules[0].Keywords = nil
	cfg.Rules[0].Filter = `let _ = setConfidence("high"); attributes.path != "archive.zip!service.env"`
	scanner := mustNew(t, cfg, WithPrecompile())
	attrs := map[string]string{sources.AttrPath: "archive.zip!service.env", sources.AttrResource: sources.ResourceFileContent}
	var finding report.Finding
	summary, err := scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("token=alpha"), Attributes: attrs}, func(f report.Finding) error { finding = f; return nil })
	require.NoError(t, err)
	require.Equal(t, 1, summary.Findings)
	require.Equal(t, report.Match{Full: "token=alpha", Value: "alpha", Captures: map[string]string{"token": "alpha"}}, finding.Match)
	require.Equal(t, "archive.zip!service.env", finding.Location.Path)
	require.Equal(t, 1, finding.Location.StartLine)
	require.Equal(t, "high", finding.Confidence)
	require.Equal(t, map[string]string{sources.AttrResource: sources.ResourceFileContent}, finding.Attributes)
	require.Equal(t, "archive.zip!service.env", attrs[sources.AttrPath], "source attributes must remain intact")
	require.True(t, finding.Analysis.IsZero())
}

func TestContextRetentionIsExplicit(t *testing.T) {
	const content = "tenant=acme\nsecret-alpha\nmode=dev"
	for _, tc := range []struct{ name, window, want string }{
		{name: "default"},
		{name: "match line", window: "1L", want: "secret-alpha"},
		{name: "surrounding lines", window: "2L", want: content},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Rules[0].ValidateExpr = `{"result":"valid", "metadata": {"evidence":finding.context}}`
			cfg.Rules[0].AnalyzeExpr = `{"reason":finding.context}`
			// Local context extraction needs no retained copy. The optional context
			// binding must reflect exactly the window the caller requested.
			cfg.Rules[0].Filter = fmt.Sprintf(`finding.context != %q || !(finding.fragment_raw[max(finding.match_start_idx - 20, 0):finding.match_start_idx] contains "tenant=acme")`, tc.want)
			options := []Option{WithPrecompile()}
			if tc.window != "" {
				options = append(options, WithMatchContext(tc.window))
			}
			scanner := mustNew(t, cfg, options...)
			findings := scanner.ScanString(content)
			require.Len(t, findings, 1)
			require.Equal(t, tc.want, findings[0].MatchContext)
			require.Equal(t, tc.want, findings[0].ToExprMap()["context"])
			require.True(t, findings[0].Analysis.IsZero())
		})
	}
}
