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
	require.True(t, findings[0].Validation.IsZero())
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
				if f.Secret != "secret-alpha" {
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
