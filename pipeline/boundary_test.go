package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/analyze"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
)

func TestProviderWorkersAreIndependentAndBounded(t *testing.T) {
	const workers = 3
	started := make(chan struct{}, workers)
	release := make(chan struct{})
	var active, maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); n > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: `secret-[a-z]+`, ValidateExpr: fmt.Sprintf(`let r = http.get(%q, {}); {"result":"valid"}`, server.URL)}}}
	scanner, err := scan.New(cfg, scan.WithJobs(1))
	require.NoError(t, err)
	analyzer, err := analyze.New(cfg, analyze.WithWorkers(workers))
	require.NoError(t, err)
	p, err := New(scanner, analyzer)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		summary, err := p.Scan(ctx, &sources.Reader{Content: strings.NewReader("secret-alpha secret-beta secret-gamma")}, nil)
		if err == nil && summary.EmittedFindings != workers {
			err = fmt.Errorf("got %d findings", summary.EmittedFindings)
		}
		done <- err
	}()
	for range workers {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("provider work was serialized behind the single scan worker")
		}
	}
	unblock()
	require.NoError(t, <-done)
	require.Equal(t, int32(workers), maximum.Load())
}

type producingSource struct {
	produced atomic.Int32
	stopped  chan struct{}
}

func (s *producingSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	defer close(s.stopped)
	for i := range 100000 {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.produced.Add(1)
		if err := yield(sources.Fragment{Raw: fmt.Sprintf("secret-%d", i)}, nil); err != nil {
			return err
		}
	}
	return nil
}

func TestHandlerFailureCancelsAndJoinsWorkers(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: `secret-[0-9]+`, ValidateExpr: `{"result":"valid"}`}}}
	p := mustPipeline(t, cfg, scan.WithJobs(1))
	source := &producingSource{stopped: make(chan struct{})}
	want := errors.New("storage failed")
	var calls int
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	summary, err := p.Scan(ctx, source, func(report.Finding) error { calls++; return want })
	require.ErrorIs(t, err, want)
	require.Equal(t, 1, calls)
	require.Equal(t, 1, summary.EmittedFindings)
	require.Less(t, source.produced.Load(), int32(1000), "bounded queues must propagate backpressure")
	select {
	case <-source.stopped:
	default:
		t.Fatal("source still running after Scan returned")
	}
}

func TestStatusPolicyAndValidationOnly(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = `{"result": finding.secret == "secret-live" ? "valid" : "invalid"}`
	cfg.Rules[0].AnalyzeExpr = `invalid analysis syntax ???`
	scanner, err := scan.New(cfg, scan.WithPrecompile())
	require.NoError(t, err)
	analyzer, err := analyze.New(cfg)
	require.NoError(t, err)
	p, err := New(scanner, analyzer, WithValidationOnly(), WithValidationStatuses(report.ValidationStatusValid))
	require.NoError(t, err)
	summary, err := p.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("secret-live secret-fixture")}, nil)
	require.NoError(t, err)
	require.Equal(t, 1, summary.EmittedFindings)
	require.Equal(t, map[report.ValidationStatus]int{report.ValidationStatusValid: 1, report.ValidationStatusInvalid: 1}, summary.ValidationCounts)
	_, err = New(scanner, analyzer, WithValidationStatuses("surprising"))
	require.ErrorContains(t, err, "invalid validation status")
	local, err := New(scanner, nil)
	require.NoError(t, err)
	summary, err = local.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("secret-live")}, nil)
	require.NoError(t, err)
	require.Equal(t, 1, summary.EmittedFindings)
	require.Equal(t, map[report.ValidationStatus]int{report.ValidationStatusNone: 1}, summary.ValidationCounts)
}

func TestExplicitContextSurvivesHandoff(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = `finding.secret == "secret-alpha" ? {"result":"valid","analysis":{"owner":"acme"}} : {"result":"invalid"}`
	cfg.Rules[0].AnalyzeExpr = `{"identity":{"id":validation.analysis.owner},"capabilities":["read"]}`
	p := mustPipeline(t, cfg, scan.WithMatchContext("2L"))
	var finding report.Finding
	_, err := p.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("tenant=acme\nsecret-alpha"), Attributes: map[string]string{sources.AttrPath: "archive.zip!app.env"}}, func(f report.Finding) error { finding = f; return nil })
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, finding.Analysis.Status)
	require.Equal(t, "archive.zip!app.env", finding.Location.Path)
	require.NotContains(t, finding.Attributes, sources.AttrPath)
	require.Equal(t, "acme", finding.Analysis.Identity.ID)
	require.Empty(t, finding.Analysis.Metadata, "private validation evidence must not enter reports")
	require.Equal(t, "tenant=acme\nsecret-alpha", finding.MatchContext)
	// Explicit context survives serialization without hidden finding state.
	encoded, err := json.Marshal(finding)
	require.NoError(t, err)
	var restored report.Finding
	require.NoError(t, json.Unmarshal(encoded, &restored))
	analyzer, err := analyze.New(cfg)
	require.NoError(t, err)
	resolved, err := analyzer.Analyze(t.Context(), restored)
	require.NoError(t, err)
	require.Equal(t, finding.Analysis, resolved.Analysis)
}

func TestCancellationInterruptsProviderRequests(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	defer server.Close()
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = fmt.Sprintf(`let r = http.get(%q, {}); {"result":"valid"}`, server.URL)
	p := mustPipeline(t, cfg)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := p.Scan(ctx, &sources.Reader{Content: strings.NewReader("secret-alpha")}, nil)
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("provider did not start")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("pipeline did not stop")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("provider request was not canceled")
	}
}
