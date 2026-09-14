package analyze_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/analyze"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/stretchr/testify/require"
)

func TestMalformedFindingsNeverReachProvider(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "key", Regex: `(?P<tenant>tenant):(?P<token>token)`, SecretGroup: 2,
			ValidateExpr: fmt.Sprintf(`let r=http.get(%q, {}); {"result": finding.captures.tenant != "" && components.part.captures.region != "" ? "valid" : "invalid"}`, server.URL),
			Components:   []*config.Component{{RuleID: "part"}}},
		{ID: "part", Regex: `part`},
	}}
	a, err := analyze.New(cfg)
	require.NoError(t, err)
	valid := report.Finding{RuleID: "key", Match: report.Match{Value: "primary-value", Captures: map[string]string{"tenant": "tenant-value"}}, ComponentSets: []report.ComponentSet{{Components: []*report.ComponentFinding{{RuleID: "part", Match: report.Match{Value: "part-value", Captures: map[string]string{"region": "region-value"}}}}}}}
	for _, tc := range []struct {
		name   string
		change func(*report.Finding)
		want   string
	}{
		{"unknown rule", func(f *report.Finding) { f.RuleID = "missing" }, "not found"},
		{"empty primary", func(f *report.Finding) { f.Match.Value = "" }, "must not be empty"},
		{"missing primary capture", func(f *report.Finding) { delete(f.Match.Captures, "tenant") }, "missing required capture"},
		{"inconsistent primary capture", func(f *report.Finding) { f.Match.Captures["token"] = "another-value" }, "disagrees"},
		{"no sets", func(f *report.Finding) { f.ComponentSets = nil }, "missing required component"},
		{"empty set", func(f *report.Finding) { f.ComponentSets[0].Components = nil }, "missing required component"},
		{"nil component", func(f *report.Finding) { f.ComponentSets[0].Components[0] = nil }, "nil component"},
		{"extra component", func(f *report.Finding) { f.ComponentSets[0].Components[0].RuleID = "extra" }, "not declared"},
		{"duplicate component", func(f *report.Finding) {
			f.ComponentSets[0].Components = append(f.ComponentSets[0].Components, f.ComponentSets[0].Components[0])
		}, "repeats component"},
		{"empty component", func(f *report.Finding) { f.ComponentSets[0].Components[0].Match.Value = "" }, "must not be empty"},
		{"missing component capture", func(f *report.Finding) { f.ComponentSets[0].Components[0].Match.Captures = nil }, "missing required capture"},
		{"oversized input", func(f *report.Finding) { f.ComponentSets = make([]report.ComponentSet, 101) }, "exceed limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := valid.Clone()
			tc.change(&f)
			_, err := a.Analyze(t.Context(), f)
			require.ErrorContains(t, err, tc.want)
		})
	}
	require.Zero(t, calls.Load())
	result, err := a.Analyze(t.Context(), valid)
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
	require.Equal(t, "primary-value", result.Match.Captures["token"])
	require.NotContains(t, valid.Match.Captures, "token", "canonicalization must not mutate input")
	requirements, err := a.Requirements("key")
	require.NoError(t, err)
	require.Equal(t, []string{"tenant"}, requirements.Captures)
	require.Equal(t, []string{"region"}, requirements.Components[0].Captures)
}

func TestBoundedComponentSearchReportsIncomplete(t *testing.T) {
	for _, working := range []string{"part_137", "part_001"} {
		t.Run(working, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path == "/"+working {
					w.WriteHeader(200)
				} else {
					w.WriteHeader(401)
				}
			}))
			defer server.Close()
			cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `PRIMARY`, ValidateExpr: fmt.Sprintf(`let r=http.get(%q+"/"+components.part.secret, {}); {"result":r.status==200 ? "valid" : "invalid"}`, server.URL), Components: []*config.Component{{RuleID: "part"}}}, {ID: "part", Regex: `part_[0-9]{3}`, SkipReport: true}}}
			scanner, err := scan.New(cfg)
			require.NoError(t, err)
			var content strings.Builder
			content.WriteString("PRIMARY\n")
			for i := 1; i <= 137; i++ {
				fmt.Fprintf(&content, "part_%03d\n", i)
			}
			findings := scanner.ScanString(content.String())
			require.Len(t, findings, 1)
			require.Len(t, findings[0].ComponentSets, 100)
			require.True(t, findings[0].ComponentSetsTruncated)
			wire, err := json.Marshal(findings[0])
			require.NoError(t, err)
			var restored report.Finding
			require.NoError(t, json.Unmarshal(wire, &restored))
			require.True(t, restored.ComponentSetsTruncated)
			a, err := analyze.New(cfg)
			require.NoError(t, err)
			resolved, err := a.Analyze(t.Context(), restored)
			require.NoError(t, err)
			require.EqualValues(t, 100, calls.Load(), "never probe beyond the cap")
			require.True(t, resolved.ComponentSetsTruncated)
			if working == "part_137" {
				require.Equal(t, report.ValidationStatusNeedsValidation, resolved.Analysis.Status)
				for _, set := range resolved.ComponentSets {
					require.Equal(t, report.ValidationStatusInvalid, set.Analysis.Status)
				}
			} else {
				require.Equal(t, report.ValidationStatusValid, resolved.Analysis.Status)
			}
		})
	}
}

func TestCredentialDedupIgnoresOccurrence(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `TOKEN`, ValidateExpr: fmt.Sprintf(`let r=http.get(%q, {}); {"result":r.status==200 ? "valid" : "invalid"}`, server.URL)}}}
	a, err := analyze.New(cfg, analyze.WithWorkers(8))
	require.NoError(t, err)
	count := 0
	err = a.AnalyzeStream(t.Context(), func(ctx context.Context, yield func(report.Finding) error) error {
		for i := 0; i < 30; i++ {
			f := report.Finding{RuleID: "key", Match: report.Match{Full: fmt.Sprintf("match%d TOKEN", i), Value: "TOKEN"}, Location: report.Location{Path: fmt.Sprintf("file%d.env", i)}, Line: fmt.Sprint(i), MatchContext: fmt.Sprint(i), Attributes: map[string]string{"git.message": fmt.Sprint(i)}}
			if err := yield(f); err != nil {
				return err
			}
		}
		return nil
	}, func(f report.Finding) error {
		count++
		require.Equal(t, report.ValidationStatusValid, f.Analysis.Status)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 30, count)
	require.EqualValues(t, 1, calls.Load())
}

func TestProducerOwnsInputAfterYield(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release; w.WriteHeader(200) }))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `TOKEN`, ValidateExpr: fmt.Sprintf(`let r=http.get(%q, {}); {"result": finding.captures.tenant=="before" && components.part.captures.region=="before" ? "valid" : "invalid"}`, server.URL), Components: []*config.Component{{RuleID: "part"}}}, {ID: "part", Regex: `PART`}}}
	a, err := analyze.New(cfg)
	require.NoError(t, err)
	f := report.Finding{RuleID: "key", Match: report.Match{Value: "TOKEN", Captures: map[string]string{"tenant": "before"}}, Attributes: map[string]string{"application": "before"}, Tags: []string{"before"}, ComponentSets: []report.ComponentSet{{Components: []*report.ComponentFinding{{RuleID: "part", Match: report.Match{Value: "PART", Captures: map[string]string{"region": "before"}}}}}}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var got report.Finding
	err = a.AnalyzeStream(ctx, func(ctx context.Context, yield func(report.Finding) error) error {
		defer close(release)
		if err := yield(f); err != nil {
			return err
		}
		select {
		case <-started:
		case <-ctx.Done():
			return ctx.Err()
		}
		f.Match.Captures["tenant"] = "after"
		f.Attributes["application"] = "after"
		f.Tags[0] = "after"
		f.ComponentSets[0].Components[0].Match.Captures["region"] = "after"
		f.ComponentSets[0].Components[0].Match.Value = "AFTER"
		return nil
	}, func(f report.Finding) error { got = f; return nil })
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, got.Analysis.Status)
	require.Equal(t, "before", got.Attributes["application"])
	require.Equal(t, []string{"before"}, got.Tags)
	require.Equal(t, "PART", got.ComponentSets[0].Components[0].Match.Value)
}

func TestOptionalCapturesDoNotBecomeRequired(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `TOKEN`, ValidateExpr: `{"result": (finding.captures.region ?? "default") == "default" ? "valid" : "invalid"}`}}}
	a, err := analyze.New(cfg)
	require.NoError(t, err)
	requirements, err := a.Requirements("key")
	require.NoError(t, err)
	require.Empty(t, requirements.Captures)
	result, err := a.ValidateCredential(t.Context(), analyze.Credential{RuleID: "key", Secret: "TOKEN"})
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
}
