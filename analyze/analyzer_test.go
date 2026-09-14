package analyze

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
)

func TestNewRejectsInvalidInputs(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: "key", ValidateExpr: `{"result":"valid"}`}}}
	for name, options := range map[string]Option{
		"negative workers":  WithWorkers(-1),
		"negative timeout":  WithTimeout(-time.Second),
		"negative budget":   WithMaxRequestsPerTarget(-1),
		"negative rate":     WithRequestsPerSecond(-1),
		"NaN rate":          WithRequestsPerSecond(math.NaN()),
		"infinite rate":     WithRequestsPerSecond(math.Inf(1)),
		"invalid rule rate": WithRequestsPerSecondByRule(map[string]float64{"key": 0}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(cfg, options)
			require.Error(t, err)
		})
	}
	_, err := New(nil)
	require.ErrorContains(t, err, "config is required")
	duplicate := &config.Config{Rules: []config.Rule{cfg.Rules[0], cfg.Rules[0]}}
	_, err = New(duplicate)
	require.ErrorContains(t, err, "duplicate rule ID")
	v := mustNew(t, cfg)
	_, err = v.ValidateCredential(nil, Credential{RuleID: "key", Secret: "secret"})
	require.ErrorContains(t, err, "context must not be nil")
	_, err = (&Analyzer{}).ValidateCredential(t.Context(), Credential{RuleID: "key", Secret: "secret"})
	require.ErrorContains(t, err, "must be constructed")
}

func TestNewSnapshotsInputsAndIgnoresScanExpressions(t *testing.T) {
	t.Setenv("BETTERLEAKS_SNAPSHOT_TEST", "allowed")
	cfg := &config.Config{Prefilter: "invalid scan syntax ???", Filter: "also invalid ???", Rules: []config.Rule{
		{ID: "key", Regex: "never-matches", Filter: "invalid ???", Tags: []string{"original"},
			Components:   []*config.Component{{RuleID: "part"}},
			ValidateExpr: `env.get("BETTERLEAKS_SNAPSHOT_TEST") == "allowed" && components.part.secret == "companion" ? {"result":"valid"} : {"result":"invalid"}`},
		{ID: "part", Regex: "part"},
	}}
	names := []string{"BETTERLEAKS_SNAPSHOT_TEST"}
	rates := map[string]float64{"key": 10}
	v := mustNew(t, cfg, WithEnvVars(names...), WithRequestsPerSecondByRule(rates))
	// Change caller-owned data before the first lazy compilation and evaluation.
	cfg.Rules[0].ID = "changed"
	cfg.Rules[0].ValidateExpr = `{"result":"invalid"}`
	cfg.Rules[0].Components[0].RuleID = "other"
	cfg.Rules[0].Tags[0] = "changed"
	names[0] = "DENIED"
	rates["key"] = -1
	result, err := v.ValidateCredential(t.Context(), Credential{RuleID: "key", Secret: "input", Components: map[string]CredentialComponent{"part": {Secret: "companion"}}})
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
	require.Equal(t, []string{"original"}, v.rules["key"].Tags)
}
