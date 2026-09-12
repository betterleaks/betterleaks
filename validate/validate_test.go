package validate

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
)

func TestNewValidatorRejectsInvalidInputs(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: "key", ValidateExpr: `{"result":"valid"}`}}}
	for name, options := range map[string]Options{
		"negative timeout":  {Timeout: -time.Second},
		"negative budget":   {MaxRequestsPerTarget: -1},
		"negative rate":     {RequestsPerSecond: -1},
		"NaN rate":          {RequestsPerSecond: math.NaN()},
		"infinite rate":     {RequestsPerSecond: math.Inf(1)},
		"invalid rule rate": {RequestsPerSecondByRule: map[string]float64{"key": 0}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewValidator(cfg, options)
			require.Error(t, err)
		})
	}
	_, err := NewValidator(nil, Options{})
	require.ErrorContains(t, err, "config is required")
	duplicate := &config.Config{Rules: []config.Rule{cfg.Rules[0], cfg.Rules[0]}}
	_, err = NewValidator(duplicate, Options{})
	require.ErrorContains(t, err, "duplicate rule ID")
	v := mustNewValidator(t, cfg, Options{})
	_, err = v.ValidateCredential(nil, Credential{RuleID: "key", Secret: "secret"})
	require.ErrorContains(t, err, "context must not be nil")
	_, err = (&Validator{}).ValidateCredential(t.Context(), Credential{RuleID: "key", Secret: "secret"})
	require.ErrorContains(t, err, "must be constructed")
}

func TestNewValidatorSnapshotsInputsAndIgnoresScanExpressions(t *testing.T) {
	t.Setenv("BETTERLEAKS_SNAPSHOT_TEST", "allowed")
	cfg := &config.Config{Prefilter: "invalid scan syntax ???", Filter: "also invalid ???", Rules: []config.Rule{
		{ID: "key", Regex: "never-matches", Filter: "invalid ???", Tags: []string{"original"},
			Components:   []*config.Component{{RuleID: "part"}},
			ValidateExpr: `env.get("BETTERLEAKS_SNAPSHOT_TEST") == "allowed" && components.part.secret == "companion" ? {"result":"valid"} : {"result":"invalid"}`},
		{ID: "part", Regex: "part"},
	}}
	options := Options{EnvVars: []string{"BETTERLEAKS_SNAPSHOT_TEST"}, RequestsPerSecondByRule: map[string]float64{"key": 10}}
	v := mustNewValidator(t, cfg, options)
	// Change caller-owned data before the first lazy compilation and evaluation.
	cfg.Rules[0].ID = "changed"
	cfg.Rules[0].ValidateExpr = `{"result":"invalid"}`
	cfg.Rules[0].Components[0].RuleID = "other"
	cfg.Rules[0].Tags[0] = "changed"
	options.EnvVars[0] = "DENIED"
	options.RequestsPerSecondByRule["key"] = -1
	result, err := v.ValidateCredential(t.Context(), Credential{RuleID: "key", Secret: "input", Components: map[string]CredentialComponent{"part": {Secret: "companion"}}})
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, result.Validation.Status)
	require.Equal(t, []string{"original"}, v.rules["key"].Tags)
}
