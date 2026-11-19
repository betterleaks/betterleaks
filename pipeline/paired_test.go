package pipeline

import (
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
)

func TestValidationDropsPairedGenericWhenProviderIsLive(t *testing.T) {
	const secret = "k7Qm2pLx9Vw4nR8sT1yU6zA3bC5dE0fH"
	raw := "// api_key\nadafruit = \"" + secret + "\"\n"
	source := fragmentSource{fragments: []sources.Fragment{{Raw: raw}}}

	cfg := pairedValidationConfig(`{"result": "valid"}`)
	runner := mustPipeline(t, cfg, scan.WithWorkers(1))
	var ids []string
	summary, err := runner.Scan(t.Context(), source, func(f report.Finding) error {
		if f.Match.Value == secret {
			ids = append(ids, f.RuleID)
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"adafruit-api-key"}, ids)
	require.Equal(t, 2, summary.DetectedFindings)
	require.Equal(t, 1, summary.EmittedFindings)
	require.Equal(t, 1, summary.ValidationCounts[report.ValidationStatusValid])

	invalid := mustPipeline(t, pairedValidationConfig(`{"result": "invalid"}`), scan.WithWorkers(1))
	ids = nil
	_, err = invalid.Scan(t.Context(), source, func(f report.Finding) error {
		if f.Match.Value == secret {
			ids = append(ids, f.RuleID)
		}
		return nil
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"generic-api-key", "adafruit-api-key"}, ids)

	scanner, err := scan.New(cfg, scan.WithWorkers(1))
	require.NoError(t, err)
	discovery, err := New(scanner, nil)
	require.NoError(t, err)
	ids = nil
	_, err = discovery.Scan(t.Context(), source, func(f report.Finding) error {
		if f.Match.Value == secret {
			ids = append(ids, f.RuleID)
		}
		return nil
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"generic-api-key", "adafruit-api-key"}, ids)
}

func pairedValidationConfig(validation string) *config.Config {
	return &config.Config{Rules: []config.Rule{
		{
			ID:           "adafruit-api-key",
			Description:  "Adafruit key",
			Confidence:   "high",
			Regex:        rulebuilder.Assignment([]string{"adafruit"}, `[a-zA-Z0-9_-]{32}`),
			Keywords:     []string{"adafruit"},
			ValidateExpr: validation,
		},
		{
			ID:          "generic-api-key",
			Description: "generic",
			Confidence:  "low",
			Specificity: -100,
			Regex:       `(?i)(?:api_key|adafruit)[\s'"\x60]{0,3}[:=][\s'"\x60]{0,3}([a-zA-Z0-9_-]{16,})`,
			Keywords:    []string{"key"},
		},
	}}
}
