package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
)

func TestExpandRuleFlagShorthands(t *testing.T) {
	t.Parallel()

	args := []string{
		"dir", "-dr", "generic-api-key", "-ir=github-pat",
		"--disable-rule=aws-access-key", "-i", ".", "--", "-dr",
	}

	assert.Equal(t, []string{
		"dir", "--disable-rule", "generic-api-key", "--isolate-rule=github-pat",
		"--disable-rule=aws-access-key", "-i", ".", "--", "-dr",
	}, expandRuleFlagShorthands(args))
	assert.Equal(t, "-dr", args[1], "input must not be mutated")
}

func TestApplyRuleSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		args           []string
		wantRules      []string
		wantHiddenRule string
		wantErr        string
	}{
		{
			name:      "no selection leaves all rules enabled",
			wantRules: []string{"aws", "github", "github-client-id", "slack"},
		},
		{
			name:      "disable removes rules",
			args:      []string{"--disable-rule", "aws,slack"},
			wantRules: []string{"github", "github-client-id"},
		},
		{
			name:      "isolate retains rules",
			args:      []string{"--isolate-rule", "github,slack"},
			wantRules: []string{"github", "github-client-id", "slack"},
		},
		{
			name:      "disable applies after isolate",
			args:      []string{"--isolate-rule", "aws,github", "--disable-rule", "aws"},
			wantRules: []string{"github", "github-client-id"},
		},
		{
			name:           "isolate retains component rules for matching",
			args:           []string{"--isolate-rule", "github"},
			wantRules:      []string{"github", "github-client-id"},
			wantHiddenRule: "github-client-id",
		},
		{
			name:      "disabled component is not restored by isolate",
			args:      []string{"--isolate-rule", "github", "--disable-rule", "github-client-id"},
			wantRules: []string{"github"},
		},
		{
			name:    "unknown isolated rule fails",
			args:    []string{"--isolate-rule", "missing"},
			wantErr: `requested rule "missing" not found in rules`,
		},
		{
			name:    "unknown disabled rule fails",
			args:    []string{"--disable-rule", "missing"},
			wantErr: `requested rule "missing" not found in rules`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			flags := newRuleSelectionTestFlags(t, tt.args)
			originalRules := []config.Rule{
				{RuleID: "aws", Keywords: []string{"aws"}},
				{
					RuleID:   "github",
					Keywords: []string{"github"},
					Components: []*config.Component{
						{RuleID: "github-client-id"},
					},
				},
				{RuleID: "github-client-id", Keywords: []string{"client"}},
				{RuleID: "slack"},
			}
			cfg := &config.Config{Rules: originalRules}

			err := applyRuleSelection(nil, flags, cfg)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.wantRules, ruleIDs(cfg.Rules))
			assert.Len(t, originalRules, 4, "selection must not mutate the loaded config rules")
			if tt.wantHiddenRule != "" {
				assert.True(t, findRule(t, cfg.Rules, tt.wantHiddenRule).SkipReport)
				assert.False(t, findRule(t, originalRules, tt.wantHiddenRule).SkipReport, "selection must not mutate component rules")
			}
		})
	}
}

func newRuleSelectionTestFlags(t *testing.T, args []string) *ScanFlags {
	t.Helper()
	cliArgs := append([]string{"dir"}, args...)
	cli, err := parseCLIForTest(t, cliArgs...)
	require.NoError(t, err)
	return &cli.Directory.ScanFlags
}

func ruleIDs(rules []config.Rule) []string {
	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.RuleID)
	}
	return ids
}

func findRule(t testing.TB, rules []config.Rule, id string) config.Rule {
	t.Helper()
	for _, rule := range rules {
		if rule.RuleID == id {
			return rule
		}
	}
	t.Fatalf("rule %q not found", id)
	return config.Rule{}
}
