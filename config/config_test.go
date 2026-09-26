package config

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/betterleaks/betterleaks/v2/version"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
)

func TestParseTOMLUsesInjectedLogger(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := ParseTOMLString(`
title = "logger test"
`, "test.toml", WithLogger(logger))
	require.NoError(t, err)
	assert.Contains(t, output.String(), "no minVersion specified")
	assert.Contains(t, output.String(), "config_path=test.toml")
}

const configPath = "../testdata/config/"

func TestHashes(t *testing.T) {
	newConfig := func() *Config {
		return &Config{
			Filter: "false", Prefilter: "false",
			Rules: []Rule{
				{ID: "primary", Regex: `(TOKEN)(OTHER)?`, SecretGroup: 1, Specificity: 100,
					Components:   []Component{{RuleID: "required", Within: "5L"}, {RuleID: "optional", Optional: true}},
					ValidateExpr: `{"result":"valid"}`, AnalyzeExpr: `{}`},
				{ID: "required", Regex: `REQUIRED`, SkipReport: true},
				{ID: "optional", Regex: `OPTIONAL`, SkipReport: true},
				{ID: "other", Regex: `OTHER`},
			},
		}
	}
	original := newConfig()
	wantConfig := original.Hash()
	wantRule, err := original.RuleHash("primary")
	require.NoError(t, err)
	assert.Equal(t, "7eea25c39bea00e213445c60c29ac2fe5872e078d95695d5a55df155baae1fd9", wantConfig)
	assert.Equal(t, "036fb0e0df4b98ce6847d8ca567f32b60e5366734f1ab8149c4d29a1e03dea0d", wantRule)
	for _, tc := range []struct {
		name       string
		change     func(*Config)
		configSame bool
		ruleSame   bool
	}{
		{"description", func(c *Config) { c.Rules[0].Description = "updated" }, false, false},
		{"regex", func(c *Config) { c.Rules[0].Regex = `(CHANGED)(OTHER)?` }, false, false},
		{"path", func(c *Config) { c.Rules[0].Path = `\.env$` }, false, false},
		{"secret group", func(c *Config) { c.Rules[0].SecretGroup = 2 }, false, false},
		{"keywords", func(c *Config) { c.Rules[0].Keywords = []string{"TOKEN"} }, false, false},
		{"tags", func(c *Config) { c.Rules[0].Tags = []string{"credential"} }, false, false},
		{"specificity", func(c *Config) { c.Rules[0].Specificity++ }, false, false},
		{"confidence", func(c *Config) { c.Rules[0].Confidence = "high" }, false, false},
		{"rule filter", func(c *Config) { c.Rules[0].FilterExpr = "true" }, false, false},
		{"skip report", func(c *Config) { c.Rules[0].SkipReport = true }, false, false},
		{"component reference", func(c *Config) { c.Rules[0].Components[0].RuleID = "other" }, false, false},
		{"component optionality", func(c *Config) { c.Rules[0].Components[0].Optional = true }, false, false},
		{"component proximity", func(c *Config) { c.Rules[0].Components[0].Within = "10L" }, false, false},
		{"component order", func(c *Config) { slices.Reverse(c.Rules[0].Components) }, false, false},
		{"required component regex", func(c *Config) { c.Rules[1].Regex = "NEW" }, false, false},
		{"optional component regex", func(c *Config) { c.Rules[2].Regex = "NEW" }, false, false},
		{"component filter", func(c *Config) { c.Rules[1].FilterExpr = "true" }, false, false},
		{"global filter", func(c *Config) { c.Filter = "true" }, false, true},
		{"global prefilter", func(c *Config) { c.Prefilter = "true" }, false, true},
		{"other rule", func(c *Config) { c.Rules[3].Regex = "NEW" }, false, true},
		{"other specificity", func(c *Config) { c.Rules[3].Specificity = 200 }, false, true},
		{"rule order", func(c *Config) { slices.Reverse(c.Rules) }, false, true},
		{"validation", func(c *Config) { c.Rules[0].ValidateExpr = "not a valid expression" }, false, false},
		{"analysis", func(c *Config) { c.Rules[0].AnalyzeExpr = "not a valid expression" }, false, false},
		{"revocation", func(c *Config) { c.Rules[0].RevokeExpr = "not a valid expression" }, false, false},
		{"component validation", func(c *Config) { c.Rules[1].ValidateExpr = "changed" }, false, false},
		{"component analysis", func(c *Config) {
			c.Rules[1].ValidateExpr, c.Rules[1].AnalyzeExpr = "changed", "changed"
		}, false, false},
		{"component revocation", func(c *Config) { c.Rules[1].RevokeExpr = "changed" }, false, false},
		{"optional component validation", func(c *Config) { c.Rules[2].ValidateExpr = "changed" }, false, false},
		{"other rule validation", func(c *Config) { c.Rules[3].ValidateExpr = "changed" }, false, true},
		{"config metadata", func(c *Config) {
			c.Title, c.Description, c.Path, c.MinVersion = "new", "new", "/elsewhere/config.toml", "v99.0.0"
		}, true, true},
		{"nil and empty slices", func(c *Config) {
			c.Rules[0].Keywords, c.Rules[0].Tags, c.Rules[1].Components = []string{}, []string{}, []Component{}
		}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newConfig()
			tc.change(cfg)
			gotRule, err := cfg.RuleHash("primary")
			require.NoError(t, err)
			hashes, err := cfg.RuleHashes()
			require.NoError(t, err)
			assert.Equal(t, gotRule, hashes["primary"])
			assert.Equal(t, tc.configSame, wantConfig == cfg.Hash(), "config hash equality")
			assert.Equal(t, tc.ruleSame, wantRule == gotRule, "rule hash equality")
		})
	}
	t.Run("rule ID", func(t *testing.T) {
		cfg := newConfig()
		cfg.Rules[0].ID = "renamed"
		gotRule, err := cfg.RuleHash("renamed")
		require.NoError(t, err)
		assert.NotEqual(t, wantRule, gotRule)
		assert.NotEqual(t, wantConfig, cfg.Hash())
	})
	// Hashing reads current values without mutating or memoizing the config.
	assert.Equal(t, newConfig(), original)
	assert.Equal(t, wantConfig, original.Hash())
	gotRule, err := original.RuleHash("primary")
	require.NoError(t, err)
	assert.Equal(t, wantRule, gotRule)
	original.Rules[1].Regex = "CHANGED"
	assert.NotEqual(t, wantConfig, original.Hash())
	gotRule, err = original.RuleHash("primary")
	require.NoError(t, err)
	assert.NotEqual(t, wantRule, gotRule)
}

func TestHashEncoding(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b []string
	}{
		{"field boundaries", []string{"ab", "c"}, []string{"a", "bc"}},
		{"embedded separator", []string{"a\x00b", "c"}, []string{"a", "b\x00c"}},
		{"invalid UTF-8", []string{"\xff"}, []string{"\xfe"}},
		{"slice length", nil, []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Config{Rules: []Rule{{ID: "test", Regex: "TOKEN", Tags: tc.a}}}
			b := &Config{Rules: []Rule{{ID: "test", Regex: "TOKEN", Tags: tc.b}}}
			assert.NotEqual(t, a.Hash(), b.Hash())
			ah, err := a.RuleHash("test")
			require.NoError(t, err)
			bh, err := b.RuleHash("test")
			require.NoError(t, err)
			assert.NotEqual(t, ah, bh)
		})
	}
}

func TestRuleHashErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *Config
		id   string
		want string
	}{
		{"nil", nil, "test", "config is required"},
		{"unknown", &Config{}, "test", `rule "test" not found`},
		{"missing component", &Config{Rules: []Rule{{ID: "test", Regex: "TOKEN", Components: []Component{{RuleID: "missing"}}}}}, "test", "does not exist"},
		{"duplicate", &Config{Rules: []Rule{{ID: "test", Regex: "A"}, {ID: "test", Regex: "B"}}}, "test", "duplicate rule ID"},
		{"nested components", &Config{Rules: []Rule{
			{ID: "test", Regex: "A", Components: []Component{{RuleID: "nested"}}},
			{ID: "nested", Regex: "B", Components: []Component{{RuleID: "leaf"}}},
			{ID: "leaf", Regex: "C"},
		}}, "test", "must not itself have components"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := tc.cfg.RuleHash(tc.id)
			require.ErrorContains(t, err, tc.want)
			assert.Empty(t, hash)
		})
	}
	assert.Empty(t, (*Config)(nil).Hash())
}

func TestHashesResolvedConfig(t *testing.T) {
	const plain = `filter = 'false'
[[rules]]
id = 'test'
regex = '(TOKEN)'
secretGroup = 1
`
	const formatted = `# Formatting and source location do not identify the ruleset.
filter='false'

[[rules]] # rule comment
id="test"
regex="(TOKEN)"
secretGroup=1
`
	a, err := ParseTOMLString(plain, "first.toml")
	require.NoError(t, err)
	b, err := ParseTOMLString(formatted, "second.toml")
	require.NoError(t, err)
	assert.Equal(t, a.Hash(), b.Hash())
	ah, err := a.RuleHash("test")
	require.NoError(t, err)
	bh, err := b.RuleHash("test")
	require.NoError(t, err)
	assert.Equal(t, ah, bh)
	assert.Equal(t, "025e0865f67aa331e50d02e8a638eed9e3c761ddebe399f0accaf32ac13bb8a6", a.Hash())
	assert.Equal(t, "276517af2a9452977d37603713da1d5a1f5d0e8f84ae9f48ba2c1adc0427d700", ah)
	basePath := filepath.Join(t.TempDir(), "base.toml")
	require.NoError(t, os.WriteFile(basePath, []byte(plain), 0o600))
	extended, err := ParseTOMLString(fmt.Sprintf("[extend]\npath = '%s'\n", filepath.ToSlash(basePath)), "extended.toml")
	require.NoError(t, err)
	assert.Equal(t, a.Hash(), extended.Hash())
	extendedHash, err := extended.RuleHash("test")
	require.NoError(t, err)
	assert.Equal(t, ah, extendedHash)
}

type translateCase struct {
	// Configuration file basename to load, from `../testdata/config/`.
	cfgName string
	// Expected result.
	cfg *Config
	// Rules to compare.
	rules []string
	// Error to expect.
	wantError error
}

func TestTranslate(t *testing.T) {
	tests := []translateCase{
		// Valid
		{
			cfgName: "generic",
			cfg: &Config{
				Title: "gitleaks config",
				Rules: []Rule{{
					ID:          "generic-api-key",
					Description: "Generic API Key",
					Regex:       `(?i)(?:key|api|token|secret|client|passwd|password|auth|access)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-z\-_.=]{10,150})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
					Keywords:    []string{"key", "api", "token", "secret", "client", "passwd", "password", "auth", "access"},
					Tags:        []string{},
					FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
				}},
			},
		},
		{
			cfgName: "valid/rule_path_only",
			cfg: &Config{
				Rules: []Rule{{
					ID:          "python-files-only",
					Description: "Python Files",
					Path:        `.py`,
					Keywords:    []string{},
					Tags:        []string{},
				}},
			},
		},
		{
			cfgName: "valid/rule_regex_escaped_character_group",
			cfg: &Config{
				Rules: []Rule{{
					ID:          "pypi-upload-token",
					Description: "PyPI upload token",
					Regex:       `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`,
					Keywords:    []string{},
					Tags:        []string{"key", "pypi"},
				}},
			},
		},
		{
			cfgName: "valid/rule_secret_group",
			cfg: &Config{
				Rules: []Rule{{
					ID:          "discord-api-key",
					Description: "Discord API key",
					Regex:       `(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]`,
					SecretGroup: 3,
					Keywords:    []string{},
					Tags:        []string{},
					FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
				}},
			},
		},

		// Invalid
		{
			cfgName:   "invalid/rule_missing_id",
			cfg:       &Config{},
			wantError: errors.New("rule |id| is missing or empty, description: Discord API key, regex: (?i)(discord[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-h0-9]{64})['\\\"]"),
		},
		{
			cfgName:   "invalid/rule_no_regex_or_path",
			cfg:       &Config{},
			wantError: errors.New("discord-api-key: both |regex| and |path| are empty, this rule will have no effect"),
		},
		{
			cfgName:   "invalid/rule_bad_secret_group",
			cfg:       &Config{},
			wantError: errors.New("discord-api-key: invalid regex secret group 5, max regex secret group 3"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.cfgName, func(t *testing.T) {
			testTranslate(t, tt)
		})
	}
}

func TestDefaultConfigExpressionsCompileWithExpr(t *testing.T) {
	cfg, err := Default()
	require.NoError(t, err)

	filterRuntime, err := exprruntime.New(nil)
	require.NoError(t, err)
	if cfg.Prefilter != "" {
		_, err = filterRuntime.CompilePrefilter(cfg.Prefilter)
		require.NoError(t, err, "global prefilter")
	}
	if cfg.Filter != "" {
		_, err = filterRuntime.CompileFilter(cfg.Filter, nil)
		require.NoError(t, err, "global filter")
	}

	for _, rule := range cfg.Rules {
		if rule.FilterExpr != "" {
			_, err = filterRuntime.CompileFilter(rule.FilterExpr, nil)
			require.NoErrorf(t, err, "rule %q filter", rule.ID)
		}
		if rule.ValidateExpr != "" {
			_, err = filterRuntime.CompileValidation(rule.ValidateExpr)
			require.NoErrorf(t, err, "rule %q validation", rule.ID)
		}
		if rule.AnalyzeExpr != "" {
			_, err = filterRuntime.CompileAnalysis(rule.AnalyzeExpr)
			require.NoErrorf(t, err, "rule %q analysis", rule.ID)
		}
		if rule.RevokeExpr != "" {
			_, err = filterRuntime.CompileRevocation(rule.RevokeExpr)
			require.NoErrorf(t, err, "rule %q revocation", rule.ID)
		}
	}
}

func TestDefaultConfigIncludesCredentialAnalysisProviders(t *testing.T) {
	cfg, err := Default()
	require.NoError(t, err)
	for _, ruleID := range []string{
		"aws-access-token",
		"airtable-personnal-access-token",
		"gitlab-pat",
		"huggingface-access-token",
		"slack-bot-token",
		"github-pat",
		"fastly-api-token",
		"cloudflare-api-key.1",
		"cloudflare-api-key.2",
		"buildkite-user-access-token",
		"honeycomb-api-key",
		"algolia-api-key",
		"vercel-api-token",
		"vercel-personal-access-token",
	} {
		rule := requireRule(t, cfg, ruleID)
		require.NotEmptyf(t, rule.ValidateExpr, "%s validation", ruleID)
		require.NotEmptyf(t, rule.AnalyzeExpr, "%s analysis", ruleID)
	}
}

func TestGenericRuleConfidence(t *testing.T) {
	cfg, err := Default()
	require.NoError(t, err)
	for _, rule := range cfg.Rules {
		require.NotEmptyf(t, rule.Confidence, "rule %q has no confidence", rule.ID)
	}
	require.Equal(t, "low", requireRule(t, cfg, "generic-api-key").Confidence)
	require.Equal(t, "medium", requireRule(t, cfg, "box-api-access-token").Confidence)
	require.Equal(t, "high", requireRule(t, cfg, "openai-api-key").Confidence)
	require.Contains(t, requireRule(t, cfg, "generic-api-key").FilterExpr, `\b[a-z0-9]+[_.-]+token\b`)
	require.Contains(t, requireRule(t, cfg, "generic-api-key").FilterExpr, `]) ? "medium" : "low";`)
}

func TestRuleConfidence(t *testing.T) {
	cfg, err := ParseTOMLString(`
[[rules]]
id = "test"
regex = "secret"
confidence = "high"
`, "")
	require.NoError(t, err)
	require.Equal(t, "high", requireRule(t, cfg, "test").Confidence)

	_, err = ParseTOMLString(`
[[rules]]
id = "test"
regex = "secret"
confidence = "certain"
`, "")
	require.ErrorContains(t, err, "invalid confidence")
}

func TestMinVersion(t *testing.T) {
	cfg, err := ParseTOMLString(`
minVersion = "v1.8.0"

[[rules]]
id = "test"
regex = "secret"
`, "")
	require.NoError(t, err)
	require.Equal(t, "v1.8.0", cfg.MinVersion)

	_, err = ParseTOMLString(`
minVersion = "not-a-version"

[[rules]]
id = "test"
regex = "secret"
`, "")
	require.ErrorContains(t, err, "invalid minVersion")

}

func TestTranslateExtend(t *testing.T) {
	tests := []translateCase{
		// Valid
		{
			cfgName: "valid/extend",
			cfg: &Config{
				Rules: []Rule{
					{
						ID:          "aws-access-key",
						Description: "AWS Access Key",
						Regex:       "(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
					},
					{
						ID:          "aws-secret-key",
						Description: "AWS Secret Key",
						Regex:       `(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`,
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
					},
					{
						ID:          "aws-secret-key-again",
						Description: "AWS Secret Key",
						Regex:       `(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`,
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
					},
				},
			},
		},
		{
			cfgName: "valid/extend_disabled",
			cfg: &Config{
				Title: "gitleaks extend disable",
				Rules: []Rule{
					{
						ID:       "aws-secret-key",
						Regex:    `(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`,
						Tags:     []string{"key", "AWS"},
						Keywords: []string{},
					},
					{
						ID:       "pypi-upload-token",
						Regex:    `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`,
						Tags:     []string{},
						Keywords: []string{},
					},
				},
			},
		},
		// Invalid
		{
			cfgName:   "invalid/extend_invalid_ruleid",
			wantError: errors.New("rule |id| is missing or empty"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.cfgName, func(t *testing.T) {
			testTranslate(t, tt)
		})
	}
}

func TestExtendGlobalExpressions(t *testing.T) {
	const (
		basePrefilter    = `let base = attributes["path"] == "base"; base`
		currentPrefilter = `let current = attributes["path"] == "current"; current`
		baseFilter       = `let base = finding["secret"] == "base"; base`
		currentFilter    = `let current = finding["secret"] == "current"; current`
	)
	basePath := filepath.Join(t.TempDir(), "base.toml")
	require.NoError(t, os.WriteFile(basePath, fmt.Appendf(nil, "prefilter = %q\nfilter = %q\n", basePrefilter, baseFilter), 0o600))
	current, err := ParseTOMLString(fmt.Sprintf("prefilter = %q\nfilter = %q\n[extend]\npath = %q\n", currentPrefilter, currentFilter, basePath), "")
	require.NoError(t, err)

	require.Equal(t, "(\n"+basePrefilter+"\n) || (\n"+currentPrefilter+"\n)", current.Prefilter)
	require.Equal(t, "(\n"+baseFilter+"\n) || (\n"+currentFilter+"\n)", current.Filter)

	env, err := exprruntime.New(nil)
	require.NoError(t, err)

	prefilter, err := env.CompilePrefilter(current.Prefilter)
	require.NoError(t, err)
	for _, path := range []string{"base", "current"} {
		skip, err := env.EvalPrefilter(prefilter, map[string]string{"path": path})
		require.NoError(t, err)
		require.Truef(t, skip, "extended prefilter should suppress %q", path)
	}
	skip, err := env.EvalPrefilter(prefilter, map[string]string{"path": "other"})
	require.NoError(t, err)
	require.False(t, skip)

	filter, err := env.CompileFilter(current.Filter, nil)
	require.NoError(t, err)
	for _, secret := range []string{"base", "current"} {
		skip, err := env.EvalFilter(filter, map[string]any{"secret": secret}, nil)
		require.NoError(t, err)
		require.Truef(t, skip, "extended filter should suppress %q", secret)
	}
	skip, err = env.EvalFilter(filter, map[string]any{"secret": "other"}, nil)
	require.NoError(t, err)
	require.False(t, skip)
}

func TestExtendDefaultKeepsGlobalPrefilters(t *testing.T) {
	cfg, err := ParseTOMLString(`
prefilter = '''attributes["path"] == "local.ignore"'''

[extend]
useDefault = true
`, "")
	require.NoError(t, err)

	env, err := exprruntime.New(nil)
	require.NoError(t, err)
	prefilter, err := env.CompilePrefilter(cfg.Prefilter)
	require.NoError(t, err)

	for _, path := range []string{"go.sum", "local.ignore"} {
		skip, err := env.EvalPrefilter(prefilter, map[string]string{"path": path})
		require.NoError(t, err)
		require.Truef(t, skip, "extended default prefilter should suppress %q", path)
	}
	skip, err := env.EvalPrefilter(prefilter, map[string]string{"path": "main.go"})
	require.NoError(t, err)
	require.False(t, skip)
}

func TestExtendGlobalExpressionsWithEmptySide(t *testing.T) {
	for _, tt := range []struct {
		name    string
		base    string
		current string
		want    string
	}{
		{name: "neither", want: ""},
		{name: "base only", base: "base", want: "base"},
		{name: "current only", current: "current", want: "current"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, extendGlobalExpr(tt.base, tt.current))
		})
	}
}

func testTranslate(t *testing.T, test translateCase) {
	t.Helper()
	cfg, err := loadTestConfig(test.cfgName)
	if err != nil {
		if test.wantError != nil {
			assert.EqualError(t, err, test.wantError.Error())
		} else {
			require.NoError(t, err)
		}
		return
	}
	if test.wantError != nil {
		t.Fatalf("expected error but got none: %v", test.wantError)
		return
	}

	if len(test.rules) > 0 {
		rules := make([]Rule, 0, len(test.rules))
		for _, name := range test.rules {
			rules = append(rules, requireRule(t, cfg, name))
		}
		cfg.Rules = rules
	}

	opts := cmp.Options{
		cmpopts.IgnoreFields(Rule{}, "Specificity"),
		cmpopts.IgnoreUnexported(Rule{}),
	}
	if diff := cmp.Diff(test.cfg.Title, cfg.Title); diff != "" {
		t.Errorf("%s diff: (-want +got)\n%s", test.cfgName, diff)
	}
	if diff := cmp.Diff(test.cfg.Rules, cfg.Rules, opts); diff != "" {
		t.Errorf("%s diff: (-want +got)\n%s", test.cfgName, diff)
	}
}

func TestRuleSpecificity(t *testing.T) {
	cfg, err := ParseTOMLString(`
[[rules]]
id = "default"
regex = "default"

[[rules]]
id = "fallback"
regex = "fallback"
specificity = 0
`, "")
	require.NoError(t, err)
	assert.Equal(t, DefaultRuleSpecificity, requireRule(t, cfg, "default").Specificity)
	assert.Equal(t, 0, requireRule(t, cfg, "fallback").Specificity)
}

func TestExtendedRuleReplacesBase(t *testing.T) {
	basePath := filepath.Join(t.TempDir(), "base.toml")
	require.NoError(t, os.WriteFile(basePath, []byte(`
[[rules]]
id = "token"
description = "base description"
regex = '(TOKEN)'
path = 'base.env'
secretGroup = 1
specificity = 17
skipReport = true
confidence = "high"
keywords = ["BASE"]
tags = ["base"]
filter = "true"
validate = 'base validation'
analyze = 'base analysis'
revoke = 'base revocation'
components = [{ id = "part", within = "2L" }]
[[rules]]
id = "part"
regex = 'PART'
`), 0o600))
	for _, fields := range []string{
		"regex = 'CHILD'",
		"path = 'child.env'",
		"regex = '(CHILD)'\nsecretGroup = 1\nspecificity = 0\nskipReport = true\nkeywords = ['CHILD']\ntags = ['child']",
	} {
		t.Run(fields, func(t *testing.T) {
			child := "[[rules]]\nid = 'token'\n" + fields
			standalone, err := ParseTOMLString(child, "")
			require.NoError(t, err)
			extended, err := ParseTOMLString(fmt.Sprintf("[extend]\npath = %q\n%s", basePath, child), "")
			require.NoError(t, err)
			require.Len(t, extended.Rules, 2)
			assert.Equal(t, requireRule(t, standalone, "token"), requireRule(t, extended, "token"))
			assert.Equal(t, "PART", requireRule(t, extended, "part").Regex)
		})
	}
}

func TestNestedRuleReplacement(t *testing.T) {
	dir := t.TempDir()
	basePath, middlePath := filepath.Join(dir, "base.toml"), filepath.Join(dir, "middle.toml")
	require.NoError(t, os.WriteFile(basePath, []byte(`
[[rules]]
id = "token"
regex = '(TOKEN)'
secretGroup = 1
specificity = 17
skipReport = true
keywords = ["BASE"]
tags = ["base"]
components = [{ id = "part", within = "2L" }]

[[rules]]
id = "disabled"
regex = 'DISABLED'
`), 0o600))
	require.NoError(t, os.WriteFile(middlePath, fmt.Appendf(nil, `[extend]
path = %q
[[rules]]
id = "token"
regex = 'MIDDLE'
secretGroup = 0
specificity = 0
skipReport = false
keywords = ["MIDDLE"]
tags = ["middle"]
`, basePath), 0o600))
	cfg, err := ParseTOMLString(fmt.Sprintf(`[extend]
path = %q
disabledRules = ["disabled"]
[[rules]]
id = "token"
regex = 'CHILD'
keywords = ["CHILD"]
tags = ["child"]
[[rules]]
id = "part"
regex = 'PART'
`, middlePath), filepath.Join(dir, "child.toml"))
	require.NoError(t, err)
	require.Len(t, cfg.Rules, 2)
	require.Equal(t, "part", cfg.Rules[0].ID)
	require.Equal(t, DefaultRuleSpecificity, cfg.Rules[0].Specificity)
	rule := requireRule(t, cfg, "token")
	assert.Zero(t, rule.SecretGroup)
	assert.Equal(t, DefaultRuleSpecificity, rule.Specificity)
	assert.Equal(t, "CHILD", rule.Regex)
	assert.False(t, rule.SkipReport)
	assert.Equal(t, []string{"child"}, rule.Keywords)
	assert.Equal(t, []string{"child"}, rule.Tags)
	assert.Empty(t, rule.Components)
}

func TestExtendDefaultReplacesRule(t *testing.T) {
	cfg, err := ParseTOMLString(`[extend]
useDefault = true
[[rules]]
id = "github-pat"
regex = 'CUSTOM'
specificity = 0
skipReport = true
`, "")
	require.NoError(t, err)
	rule := requireRule(t, cfg, "github-pat")
	assert.Zero(t, rule.Specificity)
	assert.True(t, rule.SkipReport)
	assert.Equal(t, "CUSTOM", rule.Regex)
	assert.Empty(t, rule.Keywords)
	assert.Greater(t, len(cfg.Rules), 1)
}

func TestInheritanceValidatesResolvedRules(t *testing.T) {
	for _, test := range []struct {
		name, baseRegex, override, wantError string
	}{
		{name: "replace regex and reset group", baseRegex: "(TOKEN)", override: "regex = 'VALUE'\nsecretGroup = 0"},
		{name: "omitted group defaults to zero", baseRegex: "(TOKEN)", override: "regex = 'VALUE'"},
		{name: "replace invalid inherited regex", baseRegex: "(", override: "regex = '(VALUE)'"},
		{name: "partial override is invalid", baseRegex: "(TOKEN)", override: "description = 'partial'", wantError: "both |regex| and |path| are empty"},
		{name: "own group must fit", baseRegex: "(TOKEN)", override: "regex = 'VALUE'\nsecretGroup = 1", wantError: "max regex secret group 0"},
		{name: "cannot clear both patterns", baseRegex: "(TOKEN)", override: "regex = ''\nsecretGroup = 0", wantError: "both |regex| and |path| are empty"},
	} {
		t.Run(test.name, func(t *testing.T) {
			basePath := filepath.Join(t.TempDir(), "base.toml")
			require.NoError(t, os.WriteFile(basePath, fmt.Appendf(nil, "[[rules]]\nid = 'token'\nregex = %q\nsecretGroup = 1\n", test.baseRegex), 0o600))
			_, err := ParseTOMLString(fmt.Sprintf("[extend]\npath = %q\n[[rules]]\nid = 'token'\n%s\n", basePath, test.override), "")
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestComponents(t *testing.T) {
	t.Run("new syntax", func(t *testing.T) {
		cfg, err := ParseTOMLString(`
[[rules]]
id = "primary"
regex = "primary"
components = [
  { id = "required-component", optional = false, within = "5L" },
  { id = "optional-component", optional = true, within = "-12C,+4C" },
]

[[rules]]
id = "required-component"
regex = "required"

[[rules]]
id = "optional-component"
regex = "optional"
`, "")
		require.NoError(t, err)
		components := requireRule(t, cfg, "primary").Components
		require.Len(t, components, 2)
		assert.False(t, components[0].Optional)
		assert.Equal(t, "5L", components[0].Within)
		assert.True(t, components[1].Optional)
		assert.Equal(t, "-12C,+4C", components[1].Within)
	})

	t.Run("removed required syntax is rejected", func(t *testing.T) {
		_, err := ParseTOMLString(`
[[rules]]
id = "primary"
regex = "primary"
[[rules.required]]
id = "component"
`, "")
		require.ErrorContains(t, err, "rules.required")
	})
}

func TestComponentValidation(t *testing.T) {
	_, err := ParseTOMLString(`
[[rules]]
id = "primary"
regex = "primary"
components = [{ id = "component", optional = "yes" }]
`, "")
	require.ErrorContains(t, err, "Optional")

	tests := []struct {
		name       string
		components string
		want       string
	}{
		{name: "empty ID", components: `{ id = "" }`, want: "component rule ID is empty"},
		{name: "invalid within unit", components: `{ id = "component", within = "10X" }`, want: "invalid within value"},
		{name: "malformed within", components: `{ id = "component", within = "10L-" }`, want: "invalid within value"},
		{name: "missing rule", components: `{ id = "missing" }`, want: "does not exist"},
		{name: "duplicate ID", components: `{ id = "component" }, { id = "component", optional = true }`, want: "duplicate component rule ID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTOMLString(fmt.Sprintf(`
[[rules]]
id = "primary"
regex = "primary"
components = [%s]

[[rules]]
id = "component"
regex = "component"
`, tt.components), "")
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestComponentsWithExtend(t *testing.T) {
	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "base.toml")
	require.NoError(t, os.WriteFile(basePath, []byte(`
[[rules]]
id = "base-primary"
regex = "primary"
components = [{ id = "component" }]

[[rules]]
id = "component"
regex = "component"
`), 0o600))

	cfg, err := ParseTOMLString(fmt.Sprintf(`
[extend]
path = %q

[[rules]]
id = "base-primary"
regex = "replacement"
components = []

[[rules]]
id = "child-primary"
regex = "child"
components = [{ id = "component" }]
`, basePath), filepath.Join(tempDir, "child.toml"))
	require.NoError(t, err)
	assert.Empty(t, requireRule(t, cfg, "base-primary").Components, "an explicit empty list should clear inherited components")
	require.Len(t, requireRule(t, cfg, "child-primary").Components, 1, "references should resolve after extension")

	cfg, err = ParseTOMLString(fmt.Sprintf(`[extend]
path = %q
[[rules]]
id = "base-primary"
regex = "replacement"
components = [{ id = "component", optional = true, within = "7L" }]
`, basePath), "")
	require.NoError(t, err)
	assert.Equal(t, []Component{{RuleID: "component", Optional: true, Within: "7L"}}, requireRule(t, cfg, "base-primary").Components)
}

func loadTestConfig(cfgName string) (*Config, error) {
	return LoadFile(filepath.Join(configPath, cfgName+".toml"))
}

func TestParseTOMLPreservesPath(t *testing.T) {
	cfg, err := ParseTOMLString(`
title = "custom"

[[rules]]
id = "test-rule"
description = "test rule"
regex = '''test-(secret)'''
`, "/tmp/custom.toml")
	require.NoError(t, err)

	require.Equal(t, "custom", cfg.Title)
	require.Equal(t, "/tmp/custom.toml", cfg.Path)
	_, exists := cfg.Rule("test-rule")
	require.True(t, exists)
}

func TestExtendedRuleKeywordsAreDowncase(t *testing.T) {
	tests := []struct {
		name             string
		cfgName          string
		expectedKeywords string
	}{
		{
			name:             "Extend base with a new rule with CMS keyword",
			cfgName:          "valid/extend_rule_new",
			expectedKeywords: "cms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadTestConfig(tt.cfgName)
			require.NoError(t, err)

			found := false
			for _, rule := range cfg.Rules {
				if slices.Contains(rule.Keywords, tt.expectedKeywords) {
					found = true
				}
			}
			require.Truef(t, found, "The expected keyword %s did not exist in any rule", tt.expectedKeywords)
		})
	}
}

func requireRule(t testing.TB, cfg *Config, id string) Rule {
	t.Helper()
	rule, ok := cfg.Rule(id)
	require.Truef(t, ok, "rule %q not found", id)
	return rule
}

func BenchmarkParseConfig(b *testing.B) {
	for _, test := range []struct{ name, content string }{
		{"default", defaultConfig},
		{"extend-default", "[extend]\nuseDefault = true\n[[rules]]\nid = 'github-pat'\nregex = 'CUSTOM'\ndescription = 'custom'\n"},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := ParseTOMLString(test.content, ""); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestParseTOMLRejectsUnknownFields(t *testing.T) {
	for _, test := range []struct{ name, content, field string }{
		{"top level", "minVerison = 'v2.0.0'", "minVerison"},
		{"rule", "[[rules]]\nid = 'token'\nregex = 'TOKEN'\nvalidte = 'true'", "rules.validte"},
		{"component", "[[rules]]\nid = 'token'\nregex = 'TOKEN'\ncomponents = [{id = 'part', optonal = true}]", "rules.components.optonal"},
		{"extension", "[extend]\nuseDefaut = true", "extend.useDefaut"},
		{"unsupported URL", "[extend]\nurl = 'https://example.invalid/rules.toml'", "extend.url"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := ParseTOMLString(test.content, "custom.toml")
			require.Nil(t, cfg)
			require.ErrorContains(t, err, test.field)
			require.ErrorContains(t, err, "custom.toml")
			require.ErrorContains(t, err, "line ")
			var strict *toml.StrictMissingError
			require.ErrorAs(t, err, &strict)

			basePath := filepath.Join(t.TempDir(), "base.toml")
			require.NoError(t, os.WriteFile(basePath, []byte(test.content), 0o600))
			_, err = ParseTOMLString(fmt.Sprintf("[extend]\npath = %q\n[[rules]]\nid = 'token'\nregex = 'REPLACEMENT'", basePath), "child.toml")
			require.ErrorContains(t, err, test.field)
			require.ErrorContains(t, err, fmt.Sprintf("%q", basePath))
		})
	}
}

func TestExtensionDepth(t *testing.T) {
	for _, extensions := range []int{2, 3} {
		dir := t.TempDir()
		base := filepath.Join(dir, "base.toml")
		require.NoError(t, os.WriteFile(base, []byte("[[rules]]\nid = 'base'\nregex = 'TOKEN'"), 0o600))
		for i := range extensions {
			path := filepath.Join(dir, fmt.Sprintf("level%d.toml", i))
			require.NoError(t, os.WriteFile(path, fmt.Appendf(nil, "[extend]\npath = %q", base), 0o600))
			base = path
		}
		cfg, err := LoadFile(base)
		if extensions == 2 {
			require.NoError(t, err)
			require.Len(t, cfg.Rules, 1)
			require.Equal(t, "base", cfg.Rules[0].ID)
		} else {
			require.Nil(t, cfg)
			require.ErrorContains(t, err, "maximum depth of 2")
		}
	}
	t.Run("cycle", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cycle.toml")
		require.NoError(t, os.WriteFile(path, fmt.Appendf(nil, "[extend]\npath = %q", path), 0o600))
		_, err := LoadFile(path)
		require.ErrorContains(t, err, "maximum depth of 2")
	})
	t.Run("default extension counts toward limit", func(t *testing.T) {
		dir := t.TempDir()
		base, middle := filepath.Join(dir, "base.toml"), filepath.Join(dir, "middle.toml")
		require.NoError(t, os.WriteFile(base, []byte("[extend]\nuseDefault = true"), 0o600))
		require.NoError(t, os.WriteFile(middle, fmt.Appendf(nil, "[extend]\npath = %q", base), 0o600))
		_, err := ParseTOMLString(fmt.Sprintf("[extend]\npath = %q", middle), "")
		require.ErrorContains(t, err, "maximum depth of 2")
	})
}

func TestMinVersionEnforcement(t *testing.T) {
	original := version.Version
	t.Cleanup(func() { version.Version = original })
	for _, test := range []struct{ name, current, minimum, wantError string }{
		{"older stable", "v1.9.0", "v2.0.0-rc.1", "requires Betterleaks"},
		{"older prerelease", "v2.0.0-beta.1", "v2.0.0-rc.1", "requires Betterleaks"},
		{"first RC", "v2.0.0-rc.1", "v2.0.0-rc.1", ""},
		{"later RC", "v2.0.0-rc.2", "v2.0.0-rc.1", ""},
		{"stable", "v2.0.0", "v2.0.0-rc.1", ""},
		{"RC below stable", "v2.0.0-rc.1", "v2.0.0", "requires Betterleaks"},
		{"development build", "dev", "v9.0.0", ""},
		{"invalid minimum on dev", "dev", "invalid", "invalid minVersion"},
		{"invalid current", "invalid", "v2.0.0", "unable to parse current"},
	} {
		t.Run(test.name, func(t *testing.T) {
			version.Version = test.current
			_, err := ParseTOMLString(fmt.Sprintf("minVersion = %q", test.minimum), "versioned.toml")
			if test.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantError)
			}
		})
	}
	t.Run("extended minimum is enforced", func(t *testing.T) {
		version.Version = "v2.0.0-rc.1"
		path := filepath.Join(t.TempDir(), "base.toml")
		require.NoError(t, os.WriteFile(path, []byte("minVersion = 'v9.0.0'"), 0o600))
		_, err := ParseTOMLString(fmt.Sprintf("[extend]\npath = %q", path), "")
		require.ErrorContains(t, err, "requires Betterleaks v9.0.0")
		require.ErrorContains(t, err, fmt.Sprintf("%q", path))
	})
}
