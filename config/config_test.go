package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/regexp"
)

const configPath = "../testdata/config/"

var regexComparer = func(x, y *regexp.Regexp) bool {
	if x == nil || y == nil {
		return x == y
	}
	return x.String() == y.String()
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
					RuleID:      "generic-api-key",
					Description: "Generic API Key",
					Regex:       regexp.MustCompile(`(?i)(?:key|api|token|secret|client|passwd|password|auth|access)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-z\-_.=]{10,150})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
					Keywords:    []string{"key", "api", "token", "secret", "client", "passwd", "password", "auth", "access"},
					Tags:        []string{},
					Filter:      `entropy(finding["secret"]) <= 3.5`,
				}},
			},
		},
		{
			cfgName: "valid/rule_path_only",
			cfg: &Config{
				Rules: []Rule{{
					RuleID:      "python-files-only",
					Description: "Python Files",
					Path:        regexp.MustCompile(`.py`),
					Keywords:    []string{},
					Tags:        []string{},
				}},
			},
		},
		{
			cfgName: "valid/rule_regex_escaped_character_group",
			cfg: &Config{
				Rules: []Rule{{
					RuleID:      "pypi-upload-token",
					Description: "PyPI upload token",
					Regex:       regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`),
					Keywords:    []string{},
					Tags:        []string{"key", "pypi"},
				}},
			},
		},
		{
			cfgName: "valid/rule_secret_group",
			cfg: &Config{
				Rules: []Rule{{
					RuleID:      "discord-api-key",
					Description: "Discord API key",
					Regex:       regexp.MustCompile(`(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]`),
					SecretGroup: 3,
					Keywords:    []string{},
					Tags:        []string{},
					Filter:      `entropy(finding["secret"]) <= 3.5`,
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
		if rule.Filter != "" {
			_, err = filterRuntime.CompileFilter(rule.Filter, nil)
			require.NoErrorf(t, err, "rule %q filter", rule.RuleID)
		}
		if rule.ValidateExpr != "" {
			_, err = filterRuntime.CompileValidation(rule.ValidateExpr)
			require.NoErrorf(t, err, "rule %q validation", rule.RuleID)
		}
		if rule.AnalyzeExpr != "" {
			_, err = filterRuntime.CompileAnalysis(rule.AnalyzeExpr)
			require.NoErrorf(t, err, "rule %q analysis", rule.RuleID)
		}
	}
}

func TestDefaultConfigIncludesCredentialAnalysisProviders(t *testing.T) {
	cfg, err := Default()
	require.NoError(t, err)
	for _, ruleID := range []string{
		"airtable-personnal-access-token",
		"gitlab-pat",
		"huggingface-access-token",
		"slack-bot-token",
		"github-pat",
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
		require.NotEmptyf(t, rule.Confidence, "rule %q has no confidence", rule.RuleID)
	}
	require.Equal(t, "low", requireRule(t, cfg, "generic-api-key").Confidence)
	require.Equal(t, "medium", requireRule(t, cfg, "box-api-access-token").Confidence)
	require.Equal(t, "high", requireRule(t, cfg, "openai-api-key").Confidence)
	require.Contains(t, requireRule(t, cfg, "generic-api-key").Filter, `\b[a-z0-9]+[_.-]+token\b`)
	require.Contains(t, requireRule(t, cfg, "generic-api-key").Filter, `]) ? "medium" : "low";`)
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
						RuleID:      "aws-access-key",
						Description: "AWS Access Key",
						Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
					},
					{
						RuleID:      "aws-secret-key",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
					},
					{
						RuleID:      "aws-secret-key-again",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
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
						RuleID:   "aws-secret-key",
						Regex:    regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Tags:     []string{"key", "AWS"},
						Keywords: []string{},
					},
					{
						RuleID:   "pypi-upload-token",
						Regex:    regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`),
						Tags:     []string{},
						Keywords: []string{},
					},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_no_regexpath",
			cfg: &Config{
				Rules: []Rule{
					{
						RuleID:      "aws-secret-key-again-again",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
						Filter:      "filter.matchesAny(attributes[\"path\"], [`something.py`])",
					},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_description",
			rules:   []string{"aws-access-key"},
			cfg: &Config{
				Title: "override a built-in rule's description",
				Rules: []Rule{{
					RuleID:      "aws-access-key",
					Description: "Puppy Doggy",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_path",
			rules:   []string{"aws-access-key"},
			cfg: &Config{
				Title: "override a built-in rule's path",
				Rules: []Rule{{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Path:        regexp.MustCompile("(?:puppy)"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_regex",
			rules:   []string{"aws-access-key"},
			cfg: &Config{
				Title: "override a built-in rule's regex",
				Rules: []Rule{{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:a)"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_secret_group",
			rules:   []string{"aws-access-key"},
			cfg: &Config{
				Title: "override a built-in rule's secretGroup",
				Rules: []Rule{{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(a)(a)"),
					SecretGroup: 2,
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_filter",
			rules:   []string{"aws-access-key"},
			cfg: &Config{
				Title: "override a built-in rule's filter",
				Rules: []Rule{{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
					Filter:      `entropy(finding["secret"]) <= 999.0`,
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_keywords",
			rules:   []string{"aws-access-key"},
			cfg: &Config{
				Title: "override a built-in rule's keywords",
				Rules: []Rule{{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{"puppy"},
					Tags:        []string{"key", "AWS"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_tags",
			rules:   []string{"aws-access-key"},
			cfg: &Config{
				Title: "override a built-in rule's tags",
				Rules: []Rule{{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS", "puppy"},
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
	base := &Config{
		Prefilter: basePrefilter,
		Filter:    baseFilter,
	}
	current := &Config{
		Prefilter: currentPrefilter,
		Filter:    currentFilter,
	}

	current.extend(base, extendConfig{}, nil)

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
		cmp.Comparer(regexComparer),
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
		require.ErrorContains(t, err, "[[rules.required]] is not supported; use rules.components")
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
components = []

[[rules]]
id = "child-primary"
regex = "child"
components = [{ id = "component" }]
`, basePath), filepath.Join(tempDir, "child.toml"))
	require.NoError(t, err)
	assert.Empty(t, requireRule(t, cfg, "base-primary").Components, "an explicit empty list should clear inherited components")
	require.Len(t, requireRule(t, cfg, "child-primary").Components, 1, "references should resolve after extension")
}

func loadTestConfig(cfgName string) (*Config, error) {
	return LoadFile(filepath.Join(configPath, cfgName+".toml"))
}

func TestParseTOMLPermissiveUnknownKeysAndPath(t *testing.T) {
	cfg, err := ParseTOMLString(`
title = "custom"
unknownTopLevel = "ignored"

[[rules]]
id = "test-rule"
description = "test rule"
regex = '''test-(secret)'''
unknownRuleKey = "ignored"
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
			name:             "Extend base rule that includes AWS keyword with new attribute",
			cfgName:          "valid/extend_base_rule_including_keywords_with_attribute",
			expectedKeywords: "aws",
		},
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
				for _, keyword := range rule.Keywords {
					if keyword == tt.expectedKeywords {
						found = true
						break
					}
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
