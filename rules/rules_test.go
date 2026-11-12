package rules

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/analyze"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
	"github.com/betterleaks/betterleaks/v2/internal/ruletest"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

var engines = []regexp.Engine{regexp.Stdlib{}, re2.RE2{}}

// TestRules runs every rule's tests. Focus on one provider with:
//
//	go test ./rules -run TestRules/acme
func TestRules(t *testing.T) {
	cfg, err := rulebuilder.Config()
	require.NoError(t, err)
	runners := make([]*ruletest.Runner, len(engines))
	for i, engine := range engines {
		runners[i], err = ruletest.New(cfg, engine)
		require.NoError(t, err)
	}
	for _, rule := range cfg.Rules {
		t.Run(rule.ID, func(t *testing.T) {
			for i, engine := range engines {
				failures, err := runners[i].Run(t.Context(), rule)
				require.NoError(t, err)
				for _, failure := range failures {
					t.Errorf("%s: %s test %q: %v", rulebuilder.File(rule.ID), engine.Version(), failure.Test, failure.Err)
				}
			}
		})
	}
}

// TestDefaultConfigPrecedence runs each positive test with every rule active,
// so a new rule cannot silently hide an existing one through overlap or
// specificity. TestRules isolates each rule and cannot see this.
func TestDefaultConfigPrecedence(t *testing.T) {
	cfg, err := rulebuilder.Config()
	require.NoError(t, err)
	scanners := make([]*scan.Scanner, len(engines))
	for i, engine := range engines {
		scanners[i], err = scan.New(cfg, scan.WithRegexEngine(engine), scan.WithWorkers(1))
		require.NoError(t, err)
	}
	for _, rule := range cfg.Rules {
		if rule.SkipReport {
			continue // Components only report through their parents.
		}
		t.Run(rule.ID, func(t *testing.T) {
			for _, test := range rule.Tests {
				if len(test.Expect) == 0 {
					continue
				}
				want := rule.ID
				if winner, ok := intendedOverrides[rule.ID+"/"+test.Name]; ok {
					want = winner
				}
				for i, engine := range engines {
					var got []string
					_, err := scanners[i].Scan(t.Context(), testFragment(test), func(f report.Finding) error {
						got = append(got, f.RuleID)
						return nil
					})
					require.NoError(t, err)
					if !slices.Contains(got, want) {
						t.Errorf("%s: %s test %q: no %s finding with every rule active; got %v",
							rulebuilder.File(rule.ID), engine.Version(), test.Name, want, got)
					}
				}
			}
		})
	}
}

// intendedOverrides lists positive tests whose secret another, more specific
// rule reports in the full config, keyed by "rule/test" and valued by the
// winning rule.
var intendedOverrides = map[string]string{
	"generic-api-key/assignment":             "clojars-api-token",
	"generic-credential-uri/true positive 8": "mongodb-connection-string",
	// Specificity -50 defers to the dedicated token rule.
	"gitlab-incoming-mail-address-token/true positive 4": "gitlab-incoming-mail-token",
}

// testFragment scans a rule test's input as a single file.
type testFragment config.RuleTest

func (f testFragment) Fragments(_ context.Context, yield sources.FragmentsFunc) error {
	return yield(sources.Fragment{Raw: f.Input, Attributes: f.Attributes, StartLine: 1}, nil)
}

// TestCompile checks every regex and provider expression, including rules
// without tests.
func TestCompile(t *testing.T) {
	cfg, err := rulebuilder.Config()
	require.NoError(t, err)
	for _, engine := range engines {
		_, err := scan.New(cfg, scan.WithRegexEngine(engine), scan.WithPrecompile())
		require.NoError(t, err, engine.Version())
	}
	_, err = analyze.New(cfg, analyze.WithPrecompile())
	require.NoError(t, err)
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	for _, rule := range cfg.Rules {
		if rule.RevokeExpr != "" {
			_, err := runtime.CompileRevocation(rule.RevokeExpr)
			require.NoError(t, err, rule.ID)
		}
	}
}

// testConfig returns the default config narrowed to the rules ids, in order.
func testConfig(t testing.TB, ids ...string) *config.Config {
	t.Helper()
	cfg, err := rulebuilder.Config()
	require.NoError(t, err)
	rules := cfg.Rules
	cfg.Rules = nil
	for _, id := range ids {
		i := slices.IndexFunc(rules, func(rule config.Rule) bool { return rule.ID == id })
		require.NotEqual(t, -1, i, "no registered rule %q", id)
		cfg.Rules = append(cfg.Rules, rules[i])
	}
	return cfg
}

// testRule returns a copy of a registered rule.
func testRule(t testing.TB, id string) *config.Rule {
	t.Helper()
	return &testConfig(t, id).Rules[0]
}
