package cmd

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanFlagsAreCommandLocal(t *testing.T) {
	scanOnly := []string{
		"exit-code",
		"silent",
		"output",
		"confidence",
		"max-target-megabytes",
		"jobs",
		"ignore-file",
		"ignore-allow-comments",
		"redact",
		"no-banner",
		"disable-rule",
		"isolate-rule",
		"match-context",
		"max-decode-depth",
		"max-archive-depth",
		"offline",
		"no-analysis",
		"validation-status",
		"provider-workers",
		"diagnostics",
		"diagnostics-dir",
	}

	_, parser := newCLIParserForTest(t)
	scanNodes := []*kong.Node{
		commandNode(t, parser.Model.Node, "auto"),
		commandNode(t, parser.Model.Node, "url"),
		commandNode(t, parser.Model.Node, "filesystem"),
		commandNode(t, parser.Model.Node, "git"),
		commandNode(t, parser.Model.Node, "github"),
		commandNode(t, parser.Model.Node, "gitlab"),
		commandNode(t, parser.Model.Node, "huggingface"),
		commandNode(t, parser.Model.Node, "s3"),
		commandNode(t, parser.Model.Node, "stdin"),
	}
	validateNode := commandNode(t, parser.Model.Node, "validate")
	analyzeNode := commandNode(t, parser.Model.Node, "analyze")
	revokeNode := commandNode(t, parser.Model.Node, "revoke")
	configNode := commandNode(t, parser.Model.Node, "config")
	for _, name := range scanOnly {
		require.False(t, nodeHasFlag(parser.Model.Node, name), name)
		require.False(t, nodeHasFlag(configNode, name), name)
		require.False(t, nodeHasFlag(validateNode, name), name)
		require.False(t, nodeHasFlag(analyzeNode, name), name)
		require.False(t, nodeHasFlag(revokeNode, name), name)
		for _, node := range scanNodes {
			require.True(t, nodeHasFlag(node, name), "%s: %s", node.Name, name)
		}
	}

	sharedWithCredentials := []string{
		"jsonl",
		"provider-debug",
		"provider-timeout",
		"provider-max-requests",
		"provider-rps",
		"provider-rps-rule",
		"provider-env-vars",
	}
	for _, name := range sharedWithCredentials {
		require.False(t, nodeHasFlag(parser.Model.Node, name), name)
		require.False(t, nodeHasFlag(configNode, name), name)
		require.True(t, nodeHasFlag(validateNode, name), name)
		require.True(t, nodeHasFlag(analyzeNode, name), name)
		require.True(t, nodeHasFlag(revokeNode, name), name)
		for _, node := range scanNodes {
			require.True(t, nodeHasFlag(node, name), "%s: %s", node.Name, name)
		}
	}

	for _, deprecated := range []string{
		"validation-workers", "validation-debug", "validation-timeout",
		"validation-max-requests", "validation-rps", "validation-rps-rule",
		"validation-env-vars",
	} {
		require.False(t, nodeHasFlag(validateNode, deprecated), deprecated)
		require.False(t, nodeHasFlag(analyzeNode, deprecated), deprecated)
		require.False(t, nodeHasFlag(revokeNode, deprecated), deprecated)
		for _, node := range scanNodes {
			require.False(t, nodeHasFlag(node, deprecated), "%s: %s", node.Name, deprecated)
		}
	}
}

func TestRemovedProviderFlagsAreRejected(t *testing.T) {
	for _, flag := range []string{
		"--validation", "--analysis", "--validation-extract-empty", "--no-validation",
		"--validation-workers=4", "--validation-debug", "--validation-timeout=2s",
		"--validation-max-requests=5", "--validation-rps=1", "--validation-rps-rule=github-pat=1",
		"--validation-env-vars=GITHUB_BASE_URL",
	} {
		t.Run(flag, func(t *testing.T) {
			_, err := parseCLIForTest(t, "dir", flag)
			require.ErrorContains(t, err, "unknown flag")
		})
	}
}

func TestRedactFlagSupportsImplicitAndExplicitPercentages(t *testing.T) {
	cli, err := parseCLIForTest(t, "dir", "--redact")
	require.NoError(t, err)
	require.Equal(t, redactFlag(100), cli.Directory.Redact)

	cli, err = parseCLIForTest(t, "dir", "--redact=20")
	require.NoError(t, err)
	require.Equal(t, redactFlag(20), cli.Directory.Redact)
}

func nodeHasFlag(node *kong.Node, name string) bool {
	for _, flag := range node.Flags {
		if flag.Name == name {
			return true
		}
	}
	return false
}

func commandNode(t *testing.T, parent *kong.Node, name string) *kong.Node {
	t.Helper()
	for _, child := range parent.Children {
		if child.Name == name {
			return child
		}
	}
	t.Fatalf("command %q not found", name)
	return nil
}

func TestScanProviderModes(t *testing.T) {
	configPath := writeTestConfig(t, `
[[rules]]
id = "test-token"
regex = '''(secret-[a-z]+)'''
validate = '''
{"result": "valid", "analysis": {"owner": "user-1"}}
'''
analyze = '''
{
  "identity": {"id": validation["analysis"]["owner"]},
  "capabilities": ["write", "read"]
}
'''
`)

	tests := []struct {
		name           string
		flags          []string
		wantValidation bool
		wantAnalysis   bool
	}{
		{name: "enabled by default", wantValidation: true, wantAnalysis: true},
		{name: "no analysis", flags: []string{"--no-analysis"}, wantValidation: true},
		{name: "offline", flags: []string{"--offline"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, stdout := newTestCLI(t)
			root.SetIn(strings.NewReader("token = secret-alpha\n"))
			args := []string{
				"stdin",
				"--config", configPath,
				"--jsonl",
				"--no-banner",
				"--exit-code", "0",
			}
			args = append(args, test.flags...)
			root.SetArgs(args)
			require.NoError(t, root.Execute())

			var finding report.Finding
			require.NoError(t, json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &finding))
			if !test.wantValidation {
				assert.Empty(t, finding.Analysis.Status)
				assert.True(t, finding.Analysis.IsZero())
				return
			}

			assert.Equal(t, report.ValidationStatusValid, finding.Analysis.Status)
			assert.Empty(t, finding.Analysis.Metadata)
			if !test.wantAnalysis {
				assert.Equal(t, report.Analysis{Status: report.ValidationStatusValid}, finding.Analysis)
				return
			}

			assert.Equal(t, report.SeverityHigh, finding.Analysis.Severity)
			assert.Equal(t, []report.Capability{report.CapabilityRead, report.CapabilityWrite}, finding.Analysis.Capabilities)
			require.NotNil(t, finding.Analysis.Identity)
			assert.Equal(t, "user-1", finding.Analysis.Identity.ID)
		})
	}
}

func TestParseValidationStatuses(t *testing.T) {
	got, err := parseValidationStatuses(" valid, NONE,needs_validation ")
	if err != nil {
		t.Fatalf("parseValidationStatuses: %v", err)
	}
	want := []report.ValidationStatus{
		report.ValidationStatusValid,
		report.ValidationStatusNone,
		report.ValidationStatusNeedsValidation,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
	if _, err := parseValidationStatuses("valid,surprising"); err == nil {
		t.Fatal("invalid status returned no error")
	}
}

func TestParseProviderRuleRPS(t *testing.T) {
	got, err := parseProviderRuleRPS([]string{"github-pat=2", "gcp-service-account=0.5"})
	if err != nil {
		t.Fatalf("parseProviderRuleRPS: %v", err)
	}
	if got["github-pat"] != 2 {
		t.Fatalf("github rate = %v, want 2", got["github-pat"])
	}
	if got["gcp-service-account"] != 0.5 {
		t.Fatalf("gcp rate = %v, want 0.5", got["gcp-service-account"])
	}
}

func TestParseProviderRuleRPSRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{
		"github-pat",
		"=1",
		"github-pat=0",
		"github-pat=-1",
		"github-pat=not-a-number",
		"github-pat=1,github-pat=2",
	} {
		if _, err := parseProviderRuleRPS([]string{value}); err == nil {
			t.Fatalf("parseProviderRuleRPS(%q) returned no error", value)
		}
	}
	if _, err := parseProviderRuleRPS([]string{"github-pat=1", "github-pat=2"}); err == nil {
		t.Fatal("duplicate rule rate returned no error")
	}
}

func TestValidateProviderRPS(t *testing.T) {
	for _, value := range []float64{0, 0.5, 10} {
		if err := validateProviderRPS(value); err != nil {
			t.Fatalf("validateProviderRPS(%v): %v", value, err)
		}
	}
	for _, value := range []float64{-1, math.NaN(), math.Inf(1)} {
		if err := validateProviderRPS(value); err == nil {
			t.Fatalf("validateProviderRPS(%v) returned no error", value)
		}
	}
}

func TestProviderRuntimeFlagsRejectInvalidValues(t *testing.T) {
	for _, test := range []struct {
		name  string
		flags ProviderRuntimeFlags
		want  string
	}{
		{"negative timeout", ProviderRuntimeFlags{ProviderTimeout: -time.Second}, "--provider-timeout must be non-negative"},
		{"negative request limit", ProviderRuntimeFlags{ProviderMaxRequests: -1}, "--provider-max-requests must be non-negative"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.EqualError(t, test.flags.Validate(), test.want)
		})
	}
}

func TestScanOutputFlags(t *testing.T) {
	cli, err := parseCLIForTest(t, "dir", "-s", "--jsonl", "-o", "findings.json")
	require.NoError(t, err)
	require.True(t, cli.Directory.Silent)
	require.True(t, cli.Directory.JSONL)
	require.Equal(t, "findings.json", cli.Directory.Output)

	for _, removed := range []string{"report", "report-path", "report-format", "verbose"} {
		_, err := parseCLIForTest(t, "dir", "--"+removed)
		require.ErrorContains(t, err, "unknown flag")
	}
	_, err = parseCLIForTest(t, "dir", "-r", "findings.json")
	require.ErrorContains(t, err, "unknown flag")
}

func TestJobsFlag(t *testing.T) {
	cli, err := parseCLIForTest(t, "dir", "-j", "3")
	require.NoError(t, err)
	require.Equal(t, 3, cli.Directory.Jobs)

	cli, err = parseCLIForTest(t, "git", "--jobs=5")
	require.NoError(t, err)
	require.Equal(t, 5, cli.Git.Jobs)

	cli, err = parseCLIForTest(t, "s3", "-j", "6", "s3://bucket")
	require.NoError(t, err)
	require.Equal(t, 6, cli.S3.Jobs)
}

func TestResolveWorkerPlan(t *testing.T) {
	cpus := max(runtime.GOMAXPROCS(0), 1)

	explicitJobs := cpus + 3
	wantExplicit := workerPlan{Source: explicitJobs, Scanner: cpus}
	require.Equal(t, wantExplicit, resolveWorkerPlan(explicitJobs, directoryWorkerProfile))
	require.Equal(t, wantExplicit, resolveWorkerPlan(explicitJobs, objectWorkerProfile))
	require.Equal(t, wantExplicit, resolveWorkerPlan(explicitJobs, streamWorkerProfile))
	require.Equal(t, workerPlan{Source: cpus, Scanner: cpus}, resolveWorkerPlan(explicitJobs, gitWorkerProfile))
	require.Equal(t, wantExplicit, resolveWorkerPlan(explicitJobs, providerWorkerProfile))

	require.Equal(t,
		workerPlan{Source: max(cpus, min(cpus*automaticFileWorkersPerCPU, maxAutomaticFileWorkers)), Scanner: cpus},
		resolveWorkerPlan(0, directoryWorkerProfile),
	)
	require.Equal(t,
		workerPlan{Source: cpus * automaticObjectWorkersPerCPU, Scanner: cpus},
		resolveWorkerPlan(0, objectWorkerProfile),
	)
	require.Equal(t, workerPlan{Source: cpus, Scanner: cpus}, resolveWorkerPlan(0, streamWorkerProfile))
	require.Equal(t, workerPlan{Source: min(cpus, maxAutomaticGitWorkers), Scanner: cpus}, resolveWorkerPlan(0, gitWorkerProfile))
	providerWorkers := min(cpus, maxAutomaticProviderWorkers)
	require.Equal(t, workerPlan{Source: providerWorkers, Scanner: providerWorkers}, resolveWorkerPlan(0, providerWorkerProfile))
}

func TestResolveWorkerPlanOneWorkerIsSerial(t *testing.T) {
	want := workerPlan{Source: 1, Scanner: 1}
	require.Equal(t, want, resolveWorkerPlan(1, directoryWorkerProfile))
	require.Equal(t, want, resolveWorkerPlan(1, objectWorkerProfile))
	require.Equal(t, want, resolveWorkerPlan(1, streamWorkerProfile))
	require.Equal(t, want, resolveWorkerPlan(1, gitWorkerProfile))
	require.Equal(t, want, resolveWorkerPlan(1, providerWorkerProfile))
}

func TestJobsRejectsNegativeValues(t *testing.T) {
	_, err := parseCLIForTest(t, "git", "--jobs=-1")
	require.ErrorContains(t, err, "--jobs must be non-negative")
}

func TestRemovedWorkerFlagsAreRejected(t *testing.T) {
	tests := [][]string{
		{"dir", "--source-workers=2"},
		{"dir", "--detect-workers=2"},
		{"git", "--git-workers=2"},
		{"s3", "--workers=2", "s3://bucket"},
	}
	for _, args := range tests {
		_, err := parseCLIForTest(t, args...)
		require.Error(t, err, "parseCLIForTest(%q)", args)
	}
}

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
				{ID: "aws", Keywords: []string{"aws"}},
				{
					ID:       "github",
					Keywords: []string{"github"},
					Components: []config.Component{
						{RuleID: "github-client-id"},
					},
				},
				{ID: "github-client-id", Keywords: []string{"client"}},
				{ID: "slack"},
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
		ids = append(ids, rule.ID)
	}
	return ids
}

func findRule(t testing.TB, rules []config.Rule, id string) config.Rule {
	t.Helper()
	for _, rule := range rules {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("rule %q not found", id)
	return config.Rule{}
}
