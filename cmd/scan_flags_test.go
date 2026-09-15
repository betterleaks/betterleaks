package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
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
		"provider-debug",
		"diagnostics",
		"diagnostics-dir",
	}

	_, parser := newCLIParserForTest(t)
	scanNodes := []*kong.Node{
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
	configNode := commandNode(t, parser.Model.Node, "config")
	for _, name := range scanOnly {
		require.False(t, nodeHasFlag(parser.Model.Node, name), name)
		require.False(t, nodeHasFlag(configNode, name), name)
		require.False(t, nodeHasFlag(validateNode, name), name)
		require.False(t, nodeHasFlag(analyzeNode, name), name)
		for _, node := range scanNodes {
			require.True(t, nodeHasFlag(node, name), "%s: %s", node.Name, name)
		}
	}

	sharedWithCredentials := []string{
		"jsonl",
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
		for _, node := range scanNodes {
			require.False(t, nodeHasFlag(node, deprecated), "%s: %s", node.Name, deprecated)
		}
	}
}

func TestScanProviderModes(t *testing.T) {
	tests := []struct {
		name              string
		flags             []string
		validationEnabled bool
		analysisEnabled   bool
	}{
		{name: "default", validationEnabled: true, analysisEnabled: true},
		{name: "analysis disabled", flags: []string{"--no-analysis"}, validationEnabled: true},
		{name: "offline", flags: []string{"--offline"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"dir"}, test.flags...)
			cli, err := parseCLIForTest(t, args...)
			require.NoError(t, err)
			require.Equal(t, test.validationEnabled, cli.Directory.validationEnabled())
			require.Equal(t, test.analysisEnabled, cli.Directory.analysisEnabled())
		})
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

func TestScanProviderModesEndToEnd(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "betterleaks.toml")
	configContents := `
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
`
	require.NoError(t, os.WriteFile(configPath, []byte(strings.TrimSpace(configContents)+"\n"), 0o600))

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
			stdout := new(bytes.Buffer)
			runtime := &commandRuntime{
				Context: context.Background(),
				stdin:   strings.NewReader("token = secret-alpha\n"),
				stdout:  stdout,
				stderr:  io.Discard,
				exit:    func(int) {},
			}
			args := []string{
				"stdin",
				"--config", configPath,
				"--jsonl",
				"--no-banner",
				"--exit-code", "0",
			}
			args = append(args, test.flags...)
			require.NoError(t, runCLI(args, runtime))

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

func TestProviderRuntimeFlagsRejectNegativeMaxRequests(t *testing.T) {
	flags := ProviderRuntimeFlags{ProviderMaxRequests: -1}
	if err := flags.Validate(); err == nil {
		t.Fatal("negative maximum returned no error")
	}
}
