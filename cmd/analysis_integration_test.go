package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/report"
)

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
		{name: "no validation", flags: []string{"--no-validation"}},
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
				assert.Empty(t, finding.Validation.Status)
				assert.True(t, finding.Analysis.IsZero())
				return
			}

			assert.Equal(t, report.ValidationStatusValid, finding.Validation.Status)
			assert.Empty(t, finding.Validation.Metadata)
			if !test.wantAnalysis {
				assert.True(t, finding.Analysis.IsZero())
				return
			}

			assert.Equal(t, report.SeverityHigh, finding.Analysis.Severity)
			assert.Equal(t, []report.Capability{report.CapabilityRead, report.CapabilityWrite}, finding.Analysis.Capabilities)
			require.NotNil(t, finding.Analysis.Identity)
			assert.Equal(t, "user-1", finding.Analysis.Identity.ID)
		})
	}
}
