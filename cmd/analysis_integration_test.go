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

	"github.com/betterleaks/betterleaks/report"
)

func TestAnalysisFlagValidatesAndEnrichesFindings(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "betterleaks.toml")
	configContents := `
[[rules]]
id = "test-token"
regex = '''(secret-[a-z]+)'''
validate = '''
{"result": "valid", "owner": "user-1"}
'''
analyze = '''
{
  "identity": {"id": validation["metadata"]["owner"]},
  "capabilities": ["write", "read"]
}
'''
`
	require.NoError(t, os.WriteFile(configPath, []byte(strings.TrimSpace(configContents)+"\n"), 0o600))

	stdout := new(bytes.Buffer)
	runtime := &commandRuntime{
		Context: context.Background(),
		stdin:   strings.NewReader("token = secret-alpha\n"),
		stdout:  stdout,
		stderr:  io.Discard,
		exit:    func(int) {},
	}
	require.NoError(t, runCLI([]string{
		"stdin",
		"--config", configPath,
		"--analysis",
		"--jsonl",
		"--no-banner",
		"--exit-code", "0",
	}, runtime))

	var finding report.Finding
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &finding))
	assert.Equal(t, report.ValidationStatusValid, finding.Validation.Status)
	assert.Equal(t, report.SeverityHigh, finding.Analysis.Severity)
	assert.Equal(t, []report.Capability{report.CapabilityRead, report.CapabilityWrite}, finding.Analysis.Capabilities)
	require.NotNil(t, finding.Analysis.Identity)
	assert.Equal(t, "user-1", finding.Analysis.Identity.ID)
}
