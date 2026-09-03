package report

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintPrettyAnalysisMetadata(t *testing.T) {
	original := os.Stdout
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = original
		_ = reader.Close()
		_ = writer.Close()
	})

	finding := Finding{Analysis: Analysis{
		Severity: SeverityHigh,
		Metadata: map[string]any{
			"permissions": []any{"create_access_request", "read_personal_access_token"},
		},
	}}
	finding.printPrettyAnalysis(true)
	require.NoError(t, writer.Close())

	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Contains(t, string(output), "permissions")
	assert.Contains(t, string(output), "[create_access_request, read_personal_access_token]")
	assert.NotContains(t, string(output), "metadata.permissions")
}
