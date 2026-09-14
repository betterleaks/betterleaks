package report

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingPrettyWriter struct {
	err   error
	calls int
}

func (w *failingPrettyWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, w.err
}

func TestWritePrettyReportsWriterError(t *testing.T) {
	want := errors.New("output disconnected")
	w := &failingPrettyWriter{err: want}
	err := WritePretty(w, simpleFinding, PrettyOptions{})
	require.ErrorIs(t, err, want)
	require.Equal(t, 1, w.calls, "do not continue writing after failure")
	require.Error(t, WritePretty(nil, simpleFinding, PrettyOptions{}))
}

func TestWritePrettyKeepsMetadataAligned(t *testing.T) {
	var out bytes.Buffer
	f := simpleFinding
	f.Confidence = "high"
	require.NoError(t, WritePretty(&out, f, PrettyOptions{NoColor: true}))
	require.Contains(t, out.String(), "│   path ............ auth.py\n│   confidence ...... HIGH\n│ attributes:")
}

func TestPrintPrettyAnalysisMetadata(t *testing.T) {
	var output bytes.Buffer

	finding := Finding{Analysis: Analysis{
		Severity: SeverityHigh,
		Metadata: map[string]any{
			"permissions": []any{"create_access_request", "read_personal_access_token"},
		},
	}}
	require.NoError(t, WritePretty(&output, finding, PrettyOptions{NoColor: true}))
	assert.Contains(t, output.String(), "permissions")
	assert.Contains(t, output.String(), "[create_access_request, read_personal_access_token]")
	assert.NotContains(t, output.String(), "metadata.permissions")
}

func TestPrintComponentFindingsOmitsAnalysis(t *testing.T) {
	var output bytes.Buffer

	finding := Finding{ComponentSets: []ComponentSet{{
		Components: []ComponentFinding{{
			RuleID:   "cloudflare-account-id.1",
			Match:    Match{Value: "account-id"},
			Location: Location{StartLine: 3},
		}},
		Analysis: Analysis{Severity: SeverityHigh, Capabilities: []Capability{CapabilityRead, CapabilityWrite}, Status: ValidationStatusValid},
	}}}
	require.NoError(t, WritePretty(&output, finding, PrettyOptions{NoColor: true}))
	assert.Contains(t, output.String(), "cloudflare-account-id.1:3")
	assert.NotContains(t, output.String(), "analysis")
	assert.NotContains(t, output.String(), "read, write")
}
