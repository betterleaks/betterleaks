package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWritePrettyBinarySnippet(t *testing.T) {
	const secret = "token-example"
	prefix := secret + strings.Repeat("x", 120) + "\x00\xff\x1b[2J\r\b"
	f := Finding{
		RuleID:   "test",
		Match:    Match{Full: secret, Value: secret, Line: prefix + secret + "\x00tail"},
		Location: Location{StartLine: 236634, StartColumn: len(prefix) + 1},
	}
	original := f.Clone()
	var out bytes.Buffer
	require.NoError(t, WritePretty(&out, f, PrettyOptions{NoColor: true}))
	assert.True(t, utf8.Valid(out.Bytes()))
	assert.Contains(t, out.String(), "⟨binary⟩ "+secret+" ⟨binary⟩ tail")
	assert.Contains(t, out.String(), "│ 236634 │ …")
	assert.NotContains(t, out.String(), "encoding")
	assert.NotContains(t, out.String(), "line ....")
	assert.NotContains(t, out.String(), "column ....")
	assert.NotContains(t, out.String(), "\x00")
	assert.NotContains(t, out.String(), "\x1b")
	rows := strings.Split(out.String(), "\n")
	require.Len(t, strings.Split(rows[2], secret), 2, "window must contain only the second occurrence")
	assert.Contains(t, rows[3], strings.Repeat("^", len(secret)))
	assert.Equal(t, displayWidth(rows[2][:strings.Index(rows[2], secret)]),
		displayWidth(rows[3][:strings.Index(rows[3], "^")]), "caret must align with the secret")
	assert.Equal(t, original, f)
}

func TestWritePrettyDecodedValue(t *testing.T) {
	for _, line := range []string{"unrelated binary prefix\x00dG9rZW4=", "token also appears elsewhere"} {
		f := Finding{
			Match:       Match{Full: "api_key=token", Value: "token", Line: line},
			Location:    Location{StartLine: 42, StartColumn: 200},
			Tags:        []string{},
			Encodings:   []string{"base64"},
			DecodeDepth: 1,
		}
		original := f.Clone()
		var out bytes.Buffer
		require.NoError(t, WritePretty(&out, f, PrettyOptions{NoColor: true}))
		assert.Contains(t, out.String(), "│ 42 │ api_key=token\n│    │         ^^^^^\n")
		assert.NotContains(t, out.String(), "decoded value:")
		assert.Contains(t, out.String(), "encoding ...... base64")
		assert.NotContains(t, out.String(), "line ....")
		assert.NotContains(t, out.String(), "column ....")
		assert.NotContains(t, out.String(), "source:")
		assert.NotContains(t, out.String(), "unrelated binary prefix")
		out.Reset()
		require.NoError(t, WritePretty(&out, f, PrettyOptions{NoColor: true, Redact: 100}))
		assert.Contains(t, out.String(), "│ 42 │ api_key=REDACTED\n│    │         ^^^^^^^^\n")
		assert.NotContains(t, out.String(), "token")
		assert.Equal(t, original, f, "preview must not change report values or coordinates")
	}
}

func TestWritePrettyMissingSourceValue(t *testing.T) {
	f := Finding{Match: Match{Value: "token\x00\xff\n\x1b[2J"}}
	var out bytes.Buffer
	require.NoError(t, WritePretty(&out, f, PrettyOptions{NoColor: true}))
	assert.Contains(t, out.String(), `value: "token\x00\xff\n\x1b[2J"`)
	assert.True(t, utf8.Valid(out.Bytes()))
}

func TestWritePrettyRuleTagsDoNotImplyDecoding(t *testing.T) {
	f := Finding{
		Match:    Match{Line: "api_key=token", Full: "token", Value: "token"},
		Location: Location{StartLine: 42, StartColumn: 9},
		Tags:     []string{"decoded:base64", "decode-depth:1"},
	}
	var out bytes.Buffer
	require.NoError(t, WritePretty(&out, f, PrettyOptions{NoColor: true}))
	assert.Contains(t, out.String(), "│ 42 │ api_key=token")
	assert.NotContains(t, out.String(), "encoding")
}

func TestWritePrettyBinarySecretBytes(t *testing.T) {
	secret := "tok\x00\xffen"
	f := Finding{
		Match: Match{Full: secret, Value: secret, Line: "before\x00\xff" + secret + "\x00after"},
	}
	var out bytes.Buffer
	require.NoError(t, WritePretty(&out, f, PrettyOptions{NoColor: true}))
	assert.Contains(t, out.String(), `before ⟨binary⟩ tok\x00\xffen ⟨binary⟩ after`)
	assert.Contains(t, out.String(), strings.Repeat("^", len(`tok\x00\xffen`)))
	out.Reset()
	require.NoError(t, WritePretty(&out, f, PrettyOptions{NoColor: true, Redact: 100}))
	assert.Contains(t, out.String(), "before ⟨binary⟩ REDACTED ⟨binary⟩ after")
	assert.Contains(t, out.String(), "^^^^^^^^")
	assert.NotContains(t, out.String(), "tok")
}

func TestWritePrettyDecodedEncodings(t *testing.T) {
	f := Finding{
		Match:       Match{Full: "api_key=" + strings.Repeat("x", 120), Value: strings.Repeat("x", 120)},
		Tags:        []string{},
		Encodings:   []string{"base64", "percent"},
		DecodeDepth: 2,
	}
	var out bytes.Buffer
	require.NoError(t, WritePretty(&out, f, PrettyOptions{NoColor: true, Width: 60}))
	assert.Contains(t, out.String(), "encoding ...... base64, percent")
	assert.NotContains(t, out.String(), "line ....")
	assert.NotContains(t, out.String(), "column ....")
	assert.NotContains(t, out.String(), "decode-depth")
	assert.Contains(t, out.String(), ". (120 bytes)")
	assert.Contains(t, out.String(), "…")
}

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
	assert.Contains(t, output.String(), "metadata.permissions")
	assert.Contains(t, output.String(), "[create_access_request, read_personal_access_token]")
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
