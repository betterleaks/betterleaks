package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWriteJSONL verifies the NDJSON contract: one JSON object per line, and
// zero bytes (not "[]") when there are no findings. Lines are compared as
// decoded JSON since Go's map iteration makes key order unstable.
func TestWriteJSONL(t *testing.T) {
	tests := []struct {
		findings       []Finding
		testReportName string
		expected       string
		wantEmpty      bool
	}{
		{
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "jsonl_simple.jsonl"),
			findings:       []Finding{simpleFinding},
		},
		{
			// No findings must produce a zero-byte file so consumers can `wc -l`
			// or concatenate outputs without stripping an array wrapper.
			testReportName: "empty",
			findings:       []Finding{},
			wantEmpty:      true,
		},
	}

	reporter := JsonlReporter{}
	for _, test := range tests {
		t.Run(test.testReportName, func(t *testing.T) {
			tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".jsonl"))
			require.NoError(t, err)
			defer tmpfile.Close()

			err = reporter.Write(tmpfile, test.findings)
			require.NoError(t, err)

			got, err := os.ReadFile(tmpfile.Name())
			require.NoError(t, err)
			if test.wantEmpty {
				assert.Empty(t, got)
				return
			}

			want, err := os.ReadFile(test.expected)
			require.NoError(t, err)

			// lineEndingReplacer normalizes CRLF so fixtures work on Windows checkouts.
			wantLines := splitJSONLLines(lineEndingReplacer.Replace(string(want)))
			gotLines := splitJSONLLines(lineEndingReplacer.Replace(string(got)))
			require.Equal(t, len(wantLines), len(gotLines), "line count mismatch")

			for i := range wantLines {
				// Decode-then-compare tolerates key-order differences between
				// the fixture and the encoder output.
				var wantJSON, gotJSON any
				require.NoError(t, json.Unmarshal([]byte(wantLines[i]), &wantJSON))
				require.NoError(t, json.Unmarshal([]byte(gotLines[i]), &gotJSON))
				assert.Equal(t, wantJSON, gotJSON, "line %d", i+1)
			}
		})
	}
}

// TestWriteJSONL_MultiLineMessage verifies that a finding whose Message
// contains embedded newlines still produces exactly one output line.
func TestWriteJSONL_MultiLineMessage(t *testing.T) {
	multiLineFinding := Finding{
		RuleID:  "test-rule",
		Match:   "line containing secret",
		Secret:  "a secret",
		Message: "first line\nsecond line\nthird line",
		File:    "auth.py",
		Tags:    []string{},
	}
	findings := []Finding{simpleFinding, multiLineFinding}

	tmpfile, err := os.Create(filepath.Join(t.TempDir(), "multiline.jsonl"))
	require.NoError(t, err)
	defer tmpfile.Close()

	reporter := JsonlReporter{}
	err = reporter.Write(tmpfile, findings)
	require.NoError(t, err)

	got, err := os.ReadFile(tmpfile.Name())
	require.NoError(t, err)

	lines := splitJSONLLines(lineEndingReplacer.Replace(string(got)))
	require.Equal(t, len(findings), len(lines), "expected one line per finding")

	for i, line := range lines {
		var obj any
		require.NoError(t, json.Unmarshal([]byte(line), &obj), "line %d must be valid JSON", i+1)
	}
}

// splitJSONLLines returns the non-blank lines of s, so tests tolerate a
// trailing newline and any incidental blank lines in fixtures.
func splitJSONLLines(s string) []string {
	var out []string
	scanner := bufio.NewScanner(bytes.NewReader([]byte(s)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			out = append(out, line)
		}
	}
	return out
}
