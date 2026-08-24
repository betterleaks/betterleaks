package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var fixtureFindings = []Finding{
	{RuleID: "rule-a", Secret: "s3cr3t", Fingerprint: "fp1"},
	{RuleID: "rule-b", Secret: "another", Fingerprint: "fp2"},
}

func writeJSON(t *testing.T, dir string, findings []Finding) string {
	t.Helper()
	data, err := json.Marshal(findings)
	require.NoError(t, err)
	path := filepath.Join(dir, "input.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

func writeJSONL(t *testing.T, dir string, findings []Finding) string {
	t.Helper()
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	for _, f := range findings {
		require.NoError(t, enc.Encode(f))
	}
	path := filepath.Join(dir, "input.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(sb.String()), 0600))
	return path
}

func assertFixtureFindings(t *testing.T, path string) {
	t.Helper()
	got, err := LoadFindings(path)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "rule-a", got[0].RuleID)
	assert.Equal(t, "s3cr3t", got[0].Secret)
	assert.Equal(t, "rule-b", got[1].RuleID)
}

func TestLoadFindings_JSON(t *testing.T) {
	assertFixtureFindings(t, writeJSON(t, t.TempDir(), fixtureFindings))
}

func TestLoadFindings_JSONL(t *testing.T) {
	assertFixtureFindings(t, writeJSONL(t, t.TempDir(), fixtureFindings))
}

func TestLoadFindings_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0600))

	_, err := LoadFindings(path)
	assert.Error(t, err)
}

func TestLoadFindings_MissingFile(t *testing.T) {
	_, err := LoadFindings(filepath.Join(t.TempDir(), "nonexistent.json"))
	assert.Error(t, err)
}
