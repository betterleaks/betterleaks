package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLeadingFlagsMatchCommandLocalFlags(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want []string
	}{
		{"boolean", []string{"--no-banner", "fs", "."}, []string{"fs", "--no-banner", "."}},
		{"output", []string{"--output", "out.json", "filesystem", "."}, []string{"filesystem", "--output", "out.json", "."}},
		{"scalar order", []string{"--output=first.json", "-j2", "fs", "--output=last.json", "-j0", "."}, []string{"fs", "--output=first.json", "-j2", "--output=last.json", "-j0", "."}},
		{"boolean override", []string{"--no-banner", "fs", "--no-banner=false", "."}, []string{"fs", "--no-banner", "--no-banner=false", "."}},
		{"repeated flags", []string{"-ir", "first", "fs", "--isolate-rule", "second", "."}, []string{"fs", "--isolate-rule", "first", "--isolate-rule", "second", "."}},
		{"short flags", []string{"-sj2", "-oout.json", "fs", "."}, []string{"fs", "-sj2", "-oout.json", "."}},
		{"implicit redaction", []string{"--redact", "fs", "."}, []string{"fs", "--redact", "."}},
		{"partial redaction", []string{"--redact=20", "fs", "."}, []string{"fs", "--redact=20", "."}},
		{"command as output", []string{"--output", "git", "fs", "."}, []string{"fs", "--output", "git", "."}},
		{"command as config", []string{"--config", "git", "--offline", "fs", "."}, []string{"fs", "--config", "git", "--offline", "."}},
		{"source flag", []string{"--staged", "--offline", "git", "."}, []string{"git", "--staged", "--offline", "."}},
		{"credential flag", []string{"--rule", "token", "--jsonl", "analyze", "secret"}, []string{"analyze", "--rule", "token", "--jsonl", "secret"}},
		{"nested command", []string{"--analysis", "config", "show", "ids"}, []string{"config", "show", "ids", "--analysis"}},
		{"between nested commands", []string{"config", "--analysis", "show", "--validation", "ids"}, []string{"config", "show", "ids", "--analysis", "--validation"}},
		{"auto", []string{"--offline", "--output=out.json", "target"}, []string{"auto", "--offline", "--output=out.json", "target"}},
		{"explicit auto", []string{"--offline", "auto", "target"}, []string{"auto", "--offline", "target"}},
		{"command after path", []string{"--offline", "target", "fs"}, []string{"auto", "--offline", "target", "fs"}},
		{"literal command path", []string{"--offline", "--", "fs"}, []string{"auto", "--offline", "--", "fs"}},
		{"literal flag path", []string{"--", "--offline", "fs"}, []string{"auto", "--", "--offline", "fs"}},
		{"explicit literal paths", []string{"--offline", "fs", "--", "--no-banner", "git"}, []string{"fs", "--offline", "--", "--no-banner", "git"}},
		{"nested literal path", []string{"config", "show", "--", "ids"}, []string{"config", "show", "toml", "--", "ids"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual, err := parseCLIForTest(t, test.args...)
			require.NoError(t, err)
			expected, err := parseCLIForTest(t, test.want...)
			require.NoError(t, err)
			assert.Equal(t, expected, actual)
		})
	}
}

func TestLeadingFlagsAcrossCommands(t *testing.T) {
	for _, args := range [][]string{
		{"fs", "."}, {"filesystem", "."}, {"auto", "."}, {"git", "."}, {"stdin"},
		{"url", "https://example.com/file"}, {"github", "https://github.com/example/repo"},
		{"gitlab", "https://gitlab.com/example/repo"}, {"huggingface", "https://huggingface.co/example/repo"},
		{"hf", "https://huggingface.co/example/repo"}, {"s3", "s3://example"},
	} {
		t.Run(args[0], func(t *testing.T) {
			prefix := []string{"--offline", "--no-banner", "--redact", "--output=out.json"}
			actual, err := parseCLIForTest(t, append(prefix, args...)...)
			require.NoError(t, err)
			local := append([]string{args[0]}, prefix...)
			local = append(local, args[1:]...)
			expected, err := parseCLIForTest(t, local...)
			require.NoError(t, err)
			assert.Equal(t, expected, actual)
		})
	}
}

func TestLeadingFlagsRejectInvalidScopeAndValues(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--offline", "validate"}, "unknown flag --offline"},
		{[]string{"--no-banner", "config", "show", "ids"}, "unknown flag --no-banner"},
		{[]string{"--staged", "fs", "."}, "unknown flag --staged"},
		{[]string{"--rule", "token", "fs", "."}, "unknown flag --rule"},
		{[]string{"--bad-opt", "fs", "."}, "unknown flag --bad-opt"},
		{[]string{"--jobs=bad", "fs", "."}, "--jobs"},
		{[]string{"--jobs=-1", "fs", "."}, "--jobs must be non-negative"},
		{[]string{"--redact=bad", "fs", "."}, "invalid redaction percentage"},
		{[]string{"--output"}, "--output"},
	} {
		t.Run(fmt.Sprint(test.args), func(t *testing.T) {
			_, err := parseCLIForTest(t, test.args...)
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestLeadingScanFlagsTakeEffect(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	configPath := writeTestConfig(t, fmt.Sprintf(`[[rules]]
id = "fixture-token"
regex = 'fixture-secret-[a-z]+'
validate = '''let r = http.get(%q); {"result": "valid"}'''
`, server.URL))
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.txt")
	require.NoError(t, os.WriteFile(inputPath, []byte("fixture-secret-alpha\n"), 0o600))
	for _, mode := range []string{"before", "after", "auto"} {
		t.Run(mode, func(t *testing.T) {
			previousBanner := bannerPrinted
			bannerPrinted = false
			t.Cleanup(func() { bannerPrinted = previousBanner })
			root, stdout := newTestCLI(t)
			var stderr bytes.Buffer
			root.runtime.stderr = &stderr
			outputPath := filepath.Join(t.TempDir(), "report.json")
			flags := []string{"--config", configPath, "--no-banner", "--offline", "--redact", "--output", outputPath, "--exit-code=0"}
			var args []string
			switch mode {
			case "before":
				args = append(flags, "fs", inputPath)
			case "after":
				args = append([]string{"fs", inputPath}, flags...)
			case "auto":
				args = append(flags, inputPath)
			}
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			assert.False(t, bannerPrinted)
			assert.NotContains(t, stderr.String(), banner)
			assert.Zero(t, requests.Load(), "offline must prevent provider requests")
			raw, err := os.ReadFile(outputPath)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "fixture-secret-alpha")
			assert.NotContains(t, stdout.String(), "fixture-secret-alpha")
			assert.NotContains(t, stderr.String(), "fixture-secret-alpha")
			var findings []report.Finding
			require.NoError(t, json.Unmarshal(raw, &findings))
			require.Len(t, findings, 1)
			assert.Equal(t, "REDACTED", findings[0].Match.Value)
			assert.True(t, findings[0].Analysis.IsZero())
		})
	}
}
