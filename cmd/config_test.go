package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	configpkg "github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveConfigIgnoresGitleaksCompatibility(t *testing.T) {
	dir := t.TempDir()
	legacyConfig := filepath.Join(dir, ".gitleaks.toml")
	require.NoError(t, os.WriteFile(legacyConfig, []byte(`title = "legacy"`), 0o600))
	t.Chdir(dir)
	t.Setenv("BETTERLEAKS_CONFIG", "")
	t.Setenv("BETTERLEAKS_CONFIG_TOML", "")
	t.Setenv("GITLEAKS_CONFIG", legacyConfig)
	t.Setenv("GITLEAKS_CONFIG_TOML", `title = "legacy environment"`)

	resolved, err := resolveConfig(&commandRuntime{stderr: io.Discard}, "", "")
	require.NoError(t, err)
	assert.Equal(t, "default", resolved.source)
}

func TestRenderConfigTOMLComponents(t *testing.T) {
	cfg := &configpkg.Config{
		MinVersion: "v1.8.0",
		Rules: []configpkg.Rule{
			{
				ID:    "primary",
				Regex: "primary",
				Components: []configpkg.Component{
					{
						RuleID:   "component",
						Optional: true,
						Within:   "-5L,+2L",
					},
				},
			},
			{
				ID:    "component",
				Regex: "component",
			},
		},
	}

	rendered := renderConfigTOML(renderConfig(cfg))
	assert.Contains(t, rendered, "minVersion = 'v1.8.0'")
	assert.NotContains(t, rendered, "betterleaksMinVersion")
	assert.Contains(t, rendered, `components = [
  { id = 'component', optional = true, within = '-5L,+2L' },
]`)
	assert.NotContains(t, rendered, "[[rules.required]]")

	parsed, err := configpkg.ParseTOMLString(rendered, "")
	require.NoError(t, err)
	primary, ok := parsed.Rule("primary")
	require.True(t, ok)
	require.Len(t, primary.Components, 1)
	assert.True(t, primary.Components[0].Optional)
	assert.Equal(t, "-5L,+2L", primary.Components[0].Within)
}

func TestConfigRevokeRoundTripAndCompile(t *testing.T) {
	const expression = `let response = http.delete("https://example.test/self", {}); response.status == 204 ? {"result": "revoked"} : revoke.unknown(response)`
	cfg := &configpkg.Config{Rules: []configpkg.Rule{{ID: "token", Regex: "unused", RevokeExpr: expression}}}
	rendered := renderConfigTOML(renderConfig(cfg))
	require.Contains(t, rendered, "revoke = ")
	parsed, err := configpkg.ParseTOMLString(rendered, "")
	require.NoError(t, err)
	require.Equal(t, expression, parsed.Rules[0].RevokeExpr)
	require.NoError(t, validateConfig(parsed, nil))
	parsed.Rules[0].RevokeExpr = `invalid revocation syntax ???`
	require.ErrorContains(t, validateConfig(parsed, nil), "compiling rule token revocation")
}

func writeTestConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "betterleaks.toml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestCLIExplicitlyExcludesLoadedConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "rules.toml")
	require.NoError(t, os.WriteFile(configPath, []byte("[[rules]]\nid = \"token\"\nregex = '''TOKEN'''\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.env"), []byte("TOKEN"), 0600))
	root, stdout := newTestCLI(t)
	root.SetArgs([]string{"fs", dir, "--config", configPath, "--offline", "--jsonl", "--no-color", "--exit-code=0"})
	require.NoError(t, root.Execute())
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	require.Len(t, lines, 1)
	var finding report.Finding
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &finding))
	require.Equal(t, filepath.ToSlash(filepath.Join(dir, "app.env")), finding.Location.Path)
}

func TestInvalidPrefilterStopsBeforeSourceIO(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, "TOKEN")
	}))
	defer server.Close()
	path := writeTestConfig(t, `
prefilter = 'tokenRatio(attributes.path) > 0'
[[rules]]
id = "token"
regex = 'TOKEN'
`)
	root, _ := newTestCLI(t)
	root.runtime.exit = func(code int) { panic(code) }
	root.SetArgs([]string{"url", server.URL, "--config", path, "--offline", "--no-color"})
	require.PanicsWithValue(t, 1, func() { _ = root.Execute() })
	require.Zero(t, requests.Load())
}

func TestConfigShowIDs(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()
	configPath := writeTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "z-local"
regex = '''unused'''

[[rules]]
id = "b-validation"
regex = '''unused'''
validate = '''let response = http.get(%[1]q, {}); {"result": "valid"}'''

[[rules]]
id = "a-analysis"
regex = '''unused'''
validate = '''let response = http.get(%[1]q, {}); {"result": "valid"}'''
analyze = '''let response = http.get(%[1]q, {}); {"capabilities": ["read"]}'''

[[rules]]
id = "d-revoke"
regex = '''unused'''
revoke = '''let response = http.delete(%[1]q, {}); {"result": "revoked"}'''

[[rules]]
id = "c-all-stages"
regex = '''unused'''
validate = '''let response = http.get(%[1]q, {}); {"result": "valid"}'''
analyze = '''let response = http.get(%[1]q, {}); {"capabilities": ["read"]}'''
revoke = '''let response = http.delete(%[1]q, {}); {"result": "revoked"}'''
`, server.URL))
	for _, test := range []struct {
		name  string
		flags []string
		want  string
	}{
		{name: "all", want: "a-analysis\nb-validation\nc-all-stages\nd-revoke\nz-local\n"},
		{name: "validation", flags: []string{"--validation"}, want: "a-analysis\nb-validation\nc-all-stages\n"},
		{name: "analysis", flags: []string{"--analysis"}, want: "a-analysis\nc-all-stages\n"},
		{name: "revocation", flags: []string{"--revocation"}, want: "c-all-stages\nd-revoke\n"},
		{name: "validation and analysis", flags: []string{"--validation", "--analysis"}, want: "a-analysis\nc-all-stages\n"},
		{name: "validation and revocation", flags: []string{"--validation", "--revocation"}, want: "c-all-stages\n"},
		{name: "analysis and revocation", flags: []string{"--analysis", "--revocation"}, want: "c-all-stages\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, stdout := newTestCLI(t)
			args := []string{"config", "show", "ids", "--config", configPath}
			root.SetArgs(append(args, test.flags...))
			require.NoError(t, root.Execute())
			require.Equal(t, test.want, stdout.String())
		})
	}

	t.Run("no matches", func(t *testing.T) {
		localConfig := writeTestConfig(t, `[[rules]]
id = "local-only"
regex = '''unused'''
`)
		root, stdout := newTestCLI(t)
		root.SetArgs([]string{"config", "show", "ids", "--analysis", localConfig})
		require.NoError(t, root.Execute())
		require.Empty(t, stdout.String())
	})
	t.Run("positional config overrides global flag", func(t *testing.T) {
		root, stdout := newTestCLI(t)
		root.SetArgs([]string{"config", "show", "ids", "--config", "missing-config.toml", "--analysis", configPath})
		require.NoError(t, root.Execute())
		require.Equal(t, "a-analysis\nc-all-stages\n", stdout.String())
	})
	t.Run("config environment", func(t *testing.T) {
		t.Setenv("BETTERLEAKS_CONFIG", configPath)
		root, stdout := newTestCLI(t)
		root.SetArgs([]string{"config", "show", "ids", "--analysis"})
		require.NoError(t, root.Execute())
		require.Equal(t, "a-analysis\nc-all-stages\n", stdout.String())
	})
	require.Zero(t, requests.Load(), "listing IDs must not execute provider expressions")
}

func TestConfigShowIDsBuiltinRevocation(t *testing.T) {
	configPath := writeTestConfig(t, "[extend]\nuseDefault = true\n")
	root, stdout := newTestCLI(t)
	root.SetArgs([]string{"config", "show", "ids", "--config", configPath, "--revocation"})
	require.NoError(t, root.Execute())
	want := []string{
		"buildkite-user-access-token",
		"github-fine-grained-pat", "github-oauth", "github-pat", "github-refresh-token",
		"gitlab-pat", "gitlab-pat-routable", "gitlab-pat-routable-versioned",
		"huggingface-access-token", "huggingface-organization-api-token",
		"slack-bot-token", "slack-user-token", "twitch-api-token",
	}
	require.Equal(t, strings.Join(want, "\n")+"\n", stdout.String())
	// All built-in revocable credentials now also support validation.
	root, stdout = newTestCLI(t)
	root.SetArgs([]string{"config", "show", "ids", "--config", configPath, "--revocation", "--validation"})
	require.NoError(t, root.Execute())
	require.Equal(t, strings.Join(want, "\n")+"\n", stdout.String())
}

func TestConfigShowIDsPropagatesWriteError(t *testing.T) {
	configPath := writeTestConfig(t, "[[rules]]\nid = \"test-token\"\nregex = '''unused'''\n")
	root, _ := newTestCLI(t)
	want := errors.New("output failed")
	root.runtime.stdout = testErrorWriter{err: want}
	root.SetArgs([]string{"config", "show", "ids", configPath})
	require.ErrorIs(t, root.Execute(), want)
}

func TestConfigShowPreservesTOMLForms(t *testing.T) {
	configPath := writeTestConfig(t, "[[rules]]\nid = \"test-token\"\nregex = '''unused'''\n")
	for _, args := range [][]string{
		{"config", "show", "--config", configPath},
		{"config", "show", configPath},
		{"config", "show", "toml", configPath},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root, stdout := newTestCLI(t)
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			require.Contains(t, stdout.String(), "[[rules]]")
			require.Contains(t, stdout.String(), "id = 'test-token'")
		})
	}
}
