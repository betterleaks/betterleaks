package cmd

import (
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveConfigIgnoresImplicitAndLegacyConfigs(t *testing.T) {
	dir := t.TempDir()
	legacyConfig := filepath.Join(dir, ".gitleaks.toml")
	require.NoError(t, os.WriteFile(legacyConfig, []byte(`title = "legacy"`), 0o600))
	t.Chdir(dir)
	require.NoError(t, os.WriteFile(".betterleaks.toml", []byte("invalid TOML ["), 0o600))
	t.Setenv("BETTERLEAKS_CONFIG", "")
	t.Setenv("BETTERLEAKS_CONFIG_TOML", "")
	t.Setenv("GITLEAKS_CONFIG", legacyConfig)
	t.Setenv("GITLEAKS_CONFIG_TOML", `title = "legacy environment"`)

	resolved, err := resolveConfig(&commandRuntime{stderr: io.Discard}, "", "")
	require.NoError(t, err)
	assert.Equal(t, "default", resolved.source)
}

func TestConfigHash(t *testing.T) {
	t.Setenv("BETTERLEAKS_CONFIG", "")
	t.Setenv("BETTERLEAKS_CONFIG_TOML", "")
	const component = "[[rules]]\nid='part'\nregex='COMPONENT'\nskipReport=true\n"
	const primary = "[[rules]]\nid='token'\nregex='PRIMARY'\ncomponents=[{id='part'}]\nvalidate='missingFunction()'\nanalyze='missingFunction()'\n"
	custom := writeTestConfig(t, component+primary)
	base := writeTestConfig(t, component)
	inherited := writeTestConfig(t, fmt.Sprintf("[extend]\npath='%s'\n%s", filepath.ToSlash(base), primary))
	invalid := writeTestConfig(t, "[[rules]]\nid='broken'\nregex='['\n")
	defaults, err := configpkg.Default()
	require.NoError(t, err)
	defaultRuleHash, err := defaults.RuleHash("github-pat")
	require.NoError(t, err)

	// Compare the command with real scan output, including inherited components.
	root, output := newTestCLI(t)
	root.SetIn(strings.NewReader("PRIMARY COMPONENT\n"))
	root.SetArgs([]string{"stdin", "--config", inherited, "--offline", "--no-banner", "--exit-code=0", "--output=-"})
	require.NoError(t, root.Execute())
	metadata, findings := decodeScanJSON(t, output.Bytes())
	require.Len(t, findings, 1)
	require.Len(t, findings[0].ComponentSets, 1)
	require.Len(t, findings[0].ComponentSets[0].Components, 1)
	ruleHash := findings[0].RuleHash
	writeErr := errors.New("output disconnected")
	for _, tc := range []struct {
		name      string
		args      []string
		envPath   string
		envTOML   string
		want      string
		wantErr   string
		failWrite bool
	}{
		{name: "default config", want: defaults.Hash()},
		{name: "default rule", args: []string{"--rule", "github-pat"}, want: defaultRuleHash},
		{name: "custom config", args: []string{"--config", custom}, want: metadata.ConfigHash},
		{name: "custom rule", args: []string{"--config", custom, "--rule", "token"}, want: ruleHash},
		{name: "inherited config", args: []string{inherited}, want: metadata.ConfigHash},
		{name: "inherited rule", args: []string{inherited, "--rule", "token"}, want: ruleHash},
		{name: "component rule", args: []string{inherited, "--rule", "part"}, want: findings[0].ComponentSets[0].Components[0].RuleHash},
		{name: "positional path wins", args: []string{"--config", invalid, inherited, "--rule", "token"}, want: ruleHash},
		{name: "environment file", envPath: inherited, args: []string{"--rule", "token"}, want: ruleHash},
		{name: "environment content", envTOML: primary + component, args: []string{"--rule", "token"}, want: ruleHash},
		{name: "unknown rule", args: []string{custom, "--rule", "missing"}, wantErr: `rule "missing" not found`},
		{name: "invalid config", args: []string{invalid}, wantErr: "invalid regex"},
		{name: "output error", args: []string{custom}, failWrite: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BETTERLEAKS_CONFIG", tc.envPath)
			t.Setenv("BETTERLEAKS_CONFIG_TOML", tc.envTOML)
			root, stdout := newTestCLI(t)
			if tc.failWrite {
				root.runtime.stdout = testErrorWriter{err: writeErr}
			}
			root.SetArgs(append([]string{"config", "hash"}, tc.args...))
			err := root.Execute()
			if tc.failWrite {
				require.ErrorIs(t, err, writeErr)
			} else if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.Empty(t, stdout.String())
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want+"\n", stdout.String())
			}
		})
	}
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
	_, findings := decodeScanJSONL(t, stdout.Bytes())
	require.Len(t, findings, 1)
	require.Equal(t, filepath.ToSlash(filepath.Join(dir, "app.env")), findings[0].Location.Path)
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
	root, stdout := newTestCLI(t)
	root.SetArgs([]string{"url", server.URL, "--config", path, "--offline", "--no-color", "--no-banner", "--output=-"})
	require.ErrorContains(t, root.Execute(), "unable to compile source prefilter")
	require.Empty(t, stdout.String())
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
